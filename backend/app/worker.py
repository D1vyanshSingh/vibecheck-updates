"""Scanner worker.

Claims queued jobs with a database-backed queue (FOR UPDATE SKIP LOCKED via
claim_scan_jobs), extracts the stored archive into a temporary directory,
runs the allowlisted tools and persists normalized findings.

Run one pass:      python -m app.worker --once
Run continuously:  python -m app.worker
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import traceback
from pathlib import Path
from typing import Any

from app.config import settings
from app.repository import ScanRepository, utcnow
from app.scanners.engine import run_source_scan
from app.storage import ArchiveError, cleanup, read_source, safe_extract, work_directory


async def run_job(repo: ScanRepository, job: dict[str, Any]) -> None:
    scan_id = job["scan_id"]
    job_id = job["id"]
    started = time.monotonic()

    scan = await repo.get_scan(scan_id)
    if not scan:
        await repo.finish_job(
            job_id, {"status": "failed", "error_message": "Scan disappeared."}
        )
        return

    if scan["status"] == "cancelled":
        await repo.finish_job(job_id, {"status": "cancelled", "finished_at": utcnow()})
        return

    if scan["status"] == "queued":
        await repo.update_scan(scan_id, {"status": "running", "started_at": utcnow()})

    source = await repo.get_source(scan["source_id"]) if scan.get("source_id") else None
    if not source or not source.get("storage_path"):
        await repo.finish_job(
            job_id,
            {
                "status": "failed",
                "error_message": "No stored source archive for this scan.",
                "finished_at": utcnow(),
            },
        )
        await finalize(repo, scan_id, failed_reason="No stored source archive.")
        return

    try:
        data = read_source(source["storage_path"])
    except ArchiveError as exc:
        await repo.finish_job(
            job_id,
            {"status": "failed", "error_message": exc.message, "finished_at": utcnow()},
        )
        await finalize(repo, scan_id, failed_reason=exc.message)
        return

    with work_directory() as tmp:
        root = Path(tmp) / "src"
        try:
            safe_extract(data, root)
        except ArchiveError as exc:
            await repo.finish_job(
                job_id,
                {"status": "failed", "error_message": exc.message, "finished_at": utcnow()},
            )
            await finalize(repo, scan_id, failed_reason=exc.message)
            return

        kinds = [job["kind"]] if job["kind"] != "all" else [
            "native_secrets",
            "static_checks",
            "semgrep",
            "gitleaks",
            "osv",
        ]
        output = await asyncio.to_thread(run_source_scan, root, kinds)

        saved = await repo.save_findings(scan, output.dedupe())

        evidence_rows = []
        for finding in saved:
            row = next(
                (f for f in output.findings if f.fingerprint == finding.get("fingerprint")),
                None,
            )
            if row and row.evidence:
                evidence_rows.append(
                    {
                        "workspace_id": scan["workspace_id"],
                        "finding_id": finding["id"],
                        "kind": "scanner_output",
                        "file_path": row.file_path or None,
                        "line_start": row.line_start or None,
                        "snippet": row.evidence,
                        "metadata": {"scanner": row.scanner, "rule_id": row.rule_id},
                    }
                )
        await repo.add_evidence(evidence_rows)

        duration = int((time.monotonic() - started) * 1000)
        coverage = output.coverage.as_dict()

        if job["kind"] == "all":
            await repo.finish_job(
                job_id,
                {
                    "status": "completed",
                    "finished_at": utcnow(),
                    "output_ref": json.dumps(coverage)[:2000],
                },
            )
        else:
            await repo.finish_job(
                job_id,
                {
                    "status": "completed",
                    "finished_at": utcnow(),
                    "output_ref": json.dumps(
                        {"tool_runs": coverage.get("tool_runs", []), "duration_ms": duration}
                    )[:2000],
                },
            )

        await merge_coverage(repo, scan_id, coverage, len(saved))

    cleanup(str(root))


async def merge_coverage(
    repo: ScanRepository, scan_id: str, coverage: dict[str, Any], findings: int
) -> None:
    scan = await repo.get_scan(scan_id)
    if not scan:
        return

    existing = scan.get("coverage") or {}
    if isinstance(existing, str):
        try:
            existing = json.loads(existing)
        except json.JSONDecodeError:
            existing = {}

    merged_scanners = {**(existing.get("scanners") or {}), **(coverage.get("scanners") or {})}
    merged = {
        "scanners": merged_scanners,
        "tool_runs": (existing.get("tool_runs") or []) + (coverage.get("tool_runs") or []),
        "technologies": coverage.get("technologies") or existing.get("technologies") or [],
        "limitations": sorted(
            set((existing.get("limitations") or []) + (coverage.get("limitations") or []))
        ),
    }

    await repo.update_scan(
        scan_id,
        {"coverage": merged, "findings_total": findings},
    )


async def finalize(repo: ScanRepository, scan_id: str, *, failed_reason: str | None = None) -> None:
    scan = await repo.get_scan(scan_id)
    if not scan or scan["status"] not in ("queued", "running"):
        return

    if failed_reason:
        await repo.update_scan(
            scan_id,
            {"status": "failed", "error_message": failed_reason, "completed_at": utcnow()},
        )
        return

    db = repo._db  # noqa: SLF001 - repository is the worker's own object
    jobs = await db.select(
        "scan_jobs", params={"scan_id": f"eq.{scan_id}", "select": "status"}
    )
    states = {row["status"] for row in jobs}
    terminal = {"completed", "failed", "cancelled", "skipped"}

    if states and states <= terminal:
        ok = states <= {"completed", "skipped"}
        await repo.update_scan(
            scan_id,
            {
                "status": "completed" if ok else "failed",
                "completed_at": utcnow(),
            },
        )


async def loop(once: bool = False) -> None:
    repo = ScanRepository()
    while True:
        jobs = await repo.claim_jobs(settings.worker_id, limit=3)
        for job in jobs:
            try:
                await run_job(repo, job)
            except Exception:  # noqa: BLE001 - a single job must not kill the worker
                traceback.print_exc()
                await repo.finish_job(
                    job["id"],
                    {
                        "status": "failed",
                        "error_message": "Unhandled worker error.",
                        "finished_at": utcnow(),
                    },
                )

        if jobs:
            await asyncio.gather(
                *(finalize(repo, job["scan_id"]) for job in jobs), return_exceptions=True
            )

        if once:
            return

        await asyncio.sleep(settings.worker_poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="VibeCheck scanner worker")
    parser.add_argument("--once", action="store_true", help="claim one batch and exit")
    args = parser.parse_args()
    os.environ.setdefault("WORKER_ID", settings.worker_id)
    asyncio.run(loop(once=args.once))


if __name__ == "__main__":
    main()
