"""Persistence for scans, jobs and findings.

Every method here uses the service role. It is only reachable from the backend
worker and from service methods that have already verified the caller's
workspace membership with the user's own JWT.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.db import SupabaseRest


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanRepository:
    def __init__(self, db: SupabaseRest | None = None) -> None:
        self._db = db or SupabaseRest(service=True)

    async def get_project(self, project_id: str) -> dict[str, Any] | None:
        rows = await self._db.select(
            "projects",
            params={"id": f"eq.{project_id}", "select": "*", "limit": "1"},
        )
        return rows[0] if rows else None

    async def get_source(self, source_id: str) -> dict[str, Any] | None:
        rows = await self._db.select(
            "project_sources",
            params={"id": f"eq.{source_id}", "select": "*", "limit": "1"},
        )
        return rows[0] if rows else None

    async def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        rows = await self._db.select(
            "scans",
            params={"id": f"eq.{scan_id}", "select": "*", "limit": "1"},
        )
        return rows[0] if rows else None

    async def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        rows = await self._db.select(
            "findings",
            params={"id": f"eq.{finding_id}", "select": "*", "limit": "1"},
        )
        return rows[0] if rows else None

    async def create_source(self, values: dict[str, Any]) -> dict[str, Any]:
        rows = await self._db.insert("project_sources", values)
        return rows[0] if isinstance(rows, list) else rows

    async def create_scan(
        self, values: dict[str, Any], job_kinds: list[str]
    ) -> dict[str, Any]:
        rows = await self._db.insert("scans", values)
        scan = rows[0] if isinstance(rows, list) else rows
        scan_id = scan["id"]
        jobs = [
            {
                "workspace_id": values["workspace_id"],
                "scan_id": scan_id,
                "kind": kind,
                "status": "queued",
            }
            for kind in job_kinds
        ]
        # Inline assessments (a single fetched URL) complete inside the request
        # and have no queued work, so never insert an empty batch.
        if jobs:
            await self._db.insert("scan_jobs", jobs, prefer="return=minimal")
        return scan

    async def update_scan(self, scan_id: str, values: dict[str, Any]) -> None:
        await self._db.update("scans", values, params={"id": f"eq.{scan_id}"})

    async def cancel(self, scan_id: str) -> None:
        await self._db.update(
            "scans",
            {
                "status": "cancelled",
                "completed_at": utcnow(),
                "error_message": "Cancelled by a workspace manager.",
            },
            params={"id": f"eq.{scan_id}"},
        )
        await self._db.update(
            "scan_jobs",
            {"status": "cancelled", "finished_at": utcnow()},
            params={"scan_id": f"eq.{scan_id}", "status": "eq.queued"},
        )

    async def claim_jobs(self, worker_id: str, limit: int) -> list[dict[str, Any]]:
        rows = await self._db.rpc(
            "claim_scan_jobs", {"p_worker": worker_id, "p_limit": limit}
        )
        if isinstance(rows, dict):
            return [rows]
        return rows or []

    async def finish_job(self, job_id: str, values: dict[str, Any]) -> None:
        await self._db.update("scan_jobs", values, params={"id": f"eq.{job_id}"})

    async def save_findings(
        self,
        scan: dict[str, Any],
        findings: list[Any],
    ) -> list[dict[str, Any]]:
        rows = [
            finding.to_row(
                workspace_id=scan["workspace_id"],
                project_id=scan["project_id"],
                scan_id=scan["id"],
                source_id=scan.get("source_id"),
            )
            for finding in findings
        ]
        if not rows:
            return []
        saved = await self._db.insert(
            "findings",
            rows,
            prefer="resolution=merge-duplicates,return=representation",
            on_conflict="project_id,fingerprint",
        )
        return saved if isinstance(saved, list) else [saved]

    async def add_evidence(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            await self._db.insert("finding_evidence", rows, prefer="return=minimal")

    async def create_verification(self, values: dict[str, Any]) -> dict[str, Any]:
        rows = await self._db.insert("verification_runs", values)
        return rows[0] if isinstance(rows, list) else rows

    async def link_verification_scan(self, run_id: str, scan_id: str) -> None:
        await self._db.update(
            "verification_runs", {"scan_id": scan_id}, params={"id": f"eq.{run_id}"}
        )

    async def create_report(self, values: dict[str, Any]) -> dict[str, Any]:
        rows = await self._db.insert(
            "reports",
            values,
            prefer="resolution=merge-duplicates,return=representation",
            on_conflict="scan_id,report_type,version",
        )
        return rows[0] if isinstance(rows, list) else rows

    async def audit(self, values: dict[str, Any]) -> None:
        try:
            await self._db.insert("audit_events", values, prefer="return=minimal")
        except Exception:  # noqa: BLE001 - audit must never fail a scan
            pass

    async def count_findings(self, scan_id: str) -> int:
        rows = await self._db.select(
            "findings",
            params={"scan_id": f"eq.{scan_id}", "select": "id"},
        )
        return len(rows)
