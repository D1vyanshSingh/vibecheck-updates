"""End-to-end worker behaviour without Supabase.

Proves the real chain: stored ZIP -> extraction -> allowlisted scanners ->
normalized findings -> redacted evidence -> coverage recorded on the scan.
The repository is faked; nothing else is.
"""

from __future__ import annotations

import io
import zipfile
from types import SimpleNamespace
from typing import Any

import pytest

import app.storage as storage_module
from app.worker import run_job


def make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class FakeRepo:
    def __init__(self, scan: dict[str, Any], source: dict[str, Any]) -> None:
        self.scan = scan
        self.source = source
        self.findings: list[dict[str, Any]] = []
        self.evidence: list[dict[str, Any]] = []
        self.job_updates: list[dict[str, Any]] = []
        self.audits: list[dict[str, Any]] = []

    async def get_scan(self, scan_id: str):
        return dict(self.scan)

    async def get_source(self, source_id: str):
        return dict(self.source)

    async def update_scan(self, scan_id: str, values: dict[str, Any]) -> None:
        self.scan.update(values)

    async def finish_job(self, job_id: str, values: dict[str, Any]) -> None:
        self.job_updates.append(values)

    async def save_findings(self, scan: dict[str, Any], findings: list[Any]):
        saved = []
        for index, finding in enumerate(findings):
            row = finding.to_row(
                workspace_id=scan["workspace_id"],
                project_id=scan["project_id"],
                scan_id=scan["id"],
                source_id=scan.get("source_id"),
            )
            row["id"] = f"finding-{index}"
            saved.append(row)
        self.findings.extend(saved)
        return saved

    async def add_evidence(self, rows: list[dict[str, Any]]) -> None:
        self.evidence.extend(rows)

    async def audit(self, values: dict[str, Any]) -> None:
        self.audits.append(values)


@pytest.fixture()
def isolated_storage(tmp_path, monkeypatch):
    settings = SimpleNamespace(
        source_storage_dir=str(tmp_path / "sources"),
        max_zip_bytes=10 * 1024 * 1024,
        max_extracted_bytes=50 * 1024 * 1024,
        max_file_count=5000,
        scanner_timeout_seconds=60,
    )
    monkeypatch.setattr(storage_module, "settings", settings)
    return tmp_path


@pytest.mark.asyncio
async def test_worker_stores_redacted_findings_and_coverage(isolated_storage) -> None:
    archive = make_zip(
        {
            "src/config.py": 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
            "src/view.tsx": "export const X = () => <div dangerouslySetInnerHTML={{ __html: html }} />;\n",
            "README.md": "# clean file\n",
        }
    )
    path = storage_module.store_source("ws-1", "proj-1", "app.zip", archive)

    repo = FakeRepo(
        scan={
            "id": "scan-1",
            "workspace_id": "ws-1",
            "project_id": "proj-1",
            "source_id": "source-1",
            "status": "queued",
            "coverage": None,
            "findings_total": 0,
        },
        source={"id": "source-1", "storage_path": path},
    )

    await run_job(repo, {"id": "job-1", "scan_id": "scan-1", "kind": "all"})

    assert repo.scan["status"] == "running" or repo.scan.get("started_at")
    assert repo.findings, "the worker must persist findings"
    assert repo.evidence, "evidence rows must be written for findings with samples"

    # No usable secret may survive into the database.
    for row in repo.findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in (row["redacted_evidence"] or "")
        assert row["severity"] in {"critical", "high", "medium", "low", "info"}
        assert row["fingerprint"] and len(row["fingerprint"]) == 64

    assert repo.job_updates and repo.job_updates[-1]["status"] == "completed"

    coverage = repo.scan["coverage"]
    assert coverage["scanners"]["native_secrets"]["status"] == "ran"
    assert "limitations" in coverage and coverage["limitations"]


@pytest.mark.asyncio
async def test_worker_fails_cleanly_when_the_archive_is_gone(isolated_storage) -> None:
    repo = FakeRepo(
        scan={
            "id": "scan-2",
            "workspace_id": "ws-1",
            "project_id": "proj-1",
            "source_id": "source-2",
            "status": "queued",
            "coverage": None,
            "findings_total": 0,
        },
        # Inside the storage root but not on disk: the file is gone, the path is valid.
        source={
            "id": "source-2",
            "storage_path": str(isolated_storage / "sources" / "ws-1" / "proj-1" / "missing.zip"),
        },
    )

    await run_job(repo, {"id": "job-2", "scan_id": "scan-2", "kind": "all"})

    assert repo.job_updates[-1]["status"] == "failed"
    assert "no longer available" in repo.job_updates[-1]["error_message"].lower()
    assert repo.scan["status"] == "failed"
