"""Persistence and authorization for URL assessments and report snapshots.

The network fetch and the database are faked here; the ordering, authorization
and the rows that would be written are real.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.assessment.web import WebAssessment
from app.service import ScanService

WORKSPACE = "ws-1"
PROJECT = "prj-1"


class FakeRepo:
    def __init__(self, project: dict | None = None, scan: dict | None = None) -> None:
        self.project = project if project is not None else {"id": PROJECT, "workspace_id": WORKSPACE}
        self.scan = scan
        self.sources: list[dict] = []
        self.scans: list[tuple[dict, list[str]]] = []
        self.saved: list = []
        self.evidence: list = []
        self.audits: list[dict] = []
        self.reports: list[dict] = []

    async def get_project(self, project_id: str):
        return self.project if self.project and self.project.get("id") == project_id else None

    async def create_source(self, values):
        self.sources.append(values)
        return {"id": "source-1", **values}

    async def create_scan(self, values, job_kinds):
        self.scans.append((values, list(job_kinds)))
        return {"id": "scan-1", **values}

    async def save_findings(self, scan, findings):
        self.saved = list(findings)
        return [
            {
                "id": f"finding-{index}",
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "redacted_evidence": finding.evidence,
                "scanner": finding.scanner,
                "rule_id": finding.rule_id,
            }
            for index, finding in enumerate(findings)
        ]

    async def add_evidence(self, rows):
        self.evidence = list(rows)

    async def audit(self, values):
        self.audits.append(values)

    async def get_scan(self, scan_id: str):
        return self.scan

    async def create_report(self, values):
        self.reports.append(values)
        return {"id": "report-1", **values}


def _principal(role: str = "developer") -> SimpleNamespace:
    return SimpleNamespace(id="user-1", token=f"token-{role}", role=role)


def _finding():
    return SimpleNamespace(
        rule_id="VC-WEB-HSTS",
        title="No HSTS header",
        severity="medium",
        category="configuration",
        confidence="high",
        description="HSTS is missing.",
        file_path="https://staging.example.com/",
        line_start=None,
        line_end=None,
        remediation="Send Strict-Transport-Security.",
        evidence="URL: https://staging.example.com/",
        fingerprint="fp-1",
        scanner="web_headers",
        metadata={"scanner_version": "builtin"},
    )


def _assessment(**overrides) -> WebAssessment:
    assessment = WebAssessment(requested_url="https://staging.example.com")
    assessment.final_url = "https://staging.example.com/"
    assessment.status_code = 200
    assessment.headers = {"content-type": "text/html"}
    assessment.body_bytes = 512
    assessment.findings = [_finding()]
    assessment.limitations = ["Header and transport observations only."]
    for key, value in overrides.items():
        setattr(assessment, key, value)
    return assessment


@pytest.fixture()
def patched(monkeypatch, request):
    """Patch role lookup and the network assessment."""
    role = getattr(request, "param", "developer")
    outcome = getattr(request, "outcome", _assessment())

    async def fake_role(token: str, workspace_id: str):
        return role if workspace_id == WORKSPACE else None

    monkeypatch.setattr("app.service.workspace_role", fake_role)
    monkeypatch.setattr("app.assessment.assess_url", lambda url: outcome)
    return outcome


@pytest.mark.parametrize("patched", ["viewer"], indirect=True)
@pytest.mark.asyncio
async def test_viewer_cannot_start_a_url_assessment(patched):
    repo = FakeRepo()
    service = ScanService(repo=repo)

    with pytest.raises(HTTPException) as exc:
        await service.assess_url(
            _principal("viewer"),
            workspace_id=WORKSPACE,
            project_id=PROJECT,
            source_url="https://staging.example.com",
        )

    assert exc.value.status_code == 403
    assert repo.sources == [] and repo.scans == []


@pytest.mark.parametrize("patched", [None], indirect=True)
@pytest.mark.asyncio
async def test_non_member_sees_not_found(patched):
    repo = FakeRepo()
    service = ScanService(repo=repo)

    with pytest.raises(HTTPException) as exc:
        await service.assess_url(
            _principal("developer"),
            workspace_id=WORKSPACE,
            project_id=PROJECT,
            source_url="https://staging.example.com",
        )

    assert exc.value.status_code == 404
    assert repo.scans == []


@pytest.mark.asyncio
async def test_successful_assessment_is_persisted_as_a_completed_scan(
    monkeypatch, patched
):
    repo = FakeRepo()
    service = ScanService(repo=repo)

    result = await service.assess_url(
        _principal(),
        workspace_id=WORKSPACE,
        project_id=PROJECT,
        source_url="https://staging.example.com",
    )

    assert result["scan"]["status"] == "completed"
    assert result["scan"]["findings_total"] == 1

    values, job_kinds = repo.scans[0]
    assert job_kinds == [], "an inline assessment must not queue worker jobs"
    assert values["coverage"]["scanners"]["web_headers"]["status"] == "ran"
    assert values["coverage"]["final_url"] == "https://staging.example.com/"

    assert repo.sources[0]["kind"] == "url"
    assert repo.sources[0]["storage_path"] is None

    assert len(repo.saved) == 1
    assert repo.evidence[0]["finding_id"] == "finding-0"
    assert repo.evidence[0]["metadata"]["final_url"] == "https://staging.example.com/"

    assert repo.audits[0]["action"] == "assessment.url.completed"


@pytest.mark.asyncio
async def test_unreachable_target_writes_nothing(monkeypatch):
    async def fake_role(token: str, workspace_id: str):
        return "developer"

    failed = WebAssessment(requested_url="https://example.invalid")
    failed.error = "That hostname did not resolve."

    monkeypatch.setattr("app.service.workspace_role", fake_role)
    monkeypatch.setattr("app.assessment.assess_url", lambda url: failed)

    repo = FakeRepo()
    service = ScanService(repo=repo)

    with pytest.raises(HTTPException) as exc:
        await service.assess_url(
            _principal(),
            workspace_id=WORKSPACE,
            project_id=PROJECT,
            source_url="https://example.invalid",
        )

    assert exc.value.status_code == 400
    assert repo.sources == [] and repo.scans == []


class FakeDb:
    def __init__(self, findings):
        self.findings = findings

    async def select(self, table, params=None):
        assert table == "findings"
        return self.findings


@pytest.mark.asyncio
async def test_report_snapshot_records_counts_and_limitations(monkeypatch):
    async def fake_role(token: str, workspace_id: str):
        return "viewer"

    scan = {
        "id": "scan-1",
        "workspace_id": WORKSPACE,
        "project_id": PROJECT,
        "coverage": {
            "scanners": {"web_headers": {"status": "ran", "detail": "HTTP 200"}},
            "limitations": ["Header and transport observations only."],
        },
    }
    findings = [
        {"id": "f1", "severity": "high", "scanner": "web_headers"},
        {"id": "f2", "severity": "low", "scanner": "web_headers"},
    ]

    monkeypatch.setattr("app.service.workspace_role", fake_role)
    monkeypatch.setattr("app.service.SupabaseRest", lambda *args, **kwargs: FakeDb(findings))

    repo = FakeRepo(scan=scan)
    service = ScanService(repo=repo)

    report = await service.create_report(
        _principal("viewer"), scan_id="scan-1", report_type="technical", version=2
    )

    assert report["status"] == "ready"
    assert report["version"] == 2
    summary = repo.reports[0]["summary"]
    assert "2 findings stored" in summary
    assert "high 1" in summary
    assert "web_headers ran" in summary
    assert "limitations" in summary
    assert repo.audits[0]["action"] == "report.generated"


@pytest.mark.asyncio
async def test_report_for_a_scan_outside_the_workspace_is_not_found(monkeypatch):
    async def fake_role(token: str, workspace_id: str):
        return "viewer"

    monkeypatch.setattr("app.service.workspace_role", fake_role)
    monkeypatch.setattr("app.service.SupabaseRest", lambda *args, **kwargs: FakeDb([]))

    service = ScanService(repo=FakeRepo(scan=None))

    with pytest.raises(HTTPException) as exc:
        await service.create_report(
            _principal("viewer"), scan_id="scan-foreign", report_type="client"
        )

    assert exc.value.status_code == 404
