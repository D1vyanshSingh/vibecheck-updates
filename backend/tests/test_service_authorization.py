"""Workspace authorization.

The service is the enforcement point: a client-supplied workspace id that the
caller does not belong to must not produce data, and a read-only role must not
be able to start or cancel work.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException

from app.security import Principal
from app.service import ScanService

USER = Principal(id="user-1", email="a@example.com", token="token")


class FakeRepo:
    def __init__(
        self,
        project: dict[str, Any] | None = None,
        source: dict[str, Any] | None = None,
        scan: dict[str, Any] | None = None,
        finding: dict[str, Any] | None = None,
    ) -> None:
        self.project = project
        self.source = source
        self.scan = scan
        self.finding = finding
        self.created = False
        self.cancelled = False
        self.audits: list[dict[str, Any]] = []

    async def get_project(self, project_id: str):
        return self.project

    async def get_source(self, source_id: str):
        return self.source

    async def get_scan(self, scan_id: str):
        return self.scan

    async def get_finding(self, finding_id: str):
        return self.finding

    async def create_scan(self, values, job_kinds):
        self.created = True
        return {"id": "scan-1", **values}

    async def create_source(self, values):
        return {"id": "source-1", **values}

    async def cancel(self, scan_id: str) -> None:
        self.cancelled = True
        if self.scan:
            self.scan = {**self.scan, "status": "cancelled"}

    async def audit(self, values) -> None:
        self.audits.append(values)

    async def create_verification(self, values):
        return {"id": "run-1", **values}

    async def link_verification_scan(self, run_id: str, scan_id: str) -> None:
        return None


class StubService(ScanService):
    def __init__(self, repo: FakeRepo, role: str | None) -> None:
        super().__init__(repo=repo)  # type: ignore[arg-type]
        self._stub_role = role

    async def _role(self, principal: Principal, workspace_id: str) -> str | None:
        return self._stub_role


@pytest.mark.asyncio
async def test_non_member_cannot_create_a_scan() -> None:
    repo = FakeRepo(project={"id": "p1", "workspace_id": "w1"}, source={"id": "s1", "project_id": "p1"})
    service = StubService(repo, role=None)

    with pytest.raises(HTTPException) as exc:
        await service.create_scan(USER, workspace_id="w1", project_id="p1", source_id="s1")
    assert exc.value.status_code == 404
    assert repo.created is False


@pytest.mark.asyncio
async def test_viewer_cannot_create_a_scan() -> None:
    repo = FakeRepo(project={"id": "p1", "workspace_id": "w1"}, source={"id": "s1", "project_id": "p1"})
    service = StubService(repo, role="viewer")

    with pytest.raises(HTTPException) as exc:
        await service.create_scan(USER, workspace_id="w1", project_id="p1", source_id="s1")
    assert exc.value.status_code == 403
    assert repo.created is False


@pytest.mark.asyncio
async def test_cross_tenant_project_is_not_found() -> None:
    # The caller is a member of w1 but the project belongs to w2.
    repo = FakeRepo(project={"id": "p1", "workspace_id": "w2"}, source=None)
    service = StubService(repo, role="developer")

    with pytest.raises(HTTPException) as exc:
        await service.create_scan(USER, workspace_id="w1", project_id="p1", source_id="s1")
    assert exc.value.status_code == 404
    assert repo.created is False


@pytest.mark.asyncio
async def test_developer_can_create_a_scan_in_their_workspace() -> None:
    repo = FakeRepo(
        project={"id": "p1", "workspace_id": "w1"},
        source={"id": "s1", "project_id": "p1"},
    )
    service = StubService(repo, role="developer")

    scan = await service.create_scan(USER, workspace_id="w1", project_id="p1", source_id="s1")
    assert scan["status"] == "queued"
    assert repo.created is True
    assert repo.audits and repo.audits[0]["action"] == "scan.created"


@pytest.mark.asyncio
async def test_analyst_can_cancel_but_viewer_cannot() -> None:
    repo = FakeRepo(scan={"id": "scan-1", "workspace_id": "w1", "status": "running"})

    with pytest.raises(HTTPException) as exc:
        await StubService(repo, role="viewer").cancel_scan(USER, "scan-1")
    assert exc.value.status_code == 403

    result = await StubService(repo, role="analyst").cancel_scan(USER, "scan-1")
    assert result["status"] == "cancelled"


@pytest.mark.asyncio
async def test_completed_scan_cannot_be_cancelled() -> None:
    repo = FakeRepo(scan={"id": "scan-1", "workspace_id": "w1", "status": "completed"})
    with pytest.raises(HTTPException) as exc:
        await StubService(repo, role="admin").cancel_scan(USER, "scan-1")
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_verification_rejects_source_from_another_project() -> None:
    repo = FakeRepo(
        finding={"id": "f1", "workspace_id": "w1", "project_id": "p1"},
        source={"id": "s9", "project_id": "p2"},
    )
    with pytest.raises(HTTPException) as exc:
        await StubService(repo, role="analyst").request_verification(USER, "f1", "s9")
    assert exc.value.status_code == 404
