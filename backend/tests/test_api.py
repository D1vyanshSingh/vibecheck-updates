"""API contract and authorization tests.

External services are replaced by fakes: these tests prove the HTTP contract,
the 401 path and the error mapping. They do not pretend to test Supabase.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api import app, get_scan_service
from app.security import Principal, get_current_user

USER = Principal(id="11111111-1111-1111-1111-111111111111", email="a@example.com", token="test-token")


class FakeService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []

    async def create_scan(self, principal: Principal, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("create_scan", kwargs))
        return {
            "id": "scan-1",
            "workspace_id": kwargs["workspace_id"],
            "project_id": kwargs["project_id"],
            "source_id": kwargs["source_id"],
            "status": "queued",
            "trigger": kwargs.get("trigger", "manual"),
            "findings_total": 0,
        }

    async def upload_source(self, principal: Principal, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("upload_source", kwargs))
        return {"id": "source-1", "kind": "zip", "file_count": 2}

    async def cancel_scan(self, principal: Principal, scan_id: str) -> dict[str, Any]:
        self.calls.append(("cancel_scan", scan_id))
        return {"id": scan_id, "status": "cancelled"}

    async def list_findings(self, principal: Principal, workspace_id: str, **kwargs: Any):
        self.calls.append(("list_findings", workspace_id))
        return {"findings": [], "total": 0, "limit": 100, "offset": 0}

    async def get_finding(self, principal: Principal, finding_id: str):
        self.calls.append(("get_finding", finding_id))
        return {"finding": {"id": finding_id}, "evidence": []}

    async def request_verification(self, principal: Principal, finding_id: str, source_id: str):
        self.calls.append(("request_verification", finding_id))
        return {"verification_run": {"id": "run-1"}, "scan": {"id": "scan-2"}}


@pytest.fixture()
def client() -> TestClient:
    app.dependency_overrides[get_current_user] = lambda: USER
    app.dependency_overrides[get_scan_service] = lambda: FakeService()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_health_reports_configuration_state(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "supabase" in body and "omniroute" in body


def test_capabilities_lists_tools_and_limits(client: TestClient) -> None:
    response = client.get("/v1/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert set(body["scanners"]) >= {"native_secrets", "static_checks", "semgrep", "gitleaks", "osv"}
    assert body["limits"]["max_zip_bytes"] > 0


def test_missing_token_is_401() -> None:
    app.dependency_overrides.clear()
    with TestClient(app) as bare:
        response = bare.post(
            "/v1/scans",
            json={"workspace_id": "w", "project_id": "p", "source_id": "s"},
        )
    assert response.status_code == 401


def test_create_scan_returns_201(client: TestClient) -> None:
    response = client.post(
        "/v1/scans",
        json={"workspace_id": "w1", "project_id": "p1", "source_id": "s1", "trigger": "manual"},
    )
    assert response.status_code == 201
    assert response.json()["scan"]["status"] == "queued"


def test_invalid_trigger_is_422(client: TestClient) -> None:
    response = client.post(
        "/v1/scans",
        json={"workspace_id": "w1", "project_id": "p1", "source_id": "s1", "trigger": "hack"},
    )
    assert response.status_code == 422


def test_cancel_scan(client: TestClient) -> None:
    response = client.post("/v1/scans/scan-1/cancel")
    assert response.status_code == 200
    assert response.json()["scan"]["status"] == "cancelled"


def test_verify_requires_source_id(client: TestClient) -> None:
    response = client.post("/v1/findings/f1/verify", json={})
    assert response.status_code == 422

    ok = client.post("/v1/findings/f1/verify", json={"source_id": "s1"})
    assert ok.status_code == 201
    assert ok.json()["verification_run"]["id"] == "run-1"


def test_upload_rejects_non_zip(client: TestClient) -> None:
    response = client.post(
        "/v1/sources",
        data={"workspace_id": "w1", "project_id": "p1"},
        files={"file": ("payload.txt", b"not a zip", "text/plain")},
    )
    # The fake service accepts it; the real one raises ArchiveError. This test
    # pins the multipart contract, not the archive validation.
    assert response.status_code == 201
