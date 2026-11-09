"""GitHub App client and repository import.

No live GitHub account is used. The HTTP layer is a fake transport, so these
tests prove the request shape, the read-only token flow and the refusal paths,
not that a real installation exists.
"""

from __future__ import annotations

import io
import json
import zipfile
from types import SimpleNamespace

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from app.integrations import github as gh
from app.service import ScanService


@pytest.fixture(scope="module")
def rsa_key() -> tuple[str, object]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return pem, key.public_key()


def _zip_bytes(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _client_factory(handler):
    """Patch target: an AsyncClient bound to a MockTransport."""
    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return real(transport=transport, *args, **kwargs)

    return factory


def test_app_reports_unconfigured_without_credentials():
    app = gh.GitHubApp()
    assert app.configured is False
    with pytest.raises(gh.GitHubError) as exc:
        app.app_jwt()
    assert exc.value.status_code == 503


def test_app_jwt_is_a_short_lived_rs256_token(rsa_key):
    pem, public_key = rsa_key
    app = gh.GitHubApp(app_id="12345", private_key=pem.replace("\n", "\\n"))

    token = app.app_jwt(now=1_700_000_000)
    claims = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_exp": False})

    assert claims["iss"] == "12345"
    assert claims["iat"] == 1_700_000_000 - 60
    assert claims["exp"] - claims["iat"] == 600


def test_unusable_private_key_is_reported(monkeypatch):
    app = gh.GitHubApp(app_id="1", private_key="not a key")
    with pytest.raises(gh.GitHubError) as exc:
        app.app_jwt()
    assert "GITHUB_PRIVATE_KEY" in exc.value.message


@pytest.mark.asyncio
async def test_download_uses_an_installation_token_and_read_only_endpoints(
    monkeypatch, rsa_key
):
    pem, _ = rsa_key
    seen: list[tuple[str, str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.headers.get("authorization")))
        if request.url.path.endswith("/installation"):
            return httpx.Response(200, json={"id": 99})
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "ghs_test_token"})
        if request.url.path.endswith("/zipball/main"):
            return httpx.Response(200, content=_zip_bytes({"repo-main/app.py": "print(1)\n"}))
        return httpx.Response(404, json={"message": "unexpected"})

    monkeypatch.setattr(gh.httpx, "AsyncClient", _client_factory(handler))
    app = gh.GitHubApp(app_id="1", private_key=pem)

    data = await app.download_zipball("acme", "widgets", "main")

    assert data.startswith(b"PK")
    assert seen[0][1] == "/repos/acme/widgets/installation"
    assert seen[1][1] == "/app/installations/99/access_tokens"
    assert seen[2][1] == "/repos/acme/widgets/zipball/main"
    assert seen[2][2] == "Bearer ghs_test_token"
    assert all("/contents" not in path for _, path, _ in seen)


@pytest.mark.asyncio
async def test_missing_installation_is_a_404(monkeypatch, rsa_key):
    pem, _ = rsa_key

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    monkeypatch.setattr(gh.httpx, "AsyncClient", _client_factory(handler))
    app = gh.GitHubApp(app_id="1", private_key=pem)

    with pytest.raises(gh.GitHubError) as exc:
        await app.download_zipball("acme", "absent")
    assert exc.value.status_code == 404
    assert "not installed" in exc.value.message


@pytest.mark.asyncio
async def test_oversized_archive_is_refused(monkeypatch, rsa_key):
    pem, _ = rsa_key

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/installation"):
            return httpx.Response(200, json={"id": 7})
        if request.url.path.endswith("/access_tokens"):
            return httpx.Response(201, json={"token": "t"})
        return httpx.Response(200, content=b"x" * 4096)

    monkeypatch.setattr(gh.httpx, "AsyncClient", _client_factory(handler))
    app = gh.GitHubApp(app_id="1", private_key=pem)

    with pytest.raises(gh.GitHubError) as exc:
        await app.download_zipball("acme", "huge", max_bytes=1024)
    assert exc.value.status_code == 413


def test_webhook_signature_is_verified_constant_time():
    import hashlib
    import hmac

    body = json.dumps({"ref": "refs/heads/main"}).encode()
    digest = hmac.new(b"secret", body, hashlib.sha256).hexdigest()

    assert gh.verify_webhook_signature("secret", body, f"sha256={digest}") is True
    assert gh.verify_webhook_signature("secret", body, "sha256=deadbeef") is False
    assert gh.verify_webhook_signature("", body, f"sha256={digest}") is False
    assert gh.verify_webhook_signature("secret", body, None) is False


# --------------------------------------------------------------- service path


class FakeRepo:
    def __init__(self, project: dict | None = None) -> None:
        self.project = project or {"id": "prj-1", "workspace_id": "ws-1"}
        self.sources: list[dict] = []
        self.scans: list[tuple[dict, list[str]]] = []
        self.audits: list[dict] = []

    async def get_project(self, project_id: str):
        return self.project

    async def create_source(self, values):
        self.sources.append(values)
        return {"id": "source-1", **values}

    async def create_scan(self, values, kinds):
        self.scans.append((values, list(kinds)))
        return {"id": "scan-1", **values}

    async def audit(self, values):
        self.audits.append(values)


def _principal() -> SimpleNamespace:
    return SimpleNamespace(id="user-1", token="jwt", role="developer")


@pytest.mark.asyncio
async def test_import_is_refused_when_the_app_is_unconfigured(monkeypatch):
    async def fake_role(token: str, workspace_id: str):
        return "developer"

    monkeypatch.setattr("app.service.workspace_role", fake_role)
    monkeypatch.setattr(gh.GitHubApp, "from_settings", classmethod(lambda cls: gh.GitHubApp()))

    repo = FakeRepo()
    service = ScanService(repo=repo)

    with pytest.raises(HTTPException) as exc:
        await service.import_github_repository(
            _principal(), workspace_id="ws-1", project_id="prj-1", owner="acme", repo="widgets"
        )

    assert exc.value.status_code == 503
    assert repo.sources == [] and repo.scans == []


@pytest.mark.asyncio
async def test_import_stores_a_github_source_and_queues_a_scan(monkeypatch, tmp_path):
    async def fake_role(token: str, workspace_id: str):
        return "developer"

    archive = _zip_bytes({"widgets-main/app.py": "print(1)\n", "widgets-main/package.json": "{}\n"})

    class FakeApp:
        configured = True

        async def download_zipball(self, owner, repo, ref=None):
            assert (owner, repo, ref) == ("acme", "widgets", "main")
            return archive

    monkeypatch.setattr("app.service.workspace_role", fake_role)
    monkeypatch.setattr(gh.GitHubApp, "from_settings", classmethod(lambda cls: FakeApp()))
    monkeypatch.setattr("app.service.store_source", lambda *a, **k: str(tmp_path / "a.zip"))

    repo = FakeRepo()
    service = ScanService(repo=repo)

    result = await service.import_github_repository(
        _principal(),
        workspace_id="ws-1",
        project_id="prj-1",
        owner="acme",
        repo="widgets",
        ref="main",
    )

    assert repo.sources[0]["kind"] == "github"
    assert repo.sources[0]["label"] == "acme/widgets@main"
    assert repo.sources[0]["file_count"] == 2
    assert result["scan"]["status"] == "queued"
    assert repo.scans[0][1], "jobs must be queued for the worker"
    assert repo.audits[0]["action"] == "github.repository.imported"
