"""GitHub App client.

Read-only by design: the app requests repository contents and nothing else, and
the credentials live in the environment, never in the database or the browser.
Every method here is a thin, explicit HTTP call so tests can use a fake
transport instead of a live GitHub account.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

import httpx
import jwt

from app.config import settings

API_BASE = "https://api.github.com"
USER_AGENT = "VibeCheck/1.0 (+https://vibecheck.dev)"


class GitHubError(Exception):
    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _private_key(raw: str) -> str:
    return raw.replace("\\n", "\n").strip()


def verify_webhook_signature(secret: str, body: bytes, signature: str | None) -> bool:
    """Constant-time check of X-Hub-Signature-256."""
    if not secret or not signature or not signature.startswith("sha256="):
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={digest}", signature)


@dataclass
class GitHubApp:
    app_id: str = ""
    slug: str = ""
    private_key: str = ""
    api_base: str = API_BASE

    @classmethod
    def from_settings(cls) -> "GitHubApp":
        return cls(
            app_id=settings.github_app_id,
            slug=settings.github_app_slug,
            private_key=settings.github_private_key,
            api_base=API_BASE,
        )

    @property
    def configured(self) -> bool:
        return bool(self.app_id and self.private_key)

    def app_jwt(self, now: int | None = None) -> str:
        """Short-lived RS256 token identifying the app itself (max 10 minutes)."""
        if not self.configured:
            raise GitHubError("The GitHub App is not configured on this deployment.", 503)
        issued = int(now if now is not None else time.time())
        payload = {"iat": issued - 60, "exp": issued + 540, "iss": self.app_id}
        try:
            return jwt.encode(payload, _private_key(self.private_key), algorithm="RS256")
        except Exception as exc:  # noqa: BLE001 - key format errors must be explicit
            raise GitHubError(
                "GITHUB_PRIVATE_KEY is not a usable RSA private key.", 503
            ) from exc

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }

    async def installation_for(self, owner: str, repo: str) -> int:
        """Installation id that can read this repository."""
        url = f"{self.api_base}/repos/{owner}/{repo}/installation"
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(url, headers=self._headers(self.app_jwt()))
        if response.status_code == 404:
            raise GitHubError(
                "The GitHub App is not installed on that repository.", 404
            )
        if response.status_code != 200:
            raise GitHubError(
                f"GitHub refused the installation lookup ({response.status_code}).", 502
            )
        return int(response.json()["id"])

    async def installation_token(self, installation_id: int) -> str:
        url = f"{self.api_base}/app/installations/{installation_id}/access_tokens"
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, headers=self._headers(self.app_jwt()))
        if response.status_code not in (200, 201):
            raise GitHubError(
                f"GitHub refused an installation token ({response.status_code}).", 502
            )
        return str(response.json()["token"])

    async def list_repositories(self, installation_id: int) -> list[dict]:
        token = await self.installation_token(installation_id)
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(
                f"{self.api_base}/installation/repositories",
                headers=self._headers(token),
                params={"per_page": 100},
            )
        if response.status_code != 200:
            raise GitHubError(
                f"GitHub refused the repository list ({response.status_code}).", 502
            )
        return list((response.json() or {}).get("repositories", []))

    async def download_zipball(
        self, owner: str, repo: str, ref: str | None = None, max_bytes: int | None = None
    ) -> bytes:
        """Read-only archive download; refuses anything above the upload limit."""
        installation_id = await self.installation_for(owner, repo)
        token = await self.installation_token(installation_id)
        limit = max_bytes or settings.max_zip_bytes
        suffix = f"/{ref}" if ref else ""
        url = f"{self.api_base}/repos/{owner}/{repo}/zipball{suffix}"

        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            async with client.stream("GET", url, headers=self._headers(token)) as response:
                if response.status_code != 200:
                    raise GitHubError(
                        f"GitHub refused the archive download ({response.status_code}).",
                        404 if response.status_code == 404 else 502,
                    )
                buffer = bytearray()
                async for chunk in response.aiter_bytes():
                    buffer.extend(chunk)
                    if len(buffer) > limit:
                        raise GitHubError(
                            f"Repository archive exceeds the {limit} byte limit.", 413
                        )
        if not buffer:
            raise GitHubError("GitHub returned an empty archive.", 502)
        return bytes(buffer)


__all__ = ["GitHubApp", "GitHubError", "verify_webhook_signature"]
