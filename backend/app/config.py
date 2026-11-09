"""Runtime configuration.

Every value comes from the environment. Nothing is hard-coded and no secret
has a default. Names match the frontend's .env.example.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").strip()


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Supabase
    supabase_url: str = field(default_factory=lambda: _env("SUPABASE_URL"))
    supabase_anon_key: str = field(default_factory=lambda: _env("SUPABASE_ANON_KEY"))
    supabase_service_role_key: str = field(
        default_factory=lambda: _env("SUPABASE_SERVICE_ROLE_KEY")
    )
    supabase_jwt_secret: str = field(
        default_factory=lambda: _env("SUPABASE_JWT_SECRET")
    )

    # Origins
    frontend_url: str = field(default_factory=lambda: _env("FRONTEND_URL"))
    backend_public_url: str = field(
        default_factory=lambda: _env("BACKEND_PUBLIC_URL")
    )

    # AI gateway
    omniroute_base_url: str = field(default_factory=lambda: _env("OMNIROUTE_BASE_URL"))
    omniroute_api_key: str = field(default_factory=lambda: _env("OMNIROUTE_API_KEY"))
    omniroute_default_model: str = field(
        default_factory=lambda: _env("OMNIROUTE_DEFAULT_MODEL")
    )

    # GitHub App
    github_app_id: str = field(default_factory=lambda: _env("GITHUB_APP_ID"))
    github_app_slug: str = field(default_factory=lambda: _env("GITHUB_APP_SLUG"))
    github_private_key: str = field(
        default_factory=lambda: _env("GITHUB_PRIVATE_KEY")
    )
    github_webhook_secret: str = field(
        default_factory=lambda: _env("GITHUB_WEBHOOK_SECRET")
    )
    github_state_secret: str = field(
        default_factory=lambda: _env("GITHUB_STATE_SECRET")
    )

    # Storage and limits
    # Defaults to <repo>/backend/sources regardless of the process working
    # directory, so a source archive can never land in a nested, unignored path.
    source_storage_dir: str = field(
        default_factory=lambda: _env("SOURCE_STORAGE_DIR")
        or str(Path(__file__).resolve().parent.parent / "sources")
    )
    max_zip_bytes: int = field(default_factory=lambda: _int("MAX_ZIP_BYTES", 50 * 1024 * 1024))
    max_extracted_bytes: int = field(
        default_factory=lambda: _int("MAX_EXTRACTED_BYTES", 250 * 1024 * 1024)
    )
    max_file_count: int = field(default_factory=lambda: _int("MAX_FILE_COUNT", 20000))
    max_files: int = field(default_factory=lambda: _int("MAX_FILES", 20000))

    # Scanners
    scanner_bin: str = field(default_factory=lambda: _env("SCANNER_BIN", "./backend/.tools"))
    scanner_timeout_seconds: int = field(
        default_factory=lambda: _int("SCANNER_TIMEOUT_SECONDS", 300)
    )
    job_timeout_seconds: int = field(
        default_factory=lambda: _int("JOB_TIMEOUT_SECONDS", 600)
    )
    max_attempts: int = field(default_factory=lambda: _int("MAX_ATTEMPTS", 3))

    # Assessment scope
    # Off by default. When set, the SSRF guard permits loopback and private
    # addresses so an authorised test target on the local network can be
    # assessed. Cloud metadata endpoints stay blocked either way.
    allow_private_assessment_hosts: bool = field(
        default_factory=lambda: _env("ASSESSMENT_ALLOW_PRIVATE_HOSTS").lower()
        in {"1", "true", "yes", "on"}
    )

    # Worker
    worker_id: str = field(default_factory=lambda: _env("WORKER_ID", "worker-local"))
    worker_poll_seconds: int = field(
        default_factory=lambda: _int("WORKER_POLL_SECONDS", 3)
    )

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_anon_key)

    @property
    def service_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_role_key)

    @property
    def omniroute_configured(self) -> bool:
        return bool(self.omniroute_base_url and self.omniroute_api_key)


settings = Settings()
