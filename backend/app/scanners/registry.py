"""Fixed tool registry.

The AI layer may request a tool by name. It may not supply an executable, a
flag or a path. Each entry declares its argv builder, so a request can only
select from this list; arguments are constructed here from validated values.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.config import settings

ALLOWED_KINDS = (
    "native_secrets",
    "static_checks",
    "semgrep",
    "gitleaks",
    "osv",
)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    purpose: str
    binary: str | None
    timeout_seconds: int
    build_argv: Callable[[Path, Path], list[str]] | None

    def available(self) -> bool:
        if not self.binary:
            return True  # pure-python check
        return resolve_binary(self.binary) is not None


def _bin_dir() -> Path:
    """Scanner bin directory, with a relative path anchored to the repo root.

    Resolving against the process working directory made `SCANNER_BIN=./backend/.tools`
    miss when uvicorn was started from `backend/`, so installed tools were
    reported as absent.
    """
    from app.storage import REPO_ROOT

    configured = Path(settings.scanner_bin)
    return configured if configured.is_absolute() else (REPO_ROOT / configured).resolve()


def resolve_binary(name: str) -> str | None:
    """Resolve a tool inside the configured scanner bin directory first."""
    directory = _bin_dir()
    local = directory / f"{name}.exe"
    if local.is_file():
        return str(local)
    local_no_ext = directory / name
    if local_no_ext.is_file():
        return str(local_no_ext)
    return shutil.which(name)


def _semgrep_argv(binary_path: Path, rules: Path) -> list[str]:
    return [
        resolve_binary("semgrep") or "semgrep",
        "scan",
        "--config",
        str(rules),
        "--json",
        "--metrics=off",
        "--quiet",
        "--timeout",
        str(min(settings.scanner_timeout_seconds, 240)),
        "--max-target-bytes",
        "2000000",
        str(binary_path),
    ]


def _gitleaks_argv(source: Path, report: Path) -> list[str]:
    return [
        resolve_binary("gitleaks") or "gitleaks",
        "detect",
        "--source",
        str(source),
        "--no-git",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--exit-code",
        "0",
    ]


def _osv_argv(source: Path, report: Path) -> list[str]:
    return [
        resolve_binary("osv-scanner") or "osv-scanner",
        "--format",
        "json",
        "--recursive",
        str(source),
    ]


TOOLS: dict[str, ToolSpec] = {
    "native_secrets": ToolSpec(
        name="native_secrets",
        purpose="Built-in credential pattern detection with redaction.",
        binary=None,
        timeout_seconds=60,
        build_argv=None,
    ),
    "static_checks": ToolSpec(
        name="static_checks",
        purpose="Built-in high-signal source patterns (no exploit claims).",
        binary=None,
        timeout_seconds=60,
        build_argv=None,
    ),
    "semgrep": ToolSpec(
        name="semgrep",
        purpose="Static analysis against the bundled rule set.",
        binary="semgrep",
        timeout_seconds=240,
        build_argv=_semgrep_argv,
    ),
    "gitleaks": ToolSpec(
        name="gitleaks",
        purpose="Secret detection across tracked files.",
        binary="gitleaks",
        timeout_seconds=180,
        build_argv=_gitleaks_argv,
    ),
    "osv": ToolSpec(
        name="osv",
        purpose="Dependency vulnerability detection from lockfiles.",
        binary="osv-scanner",
        timeout_seconds=240,
        build_argv=_osv_argv,
    ),
}


def availability() -> dict[str, bool]:
    return {name: spec.available() for name, spec in TOOLS.items()}


def version_of(name: str) -> str:
    spec = TOOLS.get(name)
    if not spec or not spec.binary:
        return "builtin"
    binary = resolve_binary(spec.binary)
    if not binary:
        return "unavailable"
    for flag in ("--version", "version"):
        try:
            result = subprocess.run(
                [binary, flag],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            text = (result.stdout or result.stderr or "").strip().splitlines()
            if text:
                return text[0][:80]
        except (OSError, subprocess.SubprocessError):
            continue
    return "unknown"
