"""External scanner adapters.

Each adapter runs one allowlisted binary with an argv built from the registry.
There is no shell, no user-supplied flag and no unbounded output capture.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from app.config import settings
from app.scanners.redact import redact
from app.scanners.registry import resolve_binary, version_of
from app.scanners.types import Finding, ToolResult

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def _run(argv: list[str], timeout: int, cwd: Path | None = None):
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            check=False,
            shell=False,
        )
        return completed, int((time.monotonic() - started) * 1000), None
    except subprocess.TimeoutExpired:
        return None, int((time.monotonic() - started) * 1000), "timeout"
    except OSError as exc:
        return None, int((time.monotonic() - started) * 1000), str(exc)


def run_semgrep(root: Path, findings: list[Finding]) -> ToolResult:
    binary = resolve_binary("semgrep")
    result = ToolResult(tool="semgrep", version=version_of("semgrep"))

    if not binary:
        result.status = "skipped"
        result.detail = "semgrep is not installed on this worker."
        return result

    if not RULES_DIR.is_dir():
        result.status = "skipped"
        result.detail = "Bundled rule directory is missing."
        return result

    argv = [
        binary,
        "scan",
        "--config",
        str(RULES_DIR),
        "--json",
        "--metrics=off",
        "--quiet",
        "--timeout",
        "120",
        "--max-target-bytes",
        "2000000",
        str(root),
    ]

    completed, duration, failure = _run(argv, settings.scanner_timeout_seconds)
    result.duration_ms = duration

    if failure == "timeout":
        result.status = "timeout"
        result.detail = "Semgrep exceeded its time budget."
        return result
    if failure or completed is None:
        result.status = "failed"
        result.detail = f"Semgrep could not run: {failure}"
        return result

    result.exit_code = completed.returncode
    result.status = "ran"

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        result.status = "failed"
        result.detail = "Semgrep returned unparsable JSON."
        return result

    for item in payload.get("results", [])[:2000]:
        extra = item.get("extra", {}) or {}
        start = (item.get("start") or {}).get("line") or 0
        end = (item.get("end") or {}).get("line") or start
        findings.append(
            Finding(
                scanner="semgrep",
                rule_id=item.get("check_id", "semgrep.unknown"),
                title=(extra.get("message") or "Semgrep rule matched")[:200],
                severity=_map_severity(extra.get("severity")),
                category="code",
                confidence="medium",
                description=(extra.get("message") or "")[:4000],
                file_path=item.get("path", ""),
                line_start=int(start),
                line_end=int(end),
                evidence=str(extra.get("lines", ""))[:600],
                remediation=_remediation(extra),
                metadata={"scanner_version": result.version},
            ).normalize()
        )

    result.findings = len(payload.get("results", []))
    result.detail = f"{result.findings} rule matches"
    return result


def run_gitleaks(root: Path, findings: list[Finding]) -> ToolResult:
    binary = resolve_binary("gitleaks")
    result = ToolResult(tool="gitleaks", version=version_of("gitleaks"))

    if not binary:
        result.status = "skipped"
        result.detail = "gitleaks is not installed on this worker."
        return result

    report = root / ".gitleaks-report.json"
    argv = [
        binary,
        "detect",
        "--source",
        str(root),
        "--no-git",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--exit-code",
        "0",
    ]

    completed, duration, failure = _run(argv, settings.scanner_timeout_seconds, cwd=root)
    result.duration_ms = duration

    if failure == "timeout":
        result.status = "timeout"
        result.detail = "Gitleaks exceeded its time budget."
        return result
    if failure or completed is None:
        result.status = "failed"
        result.detail = f"Gitleaks could not run: {failure}"
        return result

    result.exit_code = completed.returncode
    result.status = "ran"

    if not report.is_file():
        result.detail = "No report file was produced."
        return result

    try:
        items = json.loads(report.read_text(encoding="utf-8") or "[]")
    except (json.JSONDecodeError, OSError):
        result.status = "failed"
        result.detail = "Gitleaks report was unreadable."
        return result
    finally:
        report.unlink(missing_ok=True)

    for item in items[:2000]:
        start = int(item.get("StartLine") or 0)
        findings.append(
            Finding(
                scanner="gitleaks",
                rule_id=item.get("RuleID", "gitleaks.unknown"),
                title=(item.get("Description") or "Secret detected")[:200],
                severity="high",
                category="secrets",
                confidence="high",
                description=item.get("Description") or "",
                file_path=item.get("File", ""),
                line_start=start,
                line_end=int(item.get("EndLine") or start),
                evidence=redact(str(item.get("Secret") or item.get("Match") or "")),
                remediation="Rotate the credential, remove it from history and load it from a secret store.",
                metadata={"scanner_version": result.version},
            ).normalize()
        )

    result.findings = len(items)
    result.detail = f"{result.findings} secret matches"
    return result


def run_osv(root: Path, findings: list[Finding]) -> ToolResult:
    binary = resolve_binary("osv-scanner")
    result = ToolResult(tool="osv", version=version_of("osv"))

    if not binary:
        result.status = "skipped"
        result.detail = "osv-scanner is not installed on this worker."
        return result

    # OSV only sees declared dependencies. With no manifest it reports zero
    # matches, which would read as "no vulnerable dependencies" when nothing
    # was actually resolved. Report that honestly instead.
    manifests = {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
        "requirements.txt", "poetry.lock", "Pipfile.lock", "pyproject.toml",
        "go.mod", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock",
    }
    has_manifest = False
    for path in root.rglob("*"):
        if path.is_file() and path.name in manifests:
            has_manifest = True
            break
    if not has_manifest:
        result.status = "skipped"
        result.detail = (
            "No dependency manifest or lockfile was found, so no dependency was assessed."
        )
        return result

    argv = [binary, "--format", "json", "--recursive", str(root)]
    completed, duration, failure = _run(argv, settings.scanner_timeout_seconds, cwd=root)
    result.duration_ms = duration

    if failure == "timeout":
        result.status = "timeout"
        result.detail = "OSV-Scanner exceeded its time budget."
        return result
    if failure or completed is None:
        result.status = "failed"
        result.detail = f"OSV-Scanner could not run: {failure}"
        return result

    result.exit_code = completed.returncode
    result.status = "ran"

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        result.status = "failed"
        result.detail = "OSV-Scanner returned unparsable JSON."
        return result

    count = 0
    for entry in payload.get("results", [])[:500]:
        source = (entry.get("source") or {}).get("path", "")
        for package in entry.get("packages", [])[:200]:
            name = (package.get("package") or {}).get("name", "dependency")
            version = (package.get("package") or {}).get("version", "")
            for vuln in package.get("vulnerabilities", [])[:100]:
                count += 1
                findings.append(
                    Finding(
                        scanner="osv",
                        rule_id=vuln.get("id", "osv.unknown"),
                        title=f"Vulnerable dependency: {name}",
                        severity=_osv_severity(vuln),
                        category="dependencies",
                        confidence="high",
                        description=(vuln.get("summary") or vuln.get("details") or "")[:4000],
                        file_path=source,
                        evidence=redact(f"{name}@{version} affected by {vuln.get('id', '')}"),
                        remediation="Upgrade to a fixed version, or document why the vulnerable path is unreachable.",
                        metadata={"scanner_version": result.version, "package": name},
                    ).normalize()
                )

    result.findings = count
    result.detail = f"{count} advisory matches"
    return result


def _map_severity(value: object) -> str:
    text = str(value or "").upper()
    if text in {"ERROR", "CRITICAL"}:
        return "high"
    if text == "WARNING":
        return "medium"
    if text == "INFO":
        return "low"
    return "medium"


def _osv_severity(vuln: dict) -> str:
    for item in vuln.get("severity", []) or []:
        score = str(item.get("score", ""))
        if "CVSS:3" in score or "CVSS:4" in score:
            try:
                numeric = float(score.rsplit("/", 1)[-1]) if "/" in score else float(score)
            except ValueError:
                continue
            if numeric >= 9:
                return "critical"
            if numeric >= 7:
                return "high"
            if numeric >= 4:
                return "medium"
            return "low"
    return "high" if vuln.get("database_specific", {}).get("severity") == "HIGH" else "medium"


def _remediation(extra: dict) -> str:
    metadata = extra.get("metadata") or {}
    fix = metadata.get("fix") or metadata.get("remediation")
    if isinstance(fix, str) and fix.strip():
        return fix.strip()[:2000]
    return "Review the matched code path and apply the guidance in the rule message."
