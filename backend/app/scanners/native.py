"""Built-in checks that need no external binary.

These are deliberately narrow. A pattern match is reported as an observation
with medium confidence, never as proof of exploitability.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.scanners.redact import redact
from app.scanners.types import Finding

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "venv",
    ".venv",
    "__pycache__",
    "vendor",
    ".tools",
}

TEXT_SUFFIXES = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".java",
    ".php", ".cs", ".rs", ".kt", ".swift", ".sql", ".env", ".yml", ".yaml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".sh", ".md", ".txt", ".html",
}

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 4000

SECRET_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "vibecheck.secret.aws_access_key",
        "AWS access key id in source",
        "critical",
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    (
        "vibecheck.secret.private_key",
        "Private key block in source",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "vibecheck.secret.supabase_service_role",
        "Supabase service-role key in source",
        "critical",
        re.compile(r"service_role[^\"'\n]{0,20}eyJ[A-Za-z0-9_\-]{20,}"),
    ),
    (
        "vibecheck.secret.generic_bearer",
        "Hard-coded bearer token",
        "high",
        re.compile(r"(?i)authorization\s*[:=]\s*[\"']Bearer\s+[A-Za-z0-9._\-]{20,}"),
    ),
    (
        "vibecheck.secret.postgres_url",
        "Database URL with embedded password",
        "high",
        re.compile(r"postgres(?:ql)?://[^\s:\"']+:[^\s@\"']{6,}@"),
    ),
)

STATIC_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str], str], ...] = (
    (
        "vibecheck.code.raw_html",
        "Unsanitised HTML injection sink",
        "high",
        re.compile(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html"),
        "Confirm the value is sanitised (for example with a vetted HTML sanitiser) before it reaches the DOM.",
    ),
    (
        "vibecheck.code.eval",
        "Dynamic code execution",
        "high",
        re.compile(r"(?<![.\w])eval\s*\("),
        "Replace eval with an explicit parser or dispatch table; user input must never reach it.",
    ),
    (
        "vibecheck.code.tls_disabled",
        "TLS verification disabled",
        "critical",
        re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false"),
        "Re-enable certificate verification and fix the underlying trust chain instead.",
    ),
    (
        "vibecheck.code.service_role_client",
        "Service-role key referenced in client code",
        "critical",
        re.compile(r"NEXT_PUBLIC_[A-Z_]*SERVICE_ROLE"),
        "Service-role keys must only be read server-side; a NEXT_PUBLIC_ variable is bundled for the browser.",
    ),
    (
        "vibecheck.code.sql_concat",
        "SQL built by string interpolation",
        "high",
        re.compile(r"(?i)(?:execute|executemany|query)\s*\(\s*f?[\"'][^\"']*(?:SELECT|INSERT|UPDATE|DELETE)[^\"']*\{"),
        "Use parameterised queries; never interpolate values into SQL text.",
    ),
)


def _iter_files(root: Path):
    seen = 0
    for path in root.rglob("*"):
        if seen >= MAX_FILES:
            return
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name != ".env":
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        seen += 1
        yield path


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan_secrets(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rule_id, title, severity, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        scanner="native_secrets",
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        category="secrets",
                        confidence="high",
                        description=(
                            "A credential-shaped value was found in source. The value is "
                            "redacted here; rotate it if it is real."
                        ),
                        file_path=_relative(path, root),
                        line_start=line,
                        evidence=redact(match.group(0)),
                        remediation="Remove the value from source, rotate the credential and load it from a secret store.",
                    )
                )
    return findings


def scan_static(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rule_id, title, severity, pattern, remediation in STATIC_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        scanner="static_checks",
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        category="code",
                        confidence="medium",
                        description=(
                            "A risky pattern is present. This is an observation, not a "
                            "demonstrated vulnerability: the surrounding data flow must be "
                            "reviewed before impact is claimed."
                        ),
                        file_path=_relative(path, root),
                        line_start=line,
                        evidence=redact(match.group(0))[:400],
                        remediation=remediation,
                    )
                )
    return findings
