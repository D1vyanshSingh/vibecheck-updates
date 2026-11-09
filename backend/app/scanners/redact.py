"""Secret redaction.

Evidence leaving the scanner must never contain a usable credential. The
prefix is kept so a human can identify the provider; the tail is replaced.
"""

from __future__ import annotations

import re

_LITERAL = re.compile(r"[A-Za-z0-9_\-]{12,}")

PROVIDER_HINTS = (
    "aws",
    "sk-",
    "ghp_",
    "gho_",
    "github_pat_",
    "sbp_",
    "eyJ",
    "AIza",
    "xoxb-",
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb",
    "redis://",
    "-----BEGIN",
)


def redact(value: str) -> str:
    """Replace the body of a secret-looking value with a length marker."""
    if not value:
        return ""
    text = value.strip()

    if text.startswith("-----BEGIN"):
        header = text.splitlines()[0]
        return f"{header} …redacted…"

    match = _LITERAL.search(text)
    if match:
        token = match.group(0)
        keep = token[:4]
        return text.replace(token, f"{keep}…redacted({len(token)})", 1)

    if len(text) > 8:
        return f"{text[:3]}…redacted({len(text)})"
    return "…redacted…"


def looks_secret(value: str) -> bool:
    lowered = value.lower()
    return any(hint.lower() in lowered for hint in PROVIDER_HINTS)


def redact_text(text: str) -> str:
    """Redact every long token in a free-form block (used for log lines)."""
    return _LITERAL.sub(lambda m: f"{m.group(0)[:4]}…redacted({len(m.group(0))})", text)
