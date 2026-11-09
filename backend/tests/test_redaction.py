"""Secrets must never survive into stored evidence."""

from __future__ import annotations

from app.scanners.redact import looks_secret, redact, redact_text


def test_redact_keeps_a_prefix_and_drops_the_body() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    out = redact(secret)
    assert out.startswith("AKIA")
    assert secret not in out
    assert "redacted" in out


def test_redact_private_key_block() -> None:
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
    out = redact(block)
    assert "BEGIN RSA PRIVATE KEY" in out
    assert "MIIEow" not in out


def test_looks_secret_detects_common_prefixes() -> None:
    assert looks_secret("sk-live-abcdef123456")
    assert looks_secret("postgres://user:pass@host/db")
    assert not looks_secret("hello world")


def test_redact_text_masks_every_token() -> None:
    text = "api_key=sk_live_1234567890abcdef and token=ghp_0987654321fedcba"
    out = redact_text(text)
    assert "sk_live_1234567890abcdef" not in out
    assert "ghp_0987654321fedcba" not in out
