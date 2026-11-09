"""SSRF guard tests. No network access is required."""

from __future__ import annotations

import pytest

from app.assessment.urlguard import URLGuardError, guard_url

BLOCKED = [
    "http://127.0.0.1/admin",
    "http://localhost:3000",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://[::1]/",
    "http://[fd00::1]/",
    "http://0.0.0.0/",
    "http://metadata.google.internal/",
    "http://printer.local/",
    "file:///etc/passwd",
    "ftp://example.com/",
    "http://user:pass@example.com/",
    "http://example.com:99999/",
]


@pytest.mark.parametrize("url", BLOCKED)
def test_refuses_dangerous_targets(url):
    with pytest.raises(URLGuardError):
        guard_url(url)


def test_accepts_a_public_ip_literal():
    guarded = guard_url("https://93.184.216.34/path?q=1")
    assert guarded.scheme == "https"
    assert guarded.host == "93.184.216.34"
    assert guarded.port == 443
    assert guarded.addresses == ("93.184.216.34",)


def test_adds_https_when_scheme_is_missing():
    assert guard_url("93.184.216.34").normalized.startswith("https://")


def test_refuses_empty_and_over_long_urls():
    with pytest.raises(URLGuardError):
        guard_url("   ")
    with pytest.raises(URLGuardError):
        guard_url("https://example.com/" + "a" * 3000)


def test_refuses_unresolvable_host():
    with pytest.raises(URLGuardError):
        guard_url("https://this-host-should-not-exist.invalid/")
