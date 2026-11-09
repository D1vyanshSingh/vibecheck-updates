"""OSV adapter behaviour around dependency coverage.

The adapter must never report "0 advisory matches" when it never resolved a
dependency. These tests stub the binary lookup and the process runner so the
manifest decision is exercised without needing osv-scanner installed.
"""

from __future__ import annotations

import subprocess

import pytest

from app.scanners import external


class _Runner:
    """Stands in for `_run` so no child process is started."""

    def __init__(self, stdout: str):
        self.stdout = stdout
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout, cwd=None):
        self.calls.append(list(argv))
        completed = subprocess.CompletedProcess(argv, 0, stdout=self.stdout, stderr="")
        return completed, 12, None


@pytest.fixture()
def stub_binary(monkeypatch):
    monkeypatch.setattr(external, "resolve_binary", lambda name: f"/stub/{name}")
    return "/stub/osv-scanner"


def test_missing_manifest_is_skipped_without_running_osv(tmp_path, stub_binary):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('no dependencies here')\n")

    runner = _Runner('{"results": []}')
    external_run = external._run
    external._run = runner
    try:
        findings: list[external.Finding] = []
        result = external.run_osv(tmp_path, findings)
    finally:
        external._run = external_run

    assert result.status == "skipped"
    assert "No dependency manifest or lockfile" in result.detail
    assert result.findings == 0
    assert findings == []
    assert runner.calls == [], "OSV must not run when nothing is declared"


def test_missing_binary_is_reported_as_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(external, "resolve_binary", lambda name: None)

    result = external.run_osv(tmp_path, [])

    assert result.status == "skipped"
    assert "not installed" in result.detail


def test_declared_dependencies_are_actually_scanned(tmp_path, stub_binary):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}\n')

    runner = _Runner('{"results": []}')
    external_run = external._run
    external._run = runner
    try:
        findings: list[external.Finding] = []
        result = external.run_osv(tmp_path, findings)
    finally:
        external._run = external_run

    assert result.status == "ran"
    assert result.detail == "0 advisory matches"
    assert runner.calls and runner.calls[0][0] == stub_binary
    assert "--recursive" in runner.calls[0]


def test_advisories_become_evidence_linked_findings(tmp_path, stub_binary):
    (tmp_path / "requirements.txt").write_text("django==1.0\n")
    payload = (
        '{"results": [{"source": {"path": "requirements.txt"}, "packages": '
        '[{"package": {"name": "django", "version": "1.0"}, "vulnerabilities": '
        '[{"id": "GHSA-test-0001", "summary": "Unpatched Django issue"}]}]}]}'
    )

    runner = _Runner(payload)
    external_run = external._run
    external._run = runner
    try:
        findings: list[external.Finding] = []
        result = external.run_osv(tmp_path, findings)
    finally:
        external._run = external_run

    assert result.status == "ran"
    assert result.findings == 1
    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-test-0001"
    assert findings[0].file_path == "requirements.txt"
    assert "django@1.0" in findings[0].evidence
