"""Benchmark corpus scoring.

The last test executes the built-in checks against the real corpus tree; the
others pin the matching rules with synthetic scanner output.
"""

from __future__ import annotations

import json

from app.benchmark import CORPUS_ROOT, load_manifest, run_corpus
from app.scanners.types import Finding, ScanCoverage, ScanOutput, ToolResult


def test_manifest_cases_all_exist_in_the_corpus():
    manifest = load_manifest("v1")
    cases = manifest["cases"]

    assert len(cases) == 3
    for case in cases:
        path = CORPUS_ROOT / "v1" / "files" / case["file"]
        assert path.is_file(), case["file"]
        assert path.read_text(encoding="utf-8").strip(), case["file"]


def test_manifest_rules_are_native_rule_ids():
    rules = {case["rule"] for case in load_manifest("v1")["cases"]}
    assert rules == {
        "vibecheck.secret.aws_access_key",
        "vibecheck.code.eval",
        "vibecheck.code.service_role_client",
    }


def _output(findings):
    coverage = ScanCoverage(
        tools=[ToolResult(tool="native_secrets", status="ran", detail="x")],
        technologies=[],
        limitations=[],
    )
    return ScanOutput(findings=list(findings), coverage=coverage)


def _finding(rule_id: str, file_path: str):
    return Finding(
        scanner="native_secrets",
        rule_id=rule_id,
        title="t",
        severity="high",
        category="secrets",
        confidence="high",
        description="d",
        file_path=file_path,
    )


def test_scoring_counts_misses_and_extras(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.engine.run_source_scan",
        lambda root, kinds: _output(
            [
                _finding("vibecheck.secret.aws_access_key", "app/settings.py"),
                _finding("vibecheck.code.eval", "app/handlers.py"),
                _finding("vibecheck.other.rule", "app/handlers.py"),
            ]
        ),
    )

    result = run_corpus("v1", ["native_secrets"])
    payload = result.as_dict()

    assert payload["true_positives"] == 2
    assert payload["false_negatives"] == 1
    assert payload["false_positives"] == 1
    assert payload["meta"]["missing_cases"] == ["service-role-in-client-bundle"]
    assert payload["meta"]["unmatched_findings"][0]["rule_id"] == "vibecheck.other.rule"


def test_two_findings_for_one_case_are_not_two_hits(monkeypatch):
    monkeypatch.setattr(
        "app.scanners.engine.run_source_scan",
        lambda root, kinds: _output(
            [
                _finding("vibecheck.secret.aws_access_key", "app/settings.py"),
                _finding("vibecheck.secret.aws_access_key", "app/settings.py"),
            ]
        ),
    )

    payload = run_corpus("v1", ["native_secrets"]).as_dict()

    assert payload["true_positives"] == 1
    assert payload["false_negatives"] == 2
    assert payload["false_positives"] == 0


def test_skipped_tools_are_recorded_not_hidden(monkeypatch):
    skipped = ScanCoverage(
        tools=[
            ToolResult(tool="native_secrets", status="ran", detail="2 matches"),
            ToolResult(tool="gitleaks", status="skipped", detail="not installed"),
        ]
    )
    monkeypatch.setattr(
        "app.scanners.engine.run_source_scan",
        lambda root, kinds: ScanOutput(findings=[], coverage=skipped),
    )

    payload = run_corpus("v1", ["native_secrets", "gitleaks"]).as_dict()

    assert payload["meta"]["tools_ran"] == ["native_secrets"]
    assert payload["meta"]["tools_not_ran"] == {"gitleaks": "not installed"}
    assert "never measured" in payload["meta"]["note"]


def test_real_corpus_is_fully_detected_by_the_builtin_checks():
    payload = run_corpus("v1", ["native_secrets", "static_checks"]).as_dict()

    assert payload["meta"]["tools_ran"] == ["native_secrets", "static_checks"]
    assert payload["true_positives"] == 3
    assert payload["false_negatives"] == 0
    assert payload["false_positives"] == 0
    assert payload["recall"] == 1.0
    assert json.loads(json.dumps(payload["meta"]))  # meta is JSON-safe for jsonb
