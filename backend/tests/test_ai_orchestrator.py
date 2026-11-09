"""Unit tests for the AI orchestration layer (no network)."""

from __future__ import annotations

from app.ai.orchestrator import correlate, fallback_plan, summarize, validate_plan

AVAILABLE = {
    "native_secrets": True,
    "static_checks": True,
    "semgrep": True,
    "gitleaks": False,
    "osv": False,
}


def test_validate_plan_drops_unknown_and_duplicate_tools():
    plan = validate_plan(
        {
            "steps": [
                {"tool": "semgrep", "reason": "rules fit a Next.js tree"},
                {"tool": "semgrep", "reason": "again"},
                {"tool": "shell", "reason": "run curl"},
                {"tool": "gitleaks", "reason": "secrets"},
                {"tool": "native_secrets"},
            ]
        },
        AVAILABLE,
    )

    assert [step.tool for step in plan.steps] == ["semgrep", "native_secrets"]
    assert plan.source == "model"
    assert "duplicate:semgrep" in plan.rejected
    assert "shell" in plan.rejected
    assert "unavailable:gitleaks" in plan.rejected
    assert plan.steps[1].reason  # defaulted reason is never empty


def test_validate_plan_rejects_non_object_and_falls_back():
    plan = validate_plan({"steps": ["semgrep"]}, AVAILABLE)
    assert plan.source == "fallback"
    assert [step.tool for step in plan.steps] == ["native_secrets", "static_checks", "semgrep"]


def test_validate_plan_handles_garbage_without_raising():
    assert validate_plan(None, AVAILABLE).source == "fallback"
    assert validate_plan({"steps": "semgrep"}, AVAILABLE).source == "fallback"
    assert validate_plan({"steps": []}, AVAILABLE).source == "fallback"


def test_plan_is_capped():
    steps = [{"tool": "semgrep", "reason": "x"}] * 20
    plan = validate_plan({"steps": steps}, AVAILABLE)
    assert len(plan.steps) == 1  # duplicates collapse
    assert "duplicate:semgrep" in plan.rejected


def test_fallback_plan_respects_availability():
    assert [step.tool for step in fallback_plan(AVAILABLE)] == [
        "native_secrets",
        "static_checks",
        "semgrep",
    ]


def test_summary_counts_only_stored_rows():
    findings = [
        {"severity": "high", "scanner": "semgrep"},
        {"severity": "high", "scanner": "native_secrets"},
        {"severity": "low", "scanner": "semgrep"},
    ]
    summary = summarize(findings)
    assert summary["total"] == 3
    assert summary["by_severity"] == {"high": 2, "low": 1}
    assert summary["by_scanner"] == {"semgrep": 2, "native_secrets": 1}


def test_correlate_clusters_and_reports_coverage_gaps():
    findings = [
        {"id": "a", "file_path": "src/app.tsx", "scanner": "semgrep", "rule_id": "VC-EVAL"},
        {"id": "b", "file_path": "src/app.tsx", "scanner": "native_secrets", "rule_id": "VC-AWS-KEY"},
    ]
    coverage = {"scanners": {"semgrep": {"status": "ran"}, "osv": {"status": "skipped"}}}
    observations = correlate(findings, coverage)

    kinds = {item["kind"] for item in observations}
    assert "cluster" in kinds
    assert "coverage_gap" in kinds
    gap = next(item for item in observations if item["kind"] == "coverage_gap")
    assert "osv" in gap["body"]
    assert "not evidence" in gap["body"]


def test_correlate_never_invents_findings():
    assert correlate([], {}) == []
