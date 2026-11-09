"""Report rendering tests."""

from __future__ import annotations

import json

import pytest

from app.reports import build_report, render_html, render_json, render_pdf

WORKSPACE = {"id": "ws-1", "name": "Acme <script>alert(1)</script>"}
PROJECT = {"id": "p-1", "name": "Shop", "project_type": "web_app"}
SCAN = {
    "id": "s-1",
    "status": "completed",
    "trigger": "manual",
    "coverage": {
        "scanners": {"semgrep": {"status": "ran"}, "osv": {"status": "skipped"}},
        "limitations": ["Static observations describe code patterns."],
    },
}
FINDINGS = [
    {
        "id": "f-1",
        "title": "Hardcoded AWS key",
        "severity": "critical",
        "scanner": "native_secrets",
        "confidence": "high",
        "file_path": "src/config.py",
        "line_start": 4,
        "description": "A credential-like value was found.",
        "remediation": "Move it to a secret store and rotate it.",
        "redacted_evidence": 'AWS_ACCESS_KEY_ID = "AKIA…"',
    },
    {
        "id": "f-2",
        "title": "Missing CSP",
        "severity": "medium",
        "scanner": "web_headers",
        "confidence": "high",
        "file_path": "https://example.com/",
    },
]


def make_document(report_type: str = "technical"):
    return build_report(
        report_type=report_type,
        workspace=WORKSPACE,
        project=PROJECT,
        scan=SCAN,
        findings=FINDINGS,
        evidence={"f-1": [{"snippet": 'AWS_ACCESS_KEY_ID = "AKIA…"'}]},
        observations=[{"kind": "cluster", "title": "Two findings", "body": "Same file."}],
    )


def test_build_report_rejects_unknown_type():
    with pytest.raises(ValueError):
        build_report(
            report_type="executive",
            workspace=WORKSPACE,
            project=PROJECT,
            scan=SCAN,
            findings=FINDINGS,
        )


def test_json_report_is_serializable_and_ordered():
    data = json.loads(render_json(make_document()))
    assert data["summary"]["total"] == 2
    assert data["summary"]["highest"] == "critical"
    assert [f["severity"] for f in data["findings"]] == ["critical", "medium"]
    assert data["findings"][0]["evidence"][0]["snippet"].startswith("AWS_ACCESS_KEY_ID")
    assert any("osv: skipped" in item for item in data["limitations"])


def test_report_states_coverage_gaps_and_honesty():
    data = json.loads(render_json(make_document("client")))
    joined = " ".join(data["limitations"])
    assert "skipped" in joined
    assert "not evidence" in joined or "no result" in joined
    assert "do not prove exploitability" in data["honesty"]


def test_html_report_escapes_customer_content():
    html = render_html(make_document())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Coverage and limitations" in html
    assert "Hardcoded AWS key" in html


def test_pdf_is_a_valid_skeleton():
    pdf = render_pdf(make_document())
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"/Type /Catalog" in pdf
    assert b"Helvetica" in pdf
    assert b"Hardcoded AWS key" in pdf


def test_report_without_coverage_admits_it():
    document = build_report(
        report_type="technical",
        workspace=WORKSPACE,
        project=PROJECT,
        scan={"id": "s-2", "status": "completed"},
        findings=[],
    )
    assert "cannot be claimed" in " ".join(document.coverage_limitations())
