"""Built-in checks: find the pattern, redact the value, keep confidence honest."""

from __future__ import annotations

from pathlib import Path

from app.scanners.engine import run_source_scan
from app.scanners.native import scan_secrets, scan_static


def write(root: Path, name: str, content: str) -> None:
    target = root / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_detects_and_redacts_an_aws_key(tmp_path: Path) -> None:
    write(tmp_path, "config/settings.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_secrets(tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "vibecheck.secret.aws_access_key"
    assert finding.line_start == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.evidence


def test_detects_service_role_reference_in_client_code(tmp_path: Path) -> None:
    write(
        tmp_path,
        "lib/supabase.ts",
        "const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n",
    )
    findings = scan_static(tmp_path)
    assert any(f.rule_id == "vibecheck.code.service_role_client" for f in findings)
    assert all(f.confidence == "medium" for f in findings)


def test_clean_tree_has_no_findings(tmp_path: Path) -> None:
    write(tmp_path, "app/page.tsx", "export default function Page() { return null }\n")
    assert scan_secrets(tmp_path) == []
    assert scan_static(tmp_path) == []


def test_engine_records_coverage_and_limitations(tmp_path: Path) -> None:
    write(tmp_path, "package.json", '{"name":"fixture"}')
    output = run_source_scan(tmp_path, ["native_secrets", "static_checks"])
    coverage = output.coverage.as_dict()

    assert coverage["scanners"]["native_secrets"]["status"] == "ran"
    assert coverage["scanners"]["static_checks"]["status"] == "ran"
    assert "node" in coverage["technologies"]
    assert any("does not perform" in note for note in coverage["limitations"])


def test_findings_deduplicate_by_fingerprint(tmp_path: Path) -> None:
    write(tmp_path, "a.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    output = run_source_scan(tmp_path, ["native_secrets"])
    assert len(output.dedupe()) == len(output.findings) == 1
