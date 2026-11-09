"""Benchmark corpus and runner.

The corpus is a fixture tree with a manifest that names every defect planted in
it. Running it gives objective numbers: a truth case with no matching finding is
a false negative, and a finding matching no truth case is a false positive. The
number is only meaningful for the tools that actually ran, so the coverage of
each run is stored alongside the counts.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CORPUS_ROOT = Path(__file__).resolve().parent / "corpus"
DEFAULT_KINDS = ["native_secrets", "static_checks", "semgrep", "gitleaks"]


def corpus_versions() -> list[str]:
    return sorted(path.name for path in CORPUS_ROOT.iterdir() if path.is_dir())


def load_manifest(version: str) -> dict[str, Any]:
    manifest_path = CORPUS_ROOT / version / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"Unknown corpus version: {version}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


@dataclass
class BenchmarkResult:
    corpus_version: str
    scanner: str
    true_positives: int
    false_positives: int
    false_negatives: int
    runtime_ms: int
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def total_cases(self) -> int:
        return self.true_positives + self.false_negatives

    def as_dict(self) -> dict[str, Any]:
        recall = self.true_positives / self.total_cases if self.total_cases else 0.0
        return {
            "corpus_version": self.corpus_version,
            "scanner": self.scanner,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "runtime_ms": self.runtime_ms,
            "recall": round(recall, 4),
            "meta": self.meta,
        }

    def to_row(self, workspace_id: str) -> dict[str, Any]:
        return {
            "workspace_id": workspace_id,
            "corpus_version": self.corpus_version,
            "scanner": self.scanner,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "runtime_ms": self.runtime_ms,
            "meta": self.meta,
        }


def _matches(finding: Any, case: dict[str, Any]) -> bool:
    path = (finding.file_path or "").replace("\\", "/")
    rule = (finding.rule_id or "").strip()
    return path.endswith(case["file"]) and (
        rule == case["rule"] or rule.endswith(case["rule"])
    )


def run_corpus(version: str = "v1", kinds: list[str] | None = None) -> BenchmarkResult:
    """Scan the corpus with the real registry and score it against the manifest."""
    from app.scanners.engine import run_source_scan

    manifest = load_manifest(version)
    cases: list[dict[str, Any]] = manifest.get("cases", [])
    files_root = CORPUS_ROOT / version / "files"
    requested = list(kinds or DEFAULT_KINDS)

    started = time.monotonic()
    output = run_source_scan(files_root, requested)
    runtime_ms = int((time.monotonic() - started) * 1000)

    findings = output.dedupe()
    matched_cases: set[int] = set()
    unmatched_findings: list[dict[str, Any]] = []

    for finding in findings:
        hit = next(
            (index for index, case in enumerate(cases) if _matches(finding, case)),
            None,
        )
        if hit is None:
            unmatched_findings.append(
                {
                    "rule_id": finding.rule_id,
                    "file_path": finding.file_path,
                    "severity": finding.severity,
                }
            )
        else:
            matched_cases.add(hit)

    coverage = output.coverage.as_dict()
    ran = sorted(
        name
        for name, info in (coverage.get("scanners") or {}).items()
        if info.get("status") == "ran"
    )
    skipped = {
        name: info.get("detail")
        for name, info in (coverage.get("scanners") or {}).items()
        if info.get("status") != "ran"
    }

    return BenchmarkResult(
        corpus_version=version,
        scanner=",".join(requested),
        true_positives=len(matched_cases),
        false_positives=len(unmatched_findings),
        false_negatives=len(cases) - len(matched_cases),
        runtime_ms=runtime_ms,
        meta={
            "cases": len(cases),
            "tools_requested": requested,
            "tools_ran": ran,
            "tools_not_ran": skipped,
            "unmatched_findings": unmatched_findings[:20],
            "missing_cases": [
                cases[index]["id"]
                for index in range(len(cases))
                if index not in matched_cases
            ],
            "note": (
                "Counts cover only the tools listed in tools_ran. A skipped tool "
                "means its detection was never measured."
            ),
        },
    )


__all__ = ["BenchmarkResult", "corpus_versions", "load_manifest", "run_corpus"]
