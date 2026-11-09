"""Scan engine: runs the requested tools over an extracted source tree."""

from __future__ import annotations

from pathlib import Path

from app.scanners import external, native
from app.scanners.types import ScanCoverage, ScanOutput


def detect_technologies(root: Path) -> list[str]:
    markers = {
        "package.json": "node",
        "next.config.ts": "nextjs",
        "next.config.js": "nextjs",
        "requirements.txt": "python",
        "pyproject.toml": "python",
        "manage.py": "django",
        "Dockerfile": "docker",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "composer.json": "php",
        "Gemfile": "ruby",
    }
    found: list[str] = []
    for filename, label in markers.items():
        if any(root.glob(f"**/{filename}")):
            if label not in found:
                found.append(label)
    return found


def run_source_scan(root: Path, kinds: list[str]) -> ScanOutput:
    output = ScanOutput(coverage=ScanCoverage())
    output.coverage.technologies = detect_technologies(root)

    for kind in kinds:
        if kind == "native_secrets":
            findings = native.scan_secrets(root)
            output.findings.extend(findings)
            output.coverage.tools.append(
                external.ToolResult(tool="native_secrets", version="builtin", status="ran", findings=len(findings))
            )
        elif kind == "static_checks":
            findings = native.scan_static(root)
            output.findings.extend(findings)
            output.coverage.tools.append(
                external.ToolResult(tool="static_checks", version="builtin", status="ran", findings=len(findings))
            )
        elif kind == "semgrep":
            output.coverage.tools.append(external.run_semgrep(root, output.findings))
        elif kind == "gitleaks":
            output.coverage.tools.append(external.run_gitleaks(root, output.findings))
        elif kind == "osv":
            output.coverage.tools.append(external.run_osv(root, output.findings))

    skipped = [t.tool for t in output.coverage.tools if t.status in {"skipped", "failed", "timeout"}]
    if skipped:
        output.coverage.limitations.append(
            "These checks did not complete and their absence is not evidence of safety: "
            + ", ".join(sorted(skipped))
        )

    output.coverage.limitations.append(
        "Static observations describe code patterns. Impact requires reachability review "
        "that this run does not perform."
    )

    return output
