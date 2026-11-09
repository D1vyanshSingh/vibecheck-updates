"""Normalized scanner output types."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("low", "medium", "high")


@dataclass
class Finding:
    scanner: str
    rule_id: str
    title: str
    severity: str = "medium"
    category: str = "general"
    confidence: str = "medium"
    description: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    affected_component: str = ""
    remediation: str = ""
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalize(self) -> "Finding":
        self.severity = self.severity.lower()
        if self.severity not in SEVERITIES:
            self.severity = "medium"
        self.confidence = self.confidence.lower()
        if self.confidence not in CONFIDENCES:
            self.confidence = "medium"
        self.title = (self.title or self.rule_id)[:200]
        self.category = (self.category or "general")[:60]
        self.description = (self.description or "")[:4000]
        self.remediation = (self.remediation or "")[:8000]
        self.file_path = (self.file_path or "")[:400]
        self.line_end = max(self.line_end, self.line_start)
        return self

    @property
    def fingerprint(self) -> str:
        raw = "|".join(
            (
                self.scanner,
                self.rule_id,
                self.file_path,
                str(self.line_start),
                self.title,
            )
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:64]

    def to_row(
        self, *, workspace_id: str, project_id: str, scan_id: str | None, source_id: str | None
    ) -> dict[str, Any]:
        return {
            "workspace_id": workspace_id,
            "project_id": project_id,
            "scan_id": scan_id,
            "source_id": source_id,
            "severity": self.severity,
            "status": "open",
            "category": self.category,
            "title": self.title,
            "description": self.description or None,
            "file_path": self.file_path or None,
            "line_start": self.line_start or None,
            "line_end": self.line_end or None,
            "affected_component": self.affected_component or None,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "scanner": self.scanner,
            "scanner_version": self.metadata.get("scanner_version"),
            "confidence": self.confidence,
            "remediation": self.remediation or None,
            "redacted_evidence": self.evidence or None,
            "metadata": self.metadata or None,
        }


@dataclass
class ToolResult:
    tool: str
    version: str = ""
    status: str = "skipped"  # ran | skipped | failed | timeout
    exit_code: int | None = None
    duration_ms: int = 0
    detail: str = ""
    findings: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "detail": self.detail,
            "findings": self.findings,
        }


@dataclass
class ScanCoverage:
    tools: list[ToolResult] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanners": {
                item.tool: {"status": item.status, "detail": item.detail}
                for item in self.tools
            },
            "tool_runs": [item.as_dict() for item in self.tools],
            "technologies": self.technologies,
            "limitations": self.limitations,
        }


@dataclass
class ScanOutput:
    findings: list[Finding] = field(default_factory=list)
    coverage: ScanCoverage = field(default_factory=ScanCoverage)

    def dedupe(self) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for finding in self.findings:
            seen.setdefault(finding.fingerprint, finding.normalize())
        return list(seen.values())
