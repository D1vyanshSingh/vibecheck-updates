"""Assessment planning, validation and correlation.

Two rules hold everywhere in this module:

1. A plan is a list of tool *names* from the fixed registry. Anything else is
   dropped, and the drop is reported rather than silently ignored.
2. Correlation only restates what the scanners recorded. It never invents a
   finding, a severity or a confidence that a scanner did not produce.

The deterministic plan is always available, so a scan never depends on a model
being reachable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.scanners.registry import ALLOWED_KINDS, availability

MAX_STEPS = 8
MAX_REASON = 240

#: Reasons a plan step may exist for, used by the validator as a sanity check.
_STEP_PURPOSES = {
    "native_secrets": "credential-like strings in source",
    "static_checks": "high-signal source patterns",
    "semgrep": "rule-based static analysis",
    "gitleaks": "secret detection across tracked files",
    "osv": "known vulnerabilities in declared dependencies",
}


@dataclass(frozen=True)
class PlanStep:
    tool: str
    reason: str
    required: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "reason": self.reason, "required": self.required}


@dataclass
class Plan:
    steps: list[PlanStep] = field(default_factory=list)
    source: str = "fallback"
    rejected: list[str] = field(default_factory=list)
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "steps": [step.as_dict() for step in self.steps],
            "source": self.source,
            "rejected": self.rejected,
            "notes": self.notes,
        }


def validate_plan(raw: Any, available: dict[str, bool] | None = None) -> Plan:
    """Coerce model output into a plan that can only name allowlisted tools."""
    available = available if available is not None else availability()
    plan = Plan(source="model")

    if not isinstance(raw, dict):
        plan.source = "fallback"
        plan.steps = fallback_plan(available)
        plan.notes = "Plan was not a JSON object; deterministic plan used."
        return plan

    steps = raw.get("steps")
    if not isinstance(steps, list):
        plan.source = "fallback"
        plan.steps = fallback_plan(available)
        plan.notes = "Plan had no steps array; deterministic plan used."
        return plan

    seen: set[str] = set()
    for entry in steps[:MAX_STEPS]:
        if not isinstance(entry, dict):
            plan.rejected.append("non-object step")
            continue
        tool = entry.get("tool")
        if not isinstance(tool, str) or tool not in ALLOWED_KINDS:
            plan.rejected.append(str(tool)[:60])
            continue
        if tool in seen:
            plan.rejected.append(f"duplicate:{tool}")
            continue
        if not available.get(tool, False):
            plan.rejected.append(f"unavailable:{tool}")
            continue
        reason = entry.get("reason")
        reason = reason.strip()[:MAX_REASON] if isinstance(reason, str) and reason.strip() else _STEP_PURPOSES[tool]
        seen.add(tool)
        plan.steps.append(PlanStep(tool=tool, reason=reason))

    if plan.rejected:
        plan.notes = "Rejected by the allowlist: " + ", ".join(plan.rejected)
    if not plan.steps:
        plan.source = "fallback"
        plan.notes = (plan.notes + " " if plan.notes else "") + "No usable step; deterministic plan used."
        plan.steps = fallback_plan(available)
    return plan


def fallback_plan(available: dict[str, bool] | None = None) -> list[PlanStep]:
    """Deterministic plan: every available tool, in a fixed order."""
    available = available if available is not None else availability()
    order = ["native_secrets", "static_checks", "semgrep", "gitleaks", "osv"]
    return [
        PlanStep(tool=tool, reason=_STEP_PURPOSES[tool])
        for tool in order
        if available.get(tool, False)
    ]


def summarize(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts taken from stored rows only."""
    by_severity: dict[str, int] = {}
    by_scanner: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.get("severity", "info")] = by_severity.get(finding.get("severity", "info"), 0) + 1
        by_scanner[finding.get("scanner", "unknown")] = by_scanner.get(finding.get("scanner", "unknown"), 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_scanner": by_scanner,
    }


def correlate(findings: list[dict[str, Any]], coverage: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Observations that are strictly derived from stored findings + coverage.

    `kind` is one of: cluster, coverage_gap, exposure_chain.
    """
    observations: list[dict[str, Any]] = []
    coverage = coverage or {}

    by_file: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        path = finding.get("file_path") or ""
        if path:
            by_file.setdefault(path, []).append(finding)

    for path, group in sorted(by_file.items()):
        if len(group) < 2:
            continue
        scanners = sorted({str(item.get("scanner")) for item in group})
        observations.append(
            {
                "kind": "cluster",
                "title": f"{len(group)} findings in {path}",
                "body": (
                    f"{path} produced {len(group)} findings from {', '.join(scanners)}. "
                    "Concentrated findings usually mean the file was generated in one pass; "
                    "fix the pattern rather than each line."
                ),
                "finding_ids": [item.get("id") for item in group if item.get("id")],
            }
        )

    secret_files = {
        item.get("file_path")
        for item in findings
        if item.get("scanner") == "native_secrets" and item.get("file_path")
    }
    config_files = {
        item.get("file_path")
        for item in findings
        if item.get("rule_id") in {"VC-DANGEROUS-HTML", "VC-EVAL", "VC-DEBUG-MODE"}
    }
    for path in sorted(secret_files & config_files):
        observations.append(
            {
                "kind": "exposure_chain",
                "title": f"Secret and rendering risk share {path}",
                "body": (
                    f"{path} contains both a credential-like value and a risky sink. "
                    "Treat the secret as exposed if this file is shipped to a browser bundle."
                ),
                "finding_ids": [
                    item.get("id")
                    for item in findings
                    if item.get("file_path") == path and item.get("id")
                ],
            }
        )

    scanners = coverage.get("scanners") or {}
    if isinstance(scanners, dict):
        missing = sorted(name for name, state in scanners.items() if (state or {}).get("status") != "ran")
        if missing:
            observations.append(
                {
                    "kind": "coverage_gap",
                    "title": f"{len(missing)} check(s) did not run",
                    "body": (
                        "These checks produced no result: "
                        + ", ".join(missing)
                        + ". Their absence is not evidence that the code is clean."
                    ),
                    "finding_ids": [],
                }
            )

    return observations
