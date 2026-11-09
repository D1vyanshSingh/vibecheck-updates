"""Report generation: JSON, HTML and PDF from stored rows.

The report is an assembly of what the database already holds. It does not run
a scan, and it never adds a finding, a severity or a coverage claim. Where a
check did not run, the report says so in its own section.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ReportDocument:
    report_type: str
    workspace: dict[str, Any]
    project: dict[str, Any]
    scan: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    observations: list[dict[str, Any]] = field(default_factory=list)
    generated_at: str = field(default_factory=_now)
    version: int = 1

    def summary(self) -> dict[str, Any]:
        by_severity = {level: 0 for level in SEVERITY_ORDER}
        by_scanner: dict[str, int] = {}
        for finding in self.findings:
            level = finding.get("severity") or "info"
            by_severity[level] = by_severity.get(level, 0) + 1
            scanner = finding.get("scanner") or "unknown"
            by_scanner[scanner] = by_scanner.get(scanner, 0) + 1
        return {
            "total": len(self.findings),
            "by_severity": by_severity,
            "by_scanner": by_scanner,
            "highest": next((lvl for lvl in SEVERITY_ORDER if by_severity.get(lvl)), "none"),
        }

    def coverage_limitations(self) -> list[str]:
        coverage = self.scan.get("coverage") or {}
        if isinstance(coverage, str):
            try:
                coverage = json.loads(coverage)
            except json.JSONDecodeError:
                coverage = {}
        limitations = list(coverage.get("limitations") or [])
        scanners = coverage.get("scanners") or {}
        if isinstance(scanners, dict):
            for name, state in sorted(scanners.items()):
                status = (state or {}).get("status")
                if status and status != "ran":
                    limitations.append(f"{name}: {status} — this check produced no result.")
        if not limitations:
            limitations.append(
                "No coverage record was stored with this scan, so completeness cannot be claimed."
            )
        return limitations

    def as_dict(self) -> dict[str, Any]:
        return {
            "report_type": self.report_type,
            "version": self.version,
            "generated_at": self.generated_at,
            "workspace": {"id": self.workspace.get("id"), "name": self.workspace.get("name")},
            "project": {
                "id": self.project.get("id"),
                "name": self.project.get("name"),
                "project_type": self.project.get("project_type"),
                "website_url": self.project.get("website_url"),
            },
            "scan": {
                "id": self.scan.get("id"),
                "status": self.scan.get("status"),
                "trigger": self.scan.get("trigger"),
                "created_at": self.scan.get("created_at"),
                "completed_at": self.scan.get("completed_at"),
                "coverage": self.scan.get("coverage"),
            },
            "summary": self.summary(),
            "findings": [
                {
                    **{
                        key: finding.get(key)
                        for key in (
                            "id",
                            "title",
                            "severity",
                            "status",
                            "category",
                            "scanner",
                            "confidence",
                            "rule_id",
                            "file_path",
                            "line_start",
                            "description",
                            "remediation",
                            "redacted_evidence",
                        )
                    },
                    "evidence": self.evidence.get(finding.get("id", ""), []),
                }
                for finding in self.sorted_findings()
            ],
            "observations": self.observations,
            "limitations": self.coverage_limitations(),
            "honesty": (
                "Static and header observations describe patterns and configuration. "
                "They do not prove exploitability, and checks that did not run are "
                "listed as limitations rather than treated as clean."
            ),
        }

    def sorted_findings(self) -> list[dict[str, Any]]:
        def rank(finding: dict[str, Any]) -> tuple[int, str]:
            severity = finding.get("severity") or "info"
            return (SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 9, finding.get("title") or "")

        return sorted(self.findings, key=rank)


def build_report(
    *,
    report_type: str,
    workspace: dict[str, Any],
    project: dict[str, Any],
    scan: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: dict[str, list[dict[str, Any]]] | None = None,
    observations: list[dict[str, Any]] | None = None,
    version: int = 1,
) -> ReportDocument:
    if report_type not in ("client", "technical"):
        raise ValueError("report_type must be client or technical")
    return ReportDocument(
        report_type=report_type,
        workspace=workspace or {},
        project=project or {},
        scan=scan or {},
        findings=list(findings or []),
        evidence=evidence or {},
        observations=list(observations or []),
        version=version,
    )


def render_json(document: ReportDocument) -> str:
    return json.dumps(document.as_dict(), indent=2, default=str)


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def render_html(document: ReportDocument) -> str:
    data = document.as_dict()
    summary = data["summary"]
    rows = []
    for finding in data["findings"]:
        location = finding.get("file_path") or ""
        if location and finding.get("line_start"):
            location = f"{location}:{finding['line_start']}"
        evidence = finding.get("evidence") or []
        evidence_html = "".join(
            f"<pre>{_e(item.get('snippet'))}</pre>" for item in evidence[:3] if item.get("snippet")
        )
        rows.append(
            f"""
            <article class="finding sev-{_e(finding['severity'])}">
              <header>
                <span class="badge">{_e(SEVERITY_LABEL.get(finding['severity'], finding['severity']))}</span>
                <h3>{_e(finding['title'])}</h3>
              </header>
              <p class="meta">{_e(finding['scanner'])} · {_e(finding['confidence'])} confidence
                 {(' · ' + _e(location)) if location else ''}</p>
              <p>{_e(finding.get('description'))}</p>
              {evidence_html}
              <p class="meta">Suggested direction</p>
              <p>{_e(finding.get('remediation'))}</p>
            </article>"""
        )

    observations = "".join(
        f"<li><strong>{_e(item.get('title'))}</strong><p>{_e(item.get('body'))}</p></li>"
        for item in data["observations"]
    )
    limitations = "".join(f"<li>{_e(item)}</li>" for item in data["limitations"])

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_e(data['project'].get('name'))} — VibeCheck {_e(document.report_type)} report</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: Inter, system-ui, sans-serif; margin: 0 auto; max-width: 900px; padding: 48px 24px; color: #14121c; }}
  h1 {{ font-size: 30px; margin: 0 0 4px; }}
  h2 {{ font-size: 18px; margin-top: 40px; border-bottom: 1px solid #e5e1f2; padding-bottom: 8px; }}
  .brand {{ letter-spacing: .22em; font-size: 11px; color: #702bff; text-transform: uppercase; }}
  .meta {{ color: #6b6580; font-size: 12px; margin: 4px 0; }}
  .finding {{ border: 1px solid #e5e1f2; border-radius: 12px; padding: 16px 18px; margin: 14px 0; }}
  .badge {{ display: inline-block; font-size: 10px; letter-spacing: .12em; padding: 3px 8px; border-radius: 999px; background: #f1ecff; color: #4c1d95; }}
  .sev-critical .badge {{ background: #fee2e2; color: #991b1b; }}
  .sev-high .badge {{ background: #ffedd5; color: #9a3412; }}
  pre {{ background: #f7f5ff; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; }}
  .sum table {{ border-collapse: collapse; width: 100%; }}
  .sum td, .sum th {{ border-bottom: 1px solid #eee; padding: 6px 8px; text-align: left; font-size: 13px; }}
  footer {{ margin-top: 48px; color: #6b6580; font-size: 11px; }}
</style>
</head>
<body>
  <p class="brand">VibeCheck · {_e(document.report_type)} report</p>
  <h1>{_e(data['project'].get('name'))}</h1>
  <p class="meta">Workspace {_e(data['workspace'].get('name'))} · scan {_e(data['scan'].get('id'))} · version {data['version']}</p>
  <p class="meta">Generated {_e(data['generated_at'])} · status {_e(data['scan'].get('status'))}</p>

  <h2>Summary</h2>
  <div class="sum">
    <table>
      <tr><th>Findings</th><td>{summary['total']}</td></tr>
      {''.join(f"<tr><th>{_e(SEVERITY_LABEL.get(level, level))}</th><td>{count}</td></tr>" for level, count in summary['by_severity'].items())}
      <tr><th>Highest severity</th><td>{_e(summary['highest'])}</td></tr>
    </table>
  </div>

  <h2>Findings</h2>
  {''.join(rows) or '<p>No findings were stored for this scan.</p>'}

  <h2>Observations</h2>
  <ul>{observations or '<li>No correlations were produced for this scan.</li>'}</ul>

  <h2>Coverage and limitations</h2>
  <ul>{limitations}</ul>
  <p>{_e(data['honesty'])}</p>

  <footer>Generated by VibeCheck from stored scan records. Evidence is redacted at collection time.</footer>
</body>
</html>"""


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf(document: ReportDocument) -> bytes:
    """Minimal single-document PDF built without third-party dependencies.

    Text-only, one column, Helvetica. Enough to hand a reviewer a file; the
    HTML output remains the richer artifact.
    """
    data = document.as_dict()
    lines: list[str] = [
        f"VibeCheck - {document.report_type} report",
        f"Project: {data['project'].get('name')}",
        f"Workspace: {data['workspace'].get('name')}",
        f"Scan: {data['scan'].get('id')}  Status: {data['scan'].get('status')}",
        f"Generated: {data['generated_at']}  Version: {data['version']}",
        "",
        f"Findings: {data['summary']['total']}  Highest: {data['summary']['highest']}",
        "",
    ]
    for finding in data["findings"]:
        lines.append(f"[{str(finding['severity']).upper()}] {finding['title']}")
        if finding.get("file_path"):
            lines.append(f"    at {finding['file_path']}")
        wrapped = _wrap(finding.get("remediation") or "", 92)
        lines.extend(f"    fix: {part}" for part in wrapped[:3])
        lines.append("")
    lines.append("Coverage and limitations")
    for item in data["limitations"]:
        lines.extend(_wrap(item, 92)[:3])
    lines.append("")
    lines.append("Observations describe patterns, not proven exploitability.")

    pages = [lines[i : i + 52] for i in range(0, len(lines), 52)] or [[""]]

    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{3 + index * 2} 0 R" for index in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())

    font_obj = 3 + len(pages) * 2

    for index, page_lines in enumerate(pages):
        page_obj = 3 + index * 2
        content_obj = page_obj + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> /Contents {content_obj} 0 R >>".encode()
        )
        stream_parts = ["BT", "/F1 11 Tf", "14 TL", "48 794 Td"]
        for line in page_lines:
            stream_parts.append(f"({_pdf_escape(line[:110])}) Tj T*")
        stream_parts.append("ET")
        stream = "\n".join(stream_parts).encode("latin-1", "replace")
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")

    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"

    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    ).encode()
    return bytes(out)


def _wrap(text: str, width: int) -> list[str]:
    words = (text or "").split()
    if not words:
        return [""]
    lines, current = [], ""
    for word in words:
        if len(current) + len(word) + 1 > width and current:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
