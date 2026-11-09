"""Report generation: JSON (machine), HTML (human), terminal (operator)."""

from __future__ import annotations

import csv
import html
import json
import platform
import shlex
import socket
import time
from datetime import datetime, timezone

from . import __version__, branding, cvss as cvss_mod, guidance as guidance_mod
from .checks import SEVERITY_ORDER, Finding, claims_conflict
from .scanner import PortService

# 1.3 adds ``metadata.report_name`` (the -r name; ``metadata.title`` follows it);
# 1.2 adds the per-finding attack/detection/next_step guidance and
# ``entry_point``; 1.1 added ``coverage`` and the per-finding ``cvss`` block.
# Every earlier key keeps its meaning, so an older report stays readable.
REPORT_SCHEMA_VERSION = "1.3"

SEV_META = {
    "critical":     {"label": "Critical",     "hex": "#7F1D1D", "wash": "#FBE9EB"},
    "high":         {"label": "High",         "hex": "#B42318", "wash": "#FDECEA"},
    "medium":       {"label": "Medium",       "hex": "#B54708", "wash": "#FEF3E2"},
    "low":          {"label": "Low",          "hex": "#175CD3", "wash": "#EAF1FE"},
    "informational": {"label": "Informational", "hex": "#475467", "wash": "#F1F3F5"},
}
ANSI = {
    "critical": "\033[1;95m", "high": "\033[1;91m", "medium": "\033[1;93m",
    "low": "\033[1;96m", "informational": "\033[1;37m",
}
ANSI_RESET = "\033[0m"


def confirmed_only(findings: list[Finding]) -> list[Finding]:
    """Findings proven by protocol-level evidence, for ``--strict`` reports."""
    return [finding for finding in findings if finding.confidence == "certain"]


def build_report(targets: list[str], ports: list[int], services: list[PortService],
                 findings: list[Finding], started_at: str, duration_s: float,
                 options: dict | None = None, scan_meta: dict | None = None,
                 advisory_meta: dict | None = None) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    scan_meta = scan_meta or {}
    options = options or {}
    engine = scan_meta.get("engine") or "native"
    method = ("nmap service/version detection (-sV) followed by native TLS, "
              "HTTP and banner evidence collection" if engine == "nmap"
              else "async TCP connect scan with banner, TLS and HTTP probing")
    coverage = _coverage(targets, ports, services, started_at, duration_s,
                         scan_meta, options, advisory_meta or {})
    report_name = str(options.get("report_name") or "").strip()
    return {
        "report_version": REPORT_SCHEMA_VERSION,
        "metadata": {
            "title": report_name or "Vulnerability Scan Report",
            "report_name": report_name,
            "scanner": {"name": "vulnscan", "version": __version__},
            "engine": engine,
            "scan": scan_meta,
            "advisory_db": advisory_meta or {},
            "scan_source": coverage["scan_source"],
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "started_at": started_at,
            "duration_seconds": round(duration_s, 2),
        },
        "scope": {
            "targets": targets,
            "ports_scanned": len(ports),
            "port_range": _describe_ports(ports),
            "method": method,
            "options": options,
        },
        "coverage": coverage,
        "summary": {
            "total_findings": len(findings),
            "counts_by_severity": counts,
            "open_services": len(services),
        },
        "services": [_service_dict(s) for s in services],
        "findings": [_finding_dict(f) for f in findings],
    }


_NOT_TESTED = (
    "UDP, SCTP and any port outside the TCP list above.",
    "Authentication, credential guessing, exploitation and denial of service — "
    "the scan is non-destructive by design.",
    "Application-layer business logic and anything behind a login.",
    "Services filtered by a firewall, IDS/IPS or rate limiting; absence of a "
    "finding is not proof of absence.",
    "TLS 1.0/1.1 unless --legacy-tls was used.",
    "Vulnerabilities that need a version the banner does not reveal: version "
    "matching is only as good as the identification behind it.",
    "NSE scripts outside the selected profile.",
)


def _coverage(targets: list[str], ports: list[int], services: list[PortService],
              started_at: str, duration_s: float, scan_meta: dict,
              options: dict, advisory_meta: dict) -> dict:
    """Everything needed to reproduce and bound the scan.

    A report that claims coverage it did not perform is worse than one that
    says nothing; this block is generated from what actually ran (the engine's
    own metadata), not from what was requested.
    """
    engine = scan_meta.get("engine") or "native"
    argv = scan_meta.get("argv") or []
    return {
        "engine": engine,
        "engine_version": scan_meta.get("version") or "",
        "requested_engine": scan_meta.get("requested_engine") or options.get("engine_requested", ""),
        "fallback_reason": scan_meta.get("fallback_reason") or "",
        "argv": list(argv),
        "command": shlex.join(str(part) for part in argv) if argv else "",
        "privileged": bool(scan_meta.get("privileged")),
        "scripts": list(scan_meta.get("scripts") or []),
        "nse_profile": options.get("nse_profile", ""),
        "version_intensity": options.get("version_intensity"),
        "timeout_s": options.get("timeout"),
        "host_timeout_s": scan_meta.get("host_timeout_seconds"),
        "concurrency": options.get("concurrency"),
        "started_at": started_at,
        "duration_s": round(duration_s, 2),
        "targets": list(targets),
        "ports": list(ports),
        "ports_scanned": len(ports),
        "port_range": _describe_ports(ports),
        "open_services": len(services),
        "unidentified": [{"host": svc.host, "port": svc.port,
                          "reason": svc.identification_error}
                         for svc in services if svc.identification_error],
        "skipped_ports": scan_meta.get("skipped_ports") or {},
        "scan_source": socket.gethostname() or "unknown host",
        "scan_platform": platform.platform(),
        "strict": bool(options.get("strict")),
        "suppressed_by_strict": int(options.get("suppressed_by_strict") or 0),
        "app_probes": sorted({probe.get("name") for svc in services
                              for probe in (svc.app or {}).values()
                              if probe.get("name")}),
        "advisory": advisory_meta or {},
        "authorisation_reference": options.get("reference") or "",
        "not_tested": list(_NOT_TESTED),
    }


def _describe_ports(ports: list[int]) -> str:
    if not ports:
        return ""
    ranges, start, prev = [], ports[0], ports[0]
    for port in ports[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = port
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges[:40]) + (", …" if len(ranges) > 40 else "")


def _service_dict(svc: PortService) -> dict:
    out = {
        "host": svc.host, "ip": svc.ip, "port": svc.port, "state": svc.state,
        "service": svc.service, "product": svc.product, "version": svc.version,
        "banner": svc.banner[:512],
    }
    if svc.tls:
        out["tls"] = svc.tls
    if svc.http:
        http = dict(svc.http)
        http["body_preview"] = http.get("body_preview", "")[:1000]
        out["http"] = http
    if svc.proto and svc.proto != "tcp":
        out["protocol"] = svc.proto
    if svc.source:
        out["source"] = svc.source
    if svc.cpe:
        out["cpe"] = svc.cpe
    if svc.nmap_conf:
        out["identification_confidence"] = svc.nmap_conf
    if svc.extrainfo:
        out["extra_info"] = svc.extrainfo
    if svc.os_matches:
        out["os"] = svc.os_matches[:3]
    if svc.scripts:
        out["scripts"] = svc.scripts
    if svc.app:
        out["app"] = svc.app
    if svc.identity_source:
        out["identity_source"] = svc.identity_source
    if svc.identification_error:
        out["identification_error"] = svc.identification_error
    if len(svc.identity_claims or []) > 1:
        out["identity_claims"] = svc.identity_claims
    return out


def _finding_dict(finding: Finding) -> dict:
    guidance = guidance_mod.for_finding(finding)
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "status": finding.status,
        "cwe": finding.cwe,
        "cve": finding.cve,
        "asset": finding.asset,
        "description": finding.description,
        "impact": finding.impact,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "references": finding.references,
        "cvss": cvss_mod.describe(finding),
        "attack": guidance["attack"],
        "detection": guidance["detection"],
        "next_step": guidance["next_step"],
        "entry_point": guidance_mod.is_entry_point(finding),
        "provenance": {"scanner": f"vulnscan {__version__}",
                       "guidance": guidance["source"]},
    }


# Asset-inventory export. Column order is the roadmap's minimum (host, port,
# protocol, service, product, version, CPE) followed by the extra fields both
# teams need to triage without opening the HTML; every row is one service.
CSV_COLUMNS = [
    "host", "ip", "port", "protocol", "service", "product", "version",
    "cpe", "identified_by", "tls", "state", "findings", "critical", "high",
]


def write_csv(report: dict, path: str) -> None:
    """Write the asset inventory as CSV (RFC 4180, one row per open service)."""
    counts: dict[tuple[str, int], dict[str, int]] = {}
    for finding in report.get("findings") or []:
        asset = finding.get("asset") or {}
        key = (asset.get("host") or "", asset.get("port") or 0)
        bucket = counts.setdefault(key, {"total": 0, "critical": 0, "high": 0})
        bucket["total"] += 1
        if finding.get("severity") in ("critical", "high"):
            bucket[finding["severity"]] += 1
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(CSV_COLUMNS)
        for service in report.get("services") or []:
            key = (service.get("host") or "", service.get("port") or 0)
            bucket = counts.get(key, {})
            cpe = service.get("cpe") or []
            tls = service.get("tls") or {}
            writer.writerow([
                service.get("host") or "",
                service.get("ip") or "",
                service.get("port") or "",
                service.get("protocol") or "tcp",
                service.get("service") or "unknown",
                service.get("product") or "",
                service.get("version") or "",
                ";".join(cpe) if isinstance(cpe, list) else str(cpe),
                service.get("identity_source") or "port",
                tls.get("version", "") if tls.get("ok") else "",
                service.get("state") or "",
                bucket.get("total", 0),
                bucket.get("critical", 0),
                bucket.get("high", 0),
            ])


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

_CSS = """
:root {
  --ink: #14121c;
  --ink-soft: #56506e;
  --ink-faint: #8b86a0;
  --line: #e6e2f2;
  --line-soft: #f1eef9;
  --paper: #ffffff;
  --desk: #f4f2fa;
  --wash: #f8f6fe;
  --accent: #702bff;
  --accent-wash: #f1eaff;
  --void: #08080d;
  --violet: #702bff;
  --violet-bright: #974fff;
  --lavender: #c9b5ff;
  --fog: #f5f3ff;
  --muted: #a5a0b5;
  --display: "Space Grotesk", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  --sans: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --mono: "JetBrains Mono", ui-monospace, "SF Mono", "Cascadia Mono", Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--desk); color: var(--ink);
  font-family: var(--sans);
  font-size: 15px; line-height: 1.56;
  -webkit-font-smoothing: antialiased;
}
.sheet {
  max-width: 64rem; margin: 2.5rem auto; background: var(--paper);
  border-radius: 14px; padding: 3rem 3.5rem 4rem;
  box-shadow: 0 1px 2px rgba(16, 21, 27, .05), 0 18px 44px -30px rgba(16, 21, 27, .45);
}

/* ---------- branded cover ---------- */
.cover {
  position: relative; overflow: hidden; border-radius: 16px;
  background: var(--void); color: var(--fog);
  padding: 2rem 2.3rem 2.1rem; margin: 0 0 2.6rem;
  border: 1px solid rgba(255, 255, 255, .09);
  -webkit-print-color-adjust: exact; print-color-adjust: exact;
}
.cover::before {
  content: ""; position: absolute; inset: -55% -15% auto -25%; height: 165%;
  background:
    radial-gradient(55% 55% at 22% 30%, rgba(112, 43, 255, .50), transparent 72%),
    radial-gradient(42% 48% at 88% 6%, rgba(151, 79, 255, .30), transparent 72%);
  pointer-events: none;
}
.cover > * { position: relative; }
.cover-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; }
.brandline { display: flex; align-items: center; gap: .7rem; }
.brandline svg { flex: none; }
.wordmark {
  display: block; font-family: var(--display); font-weight: 600;
  font-size: 1.28rem; letter-spacing: -0.045em; line-height: 1; color: var(--fog);
}
.wordmark .dot { color: var(--violet-bright); }
.tagline {
  display: block; margin-top: .42rem; font-family: var(--mono); font-size: .58rem;
  letter-spacing: .19em; text-transform: uppercase; color: var(--muted);
}
.cover-kind {
  font-family: var(--mono); font-size: .6rem; letter-spacing: .14em;
  text-transform: uppercase; color: var(--lavender); white-space: nowrap;
  border: 1px solid rgba(201, 181, 255, .28); background: rgba(112, 43, 255, .18);
  padding: .4rem .7rem; border-radius: 999px;
}
.cover h1 {
  font-family: var(--display); font-size: 2.05rem; font-weight: 600;
  line-height: 1.1; letter-spacing: -0.03em; margin: 1.5rem 0 .45rem; color: var(--fog);
}
.cover-sub { margin: 0 0 1.5rem; color: #b9b3cc; font-size: .86rem; }
.cover-sub .mono { color: var(--lavender); }
.cover .kpis { margin-bottom: 1.2rem; }
.cover .kpi {
  background: rgba(255, 255, 255, .05); border: 1px solid rgba(255, 255, 255, .10);
}
.cover .kpi-label { color: #b3adc6; }
.cover .kpi-value { color: var(--fog); }
.cover .kpi-note { color: #9892ad; }
.cover .kpi.risk {
  background: rgba(151, 79, 255, .16); border-color: rgba(201, 181, 255, .30);
}
.cover .kpi.risk .kpi-value { color: var(--lavender); }
.cover .meta { padding-top: 1.1rem; border-top: 1px solid rgba(255, 255, 255, .10); }
.cover .meta dt { color: #8d87a2; }
.cover .meta dd { color: #e7e3f5; }
.engine-note {
  margin: 1rem 0 0; font-family: var(--mono); font-size: .65rem;
  letter-spacing: .01em; color: #8d87a2;
}
.cover + h2 { margin-top: 0; }

.kpis {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: .7rem;
  margin: 0 0 1.3rem;
}
.kpi {
  border: 1px solid var(--line); border-radius: 10px;
  background: linear-gradient(180deg, #fff 0%, #faf8ff 100%);
  padding: .75rem .85rem .8rem; display: flex; flex-direction: column;
}
.kpi-label {
  font-size: .67rem; text-transform: uppercase; letter-spacing: .08em;
  color: var(--ink-soft); font-weight: 650;
}
.kpi-value {
  font-family: var(--display);
  font-size: 1.65rem; font-weight: 600; line-height: 1.2;
  font-variant-numeric: tabular-nums; letter-spacing: -0.01em;
}
.kpi-value .unit { font-size: .95rem; font-weight: 500; color: var(--ink-soft); }
.kpi-note { font-size: .72rem; color: var(--ink-soft); margin-top: .1rem; }
.kpi.risk { border-color: #f0cfc9; background: linear-gradient(180deg, #fff 0%, #fdf4f2 100%); }
.kpi.risk .kpi-value { color: #b42318; }

.meta {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: .5rem 1.6rem; margin: 0; font-size: .84rem;
}
.meta div { display: flex; flex-direction: column; min-width: 0; }
.meta dt {
  color: var(--ink-faint); font-size: .67rem; text-transform: uppercase;
  letter-spacing: .07em; font-weight: 650; margin-bottom: .1rem;
}
.meta dd { margin: 0; font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }

/* ---------- structure ---------- */
h2 {
  font-family: var(--display);
  font-size: 1.45rem; font-weight: 600; margin: 3rem 0 1rem; letter-spacing: -0.02em;
  scroll-margin-top: 1rem;
  padding-bottom: .5rem; border-bottom: 1px solid var(--line);
  letter-spacing: -0.01em; break-after: avoid;
}
h3 { font-size: .97rem; font-weight: 650; margin: 0 0 .35rem; letter-spacing: -0.005em; }
h4 { font-size: .7rem; text-transform: uppercase; letter-spacing: .08em;
  color: var(--ink-soft); font-weight: 700; }

/* ---------- severity summary ---------- */
.riskbar {
  display: flex; gap: 2px; height: 1.1rem; border-radius: 999px;
  overflow: hidden; background: var(--line-soft); margin-bottom: 1rem;
}
.riskbar span { display: block; height: 100%; }
.riskcounts { display: flex; flex-wrap: wrap; gap: .45rem; margin-bottom: .4rem; }
.riskcounts button {
  font: inherit; font-size: .82rem; border: 1px solid var(--line);
  background: #fff; border-radius: 999px; padding: .28rem .75rem; cursor: pointer;
  display: flex; align-items: center; gap: .45rem; color: var(--ink);
  box-shadow: 0 1px 2px rgba(16, 21, 27, .04);
}
.riskcounts button:hover { border-color: var(--ink-faint); }
.riskcounts button[aria-pressed="true"] { border-color: var(--ink); background: var(--wash); }
.riskcounts button:focus-visible { outline: 2px solid #175cd3; outline-offset: 2px; }
.riskcounts b { font-variant-numeric: tabular-nums; font-size: .95rem; }
.riskcounts .dot { width: .58rem; height: .58rem; border-radius: 50%; display: inline-block; }
.total { color: var(--ink-soft); font-size: .84rem; margin: .6rem 0 0; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.count-table td:first-child { font-size: .92rem; }
.count-table { border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.count-table th:first-child { border-top-left-radius: 9px; }

/* ---------- findings ---------- */
.finding {
  background: #fff; border: 1px solid var(--line); border-left-width: 4px;
  border-radius: 10px; margin: 0 0 1.1rem;
  box-shadow: 0 1px 2px rgba(16, 21, 27, .04);
  break-inside: avoid;
}
.finding-head { padding: .95rem 1.1rem .15rem; }
.finding h3 { font-size: 1.04rem; margin-top: .5rem; }
.finding dl {
  display: grid; grid-template-columns: 10.5rem minmax(0, 1fr);
  gap: 1rem 1.5rem; margin: .95rem 0 0; padding: 0 1.1rem 1.2rem;
}
.finding dt {
  font-size: .67rem; color: var(--ink-faint); font-weight: 700;
  text-transform: uppercase; letter-spacing: .07em; padding-top: .1rem;
}
.finding dd { margin: 0; min-width: 0; }
.finding a {
  color: var(--accent); text-decoration: none;
  border-bottom: 1px solid rgba(112, 43, 255, .35); overflow-wrap: anywhere;
}
.finding a:hover { border-bottom-color: var(--accent); }
.sev {
  display: inline-block; font-size: .7rem; font-weight: 650;
  padding: .12rem .5rem; border-radius: 999px; vertical-align: middle;
  letter-spacing: .01em;
}
.fid {
  font-family: var(--mono); font-variant-numeric: tabular-nums;
  color: var(--ink-faint); font-size: .78rem; margin-right: .5rem;
}
.tags { display: flex; flex-wrap: wrap; gap: .3rem; margin-top: .55rem; }
.tag {
  font-family: var(--mono); font-size: .72rem;
  background: var(--wash); border: 1px solid var(--line); border-radius: 5px;
  padding: .06rem .42rem; color: var(--ink-soft);
}

/* ---------- code and evidence ---------- */
pre {
  font-family: var(--mono); font-size: .77rem; line-height: 1.55;
  background: #0d0b16; color: #ece7ff; border: 1px solid #171323;
  border-radius: 8px; padding: .7rem .85rem; overflow-x: auto;
  white-space: pre-wrap; word-break: break-word; max-height: 16rem;
}
pre .mono, .nse pre { color: inherit; }

/* ---------- tables ---------- */
table { width: 100%; border-collapse: collapse; font-size: .85rem; }
th, td { text-align: left; padding: .5rem .65rem; border-bottom: 1px solid var(--line); }
th {
  font-size: .68rem; text-transform: uppercase; letter-spacing: .07em;
  font-weight: 700; color: var(--ink-soft); background: var(--wash);
}
tbody tr:hover { background: #faf8ff; }
td.mono, .mono { font-family: var(--mono); }
.table-scroll { max-width: 100%; overflow-x: auto; }

/* ---------- prose ---------- */
.prose { max-width: 46rem; color: var(--ink-soft); font-size: .9rem; }
.prose b, .prose strong { color: var(--ink); }
.small { font-size: .77rem; color: var(--ink-soft); }
.empty { color: var(--ink-soft); padding: 1rem 0; }
.nse { margin: 0 0 .7rem; }
.nse summary { cursor: pointer; color: var(--ink-soft); font-size: .82rem; }
.nse summary:hover { color: var(--ink); }
.nse pre { margin-top: .4rem; }

/* ---------- coverage + appendix ---------- */
.coverage { border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.coverage th {
  width: 13rem; background: var(--wash); font-weight: 650;
  text-transform: none; letter-spacing: 0; font-size: .8rem;
  color: var(--ink); vertical-align: top;
}
.coverage td { word-break: break-word; }
.coverage tr:last-child th, .coverage tr:last-child td { border-bottom: 0; }

/* ---------- per-host pages ---------- */
.hostpage {
  border: 1px solid var(--line); border-radius: 12px; padding: 1.1rem 1.35rem 1.3rem;
  margin: 0 0 1.6rem; background: #fff;
  box-shadow: 0 1px 2px rgba(16, 21, 27, .04);
}
.host-head {
  font-family: var(--mono); font-size: 1.05rem; margin: .1rem 0 .5rem;
  padding-bottom: .55rem; border-bottom: 1px solid var(--line);
  letter-spacing: -0.01em;
}
.host-head .small { font-weight: 400; margin-left: .5rem; }
.hostpage h4 { margin: 1.2rem 0 .4rem; }
.topfindings li { margin-bottom: .35rem; }
.topfindings b { font-family: var(--mono); font-variant-numeric: tabular-nums; }

footer.brand-footer {
  margin-top: 3rem; padding-top: 1.1rem; border-top: 1px solid var(--line);
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
  gap: .6rem 1.2rem; font-size: .77rem; color: var(--ink-faint);
}
footer .brandline { gap: .5rem; }
footer .wordmark { font-size: .95rem; color: var(--ink); }
footer .tagline {
  display: inline; margin: 0 0 0 .55rem; font-size: .55rem;
  letter-spacing: .16em; color: var(--ink-faint);
}
footer .footer-meta { font-family: var(--mono); font-size: .65rem; }

@media (max-width: 720px) {
  .sheet { margin: 0; padding: 1.5rem 1.1rem 3rem; border-radius: 0; box-shadow: none; }
  .kpis { grid-template-columns: 1fr 1fr; }
  .meta { grid-template-columns: 1fr 1fr; }
  .finding dl { grid-template-columns: 1fr; gap: .15rem; }
  .finding dt { padding-top: .5rem; }
  .finding dl > dd { border-top: 0; padding-top: 0; }
}

@media print {
  @page { size: A4; margin: 13mm 12mm 15mm; }
  body { background: #fff; font-size: 9pt; line-height: 1.42; }
  .sheet {
    max-width: none; margin: 0; padding: 0; border-radius: 0; box-shadow: none;
  }
  .cover { padding: 8mm 9mm 8.5mm; margin-bottom: 8mm; border-radius: 6mm; break-inside: avoid; }
  .cover h1 { font-size: 19pt; margin: 6mm 0 2mm; }
  .cover-sub { margin-bottom: 5mm; }
  .cover .meta { padding-top: 4mm; }
  .cover-kind { font-size: 6.6pt; }
  .kpis { gap: 3mm; margin-bottom: 1rem; }
  .kpi { padding: 2.4mm 3mm; }
  .kpi-value { font-size: 14pt; }
  .kpi-note { font-size: .68rem; }
  .finding { margin-bottom: 4mm; }
  .finding-head { padding: 3.2mm 4mm .5mm; }
  .finding h3 { margin-top: .35rem; }
  .finding dl {
    grid-template-columns: 8rem minmax(0, 1fr);
    gap: .42rem 4mm; padding: 0 4mm 3mm; margin-top: .5rem;
  }
  pre { font-size: 7pt; padding: 2.2mm 3mm; max-height: none; overflow: visible; }
  .table-scroll { overflow: visible; }
  table { font-size: 8.1pt; }
  th, td { padding: 1.5mm 2mm; }
  h2 { font-size: 13pt; margin-top: 9mm; }
  .kpi, .finding, .hostpage, .count-table, .coverage { box-shadow: none; }
  .finding, .hostpage { break-inside: avoid; }
  .riskcounts button { display: none; }
  .nse pre { max-height: none; overflow: visible; }
  pre { border-color: #dfe5ec; }
  a { color: var(--ink); text-decoration: none; }
  h2 { break-after: avoid; }
  /* Every host after the first opens a fresh page; the first stays with the
     section heading so a page is not left mostly blank in the PDF. */
  .hostpage ~ .hostpage { break-before: page; }
}
"""

_IDENTITY_LABELS = {
    "nmap": "nmap -sV",
    "banner": "protocol banner",
    "http": "HTTP response",
    "port": "port number only",
}


def _identity_label(service: dict) -> str:
    """How this service was identified, flagged when sources disagree."""
    if service.get("identification_error"):
        return '<span class="tag">not identified</span>'
    source = service.get("identity_source") or "port"
    label = html.escape(_IDENTITY_LABELS.get(source, source))
    if claims_conflict(service.get("identity_claims")):
        return f'{label} <span class="tag">conflicting</span>'
    return label


# nmap's own version-detection helper: its output duplicates the banner and
# buries the curated results, so it stays in the JSON/XML but not the appendix.
_INTERNAL_SCRIPTS = frozenset({"fingerprint-strings"})


def _scripts_text(scripts: dict[str, str], limit: int = 4000) -> str:
    """Plain-text rendering of NSE output for the appendix."""
    blocks = []
    for script_id, output in scripts.items():
        if script_id in _INTERNAL_SCRIPTS:
            continue
        text = (output or "").strip()
        if len(text) > limit:
            text = text[:limit] + "\n… (truncated; full output in the JSON/XML)"
        blocks.append(f"== {script_id} ==\n{text}")
    return "\n\n".join(blocks)


def _script_count(service: dict) -> int:
    return sum(1 for script_id in (service.get("scripts") or {})
               if script_id not in _INTERNAL_SCRIPTS)


def _identity_summary(services: list[dict]) -> str:
    """Plain-text breakdown of identification sources for the methodology text."""
    if not services:
        return "no services were identified"
    counts: dict[str, int] = {}
    for service in services:
        if service.get("identification_error"):
            counts["not identified"] = counts.get("not identified", 0) + 1
            continue
        source = service.get("identity_source") or "port"
        label = _IDENTITY_LABELS.get(source, source)
        counts[label] = counts.get(label, 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return ", ".join(f"{count} by {label}" for label, count in ordered)


CVSS_RANGES = {
    "critical": "9.0–10.0",
    "high": "7.0–8.9",
    "medium": "4.0–6.9",
    "low": "0.1–3.9",
    "informational": "0.0",
}
_CVSS_SOURCE_LABELS = {
    "nvd": "NVD",
    "rule": "rule vector",
    "baseline": "band baseline",
}


def _cvss_of(finding: dict) -> dict:
    return finding.get("cvss") or {}


def _cvss_label(block: dict) -> str:
    source = block.get("source", "")
    return _CVSS_SOURCE_LABELS.get(source, source)


def _top_findings(findings: list[dict], limit: int = 3) -> list[dict]:
    """The findings that actually matter: worst band, then highest CVSS."""
    def key(finding: dict):
        sev = finding.get("severity")
        return (SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 99,
                -float(_cvss_of(finding).get("score") or 0.0))
    return sorted(findings, key=key)[:limit]


def _coverage_rows(coverage: dict) -> str:
    """Table body for the coverage and provenance section."""
    e = html.escape
    engine = coverage.get("engine") or "native"
    version = coverage.get("engine_version") or ""
    requested = coverage.get("requested_engine") or ""
    engine_text = f"{engine}" + (f" {version}" if version else "")
    if requested and requested != engine:
        engine_text += f" (requested {requested})"
    if coverage.get("fallback_reason"):
        engine_text += f" — {coverage['fallback_reason']}"
    command = coverage.get("command") or ""
    command_html = (f'<span class="mono">{e(command)}</span>' if command else
                    "in-process native scanner — no external command")
    scripts = coverage.get("scripts") or []
    script_text = (", ".join(scripts) if scripts else
                   ("none (--nse off)" if coverage.get("nse_profile") == "off"
                    else "none — the native engine does not run NSE scripts"))
    skipped = coverage.get("skipped_ports") or {}
    skipped_text = ", ".join(f"{count} {state}" for state, count in sorted(skipped.items())) or "—"
    unidentified = coverage.get("unidentified") or []
    unidentified_text = ("; ".join(
        f"{e(item.get('host') or '')}:{item.get('port')} — {e(item.get('reason') or '')}"
        for item in unidentified)
        if unidentified else
        "none — every open port sent a readable protocol")
    app_probes = coverage.get("app_probes") or []
    app_text = (", ".join(app_probes) + " (one read-only request each, no credentials)"
                if app_probes else "none triggered")
    advisory = coverage.get("advisory") or {}
    if advisory.get("available"):
        advisory_text = (f"{advisory.get('cves', 0)} CVEs, built "
                         f"{advisory.get('built_at') or 'unknown'} "
                         f"({advisory.get('path', '')})")
    else:
        advisory_text = "none — built-in CVE fingerprints only"
    if coverage.get("strict"):
        strict_text = ("confirmed findings only (--strict); "
                       f"{coverage.get('suppressed_by_strict', 0)} lower-confidence "
                       "finding(s) suppressed")
    else:
        strict_text = "all findings, with confidence stated on each"
    rows = [
        ("Targets", e(", ".join(coverage.get("targets") or []))),
        ("Ports", f"{coverage.get('ports_scanned', 0)} TCP "
                   f"({e(coverage.get('port_range') or '')})"),
        ("Engine", e(engine_text)),
        ("Exact command", command_html),
        ("Privilege", "root (raw-socket privileges available)"
         if coverage.get("privileged") else
         "unprivileged user (connect scan; no raw-socket features)"),
        ("Version detection", (f"nmap -sV, intensity {coverage['version_intensity']}"
                              if coverage.get("version_intensity") else
                              ("nmap -sV (default intensity)" if engine == "nmap"
                               else "banner and HTTP header parsing"))),
        ("OS detection", "not performed (-O was not requested)"),
        ("NSE scripts", e(script_text)),
        ("Timeouts", f"{coverage.get('timeout_s') if coverage.get('timeout_s') is not None else 'default'} s per probe; "
                      f"{coverage.get('host_timeout_s')} s per host"
         if coverage.get("host_timeout_s") is not None else
         f"{coverage.get('timeout_s') if coverage.get('timeout_s') is not None else 'default'} s per probe; no per-host limit"),
        ("Concurrency", str(coverage.get("concurrency") or "default")),
        ("Started", e(coverage.get("started_at") or "")),
        ("Duration", f"{coverage.get('duration_s')} s"),
        ("Scan source", f"<span class=\"mono\">{e(coverage.get('scan_source') or '')}</span> "
                         f"<span class=\"small\">{e(coverage.get('scan_platform') or '')}</span>"),
        ("Advisory database", e(advisory_text)),
        ("App-layer probes", e(app_text)),
        ("Findings filter", e(strict_text)),
        ("Unidentified", unidentified_text),
        ("Ports not open", e(skipped_text)),
    ]
    return "".join(f"<tr><th>{label}</th><td>{value}</td></tr>"
                   for label, value in rows)


def _asset_rows(services: list[dict]) -> str:
    e = html.escape
    rows = []
    for service in services:
        cpe = ", ".join(service.get("cpe") or []) or "—"
        rows.append(
            "<tr>"
            f'<td class="mono">{e(service["host"])}</td>'
            f'<td class="mono">{e(service.get("ip") or "")}</td>'
            f'<td class="mono">{service["port"]}</td>'
            f'<td class="mono">{e(service.get("protocol") or "tcp")}</td>'
            f'<td class="mono">{e(service.get("service") or "not identified")}</td>'
            f'<td>{e(service.get("product") or "—")} {e(service.get("version") or "")}</td>'
            f'<td class="mono small">{e(cpe)}</td>'
            f'<td>{_identity_label(service)}</td>'
            f'<td>{"TLS " + e(service["tls"].get("version", "")) if service.get("tls", {}).get("ok") else "—"}</td>'
            "</tr>")
    return "".join(rows) or '<tr><td colspan="9">No open ports found.</td></tr>'


def _host_order(targets: list[str], services: list[dict], findings: list[dict]) -> list[str]:
    hosts = list(targets)
    for source in (services, findings):
        for item in source:
            host = item.get("host") or (item.get("asset") or {}).get("host")
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def _render_hosts(targets: list[str], services: list[dict], findings: list[dict]) -> str:
    """One page per host: what runs there, what is wrong, what to fix first."""
    e = html.escape
    blocks = []
    for host in _host_order(targets, services, findings):
        host_services = [s for s in services if s.get("host") == host]
        host_findings = [f for f in findings if (f.get("asset") or {}).get("host") == host]
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for finding in host_findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        count_text = ", ".join(f"{counts[sev]} {SEV_META[sev]['label'].lower()}"
                               for sev in SEVERITY_ORDER if counts[sev]) or "none"
        ip = next((s.get("ip") for s in host_services if s.get("ip")), "")
        anchor = "".join(char if char.isalnum() else "-" for char in host).strip("-") or "host"
        rows = "".join(
            "<tr>"
            f'<td class="mono">{s["port"]}</td>'
            f'<td class="mono">{e(s.get("service") or "unknown")}</td>'
            f'<td>{e(s.get("product") or "—")} {e(s.get("version") or "")}</td>'
            f'<td>{_identity_label(s)}</td>'
            f'<td class="num">{sum(1 for f in host_findings if (f.get("asset") or {}).get("port") == s["port"])}</td>'
            "</tr>" for s in host_services) or (
            '<tr><td colspan="5">No open ports among the scanned set.</td></tr>')
        finding_rows = "".join(
            "<tr>"
            f'<td><span class="sev" style="background:{SEV_META[f["severity"]]["wash"]};'
            f'color:{SEV_META[f["severity"]]["hex"]}">{SEV_META[f["severity"]]["label"]}</span></td>'
            f'<td><span class="mono small">{f["id"]}</span> {e(f["title"])}</td>'
            f'<td class="num">{_cvss_of(f).get("score", "—")}</td>'
            f'<td class="mono">{e(str((f.get("asset") or {}).get("port") or ""))}</td>'
            "</tr>"
            for f in sorted(host_findings,
                            key=lambda f: (SEVERITY_ORDER.index(f["severity"])
                                           if f["severity"] in SEVERITY_ORDER else 99,
                                           -float(_cvss_of(f).get("score") or 0.0)))
        ) or '<tr><td colspan="4">No findings on this host.</td></tr>'
        # One action per rule, worst first: the shortest path to a quieter host.
        seen_rules: set[str] = set()
        fixes = []
        for finding in sorted(host_findings,
                              key=lambda f: (SEVERITY_ORDER.index(f["severity"])
                                             if f["severity"] in SEVERITY_ORDER else 99,
                                             -float(_cvss_of(f).get("score") or 0.0))):
            if finding["rule_id"] in seen_rules:
                continue
            seen_rules.add(finding["rule_id"])
            fixes.append(f'<li><span class="mono small">{e(finding["rule_id"])}</span> '
                         f'{e(finding["remediation"])}</li>')
            if len(fixes) == 3:
                break
        blocks.append(f"""
<div class="hostpage" id="host-{anchor}">
  <h3 class="host-head">{e(host)}
    {f'<span class="mono small">{e(ip)}</span>' if ip and ip != host else ''}</h3>
  <p class="prose">{len(host_services)} open service(s), {len(host_findings)} finding(s):
    {e(count_text)}.</p>
  <h4>What is running</h4>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Product / version</th>
      <th>Identified by</th><th class="num">Findings</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <h4>What is wrong</h4>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th class="num">CVSS</th><th>Port</th></tr></thead>
    <tbody>{finding_rows}</tbody>
  </table>
  <h4>What to fix first</h4>
  <ol class="prose">{''.join(fixes) or '<li>Nothing to remediate on this host.</li>'}</ol>
</div>""")
    return "".join(blocks)


def render_html(report: dict) -> str:
    meta = report["metadata"]
    scope = report["scope"]
    summary = report["summary"]
    counts = summary["counts_by_severity"]
    findings = report["findings"]
    services = report["services"]
    total = max(summary["total_findings"], 1)
    e = html.escape
    advisory = meta.get("advisory_db") or {}
    advisory_note = (
        f"Version fingerprints were matched against an offline advisory "
        f"database ({advisory.get('cves', 0)} CVEs, built "
        f"{e(str(advisory.get('built_at') or 'unknown'))}). "
        if advisory.get("available") else
        "No advisory database was available, so CVE matching used the scanner's "
        "built-in fingerprints only. ")

    segments = "".join(
        f'<span style="width:{counts[sev] / total * 100:.2f}%;'
        f'background:{SEV_META[sev]["hex"]}" title="{SEV_META[sev]["label"]}"></span>'
        for sev in SEVERITY_ORDER if counts[sev])
    chips = "".join(
        f'<button type="button" data-sev="{sev}" aria-pressed="false">'
        f'<span class="dot" style="background:{SEV_META[sev]["hex"]}"></span>'
        f'{SEV_META[sev]["label"]} <b>{counts[sev]}</b></button>'
        for sev in SEVERITY_ORDER)

    findings_by_sev: dict[str, list] = {sev: [] for sev in SEVERITY_ORDER}
    for finding in findings:
        findings_by_sev.setdefault(finding["severity"], []).append(finding)

    # Prioritized remediation: one action per rule, ranked by how many
    # findings it clears (mirrors the reference report's Remediation table).
    by_rule: dict[str, list] = {}
    for finding in findings:
        by_rule.setdefault(finding["rule_id"], []).append(finding)
    remediation_rows = sorted(
        by_rule.items(),
        key=lambda kv: (-len(kv[1]), SEVERITY_ORDER.index(kv[1][0]["severity"])
                        if kv[1][0]["severity"] in SEVERITY_ORDER else 99))

    finding_blocks = "".join(_render_finding(f) for f in findings) or (
        '<p class="empty">No vulnerabilities matched the scan checks. '
        'Review the services table below — an empty result is not a guarantee '
        'of a clean system.</p>')

    severity_sections = "".join(_render_severity_section(sev, group)
                                for sev, group in findings_by_sev.items() if group)

    remed_html = "".join(
        "<tr>"
        f'<td>{e(fs[0]["remediation"])}</td>'
        f'<td style="color:{SEV_META[fs[0]["severity"]]["hex"]};font-weight:600">'
        f'{SEV_META[fs[0]["severity"]]["label"]}</td>'
        f'<td class="num">{len(fs)}</td>'
        f'<td class="num">{len({(a["asset"].get("host"), a["asset"].get("port")) for a in fs})}</td>'
        "</tr>"
        for _rule_id, fs in remediation_rows[:20])

    scripts_run = (meta.get("scan") or {}).get("scripts") or []
    # ``open`` matters for the PDF: headless Chrome does not expand a collapsed
    # <details>, and the appendix must be readable in the printed report.
    script_blocks = "".join(
        f'<details class="nse" open><summary class="mono">{e(s["host"])}:{s["port"]}'
        f' — {_script_count(s)} script(s)</summary>'
        f'<pre>{e(_scripts_text(s["scripts"]))}</pre></details>'
        for s in services if _scripts_text(s.get("scripts") or {})) or (
        '<p class="empty">No curated script produced usable output — the native '
        'engine was used, scripts were disabled with --nse off, or the scripts '
        'found nothing on these ports.</p>')

    coverage = report.get("coverage") or {}
    cov_rows = _coverage_rows(coverage)
    not_tested_html = "".join(f"<li>{e(item)}</li>" for item in coverage.get("not_tested") or [])
    entry_findings = [f for f in findings if f.get("entry_point")]
    entry_html = ""
    if entry_findings:
        rows = []
        for item in entry_findings:
            attack = item.get("attack") or []
            technique = (f'<span class="mono small">{e(attack[0]["id"])}</span> '
                         f'{e(attack[0]["name"])}' if attack else "—")
            asset = item.get("asset") or {}
            rows.append(
                "<tr>"
                f'<td><span class="sev" style="background:{SEV_META[item["severity"]]["wash"]};'
                f'color:{SEV_META[item["severity"]]["hex"]}">'
                f'{SEV_META[item["severity"]]["label"]}</span></td>'
                f'<td><span class="mono small">{e(item["id"])}</span> {e(item["title"])}</td>'
                f'<td class="mono">{e(str(asset.get("host") or ""))}:'
                f'{e(str(asset.get("port") or ""))}</td>'
                f'<td class="num">{_cvss_of(item).get("score", "—")}</td>'
                f'<td>{technique}</td>'
                "</tr>")
        entry_html = f"""
  <h3 style="font-size:1.05rem;margin:1.8rem 0 .5rem">Initial access candidates</h3>
  <p class="prose">These findings need no prior foothold: anonymous access,
    unauthenticated management APIs and remotely reachable known-vulnerable
    services. A red team starts here; a blue team should treat this list as the
    priority detection backlog.</p>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th>
      <th class="num">CVSS</th><th>ATT&amp;CK technique</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>"""
    else:
        entry_html = ('<p class="prose">No finding in this report is a '
                      'credential-free initial-access path: every exposed '
                      'service here needs credentials, user interaction or a '
                      'foothold to reach.</p>')
    top = _top_findings(findings)
    top_html = "".join(
        f'<li><b>{_cvss_of(f).get("score", "—")}</b> '
        f'<span class="sev" style="background:{SEV_META[f["severity"]]["wash"]};'
        f'color:{SEV_META[f["severity"]]["hex"]}">{SEV_META[f["severity"]]["label"]}</span> '
        f'{e(f["title"])} '
        f'<span class="mono small">{e(str(f["asset"].get("host") or ""))}:'
        f'{e(str(f["asset"].get("port") or ""))}</span></li>'
        for f in top) or '<li>No findings matched the scan checks.</li>'
    critical_and_high = counts.get("critical", 0) + counts.get("high", 0)
    raw_xml = (meta.get("scan") or {}).get("raw_xml") or ""
    raw_note = (f"The raw nmap XML behind this report is saved at "
                f'<span class="mono">{e(raw_xml)}</span>; it can be re-parsed to '
                f"re-derive every service shown here." if raw_xml else
                "No raw engine output was saved for this scan (the native engine "
                "produces no XML); the JSON report carries the evidence instead.")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(meta["title"])} — VibeCheck</title>
<meta name="generator" content="VibeCheck · {e(meta["scanner"]["name"])} {e(meta["scanner"]["version"])}">
<link rel="icon" href="{branding.favicon_data_uri()}">
<style>{branding.font_css()}{_CSS}</style>
</head>
<body>
<div class="sheet">
  <header class="cover">
    <div class="cover-top">
      <div class="brandline">
        {branding.logo_svg(40, "dark")}
        <div>
          <span class="wordmark">VibeCheck<span class="dot">.</span></span>
          <span class="tagline">Secure what you build</span>
        </div>
      </div>
      <span class="cover-kind">Vulnerability assessment</span>
    </div>
    <h1>{e(meta["title"])}</h1>
    <p class="cover-sub">Targets <span class="mono">{e(", ".join(scope["targets"]))}</span>
      · scanned {e(meta["started_at"])}</p>
    <div class="kpis">
      <div class="kpi">
        <span class="kpi-label">Findings</span>
        <span class="kpi-value">{summary["total_findings"]}</span>
        <span class="kpi-note">across {summary["open_services"]} open service(s)</span>
      </div>
      <div class="kpi risk">
        <span class="kpi-label">Critical + high</span>
        <span class="kpi-value">{critical_and_high}</span>
        <span class="kpi-note">fix these first</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Hosts</span>
        <span class="kpi-value">{len(scope["targets"])}</span>
        <span class="kpi-note">{scope["ports_scanned"]} port(s) each</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Duration</span>
        <span class="kpi-value">{meta["duration_seconds"]}<span class="unit"> s</span></span>
        <span class="kpi-note">engine: {e(meta["engine"])}</span>
      </div>
    </div>
    <dl class="meta">
      <div><dt>Generated</dt><dd>{e(meta["generated_at"])}</dd></div>
      <div><dt>Scope</dt><dd>{len(scope["targets"])} host(s) ·
        {scope["ports_scanned"]} TCP port(s)</dd></div>
      <div><dt>Authorisation</dt><dd>{e(coverage.get("authorisation_reference") or "none supplied")}</dd></div>
      <div><dt>Report schema</dt><dd>{e(report["report_version"])}</dd></div>
    </dl>
    <p class="engine-note">Scan engine {e(meta["scanner"]["name"])}
      {e(meta["scanner"]["version"])} · {e(meta["engine"])} · report schema
      {e(report["report_version"])}</p>
  </header>

  <h2 id="scope">1. Scope and authorisation</h2>
  <p class="prose">This is a non-intrusive assessment of the network services
    reachable on the listed targets from the scan source. It identifies services,
    their versions and their configuration, and reports what those observations
    justify — it does not attempt to compromise anything.</p>
  <table class="coverage">
    <tbody>
      <tr><th>Targets</th><td class="mono">{e(", ".join(scope["targets"]))}</td></tr>
      <tr><th>Ports</th><td>{scope["ports_scanned"]} TCP
        (<span class="mono">{e(scope["port_range"])}</span>)</td></tr>
      <tr><th>Scan window</th><td>{e(meta["started_at"])} · {meta["duration_seconds"]} s</td></tr>
      <tr><th>Scan source</th><td class="mono">{e(meta.get("scan_source") or coverage.get("scan_source") or "")}</td></tr>
      <tr><th>Authorisation</th><td>{e(coverage.get("authorisation_reference") or
        "No authorisation reference was supplied with this scan; confirm written "
        "permission covers these targets and dates before acting on the report.")}</td></tr>
    </tbody>
  </table>
  <h3>Explicitly not tested</h3>
  <ul class="prose">{not_tested_html}</ul>

  <h2 id="coverage">2. Coverage and provenance</h2>
  <p class="prose">Every line below is reported by the engine that actually ran,
    not by what was requested. Where a capability was unavailable or switched off,
    it says so, so the absence of a result is never mistaken for a clean result.</p>
  <table class="coverage"><tbody>{cov_rows}</tbody></table>
  <p class="prose small">{raw_note}</p>

  <h2 id="executive-summary">3. Executive summary</h2>
  <p class="prose">{summary["total_findings"]} finding(s) were identified across
    {summary["open_services"]} open service(s) on {len(scope["targets"])} target(s).
    {critical_and_high} of them are critical or high severity. The table below
    counts findings by severity band with the CVSS 3.1 range each band covers; the
    sections that follow group the detail by the same bands, highest risk first.</p>
  <table class="count-table">
    <thead><tr><th>Vulnerability risk</th><th>CVSS 3.1 range</th><th>Unique count</th></tr></thead>
    <tbody>
      {''.join(
        f'<tr><td style="color:{SEV_META[sev]["hex"]};font-weight:650">'
        f'{SEV_META[sev]["label"]} vulnerability</td>'
        f'<td class="mono">{CVSS_RANGES[sev]}</td>'
        f'<td class="num">{counts[sev]}</td></tr>'
        for sev in SEVERITY_ORDER)}
    </tbody>
  </table>
  <h3>What matters most</h3>
  <ol class="prose topfindings">{top_html}</ol>
  <h3 style="margin-top:1.2rem">In plain language</h3>
  <p class="prose">{("The critical and high findings are the ones that can be turned "
    "into access or data loss without special conditions; treat them as the "
    "priority for the next change window. " if critical_and_high else
    "No critical or high findings were confirmed, so the practical risk in this "
    "report is hardening and information exposure rather than immediate "
    "compromise. ")}Each finding states its confidence: <em>certain</em> means the
    service itself answered and proved the observation, <em>firm</em> means a
    version or configuration matched, and <em>tentative</em> means the port number
    or a distro build is the only evidence — verify those before acting.</p>

  <h2 id="assets">4. Asset inventory</h2>
  <p class="prose">Every host and service observed, with the product, version and
    CPE the identification produced. This is the table both teams work from; the
    JSON report carries the same rows plus full banners and HTTP/TLS detail.</p>
  <div class="table-scroll">
  <table>
    <thead><tr><th>Host</th><th>IP</th><th>Port</th><th>Proto</th><th>Service</th>
      <th>Product / version</th><th>CPE</th><th>Identified by</th><th>TLS</th></tr></thead>
    <tbody>{_asset_rows(services)}</tbody>
  </table>
  </div>

  <h2 id="hosts">5. Per-host rollup</h2>
  <p class="prose">One block per host: what is running, what is wrong with it, and
    what to fix first. Each host after the first starts on a new page in the PDF.</p>
  {_render_hosts(scope["targets"], services, findings)}

  <h2 id="findings">6. Findings</h2>
  <div class="riskbar" role="img" aria-label="Findings by severity">{segments}</div>
  <div class="riskcounts">{chips}</div>
  <p class="total">{summary["total_findings"]} finding(s). Click a severity to filter.</p>
  {entry_html}
  {severity_sections or '<p class="empty">No findings to report.</p>'}
  <h3 style="font-size:1.05rem;margin:2rem 0 .8rem">Detailed findings</h3>
  <div id="finding-detail">{finding_blocks}</div>

  <h2 id="recommendations">7. Recommendations</h2>
  <p class="prose">Addressing the actions below in this order resolves the most
    findings with the least effort. The Vulns column counts affected findings and
    the Hosts column counts distinct services affected.</p>
  <table>
    <thead><tr><th>Remediation action</th><th>Severity</th><th>Vulns</th><th>Hosts</th></tr></thead>
    <tbody>{remed_html or '<tr><td colspan="4">Nothing to remediate.</td></tr>'}</tbody>
  </table>

  <h2 id="methodology">8. Methodology and limits</h2>
  <p class="prose">Targets {e(", ".join(scope["targets"]))} were probed on
    {scope["ports_scanned"]} TCP ports ({e(scope["port_range"])}) using
    {e(scope["method"])}. The scan runs in two phases: an availability phase that
    establishes which ports are reachable, and an assessment phase that probes each
    open port for its banner, TLS certificate and HTTP response, then applies the
    checks behind the findings. Checks cover exposed management and database
    services, anonymous access, TLS certificate and protocol weaknesses, HTTP
    security-header configuration, and version fingerprints matched against known
    CVEs. {advisory_note}Each service records how it was identified —
    {e(_identity_summary(services))} — and a rule that would otherwise fire on a
    port number alone is reported as tentative, or not at all when the protocol
    contradicts it. No exploitation, authentication attempts or denial-of-service
    testing were performed; results reflect the state visible from the scan source
    at {e(meta["started_at"])}.</p>
  <h3>What the confidence labels mean</h3>
  <table>
    <thead><tr><th>Confidence</th><th>Meaning</th></tr></thead>
    <tbody>
      <tr><td><b>certain</b></td><td>The service answered and the response itself
        proves the observation (an HTTP status and header, a TLS handshake, a
        protocol banner).</td></tr>
      <tr><td><b>firm</b></td><td>A version or configuration matched a known pattern,
        but the vulnerable code path was not exercised.</td></tr>
      <tr><td><b>tentative</b></td><td>The port number, a weak nmap guess or a distro
        package revision is the only evidence. Verify before acting.</td></tr>
    </tbody>
  </table>
  <h3>How CVSS was assigned</h3>
  <p class="prose">Every finding carries a CVSS 3.1 base score computed from its
    vector, and the vector is shown with the finding. The score and the severity
    band always agree because the band is derived from the score. Sources, in
    order of preference: the advisory database's own NVD vector for a CVE, a
    curated vector written from the rule's impact, or — for rules with no curated
    vector — the band baseline. The report names which source was used.</p>
  <h3>What this scan cannot see</h3>
  <p class="prose">Identification is banner-based: a service that answers nothing,
    answers in an unexpected protocol, or is filtered by a middlebox is invisible
    here. Version matching can only report CVEs for the products it recognises and
    versions it can parse, and a distro backport may already fix an upstream issue.
    Findings describe reachable exposure, not proof of exploitability.</p>

  <h2 id="nse">9. Appendix — NSE script output</h2>
  <p class="prose">Curated read-only scripts run during identification
    ({e(", ".join(scripts_run)) if scripts_run else "none"}). Output that
    substantiates a finding is quoted in that finding's evidence above;
    what the scripts observed is reproduced here (the JSON and raw XML carry
    the complete output, including long script transcripts).</p>
  {script_blocks}

  <footer class="brand-footer">
    <div class="brandline">
      {branding.logo_svg(20, "light")}
      <span class="wordmark">VibeCheck<span class="dot">.</span></span>
      <span class="tagline">Secure what you build</span>
    </div>
    <div class="footer-meta">Generated by {e(meta["scanner"]["name"])}
      {e(meta["scanner"]["version"])} · report schema
      {e(report["report_version"])} · {branding.BRAND["site"]}</div>
  </footer>
</div>
<script>
document.querySelectorAll('.riskcounts button').forEach(function (btn) {{
  btn.addEventListener('click', function () {{
    var sev = btn.dataset.sev;
    var active = btn.getAttribute('aria-pressed') === 'true';
    document.querySelectorAll('.riskcounts button').forEach(function (b) {{
      b.setAttribute('aria-pressed', 'false');
    }});
    btn.setAttribute('aria-pressed', active ? 'false' : 'true');
    document.querySelectorAll('.finding').forEach(function (f) {{
      f.hidden = !active && f.dataset.sev !== sev;
    }});
  }});
}});
</script>
</body>
</html>
"""


def _render_severity_section(sev: str, group: list) -> str:
    """One severity band heading followed by its finding cards.

    Mirrors the reference report's Risk Assessment bands, each opening with a
    one-line count and framing, highest risk first.
    """
    meta = SEV_META.get(sev, SEV_META["informational"])
    text = {
        "critical": "Critical vulnerabilities require immediate attention. They "
                    "are relatively easy for attackers to exploit and may provide "
                    "them with full control of the affected services.",
        "high": "High severity vulnerabilities are often harder to exploit and may "
                "not provide the same access to affected services.",
        "medium": "Medium severity vulnerabilities often provide information to "
                  "attackers that may assist them in mounting subsequent attacks. "
                  "Fix them in a timely manner.",
        "low": "Low severity vulnerabilities do not need to be patched immediately "
               "and can be resolved during the next maintenance window.",
        "informational": "Informational items are observations worth reviewing, not "
                         "immediate risks.",
    }.get(sev, "")
    cards = "".join(_render_finding(f) for f in group)
    return (f'<h3 style="font-size:1.1rem;margin:1.8rem 0 .5rem;color:{meta["hex"]}">'
            f'{meta["label"]} severity vulnerability</h3>'
            f'<p class="prose">{len(group)} finding(s). {text}</p>{cards}')


def _render_finding(f: dict) -> str:
    e = html.escape
    sev = SEV_META.get(f["severity"], SEV_META["informational"])
    tags = "".join(f'<span class="tag">{e(t)}</span>'
                   for t in (f["cwe"] + f["cve"] + [f["rule_id"]]))
    asset = f["asset"]
    location = asset.get("url") or (f"{asset.get('host')}:{asset.get('port')}/tcp")
    refs = "".join(
        f'<div><a href="{e(r)}" rel="noopener">{e(r)}</a></div>'
        for r in f.get("references", []))
    return f"""
<div class="finding" data-sev="{e(f["severity"])}"
     style="border-left-color:{sev["hex"]}">
  <div class="finding-head">
    <span class="fid">{e(f["id"])}</span>
    <span class="sev" style="background:{sev["wash"]};color:{sev["hex"]}">{sev["label"]}</span>
    <span class="sev" style="background:#f4f5f7;color:#4a515c">confidence: {e(f["confidence"])}</span>
    <span class="sev" style="background:#f4f5f7;color:#4a515c">CVSS {_cvss_of(f).get("score", "—")}</span>
    <h3>{e(f["title"])}</h3>
    <div class="tags">{tags}</div>
  </div>
  <dl>
    <dt>Affected asset</dt>
    <dd class="mono">{e(location)} · status {e(f["status"])}</dd>
    <dt>CVSS 3.1</dt>
    <dd><b>{_cvss_of(f).get("score", "—")}</b>
      <span class="mono small">{e(_cvss_of(f).get("vector", ""))}</span><br>
      <span class="small">vector version {e(_cvss_of(f).get("version", "3.1"))} ·
      score band {e(_cvss_of(f).get("band", ""))} · source:
      {e(_cvss_label(_cvss_of(f)))}</span></dd>
    <dt>What was found</dt>
    <dd>{e(f["description"])}</dd>
    <dt>Impact</dt>
    <dd>{e(f["impact"])}</dd>
    <dt>Attack techniques (MITRE ATT&amp;CK)</dt>
    <dd>{''.join(
        f'<div><span class="mono">{e(t.get("id", ""))}</span> '
        f'{e(t.get("name", ""))}</div>'
        for t in (f.get("attack") or [])) or '<span class="small">No technique '
        'mapped for this rule.</span>'}</dd>
    <dt>Detection (blue team)</dt>
    <dd>{e(f.get("detection") or "")}</dd>
    <dt>Validation next step (red team)</dt>
    <dd>{e(f.get("next_step") or "")}</dd>
    <dt>Evidence</dt>
    <dd><pre>{e(f["evidence"])}</pre></dd>
    <dt>Recommendation</dt>
    <dd>{e(f["remediation"])}</dd>
    {f'<dt>References</dt><dd>{refs}</dd>' if refs else ''}
  </dl>
</div>"""


def write_html(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(report))


# --------------------------------------------------------------------------
# Terminal summary
# --------------------------------------------------------------------------

def print_summary(report: dict, color: bool = True) -> None:
    summary = report["summary"]
    counts = summary["counts_by_severity"]
    def paint(text: str, sev: str) -> str:
        if not color:
            return text
        return f"{ANSI.get(sev, '')}{text}{ANSI_RESET}"

    print()
    print(f"  Scan of {', '.join(report['scope']['targets'])} — "
          f"{report['scope']['ports_scanned']} ports in "
          f"{report['metadata']['duration_seconds']}s")
    print(f"  {summary['open_services']} open service(s), "
          f"{summary['total_findings']} finding(s)\n")
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            label = SEV_META[sev]["label"]
            print(f"    {paint(f'{label:>14}', sev)}  {counts[sev]}")
    print()
    for finding in report["findings"]:
        if finding["severity"] == "informational":
            continue
        asset = finding["asset"]
        loc = asset.get("url") or f"{asset.get('host')}:{asset.get('port')}"
        sev_text = f"{finding['severity'].upper():<14}"
        sev_colored = paint(sev_text, finding["severity"]) if color else sev_text
        score = _cvss_of(finding).get("score")
        cvss_text = f" (CVSS {score})" if score is not None else ""
        print(f"  [{finding['id']}] {sev_colored} {finding['title']} — {loc}{cvss_text}")
    print()
