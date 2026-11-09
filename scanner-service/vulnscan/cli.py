"""Command-line interface for vulnscan."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import subprocess
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, advisories, pdf as pdf_mod
from .lab_exploits import run_lab_exploits
from . import config as config_mod
from .checks import run_checks
from .engines import (DEFAULT_NSE, ENGINE_CHOICES, NSE_CHOICES, EngineError,
                      nse_scripts, scan as run_engine_scan)
from .report import (build_report, confirmed_only, print_summary, write_csv,
                     write_html, write_json)
from .scanner import DEFAULT_TIMEOUT
from .targets import SpecError, parse_ports, parse_targets


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="Network/service vulnerability scanner with HTML and JSON reports.")
    parser.add_argument("targets", nargs="*",
                        help="hostnames, IPs or CIDR ranges to scan")
    parser.add_argument("-p", "--ports", default=None,
                        help="port spec: 'top' (default), 'all', or e.g. "
                             "'22,80,8000-8100'")
    parser.add_argument("--lab-exploits", action="store_true",
                        help="run fixed, non-destructive proof checks against "
                             "recognized vulnlab services on 127.0.0.1 only")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"per-probe timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("-o", "--output-dir", metavar="DIR", default=None,
                        help="directory for the automatic HTML/JSON reports "
                             "(default: saved config, otherwise out)")
    parser.add_argument("--pdf-dir", metavar="DIR", default=None,
                        help="directory for the automatic PDF report "
                             "(default: saved config, otherwise Downloads)")
    parser.add_argument("-c", "--concurrency", type=int, default=256,
                        help="max simultaneous probes (default 256)")
    parser.add_argument("--json", metavar="PATH", nargs="?", const="auto",
                        help="write JSON report to PATH (default: automatic)")
    parser.add_argument("--html", metavar="PATH", nargs="?", const="auto",
                        help="write HTML report to PATH (default: automatic)")
    parser.add_argument("--pdf", metavar="PATH", nargs="?", const="auto",
                        help="render a PDF report; with no PATH it goes to your "
                             "Downloads folder automatically (default: automatic)")
    parser.add_argument("--csv", metavar="PATH", nargs="?", const="auto",
                        help="write the asset inventory (host, port, protocol, "
                             "service, product, version, CPE) as CSV; with no "
                             "PATH it lands in the output directory")
    parser.add_argument("--no-html", action="store_true",
                        help="skip the automatic HTML report")
    parser.add_argument("--no-json", action="store_true",
                        help="skip the automatic JSON report")
    parser.add_argument("--no-pdf", action="store_true",
                        help="skip the automatic PDF report")
    parser.add_argument("--legacy-tls", action="store_true",
                        help="also test for TLS 1.0/1.1 support (slower)")
    parser.add_argument("--engine", choices=ENGINE_CHOICES, default="auto",
                        metavar="ENGINE",
                        help="detection engine: 'auto' prefers nmap and falls "
                             "back to the built-in scanner, 'nmap' requires "
                             "nmap, 'native' never uses it (default: auto)")
    parser.add_argument("--nse", choices=NSE_CHOICES, default=DEFAULT_NSE,
                        metavar="PROFILE",
                        help="nmap NSE evidence scripts: 'safe' (default, only "
                             "scripts nmap tags safe), 'extended' (adds read-only "
                             "but intrusive scripts: ssl-enum-ciphers, "
                             "ssh-auth-methods, http-enum), 'off' (none). "
                             "Vuln/exploit/DoS/brute categories are never run")
    parser.add_argument("--version-intensity", type=int, choices=range(2, 10),
                        default=None, metavar="2-9",
                        help="nmap service-detection effort (default: nmap's "
                             "own); lower is faster, higher identifies more")
    parser.add_argument("--db", metavar="PATH", default=None,
                        help="advisory database to use for this scan "
                             "(default: the cached database under ~/.cache/"
                             "vulnscan, or $VULNSCAN_DB)")
    parser.add_argument("--update-db", action="store_true",
                        help="download NVD CVE feeds, rebuild the advisory "
                             "database, then exit")
    parser.add_argument("--db-years", metavar="2021,2022", default=None,
                        help="years to include when rebuilding with "
                             "--update-db (default: the last six)")
    parser.add_argument("--strict", action="store_true",
                        help="report only findings proven by protocol-level "
                             "evidence (confidence: certain); suppressed "
                             "lower-confidence findings are counted in the "
                             "coverage section")
    parser.add_argument("--reference", metavar="TEXT", default=None,
                        help="authorisation or engagement reference recorded in "
                             "the report's scope section (e.g. a ticket or SOW id)")
    parser.add_argument("-r", "--report-name", metavar="NAME", default=None,
                        help="name this report: it becomes the report title and "
                             "the report/PDF file names "
                             "(e.g. -r \"ACME external, Nov 2026\")")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="suppress progress output")
    parser.add_argument("--no-color", action="store_true",
                        help="disable colored terminal output")
    parser.add_argument("--set-output-dir", metavar="DIR",
                        help="permanently save DIR as the report output "
                             "directory, then exit")
    parser.add_argument("--set-pdf-dir", metavar="DIR",
                        help="permanently save DIR as the PDF destination, "
                             "then exit")
    parser.add_argument("--reset-config", action="store_true",
                        help="clear all saved configuration, then exit")
    parser.add_argument("--show-config", action="store_true",
                        help="print the saved configuration, then exit")
    parser.add_argument("--version", action="version",
                        version=f"vulnscan {__version__}")
    return parser


def report_stem(name: str | None, stamp: str) -> str:
    """File stem shared by the report artifacts, e.g. ``vulnscan-acme-q1_<stamp>``.

    ``-r`` names the report rather than just decorating it, so the title, the
    file names and the PDF all carry the same name.
    """
    if not name or not name.strip():
        return f"vulnscan-report_{stamp}"
    ascii_name = (unicodedata.normalize("NFKD", name)
                  .encode("ascii", "ignore").decode("ascii"))
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")[:60]
    return f"vulnscan-{slug.rstrip('-') or 'report'}_{stamp}"


def _handle_config_flags(args) -> int:
    """Process config-management flags; return an exit code (0 = continue)."""
    cfg = config_mod.load_config()
    changed = False
    if args.set_output_dir is not None:
        cfg["output_dir"] = args.set_output_dir
        changed = True
        print(f"saved: automatic HTML/JSON reports go to {args.set_output_dir}")
    if args.set_pdf_dir is not None:
        cfg["pdf_dir"] = args.set_pdf_dir
        changed = True
        print(f"saved: automatic PDF reports go to {args.set_pdf_dir}")
    if args.reset_config:
        cfg = dict(config_mod.DEFAULTS)
        changed = True
        print("saved configuration cleared (defaults: out/ and Downloads)")
    if changed:
        config_mod.save_config(cfg)
        print(f"config written to {config_mod.CONFIG_PATH}")
    if args.show_config:
        saved = {k: v for k, v in cfg.items() if v is not None}
        if saved:
            print(f"config file: {config_mod.CONFIG_PATH}")
            for key, value in saved.items():
                print(f"  {key} = {value}")
        else:
            print("no saved configuration; defaults in effect "
                  "(out/ and Downloads)")
    return 0 if (changed or args.show_config) else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.update_db:
        years = None
        if args.db_years:
            try:
                years = [int(part) for part in args.db_years.split(",") if part.strip()]
            except ValueError:
                print("vulnscan: --db-years expects comma-separated years",
                      file=sys.stderr)
                return 2
        target = advisories.default_db_path() if not args.db else args.db
        print(f"rebuilding advisory database at {target}")
        try:
            info = advisories.update_database(target, years=years)
        except RuntimeError as exc:
            print(f"vulnscan: {exc}", file=sys.stderr)
            return 2
        print(f"  {info.advisories} rows for {info.cves} CVEs "
              f"(years {info.years}, built {info.built_at})")
        return 0

    if args.lab_exploits:
        if args.targets:
            print("vulnscan: --lab-exploits has a fixed loopback target; "
                  "do not provide targets", file=sys.stderr)
            return 2
        return run_lab_exploits()

    config_flags = (args.set_output_dir, args.set_pdf_dir,
                    args.reset_config, args.show_config)
    if any(f is not None and f is not False for f in config_flags):
        return _handle_config_flags(args)

    # Per-run flags win over the saved config; saved config wins over defaults.
    saved = config_mod.load_config()
    args.output_dir = args.output_dir or saved["output_dir"] or "out"
    pdf_dir = args.pdf_dir or saved["pdf_dir"]

    try:
        hosts = parse_targets(args.targets)
        ports = parse_ports(args.ports)
    except SpecError as exc:
        print(f"vulnscan: {exc}", file=sys.stderr)
        return 2

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    start = time.monotonic()

    def progress(done: int, total: int, result) -> None:
        if not args.quiet:
            sys.stderr.write(f"\r  probing {done}/{total} "
                             f"(open: {result.host}:{result.port})   ")
            sys.stderr.flush()

    if not args.quiet:
        print(f"vulnscan {__version__} — {len(hosts)} target(s), {len(ports)} port(s)")

    try:
        services, scan_meta = asyncio.run(run_engine_scan(
            hosts, ports, engine=args.engine, timeout=args.timeout,
            concurrency=args.concurrency,
            scripts=nse_scripts(args.nse),
            version_intensity=args.version_intensity,
            progress=progress if not args.quiet else None))
    except EngineError as exc:
        print(f"vulnscan: {exc}", file=sys.stderr)
        return 2
    if not args.quiet:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()
        used = scan_meta.get("engine", "native")
        detail = scan_meta.get("version") or ""
        print(f"  detected with {used}" + (f" ({detail})" if detail else ""))
        if scan_meta.get("fallback_reason"):
            print(f"  note: {scan_meta['fallback_reason']}")
        if used != "nmap" and args.nse == "extended":
            print("  note: --nse extended needs nmap; no script evidence "
                  "was collected")

    advisory_db = advisories.AdvisoryDB(args.db)
    if not args.quiet:
        if advisory_db.available:
            info = advisory_db.info()
            print(f"  advisory database: {info.cves} CVEs "
                  f"(built {info.built_at or 'unknown'})")
        else:
            print("  note: no advisory database; using built-in CVE fingerprints "
                  "(run --update-db for version-range matching)")
        unidentified = [svc for svc in services
                        if getattr(svc, "identification_error", "")]
        if unidentified:
            listed = ", ".join(f"{svc.port}/{svc.proto}" for svc in unidentified[:6])
            more = (f" (+{len(unidentified) - 6} more)"
                    if len(unidentified) > 6 else "")
            print(f"  note: {len(unidentified)} open service(s) could not be "
                  f"identified ({listed}{more}); reported as unidentified, "
                  "not as clean")

    try:
        findings = asyncio.run(run_checks(services, args.timeout,
                                          check_legacy_tls=args.legacy_tls,
                                          advisory_db=advisory_db))
    finally:
        advisory_meta = {
            "path": str(advisory_db.path),
            "available": advisory_db.available,
        }
        if advisory_db.available:
            info = advisory_db.info()
            advisory_meta.update({"cves": info.cves, "advisories": info.advisories,
                                  "built_at": info.built_at, "years": info.years})
        advisory_db.close()
    suppressed_by_strict = 0
    if args.strict:
        kept = confirmed_only(findings)
        suppressed_by_strict = len(findings) - len(kept)
        findings = kept
        if not args.quiet:
            print(f"  strict: {len(findings)} confirmed finding(s), "
                  f"{suppressed_by_strict} lower-confidence finding(s) "
                  "suppressed")
    duration = time.monotonic() - start

    # Reports are automatic by default: report files land in the output
    # directory (default out/), the PDF in Downloads. Explicit paths override;
    # --no-* flags opt out. -r names the report and therefore the file stem.
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    stem = report_stem(args.report_name, stamp)
    out_dir = args.output_dir
    json_path = None if args.no_json else (
        args.json if args.json else os.path.join(out_dir, f"{stem}.json"))
    html_path = None if args.no_html else (
        args.html if args.html else os.path.join(out_dir, f"{stem}.html"))
    if json_path == "auto":
        json_path = os.path.join(out_dir, f"{stem}.json")
    if html_path == "auto":
        html_path = os.path.join(out_dir, f"{stem}.html")
    csv_path = None if args.csv is None else (
        args.csv if args.csv != "auto"
        else os.path.join(out_dir, f"vulnscan-assets_{stamp}.csv"))

    # Raw nmap XML is saved beside the report so findings can be re-derived;
    # it is never embedded in the report itself.
    raw_xml = scan_meta.pop("_raw_xml", None)
    raw_path = None
    if raw_xml:
        anchor = json_path or html_path
        raw_path = ((os.path.splitext(anchor)[0] if anchor
                     else os.path.join(out_dir, f"vulnscan-raw_{stamp}"))
                    + ".nmap.xml")
        scan_meta["raw_xml"] = raw_path

    report = build_report(
        targets=hosts, ports=ports, services=services, findings=findings,
        started_at=started_at, duration_s=duration,
        options={"timeout": args.timeout, "concurrency": args.concurrency,
                 "legacy_tls_check": args.legacy_tls,
                 "engine_requested": args.engine, "nse_profile": args.nse,
                 "version_intensity": args.version_intensity,
                 "strict": args.strict,
                 "suppressed_by_strict": suppressed_by_strict,
                 "reference": args.reference or "",
                 "report_name": args.report_name or ""},
        scan_meta=scan_meta, advisory_meta=advisory_meta)

    color = sys.stdout.isatty() and not args.no_color
    print_summary(report, color=color)

    written = []
    if json_path:
        os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
        write_json(report, json_path)
        written.append(json_path)
    if raw_path:
        os.makedirs(os.path.dirname(raw_path) or ".", exist_ok=True)
        with open(raw_path, "w", encoding="utf-8") as handle:
            handle.write(raw_xml)
        written.append(raw_path)
    if html_path:
        os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
        write_html(report, html_path)
        written.append(html_path)
    if csv_path:
        os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
        write_csv(report, csv_path)
        written.append(csv_path)
    wants_pdf = (not args.no_pdf) if args.pdf is None else (args.pdf is not None)
    if wants_pdf and html_path:
        if args.pdf in (None, "auto"):
            target = (Path(pdf_dir) / pdf_mod.default_pdf_path(stem).name
                      if pdf_dir else pdf_mod.default_pdf_path(stem))
        else:
            target = Path(args.pdf)
        try:
            pdf_path = pdf_mod.html_to_pdf(Path(html_path), target)
            written.append(str(pdf_path))
        except (RuntimeError, subprocess.SubprocessError) as exc:
            print(f"vulnscan: PDF rendering failed: {exc}", file=sys.stderr)
    for path in written:
        print(f"  report written to {path}")
    if written:
        print()

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
