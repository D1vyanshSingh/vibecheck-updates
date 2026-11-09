"""Client-ready report tests: section order, CVSS, host rollup, strict."""

from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from vulnscan import cvss
from vulnscan.checks import Finding
from vulnscan.report import (CSV_COLUMNS, build_report, confirmed_only,
                             render_html, write_csv)
from vulnscan.scanner import PortService


def svc(host: str, port: int, service: str, product: str = "", version: str = "",
        cpe: list[str] | None = None) -> PortService:
    return PortService(host=host, ip="10.0.0.1", port=port, state="open",
                       service=service, product=product, version=version,
                       identity_source="nmap", cpe=cpe or [],
                       banner=f"{service} banner")


def finding(rule_id: str, severity: str, host: str, port: int,
            confidence: str = "certain", vector: str = "") -> Finding:
    return Finding(
        rule_id=rule_id, title=f"{rule_id} on {host}:{port}", severity=severity,
        confidence=confidence, description="description", impact="impact",
        evidence="evidence", remediation="apply the vendor fix",
        asset={"host": host, "ip": "10.0.0.1", "port": port, "protocol": "tcp"},
        cwe=["CWE-79"], cve=[], references=[], cvss_vector=vector)


SERVICES = [
    svc("a.example", 443, "https", "nginx", "1.18.0",
        ["cpe:/a:igor_sysoev:nginx:1.18.0"]),
    svc("a.example", 6379, "redis", "Redis", "6.0.9"),
    svc("b.example", 22, "ssh", "OpenSSH", "9.6p1"),
]

FINDINGS = [
    finding("VS-EXP-REDIS-NOAUTH", "critical", "a.example", 6379),
    finding("VS-TLS-EXPIRED", "high", "a.example", 443, confidence="firm"),
    finding("VS-CVE-2024-6387", "medium", "b.example", 22,
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    finding("VS-HTTP-XFO", "low", "b.example", 22, confidence="tentative"),
]

COVERAGE = {
    "engine": "nmap", "version": "7.94",
    "argv": ["nmap", "-sV", "-p", "22,443,6379", "a.example", "b.example"],
    "privileged": True, "scripts": ["ssl-cert", "http-title"],
    "duration_seconds": 12.5,
}


def report(**options) -> dict:
    opts = {"timeout": 5.0, "concurrency": 64, "nse_profile": "safe",
            "version_intensity": 7}
    opts.update(options)
    return build_report(
        targets=["a.example", "b.example"], ports=[22, 443, 6379],
        services=SERVICES, findings=FINDINGS,
        started_at="2026-11-04T10:00:00Z", duration_s=12.5,
        options=opts, scan_meta=dict(COVERAGE),
        advisory_meta={"available": True, "cves": 316,
                       "built_at": "2026-11-01T00:00:00Z",
                       "path": "/tmp/advisories.sqlite3"})


class JsonFindingTests(unittest.TestCase):
    def test_schema_version_records_the_latest_additions(self):
        data = report()
        self.assertEqual("1.3", data["report_version"])
        self.assertIn("coverage", data)
        self.assertIn("cvss", data["findings"][0])
        self.assertIn("attack", data["findings"][0])

    def test_every_finding_carries_both_teams_guidance(self):
        for item in report()["findings"]:
            with self.subTest(rule=item["rule_id"]):
                self.assertGreaterEqual(len(item["attack"]), 1)
                self.assertTrue(item["detection"])
                self.assertTrue(item["next_step"])
                self.assertIn("id", item["attack"][0])
                self.assertIn("name", item["attack"][0])

    def test_guidance_source_and_entry_point_are_recorded(self):
        by_rule = {f["rule_id"]: f for f in report()["findings"]}
        self.assertEqual("rule", by_rule["VS-EXP-REDIS-NOAUTH"]["provenance"]["guidance"])
        self.assertTrue(by_rule["VS-EXP-REDIS-NOAUTH"]["entry_point"])
        self.assertFalse(by_rule["VS-HTTP-XFO"]["entry_point"])

    def test_every_finding_carries_a_cvss_block(self):
        data = report()
        self.assertEqual(len(FINDINGS), len(data["findings"]))
        for item in data["findings"]:
            block = item["cvss"]
            with self.subTest(rule=item["rule_id"]):
                self.assertTrue(block["vector"].startswith("CVSS:3."))
                self.assertGreaterEqual(block["score"], 0.0)
                self.assertEqual(item["severity"], block["band"])

    def test_curated_and_baseline_sources_are_recorded(self):
        by_rule = {f["rule_id"]: f["cvss"] for f in report()["findings"]}
        self.assertEqual("rule", by_rule["VS-EXP-REDIS-NOAUTH"]["source"])
        self.assertEqual("nvd", by_rule["VS-CVE-2024-6387"]["source"])
        self.assertEqual(5.9, by_rule["VS-CVE-2024-6387"]["score"])

    def test_confidence_is_still_stated(self):
        by_rule = {f["rule_id"]: f for f in report()["findings"]}
        self.assertEqual("firm", by_rule["VS-TLS-EXPIRED"]["confidence"])


class CoverageTests(unittest.TestCase):
    def test_coverage_records_what_ran(self):
        coverage = report()["coverage"]
        self.assertEqual("nmap", coverage["engine"])
        self.assertEqual("7.94", coverage["engine_version"])
        self.assertIn("nmap -sV", coverage["command"])
        self.assertTrue(coverage["privileged"])
        self.assertEqual(["ssl-cert", "http-title"], coverage["scripts"])
        self.assertEqual(3, coverage["ports_scanned"])
        self.assertEqual("a.example", coverage["targets"][0])
        self.assertTrue(any("UDP" in item for item in coverage["not_tested"]))
        self.assertEqual(5.0, coverage["timeout_s"])

    def test_strict_filter_is_recorded(self):
        kept = confirmed_only(FINDINGS)
        self.assertEqual(2, len(kept))
        self.assertEqual({"VS-EXP-REDIS-NOAUTH", "VS-CVE-2024-6387"},
                         {f.rule_id for f in kept})
        coverage = report(strict=True, suppressed_by_strict=2)["coverage"]
        self.assertTrue(coverage["strict"])
        self.assertEqual(2, coverage["suppressed_by_strict"])

    def test_authorisation_reference_is_recorded(self):
        coverage = report(reference="SOW-2026-14")["coverage"]
        self.assertEqual("SOW-2026-14", coverage["authorisation_reference"])


class HtmlStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.html = render_html(report(reference="SOW-2026-14"))

    def test_sections_appear_in_client_order(self):
        order = [
            "1. Scope and authorisation",
            "2. Coverage and provenance",
            "3. Executive summary",
            "4. Asset inventory",
            "5. Per-host rollup",
            "6. Findings",
            "7. Recommendations",
            "8. Methodology and limits",
            "9. Appendix",
        ]
        positions = [self.html.index(heading) for heading in order]
        self.assertEqual(positions, sorted(positions))
        # Coverage must precede the findings, not trail them.
        self.assertLess(self.html.index("2. Coverage and provenance"),
                        self.html.index("6. Findings"))

    def test_scope_states_authorisation_and_not_tested(self):
        self.assertIn("SOW-2026-14", self.html)
        self.assertIn("Explicitly not tested", self.html)
        self.assertIn("UDP, SCTP", self.html)

    def test_coverage_shows_command_privilege_and_scripts(self):
        self.assertIn("nmap -sV", self.html)
        self.assertIn("raw-socket privileges", self.html)
        self.assertIn("ssl-cert, http-title", self.html)
        self.assertIn("9.0–10.0", self.html)

    def test_every_finding_card_shows_its_cvss_vector(self):
        for item in report()["findings"]:
            with self.subTest(rule=item["rule_id"]):
                self.assertIn(item["cvss"]["vector"], self.html)
                self.assertIn(f'CVSS {item["cvss"]["score"]}', self.html)

    def test_each_host_gets_its_own_page_block(self):
        self.assertEqual(2, self.html.count('class="hostpage"'))
        self.assertIn('id="host-a-example"', self.html)
        self.assertIn('id="host-b-example"', self.html)
        # Only hosts after the first break to a new page, so the section heading
        # is not left alone at the bottom of the preceding page in the PDF.
        self.assertIn(".hostpage ~ .hostpage { break-before: page; }", self.html)

    def test_host_block_does_not_repeat_the_ip_as_a_hostname(self):
        same = [svc("10.0.0.1", 443, "https", "nginx", "1.18.0")]
        data = build_report(targets=["10.0.0.1"], ports=[443], services=same,
                            findings=[], started_at="2026-11-04T10:00:00Z",
                            duration_s=0.4, options={}, scan_meta={})
        page = render_html(data)
        self.assertIn('<h3 class="host-head">10.0.0.1\n    </h3>', page)
        self.assertNotIn('10.0.0.1\n    <span class="mono small">10.0.0.1</span>',
                         page)

    def test_host_rollup_lists_services_and_fix_first(self):
        self.assertIn("What is running", self.html)
        self.assertIn("What is wrong", self.html)
        self.assertIn("What to fix first", self.html)
        self.assertIn("Redis", self.html)

    def test_asset_inventory_carries_cpe(self):
        self.assertIn("cpe:/a:igor_sysoev:nginx:1.18.0", self.html)

    def test_top_findings_lead_with_the_worst(self):
        self.assertIn("What matters most", self.html)
        self.assertLess(self.html.index("VS-EXP-REDIS-NOAUTH on a.example:6379"),
                        self.html.index("VS-TLS-EXPIRED on a.example:443"))

    def test_finding_card_shows_attack_detection_and_validation(self):
        self.assertIn("Attack techniques (MITRE ATT&amp;CK)", self.html)
        self.assertIn("Detection (blue team)", self.html)
        self.assertIn("Validation next step (red team)", self.html)
        # Redis noauth is on T1190 in the guidance table.
        self.assertIn("T1190", self.html)
        self.assertIn("Exploit Public-Facing Application", self.html)

    def test_initial_access_candidates_lead_with_the_entry_points(self):
        self.assertIn("Initial access candidates", self.html)
        block = self.html.split("Initial access candidates", 1)[1]
        block = block.split("Critical severity vulnerability", 1)[0]
        self.assertIn("VS-EXP-REDIS-NOAUTH on a.example:6379", block)
        self.assertNotIn("VS-HTTP-XFO", block)

    def test_no_entry_points_says_so(self):
        data = build_report(targets=["a.example"], ports=[22],
                            services=[svc("a.example", 22, "ssh")],
                            findings=[finding("VS-HTTP-XFO", "low", "a.example", 22)],
                            started_at="2026-11-04T10:00:00Z", duration_s=1.0,
                            options={}, scan_meta={})
        page = render_html(data)
        self.assertIn("No finding in this report is a credential-free", page)
        self.assertNotIn("<h3 style=\"font-size:1.05rem;margin:1.8rem 0 .5rem\">Initial access", page)

    def test_methodology_states_confidence_and_cvss_semantics(self):
        self.assertIn("The service answered and the response itself", self.html)
        self.assertIn("How CVSS was assigned", self.html)
        self.assertIn("What this scan cannot see", self.html)

    def test_raw_xml_reference_is_shown_when_saved(self):
        meta = dict(COVERAGE, raw_xml="/reports/scan.nmap.xml")
        data = build_report(targets=["a.example"], ports=[443],
                            services=SERVICES[:1], findings=[],
                            started_at="2026-11-04T10:00:00Z", duration_s=1.0,
                            options={}, scan_meta=meta)
        self.assertIn("/reports/scan.nmap.xml", render_html(data))

    def test_no_raw_xml_says_so(self):
        self.assertIn("No raw engine output was saved", self.html)


class CsvExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "assets.csv"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def rows(self) -> list[dict]:
        with self.path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))

    def test_header_and_one_row_per_service(self):
        write_csv(report(), str(self.path))
        rows = self.rows()
        self.assertEqual(3, len(rows))
        self.assertEqual(CSV_COLUMNS, list(rows[0].keys()))
        for required in ("host", "port", "protocol", "service", "product",
                         "version", "cpe"):
            self.assertIn(required, rows[0])

    def test_rows_carry_identity_and_finding_counts(self):
        write_csv(report(), str(self.path))
        rows = self.rows()
        web = next(r for r in rows if r["port"] == "443")
        self.assertEqual("a.example", web["host"])
        self.assertEqual("nginx", web["product"])
        self.assertEqual("1.18.0", web["version"])
        self.assertEqual("cpe:/a:igor_sysoev:nginx:1.18.0", web["cpe"])
        self.assertEqual("nmap", web["identified_by"])
        self.assertEqual("1", web["findings"])
        redis = next(r for r in rows if r["port"] == "6379")
        self.assertEqual("1", redis["critical"])

    def test_values_with_commas_are_quoted(self):
        odd = PortService(host="a.example", ip="10.0.0.1", port=8000,
                          state="open", service="http",
                          product="Acme, Inc", version="1.0 (beta)",
                          identity_source="http", cpe=[])
        data = build_report(targets=["a.example"], ports=[8000], services=[odd],
                            findings=[], started_at="2026-11-04T10:00:00Z",
                            duration_s=0.2, options={}, scan_meta={})
        write_csv(data, str(self.path))
        raw = self.path.read_text(encoding="utf-8")
        self.assertIn('"Acme, Inc"', raw)
        self.assertEqual("Acme, Inc", self.rows()[0]["product"])

    def test_empty_scan_writes_the_header_only(self):
        data = build_report(targets=["a.example"], ports=[443], services=[],
                            findings=[], started_at="2026-11-04T10:00:00Z",
                            duration_s=0.2, options={}, scan_meta={})
        write_csv(data, str(self.path))
        self.assertEqual([], self.rows())
        self.assertEqual(",".join(CSV_COLUMNS),
                         self.path.read_text(encoding="utf-8").splitlines()[0])

    def test_multiple_cpes_are_joined_for_one_cell(self):
        multi = svc("a.example", 443, "https", "nginx", "1.18.0",
                    ["cpe:/a:igor_sysoev:nginx:1.18.0",
                     "cpe:/a:f5:nginx:1.18.0"])
        data = build_report(targets=["a.example"], ports=[443], services=[multi],
                            findings=[], started_at="2026-11-04T10:00:00Z",
                            duration_s=0.2, options={}, scan_meta={})
        write_csv(data, str(self.path))
        self.assertEqual("cpe:/a:igor_sysoev:nginx:1.18.0;cpe:/a:f5:nginx:1.18.0",
                         self.rows()[0]["cpe"])


class NoFindingsTests(unittest.TestCase):
    def test_empty_scan_renders_without_crashing(self):
        data = build_report(targets=["a.example"], ports=[443], services=[],
                            findings=[], started_at="2026-11-04T10:00:00Z",
                            duration_s=0.5, options={}, scan_meta={})
        page = render_html(data)
        self.assertIn("No open ports found.", page)
        self.assertIn("No findings matched the scan checks.", page)
        self.assertIn("1. Scope and authorisation", page)


if __name__ == "__main__":
    unittest.main()
