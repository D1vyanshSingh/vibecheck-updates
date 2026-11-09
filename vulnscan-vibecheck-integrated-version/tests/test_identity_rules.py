"""Identity-driven rule tests: a port proposes, the protocol decides.

These pin the step-2 behaviour that removes false positives: a rule is
suppressed when the service is identified as something else, downgraded to
tentative when nothing identified it, and kept firm when nmap or the wire
confirmed the protocol.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from vulnscan import checks
from vulnscan.report import build_report, render_html
from vulnscan.scanner import PortService


def make_svc(port: int, service: str = "", source: str = "port", **kwargs) -> PortService:
    return PortService(host="host.test", ip="127.0.0.1", port=port, state="open",
                       service=service, identity_source=source, **kwargs)


class ExposureRuleTests(unittest.TestCase):
    def ids(self, svc: PortService) -> list[str]:
        return [f.rule_id for f in checks.check_exposure(svc)]

    def test_contradicted_port_rule_is_suppressed(self):
        # The acceptance test from the roadmap: HTTP on 5900 is not VNC.
        svc = make_svc(5900, "http", "http", http={"status": 200})
        self.assertEqual([], self.ids(svc))

    def test_confirmed_vnc_still_fires_firm(self):
        svc = make_svc(5900, "vnc", "banner", banner="RFB 003.008")
        findings = checks.check_exposure(svc)
        self.assertEqual(["VS-EXP-VNC"], [f.rule_id for f in findings])
        self.assertEqual("firm", findings[0].confidence)

    def test_unidentified_port_is_tentative_not_firm(self):
        svc = make_svc(3389, "ms-wbt")          # port-derived name only
        findings = checks.check_exposure(svc)
        self.assertEqual(1, len(findings))
        self.assertEqual("tentative", findings[0].confidence)
        self.assertIn("port-based lead", findings[0].evidence)

    def test_nmap_probed_rdp_is_firm(self):
        svc = make_svc(3389, "ms-wbt-server", "nmap", nmap_conf=10)
        findings = checks.check_exposure(svc)
        self.assertEqual("firm", findings[0].confidence)
        self.assertNotIn("port-based lead", findings[0].evidence)

    def test_conflicting_identifications_downgrade_and_are_reported(self):
        svc = make_svc(
            3389, "ms-wbt-server", "nmap", nmap_conf=10,
            identity_claims=[
                {"source": "nmap", "service": "ms-wbt-server", "confidence": 10},
                {"source": "http", "service": "http"},
            ])
        findings = checks.check_exposure(svc)
        self.assertEqual("tentative", findings[0].confidence)
        self.assertIn("Conflicting identifications", findings[0].evidence)
        self.assertIn("nmap=ms-wbt-server", findings[0].evidence)

    def test_nmap_port_table_guess_is_not_treated_as_a_claim(self):
        # nmap conf 3 means it never probed the port; its guess must not
        # outvote the protocol the wire actually showed.
        svc = make_svc(
            3389, "rdp", "banner",
            identity_claims=[
                {"source": "nmap", "service": "ms-wbt-server", "confidence": 3},
                {"source": "banner", "service": "rdp"},
            ])
        self.assertEqual([], checks.identity_conflicts(svc))

    def test_http_riding_service_is_not_a_conflict(self):
        # A Docker daemon identified by nmap and an HTTP response by the native
        # collector are the same protocol, not a disagreement.
        svc = make_svc(
            2375, "docker", "http", nmap_conf=10,
            identity_claims=[
                {"source": "nmap", "service": "docker", "confidence": 10},
                {"source": "http", "service": "http"},
            ])
        self.assertEqual([], checks.identity_conflicts(svc))


class EvidenceDrivenServiceTests(unittest.TestCase):
    def ids(self, svc: PortService) -> list[str]:
        return [f.rule_id for f in checks.check_exposure(svc)]

    def test_http_on_redis_port_is_not_reported_as_redis(self):
        svc = make_svc(6379, "http", "http", http={"status": 200})
        self.assertEqual([], [r for r in self.ids(svc) if "REDIS" in r])

    def test_redis_on_a_non_standard_port_is_found(self):
        svc = make_svc(6380, "redis", "banner",
                       banner="redis_version:7.0.0\r\nredis_mode:standalone")
        findings = checks.check_exposure(svc)
        self.assertEqual("VS-EXP-REDIS-NOAUTH", findings[0].rule_id)
        self.assertEqual("certain", findings[0].confidence)

    def test_docker_marker_decides_confidence(self):
        marked = make_svc(2375, "http", "http", http={
            "status": 200, "body_preview": '{"ApiVersion":"1.41","Version":"20.10.6"}',
            "server": ""})
        finding = [f for f in checks.check_exposure(marked)
                   if f.rule_id == "VS-EXP-DOCKER"][0]
        self.assertEqual("firm", finding.confidence)

        unmarked = make_svc(2375, "http", "http", http={
            "status": 200, "body_preview": "<html>hello</html>", "server": ""})
        finding = [f for f in checks.check_exposure(unmarked)
                   if f.rule_id == "VS-EXP-DOCKER"][0]
        self.assertEqual("tentative", finding.confidence)
        self.assertIn("unconfirmed", finding.description)

    def test_memcached_port_with_a_web_server_is_suppressed(self):
        svc = make_svc(11211, "http", "http", http={"status": 200})
        self.assertEqual([], [r for r in self.ids(svc) if "MEMCACHED" in r])


class SpecialServiceConfidenceTests(unittest.TestCase):
    def test_port_name_alone_does_not_make_a_database_finding_firm(self):
        for port, name in ((27017, "mongodb"), (11211, "memcached")):
            with self.subTest(service=name):
                findings = checks._check_special_service(make_svc(port, name, "port"))
                self.assertEqual(1, len(findings))
                self.assertEqual("tentative", findings[0].confidence)

    def test_wire_confirmed_databases_stay_firm(self):
        mongo = checks._check_special_service(make_svc(27017, "mongodb", "nmap"))
        self.assertEqual("firm", mongo[0].confidence)
        memcached = checks._check_special_service(make_svc(
            11211, "memcached", "banner", banner="STAT pid 1\r\n"))
        self.assertEqual("certain", memcached[0].confidence)

    def test_ftp_cleartext_is_tentative_when_only_the_port_spoke(self):
        svc = make_svc(21, "ftp", "port")
        with mock.patch.object(checks, "send_recv",
                               new=mock.AsyncMock(return_value="")):
            findings = asyncio.run(checks.check_ftp_anonymous([svc], 0.1))
        self.assertEqual("tentative", findings[0].confidence)


class FtpGateTests(unittest.TestCase):
    def test_identified_http_service_on_port_21_is_not_probed(self):
        svc = make_svc(21, "http", "http", http={"status": 200})
        with mock.patch.object(checks, "send_recv",
                               new=mock.AsyncMock()) as send:
            findings = asyncio.run(checks.check_ftp_anonymous([svc], 0.1))
        send.assert_not_awaited()
        self.assertEqual([], findings)

    def test_identified_ftp_on_a_non_standard_port_is_probed(self):
        svc = make_svc(2121, "ftp", "banner", banner="220 (vsFTPD 2.3.4)")
        with mock.patch.object(checks, "send_recv",
                               new=mock.AsyncMock(return_value="230 logged in")) as send:
            findings = asyncio.run(checks.check_ftp_anonymous([svc], 0.1))
        send.assert_awaited_once()
        self.assertIn("VS-FTP-ANON", [f.rule_id for f in findings])


class ScriptEvidenceTests(unittest.TestCase):
    """NSE output substantiates existing findings instead of adding new ones."""

    def finding(self, svc: PortService, rule_id: str):
        return [f for f in checks.check_exposure(svc) if f.rule_id == rule_id][0]

    def test_rdp_script_upgrades_a_port_only_guess(self):
        svc = make_svc(3389, "rdp", "port", scripts={
            "rdp-ntlm-info": "Target_Name: LAB\nProduct_Version: 10.0.19041"})
        finding = self.finding(svc, "VS-EXP-RDP")
        self.assertEqual("firm", finding.confidence)
        self.assertIn("nmap rdp-ntlm-info", finding.evidence)
        self.assertIn("Product_Version: 10.0.19041", finding.evidence)

    def test_rdp_script_error_proves_nothing(self):
        svc = make_svc(3389, "rdp", "port", scripts={
            "rdp-ntlm-info": "ERROR: Script execution failed."})
        finding = self.finding(svc, "VS-EXP-RDP")
        self.assertEqual("tentative", finding.confidence)
        self.assertNotIn("nmap rdp-ntlm-info", finding.evidence)

    def test_smb_script_output_is_quoted_as_evidence(self):
        svc = make_svc(445, "smb", "port", scripts={
            "smb-os-discovery": "OS: Windows Server 2019\nComputer name: DC01"})
        finding = self.finding(svc, "VS-EXP-SMB")
        self.assertEqual("firm", finding.confidence)
        self.assertIn("Windows Server 2019", finding.evidence)

    def test_docker_version_script_proves_the_daemon(self):
        svc = make_svc(2375, "http", "http",
                       http={"status": 200, "body_preview": "{}", "server": ""},
                       scripts={"docker-version": "Docker version: 20.10.6\n"
                                                  "API version: 1.41"})
        finding = self.finding(svc, "VS-EXP-DOCKER")
        # A script that read the daemon's own version output is protocol-level
        # proof, not a port-table guess: the finding is certain.
        self.assertEqual("certain", finding.confidence)
        self.assertIn("Docker version: 20.10.6", finding.evidence)


class ReportIdentityTests(unittest.TestCase):
    def build(self, *services: PortService, scan_meta: dict | None = None) -> tuple[dict, str]:
        findings = [f for svc in services for f in checks.check_exposure(svc)]
        report = build_report(
            targets=["host.test"], ports=[svc.port for svc in services],
            services=list(services), findings=findings,
            started_at="2026-01-01T00:00:00Z", duration_s=1.0,
            scan_meta=scan_meta or {"engine": "nmap"})
        return report, render_html(report)

    def test_appendix_names_how_each_service_was_identified(self):
        report, page = self.build(make_svc(3389, "ms-wbt-server", "nmap", nmap_conf=10))
        self.assertEqual("nmap", report["services"][0]["identity_source"])
        self.assertIn("Identified by", page)
        self.assertIn("nmap -sV", page)
        self.assertIn("1 by nmap -sV", page)

    def test_nse_output_reaches_the_report_appendix(self):
        svc = make_svc(3389, "rdp", "port", scripts={
            "rdp-ntlm-info": "Product_Version: 10.0.19041"})
        report, page = self.build(
            svc, scan_meta={"engine": "nmap", "scripts": ["rdp-ntlm-info"]})
        self.assertEqual("Product_Version: 10.0.19041",
                         report["services"][0]["scripts"]["rdp-ntlm-info"])
        self.assertIn("NSE script output", page)
        self.assertIn("Product_Version: 10.0.19041", page)
        self.assertIn("rdp-ntlm-info", page)      # scripts selected are named

    def test_version_detection_helper_noise_stays_out_of_the_appendix(self):
        svc = make_svc(8080, "http", "http", http={"status": 200}, scripts={
            "fingerprint-strings": "internal matcher noise",
            "http-title": "ACME Portal"})
        _, page = self.build(svc)
        self.assertIn("ACME Portal", page)
        self.assertNotIn("internal matcher noise", page)

    def test_conflicting_claims_are_labelled_and_downgraded(self):
        svc = make_svc(
            3389, "ms-wbt-server", "nmap", nmap_conf=10,
            identity_claims=[
                {"source": "nmap", "service": "ms-wbt-server", "confidence": 10},
                {"source": "http", "service": "http"},
            ])
        report, page = self.build(svc)
        self.assertEqual(2, len(report["services"][0]["identity_claims"]))
        self.assertEqual("tentative", report["findings"][0]["confidence"])
        self.assertIn("conflicting", page)


if __name__ == "__main__":
    unittest.main()
