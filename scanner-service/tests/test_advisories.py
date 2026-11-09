"""Offline advisory database tests: ingestion, ranges, distro handling, dedup.

No network and no nmap: a small NVD-shaped document is fed through the same
code path ``--update-db`` uses, and the resulting SQLite file is queried the
way a scan queries it.
"""

from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vulnscan import advisories, checks
from vulnscan.scanner import PortService

NVD_DOC = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {
                    "baseScore": 9.8, "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "2.4.49",
                    "versionEndExcluding": "2.4.50"}]}]}],
            }
        },
        {
            "cve": {
                "id": "CVE-2024-6387",
                "descriptions": [{"lang": "en", "value": "Signal handler race in OpenSSH."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "8.5",
                    "versionEndExcluding": "9.8"}]}]}],
            }
        },
        {
            "cve": {
                "id": "CVE-2022-1234",
                "descriptions": [{"lang": "en", "value": "A flaw fixed in nginx 1.18.1."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3}}]},
                "configurations": [{"nodes": [{"cpeMatch": [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                        "versionEndIncluding": "1.18.0"},
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                        "versionEndIncluding": "1.18.0"},
                ]}]}],
            }
        },
        {
            "cve": {
                "id": "CVE-2099-0001",
                "descriptions": [{"lang": "en", "value": "Wildcard-only entry with no range."}],
                "configurations": [{"nodes": [{"cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}]}]}],
            }
        },
    ]
}


def make_svc(product: str, version: str, **kwargs) -> PortService:
    return PortService(host="host.test", ip="127.0.0.1", port=8080, state="open",
                       service="http", product=product, version=version,
                       identity_source="http", **kwargs)


class VersionTests(unittest.TestCase):
    def test_numeric_ordering(self):
        self.assertTrue(advisories.version_lt("2.4.9", "2.4.10"))
        self.assertTrue(advisories.version_lt("9.6p1", "9.8"))
        self.assertFalse(advisories.version_lt("2.4.49", "2.4.49"))

    def test_distro_suffix_is_split_from_the_upstream_version(self):
        self.assertEqual(("1.18.0", "ubuntu"),
                         advisories.split_version("1.18.0-1ubuntu1"))
        self.assertEqual(("9.6p1", "ubuntu"),
                         advisories.split_version("9.6p1-3ubuntu13"))
        self.assertEqual(("2.4.49", ""), advisories.split_version("2.4.49"))
        self.assertEqual(("2.4.49", "red hat"),
                         advisories.split_version("2.4.49-1.el8"))
        self.assertEqual(("9.6p1", "ubuntu"),
                         advisories.split_version("9.6p1", "Ubuntu 22.04"))

    def test_product_names_map_onto_cpe_products(self):
        self.assertEqual("apache-httpd", advisories.product_key("Apache httpd"))
        self.assertEqual("openssh", advisories.product_key("OpenSSH"))
        self.assertEqual("postgresql", advisories.product_key("PostgreSQL"))
        self.assertIsNone(advisories.product_key("Apache Tomcat"))
        self.assertIsNone(advisories.product_key(""))


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "advisories.sqlite3"
        self.rows = advisories.rows_from_nvd(NVD_DOC)
        advisories.build_database(self.rows, self.path)
        self.db = advisories.AdvisoryDB(self.path)
        self.addCleanup(self.db.close)

    def test_schema_and_metadata_are_recorded(self):
        info = self.db.info()
        self.assertTrue(info.exists)
        self.assertGreater(info.advisories, 0)
        self.assertEqual(3, info.cves)   # wildcard-only CVE skipped
        self.assertTrue(info.built_at)

    def test_range_start_is_inclusive_and_fix_is_exclusive(self):
        self.assertEqual(["CVE-2021-41773"],
                         [a.cve for a in self.db.lookup("apache-httpd", "2.4.49")])
        self.assertEqual([], self.db.lookup("apache-httpd", "2.4.48"))
        self.assertEqual([], self.db.lookup("apache-httpd", "2.4.50"))

    def test_version_end_including_is_honoured(self):
        self.assertEqual(["CVE-2022-1234"],
                         [a.cve for a in self.db.lookup("nginx", "1.18.0")])
        self.assertEqual([], self.db.lookup("nginx", "1.18.1"))

    def test_one_advisory_per_cve_across_duplicate_cpes(self):
        # nginx is listed under both nginx:nginx and f5:nginx; still one CVE.
        matches = self.db.lookup("nginx", "1.18.0")
        self.assertEqual(1, len(matches))
        self.assertEqual("medium", matches[0].severity)   # 5.3 -> medium

    def test_exact_release_encoded_in_the_cpe_criteria_is_matched(self):
        # NVD encodes a single affected release inside the criteria string:
        # cpe:2.3:a:apache:http_server:2.4.49:*:… with no range attributes.
        doc = {"vulnerabilities": [{"cve": {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "en", "value": "Path traversal."}],
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
            }]}]}],
        }}]}
        db = advisories.AdvisoryDB(Path(self.tmp.name) / "exact.sqlite3")
        self.addCleanup(db.close)
        advisories.build_database(advisories.rows_from_nvd(doc), db.path)
        self.assertEqual(["CVE-2021-41773"],
                         [a.cve for a in db.lookup("apache-httpd", "2.4.49")])
        self.assertEqual([], db.lookup("apache-httpd", "2.4.50"))

    def test_wildcard_only_entries_are_not_imported(self):
        cves = {a.cve for a in self.db.lookup("php", "8.1.0")}
        self.assertNotIn("CVE-2099-0001", cves)

    def test_missing_database_is_unavailable_not_fatal(self):
        db = advisories.AdvisoryDB(Path(self.tmp.name) / "nope.sqlite3")
        self.assertFalse(db.available)
        self.assertEqual([], db.lookup("nginx", "1.18.0"))
        self.assertFalse(db.info().exists)

    def test_corrupt_database_is_unavailable(self):
        bad = Path(self.tmp.name) / "bad.sqlite3"
        bad.write_text("not a database", encoding="utf-8")
        db = advisories.AdvisoryDB(bad)
        self.assertFalse(db.available)
        self.assertEqual([], db.lookup("nginx", "1.18.0"))


class FingerprintIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = advisories.AdvisoryDB(Path(self.tmp.name) / "advisories.sqlite3")
        advisories.build_database(advisories.rows_from_nvd(NVD_DOC), self.db.path)
        self.addCleanup(self.db.close)

    def ids(self, svc: PortService) -> list[str]:
        return [f.rule_id for f in checks.check_fingerprints(svc, self.db)]

    def test_upstream_version_in_range_is_firm(self):
        svc = make_svc("nginx", "1.18.0")
        findings = [f for f in checks.check_fingerprints(svc, self.db)
                    if f.cve == ["CVE-2022-1234"]]
        self.assertEqual(1, len(findings))
        self.assertEqual("firm", findings[0].confidence)
        self.assertIn("versions before 1.18.0", findings[0].evidence)

    def test_distro_build_is_tentative_and_says_why(self):
        svc = make_svc("nginx", "1.18.0-1ubuntu1")
        findings = [f for f in checks.check_fingerprints(svc, self.db)
                    if f.cve == ["CVE-2022-1234"]]
        self.assertEqual(1, len(findings))
        self.assertEqual("tentative", findings[0].confidence)
        self.assertIn("ubuntu package revision", findings[0].description)
        self.assertIn("backport status unknown", findings[0].evidence)

    def test_distro_hint_from_nmap_extrainfo_also_downgrades(self):
        svc = make_svc("nginx", "1.18.0", extrainfo="Ubuntu 22.04")
        findings = [f for f in checks.check_fingerprints(svc, self.db)
                    if f.cve == ["CVE-2022-1234"]]
        self.assertEqual("tentative", findings[0].confidence)

    def test_hardcoded_rule_and_database_do_not_duplicate_a_cve(self):
        svc = make_svc("Apache httpd", "2.4.49")
        matches = [f for f in checks.check_fingerprints(svc, self.db)
                   if "CVE-2021-41773" in f.cve]
        self.assertEqual(1, len(matches))
        self.assertEqual("VS-CVE-2021-41773", matches[0].rule_id)

    def test_unmapped_products_get_no_advisory_findings(self):
        svc = make_svc("Apache Tomcat", "9.0.1")
        self.assertEqual([], [f for f in checks.check_fingerprints(svc, self.db)
                              if f.rule_id.startswith("VS-CVE-")])

    def test_no_database_falls_back_to_builtin_fingerprints(self):
        svc = make_svc("vsftpd", "2.3.4")
        ids = [f.rule_id for f in checks.check_fingerprints(svc, None)]
        self.assertIn("VS-CVE-2011-2523", ids)


class UpdateTests(unittest.TestCase):
    def test_update_builds_the_database_from_downloaded_feeds(self):
        payload = gzip.compress(json.dumps(NVD_DOC).encode("utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "advisories.sqlite3"
            with mock.patch.object(advisories, "_download", return_value=payload):
                info = advisories.update_database(path, years=[2024], log=lambda *_: None)
            self.assertEqual(3, info.cves)
            self.assertEqual("2024", info.years)
            self.assertTrue(path.is_file())

    def test_update_reports_a_download_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "advisories.sqlite3"
            with mock.patch.object(advisories, "_download",
                                   side_effect=OSError("offline")):
                with self.assertRaises(RuntimeError):
                    advisories.update_database(path, years=[2024], log=lambda *_: None)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
