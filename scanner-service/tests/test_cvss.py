"""CVSS scoring tests: the vector is the source of truth for the score."""

from __future__ import annotations

import unittest

from vulnscan import checks, cvss
from vulnscan.checks import Finding

P = cvss.PREFIX


def finding(rule_id: str, severity: str, vector: str = "") -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=severity, confidence="firm",
        description="d", impact="i", evidence="e", remediation="r",
        asset={"host": "h", "ip": "127.0.0.1", "port": 443},
        cvss_vector=vector)


class VectorScoringTests(unittest.TestCase):
    def test_known_base_scores(self):
        cases = {
            P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N": 9.1,
            P + "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
            P + "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N": 7.4,
            P + "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
            P + "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N": 3.7,
            P + "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
            P + "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in cases.items():
            with self.subTest(vector=vector):
                self.assertEqual(expected, cvss.score_from_vector(vector))

    def test_scope_changed_scores(self):
        self.assertEqual(9.9, cvss.score_from_vector(
            P + "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"))
        self.assertEqual(6.1, cvss.score_from_vector(
            P + "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"))

    def test_version_prefix_is_optional(self):
        self.assertEqual(9.8, cvss.score_from_vector(
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))

    def test_malformed_vectors_raise(self):
        with self.assertRaises(cvss.VectorError):
            cvss.score_from_vector(P + "AV:N/AC:L")
        with self.assertRaises(cvss.VectorError):
            cvss.score_from_vector(P + "AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_bands_match_scanner_thresholds(self):
        self.assertEqual("critical", cvss.band_for(9.0))
        self.assertEqual("high", cvss.band_for(8.9))
        self.assertEqual("high", cvss.band_for(7.0))
        self.assertEqual("medium", cvss.band_for(6.9))
        self.assertEqual("medium", cvss.band_for(4.0))
        self.assertEqual("low", cvss.band_for(3.9))
        self.assertEqual("low", cvss.band_for(0.1))
        self.assertEqual("informational", cvss.band_for(0.0))


class CuratedVectorTests(unittest.TestCase):
    def test_every_rule_vector_lands_in_its_rule_band(self):
        """The score a rule carries must agree with the severity it emits."""
        expected: dict[str, str] = {}
        for port, entry in checks.EXPOSURE_RULES.items():
            expected.setdefault(entry[0], entry[2])
        for entry in checks.SECURITY_HEADERS:
            expected[entry[1]] = entry[3]
        expected.update({
            "VS-EXP-REDIS-NOAUTH": "critical", "VS-EXP-REDIS-AUTH": "medium",
            "VS-EXP-REDIS": "medium", "VS-EXP-MEMCACHED-NOAUTH": "critical",
            "VS-EXP-MEMCACHED": "medium", "VS-EXP-DOCKER": "critical",
            "VS-EXP-MONGODB": "high", "VS-FTP-ANON": "high",
            "VS-FTP-CLEARTEXT": "low", "VS-TLS-EXPIRED": "high",
            "VS-TLS-NOT-YET-VALID": "medium", "VS-TLS-EXPIRING": "medium",
            "VS-TLS-SELF-SIGNED": "low", "VS-TLS-HOSTNAME": "medium",
            "VS-TLS-WEAK-CIPHER": "high", "VS-TLS-LEGACY": "medium",
            "VS-HTTP-SERVER-VERSION": "low", "VS-HTTP-POWERED-BY": "low",
            "VS-HTTP-DIR-LISTING": "medium", "VS-HTTP-STACKTRACE": "medium",
            "VS-HTTP-COOKIE-NO-SECURE": "medium",
            "VS-HTTP-COOKIE-NO-HTTPONLY": "low",
            "VS-HTTP-CLEARTEXT": "informational",
            "VS-HTTP-ES-OPEN": "critical", "VS-HTTP-ES-EXPOSED": "medium",
            "VS-HTTP-DOCKER-VERSION": "critical", "VS-HTTP-ADMIN-OPEN": "high",
            "VS-CVE-2011-2523": "critical", "VS-CVE-2021-41773": "critical",
            "VS-CVE-2021-42013": "critical", "VS-CVE-2024-6387": "medium",
            "VS-EOL-SOFTWARE": "medium",
        })
        for rule_id, severity in expected.items():
            with self.subTest(rule=rule_id):
                vector = cvss.CURATED_VECTORS[rule_id]
                self.assertEqual(severity, cvss.band_for(
                    cvss.score_from_vector(vector)))

    def test_band_baselines_land_in_their_own_band(self):
        for band, vector in cvss.BAND_VECTORS.items():
            with self.subTest(band=band):
                self.assertEqual(band, cvss.band_for(
                    cvss.score_from_vector(vector)))


class DescribeTests(unittest.TestCase):
    def test_nvd_vector_wins_and_reports_its_version(self):
        block = cvss.describe(finding(
            "VS-CVE-2024-6387", "medium",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"))
        self.assertEqual("nvd", block["source"])
        self.assertEqual(5.9, block["score"])
        self.assertEqual("3.1", block["version"])
        self.assertEqual("medium", block["band"])

    def test_cvss_30_vector_is_labelled_30(self):
        block = cvss.describe(finding(
            "VS-CVE-2021-41773", "critical",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertEqual("3.0", block["version"])
        self.assertEqual(9.8, block["score"])

    def test_curated_rule_uses_its_own_vector(self):
        block = cvss.describe(finding("VS-EXP-REDIS-NOAUTH", "critical"))
        self.assertEqual("rule", block["source"])
        self.assertEqual(9.8, block["score"])
        self.assertEqual(cvss.CURATED_VECTORS["VS-EXP-REDIS-NOAUTH"],
                         block["vector"])

    def test_unknown_rule_falls_back_to_band_baseline(self):
        block = cvss.describe(finding("VS-FUTURE-RULE", "medium"))
        self.assertEqual("baseline", block["source"])
        self.assertEqual(cvss.BAND_VECTORS["medium"], block["vector"])
        self.assertEqual("medium", block["band"])

    def test_non_cvss3_vector_is_not_reused(self):
        # NVD CVSS 2.0 vectors cannot be scored with the 3.1 formula, so the
        # curated 3.1 vector for the rule is used instead of the v2 string.
        block = cvss.describe(finding(
            "VS-CVE-2011-2523", "critical", "AV:N/AC:L/Au:N/C:C/I:C/A:C"))
        self.assertEqual("rule", block["source"])
        self.assertEqual(cvss.CURATED_VECTORS["VS-CVE-2011-2523"],
                         block["vector"])
        self.assertEqual("critical", block["band"])


if __name__ == "__main__":
    unittest.main()
