"""Guidance tests: every rule is actionable for both teams.

The report promises an ATT&CK technique, a detection line and a validation
next step on every finding. That is only true if every rule has an entry, so
these tests read the rule ids out of the checks module instead of trusting a
hand-maintained list.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from vulnscan import checks, guidance
from vulnscan.checks import Finding

CHECKS_SOURCE = Path(checks.__file__).read_text(encoding="utf-8")
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def finding(rule_id: str, severity: str = "medium",
            confidence: str = "firm") -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=severity, confidence=confidence,
        description="d", impact="i", evidence="e", remediation="r",
        asset={"host": "h", "ip": "127.0.0.1", "port": 443})


def rule_ids() -> set[str]:
    ids = set(re.findall(r'rule_id="([^"]+)"', CHECKS_SOURCE))
    ids.update(entry[0] for entry in checks.EXPOSURE_RULES.values())
    ids.update(entry[1] for entry in checks.SECURITY_HEADERS)
    return ids


class CoverageTests(unittest.TestCase):
    def test_the_source_scan_finds_the_rules(self):
        # A regex that silently matches nothing would make the coverage test
        # below pass while checking nothing at all.
        self.assertGreaterEqual(len(rule_ids()), 50)

    def test_every_rule_has_guidance(self):
        missing = sorted(rule_ids() - set(guidance.GUIDANCE))
        self.assertEqual([], missing, "rules without guidance entries")

    def test_no_guidance_entry_is_orphaned(self):
        known = rule_ids()
        # VS-HTTP-HSTS / VS-HTTP-CSP are emitted from SECURITY_HEADERS, which
        # the set above includes; anything else must belong to a rule id.
        orphaned = sorted(set(guidance.GUIDANCE) - known)
        self.assertEqual([], orphaned, "guidance for rules that do not exist")

    def test_every_entry_has_techniques_and_both_audiences(self):
        for rule_id, entry in guidance.GUIDANCE.items():
            with self.subTest(rule=rule_id):
                self.assertTrue(entry.attack)
                self.assertTrue(entry.detection.strip())
                self.assertTrue(entry.next_step.strip())

    def test_technique_ids_are_well_formed_and_named(self):
        for rule_id, entry in guidance.GUIDANCE.items():
            for technique_id, name in entry.attack:
                with self.subTest(rule=rule_id, technique=technique_id):
                    self.assertRegex(technique_id, ATTACK_ID)
                    self.assertTrue(name.strip())


class ForFindingTests(unittest.TestCase):
    def test_a_ruled_finding_gets_its_own_entry(self):
        block = guidance.for_finding(finding("VS-EXP-REDIS-NOAUTH", "critical"))
        self.assertEqual("rule", block["source"])
        self.assertIn("T1190", [item["id"] for item in block["attack"]])
        self.assertIn("CONFIG", block["detection"])
        self.assertTrue(block["next_step"])

    def test_an_unknown_cve_uses_the_cve_family_fallback(self):
        block = guidance.for_finding(finding("VS-CVE-2026-0001", "critical"))
        self.assertEqual("cve-family", block["source"])
        self.assertEqual(["T1190", "T1210", "T1059"],
                         [item["id"] for item in block["attack"]])
        self.assertIn("vendor advisory", block["next_step"])

    def test_an_unmapped_rule_still_renders_guidance(self):
        block = guidance.for_finding(finding("VS-FUTURE-RULE"))
        self.assertEqual("default", block["source"])
        self.assertTrue(block["detection"])
        self.assertTrue(block["next_step"])

    def test_every_known_rule_returns_all_three_fields(self):
        for rule_id in sorted(rule_ids()):
            block = guidance.for_finding(finding(rule_id))
            with self.subTest(rule=rule_id):
                self.assertGreaterEqual(len(block["attack"]), 1)
                self.assertTrue(block["detection"])
                self.assertTrue(block["next_step"])


class EntryPointTests(unittest.TestCase):
    def test_anonymous_access_is_an_entry_point(self):
        self.assertTrue(guidance.is_entry_point(
            finding("VS-EXP-REDIS-NOAUTH", "critical", "certain")))
        self.assertTrue(guidance.is_entry_point(
            finding("VS-FTP-ANON", "high", "certain")))

    def test_a_tentative_match_is_not_an_entry_point(self):
        # A distro build guess is not a foothold until somebody verifies it.
        self.assertFalse(guidance.is_entry_point(
            finding("VS-CVE-2024-6387", "medium", "tentative")))
        self.assertFalse(guidance.is_entry_point(
            finding("VS-EXP-MONGODB", "high", "tentative")))

    def test_a_confirmed_remote_vulnerability_is_an_entry_point(self):
        self.assertTrue(guidance.is_entry_point(
            finding("VS-CVE-2021-41773", "critical", "firm")))

    def test_a_medium_cve_is_context_not_access(self):
        self.assertFalse(guidance.is_entry_point(
            finding("VS-CVE-2026-0001", "medium", "firm")))

    def test_hardening_findings_are_not_entry_points(self):
        for rule_id in ("VS-HTTP-XFO", "VS-TLS-EXPIRED", "VS-EOL-SOFTWARE"):
            with self.subTest(rule=rule_id):
                self.assertFalse(guidance.is_entry_point(
                    finding(rule_id, "high", "certain")))


if __name__ == "__main__":
    unittest.main()
