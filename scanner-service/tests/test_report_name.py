"""``-r`` / ``--report-name``: naming a report names everything about it.

The name has to reach three places to be useful: the title a reader sees, the
JSON key a downstream tool reads, and the file names on disk. These tests pin
all three, plus the default that must not change when no name is given.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from vulnscan import pdf as pdf_mod
from vulnscan.cli import main, report_stem
from vulnscan.report import build_report, render_html


def build(report_name: str = "") -> dict:
    return build_report(
        targets=["10.0.0.1"], ports=[22, 80], services=[], findings=[],
        started_at="2026-11-05T00:00:00Z", duration_s=1.2,
        options={"report_name": report_name, "reference": "SOW-1"},
        scan_meta={"engine": "native", "argv": []},
        advisory_meta={"available": False, "path": ""})


class ReportNameTests(unittest.TestCase):
    def test_name_becomes_the_title(self):
        report = build("ACME Q1 external")
        self.assertEqual("ACME Q1 external", report["metadata"]["title"])
        self.assertEqual("ACME Q1 external", report["metadata"]["report_name"])

    def test_no_name_keeps_the_default_title(self):
        report = build()
        self.assertEqual("Vulnerability Scan Report", report["metadata"]["title"])
        self.assertEqual("", report["metadata"]["report_name"])

    def test_name_appears_on_the_page_and_in_the_html_title(self):
        page = render_html(build("ACME Q1 external"))
        self.assertIn("<h1>ACME Q1 external</h1>", page)
        self.assertIn("<title>ACME Q1 external — VibeCheck</title>", page)
        self.assertIn('class="kpis"', page)

    def test_markup_is_escaped(self):
        page = render_html(build("<script>alert(1)</script>"))
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


class ReportStemTests(unittest.TestCase):
    def test_default_stem_is_unchanged(self):
        self.assertEqual("vulnscan-report_2026-11-05_101500",
                         report_stem(None, "2026-11-05_101500"))
        self.assertEqual("vulnscan-report_2026-11-05_101500",
                         report_stem("   ", "2026-11-05_101500"))

    def test_name_is_slugged_into_the_stem(self):
        self.assertEqual("vulnscan-acme-q1-external_2026-11-05_101500",
                         report_stem("ACME Q1, external!", "2026-11-05_101500"))

    def test_accents_and_separators_collapse(self):
        self.assertEqual("vulnscan-muller-gmbh_2026-11-05_101500",
                         report_stem("  Müller — GmbH  ", "2026-11-05_101500"))

    def test_a_name_of_only_symbols_still_yields_a_stem(self):
        self.assertEqual("vulnscan-report_2026-11-05_101500",
                         report_stem("###", "2026-11-05_101500"))

    def test_pdf_default_path_uses_the_stem(self):
        path = pdf_mod.default_pdf_path("vulnscan-acme-q1_2026-11-05_101500")
        self.assertEqual("vulnscan-acme-q1_2026-11-05_101500.pdf", path.name)


class NamedScanWritesNamedFilesTests(unittest.TestCase):
    """One real scan: the name must reach the files on disk."""

    def test_scan_writes_files_named_after_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = main(["127.0.0.1", "-p", "1", "--engine", "native",
                             "-o", tmp, "-r", "ACME Q1", "-q",
                             "--no-pdf"])
            self.assertEqual(0, code)
            names = sorted(p.name for p in Path(tmp).iterdir())
            # The CLI stamps file names in local time, so the assertion must
            # too — UTC would flip the date either side of midnight.
            stamp = datetime.now().strftime("%Y-%m-%d")
            self.assertEqual(2, len(names), names)
            self.assertTrue(names[0].startswith("vulnscan-acme-q1_"), names)
            self.assertIn(stamp, names[0])
            self.assertTrue(names[0].endswith(".html"), names)
            self.assertTrue(names[1].endswith(".json"), names)


if __name__ == "__main__":
    unittest.main()
