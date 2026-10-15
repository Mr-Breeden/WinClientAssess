import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from utils.reporting import AssessmentReporter


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(attributes["id"])
        if tag == "a" and attributes.get("href"):
            self.hrefs.append(attributes["href"])


class ReportingTests(unittest.TestCase):
    def test_reporter_writes_real_line_breaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = AssessmentReporter(root, "Test", Path("Client.exe"), "static", "1.0.0")
            reporter.set_status("Example", "PASS", "line one\nline two")
            coverage = reporter.finalize()
            text = (root / "module_status.txt").read_text(encoding="utf-8")
            self.assertNotIn(r"\\n", text)
            self.assertIn("line one", text)
            self.assertEqual("COMPLETE", coverage)
            self.assertTrue((root / "coverage_summary.txt").is_file())
            self.assertTrue((root / "assessment_report.html").is_file())

    def test_consolidated_html_sorts_findings_links_evidence_and_escapes_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "binary_security_review.txt").write_text("evidence", encoding="utf-8")
            reporter = AssessmentReporter(
                root,
                "Client <script>alert(1)</script>",
                Path(r"C:\Sensitive\Path\Client.exe"),
                "static",
                "1.2.1",
            )
            reporter.set_status("PE Security Review", "WARN", "Review <unsafe> output")
            reporter.add_finding(
                title="Informational item",
                severity="Informational",
                source_module="PE Security Review",
            )
            reporter.add_finding(
                title="High item",
                severity="High",
                source_module="PE Security Review",
                evidence="A < B",
            )
            reporter.finalize()

            report = (root / "assessment_report.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", report)
            self.assertIn("Client &lt;script&gt;alert(1)&lt;/script&gt;", report)
            self.assertIn("Review &lt;unsafe&gt; output", report)
            self.assertIn('href="binary_security_review.txt"', report)
            self.assertNotIn(r"C:\Sensitive\Path", report)
            self.assertLess(report.index("High item"), report.index("Informational item"))

    def test_consolidated_html_does_not_link_absent_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = AssessmentReporter(root, "Test", Path("Client.exe"), "static", "1.2.1")
            reporter.set_status("MSI Analysis", "SKIPPED", "EXE input")
            reporter.finalize()
            report = (root / "assessment_report.html").read_text(encoding="utf-8")
            self.assertNotIn('href="msi_analysis.txt"', report)
            self.assertNotIn('href="test_cases.txt"', report)
            self.assertIn("No linked evidence generated", report)

    def test_optional_collector_evidence_gap_changes_coverage_grade(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = AssessmentReporter(root, "Test", Path("Client.exe"), "full", "1.2.1")
            reporter.set_status(
                "IPC / Named Pipe Review",
                "WARN",
                "5 permission checks unavailable",
                coverage_gap=True,
            )
            self.assertEqual("COMPLETE_WITH_OPTIONAL_GAPS", reporter.finalize())
            summary = (root / "coverage_summary.txt").read_text(encoding="utf-8")
            self.assertIn("Optional evidence gaps:", summary)
            self.assertIn("IPC / Named Pipe Review", summary)

    def test_updater_evidence_gap_changes_coverage_grade(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reporter = AssessmentReporter(root, "Test", Path("Client.exe"), "full", "1.2.1")
            reporter.set_status(
                "Updater Security Correlation",
                "WARN",
                "Updater workflow not observed",
                coverage_gap=True,
            )
            self.assertEqual("COMPLETE_WITH_OPTIONAL_GAPS", reporter.finalize())

    def test_consolidated_html_links_resolve_to_files_or_page_anchors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test_cases.txt").write_text("cases", encoding="utf-8")
            reporter = AssessmentReporter(root, "Test", Path("Client.exe"), "static", "1.2.1")
            reporter.set_status("Test Case Generation", "PASS", "Generated")
            reporter.finalize()
            parser = _LinkParser()
            parser.feed((root / "assessment_report.html").read_text(encoding="utf-8"))
            for href in parser.hrefs:
                if href.startswith("#"):
                    self.assertIn(href[1:], parser.ids)
                else:
                    self.assertTrue((root / href).is_file(), href)


if __name__ == "__main__":
    unittest.main()
