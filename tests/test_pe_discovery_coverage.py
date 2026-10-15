"""PE magic-header discovery and coverage regressions for v1.2.3-p4.

Synthetic headers only. No vulnerable third-party binaries ship in the project.
"""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.pe_analysis import _has_pe_header, _iter_candidates, run_pe_analysis
from utils.file_inventory import build_file_inventory


def synthetic_pe(path, *, signature=b"PE\x00\x00", offset=0x80):
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = bytearray(max(offset + 4, 0x100))
    blob[:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, offset)
    blob[offset:offset + len(signature)] = signature
    path.write_bytes(blob)
    return path


def successful_row(path, *, aslr=True, dep_nx=True, cfg=True):
    return {
        "path": str(path), "architecture": "x64", "aslr": aslr,
        "dep_nx": dep_nx, "cfg": cfg, "high_entropy_va": True,
        "dotnet": False, "error": "",
    }


class PePatch4Tests(unittest.TestCase):
    def test_valid_extensionless_and_disguised_pe_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            synthetic_pe(root / "Client")
            synthetic_pe(root / "Shared.dat")
            synthetic_pe(root / "normal.dll")
            (root / "ordinary.txt").write_text("text", encoding="utf-8")
            inventory = build_file_inventory([root])
            self.assertEqual(
                {"Client", "Shared.dat", "normal.dll"},
                {p.name for p in _iter_candidates([root], inventory)},
            )
            self.assertEqual(
                {"Client", "Shared.dat", "normal.dll"},
                {p.name for p in _iter_candidates([root])},
            )

    def test_mz_only_or_damaged_nt_signature_is_not_pe(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mz_only = root / "fake.exe"
            mz_only.write_bytes(b"MZ" + b"A" * 180)
            bad = synthetic_pe(root / "bad.dll", signature=b"NOT!")
            truncated = root / "truncated"
            truncated.write_bytes(b"MZ" + b"\x00" * 6)
            malformed = synthetic_pe(root / "bad_offset", offset=0x80)
            with malformed.open("r+b") as fh:
                fh.seek(0x3C)
                fh.write(b"\xff" * 4)
            for item in (mz_only, bad, truncated, malformed):
                self.assertFalse(_has_pe_header(item))
            self.assertEqual([], list(_iter_candidates([root])))

    def test_nested_and_duplicate_inventory_paths_are_analyzed_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = synthetic_pe(root / "nested" / "Beeper")
            duplicate = {"path": str(exe), "extension": "", "size_bytes": exe.stat().st_size}
            paths = list(_iter_candidates([root], [duplicate, duplicate]))
            self.assertEqual([exe], paths)

    def test_known_extension_unreadable_probe_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = synthetic_pe(root / "unreadable.exe")
            with patch("modules.pe_analysis._has_pe_header", side_effect=PermissionError("access denied")):
                self.assertEqual([exe], list(_iter_candidates([root], build_file_inventory([exe]))))

    def test_all_discovered_extensionless_pe_files_are_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = [synthetic_pe(root / name) for name in ("Client", "Server", "Shared")]
            def analyze(path):
                return successful_row(path)
            with patch("modules.pe_analysis._analyze", side_effect=analyze):
                result = run_pe_analysis([root], root, build_file_inventory([root]))
            self.assertEqual("PASS", result["status"])
            self.assertEqual((3, 3, 0), (result["discovered"], result["analyzed"], result["failed"]))
            self.assertFalse(result["coverage_gap"])
            report = (root / "binary_security_review.txt").read_text(encoding="utf-8")
            self.assertIn("PE files discovered   : 3", report)
            self.assertIn("Files analyzed        : 3", report)
            self.assertIn("[PE-0003]", report)

    def test_missing_pefile_with_real_candidates_is_a_coverage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            synthetic_pe(root / "AcmeWidgetService")
            with patch("modules.pe_analysis.pefile", None):
                result = run_pe_analysis([root], root, build_file_inventory([root]))
            self.assertEqual("ERROR", result["status"])
            self.assertTrue(result["coverage_gap"])
            self.assertEqual(1, result["failed"])
            self.assertIn("pefile Python package not installed", (root / "binary_security_review.txt").read_text())

    def test_partial_parse_errors_do_not_become_pass_or_warn_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            synthetic_pe(root / "Client")
            synthetic_pe(root / "Server")
            def analyze(path):
                if path.name == "Server":
                    return {**successful_row(path), "error": "corrupt PE optional header"}
                return successful_row(path, aslr=False)
            with patch("modules.pe_analysis._analyze", side_effect=analyze):
                result = run_pe_analysis([root], root, build_file_inventory([root]))
            self.assertEqual("ERROR", result["status"])
            self.assertEqual((2, 1, 1), (result["discovered"], result["analyzed"], result["failed"]))
            self.assertTrue(result["coverage_gap"])
            self.assertEqual(1, len(result["findings"]))
            self.assertIn("INCOMPLETE", (root / "binary_security_review.txt").read_text())

    def test_weak_parsed_pe_is_warning_not_coverage_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            synthetic_pe(root / "Client")
            with patch("modules.pe_analysis._analyze", side_effect=lambda path: successful_row(path, cfg=False)):
                result = run_pe_analysis([root], root, build_file_inventory([root]))
            self.assertEqual("WARN", result["status"])
            self.assertFalse(result["coverage_gap"])
            self.assertEqual(1, result["analyzed"])

    def test_failed_pe_analysis_marks_reporter_incomplete(self):
        from utils.reporting import AssessmentReporter
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            synthetic_pe(root / "Client")
            with patch("modules.pe_analysis.pefile", None):
                result = run_pe_analysis([root], root, build_file_inventory([root]))
            reporter = AssessmentReporter(root, "Fixture", root / "test.msi", "static", "1.2.3-p4")
            reporter.set_status("PE Security Review", result["status"], result["details"],
                                coverage_gap=result["coverage_gap"])
            self.assertEqual("INCOMPLETE", reporter.finalize())
            summary = (root / "coverage_summary.txt").read_text(encoding="utf-8")
            self.assertIn("PE Security Review", summary)

    def test_no_pe_in_scope_is_not_a_fabricated_coverage_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "installer.msi").write_bytes(b"not executable")
            (root / "README.txt").write_text("static", encoding="utf-8")
            result = run_pe_analysis([root], root, build_file_inventory([root]))
            self.assertEqual("PASS", result["status"])
            self.assertEqual((0, 0, 0), (result["discovered"], result["analyzed"], result["failed"]))
            self.assertIn("no valid PE headers", result["details"])


if __name__ == "__main__":
    unittest.main()
