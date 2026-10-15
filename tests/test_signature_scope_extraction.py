"""Patch-1 regression cases for the WCALab.Client .NET apphost field report."""
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.application_scope import detect_application_scope, installation_footprint_status, write_application_scope
from modules.dotnet_analysis import run_dotnet_analysis
from modules.installer_extract import run_installer_extract
from modules.signature_review import run_signature_review
from modules.snapshots import capture_snapshot
from utils.file_inventory import build_file_inventory
from utils.path_filters import filter_install_diff, is_framework_snapshot_path
from utils.reporting import AssessmentReporter
from utils.privacy import sanitize_report_text
from utils.artifact_policy import reset_generated_artifacts


class SignatureClassificationTests(unittest.TestCase):
    def test_notsigned_is_observation_not_collector_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("modules.signature_review.run_powershell_json", return_value=(
                {"Status": "NotSigned", "StatusMessage": "No signature found", "SignerSubject": None},
                {"returncode": 0, "stdout": "", "stderr": ""},
            )):
                result = run_signature_review(root / "client.exe", root)
            reporter = AssessmentReporter(root, "Test", root / "client.exe", "full", "1.2.3-p1")
            reporter.set_status("Digital Signature Review", result["status"], result["details"])
            for finding in result["findings"]:
                reporter.add_finding(**finding)
            self.assertEqual("WARN", result["status"])
            self.assertEqual("COMPLETE", reporter.finalize())
            self.assertIn("Signature status: NotSigned", (root / "module_status.txt").read_text())
            self.assertIn("Digital Signature Requires Review", (root / "findings.txt").read_text())

    def test_unavailable_authenticode_is_real_coverage_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch("modules.signature_review.run_powershell_json", return_value=(
                None, {"returncode": 1, "stdout": "", "stderr": "Access denied"}
            )):
                result = run_signature_review(root / "client.exe", root)
            reporter = AssessmentReporter(root, "Test", root / "client.exe", "static", "1.2.3-p1")
            reporter.set_status("Digital Signature Review", result["status"], result["details"])
            self.assertEqual("ERROR", result["status"])
            self.assertEqual("INCOMPLETE", reporter.finalize())


class PublishedApplicationTests(unittest.TestCase):
    def _fixture(self, root):
        deployed = root / "publish"
        deployed.mkdir()
        exe = deployed / "WCALab.Client.exe"
        exe.write_bytes(b"MZ" + b"native application host")
        dll = deployed / "WCALab.Client.dll"
        dll.write_bytes(b"MZ" + b"BSJB")
        (deployed / "WCALab.Client.runtimeconfig.json").write_text('{"runtimeOptions":{}}')
        (deployed / "WCALab.Client.deps.json").write_text('{}')
        (deployed / "Dependency.dll").write_bytes(b"MZ" + b"BSJB")
        assets = deployed / "runtimes" / "win-x64" / "native"
        assets.mkdir(parents=True)
        (assets / "lib.dll").write_bytes(b"MZ")
        return exe, dll

    def test_published_directory_scoped_only_with_matching_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe, dll = self._fixture(root)
            assessment = root / "results"
            assessment.mkdir()
            scope = detect_application_scope(exe, assessment, [], ".NET Core(Loader)")
            self.assertEqual("dotnet_published_application", scope["kind"])
            self.assertTrue(scope["skip_extraction"])
            self.assertIn(dll, scope["roots"])
            self.assertEqual(6, len(scope["roots"]))
            write_application_scope(assessment, exe, scope)
            self.assertIn("6", (assessment / "application_scope.txt").read_text())
            self.assertEqual("PASS", installation_footprint_status({}, scope)[0])

    def test_source_directory_and_adjacent_dll_paths_are_masked_in_reports(self):
        source = r"D:\Private\Lab\WCALab.Client.exe"
        visible = sanitize_report_text(
            "App: " + source + "\nDLL: " + r"D:\Private\Lab\WCALab.Client.dll" +
            "\nFolder: " + r"D:\Private\Lab", source,
        )
        self.assertNotIn(r"D:\Private\Lab", visible)
        self.assertIn("App: WCALab.Client.exe", visible)
        self.assertIn(r"%SOURCE_DIR%\WCALab.Client.dll", visible)

    def test_application_scope_report_is_registered_for_stale_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "application_scope.txt"
            artifact.write_text("stale")
            removed = reset_generated_artifacts(root)
            self.assertFalse(artifact.exists())
            self.assertIn(str(artifact), removed)

    def test_arbitrary_exe_does_not_capture_adjacent_private_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "setup.exe"
            exe.write_bytes(b"MZ" + b"unknown content")
            secret = root / "PrivateNotes.txt"
            secret.write_text("not part of the application")
            scope = detect_application_scope(exe, root / "results", [], "Native PE executable")
            self.assertEqual("unclassified_executable", scope["kind"])
            self.assertEqual([exe], scope["roots"])
            self.assertNotIn(secret, scope["roots"])
            self.assertEqual("WARN", installation_footprint_status({}, scope)[0])

    def test_native_dotnet_loader_without_sidecars_needs_manual_bundle_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "client.exe"
            exe.write_bytes(b"MZ" + b"host")
            scope = detect_application_scope(exe, root / "results", [], "Library: .NET Core(Loader)")
            self.assertEqual("dotnet_apphost_unbundled", scope["kind"])
            self.assertTrue(scope["skip_extraction"])
            result = run_dotnet_analysis([exe], root, {}, build_file_inventory([exe]),
                                        {"pe_rows": [{"path": str(exe), "dotnet": False, "error": ""}]}, scope)
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])
            self.assertIn("MANUAL REVIEW NEEDED", (root / "dotnet_analysis.txt").read_text())

    def test_actual_managed_sidecar_passes_to_ilspy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe, dll = self._fixture(root)
            assessment = root / "out"
            assessment.mkdir()
            scope = detect_application_scope(exe, assessment, [], ".NET Core(Loader)")
            files = build_file_inventory(scope["roots"])
            pe_rows = [
                {"path": row["path"], "dotnet": Path(row["path"]).name in
                 {"WCALab.Client.dll", "Dependency.dll"}, "error": ""}
                for row in files if row["extension"] in (".exe", ".dll")
            ]
            with patch("modules.dotnet_analysis.run_command", return_value={"returncode": 0, "stderr": ""}) as ilspy:
                result = run_dotnet_analysis(scope["roots"], assessment,
                                             {"ILSpyCmd": {"path": "ilspycmd.exe"}},
                                             files, {"pe_rows": pe_rows}, scope)
            self.assertEqual("PASS", result["status"])
            self.assertEqual(2, ilspy.call_count)
            self.assertTrue(any(str(dll) in call.args[0] for call in ilspy.call_args_list))
            self.assertFalse(result["coverage_gap"])

    def test_ilspy_failure_is_partial_static_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dll = root / "App.dll"
            dll.write_bytes(b"MZBSJB")
            with patch("modules.dotnet_analysis.run_command", return_value={"returncode": 1, "stderr": "bad input"}):
                result = run_dotnet_analysis([dll], root, {"ILSpyCmd": {"path": "ilspycmd"}},
                    build_file_inventory([dll]), {"pe_rows": [{"path": str(dll), "dotnet": True, "error": ""}]})
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])


class ExtractionClassificationTests(unittest.TestCase):
    @staticmethod
    def _fake_7z_result():
        return {"returncode": 2, "stdout": "Can't open as archive", "stderr": "Cannot open the file as archive"}

    def test_nonarchive_exe_does_not_register_as_extraction_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "Portable.exe"
            exe.write_bytes(b"MZ")
            scope = detect_application_scope(exe, root / "results")
            with patch("modules.installer_extract.run_command", return_value=self._fake_7z_result()):
                result = run_installer_extract(exe, root, {"7-Zip": {"path": "7z"}}, True, scope)
            self.assertEqual("SKIPPED", result["status"])
            self.assertTrue(result["coverage_gap"])  # unknown native EXE remains a manual scope question
            self.assertIn("NOT APPLICABLE", (root / "installer_extraction.txt").read_text())
            self.assertFalse((root / "extracted_installer").exists())

    def test_known_installer_extraction_failure_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "Setup.exe"
            exe.write_bytes(b"MZ")
            scope = detect_application_scope(exe, root / "results", ["Inno Setup"])
            with patch("modules.installer_extract.run_command", return_value=self._fake_7z_result()):
                result = run_installer_extract(exe, root, {"7-Zip": {"path": "7z"}}, True, scope)
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])
            reporter = AssessmentReporter(root, "Setup", exe, "static", "1.2.3-p1")
            reporter.set_status("Installer Extraction", result["status"], result["details"],
                                coverage_gap=result["coverage_gap"])
            self.assertEqual("INCOMPLETE", reporter.finalize())

    def test_dotnet_host_skips_7zip_entirely(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "App.exe"
            exe.write_bytes(b"MZ")
            scope = detect_application_scope(exe, root / "results", [], ".NET Core(Loader)")
            with patch("modules.installer_extract.run_command") as seven:
                result = run_installer_extract(exe, root, {"7-Zip": {"path": "7z"}}, True, scope)
            seven.assert_not_called()
            self.assertEqual("SKIPPED", result["status"])


class SnapshotNoiseTests(unittest.TestCase):
    def test_filter_excludes_only_framework_generated_temp_filesystem_records(self):
        source = {
            "Filesystem": {
                "added": [
                    {"Path": r"C:\Users\Tester\AppData\Local\Temp\winclientassess-snapshot-abc\raw_snapshot.json"},
                    {"Path": r"C:\Program Files\Example\app.exe"},
                ],
                "removed": [{"Path": r"C:\Temp\winclientassess-snapshot-def"}],
                "changed": [{"before": {"Path": r"C:\Temp\winclientassess-snapshot-ghi\a.json"},
                             "after": {"Path": r"C:\Temp\winclientassess-snapshot-ghi\a.json"}}],
            },
            "Services": {"added": [{"Name": "winclientassess-snapshot-should-not-filter"}],
                         "removed": [], "changed": []},
        }
        diff, counts = filter_install_diff(source, exclude_framework_noise=True)
        self.assertEqual(1, len(diff["Filesystem"]["added"]))
        self.assertFalse(diff["Filesystem"]["removed"])
        self.assertFalse(diff["Filesystem"]["changed"])
        self.assertEqual(3, sum(counts.values()))
        self.assertEqual(1, len(diff["Services"]["added"]))
        self.assertTrue(is_framework_snapshot_path(r"C:\Temp\winclientassess-snapshot-ghi\raw.json"))
        self.assertTrue(is_framework_snapshot_path(r"C:\Temp\wca-snapshot-new\raw.json"))
        self.assertFalse(is_framework_snapshot_path(r"C:\Temp\target-client.exe"))

    def test_raw_snapshot_parser_strips_generated_temp_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "snapshot_pre.json"
            def write_fake(script, timeout=1200):
                match = re.search(r"Set-Content -LiteralPath '([^']+)'", script)
                Path(match.group(1)).write_text(json.dumps({
                    "Metadata": {"CollectionErrors": []},
                    "Filesystem": [
                        {"Path": r"C:\Temp\winclientassess-snapshot-abc\raw_snapshot.json"},
                        {"Path": r"C:\Program Files\Example\app.exe"},
                    ],
                }))
                return {"returncode": 0, "stderr": "", "stdout": ""}
            with patch("modules.snapshots.run_powershell", side_effect=write_fake):
                result = capture_snapshot(output)
            self.assertEqual("PASS", result["status"])
            self.assertEqual(1, len(result["snapshot"]["Filesystem"]))
            self.assertEqual(1, result["snapshot"]["Metadata"]["FrameworkTempEntriesExcluded"])
            self.assertNotIn("winclientassess-snapshot-abc", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
