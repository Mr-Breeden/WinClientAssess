"""p5: runtime DLL/ACL correlation and target-only Procmon working evidence."""
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.permissions_review import _candidate_paths, run_permissions_review
from modules.procmon_analysis import analyze_procmon_csv, run_procmon_analysis
from utils.artifact_policy import reset_generated_artifacts
from utils.artifacts import ARTIFACTS
from utils.consolidated_report import _evidence_sections


TrainingApp_DIR = r"C:\ProgramData\AcmeWidget"
SERVICE_DIR = r"C:\Program Files\AcmeWidget"
FIELDS = ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"]


def acl_entry(path, broad=False):
    aces = [{"Identity": "NT AUTHORITY\\SYSTEM", "Rights": "FullControl", "Type": "Allow"}]
    if broad:
        aces.append({"Identity": "Everyone", "Rights": "Modify", "Type": "Allow", "Inherited": False})
    return {"Path": path, "Exists": True, "Owner": "SYSTEM", "Access": aces}


class FakeAclCache:
    def __init__(self):
        self.calls = []

    def get_many(self, paths):
        self.calls.extend(paths)
        return {path.lower(): acl_entry(path, path.lower() == TrainingApp_DIR.lower()) for path in paths}


def missing_dll_record(path=TrainingApp_DIR, *, broad=True, existing=True):
    return {
        "ID": "DLL-0001", "Process": "Beeper.exe", "MissingDLL": path + r"\Shared.dll",
        "SearchDirectory": path, "Account": "", "PrivilegedContext": False,
        "DirectoryExists": existing, "BroadWriteACEs": [{"Identity": "Everyone", "Rights": "Modify", "Type": "Allow"}] if broad else [],
        "LikelyUserWritableLocation": False,
    }


def diff_fixture():
    return {
        "Services": {"added": [{"Name": "AcmeWidgetService", "PathName": SERVICE_DIR + r"\AcmeWidgetService.exe", "StartName": "LocalSystem"}]},
        "ScheduledTasks": {"added": []},
        "Filesystem": {"added": [{"Path": r"C:\ProgramData\Other\noise.exe", "IsDirectory": False}], "changed": []},
    }


class RuntimeDllPermissionsTests(unittest.TestCase):
    def test_vwa_runtime_directory_is_reviewed_even_when_outside_install_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            diff = diff_fixture()
            cache = FakeAclCache()
            original = run_permissions_review(root, diff=diff, acl_cache=cache)
            self.assertNotIn(TrainingApp_DIR.lower(), {r["Path"].lower() for r in original["permission_results"]})
            refreshed = run_permissions_review(root, diff=diff, acl_cache=cache,
                                               runtime_dll_records=[missing_dll_record()])
            paths = [r["Path"].lower() for r in refreshed["permission_results"]]
            self.assertEqual(1, paths.count(TrainingApp_DIR.lower()))
            self.assertNotIn(r"c:\programdata\other\noise.exe", paths)
            self.assertEqual("WARN", refreshed["status"])
            self.assertEqual(1, len(refreshed["findings"]))
            self.assertEqual(1, len([r for r in refreshed["permission_results"] if r["BroadWrite"]]))
            report = (root / "permissions_review.txt").read_text()
            self.assertIn("C:\\ProgramData\\AcmeWidget", report)
            self.assertIn("DLL-0001 | Beeper.exe -> Shared.dll", report)
            self.assertIn("Cross-reference: dll_search_review.txt", report)
            self.assertIn("DLL-search-correlated directories   : 1", report)

    def test_duplicate_existing_acl_path_keeps_one_record_with_dll_reference(self):
        rec = missing_dll_record(SERVICE_DIR)
        candidates = _candidate_paths(None, None, diff_fixture(), runtime_dll_records=[rec])
        matching = [c for c in candidates if c["Path"].lower() == SERVICE_DIR.lower()]
        self.assertEqual(1, len(matching))
        self.assertEqual("Service directory", matching[0]["Kind"])
        self.assertEqual("Shared.dll", matching[0]["DLLCorrelations"][0]["MissingDLL"])

    def test_runtime_acl_candidate_excludes_unrelated_system_paths(self):
        rec = missing_dll_record(r"C:\Windows\System32")
        paths = {c["Path"].lower() for c in _candidate_paths(None, None, diff_fixture(), runtime_dll_records=[rec])}
        self.assertNotIn(r"c:\windows\system32", paths)

    def test_runtime_acl_candidate_requires_actual_directory_and_writable_indicator(self):
        one = missing_dll_record(existing=False)
        two = missing_dll_record(broad=False)
        for rec in (one, two):
            paths = {c["Path"].lower() for c in _candidate_paths(None, None, diff_fixture(), runtime_dll_records=[rec])}
            self.assertNotIn(TrainingApp_DIR.lower(), paths)

    def test_manual_review_path_is_not_classified_as_confirmed_exploit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = run_permissions_review(root, diff=diff_fixture(), acl_cache=FakeAclCache(),
                                            runtime_dll_records=[missing_dll_record()])
            self.assertEqual("Informational", result["findings"][0]["severity"])
            self.assertIn("effective permissions require validation", result["findings"][0]["description"])


class TargetOnlyProcmonTests(unittest.TestCase):
    @staticmethod
    def write_csv(path, events):
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(events)

    def test_filtered_working_csv_retains_only_target_and_child_events(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "capture.csv"
            view = root / "working" / "procmon_target_events.csv"
            self.write_csv(source, [
                {"Process Name": "other.exe", "Operation": "TCP Connect", "Path": "1.2.3.4"},
                {"Process Name": "Client.exe", "Operation": "Process Create", "Path": r"C:\\App\\Helper.exe"},
                {"Process Name": "Helper.exe", "Operation": "WriteFile", "Path": r"C:\\App\\log.txt", "Detail": "TOKEN=my-secret"},
                {"Process Name": "other.exe", "Operation": "RegSetValue", "Path": "HKCU\\Noise"},
            ])
            before = source.read_bytes()
            result = analyze_procmon_csv(source, [{"ProcessName": "Client.exe", "Path": r"C:\App\Client.exe"}], view)
            self.assertEqual(4, result["total_rows"])
            self.assertEqual(2, result["relevant_rows"])
            self.assertEqual(2, result["target_filtered_rows"])
            self.assertEqual(str(view), result["target_filtered_csv"])
            with view.open("r", encoding="utf-8-sig", newline="") as fh:
                events = list(csv.DictReader(fh))
            self.assertEqual(["Client.exe", "Helper.exe"], [r["Process Name"] for r in events])
            self.assertNotIn("my-secret", view.read_text(encoding="utf-8-sig"))
            self.assertIn("<REDACTED>", view.read_text(encoding="utf-8-sig"))
            self.assertEqual(before, source.read_bytes())
            self.assertFalse((view.parent / ".procmon_target_events.csv.tmp").exists())

    def test_unfiltered_runtime_does_not_duplicate_full_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "capture.csv"
            view = root / "working" / "procmon_target_events.csv"
            self.write_csv(source, [{"Process Name": "anything.exe", "Operation": "WriteFile"}])
            result = analyze_procmon_csv(source, None, view)
            self.assertEqual(1, result["relevant_rows"])
            self.assertIsNone(result["target_filtered_csv"])
            self.assertFalse(view.exists())

    def test_stale_working_view_is_removed_when_no_target_is_known(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "capture.csv"
            view = root / "working" / "procmon_target_events.csv"
            view.parent.mkdir()
            view.write_text("OLD DATA")
            self.write_csv(source, [{"Process Name": "anything.exe"}])
            analyze_procmon_csv(source, [], view)
            self.assertFalse(view.exists())

    def test_source_csv_cannot_be_destroyed_by_using_same_working_output_path(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "working" / "procmon_target_events.csv"
            source.parent.mkdir()
            self.write_csv(source, [{"Process Name": "Client.exe"}])
            before = source.read_bytes()
            with self.assertRaisesRegex(ValueError, "must differ from the source CSV"):
                analyze_procmon_csv(source, [{"ProcessName": "Client.exe"}], source)
            self.assertEqual(before, source.read_bytes())

    def test_filter_is_streamed_without_retaining_unrelated_events(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "capture.csv"
            view = root / "working" / "procmon_target_events.csv"
            events = [{"Process Name": "unrelated.exe", "Operation": "ReadFile", "Path": "C:\\Windows\\noise"}] * 2000
            events.extend([{"Process Name": "Client.exe", "Operation": "WriteFile", "Path": "C:\\App\\valid"}])
            self.write_csv(source, events)
            result = analyze_procmon_csv(source, [{"ProcessName": "Client.exe", "Path": r"C:\App\Client.exe"}], view)
            self.assertEqual(2001, result["total_rows"])
            self.assertEqual(1, result["relevant_rows"])
            self.assertLess(view.stat().st_size, 1024)

    def test_run_module_writes_summary_and_retains_sanitized_original(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "raw_source.csv"
            self.write_csv(source, [
                {"Process Name": "other.exe", "Detail": "PASSWORD=irrelevant-secret"},
                {"Process Name": "Client.exe", "Operation": "CreateFile", "Path": "C:\\Temp\\missing.dll", "Result": "NAME NOT FOUND"},
            ])
            before = source.read_bytes()
            result = run_procmon_analysis(root, source, runtime_targets=[{"ProcessName": "Client.exe"}])
            self.assertEqual(before, source.read_bytes())
            self.assertTrue((root / "procmon_runtime_sanitized.csv").is_file())
            self.assertTrue((root / "working" / "procmon_target_events.csv").is_file())
            self.assertEqual(1, result["procmon_data"]["target_filtered_rows"])
            summary = (root / "procmon_summary.txt").read_text()
            self.assertIn("Target-only working CSV", summary)
            self.assertIn("Target-only CSV rows    : 1", summary)

    def test_artifact_cleanup_only_removes_known_generated_working_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            working = root / "working"
            working.mkdir()
            (working / "procmon_target_events.csv").write_text("STALE")
            (working / "tester-notes.txt").write_text("PRESERVE")
            reset_generated_artifacts(root)
            self.assertFalse((working / "procmon_target_events.csv").exists())
            self.assertEqual("PRESERVE", (working / "tester-notes.txt").read_text())
            self.assertTrue(ARTIFACTS["procmon_target_events"]["internal"])
            self.assertNotIn("procmon_target_events.csv", _evidence_sections(root))

    def test_html_inventory_excludes_internal_working_view_even_when_present(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            working = root / "working"
            working.mkdir()
            (working / "procmon_target_events.csv").write_text("HEADER")
            (root / "procmon_summary.txt").write_text("SUMMARY")
            html = _evidence_sections(root)
            self.assertIn("procmon_summary.txt", html)
            self.assertNotIn("procmon_target_events.csv", html)


if __name__ == "__main__":
    unittest.main()
