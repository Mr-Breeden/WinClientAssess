import csv
import tempfile
import unittest
from pathlib import Path

from modules.advanced_runtime_review import _child_processes, _managed_candidate_names, run_advanced_runtime_review
from modules.procmon_analysis import analyze_procmon_csv
from modules.runtime_process_review import _is_target_process
from utils.component_context import RuntimeContextIndex


class RuntimeAnalysisTests(unittest.TestCase):
    def test_live_process_with_different_path_does_not_match_by_basename(self):
        self.assertFalse(
            _is_target_process(
                "ChatGPT.exe",
                r"C:\Program Files\WindowsApps\OpenAI.Codex_old\ChatGPT.exe",
                {"chatgpt.exe"},
                {r"c:\program files\windowsapps\openai.codex_new\chatgpt.exe"},
                {r"c:\program files\windowsapps\openai.codex_new"},
                {"chatgpt.exe"},
            )
        )

    def test_live_process_without_readable_path_can_fallback_to_name(self):
        self.assertTrue(
            _is_target_process("Client.exe", "", {"client.exe"}, set(), set(), set())
        )

    def test_target_filter_and_categories(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "procmon.csv"
            fields = ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"]
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fields)
                writer.writeheader()
                writer.writerow({"Time of Day":"1","Process Name":"Client.exe","PID":"10","Operation":"CreateFile","Path":r"C:\\Temp\\missing.dll","Result":"NAME NOT FOUND","Detail":""})
                writer.writerow({"Time of Day":"2","Process Name":"Client.exe","PID":"10","Operation":"Load Image","Path":r"C:\\App\\loaded.dll","Result":"SUCCESS","Detail":""})
                writer.writerow({"Time of Day":"3","Process Name":"Other.exe","PID":"11","Operation":"TCP Connect","Path":"1.2.3.4:443","Result":"SUCCESS","Detail":""})
            result = analyze_procmon_csv(path, [{"ProcessName":"Client.exe", "Path":r"C:\App\Client.exe"}])
            self.assertEqual(3, result["total_rows"])
            self.assertEqual(2, result["relevant_rows"])
            self.assertEqual(1, len(result["missing_dlls"]))
            self.assertEqual(1, len(result["loaded_images"]))
            self.assertEqual(0, len(result["network_activity"]))

    def test_target_filter_tracks_child_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "procmon.csv"
            fields = ["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"]
            with path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=fields)
                writer.writeheader()
                writer.writerow({"Process Name":"Client.exe", "PID":"10", "Operation":"Process Create", "Path":r"C:\\App\\Helper.exe", "Result":"SUCCESS"})
                writer.writerow({"Process Name":"Helper.exe", "PID":"11", "Operation":"TCP Connect", "Path":"1.2.3.4:443", "Result":"SUCCESS"})
                writer.writerow({"Process Name":"Other.exe", "PID":"12", "Operation":"TCP Connect", "Path":"5.6.7.8:443", "Result":"SUCCESS"})
            result = analyze_procmon_csv(path, [{"ProcessName":"Client.exe", "Path":r"C:\App\Client.exe"}])
            self.assertEqual(2, result["relevant_rows"])
            self.assertEqual(1, len(result["network_activity"]))
            self.assertIn("helper.exe", result["tracked_process_names"])

    def test_cp1252_non_ascii_after_first_buffer_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "procmon.csv"
            header = b"Process Name,Operation,Path,Result,Detail,PID,Time of Day\r\n"
            ascii_row = b"app.exe,CreateFile,C:\\\\plain,SUCCESS,,1,12:00\r\n"
            non_ascii_row = b"app.exe,CreateFile,C:\\\\caf" + bytes([0xE9]) + b",SUCCESS,,1,12:00\r\n"
            path.write_bytes(header + ascii_row * 1000 + non_ascii_row)
            result = analyze_procmon_csv(path)
            self.assertEqual("cp1252", result["encoding"])
            self.assertEqual(1001, result["total_rows"])

    def test_managed_candidate_names_use_windows_basenames(self):
        names = _managed_candidate_names({
            "dotnet_candidates": [
                r"C:\Program Files\Client\Client.exe",
                r"C:\Other\CLIENT.EXE",
                r"C:\Program Files\Client\Helper.dll",
            ]
        })
        self.assertEqual({"client.exe", "helper.dll"}, names)

    def test_advanced_runtime_review_accepts_static_managed_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_advanced_runtime_review(
                root,
                dotnet_result={"dotnet_candidates": [r"C:\Client\Managed.exe"]},
                runtime_targets=[{"ProcessName": "Managed.exe", "Path": r"C:\Client\Managed.exe"}],
                procmon_data={"loaded_images": [], "process_activity": []},
                runtime_processes=[],
                tools={},
                mode="full",
            )
            self.assertEqual("PASS", result["status"])
            self.assertTrue((root / "advanced_runtime_review.txt").is_file())
            self.assertTrue(result["managed_context"][0]["StaticManagedCandidate"])

    def test_advanced_child_review_uses_process_create_only(self):
        context = RuntimeContextIndex([], [])
        events = [
            {"Process": "Client.exe", "PID": "10", "Operation": "Process Create", "Path": r"C:\App\Child.exe"},
            {"Process": "Child.exe", "PID": "11", "Operation": "Process Start", "Path": ""},
        ]
        rows, _ = _child_processes(events, context)
        self.assertEqual(1, len(rows))
        self.assertEqual("child.exe", rows[0]["ChildName"])

    def test_pid_evidence_does_not_borrow_privilege_from_same_name_process(self):
        context = RuntimeContextIndex(
            [],
            [{"Name": "Client.exe", "PID": 10, "Username": r"NT AUTHORITY\SYSTEM"}],
        )
        matched, _ = context.privileged_for(
            process={"Name": "Client.exe", "PID": 10}, process_name="Client.exe"
        )
        different_pid, _ = context.privileged_for(
            process={"Name": "Client.exe", "PID": 20}, process_name="Client.exe"
        )
        self.assertTrue(matched)
        self.assertFalse(different_pid)


if __name__ == "__main__":
    unittest.main()
