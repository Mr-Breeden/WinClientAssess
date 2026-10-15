import tempfile
import unittest
from pathlib import Path

from modules.runtime_targets import discover_runtime_targets
from modules.updater_review import discover_updater_candidates
from utils.path_filters import filter_install_diff, path_is_excluded, write_filter_report


class PathFilterTests(unittest.TestCase):
    def test_prefix_and_glob_path_exclusions(self):
        self.assertTrue(
            path_is_excluded(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_1\app\ChatGPT.exe",
                [r"C:\Program Files\WindowsApps\OpenAI.Codex_*"],
            )
        )
        self.assertTrue(
            path_is_excluded(
                r"C:\Program Files\HostTool\bin\host.exe",
                [r"C:\Program Files\HostTool"],
            )
        )
        self.assertFalse(
            path_is_excluded(
                r"C:\Program Files\Druva\inSync.exe",
                [r"C:\Program Files\HostTool"],
            )
        )

    def test_differential_filter_preserves_unrelated_records(self):
        diff = {
            "Filesystem": {
                "added": [
                    {"Path": r"C:\Program Files\WindowsApps\OpenAI.Codex_1\ChatGPT.exe"},
                    {"Path": r"C:\Program Files\Druva\inSync.exe"},
                ],
                "removed": [],
                "changed": [],
            },
            "Services": {
                "added": [
                    {"Name": "Host", "PathName": r'"C:\Program Files\HostTool\host.exe" --service'},
                    {"Name": "Druva", "PathName": r'"C:\Program Files\Druva\svc.exe"'},
                ],
                "removed": [],
                "changed": [],
            },
        }
        filtered, removed = filter_install_diff(
            diff,
            [r"C:\Program Files\WindowsApps\OpenAI.Codex_*", r"C:\Program Files\HostTool"],
        )
        self.assertEqual(1, len(filtered["Filesystem"]["added"]))
        self.assertEqual("Druva", filtered["Services"]["added"][0]["Name"])
        self.assertEqual(1, removed["Filesystem.added"])
        self.assertEqual(1, removed["Services.added"])
        self.assertEqual(2, len(diff["Filesystem"]["added"]))

    def test_runtime_and_updater_discovery_honor_exclusions(self):
        diff = {
            "Services": {"added": []},
            "ScheduledTasks": {"added": []},
            "Filesystem": {
                "added": [
                    {"Path": r"C:\Program Files\WindowsApps\OpenAI.Codex_1\ChatGPT.exe"},
                    {"Path": r"C:\Program Files\Druva\inSyncUpgrade.exe"},
                ]
            },
        }
        exclusions = [r"C:\Program Files\WindowsApps\OpenAI.Codex_*"]
        targets = discover_runtime_targets(diff, exclude_paths=exclusions)
        self.assertEqual(["inSyncUpgrade.exe"], [item["ProcessName"] for item in targets])
        updaters = discover_updater_candidates(None, diff, exclude_paths=exclusions)
        self.assertEqual(["inSyncUpgrade.exe"], [item["ProcessName"] for item in updaters])

    def test_filter_report_records_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "assessment_filters.txt"
            write_filter_report(path, [r"C:\Host"], {"Filesystem.added": 3}, True)
            text = path.read_text(encoding="utf-8")
            self.assertIn(r"C:\Host", text)
            self.assertIn("Filesystem.added", text)
            self.assertIn("Target-only supporting inventory : True", text)


if __name__ == "__main__":
    unittest.main()
