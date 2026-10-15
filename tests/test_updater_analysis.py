import unittest
from modules.updater_review import discover_updater_candidates
from modules.updater_security_review import _candidate_parent_paths


class UpdaterAnalysisTests(unittest.TestCase):
    def test_frontend_bootstrap_library_is_not_updater(self):
        rows = [{"path": r"C:\\App\\gui\\js\\bootstrap.min.js", "extension": ".js"}]
        self.assertEqual([], discover_updater_candidates(rows, None))

    def test_camelcase_updater_candidate(self):
        rows = [{"path": r"C:\\Extract\\ClientAutoUpdater.exe", "extension": ".exe"}]
        candidates = discover_updater_candidates(rows, None)
        self.assertEqual(1, len(candidates))

    def test_installed_update_service_merges(self):
        diff = {
            "Filesystem": {"added": [{"Path": r"C:\\Program Files\\App\\UpdateService.exe", "IsDirectory": False}]},
            "Services": {"added": [{"Name":"AppUpdate","PathName":r'"C:\\Program Files\\App\\UpdateService.exe"',"StartName":"LocalSystem"}]},
            "ScheduledTasks": {"added": []},
            "RunEntries": {"added": []},
        }
        candidates = discover_updater_candidates(None, diff, [])
        self.assertTrue(any(c.get("Source") == "installed differential" for c in candidates))
        self.assertTrue(any(c.get("LaunchContexts") for c in candidates))

    def test_updater_security_parent_paths_use_shared_windows_helper(self):
        candidates = [
            {"Path": r"C:\Program Files\App\UpdateService.exe"},
            {"Path": r"C:\ProgramData\App\Updates\ClientUpdater.exe"},
        ]
        parents = _candidate_parent_paths(candidates)
        self.assertEqual(
            [
                r"c:\program files\app",
                r"c:\programdata\app\updates",
            ],
            parents,
        )


if __name__ == "__main__":
    unittest.main()
