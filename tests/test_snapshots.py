import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.snapshots import capture_snapshot, compare_snapshots


class SnapshotTests(unittest.TestCase):
    def test_partial_critical_collection_invalidates_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "snapshot.json"

            def fake_run(script, timeout=1200):
                raw = re.search(r"Set-Content -LiteralPath '([^']+)'", script)
                Path(raw.group(1)).write_text(json.dumps({
                    "Metadata": {"CollectionErrors": ["Services: Access denied"]},
                    "Services": [], "ScheduledTasks": [], "Drivers": [], "Filesystem": [],
                }), encoding="utf-8")
                return {"returncode": 0, "stdout": "", "stderr": ""}

            with patch("modules.snapshots.run_powershell", side_effect=fake_run):
                result = capture_snapshot(output)
            self.assertEqual("WARN", result["status"])
            self.assertIsNone(result["snapshot"])
            self.assertIn("partial_snapshot", result)

    def test_install_diff_does_not_include_volatile_network_categories(self):
        base = {
            "Services": [], "ScheduledTasks": [], "Drivers": [], "RunEntries": [],
            "ProtocolHandlers": [], "FileAssociations": [], "EnvironmentVariables": [],
            "InstalledApps": [], "RegistryKeys": [], "Filesystem": [],
        }
        diff = compare_snapshots(base, {k:list(v) for k,v in base.items()})
        self.assertNotIn("TcpConnections", diff)
        self.assertNotIn("UdpEndpoints", diff)

    def test_snapshot_source_does_not_persist_workstation_identity(self):
        source = Path("modules/snapshots.py").read_text(encoding="utf-8")
        self.assertNotIn("ComputerName=$env:COMPUTERNAME", source)
        self.assertNotIn("User=$env:USERNAME", source)

    def test_scheduled_task_collection_filters_null_members(self):
        source = Path("modules/snapshots.py").read_text(encoding="utf-8")
        self.assertIn('$null -ne $task.Principal', source)
        self.assertIn('$task.Actions | Where-Object {{ $null -ne $_ }}', source)
        self.assertIn('$task.Triggers | Where-Object {{ $null -ne $_ }}', source)


if __name__ == "__main__":
    unittest.main()
