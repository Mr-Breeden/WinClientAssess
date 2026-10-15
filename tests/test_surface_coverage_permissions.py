"""Portable regressions for v1.2.3-p2. Windows field validation remains separate."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.network_surface_review import run_network_surface_review
from modules.ipc_review import run_ipc_review
from modules.runtime_process_review import run_runtime_process_review
from modules.permissions_review import _candidate_paths, run_permissions_review
from utils.reporting import AssessmentReporter


class SurfaceCoverageTests(unittest.TestCase):
    def test_no_correlated_process_does_not_pass_network_review(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with patch("modules.network_surface_review.collect_runtime_processes", return_value=[]), \
                 patch("modules.network_surface_review._collect_connections", return_value=([], [])):
                result = run_network_surface_review(path, runtime_targets=[{
                    "Path": r"C:\Program Files\Acme\client.exe", "ProcessName": "client.exe"
                }])
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])
            self.assertIn("no target process", result["details"])
            self.assertIn("COVERAGE GAP", (path / "network_surface_review.txt").read_text())
            reporter = AssessmentReporter(path, "Acme", path / "acme.msi", "full", "1.2.3-p2")
            reporter.set_status("Network Surface Review", result["status"], result["details"], result["coverage_gap"])
            reporter.set_status("IPC / Named Pipe Review", "PASS", "", False)
            self.assertEqual("COMPLETE_WITH_OPTIONAL_GAPS", reporter.finalize())

    def test_target_process_without_network_endpoint_is_legitimate_empty_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            proc = [{"PID": 10, "Name": "client.exe", "Exe": r"C:\Apps\Acme\client.exe"}]
            with patch("modules.network_surface_review._collect_connections", return_value=([], [])):
                result = run_network_surface_review(path, runtime_processes=proc)
            self.assertEqual("PASS", result["status"])
            self.assertFalse(result["coverage_gap"])

    def test_network_collection_failure_is_optional_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            proc = [{"PID": 10, "Name": "client.exe", "Exe": r"C:\Apps\Acme\client.exe"}]
            with patch("modules.network_surface_review._collect_connections", return_value=([], ["Access denied"])):
                result = run_network_surface_review(path, runtime_processes=proc)
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])

    def test_no_correlated_process_does_not_pass_ipc_review(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with patch("modules.ipc_review.collect_runtime_processes", return_value=[]):
                result = run_ipc_review(path, tools={}, target_only=True)
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])
            self.assertIn("COVERAGE GAP", (path / "ipc_review.txt").read_text())

    def test_healthy_empty_ipc_sample_is_not_a_coverage_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            proc = [{"PID": 10, "Name": "client.exe", "Exe": r"C:\Apps\Acme\client.exe"}]
            with patch("modules.ipc_review._target_handle_inventory", return_value=([], [], "")), \
                 patch("modules.ipc_review._pipe_permissions", return_value=({}, "")):
                result = run_ipc_review(path, tools={}, runtime_processes=proc, target_only=True)
            self.assertEqual("PASS", result["status"])
            self.assertFalse(result["coverage_gap"])

    def test_missing_runtime_process_is_reported_by_process_review(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with patch("modules.runtime_process_review.collect_runtime_processes", return_value=[]):
                result = run_runtime_process_review(path, tools={})
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])


class ScopedAclTests(unittest.TestCase):
    def test_service_paths_preserved_but_unrelated_files_not_automatically_queried(self):
        application = r"C:\Program Files\TrainingApp"
        diff = {
            "Services": {"added": [{"Name": "TrainingAppService", "PathName": '"' + application + r'\service.exe"', "StartName": "LocalSystem"}]},
            "Filesystem": {"added": [
                {"Path": application + r"\service.exe", "IsDirectory": False},
                {"Path": application + r"\config.json", "IsDirectory": False},
                {"Path": r"C:\Program Files\Other\noise.dll", "IsDirectory": False},
            ], "changed": [{"after": {"Path": r"C:\ProgramData\Other\background.json", "IsDirectory": False}}]},
        }
        paths = {item["Path"].lower() for item in _candidate_paths(None, None, diff)}
        self.assertIn((application + r"\service.exe").lower(), paths)
        self.assertIn((application + r"\config.json").lower(), paths)
        self.assertNotIn(r"c:\program files\other\noise.dll", paths)
        self.assertNotIn(r"c:\programdata\other\background.json", paths)

    def test_no_strong_scope_keeps_unattributed_candidates_for_review(self):
        diff = {"Filesystem": {"added": [{
            "Path": r"C:\Program Files\Unidentified\client.exe", "IsDirectory": False
        }]}}
        paths = {item["Path"].lower() for item in _candidate_paths(None, None, diff)}
        self.assertIn(r"c:\program files\unidentified\client.exe", paths)

    def test_permission_review_does_not_remove_raw_differential_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            diff = {
                "Services": {"added": [{"Name": "TrainingApp", "PathName": r"C:\Program Files\TrainingApp\svc.exe"}]},
                "Filesystem": {"added": [{"Path": r"C:\Other\noise.dll", "IsDirectory": False}]},
            }
            class Cache:
                def get_many(self, paths):
                    return {path.lower(): {"Path": path, "Exists": False, "Access": []} for path in paths}
            run_permissions_review(root, diff=diff, acl_cache=Cache())
            self.assertEqual(1, len(diff["Filesystem"]["added"]))
            self.assertIn("Scoped ACL triage", (root / "permissions_review.txt").read_text())


if __name__ == "__main__":
    unittest.main()
