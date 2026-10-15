"""v1.2.3 privacy and cross-platform regression fixtures; no Windows host required."""
import csv
import json
import re
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.persistence_review import run_persistence_review
from modules.secrets_review import run_secrets_review
from modules.snapshots import capture_snapshot, write_snapshot_diff
from utils.artifacts import ARTIFACTS
from utils.consolidated_report import generate_consolidated_report
from utils.file_inventory import write_file_inventory_csv
from utils.privacy import portable_basename, sanitize_report_text
from utils.powershell import _powershell_environment
from utils.reporting import AssessmentReporter
from utils.sensitive_data import redact_sensitive_text, sanitize_procmon_csv, REDACTED


class WindowsPathTests(unittest.TestCase):
    def test_windows_paths_are_parsed_on_any_platform(self):
        self.assertEqual("Setup.exe", portable_basename(r"D:\Private\Downloads\Setup.exe"))
        self.assertEqual("Setup.exe", portable_basename("/home/tester/Setup.exe"))
        self.assertEqual("Setup.exe", portable_basename(r"\\server\share\Setup.exe"))

    def test_all_windows_powershell_path_forms_drop_inherited_module_path(self):
        with patch.dict(os.environ, {"PSModulePath": "inherited"}, clear=False):
            for executable in (
                "powershell.exe", "powershell", "powershell.EXE",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            ):
                self.assertFalse(any(key.casefold() == "psmodulepath" for key in _powershell_environment(executable)), executable)
            pwsh_env = _powershell_environment(r"C:\Program Files\PowerShell\7\pwsh.exe")
            inherited = [value for key, value in pwsh_env.items() if key.casefold() == "psmodulepath"]
            self.assertEqual(["inherited"], inherited)


class PrivacyBoundaryTests(unittest.TestCase):
    ENV = {"USERNAME": "TestPerson", "USERPROFILE": r"C:\Users\TestPerson", "COMPUTERNAME": "WIN-TESTPERSON"}

    def test_report_scrubs_installer_outside_user_profile_and_known_identity(self):
        installer = r"D:\Private\ClientDocs\ClientSetup.exe"
        value = f"Installer={installer}; profile=C:/Users/TestPerson/AppData; user=LAB\\TestPerson; host=WIN-TESTPERSON"
        with patch.dict(os.environ, self.ENV, clear=False):
            result = sanitize_report_text(value, installer)
        self.assertIn("ClientSetup.exe", result)
        self.assertIn("%USERPROFILE%/AppData", result)
        self.assertIn("CURRENT_USER", result)
        self.assertIn("CURRENT_HOST", result)
        for private in ("D:\\Private", "TestPerson", "WIN-TESTPERSON"):
            self.assertNotIn(private, result)

    def test_profile_replacement_does_not_corrupt_unrelated_account_paths(self):
        value = r"C:\Users\TestPerson\AppData; C:\Users\TestPerson2\AppData"
        with patch.dict(os.environ, self.ENV, clear=False):
            cleaned = sanitize_report_text(value)
        self.assertIn(r"%USERPROFILE%\AppData", cleaned)
        self.assertIn(r"C:\Users\TestPerson2\AppData", cleaned)

    def test_service_account_is_preserved(self):
        with patch.dict(os.environ, self.ENV, clear=False):
            result = sanitize_report_text(r"NT AUTHORITY\SYSTEM, NT AUTHORITY\NETWORK SERVICE")
        self.assertIn(r"NT AUTHORITY\SYSTEM", result)
        self.assertIn(r"NT AUTHORITY\NETWORK SERVICE", result)

    def test_html_and_all_text_reports_remove_installer_location(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.ENV, clear=False):
            root = Path(tmp)
            source = r"D:\Private\ClientDocs\ClientSetup.exe"
            (root / "configuration_review.txt").write_text(f"Source: {source}\nAccount: LAB\\TestPerson\n", encoding="utf-8")
            reporter = AssessmentReporter(root, "Test", Path(source), "static", "1.2.3")
            reporter.set_status("Configuration Review", "PASS", f"Analyzed {source}")
            reporter.add_finding("Observe", source_module="Configuration Review", evidence=source)
            reporter.finalize()
            for filename in ("configuration_review.txt", "module_status.txt", "findings.txt", "assessment_report.html"):
                value = (root / filename).read_text(encoding="utf-8")
                self.assertNotIn(r"D:\Private\ClientDocs", value, filename)
                self.assertNotIn("TestPerson", value, filename)
            self.assertIn("ClientSetup.exe", (root / "assessment_report.html").read_text(encoding="utf-8"))

    def test_inventory_scrubs_installer_and_profile_but_retains_in_memory_inputs(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, self.ENV, clear=False):
            path = r"D:\Private\ClientDocs\ClientSetup.exe"
            inventory = [{"root": path, "path": path, "name": "ClientSetup.exe", "extension": ".exe", "size_bytes": 1, "size_human": "1 B"}]
            dest = Path(tmp) / "file_inventory.csv"
            write_file_inventory_csv(inventory, dest, installer=path)
            self.assertIn(r"D:\Private", inventory[0]["path"])
            self.assertNotIn(r"D:\Private", dest.read_text(encoding="utf-8"))
            with dest.open(newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual("ClientSetup.exe", row["root"])
            self.assertEqual("ClientSetup.exe", row["path"])

    def test_cleaned_pml_is_never_linked_even_if_old_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "procmon_runtime_capture.pml").write_bytes(b"raw private environment data")
            self.assertTrue(ARTIFACTS["procmon_runtime_capture_pml"]["cleanup_only"])
            generate_consolidated_report(root, "Test", Path("Test.exe"), "full", "1.2.3", "COMPLETE", {}, [], {})
            self.assertNotIn("procmon_runtime_capture.pml", (root / "assessment_report.html").read_text(encoding="utf-8"))


class SensitiveEvidenceTests(unittest.TestCase):
    def test_static_secret_matches_have_no_prefixes_or_suffixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "config.json"
            target.write_text('password="FirstHighlySensitiveValue99"\napi_key="AnotherSensitiveValue123"\n', encoding="utf-8")
            result = run_secrets_review([target], root)
            saved = (root / "secrets_review.txt").read_text(encoding="utf-8")
            self.assertEqual("PASS", result["status"])  # Both patterns are low confidence alone.
            self.assertIn("[REDACTED]", saved)
            self.assertIn("Line", saved)
            for fragment in ("FirstHighly", "eValue99", "Another", "eValue123"):
                self.assertNotIn(fragment, saved)

    def test_quotes_spaces_cli_passwords_private_keys_and_bearer(self):
        raw = ('TOKEN="private value with spaces" --password "CLI value" '
               'PRIVATE_KEY=not-to-log Authorization: Bearer BearerValue123 '
               'https://localhost/?token="quoted value"&next=ok')
        cleaned, counts = redact_sensitive_text(raw)
        for secret in ("private value", "CLI value", "not-to-log", "BearerValue123", "quoted value"):
            self.assertNotIn(secret, cleaned)
        self.assertGreaterEqual(sum(counts.values()), 5)
        self.assertIn("&next=ok", cleaned)
        self.assertIn(REDACTED, cleaned)

    def test_imported_procmon_csv_removes_quoted_secret_identity_and_keeps_source(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, PrivacyBoundaryTests.ENV, clear=False):
            root = Path(tmp)
            source, destination = root / "manual-original.csv", root / "procmon_runtime_sanitized.csv"
            with source.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Path", "Detail"])
                writer.writeheader()
                writer.writerow({"Path": r"C:\Users\TestPerson\AppData\Client.exe", "Detail": 'Environment: TOKEN="top secret phrase"'})
            result = sanitize_procmon_csv(source, destination)
            sanitized = destination.read_text(encoding="utf-8-sig")
            self.assertEqual(1, result["redaction_count"])
            self.assertNotIn("TestPerson", sanitized)
            self.assertNotIn("top secret phrase", sanitized)
            self.assertIn("%USERPROFILE%", sanitized)
            self.assertIn("top secret phrase", source.read_text(encoding="utf-8"))

    def test_snapshots_persist_sanitized_values_but_keep_current_run_raw(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, PrivacyBoundaryTests.ENV, clear=False):
            root = Path(tmp)
            path = root / "snapshot_pre.json"
            raw = {
                "Metadata": {"CollectionErrors": []},
                "Services": [{"Name": "target", "StartName": "LAB\\TestPerson", "PathName": r"C:\Users\TestPerson\target.exe"},
                             {"Name": "system", "StartName": r"NT AUTHORITY\SYSTEM"}],
                "ScheduledTasks": [{"Principal": "TestPerson", "TaskName": "Updater"}],
                "EnvironmentVariables": [
                    {"Name": "ACCESS_TOKEN", "Scope": "User", "Value": "raw-token-NEVER-SAVE"},
                    {"Name": "USERNAME", "Scope": "User", "Value": "TestPerson"},
                    {"Name": "PROGRAM_PATH", "Scope": "User", "Value": r"C:\Users\TestPerson\AppData"},
                ],
                "Drivers": [], "Filesystem": [{"Path": r"C:\Users\TestPerson\AppData\Target\config.json"}],
            }
            def write_snapshot(script, timeout=1200):
                raw_destination = re.search(r"Set-Content -LiteralPath '([^']+)'", script)
                Path(raw_destination.group(1)).write_text(json.dumps(raw), encoding="utf-8")
                return {"returncode": 0, "stdout": "", "stderr": ""}
            with patch("modules.snapshots.run_powershell", side_effect=write_snapshot):
                result = capture_snapshot(path)
            self.assertEqual("PASS", result["status"])
            self.assertEqual("raw-token-NEVER-SAVE", result["snapshot"]["EnvironmentVariables"][0]["Value"])
            disk = path.read_text(encoding="utf-8")
            self.assertNotIn("raw-token-NEVER-SAVE", disk)
            self.assertNotIn("TestPerson", disk)
            self.assertIn("CURRENT_USER", disk)
            self.assertIn("%USERPROFILE%", disk)
            self.assertIn(r"NT AUTHORITY\\SYSTEM", disk)  # JSON escaped backslash

    def test_diff_and_persistence_reports_do_not_expose_unlabelled_environment_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = {"Scope": "Machine", "Name": "SERVICE_API_KEY", "Value": "raw-naked-secret-999"}
            diff = {"EnvironmentVariables": {"added": [env], "removed": [], "changed": []}}
            write_snapshot_diff(diff, root)
            run_persistence_review(root, diff=diff)
            self.assertEqual("raw-naked-secret-999", env["Value"])
            for name in ("install_changes.txt", "persistence_review.txt"):
                saved = (root / name).read_text(encoding="utf-8")
                self.assertNotIn("raw-naked-secret-999", saved)
                self.assertIn("[REDACTED]", saved)


if __name__ == "__main__":
    unittest.main()
