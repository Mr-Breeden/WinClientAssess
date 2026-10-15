"""v1.2.3-p3 MSI regression tests based on observed TrainingApp MSI table shapes.

Synthetic table records only: no third-party MSI or intentionally vulnerable
executables are distributed in the Windows Client Assessment project.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.msi_analysis import (
    TABLES, _named_row, _powershell_query, _query_tables, run_msi_analysis,
)

OPTIONAL_ABSENT = ("ServiceInstall", "ServiceControl", "Environment", "Shortcut")


def sample_tables():
    tables = {name: [] for name in TABLES}
    tables.update({
        "Property": [{"Property": "ProductName", "Value": "AcmeWidget"}],
        "Directory": [{"Directory": "TARGETDIR", "Directory_Parent": "", "DefaultDir": "SourceDir"}],
        "Component": [{"Component": "Core", "Directory_": "INSTALLDIR"}],
        "File": [{"File": "ClientExe", "Component_": "Core", "FileName": "Client.exe", "FileSize": "4096"}],
        "CustomAction": [
            {"Action": "SET_DIR", "Type": "51", "Source": "INSTALLDIR", "Target": r"[ProgramFilesFolder]AcmeWidget"},
            {"Action": "START_SERVICE", "Type": "210", "Source": "AcmeWidgetService", "Target": "install"},
            {"Action": "CREATE_LOG", "Type": "2258", "Source": "Logger", "Target": ""},
            {"Action": "WRITE_EVENT", "Type": "2258", "Source": "Writeevent", "Target": ""},
            {"Action": "SHOW_EULA", "Type": "65", "Source": "WixUIWixca", "Target": "PrintEula"},
        ],
        "InstallExecuteSequence": [
            {"Action": "START_SERVICE", "Condition": "NOT Installed", "Sequence": "6601"},
            {"Action": "CREATE_LOG", "Condition": "NOT Installed", "Sequence": "6602"},
            {"Action": "WRITE_EVENT", "Condition": "NOT Installed", "Sequence": "6603"},
        ],
        "Registry": [{"Registry": "R1", "Root": "2", "Key": r"Software\AcmeWidget", "Name": "Enabled", "Value": "1", "Component_": "Core"}],
        "Binary": [{"Name": "WixUIWixca", "Data": "<binary stream; content not exported>"}],
    })
    return tables


class MsiPatch3Tests(unittest.TestCase):
    def _run(self, tables, errors=None):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            msi = directory / "test.msi"
            msi.write_bytes(b"mock - collector patched")
            with patch("modules.msi_analysis._query_tables", return_value=(tables, errors or {})):
                result = run_msi_analysis(msi, directory)
            text = (directory / "msi_analysis.txt").read_text(encoding="utf-8")
            return result, text, list(directory.iterdir())

    def test_optional_absence_is_not_a_collection_failure(self):
        tables = sample_tables()
        for table in OPTIONAL_ABSENT:
            tables[table] = None
        result, text, paths = self._run(tables)
        self.assertEqual("PASS", result["status"])
        self.assertEqual(1, len(result["findings"]))
        self.assertIn("ABSENT", text)
        self.assertIn("SERVICEINSTALL", text)
        self.assertIn("NOT PRESENT in this MSI", text)
        self.assertNotIn("COLLECTION DIAGNOSTICS", text)
        self.assertEqual({"test.msi", "msi_analysis.txt"}, {path.name for path in paths})

    def test_present_empty_optional_is_distinct_from_absent(self):
        result, text, _ = self._run(sample_tables())
        self.assertEqual("PASS", result["status"])
        self.assertIn("Present, but no rows.", text)
        self.assertNotIn("OPTIONAL TABLES NOT PRESENT", text.upper())

    def test_custom_action_values_and_execution_sequence_are_rendered(self):
        result, text, _ = self._run(sample_tables())
        self.assertEqual("PASS", result["status"])
        self.assertIn("START_SERVICE", text)
        self.assertIn("AcmeWidgetService", text)
        self.assertIn("install", text)
        self.assertIn("6601", text)
        self.assertIn("NOT Installed", text)
        self.assertIn("CUSTOM ACTION EXECUTION CORRELATION (5)", text)
        self.assertIn(r"Software\AcmeWidget", text)
        self.assertNotIn("[CUSTOMACTION-001]\n\n[CUSTOMACTION-002]", text)
        self.assertIn("<binary stream; content not exported>", text)

    def test_blank_field_bug_marks_analysis_incomplete(self):
        tables = sample_tables()
        tables["CustomAction"] = [{}, {}, {}]
        result, text, _ = self._run(tables)
        self.assertEqual("ERROR", result["status"])
        self.assertIn("CustomAction", text)
        self.assertIn("no decoded field values", text)

    def test_missing_identifying_field_marks_analysis_incomplete(self):
        tables = sample_tables()
        tables["Registry"] = [{"Root": "2", "Key": "Software\\Vendor"}]
        result, text, _ = self._run(tables)
        self.assertEqual("ERROR", result["status"])
        self.assertIn("missing its required Registry value", text)

    def test_partial_com_field_extraction_is_not_mistaken_for_success(self):
        tables = sample_tables()
        tables["CustomAction"][0].pop("Type")
        result, text, _ = self._run(tables)
        self.assertEqual("ERROR", result["status"])
        self.assertIn("missing its required Type", text)

    def test_failed_present_optional_query_is_not_treated_as_absence(self):
        tables = sample_tables()
        tables["ServiceInstall"] = []
        result, text, _ = self._run(tables, {"ServiceInstall": "Read denied"})
        self.assertEqual("ERROR", result["status"])
        self.assertIn("Read denied", text)

    def test_missing_core_table_is_still_error(self):
        tables = sample_tables()
        tables["File"] = None
        result, text, _ = self._run(tables)
        self.assertEqual("ERROR", result["status"])
        self.assertIn("Empty required tables", text)

    def test_field_number_fallback_and_named_data(self):
        old = {"Field3": "Src", "Field1": "Execute", "Field2": "210", "Field4": "install"}
        self.assertEqual({
            "Action": "Execute", "Type": "210", "Source": "Src", "Target": "install",
        }, _named_row("CustomAction", old))
        new = {"Action": "Execute", "Type": "210"}
        self.assertEqual(new, _named_row("CustomAction", new))

    def test_windows_com_json_contract_and_absent_table_handling(self):
        tables = sample_tables()
        for table in OPTIONAL_ABSENT:
            tables[table] = None
        data = {"Tables": tables, "Errors": {}, "Absent": list(OPTIONAL_ABSENT)}
        with patch("modules.msi_analysis.run_powershell_json", return_value=(data, {"returncode": 0, "stderr": "", "stdout": "ok"})) as execute:
            result, errors = _query_tables(Path(r"C:\Temp\test's app.msi"))
        self.assertFalse(errors)
        self.assertIsNone(result["ServiceInstall"])
        self.assertEqual("START_SERVICE", result["CustomAction"][1]["Action"])
        script = execute.call_args.args[0]
        self.assertIn("SELECT * FROM `_Tables`", script)
        self.assertIn("SELECT * FROM `_Columns`", script)
        self.assertIn("GetProperty", script)
        self.assertNotIn("$record.FieldCount", script)
        self.assertIn("test''s app.msi", script)

    def test_power_shell_malformed_optional_rows_are_errors(self):
        data = {"Tables": sample_tables(), "Errors": {}, "Absent": []}
        data["Tables"]["Binary"] = "bad"
        with patch("modules.msi_analysis.run_powershell_json", return_value=(data, {})):
            _, errors = _query_tables(Path("unused.msi"))
        self.assertIn("Binary", errors)

    def test_secret_and_tester_path_are_redacted_from_msi_text(self):
        tables = sample_tables()
        tables["CustomAction"][0]["Target"] = r"--token=never-store-me"
        with patch.dict("os.environ", {"USERPROFILE": r"C:\Users\AssessmentTester", "USERNAME": "AssessmentTester"}):
            result, text, _ = self._run(tables)
        self.assertEqual("PASS", result["status"])
        self.assertNotIn("never-store-me", text)
        self.assertIn("REDACTED", text)

    def test_control_characters_not_written_as_terminal_escape(self):
        tables = sample_tables()
        tables["CustomAction"][0]["Target"] = "start\x1b[31m\r\nend"
        _, text, _ = self._run(tables)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("start\r", text)


if __name__ == "__main__":
    unittest.main()
