import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.installer_extract import run_installer_extract


class InstallerExtractionTests(unittest.TestCase):
    def test_7zip_warning_exit_is_not_reported_as_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installer = root / "setup.exe"
            installer.write_bytes(b"MZ")
            result_data = {"returncode": 1, "stdout": "warning", "stderr": "skipped file"}
            tools = {"7-Zip": {"path": r"C:\\Tools\\7z.exe"}}
            with patch("modules.installer_extract.run_command", return_value=result_data):
                result = run_installer_extract(installer, root, tools, defer_report=True)
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["extract_dir"])
            self.assertIn("incomplete", result["details"])


if __name__ == "__main__":
    unittest.main()
