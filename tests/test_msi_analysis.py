import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.msi_analysis import TABLES, run_msi_analysis


class MsiAnalysisTests(unittest.TestCase):
    def test_empty_core_tables_are_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installer = root / "setup.msi"
            installer.write_bytes(b"synthetic")
            empty = {name: [] for name in TABLES}
            with patch("modules.msi_analysis._query_tables", return_value=(empty, {})):
                result = run_msi_analysis(installer, root)
            self.assertEqual("ERROR", result["status"])
            self.assertIn("Empty required tables", (root / "msi_analysis.txt").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
