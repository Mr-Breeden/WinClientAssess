import csv
import tempfile
import unittest
from pathlib import Path

from utils.file_inventory import build_file_inventory, write_file_inventory_csv, inventory_stats


class FileInventoryTests(unittest.TestCase):
    def test_inventory_and_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.exe").write_bytes(b"MZ" + b"A" * 10)
            (root / "b.json").write_text("{}", encoding="utf-8")
            rows = build_file_inventory([root])
            self.assertEqual(2, len(rows))
            stats = inventory_stats(rows, root)
            self.assertEqual(2, stats["file_count"])
            out = root / "inventory.csv"
            write_file_inventory_csv(rows, out)
            with out.open("r", encoding="utf-8", newline="") as fh:
                exported = list(csv.DictReader(fh))
            self.assertEqual({"a.exe", "b.json"}, {r["name"] for r in exported})

    def test_formula_leading_cells_are_neutralized(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "inventory.csv"
            row = {
                "root": "root",
                "path": "=HYPERLINK(\"https://example.invalid\")",
                "name": "+payload.exe",
                "extension": ".exe",
                "size_bytes": 1,
                "size_human": "1 B",
            }
            write_file_inventory_csv([row], out)
            with out.open("r", encoding="utf-8", newline="") as fh:
                exported = next(csv.DictReader(fh))
            self.assertTrue(exported["path"].startswith("'="))
            self.assertTrue(exported["name"].startswith("'+"))


if __name__ == "__main__":
    unittest.main()
