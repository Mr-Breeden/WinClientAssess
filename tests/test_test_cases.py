import tempfile
import unittest
from pathlib import Path

from modules.test_cases import generate_test_cases


class TestCaseGenerationTests(unittest.TestCase):
    def test_static_checklist_excludes_runtime_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename in [
                "installer_analysis.txt", "installer_technology.txt", "signature_review.txt",
                "binary_security_review.txt", "configuration_review.txt", "secrets_review.txt",
                "high_value_security_artifacts.txt",
            ]:
                (root / filename).write_text("synthetic", encoding="utf-8")
            generate_test_cases(root, "static", ".exe", {
                "installed_state": False,
                "filesystem_snapshot": False,
                "procmon": False,
                "surface_review": False,
            })
            text = (root / "test_cases.txt").read_text(encoding="utf-8")
            self.assertIn("Applicable Cases", text)
            self.assertIn("TC-IN-001", text)
            for case_id in ["TC-PM-001", "TC-AR-001", "TC-NW-001", "TC-IP-001", "TC-UP-001"]:
                self.assertNotIn(case_id, text)


if __name__ == "__main__":
    unittest.main()
