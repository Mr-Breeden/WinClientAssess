import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.signature_review import run_signature_review


class SignatureReviewTests(unittest.TestCase):
    def test_empty_signature_object_is_reported_as_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result_data = {
                "Status": "",
                "StatusMessage": None,
                "SignerSubject": None,
            }
            process = {
                "returncode": 0,
                "stdout": '{"Status":""}',
                "stderr": "Get-AuthenticodeSignature module could not be loaded.",
            }
            with patch("modules.signature_review.run_powershell_json", return_value=(result_data, process)):
                result = run_signature_review(root / "setup.msi", root)

            report = (root / "signature_review.txt").read_text(encoding="utf-8")
            self.assertEqual("ERROR", result["status"])
            self.assertIn("Authenticode query unavailable", result["details"])
            self.assertIn("Status: UNAVAILABLE", report)
            self.assertNotIn("Signature Status      : ", report)


if __name__ == "__main__":
    unittest.main()
