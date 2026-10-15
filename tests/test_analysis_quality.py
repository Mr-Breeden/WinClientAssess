import tempfile
import unittest
import sys
import types
from pathlib import Path
from unittest.mock import patch

from modules.configuration_review import run_configuration_review
from modules.secrets_review import run_secrets_review

with patch.dict(sys.modules, {"psutil": types.ModuleType("psutil")}):
    from modules.ipc_review import _pipe_permissions


class AnalysisQualityTests(unittest.TestCase):
    def test_pem_certificate_bundle_is_not_described_as_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pem = root / "cacert.pem"
            pem.write_text("-----BEGIN CERTIFICATE-----\na\n-----END CERTIFICATE-----\n" * 2, encoding="utf-8")
            inventory = [{"path": str(pem), "extension": ".pem", "size_bytes": pem.stat().st_size}]
            run_configuration_review([root], root, inventory)
            report = (root / "high_value_security_artifacts.txt").read_text(encoding="utf-8")
            self.assertIn("certificate bundle", report)
            self.assertIn("no private-key marker", report)

    def test_low_confidence_secret_ids_are_unique_and_do_not_warn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "app.js"
            script.write_text("password=testvalue\npassword=testvalue\n", encoding="utf-8")
            inventory = [{"path": str(script), "extension": ".js", "size_bytes": script.stat().st_size}]
            result = run_secrets_review([root], root, inventory)
            report = (root / "secrets_review.txt").read_text(encoding="utf-8")
            self.assertEqual("PASS", result["status"])
            self.assertIn("SECRET-001", report)
            self.assertIn("SECRET-002", report)
            self.assertEqual([], result["findings"])

    def test_failed_accesschk_output_is_not_successful_permission_evidence(self):
        rows = [{"PipeName": "target.pipe"}]
        tools = {"AccessChk": {"path": r"C:\\Tools\\accesschk.exe"}}
        output = "Error getting security:\nAll pipe instances are busy.\nNo matching objects found."
        with patch("modules.ipc_review.run_command", return_value={"returncode": 1, "stdout": output, "stderr": ""}):
            permissions, error = _pipe_permissions(rows, tools)
        self.assertFalse(permissions["target.pipe"]["Succeeded"])
        self.assertIn("permissions unavailable", error)


if __name__ == "__main__":
    unittest.main()
