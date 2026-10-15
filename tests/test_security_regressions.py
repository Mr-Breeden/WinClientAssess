import csv
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from modules.component_lifecycle_review import run_component_lifecycle_review
from modules.electron_security_review import run_electron_security_review
from modules.pe_analysis import run_pe_analysis
from modules.procmon_analysis import run_procmon_analysis
from modules.ipc_review import _is_system_pipe, run_ipc_review
from modules.updater_security_review import _discover_artifacts, run_updater_security_review
from utils.sensitive_data import REDACTED, redact_sensitive_text, sanitize_procmon_csv

with patch.dict(sys.modules, {"psutil": types.ModuleType("psutil")}):
    from modules.network_surface_review import _configured_local_http_ports


class SensitiveRuntimeEvidenceTests(unittest.TestCase):
    def test_sensitive_assignments_and_query_values_are_redacted(self):
        raw = "CLIENT_SECRET=real-secret-value https://127.0.0.1/?token=url-token"
        clean, counts = redact_sensitive_text(raw)
        self.assertNotIn("real-secret-value", clean)
        self.assertNotIn("url-token", clean)
        self.assertIn(f"CLIENT_SECRET={REDACTED}", clean)
        self.assertEqual(1, counts["CLIENT_SECRET"])
        self.assertEqual(1, counts["TOKEN"])

    def test_procmon_analysis_retains_only_sanitized_derived_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "input.csv"
            secret = "runtime-client-secret-123"
            with source.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["Time of Day", "Process Name", "PID", "Operation", "Path", "Result", "Detail"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "Time of Day": "10:00:00",
                        "Process Name": "client.exe",
                        "PID": "10",
                        "Operation": "Process Create",
                        "Path": r"C:\Program Files\Client\child.exe",
                        "Result": "SUCCESS",
                        "Detail": f"Environment: CLIENT_SECRET={secret}",
                    }
                )
            result = run_procmon_analysis(root, source, [])
            self.assertEqual("WARN", result["status"])
            self.assertEqual(1, result["sanitization"]["redaction_count"])
            self.assertTrue(any("Sensitive Values" in item["title"] for item in result["findings"]))
            for name in ("procmon_runtime_sanitized.csv", "procmon_process_activity.txt", "runtime_secrets_review.txt"):
                self.assertNotIn(secret, (root / name).read_text(encoding="utf-8-sig"))
            # Re-analysis of the framework's sanitized path must not truncate it
            # and must preserve the fact that a sensitive field was observed.
            second = run_procmon_analysis(root, root / "procmon_runtime_sanitized.csv", [])
            self.assertEqual(1, second["sanitization"]["redaction_count"])
            self.assertGreater((root / "procmon_runtime_sanitized.csv").stat().st_size, 0)

    def test_automated_sanitized_capture_is_not_duplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "procmon_runtime_capture.csv"
            source.write_text('"Process Name","Operation"\n"client.exe","ReadFile"\n', encoding="utf-8")
            stale = root / "procmon_runtime_sanitized.csv"
            stale.write_text("stale", encoding="utf-8")
            result = run_procmon_analysis(
                root,
                source,
                [],
                {"redaction_count": 0, "sensitive_names": {}, "rows": 1},
            )
            self.assertEqual(str(source.resolve()), result["sanitization"]["sanitized_path"])
            self.assertFalse(stale.exists())

    def test_procmon_csv_sanitizer_reports_names_not_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "raw.csv"
            destination = root / "clean.csv"
            source.write_text('"Detail"\n"TOKEN=top-secret"\n', encoding="utf-8")
            result = sanitize_procmon_csv(source, destination)
            self.assertEqual({"TOKEN": 1}, result["sensitive_names"])
            self.assertNotIn("top-secret", destination.read_text(encoding="utf-8-sig"))


class ElectronAndLifecycleTests(unittest.TestCase):
    def _inventory(self, *paths):
        return [
            {"path": str(path), "extension": path.suffix.lower(), "size_bytes": path.stat().st_size}
            for path in paths
        ]

    def test_electron_insecure_remote_renderer_and_secret_flow_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "package.json"
            package.write_text('{"devDependencies":{"electron":"32.0.1"}}', encoding="utf-8")
            main = root / "main.js"
            main.write_text(
                """
                const {BrowserWindow} = require('electron');
                clientSecret = process.env.CLIENT_SECRET;
                port = jsonData.CLIENT_API_SERVER_PORT;
                target = 'http://127.0.0.1:' + port + '/index.html';
                target += '?secret=' + clientSecret;
                win = new BrowserWindow({webPreferences:{nodeIntegration:true, contextIsolation:false,
                    enableRemoteModule:true, webviewTag:true}});
                win.loadURL(target);
                app.on('certificate-error', (event, contents, url, error, cert, callback) => callback(true));
                """,
                encoding="utf-8",
            )
            result = run_electron_security_review([root], root, self._inventory(package, main))
            titles = {item["title"] for item in result["findings"]}
            self.assertIn("Electron Renderer Trust Boundary Requires Remediation", titles)
            self.assertIn("Electron Certificate Validation Can Be Bypassed", titles)
            self.assertIn("Electron Secret Is Propagated Through a URL", titles)
            self.assertEqual(["CLIENT_API_SERVER_PORT"], result["local_http_port_keys"])

    def test_end_of_life_openssl_and_electron_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crypto = root / "LIBEAY32.dll"
            crypto.write_bytes(b"prefix OpenSSL 1.0.2zk suffix")
            package = root / "package.json"
            package.write_text('{"devDependencies":{"electron":"32.0.1"}}', encoding="utf-8")
            electron = {
                "electron_versions": [
                    {"Path": str(package), "Version": "32.0.1", "Source": "devDependencies"}
                ]
            }
            result = run_component_lifecycle_review(
                [root], root, self._inventory(crypto, package), electron
            )
            titles = [item["title"] for item in result["findings"]]
            self.assertIn("End-of-Life OpenSSL Component Identified", titles)
            self.assertIn("End-of-Life Electron Component Identified", titles)


class CorrelationPrecisionTests(unittest.TestCase):
    def test_target_only_ipc_skips_host_wide_pipe_enumeration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            processes = [{"PID": 10, "Name": "Client.exe", "Exe": r"C:\Client\Client.exe"}]
            with patch(
                "modules.ipc_review._enumerate_pipes_powershell"
            ) as enumerate_pipes, patch(
                "modules.ipc_review._target_handle_inventory", return_value=([], [], "")
            ), patch(
                "modules.ipc_review._pipe_permissions", return_value=({}, "")
            ):
                run_ipc_review(
                    root,
                    {},
                    runtime_processes=processes,
                    target_only=True,
                )
            enumerate_pipes.assert_not_called()
            inventory = (root / "named_pipe_inventory.txt").read_text(encoding="utf-8")
            self.assertIn("Suppressed by --target-only", inventory)

    def test_well_known_windows_pipe_is_not_treated_as_product_owned(self):
        self.assertTrue(_is_system_pipe(r"\\lsass"))
        self.assertFalse(_is_system_pipe("vendor-control-pipe"))

    def test_declared_nonstandard_loopback_http_ports_are_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "ports.json"
            config.write_text('{"CLIENT_API_SERVER_PORT":7010,"OTHER":99}', encoding="utf-8")
            diff = {"Filesystem": {"added": [{"Path": str(config), "IsDirectory": False}], "changed": []}}
            hints = {"dynamic_loopback_http": True, "local_http_port_keys": ["CLIENT_API_SERVER_PORT"]}
            ports, sources = _configured_local_http_ports(diff, hints)
            self.assertEqual({7010}, ports)
            self.assertEqual([str(config)], sources)

    def test_unrelated_staging_named_paths_are_not_updater_artifacts(self):
        candidates = [{"Path": r"C:\Program Files\Druva\inSync\inSyncUpgrade.exe"}]
        diff = {
            "Filesystem": {
                "added": [
                    {"Path": r"C:\Users\Alice\AppData\Roaming\OtherApp\Cache\payload.zip", "IsDirectory": False},
                    {"Path": r"C:\ProgramData\Druva\inSync\Upgrade\payload.zip", "IsDirectory": False},
                ],
                "changed": [],
            }
        }
        artifacts = _discover_artifacts(diff, candidates, None)
        self.assertEqual([r"C:\ProgramData\Druva\inSync\Upgrade\payload.zip"], [item["Path"] for item in artifacts])

    def test_updater_runtime_coverage_gap_becomes_a_review_point(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = {"Path": str(root / "Updater.exe"), "Source": "static/extracted"}
            procmon = {key: [] for key in ("file_writes", "registry_writes", "network_activity", "process_activity")}
            with patch("modules.updater_security_review._signature_batch", return_value={}):
                result = run_updater_security_review(
                    root,
                    [candidate],
                    diff={},
                    procmon_data=procmon,
                    filesystem_evidence=False,
                )
            self.assertEqual("WARN", result["status"])
            self.assertTrue(result["coverage_gap"])
            self.assertTrue(any("Workflow Was Not Observed" in item["title"] for item in result["findings"]))

    def test_pe_baseline_and_cfg_gaps_are_separate_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [
                {"path": str(root / "legacy.dll"), "architecture": "x64", "aslr": False, "dep_nx": False, "cfg": False, "high_entropy_va": False, "dotnet": False, "error": ""},
                {"path": str(root / "modern.dll"), "architecture": "x64", "aslr": True, "dep_nx": True, "cfg": False, "high_entropy_va": True, "dotnet": False, "error": ""},
            ]
            with patch("modules.pe_analysis.pefile", object()), patch(
                "modules.pe_analysis._iter_candidates", return_value=[Path(item["path"]) for item in rows]
            ), patch("modules.pe_analysis._analyze", side_effect=rows):
                result = run_pe_analysis([root], root)
            titles = {item["title"] for item in result["findings"]}
            self.assertIn("PE Files Lack Baseline Exploit Mitigations", titles)
            self.assertIn("Control Flow Guard Coverage Requires Improvement", titles)


if __name__ == "__main__":
    unittest.main()
