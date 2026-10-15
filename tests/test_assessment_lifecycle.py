import json
import tempfile
import unittest
from pathlib import Path

from utils.assessment_layout import artifact_path, ensure_structured_layout, generated_directory_path
from utils.assessment_state import AssessmentState, describe_assessment


class V130LifecycleTests(unittest.TestCase):
    def _installer(self, root: Path):
        path = root / "fixture.msi"
        path.write_bytes(b"fixture-msi")
        return path

    def test_structured_layout_routes_reports_and_working_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "assessment"
            ensure_structured_layout(root)
            self.assertEqual(artifact_path(root, "findings.txt"), root / "reports" / "findings.txt")
            self.assertEqual(artifact_path(root, "snapshot_pre.json"), root / "working" / "snapshot_pre.json")
            self.assertEqual(artifact_path(root, "procmon_runtime_capture.csv"), root / "working" / "procmon_runtime_capture.csv")
            self.assertEqual(generated_directory_path(root, "extracted_installer"), root / "working" / "extracted_installer")

    def test_flat_layout_remains_backward_compatible(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.assertEqual(artifact_path(root, "findings.txt"), root / "findings.txt")
            self.assertEqual(artifact_path(root, "snapshot_pre.json"), root / "snapshot_pre.json")

    def test_state_contains_filename_and_hash_not_source_path(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            installer = self._installer(root)
            assessment = root / "assessment"
            state = AssessmentState.create(
                assessment,
                assessment_name="Lifecycle Test",
                installer=installer,
                mode="full",
                framework_version="1.3.0",
                options={"target_only": False},
                tools={"Python": {"found": True, "level": "REQUIRED", "usage": "INTEGRATED", "path": str(root / "private" / "python.exe")}},
            )
            raw = (assessment / "working" / "assessment_state.json").read_text(encoding="utf-8")
            self.assertNotIn(str(installer.parent), raw)
            self.assertNotIn("private", raw)
            self.assertEqual(state.data["installer"]["filename"], "fixture.msi")
            self.assertEqual(len(state.data["installer"]["sha256"]), 64)

    def test_atomic_state_has_no_leftover_temp_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            installer = self._installer(root)
            assessment = root / "assessment"
            state = AssessmentState.create(
                assessment, assessment_name="Atomic", installer=installer, mode="static",
                framework_version="1.3.0", options={}, tools={},
            )
            state.checkpoint("static_analysis", "COMPLETED", "done")
            self.assertFalse((assessment / "working" / "assessment_state.json.tmp").exists())
            parsed = json.loads((assessment / "working" / "assessment_state.json").read_text())
            self.assertEqual(parsed["stages"]["static_analysis"]["status"], "COMPLETED")

    def test_preinstall_checkpoint_can_resume_installation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            installer = self._installer(root)
            assessment = root / "assessment"
            state = AssessmentState.create(
                assessment, assessment_name="Resume", installer=installer, mode="full",
                framework_version="1.3.0", options={}, tools={},
            )
            state.checkpoint("pre_install_snapshot", "COMPLETED", "baseline ready")
            action, _ = state.recovery_action()
            self.assertEqual(action, "INSTALL")

    def test_started_but_incomplete_preinstall_snapshot_halts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            installer = self._installer(root)
            assessment = root / "assessment"
            state = AssessmentState.create(
                assessment, assessment_name="Unsafe", installer=installer, mode="full",
                framework_version="1.3.0", options={}, tools={},
            )
            state.checkpoint("pre_install_snapshot", "STARTED", "capture started")
            action, message = state.recovery_action()
            self.assertEqual(action, "HALT")
            self.assertIn("clean VM baseline", message)

    def test_postinstall_checkpoint_can_resume_analysis(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            installer = self._installer(root)
            assessment = root / "assessment"
            state = AssessmentState.create(
                assessment, assessment_name="Resume", installer=installer, mode="full",
                framework_version="1.3.0", options={}, tools={},
            )
            state.checkpoint("pre_install_snapshot", "COMPLETED")
            state.checkpoint("installation_confirmation", "COMPLETED")
            state.checkpoint("post_install_snapshot", "COMPLETED")
            action, _ = state.recovery_action()
            self.assertEqual(action, "ANALYSIS")

    def test_legacy_assessment_is_readable_but_not_silently_converted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "module_status.txt").write_text("legacy", encoding="utf-8")
            info = describe_assessment(root)
            self.assertEqual(info["kind"], "legacy")
            self.assertEqual(info["action"], "CONVERT_REQUIRED")


if __name__ == "__main__":
    unittest.main()
