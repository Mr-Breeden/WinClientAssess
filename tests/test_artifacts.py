import unittest
from utils.artifacts import ARTIFACTS, generated_files


class ArtifactCatalogTests(unittest.TestCase):
    def test_filenames_are_unique(self):
        filenames = [spec["filename"] for spec in ARTIFACTS.values()]
        self.assertEqual(len(filenames), len(set(filenames)))

    def test_removed_metadata_artifact_is_absent(self):
        self.assertNotIn("assessment_metadata.json", generated_files())

    def test_expected_primary_artifacts_exist_in_catalog(self):
        files = generated_files()
        for name in [
            "assessment_report.html", "module_status.txt", "test_cases.txt",
            "file_inventory.csv", "updater_review.txt", "application_profile.txt", "local_storage_review.txt",
        ]:
            self.assertIn(name, files)

    def test_duplicate_serializations_are_absent(self):
        files = generated_files()
        for name in [
            "binary_security_review.csv", "install_changes.json",
            "network_surface_review.json", "advanced_runtime_review.json",
            "dll_search_review.json", "ipc_review.json",
            "privilege_boundary_review.json", "runtime_processes.json",
            "runtime_targets.json", "updater_security_review.json",
            "procmon_analysis.json",
        ]:
            self.assertNotIn(name, files)

    def test_distinct_structured_artifacts_remain(self):
        files = generated_files()
        for name in [
            "snapshot_pre.json", "snapshot_post.json", "file_inventory.csv",
            "procmon_runtime_capture.csv", "procmon_runtime_sanitized.csv",
        ]:
            self.assertIn(name, files)

    def test_raw_pml_is_not_a_primary_retained_artifact(self):
        self.assertFalse(ARTIFACTS["procmon_runtime_capture_pml"]["primary"])


if __name__ == "__main__":
    unittest.main()
