from pathlib import Path

import modules.local_storage_review as ls


class FakeAclCache:
    def get_many(self, paths):
        result = {}
        for path in paths:
            result[str(path).lower()] = {
                "Path": str(path), "Exists": True, "Owner": "SYSTEM",
                "Access": [{"Identity": "BUILTIN\\Users", "Rights": "ReadAndExecute", "Type": "Allow", "Inherited": True}],
            }
        return result


def test_local_storage_records_indicator_location_without_secret_value(tmp_path, monkeypatch):
    storage = r"C:\\ProgramData\\AcmeWidget\\settings.json"
    diff = {
        "Filesystem": {"added": [{"Path": storage, "IsDirectory": False, "Length": 12}], "changed": []},
        "InstalledApplications": {"added": [{"DisplayName": "AcmeWidget", "Publisher": "Acme", "InstallLocation": r"C:\\Program Files\\AcmeWidget"}]},
        "Services": {"added": []}, "ScheduledTasks": {"added": []}, "RegistryKeys": {"added": []},
    }
    runtime_targets = [{"Path": r"C:\\Program Files\\AcmeWidget\\AcmeWidget.exe", "ProcessName": "AcmeWidget.exe"}]
    monkeypatch.setattr(ls, "_inspect_file", lambda path: [{"Type": "Token-like key", "Line": 17, "Source": "Text/config key name"}])
    result = ls.run_local_storage_review(
        tmp_path, diff, {}, runtime_targets, [], {"installer_info": {"name": "AcmeWidget.msi"}}, FakeAclCache(), True,
    )
    assert result["status"] == "WARN"
    assert len(result["storage_records"]) == 1
    assert len(result["storage_pois"]) == 1
    report = (tmp_path / "reports" / "local_storage_review.txt") if (tmp_path / "reports").exists() else tmp_path / "local_storage_review.txt"
    # artifact_path uses a flat fallback for unstructured unit-test roots.
    if not report.exists():
        report = tmp_path / "local_storage_review.txt"
    text = report.read_text(encoding="utf-8")
    assert "Token-like key" in text
    assert "First match line: 17" in text
    assert "secret-value-should-never-appear" not in text


def test_local_storage_no_observation_is_not_collection_unavailable(tmp_path):
    result = ls.run_local_storage_review(tmp_path, {"Filesystem": {"added": [], "changed": []}}, {}, [], [], {}, FakeAclCache(), True)
    assert result["status"] == "PASS"
    assert result["evidence_state"] == "COLLECTED / NO OBSERVATION"
    assert result["coverage_gap"] is False


def test_local_storage_candidate_gets_safe_candidate_specific_checks(tmp_path):
    from utils.contextual_checks import checks
    item = {
        "source_module": "Local Storage Review",
        "title": r"C:\ProgramData\Widget\settings.json",
        "evidence": r"C:\ProgramData\Widget\settings.json\nPotential-secret indicators: Token-like key@17",
        "artifacts": ["local_storage_review.txt"],
    }
    commands = checks(item, tmp_path, console_paths=True)
    joined = "\n".join(commands)
    assert "Get-Acl" in joined
    assert "icacls" in joined
    assert "Get-Content" not in joined  # avoid printing a potential secret line into captured output
    assert "do not paste secret values" in joined


def test_local_storage_does_not_promote_unrelated_installed_application_churn(tmp_path, monkeypatch):
    target_storage = r"C:\ProgramData\AcmeWidget\Log\AcmeWidget.log"
    unrelated_storage = r"C:\ProgramData\Microsoft\OneDrive\logs\setup.log"
    diff = {
        "Filesystem": {"added": [
            {"Path": target_storage, "IsDirectory": False, "Length": 10},
            {"Path": unrelated_storage, "IsDirectory": False, "Length": 10},
        ], "changed": []},
        "InstalledApplications": {"added": [
            {"DisplayName": "AcmeWidget TrainingApp", "DisplayVersion": "1.0.0.0", "Publisher": "Example Security Labs", "InstallLocation": "", "UninstallString": r"MsiExec.exe /X{TARGET-CODE}"},
            {"DisplayName": "Microsoft OneDrive", "DisplayVersion": "99.1", "Publisher": "Microsoft Corporation", "InstallLocation": ""},
        ]},
        "Services": {"added": [{"Name": "AcmeWidgetService", "DisplayName": "AcmeWidgetService", "PathName": r"C:\Program Files\AcmeWidget\AcmeWidgetService.exe"}]},
        "ScheduledTasks": {"added": []}, "RegistryKeys": {"added": []},
    }
    (tmp_path / "msi_analysis.txt").write_text(
        "PROPERTY\nProperty                : ProductCode\nValue                   : {TARGET-CODE}\n"
        "Property                : ProductName\nValue                   : AcmeWidget TrainingApp\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ls, "_inspect_file", lambda path: [])
    result = ls.run_local_storage_review(tmp_path, diff, {}, [], [], {}, FakeAclCache(), True)
    paths = [row["Path"] for row in result["storage_records"]]
    assert target_storage in paths
    assert unrelated_storage not in paths
    assert result["target_installed_apps"][0]["DisplayName"] == "AcmeWidget TrainingApp"


def test_local_storage_identity_is_exact_token_not_arbitrary_substring(tmp_path, monkeypatch):
    diff = {
        "Filesystem": {"added": [
            {"Path": r"C:\ProgramData\AcmeWidget\settings.json", "IsDirectory": False, "Length": 1},
            {"Path": r"C:\ProgramData\NotAcmeWidgetizer\noise.json", "IsDirectory": False, "Length": 1},
        ], "changed": []},
        "InstalledApplications": {"added": [{"DisplayName": "AcmeWidget", "InstallLocation": r"C:\Program Files\AcmeWidget"}]},
        "Services": {"added": [{"Name": "AcmeWidgetService", "PathName": r"C:\Program Files\AcmeWidget\svc.exe"}]},
        "ScheduledTasks": {"added": []}, "RegistryKeys": {"added": []},
    }
    monkeypatch.setattr(ls, "_inspect_file", lambda path: [])
    result = ls.run_local_storage_review(tmp_path, diff, {}, [], [], {"installer_info": {"name": "AcmeWidgetInstaller.exe"}}, FakeAclCache(), True)
    paths = [row["Path"] for row in result["storage_records"]]
    assert r"C:\ProgramData\AcmeWidget\settings.json" in paths
    assert r"C:\ProgramData\NotAcmeWidgetizer\noise.json" not in paths
