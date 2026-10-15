from modules.application_profile import run_application_profile


def test_application_profile_combines_cross_phase_context(tmp_path):
    result = run_application_profile(
        tmp_path, "full",
        {"installer_info": {"name": "Widget.msi", "version_info": {"ProductName": "Widget", "ProductVersion": "2.1", "CompanyName": "Acme"}}},
        {"technologies": ["MSI"]},
        {"kind": "Desktop client"},
        [{"path": "a.exe"}],
        {"pe_rows": [{"architecture": "x64"}]},
        {"dotnet_candidates": [{"path": "a.exe"}]},
        {},
        {"Services": {"added": [{"Name": "WidgetSvc"}]}, "ScheduledTasks": {"added": []}, "Drivers": {"added": []}, "InstalledApplications": {"added": []}},
        [{"Path": r"C:\\Program Files\\Widget\\widget.exe", "ProcessName": "widget.exe"}],
        [{"Name": "widget.exe"}],
        {"network_records": [{"Port": 443}]}, {"ipc_records": [{"Pipe": "Widget"}]}, [],
        {"storage_roots": [r"C:\\ProgramData\\Widget"], "storage_records": [{"Path": "x"}], "storage_pois": [], "evidence_state": "OBSERVED"},
    )
    assert result["status"] == "PASS"
    path = tmp_path / "application_profile.txt"
    text = path.read_text(encoding="utf-8")
    assert "Product name" in text and "Widget" in text
    assert "Runtime target identities" in text
    assert "Local storage evidence" in text and "OBSERVED" in text


def test_application_profile_uses_msi_and_correlated_installed_app_identity_fallback(tmp_path):
    (tmp_path / "msi_analysis.txt").write_text(
        "PROPERTY (3)\n"
        "  Property                : ProductName\n  Value                   : AcmeWidget TrainingApp\n"
        "  Property                : ProductVersion\n  Value                   : 1.0.0.0\n"
        "  Property                : Manufacturer\n  Value                   : Example Security Labs\n",
        encoding="utf-8",
    )
    diff = {
        "Services": {"added": [{"Name": "AcmeWidgetService", "PathName": r"C:\Program Files\AcmeWidget\AcmeWidgetService.exe"}]},
        "ScheduledTasks": {"added": []}, "Drivers": {"added": []},
        "Filesystem": {"added": []},
        "InstalledApplications": {"added": [
            {"DisplayName": "AcmeWidget TrainingApp", "DisplayVersion": "1.0.0.0", "Publisher": "Example Security Labs"},
            {"DisplayName": "Microsoft OneDrive", "DisplayVersion": "99.0", "Publisher": "Microsoft Corporation"},
        ]},
    }
    result = run_application_profile(tmp_path, "full", {}, {}, {}, [], {}, {}, {}, diff, [], [], {}, {}, [], {})
    assert result["profile"]["product_name"] == "AcmeWidget TrainingApp"
    assert result["profile"]["product_version"] == "1.0.0.0"
    assert result["profile"]["publisher"] == "Example Security Labs"
    text = (tmp_path / "application_profile.txt").read_text(encoding="utf-8")
    assert "Target installed application records" in text
    assert "Other observed installed-app changes" in text
    assert "Microsoft OneDrive" not in text
