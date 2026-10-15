"""Vendor-neutral v1.8.4 detection-quality regressions with synthetic fixtures only."""
from collections import Counter
from pathlib import Path

from modules.dotnet_analysis import _source_review
from modules.dll_search_review import run_dll_search_review
from modules.local_storage_review import _is_os_execution_history, run_local_storage_review
from modules.network_surface_review import run_network_surface_review
from modules.secrets_review import run_secrets_review


def test_first_party_survives_framework_source_saturation(tmp_path):
    base = tmp_path / "decompiled"
    app = base / "01_Client.Core"
    framework = base / "02_System.Framework"
    app.mkdir(parents=True)
    framework.mkdir(parents=True)
    (app / "Main.cs").write_text("\n".join("SqliteCommand x;" for _ in range(320)) +
                                   "\nServerCertificateValidationCallback = null;\nNamedPipeServerStream p;\n")
    (framework / "Core.cs").write_text("\n".join("SqliteCommand x;" for _ in range(320)))
    scope = {"roots": [Path("C:/Client/Client.exe")], "sidecars": [Path("C:/Client/Client.Core.dll")]}
    hits = _source_review(base, tmp_path, scope)
    report = (tmp_path / "dotnet_source_review.txt").read_text()
    assert len([h for h in hits if "01_Client.Core" in h[1]]) >= 95
    assert len([h for h in hits if "02_System.Framework" in h[1]]) <= 18
    assert "First-party review points" in report
    assert "TLS validation bypass" in report
    assert "Named pipe IPC" in report
    assert "Scope" in report and "FIRST-PARTY" in report
    assert "SqliteCommand x" not in report


def test_first_party_decompiled_source_per_category_limits_do_not_starve_other_categories(tmp_path):
    base = tmp_path / "decompiled"
    app = base / "01_Client"; app.mkdir(parents=True)
    (app / "Code.cs").write_text("\n".join("SqlCommand x;" for _ in range(200)) +
                                  "\nProcess.Start(command);\nAssembly.LoadFrom(path);\n")
    hits = _source_review(base, tmp_path,
                          {"roots": [Path("C:/Client.exe")], "sidecars": []})
    counts = Counter(h[0] for h in hits)
    assert counts["SQL execution / query composition"] == 95
    assert counts["OS command execution"] >= 1
    assert counts["Dynamic assembly loading"] >= 1


def test_secret_review_capped_per_pe_and_first_party_prioritized(tmp_path, monkeypatch):
    import modules.secrets_review as secrets
    monkeypatch.setattr(secrets, "_has_pe_header", lambda _: True)
    root = tmp_path / "files"; root.mkdir()
    main = root / "Client.dll"
    main.write_bytes(b"MZ" + b"password=test-only-noncredential1234 " * 120)
    system = root / "System.Runtime.dll"
    system.write_bytes(b"MZ" + b"password=test-only-noncredential1234 " * 120)
    files = [main, system]
    inv = [{"path": str(path), "extension": ".dll", "size_bytes": path.stat().st_size} for path in files]
    result = run_secrets_review(files, tmp_path, inv,
                                {"roots": [Path("C:/Client.exe")], "sidecars": [main]})
    per_file = Counter(m["path"] for m in result["matches"])
    assert per_file[str(main)] <= 24
    assert per_file[str(system)] <= 24
    assert result["matches"][0]["path"] == str(main)
    assert "test-only-noncredential1234" not in (tmp_path / "secrets_review.txt").read_text()


def test_registry_sensitive_names_generate_review_without_acl_and_bam_is_excluded(tmp_path, monkeypatch):
    import modules.local_storage_review as mod
    monkeypatch.setattr(mod, "association_roots", lambda *a, **k: [])
    monkeypatch.setattr(mod, "read_msi_properties", lambda *a, **k: {})
    monkeypatch.setattr(mod, "target_identity_tokens", lambda **kw: ({"clientapp"}, []))
    monkeypatch.setattr(mod, "path_has_target_identity", lambda path, tokens: "clientapp" in path.lower())
    paths = [r"HKCU\Software\ClientApp\CachedPassword",
             r"HKCU\Software\ClientApp\SessionToken",
             r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\ClientApp.exe"]
    monkeypatch.setattr(mod, "_runtime_storage_paths", lambda *a: ({}, {
        mod._norm(path): {"Path": path, "Source": "Procmon target-process registry write", "Process": "ClientApp.exe"}
        for path in paths}))
    result = run_local_storage_review(tmp_path, procmon_data={"registry_writes": [{}]}, filesystem_evidence=True)
    assert len(result["registry_records"]) == 2
    assert len(result["storage_pois"]) == 2
    report = (tmp_path / "local_storage_review.txt").read_text()
    assert "CachedPassword" in report and "SessionToken" in report
    assert "Services\\bam" not in report
    assert "Broad read ACE count" in report
    assert _is_os_execution_history(paths[2])


def test_historical_network_events_reported_after_process_exit(tmp_path, monkeypatch):
    import modules.network_surface_review as mod
    monkeypatch.setattr(mod, "_collect_connections", lambda *a, **k: ([], []))
    monkeypatch.setattr(mod, "_firewall_rules", lambda *a, **k: ([], ""))
    result = run_network_surface_review(tmp_path, runtime_processes=[], procmon_data={
        "network_activity": [{"Process": "Client.exe", "Operation": "TCP Connect",
                              "Path": "localhost:1234 -> example.invalid:http"}]})
    report = (tmp_path / "network_surface_review.txt").read_text()
    assert result["historical_network_events"] == 1
    assert result["network_records"] == []
    assert "HISTORICAL TARGET NETWORK EVENTS" in report
    assert "Client.exe | TCP Connect" in report
    assert "not verified listeners" in report


def test_low_confidence_user_profile_dll_lookups_remain_evidence_but_not_review_candidates(tmp_path, monkeypatch):
    from modules import dll_search_review as module
    monkeypatch.setattr(module, "get_acl_summaries", lambda _: {})
    result = run_dll_search_review(tmp_path, {"missing_dlls": [{
        "Process": "Client.exe", "PID": 123, "Path": r"%USERPROFILE%\Desktop\Client\system.dll",
        "Result": "NAME NOT FOUND"}]})
    assert len(result["dll_records"]) == 1
    assert not result["dll_pois"]
    assert "system.dll" in (tmp_path / "dll_search_review.txt").read_text()


def test_contextual_validation_uses_retained_guided_csv_when_baseline_absent(tmp_path):
    from utils.contextual_checks import checks
    folder = tmp_path / "working"; folder.mkdir()
    (folder / "guided_runtime_target_events.csv").write_text("Process Name,Path\nClient.exe,C:\\Test\\Shared.dll\n")
    condition = {"source_module": "DLL Search Review", "title": "Client.exe -> Shared.dll",
                 "evidence": "Missing DLL: C:\\ProgramData\\Client\\Shared.dll\nSearch Directory: C:\\ProgramData\\Client",
                 "artifacts": ["dll_search_review.txt"]}
    instructions = checks(condition, tmp_path, console_paths=True)
    assert "guided_runtime_target_events.csv" in "\n".join(instructions)
    assert "procmon_target_events.csv" not in "\n".join(instructions)
