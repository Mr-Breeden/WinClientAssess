"""Regression coverage for v1.8.3's vendor-neutral detection improvements.

Fixtures are synthetic: real target applications or credentials never ship with WCA.
"""
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from modules.application_profile import run_application_profile
from modules.configuration_review import run_configuration_review
from modules.dotnet_analysis import _prioritized_candidates, run_dotnet_analysis
from modules.secrets_review import run_secrets_review
from utils.privacy import sanitize_report_text


def test_xml_credential_properties_and_controls_are_found_without_value_disclosure(tmp_path):
    source = tmp_path / "config.xml"
    sentinel = "TEST_ONLY_CANARY_SECRET_11_RANDOM_NOT_REAL"
    source.write_text(
        "<Client><AdminPassword>" + sentinel + "</AdminPassword>"
        "<JwtSecret>anotherfakecredential1234</JwtSecret>"
        "<ApiKey>FAKE_KEY_NOT_VALID_ANYWHERE_1234</ApiKey>"
        "<SecretAccessKey>fakenotvalid44554455</SecretAccessKey>"
        "<LogPasswords>true</LogPasswords>"
        "<AccessKeyId>PUBLIC_EXAMPLE_ID_AAA</AccessKeyId>"
        "<IgnoreSslErrors>true</IgnoreSslErrors>"
        "<HashAlgorithm>MD5</HashAlgorithm>"
        "<UpdateServerUrl>http://example.invalid/update</UpdateServerUrl>"
        "</Client>", encoding="utf-8"
    )
    inventory = [{"path": str(source), "extension": ".xml", "size_bytes": source.stat().st_size}]
    secret_result = run_secrets_review([source], tmp_path, inventory)
    config_result = run_configuration_review([source], tmp_path, inventory)
    kinds = Counter(row["type"] for row in secret_result["matches"])
    assert kinds["XML credential element"] == 4
    assert len(config_result["security_indicators"]) == 4
    assert secret_result["status"] == "WARN"
    assert config_result["status"] == "WARN"
    assert all(row.get("redacted") == "[REDACTED]" for row in secret_result["matches"])
    for name in ("secrets_review.txt", "configuration_review.txt"):
        report = (tmp_path / name).read_text(encoding="utf-8")
        assert sentinel not in report
        assert "FAKE_KEY_NOT_VALID_ANYWHERE_1234" not in report
        assert "anotherfakecredential1234" not in report
        assert "PUBLIC_EXAMPLE_ID_AAA" not in report
    assert "TLS verification disabled" in (tmp_path / "configuration_review.txt").read_text()


def test_bearer_token_summary_count_survives_final_privacy_pass(tmp_path):
    source = tmp_path / "sample.txt"
    source.write_text("Authorization: Bearer fake-test-token-1234567890\n", encoding="utf-8")
    run_secrets_review([source], tmp_path)
    text = (tmp_path / "secrets_review.txt").read_text(encoding="utf-8")
    final = sanitize_report_text(text)
    assert "Bearer token indicators" in final
    assert "Bearer token indicators" in final and "<REDACTED>" not in final.split("Bearer token indicators", 1)[1].splitlines()[0]
    assert "fake-test-token-1234567890" not in final


def test_first_party_assemblies_precede_framework_candidates():
    root = Path("C:/client")
    files = [root / ("System." + str(i) + ".dll") for i in range(55)]
    files += [root / "Example.Core.dll", root / "Example.Services.dll", root / "Example.dll"]
    scope = {"roots": [root / "Example.exe"], "sidecars": [root / "Example.dll"]}
    order = _prioritized_candidates(files, scope)
    assert [x.name for x in order[:3]] == ["Example.dll", "Example.Core.dll", "Example.Services.dll"]


def test_decompiler_prioritizes_first_party_and_source_review_labels_only(tmp_path):
    exe = tmp_path / "TestApp.exe"
    app = tmp_path / "TestApp.dll"
    app.write_bytes(b"unit-test-stub")
    framework = [tmp_path / ("System." + str(i) + ".dll") for i in range(51)]
    for file in framework: file.write_bytes(b"stub")
    candidates = framework + [app]
    inv = [{"path": str(file), "extension": ".dll"} for file in candidates]
    pe_rows = [{"path": str(file), "dotnet": True, "error": ""} for file in candidates]
    called = []

    def fake_ilspy(command, **kwargs):
        called.append(Path(command[-1]).name)
        out = Path(command[command.index("-o") + 1]); out.mkdir(parents=True, exist_ok=True)
        if command[-1] == str(app):
            (out / "MyExample.cs").write_text(
                'class Example { void Test() { new SqliteCommand(); '
                'ServerCertificateValidationCallback = null; '
                'Assembly.LoadFrom("TEST_PRIVATE_PASSWORD_NEVER_WRITE"); } }', encoding="utf-8")
        return {"returncode": 0, "stderr": ""}

    with patch("modules.dotnet_analysis.run_command", side_effect=fake_ilspy):
        result = run_dotnet_analysis(
            [exe], tmp_path, {"ILSpyCmd": {"path": "fake-ilspycmd"}}, inv,
            {"pe_rows": pe_rows},
            {"roots": [exe], "sidecars": [app], "dotnet_host": True})
    assert called[0] == "TestApp.dll"
    assert len(called) == 50
    assert result["coverage_gap"]
    report = (tmp_path / "dotnet_source_review.txt").read_text(encoding="utf-8")
    assert "TLS validation bypass" in report
    assert "Dynamic plugin / assembly load" in report
    assert "SQL execution / query composition" in report
    assert "TEST_PRIVATE_PASSWORD_NEVER_WRITE" not in report


def test_profile_recovers_static_managed_identity_after_runtime_refresh(tmp_path):
    (tmp_path / "dotnet_analysis.txt").write_text(".NET candidates: 448\n", encoding="utf-8")
    (tmp_path / "application_scope.txt").write_text(
        "Selected executable : Client.exe\n"
        "Classification: portable_dotnet_application\n"
        "Total static source files: 477\n", encoding="utf-8")
    run_application_profile(tmp_path, mode="full", static_inventory=[], pe_result={}, dotnet_result={})
    report = (tmp_path / "application_profile.txt").read_text(encoding="utf-8")
    assert "Managed/.NET candidates" in report and "448" in report
    assert "Technologies" in report and ".NET" in report
    assert "477" in report
    assert "Client.exe" in report


def test_json_configuration_settings_are_identified_without_values(tmp_path):
    source = tmp_path / "appsettings.json"
    source.write_text('{"Logging":{"LogPasswords":true},"Updater":{"AllowUnsignedUpdates":true},"Auth":{"JwtSecret":"notarealcredential12345"}}')
    inventory = [{"path": str(source), "extension": ".json", "size_bytes": source.stat().st_size}]
    result = run_configuration_review([source], tmp_path, inventory)
    secrets = run_secrets_review([source], tmp_path, inventory)
    assert len(result["security_indicators"]) == 2
    assert any(m["type"] == "JSON credential property" for m in secrets["matches"])
    report = (tmp_path / "configuration_review.txt").read_text()
    assert "notarealcredential12345" not in report


def test_dll_acl_profile_expansion_is_not_persisted(tmp_path, monkeypatch):
    from modules.dll_search_review import run_dll_search_review
    monkeypatch.setenv("USERPROFILE", r"C:\Users\FakeTester")
    calls = []

    class StubAcl:
        def get_many(self, paths):
            calls.extend(paths)
            return {p.lower(): {"Path": p, "Exists": True, "Owner": None, "Access": []} for p in paths}

    result = run_dll_search_review(tmp_path, {"missing_dlls": [{
        "Process": "Client.exe", "Path": r"%USERPROFILE%\Desktop\Client\some.dll", "Result": "NAME NOT FOUND"}]},
        acl_cache=StubAcl())
    assert calls == [r"C:\Users\FakeTester\Desktop\Client"]
    assert result["dll_records"][0]["DirectoryExists"] is True
    assert "FakeTester" not in (tmp_path / "dll_search_review.txt").read_text()
