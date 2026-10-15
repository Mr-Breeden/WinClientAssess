from __future__ import annotations

import struct
from argparse import Namespace
from pathlib import Path

import pytest

from modules.application_scope import detect_application_scope
from modules.secrets_review import run_secrets_review
from modules.target_info import run_target_info
from utils.assessment_state import AssessmentState
from utils.artifacts import artifact
from wca import _resolve_portable_primary, resolve_inputs


def _args(**overrides):
    data = dict(
        target=None, installer=None, target_type=None, primary_executable=None,
        assessment_name=None, output=None, mode=None, no_extract=False,
        application_dir=None, no_filesystem_snapshot=False, non_interactive=True,
        no_gui=True, runtime_capture=False, runtime_seconds=0, procmon_csv=None,
        surface_review=False, exclude_path=[], target_only=False, status=None,
        resume=None, verify_assessment=None, review=None, guided_runtime=None,
        regenerate_reports=None,
    )
    data.update(overrides)
    return Namespace(**data)


def _minimal_pe(path: Path, payload=b""):
    dos = bytearray(128)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    path.write_bytes(bytes(dos) + b"PE\x00\x00" + b"\x00" * 64 + payload)
    return path


def test_portable_directory_primary_selection_requires_explicit_choice_when_ambiguous(tmp_path):
    source = tmp_path / "portable"
    source.mkdir()
    (source / "Client.exe").write_bytes(b"MZ")
    (source / "Helper.exe").write_bytes(b"MZ")
    with pytest.raises(SystemExit, match="Multiple portable executables"):
        _resolve_portable_primary(source, interactive=False)
    selected_source, primary = _resolve_portable_primary(source, "Client.exe", interactive=False)
    assert selected_source == source.resolve()
    assert primary == (source / "Client.exe").resolve()


def test_portable_noninteractive_resolution_returns_primary_source_and_type(tmp_path):
    source = tmp_path / "portable"
    source.mkdir()
    exe = source / "Client.exe"
    exe.write_bytes(b"MZ")
    output = tmp_path / "out"
    args = _args(target=str(source), target_type="portable", primary_executable="Client.exe",
                 assessment_name="portable-test", output=str(output), mode="static")
    primary, selected_source, target_type, name, assessment_dir, mode = resolve_inputs(args)
    assert primary == exe.resolve()
    assert selected_source == source.resolve()
    assert target_type == "portable"
    assert name == "portable-test"
    assert assessment_dir == (output / "portable-test").resolve()
    assert mode == "static"


def test_portable_scope_does_not_assume_installer_semantics(tmp_path):
    source = tmp_path / "portable"
    source.mkdir()
    exe = _minimal_pe(source / "Client.exe")
    (source / "Client.dll").write_bytes(b"MZ")
    scope = detect_application_scope(exe, tmp_path / "results", explicit_dir=source, target_type="portable")
    assert scope["kind"] == "portable_application_directory"
    assert scope["known_installer"] is False
    assert scope["skip_extraction"] is True
    assert exe in scope["roots"]


def test_portable_state_is_pinned_by_primary_executable_not_directory_churn(tmp_path):
    source = tmp_path / "portable"
    source.mkdir()
    exe = source / "Client.exe"
    exe.write_bytes(b"MZ-primary")
    assessment = tmp_path / "assessment"
    state = AssessmentState.create(
        assessment, assessment_name="portable", installer=exe, mode="full",
        framework_version="1.8.3", options={}, tools={}, target_type="portable", target_source=source,
    )
    (source / "runtime-created.db").write_text("runtime data")
    ok, message = state.validate_target(exe, source_path=source, target_type="portable")
    assert ok and "identity verified" in message
    exe.write_bytes(b"MZ-modified")
    ok, _ = state.validate_target(exe, source_path=source, target_type="portable")
    assert not ok


def test_target_information_artifact_and_catalog(tmp_path, monkeypatch):
    exe = tmp_path / "Client.exe"
    exe.write_bytes(b"MZ-target")
    monkeypatch.setattr("modules.target_info.run_powershell_json", lambda *_a, **_k: (None, {}))
    result = run_target_info(exe, tmp_path, source_path=exe, target_type="portable")
    report = tmp_path / artifact("target_analysis")
    assert result["status"] == "PASS"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "Portable application" in text
    assert "Primary Executable" in text
    assert str(tmp_path) not in text


def test_pe_printable_string_secret_review_redacts_value_and_records_offset(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    secret = "UltraSecretFixtureValue"
    exe = _minimal_pe(root / "Client.exe", b"prefix password=" + secret.encode() + b" suffix")
    result = run_secrets_review([root], tmp_path)
    report = (tmp_path / "secrets_review.txt").read_text(encoding="utf-8")
    assert result["pe_images_scanned"] == 1
    assert "PE printable-string matches" in report
    assert "PE file offset" in report
    assert "[REDACTED]" in report
    assert secret not in report
    assert any(m["location_type"] == "PE file offset" for m in result["matches"])
