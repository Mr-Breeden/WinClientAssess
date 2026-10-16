"""v1.9.5: portable Windows-test corrections and optional readable backend presentation."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from utils.backend_format import render_backend_text
from utils.backend_service import envelope, capabilities


def run_cli(*args):
    # Windows can inherit an OEM/ANSI output codepage (for example cp1252).
    # Force the *child* interpreter to emit UTF-8 before decoding captured text
    # as UTF-8. Changing only the parent's decode setting is insufficient.
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    return subprocess.run([sys.executable, 'wca.py', *args],
                          text=True, encoding='utf-8', capture_output=True,
                          check=False, env=env)


def test_backend_defaults_to_unchanged_json_contract():
    proc = run_cli('--backend-action', 'capabilities')
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data['schema'] == '1.0' and data['ok'] is True
    assert data['data']['version'] == '2.2.0'
    assert proc.stdout.strip().startswith('{')


def test_backend_explicit_json_same_as_default():
    default = run_cli('--backend-action', 'capabilities')
    explicit = run_cli('--backend-action', 'capabilities', '--backend-format', 'json')
    assert default.returncode == explicit.returncode == 0
    assert json.loads(default.stdout) == json.loads(explicit.stdout)


def test_readable_backend_capabilities_show_no_gui():
    proc = run_cli('--backend-action', 'capabilities', '--backend-format', 'text')
    assert proc.returncode == 0, proc.stderr
    assert 'WCA 2.2.0' in proc.stdout
    assert 'installable, portable' in proc.stdout
    assert 'GUI' in proc.stdout and 'Available' in proc.stdout
    assert 'JSON' not in proc.stdout


def test_readable_tool_readiness_has_table_without_tool_paths():
    proc = run_cli('--backend-action', 'tool_readiness', '--backend-format', 'text')
    assert proc.returncode == 0, proc.stderr
    assert 'Tool' in proc.stdout and 'Detected' in proc.stdout
    assert 'Python' in proc.stdout and 'PowerShell' in proc.stdout
    assert 'C:\\Users\\' not in proc.stdout


def test_readable_backend_requires_action():
    proc = run_cli('--backend-format', 'text')
    assert proc.returncode != 0
    assert '--backend-format requires --backend-action' in proc.stderr


def test_readable_status_is_bounded_and_contains_stages():
    response = envelope(True, 'OK', 'Assessment available.', {
        'name': 'A sample', 'mode': 'full', 'target_type': 'portable',
        'status': 'COMPLETED', 'coverage': 'COMPLETE', 'framework_version': '1.9.4',
        'integrity': {'status': 'PASS'}, 'stages': {'static_analysis': 'COMPLETED', 'reporting': 'COMPLETED'},
        'available_actions': ['verify', 'review']})
    output = render_backend_text('status', response)
    for term in ['A sample', 'portable', 'COMPLETE', 'PASS', 'static_analysis', 'COMPLETED']:
        assert term in output
    assert max(map(len, output.splitlines())) <= 118


def test_readable_review_includes_grouped_observations_not_private_fields():
    response = envelope(True, 'OK', 'Queue available.', {
        'total': 1, 'pending': 0, 'by_disposition': {'VALIDATED': 1, 'PENDING': 0},
        'items': [{'title': 'Potential local storage exposure ' * 4,
                   'module': 'Local Storage Review', 'status': 'VALIDATED',
                   'severity': 'Informational', 'fingerprint': 'PRIVATE-FINGERPRINT',
                   'notes': 'PRIVATE-NOTE', 'artifacts': ['local_storage_review.txt']}]})
    output = render_backend_text('review', response)
    assert 'Local Storage Review' in output
    assert 'VALIDATED' in output
    assert 'PRIVATE-NOTE' not in output and 'PRIVATE-FINGERPRINT' not in output
    assert max(map(len, output.splitlines())) <= 118


def test_readable_verification_and_appendix_ready():
    result = envelope(True, 'OK', 'Verification available.', {
        'status': 'PASS', 'repairable': False, 'checks': [
            {'name': 'Report artifact integrity', 'status': 'PASS', 'issue_count': 0,
             'details': '69 recorded files'}], 'damaged_counts': {'reports': 0}})
    assert '69 recorded files' in render_backend_text('verify', result)
    result = envelope(True, 'OK', 'Appendix available.', {
        'integrity': 'COMPLETED', 'ready': True, 'reviewed_items': 12})
    assert 'Ready to export       Yes' in render_backend_text('appendix_readiness', result)


def test_readable_failed_backend_does_not_echo_internal_errors():
    result = envelope(False, 'INTEGRITY_FAILED', 'Assessment integrity failed.',
                      errors=[{'secret': 'PRIVATE-REPORT-PATH'}])
    output = render_backend_text('verify', result)
    assert 'FAILED (INTEGRITY_FAILED)' in output
    assert 'PRIVATE-REPORT-PATH' not in output


def test_local_tool_paths_configuration_is_allowed_but_never_released(monkeypatch, tmp_path):
    import importlib.util
    source = Path('scripts/package_release.py').resolve()
    spec = importlib.util.spec_from_file_location('wca_195_packager', source)
    packager = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(packager)
    for name in packager.TOP_LEVEL_FILES:
        (tmp_path / name).write_text('fixture', encoding='utf-8')
    for dirname in packager.TOP_LEVEL_DIRS:
        (tmp_path / dirname).mkdir()
    for name in packager.BRAND_ASSETS:
        (tmp_path / 'assets' / name).write_bytes(bytes.fromhex('89504e470d0a1a0a'))
    for name in packager.CANONICAL_DOCS:
        (tmp_path / 'docs' / name).write_text('fixture', encoding='utf-8')
    (tmp_path / 'scripts' / 'poc').mkdir()
    (tmp_path / 'scripts' / 'package_release.py').write_text('fixture', encoding='utf-8')
    (tmp_path / 'scripts' / 'validate_windows.ps1').write_text('fixture', encoding='utf-8')
    (tmp_path / 'tool_paths.json').write_text('{"custom_tool_path":"PRIVATE"}', encoding='utf-8')
    monkeypatch.setattr(packager, 'ROOT', tmp_path)
    assert packager.audit_tree() == []
    packaged = {p.relative_to(tmp_path).as_posix() for p in packager.iter_release_files()}
    assert 'tool_paths.json' not in packaged
    assert 'tool_paths.example.json' in packaged
    (tmp_path / 'scratch.txt').write_text('unexpected', encoding='utf-8')
    assert any('scratch.txt' in issue for issue in packager.audit_tree())


def test_windows_validation_checks_backend_text_and_exit_code():
    script = Path('scripts/validate_windows.ps1').read_text(encoding='utf-8')
    assert '$LASTEXITCODE' in script
    assert "'--backend-format','text'" in script
    assert "WCA 2.2.0 version string not detected" in script


def test_subprocess_text_ignores_inherited_legacy_codepage(monkeypatch):
    """Reproduce a Windows-style legacy codepage and protect UTF-8 capture."""
    monkeypatch.setenv('PYTHONIOENCODING', 'cp1252')
    proc = run_cli('--backend-action', 'capabilities', '--backend-format', 'text')
    assert proc.returncode == 0, proc.stderr
    assert isinstance(proc.stdout, str)
    assert 'WCA backend — Capabilities' in proc.stdout
    assert 'WCA 2.2.0' in proc.stdout
    assert 'GUI' in proc.stdout
