"""v2.1.0: execution-backed provenance, redaction, lifecycle and export safety."""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest

from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_layout import artifact_path
from utils.collection_provenance import (
    finalize, module_scope, record_executed, record_native_method,
    safe_command_shape, session,
)
from utils.command_runner import run_command
from utils.client_appendix import export_client_appendix
from tests.test_client_appendix_190 import _assessment


def _files(root):
    (root / 'reports').mkdir(parents=True, exist_ok=True)
    (root / 'working').mkdir(exist_ok=True)
    for filename in ['installer_extraction.txt', 'permissions_review.txt', 'services_review.txt',
                     'test_cases.txt', 'module_status.txt']:
        artifact_path(root, filename).write_text(f'WCA {filename}\n', encoding='utf-8')


def test_command_shapes_never_expose_secrets_paths_or_script_bodies():
    raw = r'C:\Users\Tester\Desktop\AcmeClient.msi'
    script = "Get-CimInstance Win32_Service; Write-Output 'password=A_SECRET_TOKEN'"
    cmd = safe_command_shape([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                              '-NoProfile', '-Command', script])
    assert 'Get-CimInstance' in cmd and 'SCRIPT_REDACTED' in cmd
    assert 'A_SECRET_TOKEN' not in cmd and 'password' not in cmd
    cmd = safe_command_shape(['7z.exe', 'x', '-y', '-o'+str(raw), str(raw), 'Bearer a-secret'])
    assert '-o<OUTPUT_DIR>' in cmd and '<ARG>' in cmd
    assert 'AcmeClient' not in cmd and 'a-secret' not in cmd and 'Tester' not in cmd
    cmd = safe_command_shape(['any.exe', '--password', 'supersecret', '--token=value', '--api-key'])
    assert 'supersecret' not in cmd and 'token=value' not in cmd
    assert 'api-key' not in cmd


def test_initial_capture_and_artifact_index(tmp_path):
    root = tmp_path / 'assessment'; _files(root)
    with session(root, 'full-assessment', retain=False):
        with module_scope('Installer Extraction'):
            res = run_command([sys.executable, '-c', "print('SECRET_SHOULD_NOT_PERSIST')"], timeout=15)
        assert res['returncode'] == 0
        record_native_method('Installer Extraction', 'run_installer_extract')
        finalize(root, {'Installer Extraction': {'status': 'PASS'},
                        'Services Review': {'status': 'SKIPPED'}})
    central = artifact_path(root, 'collection_provenance.txt').read_text(encoding='utf-8')
    install = artifact_path(root, 'installer_extraction.txt').read_text(encoding='utf-8')
    services = artifact_path(root, 'services_review.txt').read_text(encoding='utf-8')
    assert 'PROV-00001' in central and 'PROV-00001' in install
    assert 'PROV-00002' in central and 'PROV-00002' in install
    assert 'SECRET_SHOULD_NOT_PERSIST' not in central
    assert 'No external command' not in install
    assert 'Collection unavailable or skipped' in services
    assert 'collection_provenance.txt' in services
    state = json.loads((root / 'working' / 'collection_provenance_state.json').read_text())
    assert len(state['records']) == 2
    assert all('SECRET_SHOULD_NOT_PERSIST' not in str(r) for r in state['records'])


def test_guided_runtime_preserves_original_records_and_does_not_duplicate_headers(tmp_path):
    root = tmp_path / 'assessment'; _files(root)
    with session(root, 'initial', retain=False):
        record_native_method('Services Review', 'run_services_review')
        finalize(root, {'Services Review': {'status': 'PASS'}})
    with session(root, 'guided-runtime'):
        record_native_method('Guided Runtime Observation', 'run_guided_collectors')
        finalize(root, {'Services Review': {'status': 'PASS'}})
    service = artifact_path(root, 'services_review.txt')
    before = service.read_bytes()
    finalize(root, {'Services Review': {'status': 'PASS'}})
    assert service.read_bytes() == before
    report = artifact_path(root, 'collection_provenance.txt').read_text()
    assert '[PROV-00001]' in report and '[PROV-00002]' in report
    assert report.index('[PROV-00001]') < report.index('[PROV-00002]')
    assert service.read_text().count('\nCOLLECTION PROVENANCE\n') == 1


def test_exception_during_runtime_does_not_commit_provenance(tmp_path):
    root = tmp_path / 'assessment'; _files(root)
    with session(root, 'full', retain=False):
        record_native_method('Services Review', 'run_services_review')
        finalize(root)
    state = root / 'working' / 'collection_provenance_state.json'
    original = state.read_bytes()
    with pytest.raises(RuntimeError, match='controlled failure'):
        with session(root, 'guided-runtime'):
            record_executed(['powershell.exe','-Command','Get-CimInstance', 'PASS_A_SECRET'], 0)
            raise RuntimeError('controlled failure')
    assert state.read_bytes() == original


def test_provenance_manifest_detects_tamper(tmp_path):
    root = _assessment(tmp_path)
    # This is an older-version compatibility fixture. Only explicit new sessions
    # gain the new provenance contract; no backfill of hypothetical commands.
    with session(root, 'new-assessment', retain=False):
        record_native_method('Services Review', 'run_services_review')
        finalize(root, {'Services Review': {'status': 'PASS'}})
    create_manifest(root, framework_version='1.8.6')
    assert verify_assessment(root)['status'] == 'PASS'
    (root / 'working' / 'collection_provenance_state.json').write_text('{"tampered":true}')
    assert verify_assessment(root)['status'] == 'FAIL'


def test_client_appendix_copies_sanitized_provenance_but_not_working_state(tmp_path):
    root = _assessment(tmp_path)
    with session(root, 'static', retain=False):
        with module_scope('Services Review'):
            record_executed(['powershell.exe', '-Command', 'Get-CimInstance Win32_Service;'
                             "Write-Output 'API_KEY=DO_NOT_COPY'"], 0)
        finalize(root, {'Services Review': {'status': 'PASS'}})
    create_manifest(root, framework_version='1.8.6')
    output = export_client_appendix(root, tmp_path / 'app.zip')
    with zipfile.ZipFile(output) as z:
        names = z.namelist()
        assert 'evidence/collection_provenance.txt' in names
        data = z.read('evidence/collection_provenance.txt').decode('utf-8')
        assert 'PROV-00001' in data and 'Get-CimInstance' in data
        assert 'DO_NOT_COPY' not in data
        assert not any('working/' in name for name in names)
    assert verify_assessment(root)['status'] == 'PASS'


def test_report_regeneration_does_not_invent_commands(tmp_path):
    root = tmp_path / 'case'; _files(root)
    with session(root, 'initial', retain=False):
        record_native_method('Services Review', 'run_services_review')
        finalize(root)
    original = (root / 'working' / 'collection_provenance_state.json').read_bytes()
    first = artifact_path(root, 'collection_provenance.txt').read_bytes()
    finalize(root)  # same operation as review-only report regeneration
    assert (root / 'working' / 'collection_provenance_state.json').read_bytes() == original
    assert artifact_path(root, 'collection_provenance.txt').read_bytes() == first


def test_framework_version_and_catalog_are_current():
    import wca
    from utils.gui_server import make_server
    assert wca.VERSION == '2.1.0'
    assert wca.ARTIFACT_CATALOG_VERSION == '2.0'
    assert '2.1.0' in Path('scripts/validate_windows.ps1').read_text()
    assert 'collection_provenance.txt' in Path('utils/artifacts.py').read_text()


def test_evidence_only_inline_sections_and_live_recheck(tmp_path):
    root = tmp_path / 'provenance-layout'; _files(root)
    for name in ('binary_security_review.txt', 'network_surface_review.txt',
                 'findings.txt', 'coverage_summary.txt', 'tester_review.txt',
                 'findings_summary.txt', 'procmon_capture_instructions.txt'):
        artifact_path(root, name).write_text(f'WCA - {name}\n' + '='*40 + '\n\nBODY KEEP\n', encoding='utf-8')
    with session(root, 'full', retain=False):
        with module_scope('Services Review'):
            record_executed(['powershell.exe', '-NoProfile', '-Command',
                             'Get-CimInstance Win32_Service; Write-Output A_SECRET'], 0)
        with module_scope('Procmon Runtime Capture'):
            record_executed(['procmon.exe', '-terminate', '-quiet'], 1)
        finalize(root)
    service = artifact_path(root, 'services_review.txt').read_text()
    assert 'WCA services_review.txt\n' in service.split('COLLECTION PROVENANCE')[0]
    assert 'LIVE RECHECK' in service and '<SERVICE_NAME>' in service
    assert 'NOT the recorded WCA invocation' in service
    assert service.count('COLLECTION PROVENANCE') == 2  # begin/end marker
    for name in ('findings.txt', 'coverage_summary.txt', 'tester_review.txt',
                 'findings_summary.txt', 'test_cases.txt', 'module_status.txt',
                 'procmon_capture_instructions.txt'):
        assert 'COLLECTION PROVENANCE' not in artifact_path(root, name).read_text()
    assert 'LIVE RECHECK' in artifact_path(root, 'binary_security_review.txt').read_text()
    assert 'LIVE RECHECK' in artifact_path(root, 'network_surface_review.txt').read_text()
    central = artifact_path(root, 'collection_provenance.txt').read_text()
    assert central.index('AT A GLANCE') < central.index('COLLECTION ISSUES') < central.index('EXECUTION AUDIT')
    assert 'PROV-00002 | FAILED' in central
    assert 'A_SECRET' not in central
    assert '<SERVICE_NAME>' in central
    baseline = {p.name: p.read_bytes() for p in (root / 'reports').glob('*.txt')}
    finalize(root)
    assert baseline == {p.name: p.read_bytes() for p in (root / 'reports').glob('*.txt')}


def test_legacy_tail_migrates_without_erasing_report_body(tmp_path):
    from utils.collection_provenance import _clean_old_header
    original = ('WINDOWS CLIENT ASSESSMENT - SERVICES REVIEW\n' + '='*60 +
                '\n\nPurpose:\n  Original evidence data\n')
    legacy = (original + '\nCOLLECTION PROVENANCE\n' + '-'*72 +
              '\nTools: powershell.exe\nMethod: PROV-00001\n'
              'Details: collection_provenance.txt\n')
    assert _clean_old_header(legacy).rstrip() == original.rstrip()
