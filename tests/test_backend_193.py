"""v1.9.3 backend/GUI-readiness response, state, privacy and concurrency contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_state import AssessmentState, _atomic_json
from utils.backend_service import BackendService, API_SCHEMA
from utils.client_appendix import APPROVED_REPORTS
from utils.operation_lock import AssessmentBusyError, assessment_operation, lock_path


def fixture_assessment(tmp_path, completed=True):
    root = tmp_path / 'assess'; root.mkdir()
    primary = tmp_path / 'target.exe'; primary.write_bytes(b'portable-fixture')
    state = AssessmentState.create(root, assessment_name='Fixture', installer=primary, mode='static',
                                   framework_version='1.9.2', target_type='portable', options={}, tools={})
    for stage in ('static_analysis', 'reporting'):
        state.checkpoint(stage, 'COMPLETED')
    if completed:
        state.mark_complete('COMPLETE')
    (root / 'reports' / APPROVED_REPORTS[0]).write_text('Safe fixture data\n')
    _atomic_json(root / 'working' / 'tester_review_state.json', {
        'schema_version': 1,
        'items': {'WCR-TEST': {'id': 'WCR-TEST', 'title': 'Manual validation required',
                              'source_module': 'Configuration Review', 'severity': 'Informational',
                              'status': 'VALIDATED', 'fingerprint': 'SHA-TEST',
                              'notes': 'INTERNAL_PRIVATE_TESTER_NOTE',
                              'artifacts': ['configuration_review.txt'], 'changed_evidence': False}}
    })
    create_manifest(root, framework_version='1.9.2', methodology_version='1.9', catalog_version='1.9')
    return root


def test_contract_capabilities_is_json_safe_and_no_gui():
    data = BackendService().execute('capabilities')
    assert list(data) == ['schema', 'ok', 'code', 'message', 'data', 'errors']
    assert data['schema'] == API_SCHEMA and data['ok']
    assert data['data']['interface']['gui'] is True
    assert data['data']['operations']['guided_runtime']['availability'] == 'cli_and_gui_worker'
    assert 'automatic_poc_execution' in json.dumps(data)
    assert 'WCA' in json.dumps(data)


def test_tool_readiness_hides_paths(monkeypatch):
    monkeypatch.setattr('utils.backend_service.detect_tools', lambda: {
        'Tool': {'found': True, 'path': r'C:\Users\SENSITIVE_TESTER\tool.exe', 'level': 'REQUIRED', 'usage': 'INTEGRATED'}})
    response = BackendService().execute('tool_readiness')
    assert response['data']['tools'][0]['found']
    assert 'SENSITIVE_TESTER' not in json.dumps(response)
    assert 'path' not in json.dumps(response)


def test_status_and_review_are_nonmutating_and_redacted(tmp_path):
    root = fixture_assessment(tmp_path)
    before = hashlib.sha256((root/'working'/'assessment_manifest.json').read_bytes()).hexdigest()
    service = BackendService()
    status = service.execute('status', root)
    assert status['ok'] and status['data']['integrity']['status'] == 'PASS'
    assert status['data']['recovery_action'] == 'NONE'
    assert 'export_appendix_with_confirmation' in status['data']['available_actions']
    assert status['data']['framework_version'] == '1.9.2'
    review = service.execute('review', root)
    assert review['ok'] and review['data']['pending'] == 0
    assert review['data']['items'][0]['fingerprint'] == 'SHA-TEST'
    assert 'INTERNAL_PRIVATE_TESTER_NOTE' not in json.dumps(review)
    assert hashlib.sha256((root/'working'/'assessment_manifest.json').read_bytes()).hexdigest() == before


def test_integrity_readonly_and_fail_closed(tmp_path):
    root = fixture_assessment(tmp_path)
    (root/'reports'/APPROVED_REPORTS[0]).write_text('modified')
    service = BackendService()
    assert service.execute('verify', root)['code'] == 'INTEGRITY_FAILED'
    assert service.execute('review', root)['code'] == 'INTEGRITY_FAILED'
    assert not service.execute('export_appendix', root, confirmed=True, output=tmp_path/'bad.zip')['ok']
    assert not (tmp_path/'bad.zip').exists()


def test_appendix_export_explicit_confirmation_and_source_unchanged(tmp_path):
    root = fixture_assessment(tmp_path)
    api = BackendService()
    before = {p.relative_to(root): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
    out = tmp_path/'client.zip'
    assert api.execute('export_appendix', root, output=out)['code'] == 'CONFIRMATION_REQUIRED'
    result = api.execute('export_appendix', root, confirmed=True, output=out)
    assert result['ok'], result
    assert out.is_file()
    assert verify_assessment(root)['status'] == 'PASS'
    after = {p.relative_to(root): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
    assert before == after
    assert not lock_path(root).exists()


def test_lock_blocks_concurrent_operations_and_cleans_on_error(tmp_path):
    root = tmp_path/'assess'; root.mkdir()
    with pytest.raises(ValueError):
        with assessment_operation(root, 'first'):
            assert lock_path(root).exists()
            with pytest.raises(AssessmentBusyError):
                with assessment_operation(root, 'second'):
                    pytest.fail('Should never enter concurrent writer')
            raise ValueError('test')
    assert not lock_path(root).exists()


def test_preexisting_lock_is_not_stolen(tmp_path):
    root = tmp_path/'assess'; root.mkdir()
    lock = lock_path(root); lock.write_text('stale-session')
    with pytest.raises(AssessmentBusyError):
        with assessment_operation(root, 'new'):
            pass
    assert lock.read_text() == 'stale-session'


def test_review_requires_fingerprint_and_confirmation(tmp_path):
    root = fixture_assessment(tmp_path)
    service = BackendService()
    args = {'candidate_id':'WCR-TEST', 'disposition':'INFORMATIONAL', 'fingerprint':'SHA-TEST'}
    assert service.execute('save_review', root, **args)['code'] == 'CONFIRMATION_REQUIRED'
    assert service.execute('save_review', root, confirmed=True, **{**args, 'fingerprint':'wrong'})['code'] == 'REVIEW_CHANGED'
    assert verify_assessment(root)['status'] == 'PASS'


def test_backend_cli_returns_pure_json_without_banner(tmp_path):
    import subprocess, sys
    proc = subprocess.run([sys.executable, 'wca.py', '--backend-action', 'capabilities'],
                          capture_output=True, text=True, check=True)
    result = json.loads(proc.stdout)
    assert result['ok'] and result['data']['interface']['gui'] is True
    assert '████' not in proc.stdout
    bad = subprocess.run([sys.executable, 'wca.py', '--backend-action', 'verify'],
                         capture_output=True, text=True)
    assert bad.returncode == 9
    assert json.loads(bad.stdout)['code'] == 'ASSESSMENT_REQUIRED'


def test_no_automatic_upgrade_or_conversion(tmp_path):
    root = fixture_assessment(tmp_path, completed=False)
    status = BackendService().execute('status', root)
    assert status['ok']
    assert status['data']['framework_version'] == '1.9.2'
    assert 'resume_assessment_cli_only' not in status['data'].get('available_actions', [])
    assert BackendService().execute('unsupported', root)['code'] == 'UNSUPPORTED_ACTION'


def test_programmatic_review_commit_preserves_integrity_and_notes_privacy(tmp_path):
    from tests.test_guided_review_navigation import assessment
    from utils.guided_review import read_review
    root = assessment(tmp_path, version='1.9.2')
    initial = BackendService().execute('review', root)
    assert initial['ok'] and initial['data']['pending'] == 2
    selected = initial['data']['items'][0]
    result = BackendService().execute('save_review', root, confirmed=True,
                                      candidate_id=selected['id'], fingerprint=selected['fingerprint'],
                                      disposition='INFORMATIONAL', notes='Private assessment notes')
    assert result['ok'], result
    assert result['data']['pending'] == 1
    assert verify_assessment(root)['status'] == 'PASS'
    assert read_review(root)['items'][selected['id']]['notes'] == 'Private assessment notes'
    assert 'Private assessment notes' not in json.dumps(BackendService().execute('review', root))
    assert not lock_path(root).exists()


def test_cli_tool_readiness_json_contract():
    import subprocess, sys
    proc = subprocess.run([sys.executable, 'wca.py', '--backend-action', 'tool_readiness'],
                          capture_output=True, text=True, check=True)
    data = json.loads(proc.stdout)
    assert data['ok'] and 'tools' in data['data']
    assert 'path' not in json.dumps(data['data'])
