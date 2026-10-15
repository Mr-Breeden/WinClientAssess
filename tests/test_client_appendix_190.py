"""Offline client-appendix release safety and portability regression tests."""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

import pytest

from utils.assessment_state import AssessmentState, _atomic_json
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.client_appendix import (
    APPROVED_REPORTS, ClientAppendixError, export_client_appendix, export_readiness,
)


def _assessment(tmp_path: Path, *, pending=False, mode='full'):
    root = tmp_path / 'assess'
    root.mkdir()
    installer = tmp_path / 'client.exe'
    installer.write_bytes(b'fixture')
    state = AssessmentState.create(root, assessment_name='Synthetic Client', installer=installer,
                                  mode=mode, framework_version='1.8.6', options={}, tools={},
                                  target_type='portable', target_source=installer)
    for stage in ('static_analysis', 'reporting', 'pre_install_snapshot', 'post_install_snapshot', 'installed_state_analysis'):
        state.checkpoint(stage, 'COMPLETED')
    state.mark_complete('COMPLETE_WITH_OPTIONAL_GAPS')
    for name in APPROVED_REPORTS[:3]:
        (root / 'reports' / name).write_text(f'Allowed summary {name}\n', encoding='utf-8')
    (root / 'reports' / 'secrets_review.txt').write_text('SECRET_DO_NOT_EXPORT', encoding='utf-8')
    (root / 'working' / 'snapshot_pre.json').write_text('{"private":"RAW_DO_NOT_EXPORT"}')
    reviewer = {'schema_version': 1, 'items': {
        'w1': {'id':'WCR-1', 'status':'PENDING' if pending else 'VALIDATED',
               'title':'SQL / query composition', 'source_module':'.NET Detection / Source Review',
               'notes':'TESTER_PRIVATE_NOTE', 'changed_evidence':False},
        'w2': {'id':'WCR-2', 'status':'NOT APPLICABLE', 'title':'SHOULD_NOT_EXPORT_NA',
               'source_module':'Local Storage Review', 'notes':'PRIVATE_NA', 'changed_evidence':False},
        'w3': {'id':'WCR-3', 'status':'INFORMATIONAL', 'title':'IPC review',
               'source_module':'IPC / Named Pipe Review', 'notes':'PRIVATE_INFO', 'changed_evidence':False},
    }}
    _atomic_json(root / 'working' / 'tester_review_state.json', reviewer)
    create_manifest(root, framework_version='1.8.6', methodology_version='1.8', catalog_version='1.8')
    assert verify_assessment(root)['status'] == 'PASS'
    return root


def test_client_appendix_copy_only_portable_and_sanitized(tmp_path):
    root = _assessment(tmp_path)
    manifest_before = (root / 'working' / 'assessment_manifest.json').read_bytes()
    source_files_before = {p.relative_to(root): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in root.rglob('*') if p.is_file()}
    out = export_client_appendix(root, tmp_path / 'client-copy.zip')
    with zipfile.ZipFile(out) as z:
        assert z.testzip() is None
        names = set(z.namelist())
        assert names == {'assessment_report.html', 'README.txt', 'SHA256SUMS.txt'} | {
            f'evidence/{n}' for n in APPROVED_REPORTS[:3]
        }
        doc = z.read('assessment_report.html').decode()
        assert 'SQL / query composition' in doc and 'IPC review' in doc
        assert 'SHOULD_NOT_EXPORT_NA' not in doc
        for marker in ['TESTER_PRIVATE_NOTE', 'PRIVATE_NA', 'PRIVATE_INFO', 'SECRET_DO_NOT_EXPORT',
                       'RAW_DO_NOT_EXPORT', 'working/', 'secrets_review.txt']:
            assert all(marker not in z.read(n).decode('utf-8') for n in names)
        matches = re.findall(r'href="(evidence/[^"]+)"', doc)
        assert set(matches) == set(n for n in names if n.startswith('evidence/'))
        checksums = z.read('SHA256SUMS.txt').decode().splitlines()
        for row in checksums:
            digest, filename = row.split('  ', 1)
            assert hashlib.sha256(z.read(filename)).hexdigest() == digest
    assert (root / 'working' / 'assessment_manifest.json').read_bytes() == manifest_before
    assert source_files_before == {p.relative_to(root): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in root.rglob('*') if p.is_file()}
    assert verify_assessment(root)['status'] == 'PASS'


def test_client_appendix_pending_blocks_export(tmp_path):
    root = _assessment(tmp_path, pending=True)
    with pytest.raises(ClientAppendixError, match='pending'):
        export_client_appendix(root, tmp_path / 'refused.zip')
    assert not (tmp_path / 'refused.zip').exists()


def test_client_appendix_tampered_source_blocks_export(tmp_path):
    root = _assessment(tmp_path)
    (root / 'reports' / 'application_profile.txt').write_text('Modified after signing\n')
    with pytest.raises(ClientAppendixError, match='integrity'):
        export_client_appendix(root, tmp_path / 'refused.zip')
    assert not (tmp_path / 'refused.zip').exists()


def test_client_appendix_changed_evidence_blocks_export(tmp_path):
    root = _assessment(tmp_path)
    p = root / 'working' / 'tester_review_state.json'
    data = json.loads(p.read_text()); data['items']['w1']['changed_evidence'] = True
    _atomic_json(p, data)
    create_manifest(root, framework_version='1.8.6', methodology_version='1.8', catalog_version='1.8')
    with pytest.raises(ClientAppendixError, match='revalidation'):
        export_client_appendix(root, tmp_path / 'refused.zip')


def test_client_appendix_output_inside_assessment_rejected(tmp_path):
    root = _assessment(tmp_path)
    with pytest.raises(ClientAppendixError, match='outside'):
        export_client_appendix(root, root / 'client.zip')


def test_client_appendix_critical_stage_gate(tmp_path):
    root = _assessment(tmp_path)
    path = root / 'working' / 'assessment_state.json'
    data = json.loads(path.read_text()); data['stages']['post_install_snapshot']['status'] = 'PENDING'
    _atomic_json(path, data)
    create_manifest(root, framework_version='1.8.6', methodology_version='1.8', catalog_version='1.8')
    with pytest.raises(ClientAppendixError, match='post_install_snapshot'):
        export_readiness(root)


def test_client_appendix_applies_second_pass_privacy_and_secret_redaction(tmp_path, monkeypatch):
    root = _assessment(tmp_path)
    monkeypatch.setenv('USERNAME', 'AssessmentUser')
    monkeypatch.setenv('USERPROFILE', r'C:\Users\AssessmentUser')
    profile = root / 'reports' / 'application_profile.txt'
    profile.write_text('Source: C:\\Users\\AssessmentUser\\Desktop\\Client.exe\n'
                       'API_KEY=SHOULD_NEVER_SHIP\nAuthorization: Bearer A_PRIVATE_TOKEN\n')
    create_manifest(root, framework_version='1.8.6', methodology_version='1.8', catalog_version='1.8')
    dest = export_client_appendix(root, tmp_path / 'private-test.zip')
    with zipfile.ZipFile(dest) as z:
        data = z.read('evidence/application_profile.txt').decode()
        assert 'AssessmentUser' not in data
        assert 'SHOULD_NEVER_SHIP' not in data and 'A_PRIVATE_TOKEN' not in data
        assert '%USERPROFILE%' in data and '<REDACTED>' in data
    assert 'SHOULD_NEVER_SHIP' in profile.read_text()  # copy only; source unchanged


def test_client_appendix_unrecorded_internal_file_fails_closed(tmp_path):
    root = _assessment(tmp_path)
    (root / 'working' / 'unrecorded.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ClientAppendixError, match='integrity'):
        export_client_appendix(root, tmp_path / 'refused.zip')
