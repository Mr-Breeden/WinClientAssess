"""v2.2.1 manual testing remains independent, persistent, private and integrity-safe."""
from __future__ import annotations
import json
from pathlib import Path

import pytest

from utils.assessment_state import AssessmentState
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.manual_test_workflow import read_manual_workflow, read_manual_detail, save_manual_decision, REVIEW_FILE


def fixture(tmp_path, version='2.2.1'):
    target = tmp_path / 'fixture.exe'; target.write_bytes(b'fixture')
    root = tmp_path / 'assessment'
    state = AssessmentState.create(root, assessment_name='Fixture', installer=target,
                                   mode='full', framework_version=version, options={}, tools={})
    state.mark_complete('COMPLETE_WITH_OPTIONAL_GAPS')
    cases = root/'reports'/'test_cases.txt'
    cases.write_text('WCA - TEST CASES\n' + '=' * 70 + '\n'
                     '[ ] TC-SV-001 - Privileged Service Path and ACL Review\n'
                     'Procedure:\n  Inspect service ACLs and effective access.\n'
                     '[ ] Completed    [ ] N/A\n'
                     '[ ] TC-DL-001 - Missing DLL Review\n'
                     'Procedure:\n  Observe DLL load order without execution.\n', encoding='utf-8')
    create_manifest(root, framework_version=version, methodology_version='1.9', catalog_version='2.0')
    assert verify_assessment(root)['status'] == 'PASS'
    return root


def test_manual_cases_start_unrecorded_and_are_not_guided_review(tmp_path):
    root = fixture(tmp_path)
    initial = read_manual_workflow(root)
    assert initial['total'] == 2 and initial['remaining'] == 2 and initial['resolved'] == 0
    assert [x['status'] for x in initial['items']] == ['NOT STARTED', 'NOT STARTED']
    assert not (root / REVIEW_FILE).exists()


def test_manual_save_preserves_report_source_and_manifest_integrity(tmp_path):
    root = fixture(tmp_path)
    before = (root/'reports/test_cases.txt').read_bytes()
    case = read_manual_workflow(root)['items'][0]
    result = save_manual_decision(root, case_id=case['id'], fingerprint=case['fingerprint'],
                                  status='COMPLETED', notes='Validation performed',
                                  evidence_reference='service_acl_evidence_1.png')
    assert result['resolved'] == 1 and result['remaining'] == 1
    assert (root/'reports/test_cases.txt').read_bytes() == before
    assert not (root/'working/tester_review_state.json').exists()
    assert verify_assessment(root)['status'] == 'PASS'
    manifest = json.loads((root/'working/assessment_manifest.json').read_text())
    assert REVIEW_FILE.as_posix() in manifest['files']['supporting']
    assert 'notes' not in read_manual_workflow(root)['items'][0]
    saved = read_manual_detail(root, case['id'])
    assert saved['notes'] == 'Validation performed'
    assert saved['evidence_reference'] == 'service_acl_evidence_1.png'


def test_reject_unverified_modified_assessment(tmp_path):
    root = fixture(tmp_path)
    case = read_manual_workflow(root)['items'][0]
    (root/'reports/test_cases.txt').write_text('changed')
    with pytest.raises(ValueError, match='integrity'):
        save_manual_decision(root, case_id=case['id'], fingerprint=case['fingerprint'], status='COMPLETED')
    assert not (root/REVIEW_FILE).exists()


def test_old_version_is_read_only(tmp_path):
    root = fixture(tmp_path, version='2.1.0')
    case = read_manual_workflow(root)['items'][0]
    with pytest.raises(ValueError, match='current-release'):
        save_manual_decision(root, case_id=case['id'], fingerprint=case['fingerprint'], status='COMPLETED')
    assert verify_assessment(root)['status'] == 'PASS'


def test_case_fingerprint_must_match_and_status_is_validated(tmp_path):
    root = fixture(tmp_path)
    case = read_manual_workflow(root)['items'][0]
    with pytest.raises(ValueError, match='changed'):
        save_manual_decision(root, case_id=case['id'], fingerprint='wrong', status='COMPLETED')
    with pytest.raises(ValueError, match='Unsupported'):
        save_manual_decision(root, case_id=case['id'], fingerprint=case['fingerprint'], status='VALIDATED')
    assert verify_assessment(root)['status'] == 'PASS'


def test_failed_post_write_manifest_is_rolled_back(tmp_path, monkeypatch):
    import utils.manual_test_workflow as workflow
    root = fixture(tmp_path)
    before = {name:(root/name).read_bytes() for name in ('working/assessment_manifest.json', 'reports/artifact_manifest.txt')}
    case = read_manual_workflow(root)['items'][0]
    def fail(*a, **kw):
        raise OSError('simulated manifest write failure')
    monkeypatch.setattr(workflow, 'create_manifest', fail)
    with pytest.raises(ValueError, match='restored'):
        save_manual_decision(root, case_id=case['id'], fingerprint=case['fingerprint'], status='COMPLETED')
    assert not (root/REVIEW_FILE).exists()
    assert all((root/name).read_bytes()==value for name,value in before.items())
    assert verify_assessment(root)['status'] == 'PASS'


def test_gui_offers_manual_workflow_without_mutating_evidence():
    from utils import gui_server
    root = Path(gui_server.__file__).parents[1]
    html = (root/'gui/index.html').read_text('utf-8')
    script = (root/'gui/app.js').read_text('utf-8')
    assert 'data-tab="workspace"' in html and 'id="workspace-pane-manual"' in html
    assert 'id="manualStatus"' in html and 'id="manualNotes"' in html
    assert "'/api/manual-tests'" in script and "'/api/manual-tests'" in Path(gui_server.__file__).read_text('utf-8')
    assert 'Collection coverage and Guided Review are separate' in html


def test_manual_http_requires_auth_and_explicit_save(tmp_path):
    import threading
    from urllib.parse import urlencode
    from utils.gui_catalog import RecentAssessments
    from utils.gui_server import JobManager, make_server
    from tests.test_gui_200 import http_request, gui_headers
    root = fixture(tmp_path)
    jobs = JobManager(catalog=RecentAssessments(tmp_path/'private-list.json'))
    server = make_server(port=0, version='2.2.1', jobs=jobs, token='known-test-token')
    thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
    try:
        url = '/api/manual-tests?' + urlencode({'assessment': str(root)})
        assert http_request(server,'GET',url)[0] == 403
        status, _, content = http_request(server,'GET',url,headers=gui_headers(server))
        listing = json.loads(content)['data']
        assert status == 200 and listing['total'] == 2
        assert all('notes' not in item for item in listing['items'])
        case = listing['items'][0]
        detail_url='/api/manual-test?'+urlencode({'assessment':str(root),'case_id':case['id']})
        assert http_request(server,'GET',detail_url)[0] == 403
        assert http_request(server,'GET',detail_url,headers=gui_headers(server))[0] == 200
        body={'assessment':str(root),'case_id':case['id'], 'fingerprint':case['fingerprint'],
              'status':'COMPLETED','notes':'Tester private notes','confirmed':True}
        assert http_request(server,'POST','/api/manual-tests',body=body)[0] == 403
        assert http_request(server,'POST','/api/manual-tests',headers=gui_headers(server),body={**body,'confirmed':False})[0] == 400
        status, _, response = http_request(server,'POST','/api/manual-tests',headers=gui_headers(server),body=body)
        assert status == 200, response
        assert json.loads(response)['data']['resolved'] == 1
        assert 'Tester private notes' not in response.decode()
        status, _, details = http_request(server,'GET',detail_url,headers=gui_headers(server))
        assert status == 200 and json.loads(details)['data']['notes'] == 'Tester private notes'
        assert verify_assessment(root)['status'] == 'PASS'
    finally:
        server.shutdown();server.server_close();thread.join(5);jobs.close()
