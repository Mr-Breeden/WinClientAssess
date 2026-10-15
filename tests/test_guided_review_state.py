from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from utils.assessment_state import AssessmentState
from utils.assessment_integrity import create_manifest, regenerate_derived_reports, verify_assessment
from utils.assessment_layout import artifact_path
from utils.guided_review import (
    GUIDANCE, counts, filter_items, guided_review_cli, read_review,
    render_review_reports, save_decision, sync_review,
)
from utils.privacy import sanitize_report_text, sanitize_snapshot_for_disk
from utils.reporting import AssessmentReporter
from utils.sensitive_data import sanitize_procmon_csv


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / 'assess'
    installer = tmp_path / 'setup.msi'
    installer.write_bytes(b'example installer test fixture')
    AssessmentState.create(root, assessment_name='case', installer=installer, mode='full',
                           framework_version='1.5.0', options={}, tools={})
    # Two independent network surfaces and two independent named pipes.
    artifact_path(root, 'network_surface_review.txt').write_text('''
[POI-NW-001] server.exe - TCP 0.0.0.0:7777
Confidence : MEDIUM
Manual Validation: Confirm actual authentication.
[POI-NW-002] server.exe - TCP 127.0.0.1:7778
Confidence : MEDIUM
Manual Validation: Confirm actual authentication.
''', encoding='utf-8')
    artifact_path(root, 'ipc_review.txt').write_text(r'''
[POI-IP-001] server.exe -> \\.\pipe\One
Reason: Broad ACL.
[POI-IP-002] server.exe -> \\.\pipe\Two
Reason: Broad ACL.
''', encoding='utf-8')
    findings = [
        {'title':'Multiple listener candidates', 'source_module':'Network Surface Review',
         'severity':'Informational', 'evidence':'2 POI-NW records'},
        {'title':'Named pipe candidates', 'source_module':'IPC / Named Pipe Review',
         'severity':'Informational', 'evidence':'2 POI-IP records'},
        {'title':'Unsigned installer', 'source_module':'Digital Signature Review',
         'severity':'Informational', 'evidence':'NotSigned'},
    ]
    return root, installer, findings


def _completed(root, installer, findings):
    reporter = AssessmentReporter(root, 'case', installer, 'full', '1.5.0', state_tracker=AssessmentState.load(root))
    reporter.set_status('Installer Information','PASS')
    for f in findings:
        reporter.add_finding(**f)
    reporter.finalize()
    saved=AssessmentState.load(root)
    saved.mark_complete('COMPLETE')
    create_manifest(root, framework_version='1.5.0')
    assert verify_assessment(root)['status'] == 'PASS'


def test_distinct_poi_candidates_and_no_duplicate_aggregates(sample):
    root, _, findings = sample
    data = sync_review(root, findings)
    assert len(data['items']) == 5
    assert len({x['id'] for x in data['items'].values()}) == 5
    assert len([x for x in data['items'].values() if x['source_module'] == 'Network Surface Review']) == 2
    assert len([x for x in data['items'].values() if x['source_module'] == 'IPC / Named Pipe Review']) == 2
    assert len([x for x in data['items'].values() if x['source_module'] == 'Digital Signature Review']) == 1
    assert all(x['status'] == 'PENDING' for x in data['items'].values())


def test_review_saved_and_reopened_with_manifest(sample):
    root, installer, findings = sample
    _completed(root, installer, findings)
    before=read_review(root)
    first=next(x for x in before['items'].values() if x['source_module']=='Network Surface Review')
    # v1.5.3: the reviewer may record a validation disposition first and add
    # human verification notes later; the blank-note decision is visibly
    # flagged as undocumented in the derived reports.
    save_decision(root, first['id'], 'VALIDATED', '')
    assert read_review(root)['items'][first['id']]['notes'] == ''
    save_decision(root, first['id'], 'VALIDATED', 'Confirmed unauthorized access with read-only request', 'reports/network_surface_review.txt')
    # A state edit on its own must be detected until derived outputs/manifest refresh.
    assert verify_assessment(root)['status'] == 'FAIL'
    render = json.loads((root/'working/report_render_state.json').read_text(encoding='utf-8'))
    reporter = AssessmentReporter(root, 'case', installer, 'full', '1.5.0')
    reporter.findings=render['findings']; reporter.status=render['modules']
    reporter.finalize(persist_render_state=False,sanitize_primary=False)
    create_manifest(root, framework_version='1.5.0')
    assert verify_assessment(root)['status']=='PASS'
    assert counts(read_review(root))['VALIDATED']==1
    assert first['id'] in artifact_path(root, 'tester_review.txt').read_text()
    assert 'Validated by tester' in artifact_path(root, 'findings_summary.txt').read_text()
    assert len(filter_items(read_review(root)))==4
    assert read_review(root)['items'][first['id']]['evidence_reference']=='reports/network_surface_review.txt'


def test_unchanged_review_decisions_persist_but_changed_evidence_reopens(sample):
    root, _, findings=sample
    initial=sync_review(root, findings)
    original=next(x for x in initial['items'].values() if x['source_module']=='Network Surface Review')
    save_decision(root, original['id'], 'INFORMATIONAL','Intended endpoint','reports/network_surface_review.txt')
    after=sync_review(root, findings)
    assert after['items'][original['id']]['status']=='INFORMATIONAL'
    report=artifact_path(root,'network_surface_review.txt')
    report.write_text(report.read_text().replace('Confirm actual authentication.','Authentication unexpectedly disabled.'),encoding='utf-8')
    changed=sync_review(root, findings)
    assert changed['items'][original['id']]['status']=='PENDING'
    assert changed['items'][original['id']]['changed_evidence'] is True
    assert changed['items'][original['id']]['previous_status']=='INFORMATIONAL'
    unchanged=[x for x in changed['items'].values() if x['source_module']=='IPC / Named Pipe Review']
    assert all(x['changed_evidence'] is False for x in unchanged)


def test_report_repair_keeps_decision_state(sample):
    root,installer,findings=sample
    _completed(root,installer,findings)
    artifact_path(root,'tester_review.txt').write_text('changed by hand')
    assert verify_assessment(root)['repairable'] is True
    assert regenerate_derived_reports(root)['status']=='PASS'
    assert counts(read_review(root))['PENDING']==5
    original=(root/'working/tester_review_state.json').read_bytes()
    (root/'working/tester_review_state.json').write_text('tampered')
    artifact_path(root,'tester_review.txt').write_text('changed again')
    assert verify_assessment(root)['repairable'] is False
    with pytest.raises(ValueError):
        regenerate_derived_reports(root)
    (root/'working/tester_review_state.json').write_bytes(original)


def test_cli_save_and_next_pending(sample):
    root,installer,findings=sample
    _completed(root,installer,findings)
    inputs=iter(['p','i','Expected listener, authenticated','q'])
    output=[]
    guided_review_cli(root,input_fn=lambda _: next(inputs),output_fn=output.append)
    assert read_review(root) and counts(read_review(root))['INFORMATIONAL']==1
    assert verify_assessment(root)['status']=='PASS'
    assert 'Expected listener' in artifact_path(root,'tester_review.txt').read_text()


def test_review_cli_refuses_tampered_primary_evidence(sample):
    root,installer,findings=sample
    _completed(root,installer,findings)
    artifact_path(root,'network_surface_review.txt').write_text('corrupted')
    with pytest.raises(ValueError,match='verified assessment'):
        guided_review_cli(root,input_fn=lambda _: 'q')


def test_mode_specific_playbooks_and_artifacts(sample):
    root,installer,findings=sample
    _completed(root,installer,findings)
    guide=artifact_path(root,'evidence_guide.txt').read_text()
    assert 'Expected secure behavior:' in guide
    assert '10 / 10  WHEN NOT TO REPORT' in guide
    assert '0.0.0.0:7777' in guide
    assert '127.0.0.1:7778' in guide
    assert 'test_cases.txt' in artifact_path(root,'tester_review.txt').read_text()


def test_privacy_for_snapshots_and_procmon(tmp_path):
    env={'USERNAME':'TestPerson','USERPROFILE':r'C:\Users\TestPerson','COMPUTERNAME':'WIN-TESTPERSON'}
    with patch.dict(os.environ,env,clear=False):
        example=r'HKLM\SAM\SAM\DOMAINS\Account\Users\Names\TestPerson and L.TestPerson.cdp and Autorun for TestPerson and NT AUTHORITY\SYSTEM'
        sanitized=sanitize_report_text(example)
        assert 'TestPerson' not in sanitized
        assert 'CURRENT_HOST' == sanitize_report_text('WIN-TESTPERSON')
        assert 'NT AUTHORITY\\SYSTEM' in sanitized
        snapshot={'Filesystem':[{'Path':r'C:\Users\TestPerson\AppData\Local\ConnectedDevicesPlatform\L.TestPerson'}],
                  'ScheduledTasks':[{'TaskName':'Autorun for TestPerson', 'Principal':'NT AUTHORITY\\SYSTEM'}]}
        as_text=json.dumps(sanitize_snapshot_for_disk(snapshot))
        assert 'TestPerson' not in as_text
        assert 'SYSTEM' in as_text
        src=tmp_path/'source.csv';out=tmp_path/'dest.csv'
        src.write_text('Time,Process Name,Path,Detail\n1,lsass.exe,HKLM\\SAM\\Users\\Names\\TestPerson,Desired Access: Read\n',encoding='utf-8')
        sanitize_procmon_csv(src,out)
        assert 'TestPerson' not in out.read_text(encoding='utf-8-sig')
        assert 'CURRENT_USER' in out.read_text(encoding='utf-8-sig')


def test_privacy_encoded_paths_and_hostname_suffix():
    with patch.dict(os.environ, {'USERNAME':'TestPerson', 'USERPROFILE':r'C:\Users\TestPerson',
                                 'COMPUTERNAME':'WIN-TESTPERSON'}, clear=False):
        value = r'C%3A%5CUsers%5CTestPerson%5CDesktop and WIN-TESTPERSON.localdomain:1234'
        rendered = sanitize_report_text(value)
        assert 'TestPerson' not in rendered
        assert 'CURRENT_HOST.localdomain' in rendered
        assert '%5CCURRENT_USER%5CDesktop' in rendered

def test_candidate_id_ignores_pid_churn_but_preserves_distinct_endpoints(sample):
    root, _, findings = sample
    path = artifact_path(root, 'network_surface_review.txt')
    path.write_text(path.read_text().replace('server.exe - TCP 0.0.0.0:7777', 'server.exe (PID 101) - TCP 0.0.0.0:7777'))
    before=sync_review(root,findings)
    path.write_text(path.read_text().replace('(PID 101)','(PID 7777)'))
    after=sync_review(root,findings)
    assert set(before['items']) == set(after['items'])
    assert all(not x['changed_evidence'] for x in after['items'].values())

def test_aggregate_evidence_change_reopens_same_candidate(sample):
    root, _, findings=sample
    first=sync_review(root,findings)
    candidate=next(x for x in first['items'].values() if x['source_module']=='Digital Signature Review')
    save_decision(root,candidate['id'],'INFORMATIONAL','Unsigned allowed by customer policy')
    refreshed=[dict(x) for x in findings]
    refreshed[-1]['evidence']='Invalid chain signature'
    after=sync_review(root,refreshed)
    # The source module and issue title did not change; the evidence did.
    assert candidate['id'] in after['items']
    assert after['items'][candidate['id']]['status']=='PENDING'
    assert after['items'][candidate['id']]['changed_evidence']
