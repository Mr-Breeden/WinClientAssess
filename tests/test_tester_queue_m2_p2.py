"""M2-p2: one queue, explicit coverage, read-only exports, picker threading."""
from __future__ import annotations
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_tester_workflow_220 import fixture
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.manual_test_workflow import read_manual_workflow, read_manual_detail, save_manual_decision, testing_queue as activity_queue
from utils.client_appendix import _appendix_html


def _candidate_fixture(tmp_path, status='PENDING'):
    root = fixture(tmp_path)
    (root/'working/tester_review_state.json').write_text(json.dumps({
        'schema_version':1, 'items':{
            'WCR-DLL': {'id':'WCR-DLL','title':'Observed missing DLL',
                        'status':status, 'test_cases':['TC-DL-001'],
                        'notes':'SECRET-INTERNAL-REVIEW'},
            'WCR-NOCASE':{'id':'WCR-NOCASE','title':'Separate runtime condition',
                          'status':'PENDING', 'test_cases':[],
                          'notes':'SECRET-UNLINKED-REVIEW'}}}),encoding='utf-8')
    create_manifest(root, framework_version='2.2.1', methodology_version='1.9',catalog_version='2.0')
    return root


def test_queue_deduplicates_linked_candidates_and_keeps_unlinked(tmp_path):
    root=_candidate_fixture(tmp_path)
    queue=activity_queue(root)
    assert queue['total']==3  # two manual cases, one unlinked candidate
    assert len([x for x in queue['items'] if x['id']=='TC-DL-001'])==1
    assert len([x for x in queue['items'] if x['id']=='WCR-NOCASE'])==1
    assert all(x['id']!='WCR-DLL' for x in queue['items'])
    assert queue['remaining']==3
    assert 'SECRET' not in str(queue)
    assert read_manual_workflow(root)['testing_queue']['remaining']==3
    assert verify_assessment(root)['status']=='PASS'


def test_guided_coverage_requires_explicit_tester_confirmation(tmp_path):
    root=_candidate_fixture(tmp_path)
    case=read_manual_detail(root,'TC-DL-001')
    with pytest.raises(ValueError,match='dispositioned'):
        save_manual_decision(root,case_id=case['id'],fingerprint=case['fingerprint'],
                             status='ADDRESSED IN GUIDED REVIEW')
    assert verify_assessment(root)['status']=='PASS'
    review_path=root/'working/tester_review_state.json'
    doc=json.loads(review_path.read_text());doc['items']['WCR-DLL']['status']='VALIDATED'
    review_path.write_text(json.dumps(doc),encoding='utf-8')
    create_manifest(root,framework_version='2.2.1',methodology_version='1.9',catalog_version='2.0')
    # A Guided Review disposition alone never marks the manual case addressed.
    assert read_manual_detail(root,'TC-DL-001')['status']=='NOT STARTED'
    save_manual_decision(root,case_id=case['id'],fingerprint=case['fingerprint'],
                         status='ADDRESSED IN GUIDED REVIEW',
                         notes='SECRET-INTERNAL-MANUAL',client_notes='Approved testing context')
    current=read_manual_detail(root,'TC-DL-001')
    assert current['status']=='ADDRESSED IN GUIDED REVIEW'
    assert current['client_notes']=='Approved testing context'
    assert activity_queue(root)['remaining']==2
    assert 'SECRET-INTERNAL-MANUAL' not in str(read_manual_workflow(root))
    assert verify_assessment(root)['status']=='PASS'
    # A later candidate refresh or pending revalidation must reopen the activity.
    doc=json.loads(review_path.read_text());doc['items']['WCR-DLL']['status']='PENDING'
    review_path.write_text(json.dumps(doc),encoding='utf-8')
    create_manifest(root,framework_version='2.2.1',methodology_version='1.9',catalog_version='2.0')
    assert read_manual_detail(root,'TC-DL-001')['status']=='NOT STARTED'
    assert activity_queue(root)['remaining']==3


def test_client_note_html_is_explicit_escaped_and_private_notes_excluded():
    items=[{'id':'WCR-A', 'title':'Review observation','status':'VALIDATED',
            'source_module':'Runtime','artifacts':[],'notes':'PRIVATE-NEVER-EXPORT',
            'client_notes':'Approved <b>review</b> & context'}]
    manual=[{'id':'TC-NW-001','title':'Network test','status':'COMPLETED',
             'notes':'PRIVATE-MANUAL', 'evidence_reference':'CONFIDENTIAL-PATH',
             'client_notes':'Network service checked.'}]
    html=_appendix_html({'assessment_name':'Fixture','framework_version':'2.2.1'},
                        items,['coverage_summary.txt'],{},manual_notes=manual)
    assert 'Approved &lt;b&gt;review&lt;/b&gt; &amp; context' in html
    assert 'Network service checked.' in html
    assert 'Tester-approved assessment notes' in html
    assert 'PRIVATE-' not in html and 'CONFIDENTIAL-PATH' not in html
    no_notes=_appendix_html({'assessment_name':'Fixture'},[],[],{},manual_notes=[])
    assert 'Tester-approved assessment notes' not in no_notes


def test_windows_picker_requests_separate_main_thread_process(monkeypatch):
    import utils.native_picker as picker
    monkeypatch.setattr(picker,'os',SimpleNamespace(name='nt'))
    calls=[]
    def fake_run(argv,**kw):
        calls.append((argv,kw))
        return SimpleNamespace(returncode=0,stdout='{"path":"C:\\\\target.msi"}')
    monkeypatch.setattr(picker.subprocess,'run',fake_run)
    assert picker.pick_native_path('file') == 'C:\\target.msi'
    assert calls[0][0][1:]==['-m','utils.native_picker','file']
    assert calls[0][1]['timeout']>=30
    assert picker.pick_native_path('folder') == 'C:\\target.msi'
    monkeypatch.setattr(picker.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=0,stdout='{"path":""}'))
    assert picker.pick_native_path('file')==''  # user cancellation is not an error
    monkeypatch.setattr(picker.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=1,stdout=''))
    with pytest.raises(ValueError,match='could not open'):
        picker.pick_native_path('file')


def test_queue_ui_is_single_default_testing_interface():
    root=Path(__file__).resolve().parents[1]
    html=(root/'gui/index.html').read_text(encoding='utf-8')
    js=(root/'gui/app.js').read_text(encoding='utf-8')
    assert 'data-workspace-pane="queue"' in html
    assert 'id="queueItems"' in html
    assert 'id="queueFilter"' in html
    assert 'manualLinkedReview' in js and 'loadInlineCandidate(candidate,card,detailArea)' in js
    assert 'id="manualClientNotes"' in html and 'id="reviewClientNotes"' in html
    assert '<input id="manualEvidence" type="hidden">' in html
    assert 'async function openQueueActivity' in js
    assert 'state.jobStarting=true' in js


def test_client_note_preview_contains_only_explicit_note(tmp_path):
    from utils.client_appendix import client_note_preview
    root=fixture(tmp_path)
    case=read_manual_detail(root,'TC-DL-001')
    save_manual_decision(root,case_id=case['id'],fingerprint=case['fingerprint'],
                         status='COMPLETED',notes='PRIVATE-INTERNAL-ONLY',
                         evidence_reference='PRIVATE-FILE-PATH', client_notes='Safe client context')
    notes=client_note_preview(root)
    assert notes == [{'id':'TC-DL-001','title':case['title'],'notes':'Safe client context'}]
    assert 'PRIVATE' not in json.dumps(notes)


def test_note_preview_api_requires_session_auth(tmp_path):
    from utils.gui_server import make_server, JobManager
    from utils.gui_catalog import RecentAssessments
    from tests.test_gui_200 import gui_headers, http_request
    from urllib.parse import urlencode
    import threading
    root=fixture(tmp_path)
    case=read_manual_detail(root,'TC-SV-001')
    save_manual_decision(root,case_id=case['id'],fingerprint=case['fingerprint'],
                         status='COMPLETED', notes='Internal private', client_notes='Approved scope note')
    jobs=JobManager(catalog=RecentAssessments(tmp_path/'catalog.json'))
    server=make_server(port=0,version='2.2.1',jobs=jobs,token='test-session')
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        route='/api/client-notes?'+urlencode({'assessment':str(root)})
        assert http_request(server,'GET',route)[0]==403
        status,_,data=http_request(server,'GET',route,headers=gui_headers(server, token='test-session'))
        assert status==200
        assert json.loads(data)['notes'][0]['notes']=='Approved scope note'
        assert b'Internal private' not in data
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5);jobs.close()
