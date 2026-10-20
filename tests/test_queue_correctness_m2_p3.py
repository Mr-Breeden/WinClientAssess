"""M2-p3: activity completion cannot hide unresolved linked WCR candidates."""
from __future__ import annotations
import json
from pathlib import Path

import pytest
from tests.test_tester_queue_m2_p2 import _candidate_fixture
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.manual_test_workflow import read_manual_detail, read_manual_workflow, save_manual_decision


def _update(root, status):
    p=root/'working/tester_review_state.json'
    doc=json.loads(p.read_text(encoding='utf-8'))
    doc['items']['WCR-DLL']['status']=status
    p.write_text(json.dumps(doc),encoding='utf-8')
    create_manifest(root,framework_version='2.2.1',methodology_version='1.9',catalog_version='2.0')


def test_completed_manual_keeps_pending_linked_candidate_in_remaining(tmp_path):
    root=_candidate_fixture(tmp_path)
    case=read_manual_detail(root,'TC-DL-001')
    save_manual_decision(root,case_id=case['id'],fingerprint=case['fingerprint'],status='COMPLETED')
    overview=read_manual_workflow(root)
    assert overview['resolved']==1
    activity=next(x for x in overview['testing_queue']['items'] if x['id']=='TC-DL-001')
    assert activity['manual_complete'] is True
    assert activity['addressed'] is False
    assert activity['pending_candidates']==1
    assert overview['testing_queue']['pending_guided_review']==2 # linked + unlinked
    assert overview['testing_queue']['remaining']==3
    _update(root,'VALIDATED')
    activity=next(x for x in read_manual_workflow(root)['testing_queue']['items'] if x['id']=='TC-DL-001')
    assert activity['addressed'] is True
    assert activity['pending_candidates']==0
    assert verify_assessment(root)['status']=='PASS'


def test_guided_coverage_status_requires_linked_candidates(tmp_path):
    root=_candidate_fixture(tmp_path)
    unlinked=read_manual_detail(root,'TC-SV-001')
    assert not unlinked['related_candidates']
    with pytest.raises(ValueError,match='linked candidates'):
        save_manual_decision(root,case_id=unlinked['id'],fingerprint=unlinked['fingerprint'],status='ADDRESSED IN GUIDED REVIEW')
    _update(root,'VALIDATED')
    linked=read_manual_detail(root,'TC-DL-001')
    save_manual_decision(root,case_id=linked['id'],fingerprint=linked['fingerprint'],status='ADDRESSED IN GUIDED REVIEW')
    _update(root,'PENDING')
    detail=read_manual_detail(root,'TC-DL-001')
    assert detail['status']=='NOT STARTED'
    assert detail['changed_evidence']
    assert verify_assessment(root)['status']=='PASS'


def test_queue_ui_uses_backend_projection_inline_guidance_and_filters():
    root=Path(__file__).resolve().parents[1]
    html=(root/'gui/index.html').read_text(encoding='utf-8')
    js=(root/'gui/app.js').read_text(encoding='utf-8')
    for value in ('pending-review','pending-manual','manualLinkedReview'):
        assert value in html
    assert 'return state.manual?.testing_queue?.items||[]' in js
    assert 'inline.appendChild(card)' in js
    assert 'loadInlineCandidate(candidate,card,detailArea)' in js
    assert 'linked-wcr-card' in js
    assert "guidedOption.hidden=!guidedEligible" in js
    assert 'linked Guided Review candidate(s) still require review' in js
