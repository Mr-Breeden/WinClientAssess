"""M2-p1 regression: quiet notifications, current guidance, and safe case cross-links."""
from __future__ import annotations

import json
from pathlib import Path

from modules.test_case_catalog import TEST_CASES
from tests.test_tester_workflow_220 import fixture
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.manual_test_workflow import read_manual_detail, read_manual_workflow, save_manual_decision


def test_case_links_require_actual_review_candidate_and_do_not_claim_completion(tmp_path):
    root = fixture(tmp_path)
    review_file = root / 'working' / 'tester_review_state.json'
    review_file.write_text(json.dumps({'schema_version': 1, 'items': {
        'WCR-ACTUAL': {'id': 'WCR-ACTUAL', 'title': 'Writable DLL path',
                       'test_cases': ['TC-DL-001'], 'status': 'PENDING',
                       'notes': 'Private candidate notes'},
        'WCR-NOTRELATED': {'id': 'WCR-NOTRELATED', 'title': 'Unrelated condition',
                           'test_cases': ['TC-IP-001'], 'status': 'VALIDATED'},
    }}), encoding='utf-8')
    create_manifest(root, framework_version='2.2.1', methodology_version='1.9', catalog_version='2.0')
    summary = read_manual_workflow(root)
    dll = next(row for row in summary['items'] if row['id'] == 'TC-DL-001')
    service = next(row for row in summary['items'] if row['id'] == 'TC-SV-001')
    assert [c['id'] for c in dll['related_candidates']] == ['WCR-ACTUAL']
    assert dll['related_candidates'][0]['status'] == 'PENDING'
    assert dll['status'] == 'NOT STARTED'
    assert service['related_candidates'] == []
    assert 'notes' not in dll and 'Private candidate notes' not in str(dll)
    before = (root / 'reports' / 'test_cases.txt').read_bytes()
    save_manual_decision(root, case_id=dll['id'], fingerprint=dll['fingerprint'], status='IN PROGRESS')
    assert read_manual_detail(root, 'TC-DL-001')['status'] == 'IN PROGRESS'
    assert (root / 'reports' / 'test_cases.txt').read_bytes() == before
    assert json.loads(review_file.read_text())['items']['WCR-ACTUAL']['status'] == 'PENDING'
    assert verify_assessment(root)['status'] == 'PASS'


def test_gui_has_non_intrusive_notifications_and_explicit_candidate_filters():
    root = Path(__file__).resolve().parents[1]
    js = (root/'gui/app.js').read_text(encoding='utf-8')
    markup = (root/'gui/index.html').read_text(encoding='utf-8')
    assert 'if (!error) return;' in js
    assert 'if(item.related_candidates?.length)' in js
    assert 'inline.appendChild(card)' in js and 'loadInlineCandidate(candidate,card,detailArea)' in js
    assert 'id="manualGuidedFilter"' in markup
    assert 'value="unlinked"' in markup
    assert 'id="manualSaveHint"' in markup
    assert 'linked Guided Review candidate(s) still require review' in js


def test_generated_instructions_have_no_legacy_runtime_capture_version():
    for case in TEST_CASES:
        if case['id'] in ('TC-PM-001','TC-DL-001'):
            steps = '\n'.join(case['how'])
            assert 'v0.3.0' not in steps and 'v0.4.0' not in steps
            assert 'Procmon' in steps or 'Process Monitor' in steps
