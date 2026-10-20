"""M2-p4: all WCRs visible, with independent controls and no extra test checklist."""
from pathlib import Path
from tests.test_attack_surface_guidance import assessment
from utils.assessment_layout import artifact_path
from utils.assessment_integrity import verify_assessment

ROOT = Path(__file__).resolve().parents[1]

def test_all_related_wcr_cards_have_independent_editors():
    js = (ROOT / 'gui/app.js').read_text(encoding='utf8')
    html = (ROOT / 'gui/index.html').read_text(encoding='utf8')
    css = (ROOT / 'gui/app.css').read_text(encoding='utf8')
    assert 'for(const candidate of item.related_candidates)' in js
    assert 'loadInlineCandidate(candidate,card,detailArea)' in js
    assert 'card.open=candidate.status===' in js
    assert 'const decision=el(' in js and "candidate_id:d.id" in js
    assert 'inline.appendChild(card)' in js
    assert "inline.appendChild($('reviewEditor'))" not in js
    assert 'manualCompletionHeading' in html and 'manualCompletionId' in html
    assert 'Manual Test Completion —' in html
    assert '.linked-wcr-card' in css and '.manual-completion-heading' in css
    assert 'data-unsaved' in js and 'updateUnsaved()' in js
    assert 'An associated WCR has unsaved changes.' in js
    assert 'state.review=(await backend(' in js
    assert 'state.selectedManual={...state.selectedManual,related_candidates:latest.related_candidates}' in js

def test_evidence_guidance_is_not_a_second_checklist():
    html = (ROOT / 'gui/index.html').read_text(encoding='utf8')
    js = (ROOT / 'gui/app.js').read_text(encoding='utf8')
    assert 'id="workspaceSupplemental"' in html
    assert 'id="workspaceFullMethodology"' in html
    assert 'id="workflowTestCases"' not in html
    assert 'id="workflowSurfacePlan"' not in html
    assert "const workspaceReports=[['coverage_summary.txt'" in js
    assert "['test_cases.txt','Generated test-case procedures']" not in js
    assert "showWorkspacePane('queue');await loadTestingQueue()" in js

def test_attack_surface_reference_has_queue_index_and_preserves_integrity(tmp_path):
    root=assessment(tmp_path,version='2.2.1')
    plan=artifact_path(root,'attack_surface_test_plan.txt').read_text(encoding='utf8')
    assert 'NOT A SECOND TESTING CHECKLIST' in plan
    assert 'QUICK INDEX' in plan
    assert 'TC-DL-001' in plan and 'TC-AS-001' in plan
    assert 'Related Testing Queue reference (when applicable)' in plan
    assert verify_assessment(root)['status']=='PASS'
