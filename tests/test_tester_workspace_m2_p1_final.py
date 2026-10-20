"""M2-p1 Final Checklist/Client Appendix regression guardrails."""
from pathlib import Path

from utils.client_appendix import _appendix_html


def test_final_checklist_export_is_integrity_gated_and_manual_is_not_autocomplete():
    root = Path(__file__).resolve().parents[1]
    html = (root / 'gui/index.html').read_text(encoding='utf-8')
    js = (root / 'gui/app.js').read_text(encoding='utf-8')
    pane = html.split('id="workspace-pane-final"', 1)[1].split('</section>', 1)[0]
    assert 'id="workspaceAppendixBtn"' in pane
    assert 'Generate Client Appendix' in pane
    assert 'Verify assessment integrity' not in pane
    assert 'data-go="management"' not in pane
    assert "$('workspaceAppendixBtn').addEventListener('click'" in js
    assert "await request('/api/overview?'" in js
    assert "current.integrity?.status!=='PASS'" in js
    assert "export_appendix_with_confirmation" in js
    assert "const exported=await mutate('export_appendix',{output});" in js
    assert 'testing activit' in js
    assert "if(!confirm(question))" in js
    assert "manualOverview=manual" in js
    assert 'working/manual_test_review.json' not in js  # no manual-state mutation on export


def test_client_appendix_explains_withheld_primary_evidence_without_exposing_name():
    base = {'assessment_name': 'Lab', 'framework_version': '2.2.1', 'mode': 'full'}
    items = [
        {'title': 'Allowed report', 'source_module': 'Network Surface Review',
         'status': 'VALIDATED', 'artifacts': ['network_surface_review.txt']},
        {'title': 'Withheld report', 'source_module': 'DLL Search Review',
         'status': 'VALIDATED', 'artifacts': ['private_sensitive_payload.txt']},
    ]
    html = _appendix_html(base, items, ['network_surface_review.txt'],
                         {'network_surface_review.txt': 'Sanitized evidence'})
    assert 'href="evidence/network_surface_review.txt"' in html
    assert 'Detailed supporting evidence is not included in this sanitized appendix' in html
    assert 'private_sensitive_payload.txt' not in html
    assert 'Withheld report' in html
