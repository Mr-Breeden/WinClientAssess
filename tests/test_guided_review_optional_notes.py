"""Optional-note regression: no extra undocumented labels or blocking prompts."""
from __future__ import annotations

import pytest

from tests.test_guided_review_navigation import assessment, scripted
from utils.assessment_integrity import verify_assessment
from utils.assessment_layout import artifact_path
from utils.guided_review import (
    counts, guided_review_cli, read_review, save_decision,
)


def test_blank_validated_note_saves_advances_and_flags_generated_reports(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['2', '1', '', '3', ''])
    state = read_review(root)
    assert counts(state)['VALIDATED'] == 1
    assert counts(state)['INFORMATIONAL'] == 1
    assert 'Condition 1/2' in output and 'Condition 2/2' in output
    assert 'No decision was saved' not in output
    assert 'Automatically advancing' in output
    assert 'undocumented' not in output.lower()
    txt = artifact_path(root, 'tester_review.txt').read_text(encoding='utf-8')
    summary = artifact_path(root, 'findings_summary.txt').read_text(encoding='utf-8')
    guide = artifact_path(root, 'evidence_guide.txt').read_text(encoding='utf-8')
    assert 'VALIDATED without notes:' not in txt
    assert 'Validation documentation: MISSING' not in txt
    assert 'Validated without notes' not in summary
    assert 'Validation documentation: MISSING' not in guide
    assert verify_assessment(root)['status'] == 'PASS'


def test_pending_view_blank_notes_autoadvances_and_persists(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['1', '1', '', '0'])
    assert 'Pending condition 1 of 1 remaining' in output  # Pending queue shrinks after saving.
    state = read_review(root)
    assert verify_assessment(root)['status'] == 'PASS'
    reopened = scripted(root, ['1', '0'])
    assert '1 distinct conditions' in reopened


@pytest.mark.parametrize('action,expected', [
    ('1', 'VALIDATED'), ('2', 'NOT APPLICABLE'),
    ('3', 'INFORMATIONAL'), ('4', 'PENDING'),
])
def test_all_statuses_accept_blank_notes(tmp_path, action, expected):
    root = assessment(tmp_path)
    # Pending stays on screen but can still quit; all other dispositions
    # advance and still accept an optional blank note.
    scripted(root, ['2', action, '', '0'])
    assert counts(read_review(root))[expected] >= 1
    assert verify_assessment(root)['status'] == 'PASS'


def test_enter_keeps_existing_notes_and_clear_explicitly_removes(tmp_path):
    root = assessment(tmp_path)
    # Write a first note via CLI; after save the review moves to the next item.
    scripted(root, ['2', '1', 'Observed behavior confirmed in test VM', '0'])
    state = read_review(root)
    pe = next(x for x in state['items'].values() if x['source_module'] == 'PE Security Review')
    assert pe['notes'] == 'Observed behavior confirmed in test VM'
    # The all-view opens the same PE condition first; Enter retains its note.
    scripted(root, ['2', '1', '', '0'])
    assert read_review(root)['items'][pe['id']]['notes'] == 'Observed behavior confirmed in test VM'
    # :clear removes the note without blocking VALIDATED status.
    scripted(root, ['2', '1', ':clear', '0'])
    assert read_review(root)['items'][pe['id']]['notes'] == ''
    assert verify_assessment(root)['status'] == 'PASS'


def test_programmatic_save_blank_notes_and_legacy_evidence_preserved(tmp_path):
    root = assessment(tmp_path)
    state = read_review(root)
    selected = next(x for x in state['items'].values() if x['source_module'] == 'PE Security Review')
    updated = save_decision(root, selected['id'], 'VALIDATED', '', 'reports/legacy-note.txt')
    assert updated['items'][selected['id']]['status'] == 'VALIDATED'
    assert updated['items'][selected['id']]['evidence_reference'] == 'reports/legacy-note.txt'
    # Updating the authoritative state directly without regenerating derived
    # reports MUST still be detected by the existing SHA-256 verifier.
    assert verify_assessment(root)['status'] == 'FAIL'


def test_tampered_assessment_rejects_optional_note_review(tmp_path):
    root = assessment(tmp_path)
    artifact_path(root, 'binary_security_review.txt').write_text('tampered', encoding='utf-8')
    before = (root / 'working' / 'tester_review_state.json').read_bytes()
    with pytest.raises(ValueError, match='verified assessment'):
        guided_review_cli(root, input_fn=lambda _: '1', output_fn=lambda _: None)
    assert (root / 'working' / 'tester_review_state.json').read_bytes() == before
