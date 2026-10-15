"""v1.5.1 Windows-style Guided Tester Review regressions."""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_layout import artifact_path
from utils.assessment_state import AssessmentState
from utils.guided_review import (
    counts, guided_review_cli, read_review, review_queue, save_decision,
    sync_review, validation_commands,
)
from utils.reporting import AssessmentReporter


def assessment(tmp_path, *, include_repeated=False, version='1.5.0'):
    root = tmp_path / 'case'
    installer = tmp_path / 'setup.msi'
    installer.write_bytes(b'generic-test-fixture')
    tracker = AssessmentState.create(root, assessment_name='test review', installer=installer,
                                     mode='full', framework_version=version,
                                     options={}, tools={})
    if include_repeated:
        artifact_path(root, 'advanced_runtime_review.txt').write_text('''
[POI-AR-001] Beeper.exe -> C:\\Windows\\System32\\cmd.exe
Confidence: MEDIUM
Issue: Target process launched cmd.exe.
[POI-AR-002] Beeper.exe -> C:\\Windows\\System32\\cmd.exe
Confidence: MEDIUM
Issue: Target process launched cmd.exe.
[POI-AR-003] Beeper.exe -> C:\\Windows\\System32\\cmd.exe
Confidence: MEDIUM
Issue: Target process launched cmd.exe.
''', encoding='utf-8')
    reporter = AssessmentReporter(root, 'test review', installer, 'full', version, state_tracker=tracker)
    reporter.set_status('Installer Information', 'PASS')
    reporter.add_finding(title='Unsigned installer', severity='Informational',
                         source_module='Digital Signature Review', evidence='NotSigned')
    reporter.add_finding(title='Missing PE mitigations', severity='Low',
                         source_module='PE Security Review', evidence='ASLR/DEP missing')
    reporter.finalize()
    AssessmentState.load(root).mark_complete('COMPLETE')
    create_manifest(root, framework_version=version)
    assert verify_assessment(root)['status'] == 'PASS'
    return root


def scripted(root, inputs):
    entered = iter(inputs)
    messages = []
    guided_review_cli(root, input_fn=lambda prompt: next(entered), output_fn=messages.append)
    assert verify_assessment(root)['status'] == 'PASS'
    return '\n'.join(messages)


def test_all_view_auto_advance_after_save(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['2', '3', 'Not reportable after investigation',
                             '2', 'Not applicable to this installation'])
    assert 'Condition 1/2' in output and 'Condition 2/2' in output
    assert 'Automatically advancing' in output
    statuses = counts(read_review(root))
    assert statuses['INFORMATIONAL'] == 1
    assert statuses['NOT APPLICABLE'] == 1
    assert statuses['PENDING'] == 0


def test_pending_view_moves_to_next_after_save_and_reopens(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['1', '3', 'Expected native binary configuration', '0'])
    assert 'Pending condition 2 of 1 remaining' not in output  # Pending view shrinks by one.
    assert 'Pending condition 1 of 2 remaining' in output and 'Pending condition 1 of 1 remaining' in output
    assert counts(read_review(root))['PENDING'] == 1
    reopened = scripted(root, ['1', '0'])
    assert '1 distinct conditions' in reopened
    assert 'Pending condition 1 of 1 remaining' in reopened


def test_explicit_next_back_and_list_jump(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['2', '5', '6', '7', '2', '0'])
    assert 'Condition 1/2' in output and 'Condition 2/2' in output
    assert counts(read_review(root))['PENDING'] == 2


def test_in_context_pe_commands_and_evidence_guide(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['1', '8', '', '0'])
    assert 'DllCharacteristics' in output
    assert 'ASLR' in output
    assert 'ASLR' in artifact_path(root, 'evidence_guide.txt').read_text(encoding='utf-8')
    pe = next(x for x in read_review(root)['items'].values()
              if x['source_module'] == 'PE Security Review')
    assert any('pefile.PE' in step for step in validation_commands(pe))


def test_new_assessments_collapse_identical_events_not_distinct_evidence(tmp_path):
    root = assessment(tmp_path, include_repeated=True, version='1.5.1')
    state = read_review(root)
    runtime = [x for x in state['items'].values() if x['source_module'].startswith('Advanced')]
    assert len(runtime) == 1
    assert runtime[0]['occurrence_count'] == 3
    assert runtime[0]['source_records'] == ['POI-AR-001', 'POI-AR-002', 'POI-AR-003']
    assert len(state['items']) == 3
    grouped = next(x for x in review_queue(state, status='') if x['source_module'].startswith('Advanced'))
    assert grouped['_occurrences'] == 3


def test_legacy_identical_pois_grouped_in_ui_keep_existing_ids_and_history(tmp_path):
    root = assessment(tmp_path, include_repeated=True, version='1.5.0')
    state = read_review(root)
    runtime = next(x for x in state['items'].values() if x.get('source_record'))
    original_id = runtime['id']
    runtime.pop('occurrence_count', None)  # This fixture models v1.5.0, not v1.5.1.
    runtime.pop('source_records', None)
    for ordinal in (2, 3):
        copy = deepcopy(runtime)
        copy['source_record'] = f'POI-AR-{ordinal:03d}'
        copy['identity'] += f'|POI-AR-{ordinal:03d}'
        from utils.guided_review import _fingerprint
        copy['fingerprint'] = _fingerprint(copy)
        copy['id'] = f'WCR-LEGACY-{ordinal:03d}'
        # This mimics archived v1.5.0 identities and note-less pending items.
        state['items'][copy['id']] = copy
    # The fixture's canonical base candidate retains its real base identity;
    # v1.5.0 source POI-AR-002/003 produced these alternate identities.
    import hashlib
    for key, item in list(state['items'].items()):
        if item['id'] == original_id:
            continue
        if key.startswith('WCR-LEGACY-'):
            actual_id = 'WCR-' + hashlib.sha256(item['identity'].encode('utf-8')).hexdigest()[:14].upper()
            item['id'] = actual_id
            state['items'][actual_id] = state['items'].pop(key)
    (root / 'working' / 'tester_review_state.json').write_text(json.dumps(state), encoding='utf-8')
    create_manifest(root, framework_version='1.5.0')
    assert verify_assessment(root)['status'] == 'PASS'
    queue = review_queue(read_review(root), status='')
    linked = [x for x in queue if x['source_module'].startswith('Advanced')]
    assert len(linked) == 1
    assert len(linked[0]['_linked_ids']) == 3
    # Informational decision applies to all identical records in one atomic save.
    output = scripted(root, ['2', '5', '3', 'Known repeated process launch without untrusted control', '0'])
    after = read_review(root)
    reviewed = [x for x in after['items'].values() if x['source_module'].startswith('Advanced')]
    assert len(reviewed) == 3
    assert all(x['status'] == 'INFORMATIONAL' for x in reviewed)
    assert '3 event(s)' in output


def test_review_rejects_tampered_primary_evidence_before_any_edit(tmp_path):
    root = assessment(tmp_path)
    artifact_path(root, 'binary_security_review.txt').write_text('tampered', encoding='utf-8')
    with pytest.raises(ValueError, match='verified assessment'):
        scripted(root, ['1', '3', 'x', 'x'])


def test_distinct_runtime_details_do_not_collapse_or_reset_after_reopen(tmp_path):
    root = assessment(tmp_path, include_repeated=True, version='1.5.1')
    path = artifact_path(root, 'advanced_runtime_review.txt')
    path.write_text(path.read_text().replace(
        'Issue: Target process launched cmd.exe.\n[POI-AR-003]',
        'Issue: Different execution context; distinct condition.\n[POI-AR-003]'), encoding='utf-8')
    # Regenerate only the review candidate state for a new fixture, then
    # persist a decision and re-sync identical evidence without re-review.
    original = read_review(root)
    saved = sync_review(root, [dict(title='Unsigned installer', source_module='Digital Signature Review',
                                    severity='Informational', evidence='NotSigned'),
                                dict(title='Missing PE mitigations', source_module='PE Security Review',
                                    severity='Low', evidence='ASLR/DEP missing')])
    runtime = [x for x in saved['items'].values() if x['source_module'].startswith('Advanced')]
    assert len(runtime) == 2
    assert sorted(x['occurrence_count'] for x in runtime) == [1, 2]
    original_ids = {x['id'] for x in runtime}
    selected = next(x for x in runtime if x['occurrence_count'] == 1)
    save_decision(root, selected['id'], 'INFORMATIONAL', 'Different benign instance')
    reopened = sync_review(root, [dict(title='Unsigned installer', source_module='Digital Signature Review',
                                      severity='Informational', evidence='NotSigned'),
                                  dict(title='Missing PE mitigations', source_module='PE Security Review',
                                      severity='Low', evidence='ASLR/DEP missing')])
    after = [x for x in reopened['items'].values() if x['source_module'].startswith('Advanced')]
    assert {x['id'] for x in after} == original_ids
    assert reopened['items'][selected['id']]['status'] == 'INFORMATIONAL'
    assert sum(x['status'] == 'PENDING' for x in after) == 1


def test_rich_numbered_console_renders_without_crashing(tmp_path, capsys):
    root = assessment(tmp_path)
    commands = iter(['1', '0'])
    guided_review_cli(root, input_fn=lambda _: next(commands))
    screen = capsys.readouterr().out
    assert 'Review queue' in screen
    assert 'Pending condition 1 of 2 remaining' in screen
    assert '[1] Validate' in screen
