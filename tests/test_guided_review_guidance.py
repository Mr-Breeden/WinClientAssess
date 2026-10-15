"""v1.5.2 guided-review validation guide and simplified reviewer regressions."""
from __future__ import annotations

from tests.test_guided_review_navigation import assessment, scripted
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_layout import artifact_path
from utils.guided_review import guided_review_cli, read_review, save_decision


def test_plain_guide_is_sectioned_and_returns_to_same_candidate(tmp_path):
    root = assessment(tmp_path)
    prompts = []
    choices = iter(['2', '8', '', '0'])
    messages = []

    def answer(prompt):
        prompts.append(prompt)
        return next(choices)

    guided_review_cli(root, input_fn=answer, output_fn=messages.append)
    output = '\n'.join(messages)
    for heading in ('1 / 6  OBSERVED EVIDENCE', '2 / 6  WHY VALIDATE / PREREQUISITES',
                    '3 / 6  STARTING CHECKS', '4 / 6  MANUAL VALIDATION / POC RESOURCE',
                    '5 / 6  TESTER EXECUTION / EXPECTED EVIDENCE', '6 / 6  INTERPRETATION'):
        assert heading in output
    assert output.count('Condition 1/2') == 2
    assert 'Press Enter to return' in prompts[-2]
    assert 'DllCharacteristics' in output
    assert verify_assessment(root)['status'] == 'PASS'


def test_rich_guide_shows_separate_panels_and_readable_commands(tmp_path, capsys):
    root = assessment(tmp_path)
    commands = iter(['1', '8', '', '0'])
    guided_review_cli(root, input_fn=lambda _: next(commands))
    screen = capsys.readouterr().out
    assert '1 / 6  Observed evidence' in screen
    assert '2 / 6  Why validate / prerequisites' in screen
    assert '3 / 6  Starting checks' in screen
    assert '6 / 6  Interpretation' in screen
    assert 'DllCharacteristics' in screen
    assert 'POTENTIAL SECURITY IMPACT' in screen


def test_save_prompts_only_for_notes_not_evidence_field(tmp_path):
    root = assessment(tmp_path)
    prompts = []
    commands = iter(['2', '3', 'Observed as intended behavior', '0'])
    guided_review_cli(root, input_fn=lambda prompt: (prompts.append(prompt), next(commands))[1],
                      output_fn=lambda _: None)
    assert len([p for p in prompts if 'Tester notes' in p]) == 1
    assert not any('Evidence file' in p or 'Evidence reference' in p for p in prompts)
    assert verify_assessment(root)['status'] == 'PASS'
    text = artifact_path(root, 'tester_review.txt').read_text(encoding='utf-8')
    assert 'Tester notes: Observed as intended behavior' in text
    assert 'Evidence reference:' not in text


def test_legacy_evidence_reference_survives_hidden_field_and_export(tmp_path):
    root = assessment(tmp_path)
    state = read_review(root)
    item = next(iter(state['items'].values()))
    save_decision(root, item['id'], 'INFORMATIONAL', 'Prior decision', 'reports/saved-evidence.txt')
    # A legacy decision written directly requires authorized manifest refresh.
    from utils.reporting import AssessmentReporter
    from utils.assessment_state import AssessmentState
    from pathlib import Path
    import json
    assessment_state = AssessmentState.load(root)
    render = json.loads((root / 'working' / 'report_render_state.json').read_text(encoding='utf-8'))
    reporter = AssessmentReporter(root, assessment_state.data['assessment_name'],
                                  Path(render['installer_filename']),
                                  assessment_state.data['mode'], assessment_state.data['framework_version'])
    reporter.status = render['modules']
    reporter.findings = render['findings']
    reporter.finalize(persist_render_state=False, sanitize_primary=False)
    create_manifest(root, framework_version=assessment_state.data['framework_version'])
    assert verify_assessment(root)['status'] == 'PASS'
    # Reviewing an existing condition without the removed field must not erase it.
    scripted(root, ['2', '3', 'Still informational', '0'])
    assert read_review(root)['items'][item['id']]['evidence_reference'] == 'reports/saved-evidence.txt'
    assert 'Evidence reference:' not in artifact_path(root, 'tester_review.txt').read_text(encoding='utf-8')


def test_exported_guide_uses_ten_part_tester_controlled_structure(tmp_path):
    root = assessment(tmp_path)
    guide = artifact_path(root, 'evidence_guide.txt').read_text(encoding='utf-8')
    for heading in ('1 / 10  OBSERVED EVIDENCE', '2 / 10  WHY VALIDATE IT',
                    '3 / 10  PREREQUISITES', '4 / 10  STARTING CHECKS',
                    '5 / 10  MANUAL VALIDATION PROCEDURE', '6 / 10  POC RESOURCE',
                    '7 / 10  TESTER EXECUTION', '8 / 10  EXPECTED EVIDENCE',
                    '9 / 10  INTERPRETATION', '10 / 10  WHEN NOT TO REPORT'):
        assert heading in guide
    assert 'DllCharacteristics' in guide
    assert 'Expected secure behavior:' in guide
    assert 'Windows Client Assessment never compiles or executes PoC resources' in guide
    assert 'Cleanup:' not in guide and '\nCLEANUP\n' not in guide
    assert 'Evidence file/ID' not in guide
