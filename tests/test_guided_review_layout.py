"""v1.5.4: readable Guided Tester Review card and validation-guide layout."""
from __future__ import annotations

import re

from tests.test_guided_review_navigation import assessment, scripted
from utils.assessment_integrity import verify_assessment
from utils.guided_review import guided_review_cli, read_review


def test_plain_card_uses_internal_title_and_section_labels(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['2', '0'])
    assert 'Condition 1/2\nMissing PE mitigations' in output
    assert 'Supporting File:' in output
    assert 'Validation Summary:' in output
    assert 'Starting Check:' in output
    assert 'Tester Notes:' in output
    assert 'Evidence file/ID' not in output


def test_rich_card_keeps_condition_name_out_of_border_title(tmp_path, capsys):
    root = assessment(tmp_path)
    commands = iter(['2', '0'])
    guided_review_cli(root, input_fn=lambda _: next(commands))
    screen = capsys.readouterr().out
    # Border heading is position only; the finding remains visible in card body.
    border_line = next(line for line in screen.splitlines() if 'Condition 1/2' in line)
    assert 'Missing PE mitigations' not in border_line
    assert 'Missing PE mitigations' in screen
    for label in ('VALIDATION SUMMARY', 'STARTING CHECK', 'TESTER NOTES', 'Supporting File'):
        assert label in screen


def test_rich_card_and_guide_are_capped_on_wide_terminal(tmp_path, capsys, monkeypatch):
    root = assessment(tmp_path)
    # Rich honors COLUMNS for its console width in a non-interactive test stream.
    monkeypatch.setenv('COLUMNS', '180')
    commands = iter(['2', '8', '', '0'])
    guided_review_cli(root, input_fn=lambda _: next(commands))
    # A Windows terminal or Rich configuration can emit ANSI escapes and
    # different border glyphs. Assert semantic headings and capped rendered
    # line widths instead of depending on a specific Unicode box prefix.
    ansi = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
    lines = [ansi.sub('', line) for line in capsys.readouterr().out.splitlines()]
    headings = ('Condition 1/2', '1 / 6  Observed evidence',
                '2 / 6  Why validate / prerequisites', '3 / 6  Starting checks',
                '4 / 6  Manual validation / PoC resource',
                '5 / 6  Tester execution / expected evidence',
                '6 / 6  Interpretation')
    matching = [next((line for line in lines if heading in line), None) for heading in headings]
    assert all(line is not None for line in matching), matching
    assert max(len(line) for line in matching) <= 118


def test_v153_optional_note_behavior_still_advances_and_verifies(tmp_path):
    root = assessment(tmp_path)
    output = scripted(root, ['2', '1', '', '0'])
    assert 'Automatically advancing' in output
    assert 'undocumented' not in output.lower()
    assert verify_assessment(root)['status'] == 'PASS'
    state = read_review(root)
    validated = [x for x in state['items'].values() if x['status'] == 'VALIDATED']
    assert validated and validated[0]['notes'] == ''
