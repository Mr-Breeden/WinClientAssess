"""v1.6.4 fixes discovered in the uploaded v1.6.2 Windows field run."""
from __future__ import annotations

import sys
from pathlib import Path

from tests.test_guided_review_navigation import assessment
from modules.test_cases import generate_test_cases
from modules.snapshots import write_snapshot_diff
from utils.assessment_layout import artifact_path
from utils.assessment_integrity import verify_assessment
from utils.guided_review import _applicable_test_links, collect_tester_notes, guided_review_cli, read_review
from utils.report_format import windows_root_group


def _runtime_files(root, count, with_source=False):
    for name in ("runtime_managed_context.txt", "advanced_runtime_review.txt"):
        artifact_path(root, name).write_text("", encoding="utf8")
    artifact_path(root, "runtime_managed_context.txt").write_text(
        "WINCLIENTASSESS - MANAGED RUNTIME CONTEXT\n"
        "SUMMARY\nProcesses classified : 6\n"
        f"Managed candidates/processes: {count}\n"
        "Static .NET Candidate : NO\nManaged Runtime Seen  : NO\n", encoding="utf8")
    if with_source:
        artifact_path(root, "dotnet_source_review.txt").write_text("[SRC-0001]\n", encoding="utf8")


def test_native_only_runtime_does_not_advertise_nonexistent_managed_source(tmp_path):
    root = tmp_path / 'assessment'
    root.mkdir()
    _runtime_files(root, 0)
    generate_test_cases(root, 'full', '.msi', {'procmon':True})
    text = artifact_path(root, 'test_cases.txt').read_text(encoding='utf8')
    assert 'TC-AR-001' not in text
    assert 'Review dotnet_source_review.txt' not in text
    assert 'Correlate relevant source locations' not in text
    assert 'TC-AR-001' not in _applicable_test_links(root, 'Advanced .NET / Native Runtime Review')


def test_observed_managed_runtime_without_source_has_safe_alternative(tmp_path):
    root = tmp_path / 'assessment'
    root.mkdir()
    _runtime_files(root, 1)
    generate_test_cases(root, 'full', '.msi', {'procmon':True})
    text = artifact_path(root, 'test_cases.txt').read_text(encoding='utf8')
    assert 'TC-AR-001' in text
    assert 'Managed Runtime Classification (Source Unavailable)' in text
    assert 'No dotnet_source_review.txt was generated.' in text
    assert 'Review dotnet_source_review.txt' not in text
    assert not artifact_path(root, 'dotnet_source_review.txt').exists()
    assert 'TC-AR-001' in _applicable_test_links(root, 'Advanced .NET / Native Runtime Review')
    _runtime_files(root, 1, with_source=True)
    generate_test_cases(root, 'full', '.msi', {'procmon':True})
    text = artifact_path(root, 'test_cases.txt').read_text(encoding='utf8')
    assert 'Managed Runtime Classification and Source Correlation' in text
    assert 'Review dotnet_source_review.txt' in text
    generate_test_cases(root, 'static', '.msi', {'procmon':True})
    assert 'TC-AR-001' not in artifact_path(root, 'test_cases.txt').read_text(encoding='utf8')


def test_multiline_note_is_persisted_escaped_and_integrity_safe(tmp_path):
    root = assessment(tmp_path, version='1.6.4')
    actions = iter(['2','3', ':multi', 'ASLR missing: 8', 'DEP/NX missing: 8', '<x>', '.', '0'])
    prompts, output = [], []
    guided_review_cli(root, input_fn=lambda prompt: (prompts.append(prompt), next(actions))[1],
                      output_fn=output.append)
    note = next(x['notes'] for x in read_review(root)['items'].values() if x['status']=='INFORMATIONAL')
    assert note == 'ASLR missing: 8\nDEP/NX missing: 8\n<x>'
    assert len([x for x in prompts if 'Tester notes' in x]) == 1
    assert verify_assessment(root)['status'] == 'PASS'
    html = artifact_path(root,'assessment_report.html').read_text(encoding='utf8')
    assert 'class="tester-note"' in html and 'white-space:pre-wrap' in html
    assert '&lt;x&gt;' in html and '<x>' not in html
    assert 'ASLR missing: 8\nDEP/NX missing: 8' in html


def test_notes_optional_multiline_cancel_and_clear():
    assert collect_tester_notes(lambda _: '', lambda _: None, 'keep') == 'keep'
    assert collect_tester_notes(lambda _: ':clear', lambda _: None, 'keep') == ''
    seq = iter([':multi', 'discard', ':cancel'])
    assert collect_tester_notes(lambda _: next(seq), lambda _: None, 'keep') == 'keep'
    seq = iter([':multi', 'one', '', 'two', '.'])
    assert collect_tester_notes(lambda _: next(seq), lambda _: None, '') == 'one\n\ntwo'
    seq = iter([':multi', '.'])
    assert collect_tester_notes(lambda _: next(seq), lambda _: None, 'keep') == 'keep'


def test_windowsapps_attribution_visible_but_no_snapshots_lost(tmp_path):
    root = tmp_path / 'assessment'
    root.mkdir()
    local = {'Path':r'C:\Program Files\AcmeWidget\main.exe', 'IsDirectory':False,'Length':42}
    app = {'Path':r'C:\Program Files\WindowsApps\SystemApp_123\bin.exe', 'IsDirectory':False,'Length':32}
    extra = {'Path':r'D:\Program Files\WindowsApps\BackgroundApp_77\data', 'IsDirectory':True}
    diff = {'Filesystem':{'added':[app, local,extra], 'removed':[app],
                          'changed':[{'before':app, 'after':app}]},
            'Services':{'added':[{'Name':'TargetService'}], 'removed':[], 'changed':[]}}
    write_snapshot_diff(diff, root)
    install = artifact_path(root,'install_changes.txt').read_text(encoding='utf8')
    fs = artifact_path(root,'filesystem_changes.txt').read_text(encoding='utf8')
    files = artifact_path(root,'installed_files.txt').read_text(encoding='utf8')
    assert 'WindowsApps (unattributed)' in install
    assert 'UNATTRIBUTED' in install and 'correlate' in install.lower()
    assert 'Other (still requires correlation)' in install
    assert fs.index(r'C:\Program Files\AcmeWidget\main.exe') < fs.index(r'C:\Program Files\WindowsApps\SystemApp_123\bin.exe')
    assert 'WINDOWSAPPS (UNATTRIBUTED HOST ACTIVITY)' in fs
    assert 'WindowsApps (unattributed)' in files
    assert r'C:\Program Files\WindowsApps\SystemApp_123\bin.exe' in files
    assert 'TargetService' in install
    assert len(diff['Filesystem']['added']) == 3
    assert windows_root_group(r'C:\Program Files\WindowsApps\Sample\file') == 'WindowsApps (unattributed)'
    assert windows_root_group(r'C:\Program Files\WindowsApps') == 'WindowsApps (unattributed)'
    assert windows_root_group(r'C:\Program Files\WindowsApps_old\file') == 'Program Files'
    assert windows_root_group(r'C:\Program Files\AcmeWidget\file') == 'Program Files'


def test_uppercase_full_is_accepted_by_cli(tmp_path, monkeypatch):
    import wca
    monkeypatch.setattr(sys, 'argv', ['wca.py', '--mode','FULL', '--installer','setup.msi',
                                      '--assessment-name','test', '--output',str(tmp_path)])
    args = wca.parse_args()
    assert args.mode == 'full'


def test_uppercase_full_is_accepted_by_rich_interactive_prompt():
    from io import StringIO
    from rich.console import Console
    from rich.prompt import Prompt
    console = Console(file=StringIO())
    console.input = lambda *a, **kw: 'FULL'
    result = Prompt.ask('Assessment mode', choices=['static', 'full'],
                        default='static', case_sensitive=False, console=console)
    assert result == 'full'


def test_ten_section_numbering_matches_actual_guide(tmp_path):
    root = assessment(tmp_path, version='1.6.4')
    guide = artifact_path(root, 'evidence_guide.txt').read_text(encoding='utf8')
    for i, name in enumerate(('OBSERVED EVIDENCE','WHY VALIDATE IT','PREREQUISITES','STARTING CHECKS',
                               'MANUAL VALIDATION PROCEDURE','POC RESOURCE','TESTER EXECUTION','EXPECTED EVIDENCE',
                               'INTERPRETATION','WHEN NOT TO REPORT'), 1):
        assert f'{i} / 10  {name}' in guide
    assert '4 / 4' not in guide
    assert verify_assessment(root)['status']=='PASS'
