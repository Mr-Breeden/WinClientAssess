"""Regression fixtures for portable file references and unwrapped Windows checks."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_guided_review_navigation import assessment
from utils.assessment_integrity import verify_assessment
from utils.assessment_layout import artifact_path
from utils.contextual_checks import _file_arg, checks
from utils.guided_review import guided_review_cli, read_review, validation_commands
from utils.validation_clipboard import powershell_checks


@pytest.fixture
def root(tmp_path):
    # The folder includes spaces and an apostrophe to exercise quoting; it is
    # deliberately private to the live terminal and must not enter HTML/TXT.
    base = tmp_path / "Tester O'Neil" / 'session'
    (base / 'reports').mkdir(parents=True)
    (base / 'working').mkdir()
    for filename in ('advanced_runtime_review.txt','dll_search_review.txt','attack_surface_correlations.txt',
                     'permissions_review.txt','network_surface_review.txt','msi_analysis.txt',
                     'binary_security_review.txt','ipc_review.txt','test_cases.txt'):
        (base / 'reports' / filename).write_text('Read-only fixture', encoding='utf-8')
    (base / 'working' / 'procmon_target_events.csv').write_text('Path,Result\n', encoding='utf-8')
    return base


def test_user_example_is_independent_of_current_directory(root):
    item = {'source_module': 'Advanced .NET / Native Runtime Review',
            'title': r'Beeper.exe -> C:\Windows\System32\cmd.exe', 'evidence': '',
            'artifacts': ['advanced_runtime_review.txt']}
    portable = validation_commands(item, root)
    live = validation_commands(item, root, console_paths=True)
    assert portable[0] == live[0]
    assert 'ProcessId,ParentProcessId,CommandLine' in live[0]
    assert '(Read-Host' in portable[1]
    assert '.\\reports\\' not in portable[1]
    assert str(root) not in portable[1]
    assert str((root/'reports'/'advanced_runtime_review.txt').resolve()).replace("'", "''") in live[1]
    assert 'Read-Host' not in live[1]
    assert not any('\n' in x or '\r' in x for x in live)


def test_attack_surface_dll_and_fallback_paths_have_no_cwd_dependency(root):
    cases = [
        {'source_module': 'Attack Surface Correlations', 'title':'EXE hijack',
         'evidence': 'Category: Executable/helper search-path hijacking\nPath: C:\\ProgramData\\Example\\helper.exe\nDirectory: C:\\ProgramData\\Example', 'artifacts': []},
        {'source_module': 'DLL Search Review', 'title':'EXE -> Helper.dll',
         'evidence': 'Missing DLL: C:\\ProgramData\\Example\\Helper.dll\nSearch Directory: C:\\ProgramData\\Example', 'artifacts': []},
        {'source_module': 'DLL Search Review', 'title':'Unknown', 'evidence':'', 'artifacts': []},
        {'source_module': 'IPC / Named Pipe Review', 'title':'Unknown', 'evidence':'', 'artifacts': []},
        {'source_module': 'Services Review', 'title':'Unknown', 'evidence':'', 'artifacts': []},
        {'source_module': 'Permissions Review', 'title':'Unknown', 'evidence':'', 'artifacts': []},
        {'source_module': 'MSI Analysis', 'title':'Unknown', 'evidence':'', 'artifacts': []},
        {'source_module': 'Network Surface Review', 'title':'Unknown', 'evidence':'', 'artifacts': []},
        {'source_module': 'PE Security Review', 'title':'Unknown', 'evidence':'', 'artifacts': []},
    ]
    for item in cases:
        portable = checks(item, root)
        assert portable
        assert not any('.\\reports\\' in line or '.\\working\\' in line or '.\\scripts\\' in line
                       for line in portable)
        assert not any(str(root) in line for line in portable)
        assert not any('\r' in line or '\n' in line for line in portable)
    assert 'Import-Csv -LiteralPath (Read-Host' in '\n'.join(checks(cases[0], root))


def test_report_args_validate_filename_and_never_persist_absolute_path(root):
    assert 'Read-Host' in _file_arg(root, 'reports/advanced_runtime_review.txt')
    for evil in ('working/../reports/secret.txt', 'reports/../../secret.txt', 'reports/evil;echo.txt'):
        with pytest.raises(ValueError):
            _file_arg(root, evil, console_paths=True)
    # Symlinks are not followed into private files on live display.
    path = root / 'reports' / 'private.txt'
    path.symlink_to(root/'working'/'procmon_target_events.csv')
    assert 'Read-Host' in _file_arg(root, 'reports/private.txt', console_paths=True)


def test_clipboard_export_preserves_long_single_line_commands_and_comments():
    long = "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'Beeper.exe' } | Select-Object ProcessId,ParentProcessId,CommandLine"
    text = powershell_checks([long, 'Inspect only approved paths.', 'Get-Content approved',
                              'Review the evidence\nWrite-Output UNSAFE'])
    assert ('\r\n' + long + '\r\n') in text
    assert '\r\n# Inspect only approved paths.\r\n' in text
    assert '\r\n# Write-Output UNSAFE\r\n' in text
    assert not '\r\nWrite-Output UNSAFE\r\n' in text


def test_copy_action_is_opt_in_and_does_not_change_review_state(tmp_path, monkeypatch):
    root = assessment(tmp_path, version='1.6.3')
    before = read_review(root)
    result = []
    monkeypatch.setattr('utils.validation_clipboard.copy_windows_text', result.append)
    actions = iter(['2', 'c', '8', 'c', '0'])  # all candidates, main-menu copy, guide copy, exit
    # 8 guide's C copies and returns to same item, then 0 exits.
    output = []
    guided_review_cli(root, input_fn=lambda _:next(actions), output_fn=output.append)
    assert len(result) == 2
    assert all('\r\n' in copied and 'Get-' in copied for copied in result)
    assert all('Get-AuthenticodeSignature' in x or 'pefile.PE' in x for x in result)
    assert before == read_review(root)
    assert verify_assessment(root)['status'] == 'PASS'
    assert 'complete PowerShell command' in '\n'.join(output)


def test_persisted_html_and_guide_use_prompt_without_private_path(tmp_path):
    root = assessment(tmp_path, version='1.6.3')
    html = artifact_path(root, 'assessment_report.html').read_text(encoding='utf8')
    guide = artifact_path(root, 'evidence_guide.txt').read_text(encoding='utf8')
    assert str(tmp_path) not in html + guide
    assert '.\\reports\\' not in html + guide
    assert verify_assessment(root)['status'] == 'PASS'


def test_unavailable_clipboard_preserves_review_and_reports_failure(tmp_path, monkeypatch):
    root = assessment(tmp_path, version='1.6.3')
    original = read_review(root)
    def fail(_):
        raise OSError('clipboard busy')
    monkeypatch.setattr('utils.validation_clipboard.copy_windows_text', fail)
    actions = iter(['2', 'c', '0'])
    messages = []
    guided_review_cli(root, input_fn=lambda _: next(actions), output_fn=messages.append)
    assert 'clipboard busy' in '\n'.join(messages)
    assert read_review(root) == original
    assert verify_assessment(root)['status'] == 'PASS'
