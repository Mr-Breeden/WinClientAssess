"""v1.6.5 field corrections for external-tool and installer guidance."""
from __future__ import annotations

from tests.test_guided_review_navigation import assessment
from utils.contextual_checks import checks
from utils.guided_review import guided_review_cli, validation_commands
from utils.validation_clipboard import powershell_checks


def _pipe_item():
    return {
        'source_module': 'IPC / Named Pipe Review',
        'title': r'PipeServer.exe -> \\.\pipe\AcmeWidget',
        'evidence': r'Pipe: \\.\pipe\AcmeWidget',
        'artifacts': ['ipc_review.txt'],
    }


def test_live_pipe_check_uses_exact_handle_variant_detected():
    tools = {
        'Handle': {
            'found': True,
            'path': r'C:\Users\Tester\AppData\Local\Microsoft\WindowsApps\handle.exe',
            'level': 'RECOMMENDED',
            'usage': 'INTEGRATED',
        }
    }
    command = checks(_pipe_item(), console_paths=True, tools=tools)[0]
    assert command.startswith("& 'C:\\Users\\Tester\\AppData\\Local\\Microsoft\\WindowsApps\\handle.exe'")
    assert " -accepteula -a 'AcmeWidget'" in command
    assert 'handle64.exe' not in command


def test_portable_pipe_check_resolves_supported_handle_variants_without_private_path():
    command = checks(_pipe_item(), console_paths=False)[0]
    assert command.startswith('$tool = Get-Command ')
    assert "'handle64.exe','handle.exe'" in command
    assert '& $tool.Source' in command
    assert 'C:\\Users\\' not in command
    assert 'tool_paths.json' in command


def test_signature_prompt_strips_quotes_and_rejects_directory_or_wrong_type():
    item = {'source_module': 'Digital Signature Review', 'title': 'Installer signature',
            'evidence': '', 'artifacts': ['signature_review.txt']}
    commands = validation_commands(item)
    first = commands[0]
    assert '.Trim([char]34).Trim([char]39)' in first
    assert 'Test-Path -LiteralPath $target -PathType Leaf' in first
    assert "GetExtension($target) -notin '.msi','.exe'" in first
    assert 'including the filename' in first
    assert 'Get-AuthenticodeSignature -LiteralPath $target' in first
    assert commands[1] == 'Get-FileHash -LiteralPath $target -Algorithm SHA256'
    assert '\n' not in first and '\r' not in first


def test_clipboard_keeps_guarded_installer_selection_as_one_command():
    item = {'source_module': 'Digital Signature Review', 'title': 'Installer signature',
            'evidence': '', 'artifacts': ['signature_review.txt']}
    copied = powershell_checks(list(validation_commands(item)))
    executable = [line for line in copied.splitlines() if line and not line.startswith('#')]
    assert len(executable) == 2
    assert executable[0].startswith('$target = $null; do {')
    assert executable[1].startswith('Get-FileHash -LiteralPath $target')


def test_copy_confirmation_explains_single_line_commands_and_multiline_clipboard(tmp_path, monkeypatch):
    root = assessment(tmp_path, version='1.6.5')
    copied = []
    monkeypatch.setattr('utils.validation_clipboard.copy_windows_text', copied.append)
    actions = iter(['2', 'c', '0'])
    output = []
    guided_review_cli(root, input_fn=lambda _: next(actions), output_fn=output.append)
    text = '\n'.join(output)
    assert 'complete PowerShell command' in text
    assert 'Each command is preserved as a single line' in text
    assert 'multiple commands are separated by line breaks' in text
    assert copied and '\r\n' in copied[0]
