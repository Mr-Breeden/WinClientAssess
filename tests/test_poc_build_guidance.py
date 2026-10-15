from pathlib import Path

from utils.poc_playbooks import candidate_validation
from utils.assessment_layout import artifact_path


def _write_pe_report(root: Path, name='Beeper.exe', arch='x64'):
    (root / 'reports').mkdir(parents=True, exist_ok=True)
    (root / 'working').mkdir(parents=True, exist_ok=True)
    artifact_path(root, 'binary_security_review.txt').write_text(
        f'[PE-0001] C:\\Program Files\\Example\\{name}\n  Architecture : {arch}\n',
        encoding='utf-8',
    )


def test_dll_candidate_gets_architecture_specific_build_and_verification(tmp_path):
    _write_pe_report(tmp_path, 'Beeper.exe', 'x64')
    item = {
        'source_module': 'DLL Search Review',
        'title': 'Beeper.exe -> Shared.dll',
        'component': 'Beeper.exe -> Shared.dll',
        'evidence': 'Process : Beeper.exe\nMissing DLL : C:\\ProgramData\\Example\\Shared.dll\n',
    }
    plan = candidate_validation(item, tmp_path, console_paths=False)
    assert plan['requires_compilation'] == 'YES'
    assert plan['target_architecture'] == 'x64'
    assert plan['expected_output'] == 'Shared.dll'
    joined = '\n'.join(plan['build_or_invocation'])
    assert 'cl /nologo /LD /Fe:Shared.dll marker_dll.c advapi32.lib' in joined
    assert 'x86_64-w64-mingw32-gcc' in joined
    assert 'i686-w64-mingw32-gcc' not in joined
    assert any('Get-FileHash' in x for x in plan['verification'])
    assert any('pefile' in x for x in plan['verification'])


def test_x86_exe_candidate_gets_x86_recipe(tmp_path):
    _write_pe_report(tmp_path, 'Launcher.exe', 'x86')
    item = {
        'source_module': 'Attack Surface Correlations',
        'title': 'Launcher.exe -> Helper.exe',
        'component': 'Launcher.exe -> Helper.exe',
        'evidence': 'Category : Executable/helper search-path hijacking\nProcess : Launcher.exe\nPath : C:\\ProgramData\\Example\\Helper.exe\n',
    }
    plan = candidate_validation(item, tmp_path)
    assert plan['target_architecture'] == 'x86'
    assert plan['expected_output'] == 'Helper.exe'
    joined = '\n'.join(plan['build_or_invocation'])
    assert 'i686-w64-mingw32-gcc' in joined
    assert 'x86_64-w64-mingw32-gcc' not in joined


def test_powershell_helper_is_no_compile_with_candidate_invocation(tmp_path):
    item = {
        'source_module': 'IPC / Named Pipe Review',
        'title': r'PipeServer.exe -> \\.\pipe\ExamplePipe',
        'component': r'PipeServer.exe -> \\.\pipe\ExamplePipe',
        'evidence': r'PipeServer.exe -> \\.\pipe\ExamplePipe',
    }
    plan = candidate_validation(item, tmp_path)
    assert plan['requires_compilation'] == 'NO'
    assert plan['target_architecture'] == 'Not applicable'
    assert any("-PipeName 'ExamplePipe'" in x for x in plan['build_or_invocation'])
