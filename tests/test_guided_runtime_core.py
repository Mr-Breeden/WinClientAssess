"""v1.7.0 Guided Runtime Observation and final v1.6.x guidance regressions."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from modules.guided_runtime_observation import (
    append_session,
    load_runtime_targets,
    load_assessment_filters,
    summarize_observation,
)
from tests.test_guided_review_navigation import assessment
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_layout import artifact_path
from utils.contextual_checks import checks
from utils.guided_review import read_review, save_decision
from utils.guided_runtime import run_guided_runtime, validate_guided_runtime_eligibility


def _pipe_item():
    return {
        'source_module': 'IPC / Named Pipe Review',
        'title': r'PipeServer.exe -> \\.\pipe\AcmeWidget',
        'evidence': r'Pipe: \\.\pipe\AcmeWidget',
        'artifacts': ['ipc_review.txt'],
    }


def _runtime_target_report(root: Path):
    artifact_path(root, 'runtime_targets.txt').write_text(r'''WINCLIENTASSESS - RUNTIME TARGET DISCOVERY
============================================================================================================
------------------------------------------------------------------------------------------------------------
[RT-001] AppService.exe
------------------------------------------------------------------------------------------------------------
Priority Score : 100
Role           : Service
Source         : New service
Path           : C:\Program Files\Acme\AppService.exe
Component      : AcmeService
Account        : LocalSystem
Run Level      : N/A
Note           : Acme Service

------------------------------------------------------------------------------------------------------------
[RT-002] Client.exe
------------------------------------------------------------------------------------------------------------
Priority Score : 90
Role           : Application
Source         : Filesystem added
Path           : C:\Program Files\Acme\Client.exe
Component      : N/A
Account        : N/A
Run Level      : N/A
Note           : N/A
''', encoding='utf-8')


def test_pipe_helper_live_resolves_bundled_script_and_portable_guidance_is_guarded():
    live = checks(_pipe_item(), console_paths=True)
    assert any('pipe_connect_probe.ps1' in command and command.startswith('& ') for command in live)
    assert all('Read-Host' not in command for command in live if 'pipe_connect_probe.ps1' in command)

    portable = checks(_pipe_item(), console_paths=False)
    helper = next(command for command in portable if 'pipe_connect_probe.ps1' in command)
    assert '$poc = $null; do {' in helper
    assert 'Test-Path -LiteralPath $poc -PathType Leaf' in helper
    assert '(Split-Path -Leaf $poc) -ine' in helper
    assert 'Blank values, directories, and other files are not accepted.' in helper
    assert '& $poc -PipeName' in helper
    assert '\n' not in helper and '\r' not in helper


def test_runtime_target_report_rehydrates_installed_target_identity(tmp_path):
    root = tmp_path / 'case'
    (root / 'reports').mkdir(parents=True)
    (root / 'working').mkdir()
    _runtime_target_report(root)
    rows = load_runtime_targets(root)
    assert len(rows) == 2
    assert rows[0]['Role'] == 'Service'
    assert rows[0]['Account'] == 'LocalSystem'
    assert rows[1]['ProcessName'] == 'Client.exe'

    artifact_path(root, 'assessment_filters.txt').write_text(r'''WINCLIENTASSESS - ASSESSMENT FILTERS
========================================================================================================

Target-only supporting inventory : True

EXCLUDED PATHS
--------------------------------------------------------------------------------------------------------
- C:\\Temp\\HostNoise
- C:\\ProgramData\\Ignore*

FILTERED DIFFERENTIAL RECORDS
--------------------------------------------------------------------------------------------------------
None.
''', encoding='utf-8')
    patterns, target_only = load_assessment_filters(root)
    assert target_only is True
    assert patterns == [r'C:\\Temp\\HostNoise', r'C:\\ProgramData\\Ignore*']


def test_guided_runtime_summary_distinguishes_observed_not_observed_and_unavailable():
    summary = summarize_observation(
        checklist={'launch_close': 'EXERCISED'},
        procmon_result={'procmon_data': {
            'relevant_rows': 4,
            'process_activity': [{'Process': 'Client.exe', 'Operation': 'Process Create', 'Path': r'C:\Windows\System32\cmd.exe', 'Result': 'SUCCESS'}],
            'loaded_images': [], 'file_writes': [], 'registry_writes': [],
            'network_activity': [],
        }},
        processes=[{'Name': 'AppService.exe', 'PID': 42, 'ParentName': 'services.exe', 'Exe': r'C:\Program Files\Acme\AppService.exe', 'Username': 'NT AUTHORITY\\SYSTEM'}],
        network_result={'coverage_gap': False, 'network_records': [], 'network_pois': []},
        ipc_result={'coverage_gap': True, 'ipc_records': [], 'ipc_pois': []},
        runtime_targets=[{'ProcessName': 'AppService.exe', 'Role': 'Service', 'Account': 'LocalSystem'}],
    )
    assert summary['surfaces']['process_tree']['status'] == 'OBSERVED'
    assert summary['surfaces']['file_writes']['status'] == 'NOT OBSERVED'
    assert summary['surfaces']['named_pipes']['status'] == 'COLLECTION UNAVAILABLE'
    assert summary['counts']['privileged_or_helper_processes'] == 1
    assert summary['processes'][0]['parent'] == 'services.exe'
    assert summary['processes'][0]['role'] == 'Service'


def test_append_session_keeps_bounded_history_and_single_authoritative_report(tmp_path):
    root = tmp_path / 'case'
    (root / 'reports').mkdir(parents=True)
    (root / 'working').mkdir()
    for idx in range(22):
        append_session(root, {'captured_at': f't{idx}', 'checklist': {}, 'surfaces': {}, 'counts': {}, 'privileged_processes': [], 'examples': {}, 'network': [], 'pipes': []})
    data = json.loads((root / 'working' / 'guided_runtime_observations.json').read_text())
    assert len(data['sessions']) == 20
    assert data['sessions'][0]['captured_at'] == 't2'
    assert artifact_path(root, 'guided_runtime_observation.txt').is_file()


def test_guided_runtime_eligibility_is_version_bound_and_integrity_gated(tmp_path):
    root = assessment(tmp_path, version='1.7.0')
    state, result = validate_guided_runtime_eligibility(root, '1.7.0')
    assert state.data['mode'] == 'full' and result['status'] == 'PASS'
    with pytest.raises(ValueError, match='version-bound'):
        validate_guided_runtime_eligibility(root, '1.7.1')
    artifact_path(root, 'findings.txt').write_text('tampered', encoding='utf-8')
    with pytest.raises(ValueError, match='integrity must be PASS'):
        validate_guided_runtime_eligibility(root, '1.7.0')


def test_guided_runtime_refresh_preserves_review_decision_and_manifest(tmp_path, monkeypatch):
    root = assessment(tmp_path, version='1.7.0')
    _runtime_target_report(root)
    create_manifest(root, framework_version='1.7.0', methodology_version='1.4', catalog_version='1.4')
    review = read_review(root)
    candidate = next(iter(review['items'].values()))
    save_decision(root, candidate['id'], 'INFORMATIONAL', 'Keep this decision')
    create_manifest(root, framework_version='1.7.0', methodology_version='1.4', catalog_version='1.4')

    stage_dir = tmp_path / 'guided-stage'
    stage_dir.mkdir()
    staged_capture = stage_dir / 'guided_runtime_capture.csv'
    staged_capture.write_text('Time of Day,Process Name,Operation,Path,Result\n', encoding='utf-8')

    fake = {
        'summary': {
            'captured_at': '2026-10-05T00:00:00Z', 'checklist': {},
            'surfaces': {
                'process_tree': {'status': 'OBSERVED', 'count': 1},
                'privileged_helpers': {'status': 'NOT OBSERVED', 'count': 0},
                'network': {'status': 'NOT OBSERVED', 'count': 0},
                'named_pipes': {'status': 'NOT OBSERVED', 'count': 0},
                'file_writes': {'status': 'NOT OBSERVED', 'count': 0},
                'registry_writes': {'status': 'NOT OBSERVED', 'count': 0},
                'loaded_images': {'status': 'NOT OBSERVED', 'count': 0},
                'updater_activity': {'status': 'NOT OBSERVED', 'count': 0},
            },
            'counts': {'correlated_processes': 1, 'procmon_target_events': 1},
            'privileged_processes': [], 'examples': {}, 'network': [], 'pipes': [],
            'collection': {'procmon': 'AVAILABLE', 'process_snapshot': 'AVAILABLE', 'network': 'AVAILABLE', 'ipc': 'AVAILABLE'},
        },
        'procmon': {'findings': []},
        'network': {'network_pois': []},
        'ipc': {'ipc_pois': []},
        'processes': [],
        'staged_evidence': {'working/guided_runtime_capture.csv': str(staged_capture)},
        'staging_dir': str(stage_dir),
    }
    monkeypatch.setattr('utils.guided_runtime.run_guided_collectors', lambda *a, **k: fake)
    monkeypatch.setattr('utils.guided_runtime.detect_tools', lambda: {})
    answers = iter(['y', 'a', 'n', 'n', 'n', 'a'])
    result = run_guided_runtime(
        root, version='1.7.0', methodology_version='1.4', catalog_version='1.4',
        input_fn=lambda _: next(answers), output_fn=lambda _: None,
        interactive_collectors=False,
    )
    assert result['after']['status'] == 'PASS'
    assert result['sessions'] == 1
    after = read_review(root)
    assert after['items'][candidate['id']]['status'] == 'INFORMATIONAL'
    assert after['items'][candidate['id']]['notes'] == 'Keep this decision'
    assert artifact_path(root, 'guided_runtime_observation.txt').is_file()
    assert artifact_path(root, 'working/guided_runtime_capture.csv').read_text(encoding='utf-8').startswith('Time of Day')
    assert not stage_dir.exists()
    dashboard = artifact_path(root, 'assessment_report.html').read_text(encoding='utf-8')
    assert 'Guided Runtime Observation' in dashboard
    assert 'Sessions retained: 1' in dashboard
    assert 'guided_runtime_observation.txt' in dashboard
    assert verify_assessment(root)['status'] == 'PASS'
