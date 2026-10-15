"""v1.9.2 release: no external editor/VS Code subprocess promotion."""
from __future__ import annotations

import csv
from pathlib import Path

from modules.procmon_analysis import analyze_procmon_csv
from utils.sensitive_data import sanitize_procmon_csv
from utils.procmon_scope import trusted_roots, in_target_scope
from utils.consolidated_report import _action_center
from utils.html_theme import THEME_CSS

HEADERS = ['Time of Day', 'Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail']


def _write(path: Path, rows):
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=HEADERS)
        writer.writeheader()
        for i, (name, op, path_value) in enumerate(rows):
            writer.writerow({'Time of Day': f'10:00:{i:02}', 'Process Name': name, 'PID': i+10,
                             'Operation': op, 'Path': path_value, 'Result': 'SUCCESS', 'Detail': ''})


def _sample_rows():
    return [
        ('VulnDesk.exe', 'Process Create', r'C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe'),
        ('Code.exe', 'Process Create', r'C:\Windows\System32\cmd.exe'),
        ('cmd.exe', 'WriteFile', r'C:\Temp\wsl.txt'),
        ('Code.exe', 'ReadFile', r'C:\Users\tester\AppData\Roaming\Code\data.dat'),
        ('VulnDesk.exe', 'Process Create', r'C:\Users\tester\Desktop\VulnDesk\TrustedHelper.exe'),
        ('TrustedHelper.exe', 'WriteFile', r'C:\Users\tester\Desktop\VulnDesk\data\settings.ini'),
        ('Unrelated.exe', 'WriteFile', r'C:\Temp\noise.txt'),
    ]


def test_vulndesk_external_editor_stays_direct_launch_evidence(tmp_path):
    raw, scoped = tmp_path / 'raw.csv', tmp_path / 'scoped.csv'
    _write(raw, _sample_rows())
    result = sanitize_procmon_csv(raw, scoped, target_process_names=['VulnDesk.exe'],
                                  target_executable_paths=[r'C:\Users\tester\Desktop\VulnDesk\VulnDesk.exe'])
    text = scoped.read_text(encoding='utf-8-sig')
    assert result['rows'] == 3
    assert result['source_rows'] == 7
    assert 'Code.exe' not in result['tracked_process_names']
    assert 'cmd.exe' not in result['tracked_process_names']
    assert 'trustedhelper.exe' in result['tracked_process_names']
    assert 'Microsoft VS Code\\Code.exe' in text  # Direct target launch is evidence.
    assert 'System32\\cmd.exe' not in text          # External editor's child is not target.
    assert 'TrustedHelper.exe' in text
    data = analyze_procmon_csv(scoped, [{'ProcessName': 'VulnDesk.exe',
                                         'Path': r'C:\Users\tester\Desktop\VulnDesk\VulnDesk.exe'}],
                               additional_tracked_names=result['tracked_process_names'])
    assert data['relevant_rows'] == 3
    assert set(data['observed_process_names']) == {'VulnDesk.exe', 'TrustedHelper.exe'}
    assert len(data['process_activity']) == 2
    assert all(event['Process'] != 'Code.exe' for event in data['process_activity'])


def test_raw_import_does_not_promote_third_party_shell(tmp_path):
    raw = tmp_path / 'raw.csv'
    _write(raw, _sample_rows())
    data = analyze_procmon_csv(raw, [{'ProcessName': 'VulnDesk.exe',
                                      'Path': r'C:\Users\tester\Desktop\VulnDesk\VulnDesk.exe'}])
    assert data['relevant_rows'] == 3
    assert 'Code.exe' not in data['tracked_process_names']
    assert 'cmd.exe' not in data['tracked_process_names']
    assert 'trustedhelper.exe' in data['tracked_process_names']


def test_unverified_child_fails_closed_and_process_start_is_not_a_launch(tmp_path):
    raw, dest = tmp_path/'raw.csv', tmp_path/'filtered.csv'
    _write(raw, [('Client.exe', 'Process Start', r'C:\App\Helper.exe'),
                 ('Helper.exe','WriteFile', r'C:\App\state.txt'),
                 ('Client.exe', 'Process Create', r'C:\Windows\System32\cmd.exe'),
                 ('cmd.exe', 'ReadFile', r'C:\Windows\hosts')])
    result = sanitize_procmon_csv(raw, dest, target_process_names=['Client.exe'])
    assert result['rows'] == 2
    assert result['tracked_process_names'] == ['client.exe']


def test_trusted_roots_not_broadened_to_windows_or_program_files():
    assert not trusted_roots([r'C:\Program Files\x.exe', r'C:\Windows\x.exe', r'C:\x.exe'])
    roots = trusted_roots([r'C:\Program Files\Vendor\app.exe'])
    assert in_target_scope(r'C:\Program Files\Vendor\helper.exe', roots)
    assert not in_target_scope(r'C:\Program Files\Other\Code.exe', roots)
    assert not in_target_scope(r'C:\Windows\System32\cmd.exe', roots)


def test_action_center_distinguishes_observations_from_collection_gaps(tmp_path):
    status = {'Managed Source Review': {'status': 'WARN', 'coverage_gap': False},
              'Runtime': {'status': 'PASS', 'coverage_gap': False}}
    state = {'items': {'a': {'id':'a','status':'VALIDATED'}}}
    html = _action_center(state, tmp_path, 'COMPLETE', status)
    assert '1 modules with review observations' in html
    assert '0 collection gaps/failures' in html
    assert 'review-complete' in html
    assert 'Next review actions' not in html
    status['Network'] = {'status': 'WARN', 'coverage_gap': True}
    html = _action_center(state, tmp_path, 'COMPLETE_WITH_OPTIONAL_GAPS', status)
    assert '1 collection gaps/failures' in html
    assert 'Coverage follow-up' in html
    assert 'Network' in html


def test_mobile_long_coverage_wrapping():
    assert 'overflow-wrap:anywhere' in THEME_CSS
    assert 'max-width:100%' in THEME_CSS
