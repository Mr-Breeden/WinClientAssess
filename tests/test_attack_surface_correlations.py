"""Positive/negative attack-surface correlation cases with privacy/mode gating."""
from __future__ import annotations
import csv
from pathlib import Path

from modules.attack_surface_correlations import detect_indicators, run_attack_surface_correlations
from utils.contextual_checks import checks
from utils.poc_playbooks import CATEGORIES, category_matches, render_plan, candidate_poc


class StubAcl:
    def __init__(self, writable=()):
        self.writable = {p.lower() for p in writable}
        self.visited = []

    def get_many(self, paths, batch_size=75):
        self.visited += paths
        return {p.lower(): {'Exists': True, 'Access': [
            {'Type': 'Allow', 'Identity': 'BUILTIN\\Users', 'Rights': 'Modify'}
            if p.lower() in self.writable else
            {'Type': 'Allow', 'Identity': 'BUILTIN\\Users', 'Rights': 'ReadAndExecute'}
        ]} for p in paths}


def fixture(tmp_path, *, rows=(), targets=('Widget.exe',)):
    root = tmp_path / 'case'
    (root / 'reports').mkdir(parents=True)
    (root / 'working').mkdir()
    csv_path = root / 'working' / 'procmon_target_events.csv'
    with csv_path.open('w', newline='', encoding='utf-8-sig') as fh:
        w = csv.DictWriter(fh, fieldnames=['Process Name','Operation','Result','Path'])
        w.writeheader()
        w.writerows(rows)
    return root, {'target_filter_active': True}, [{'ProcessName': name, 'Path': (r'C:\ProgramData\Widget\Widget.exe' if name == 'Widget.exe' else '')} for name in targets]


def exe_row(process='Widget.exe', path=r'C:\ProgramData\Widget\worker.exe', result='NAME NOT FOUND'):
    return {'Process Name': process, 'Operation': 'CreateFile', 'Result': result, 'Path': path}


def test_exe_positive_exact_lookups_and_target_acl(tmp_path):
    root, proc, targets = fixture(tmp_path, rows=[exe_row(), exe_row(), exe_row(process='Other.exe')])
    acl = StubAcl([r'C:\ProgramData\Widget'])
    items, coverage = detect_indicators(root, mode='full', diff={'Filesystem': {'added': []}},
                                        procmon=proc, targets=targets, acl_cache=acl)
    assert len(items) == 1
    assert items[0]['Category'] == 'Executable/helper search-path hijacking'
    assert items[0]['Path'] == r'C:\ProgramData\Widget\worker.exe'
    assert coverage['Executable/helper search-path hijacking'] == 'AUTOMATIC INDICATOR'
    assert acl.visited == [r'C:\ProgramData\Widget']


def test_exe_negative_no_writable_acl_or_target_or_csv(tmp_path):
    root, proc, targets = fixture(tmp_path, rows=[exe_row(), exe_row(process='Host.exe',path=r'C:\Users\Public\unsafe.exe')])
    items, coverage = detect_indicators(root, mode='full', diff={'Filesystem': {'added': []}},
                                        procmon=proc, targets=targets, acl_cache=StubAcl())
    assert not items
    assert coverage['Executable/helper search-path hijacking'] == 'NOT OBSERVED'
    items, coverage = detect_indicators(root, mode='full', diff={'Filesystem': {'added': []}},
                                        procmon={'target_filter_active': False}, targets=targets, acl_cache=StubAcl())
    assert not items
    assert coverage['Executable/helper search-path hijacking'] == 'COLLECTION UNAVAILABLE'


def test_ifeo_and_com_target_attribution_and_negative_noise(tmp_path):
    root, proc, targets = fixture(tmp_path)
    proc['registry_writes'] = [
        {'Process': 'Widget.exe', 'Operation': 'RegSetValue', 'Path': r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Widget.exe\Debugger'},
        {'Process': 'Widget.exe', 'Operation': 'RegSetValue', 'Path': r'HKCU\Software\Classes\CLSID\{12345678-1234-1234-1234-123456789abc}\InprocServer32'},
        {'Process': 'Unrelated.exe', 'Operation': 'RegSetValue', 'Path': r'HKCU\Software\Classes\CLSID\{12345678-1234-1234-1234-123456789abc}\InprocServer32'},
        {'Process': 'Widget.exe', 'Operation': 'RegSetValue', 'Path': r'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Other.exe\Debugger'},
    ]
    items, coverage = detect_indicators(root, mode='full', diff={'Filesystem': {'added': []}},
                                        procmon=proc, targets=targets, acl_cache=StubAcl())
    assert [i['Category'] for i in items] == ['IFEO / SilentProcessExit injection', 'COM registration and activation hijacking']
    assert coverage['IFEO / SilentProcessExit injection'] == coverage['COM registration and activation hijacking'] == 'AUTOMATIC INDICATOR'
    proc['registry_writes'] = proc['registry_writes'][2:]
    items, coverage = detect_indicators(root, mode='full', diff={'Filesystem': {'added': []}},
                                        procmon=proc, targets=targets, acl_cache=StubAcl())
    assert not items
    assert coverage['IFEO / SilentProcessExit injection'] == 'NOT OBSERVED'


def test_reparse_positive_negative_and_legacy_unavailable(tmp_path):
    root, proc, targets = fixture(tmp_path)
    before = {'Metadata': {'FilesystemIncluded': True}, 'Filesystem': [{'Path':'C:\\ProgramData','IsReparsePoint':False}]}
    after = {'Metadata': {'FilesystemIncluded': True}, 'Filesystem': [{'Path':'C:\\ProgramData','IsReparsePoint':False}]}
    diff = {'Filesystem': {'added':[{'Path': r'C:\ProgramData\Widget\Stage', 'IsReparsePoint':True,'LinkType':'Junction'}]}}
    items, coverage = detect_indicators(root, mode='full', diff=diff, pre=before, post=after, procmon=proc, targets=targets)
    assert any(i['Category'] == 'Reparse point / symlink / junction abuse' for i in items)
    assert coverage['Reparse point / symlink / junction abuse'] == 'AUTOMATIC INDICATOR'
    diff['Filesystem']['added'] = [{'Path': r'C:\ProgramData\Widget\Stage', 'IsReparsePoint':False}]
    items, coverage = detect_indicators(root, mode='full', diff=diff, pre=before, post=after, procmon=proc, targets=targets)
    assert coverage['Reparse point / symlink / junction abuse'] == 'NOT OBSERVED'
    after['Filesystem'][0].pop('IsReparsePoint')
    _, coverage = detect_indicators(root, mode='full', diff=diff, pre=before, post=after, procmon=proc, targets=targets)
    assert coverage['Reparse point / symlink / junction abuse'] == 'COLLECTION UNAVAILABLE'


def test_candidate_context_and_plan_categories(tmp_path):
    root, proc, targets = fixture(tmp_path, rows=[exe_row()])
    result = run_attack_surface_correlations(root, 'full', {'Filesystem': {'added': []}}, {}, {}, proc, targets,
                                           StubAcl([r'C:\ProgramData\Widget']))
    assert len(result['findings']) == 1
    candidate = dict(result['findings'][0], source_module='Attack Surface Correlations',id='WCR-FAKE')
    cmds = checks(candidate, root)
    assert "icacls 'C:\\ProgramData\\Widget'" in cmds[0]
    assert 'worker.exe' in cmds[1]
    assert len(CATEGORIES) >= 20
    assert any(entry[0] == "Heap memory corruption" for entry in CATEGORIES)
    assert category_matches('Executable/helper search-path hijacking', '', [candidate]) == [candidate]
    assert any('marker_exe.c' not in x for x in candidate_poc(candidate))
    render_plan(root, {'items': {'WCR-FAKE': candidate}})
    plan = (root/'reports'/'attack_surface_test_plan.txt').read_text()
    assert 'WINDOWS THICK CLIENT ATTACK SURFACE TEST PLAN' in plan
    assert 'not tied to any single application' in plan.lower()
    assert 'HEAP MEMORY CORRUPTION' in plan
    assert 'AUTOMATIC INDICATOR - MANUAL VALIDATION REQUIRED' in plan
    assert 'NOT OBSERVED IN COLLECTED EVIDENCE' in plan
    assert 'COLLECTION UNAVAILABLE' in plan


def test_no_static_mode_runtime_output_or_unverified_process_calls(tmp_path):
    root, proc, targets = fixture(tmp_path, rows=[exe_row()])
    found, coverage = detect_indicators(root, mode='static', diff={'Filesystem': {'added':[{'Path':'C:\\ProgramData'}]}},
                                         procmon=proc, targets=targets, acl_cache=StubAcl())
    assert not found and set(coverage.values()) == {'COLLECTION UNAVAILABLE'}
    assert not (root/'reports'/'attack_surface_correlations.txt').exists()  # main CLI skips static collector


def test_script_packaging_marker_and_readonly_probes():
    project = Path(__file__).resolve().parents[1]
    for filename in ('marker_dll.c', 'marker_exe.c', 'proof_identity.h', 'reparse_inventory.ps1',
                     'com_registration_probe.ps1', 'inspect_proof.ps1', 'pipe_connect_probe.ps1'):
        assert (project/'scripts'/'poc'/filename).is_file()
    for filename in ('marker_dll.c', 'marker_exe.c'):
        s = (project/'scripts'/'poc'/filename).read_text()
        assert 'INTEGRITY_RID=%lu' in s
        assert 'wca_integrity_rid()' in s


def test_full_dashboard_and_manifest_source_tamper_refusal(tmp_path):
    """The new source-backed report must link from HTML and remain fail-closed."""
    import pytest
    from utils.assessment_state import AssessmentState
    from utils.assessment_integrity import create_manifest, verify_assessment, regenerate_derived_reports
    from utils.reporting import AssessmentReporter

    root, proc, targets = fixture(tmp_path, rows=[exe_row()])
    installer = tmp_path / 'setup.msi'
    installer.write_bytes(b'fixture-only')
    tracker = AssessmentState.create(root, assessment_name='synthetic positive fixture', installer=installer,
                                     mode='full', framework_version='1.6.2', options={}, tools={})
    outcome = run_attack_surface_correlations(root, 'full', {'Filesystem': {'added': []}}, {}, {}, proc, targets,
                                            StubAcl([r'C:\ProgramData\Widget']))
    reporter = AssessmentReporter(root, 'synthetic positive fixture', installer, 'full', '1.6.2', state_tracker=tracker)
    reporter.set_status('Attack Surface Correlations', outcome['status'], outcome['details'],
                        coverage_gap=outcome['coverage_gap'])
    for finding in outcome['findings']:
        reporter.add_finding(source_module='Attack Surface Correlations', **finding)
    reporter.finalize()
    tracker.mark_complete('COMPLETE')
    create_manifest(root, framework_version='1.6.2', methodology_version='1.3', catalog_version='1.3')
    assert verify_assessment(root)['status'] == 'PASS'
    html = (root / 'reports' / 'assessment_report.html').read_text(encoding='utf-8')
    assert 'attack_surface_correlations.txt' in html
    assert 'Attack Surface Correlations' in html
    assert 'Undocumented validated' not in html
    assert 'Executable/helper search-path hijacking' in (root / 'reports' / 'attack_surface_test_plan.txt').read_text()

    # Only the regenerated dashboard is damaged: repair is allowed from intact sources.
    dashboard = root / 'reports' / 'assessment_report.html'
    dashboard.write_text(html + '\n<!-- altered -->', encoding='utf-8')
    damaged = verify_assessment(root)
    assert damaged['status'] == 'FAIL' and damaged['repairable']
    assert regenerate_derived_reports(root)['status'] == 'PASS'

    # The collector TXT itself is primary evidence; generic regeneration must REFUSE.
    correlation = root / 'reports' / 'attack_surface_correlations.txt'
    correlation.write_text(correlation.read_text() + '\naltered source evidence\n')
    damaged = verify_assessment(root)
    assert damaged['status'] == 'FAIL' and not damaged['repairable']
    with pytest.raises(ValueError):
        regenerate_derived_reports(root)


def test_distinct_same_basename_exe_candidates_keep_independent_ids(tmp_path):
    from utils.guided_review import sync_review
    root, proc, targets = fixture(tmp_path)
    results = [
        {'title': 'Executable/helper search-path hijacking: App.exe -> worker.exe', 'severity': 'Informational',
         'source_module': 'Attack Surface Correlations',
         'evidence': 'Category: Executable/helper search-path hijacking\nProcess: App.exe\nPath: C:\\ProgramData\\A\\worker.exe',
         'artifacts': ['attack_surface_correlations.txt']},
        {'title': 'Executable/helper search-path hijacking: App.exe -> worker.exe', 'severity': 'Informational',
         'source_module': 'Attack Surface Correlations',
         'evidence': 'Category: Executable/helper search-path hijacking\nProcess: App.exe\nPath: C:\\ProgramData\\B\\worker.exe',
         'artifacts': ['attack_surface_correlations.txt']},
    ]
    result = sync_review(root, results)
    assert len(result['items']) == 2
    assert len(set(result['items'])) == 2
    assert {i['component'] for i in result['items'].values()} == {
        r'C:\ProgramData\A\worker.exe', r'C:\ProgramData\B\worker.exe'
    }
    assert set(sync_review(root, results)['items']) == set(result['items'])


def test_no_injection_from_untrusted_executable_path(tmp_path):
    root, _, _ = fixture(tmp_path)
    malicious = {'source_module': 'Attack Surface Correlations',
                 'title': 'Executable/helper search-path hijacking',
                 'evidence': 'Category: Executable/helper search-path hijacking\n'
                             'Path: C:\\ProgramData\\Widget\\work.exe\'; Remove-Item C:\\\\ -Recurse\n'
                             'Directory: C:\\ProgramData\\Widget\n'}
    commands = checks(malicious, root)
    # PowerShell single-quoted arguments must escape embedded quote characters.
    assert "work.exe''; Remove-Item" in commands[1]
    assert not any('<AFFECTED_PATH>' in command for command in commands)


def test_reparse_ignores_unrelated_host_junctions(tmp_path):
    root, proc, targets = fixture(tmp_path)
    before = {'Metadata': {'FilesystemIncluded': True},
              'Filesystem': [{'Path': r'C:\ProgramData', 'IsReparsePoint': False}]}
    after = {'Metadata': {'FilesystemIncluded': True},
             'Filesystem': [{'Path': r'C:\ProgramData', 'IsReparsePoint': False}]}
    diff = {'Filesystem': {'added': [
        {'Path': r'C:\ProgramData\DifferentProduct\Stage', 'IsReparsePoint': True, 'LinkType': 'Junction'},
    ]}}
    items, coverage = detect_indicators(root, mode='full', diff=diff, pre=before, post=after,
                                        procmon=proc, targets=targets)
    assert not items
    assert coverage['Reparse point / symlink / junction abuse'] == 'NOT OBSERVED'
    # Without a verified target installation root, even a complete snapshot
    # cannot establish whether an unrelated reparse point belongs to this app.
    items, coverage = detect_indicators(root, mode='full', diff=diff, pre=before, post=after,
                                        procmon=proc, targets=[{'ProcessName': 'Widget.exe'}])
    assert coverage['Reparse point / symlink / junction abuse'] == 'COLLECTION UNAVAILABLE'
