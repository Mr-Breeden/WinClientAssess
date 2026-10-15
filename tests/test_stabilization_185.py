"""Vendor-neutral regression fixtures for v1.8.5 portable/runtime fixes."""
import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from modules.application_profile import run_application_profile
from modules.guided_runtime_observation import GuidedRuntimeLiveController, load_runtime_targets
from modules.local_storage_review import (_portable_roots_from_loaded_images,
                                         _runtime_storage_paths, run_local_storage_review)
from modules.runtime_process_review import collect_runtime_processes
from utils.contextual_checks import checks


def test_portable_target_hash_rehydrated_without_profile_path(tmp_path):
    (tmp_path / 'reports').mkdir()
    (tmp_path / 'working').mkdir()
    (tmp_path / 'reports' / 'runtime_targets.txt').write_text(
        '------------------------------\nPriority Score : 30\nSource : Static/extracted candidate\n'
        'Path : Client.exe\nRole : Application\n------------------------------\n'
        'Priority Score : 20\nPath : %SOURCE_DIR%\\helper.exe\n'
    )
    hashvalue = 'f' * 64
    (tmp_path / 'working' / 'assessment_state.json').write_text(json.dumps({
        'target': {'type': 'portable', 'primary_executable': 'Client.exe', 'sha256': hashvalue},
        'framework_version': '1.8.5',
    }))
    targets = load_runtime_targets(tmp_path)
    primary = next(t for t in targets if t['ProcessName'] == 'Client.exe')
    assert primary['PrimarySHA256'] == hashvalue
    assert 'PortablePrimary' in primary
    assert 'SOURCE_DIR' not in primary['Path']
    assert all('users\\' not in t['Path'].lower() for t in targets)


def test_portable_primary_hash_correlates_only_real_binary_and_same_root_helper(tmp_path, monkeypatch):
    import modules.runtime_process_review as module
    root = tmp_path / 'selected'; root.mkdir()
    other = tmp_path / 'unrelated'; other.mkdir()
    main = root / 'Client.exe'; main.write_bytes(b'correct-selected-primary-fixture')
    decoy = other / 'Client.exe'; decoy.write_bytes(b'unrelated-file-content')
    helper = root / 'helper.exe'; helper.write_bytes(b'helper')
    shadow = other / 'helper.exe'; shadow.write_bytes(b'decoy helper')
    selected_hash = hashlib.sha256(main.read_bytes()).hexdigest()

    class FakeProcess:
        def __init__(self, pid, path):
            self.pid, self.path = pid, str(path)
        def oneshot(self): return nullcontext()
        def ppid(self): return 1
        def name(self): return Path(self.path).name
        def exe(self): return self.path
        def username(self): return 'fixture'
        def status(self): return 'running'
        def cmdline(self): return []
        def create_time(self): return 123456.0 + self.pid
        def parent(self): return None
        def io_counters(self): return type('IO', (), {'read_count': 1, 'write_count': 2})()
        def cpu_times(self): return type('CPU', (), {'user': 0.2, 'system': 0.1})()

    procs = [FakeProcess(1, decoy), FakeProcess(2, helper), FakeProcess(3, main), FakeProcess(4, shadow)]
    monkeypatch.setattr(module.psutil, 'process_iter', lambda: iter(procs))
    monkeypatch.setattr(module.psutil, 'Process', lambda pid: next(p for p in procs if p.pid == pid))
    monkeypatch.setattr(module, '_network_by_pid', lambda: {})
    result = collect_runtime_processes([
        {'Path': 'Client.exe', 'ProcessName': 'Client.exe', 'PrimarySHA256': selected_hash, 'PortablePrimary': True},
        {'Path': '%SOURCE_DIR%\\helper.exe', 'ProcessName': 'helper.exe'},
    ])
    assert {p['PID'] for p in result} == {2, 3}
    assert {p['IdentitySource'] for p in result} == {'Selected primary executable SHA-256', 'Verified portable application directory'}
    assert all('IoCounters' in p for p in result)


def test_live_controller_tracks_process_changes_without_claiming_procmon_event_counts():
    widget = GuidedRuntimeLiveController([], refresh_seconds=0.5)
    p = {'PID': 40, 'CreateTime': '2026-01-01', 'Name': 'Client.exe',
         'NetworkConnections': [], 'IoCounters': {'read_count': 4, 'write_count': 1}, 'CpuSeconds': 1.0}
    assert widget._observe_activity([p], 20)[2] == 1
    p['IoCounters'] = {'read_count': 8, 'write_count': 3}; p['CpuSeconds'] = 1.5
    assert widget._observe_activity([p], 21)[:2] == (6, 0.5)
    panel = widget._render(elapsed=25, pml_size=123, growth_age=10, processes=[p], connections=0,
                           activity=(6,0.5,0,0), now=21)
    from rich.console import Console
    from io import StringIO
    output = StringIO(); Console(file=output, width=130, force_terminal=False).print(panel)
    text = output.getvalue()
    assert 'I/O changes' in text and 'Target activity' in text
    assert 'after capture' in text


def test_portable_storage_roots_require_matching_loaded_image_and_process(tmp_path, monkeypatch):
    import modules.local_storage_review as mod
    targets = [{'Path': 'Client.exe', 'ProcessName': 'Client.exe'}]
    procmon = {
        'loaded_images': [
            {'Process': 'Client.exe', 'Path': r'%USERPROFILE%\Desktop\TargetApp\Client.exe'},
            {'Process': 'Host.exe', 'Path': r'C:\Other\Host.exe'},
        ],
        'file_writes': [
            {'Process': 'Client.exe', 'Path': r'%USERPROFILE%\Desktop\TargetApp\logs\audit.log', 'Operation': 'WriteFile'},
            {'Process': 'Client.exe', 'Path': r'%USERPROFILE%\Desktop\TargetApp\data\session.tmp', 'Operation': 'WriteFile'},
            {'Process': 'Client.exe', 'Path': r'C:\Windows\System32\unrelated.log', 'Operation': 'WriteFile'},
            {'Process': 'Host.exe', 'Path': r'%USERPROFILE%\Desktop\TargetApp\unrelated.log', 'Operation': 'WriteFile'},
        ],
        'registry_writes': [],
    }
    roots = _portable_roots_from_loaded_images(procmon, targets)
    assert len(roots) == 1
    files, registry = _runtime_storage_paths(procmon, targets)
    assert len(files) == 2 and not registry
    assert all('Application directory' in item['Area'] for item in files.values())
    monkeypatch.setattr(mod, 'association_roots', lambda *args: [])
    monkeypatch.setattr(mod, 'target_identity_tokens', lambda **kwargs: (set(), []))
    monkeypatch.setattr(mod, 'read_msi_properties', lambda *args: {})
    report = run_local_storage_review(tmp_path, procmon_data=procmon, runtime_targets=targets,
                                      filesystem_evidence=False)
    assert len(report['storage_records']) == 2
    assert 'audit.log' in (tmp_path / 'local_storage_review.txt').read_text()
    assert 'unrelated.log' not in (tmp_path / 'local_storage_review.txt').read_text()


def test_guided_profile_recovers_portable_identity_metadata(tmp_path):
    (tmp_path / 'target_analysis.txt').write_text(
        'Product Name : Fixture Desktop Product\nProduct Version : 4.5.6\nCompany : Example Vendor\n')
    result = run_application_profile(tmp_path, 'full')
    text = (tmp_path / 'application_profile.txt').read_text()
    assert result['profile']['product_name'] == 'Fixture Desktop Product'
    assert result['profile']['product_version'] == '4.5.6'
    assert 'Example Vendor' in text


def test_managed_source_guidance_points_to_specific_category_and_lines(tmp_path):
    case = {'source_module': '.NET Detection / Source Review',
            'title': 'Managed Source SQL / input handling Requires Validation',
            'evidence': '4 first-party categorized source-line indicator(s)'}
    commands = checks(case, tmp_path, console_paths=True)
    assert 'dotnet_source_review.txt' in commands[0]
    assert 'SQL EXECUTION' in commands[0]
    assert 'FIRST-PARTY' in commands[1]
    assert 'dotnet_analysis.txt' not in '\n'.join(commands)
