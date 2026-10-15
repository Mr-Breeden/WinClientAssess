"""v2.0.5 GUI capture-controller compatibility and tester preselected workflow tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from utils.assessment_layout import ensure_structured_layout
from utils.gui_server import _validated_job_inputs
from utils.web_worker import WebWorkerControl


def test_capture_interface_accepts_real_collector_signature(tmp_path, monkeypatch):
    from modules import procmon_capture
    root = tmp_path / 'sample'
    ensure_structured_layout(root)
    job_dir = tmp_path / 'job'
    job_dir.mkdir()
    # Fake Procmon START, terminator, PML export and sanitization; no Windows
    # app or operating-system process is executed in this regression test.
    monkeypatch.setattr(procmon_capture, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(procmon_capture, '_is_admin', lambda: True)
    monkeypatch.setattr(procmon_capture.time, 'sleep', lambda *_: None)
    startup = []
    class FakeProcmon:
        def __init__(self, command, **kwargs):
            startup.append(command)
            Path(command[command.index('-backingfile') + 1]).write_bytes(b'PML fixture')
    monkeypatch.setattr(procmon_capture.subprocess, 'Popen', FakeProcmon)
    monkeypatch.setattr(procmon_capture, 'run_command', lambda *a, **k: {'returncode': 0, 'stdout': '', 'stderr': ''})
    def export(command, **kwargs):
        Path(command[command.index('-saveas') + 1]).write_text('Process Name,Operation\nfixture.exe,CreateFile\n')
        return {'returncode': 0, 'stdout': '', 'stderr': '', 'elapsed_seconds': 1}
    monkeypatch.setattr(procmon_capture, '_run_with_heartbeat', export)
    def sanitize(src, dest, **kwargs):
        dest.write_text('Process Name,Operation\nfixture.exe,CreateFile\n')
        return {'rows': 1, 'source_rows': 1, 'redaction_count': 0, 'sensitive_names': [], 'target_filter_active': True}
    monkeypatch.setattr(procmon_capture, 'sanitize_procmon_csv', sanitize)
    controller = WebWorkerControl(job_dir)
    captured = {}
    def confirmed_stop(message, **kwargs):
        for _ in range(50):
            if controller.telemetry_path.exists():
                break
            threading.Event().wait(0.01)
        telemetry = json.loads(controller.telemetry_path.read_text(encoding='utf-8'))
        assert telemetry['capture_ready'] and telemetry['pml_size_bytes'] > 0
        captured['stop_enabled'] = True
        return 'continue'
    monkeypatch.setattr(controller, 'ask', confirmed_stop)
    result = procmon_capture.run_procmon_capture(
        root, {'Procmon': {'path': 'Procmon64.exe'}},
        capture_controller=lambda **kwargs: controller.capture(**kwargs, runtime_targets=[], exclude_paths=[]),
        target_process_names=['fixture.exe'],
    )
    assert result['status'] == 'PASS', result
    assert result['csv_path'] is not None
    assert result['sanitization']['rows'] == 1
    assert result['session']['failure_stage'] == ''
    assert captured['stop_enabled']
    assert not controller.telemetry_path.exists()


def test_capture_controller_error_does_not_produce_successful_csv(tmp_path, monkeypatch):
    from modules import procmon_capture
    ensure_structured_layout(tmp_path)
    monkeypatch.setattr(procmon_capture, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(procmon_capture, '_is_admin', lambda: True)
    monkeypatch.setattr(procmon_capture.time, 'sleep', lambda *_: None)
    class FakeProcmon:
        def __init__(self, command, **kwargs):
            Path(command[command.index('-backingfile') + 1]).write_bytes(b'PML fixture')
    monkeypatch.setattr(procmon_capture.subprocess, 'Popen', FakeProcmon)
    monkeypatch.setattr(procmon_capture, 'run_command', lambda *a, **k: {'returncode': 0, 'stdout': '', 'stderr': ''})
    def fail(**kwargs):
        raise RuntimeError('simulated GUI controller failure')
    result = procmon_capture.run_procmon_capture(tmp_path, {'Procmon': {'path': 'Procmon64.exe'}}, capture_controller=fail)
    assert result['status'] == 'WARN'
    assert result['csv_path'] is None
    assert result['session']['failure_stage'] == 'capture_controller'
    assert 'simulated GUI controller failure' in result['details']


def test_gui_options_default_and_opt_out_and_strict_validation(tmp_path, monkeypatch):
    from utils import gui_server
    target = tmp_path / 'installer.msi';target.write_bytes(b'test')
    output = tmp_path / 'outputs';output.mkdir()
    payload = dict(target=str(target), output=str(output), name='Case', mode='static', target_type='installable')
    root, argv, mode = _validated_job_inputs(payload)
    assert root == output / 'Case' and mode == 'static'
    assert '--non-interactive' in argv and '--gui-preselected-options' not in argv
    options = {**payload, 'extract_installer': False, 'filesystem_snapshot': False, 'surface_review': False}
    _, argv, _ = _validated_job_inputs(options)
    assert '--no-extract' in argv and '--no-filesystem-snapshot' in argv
    with pytest.raises(ValueError, match='Yes/No'):
        _validated_job_inputs({**payload, 'surface_review': 'false'})
    with pytest.raises(ValueError, match='requires full'):
        _validated_job_inputs({**payload, 'runtime_capture': True})


def test_full_mode_preselection_omits_extra_checkpoints(tmp_path, monkeypatch):
    from utils import gui_server
    # Platform gate is checked by full-mode on Windows; mimic only that guard
    # while retaining real host filesystem paths.
    original_os = gui_server.os
    monkeypatch.setattr(gui_server, 'os', SimpleNamespace(name='nt', path=original_os.path))
    target = tmp_path / 'installer.msi';target.write_bytes(b'test')
    output = tmp_path / 'outputs';output.mkdir()
    payload = dict(target=str(target), output=str(output), name='Full', mode='full', target_type='installable')
    _, argv, _ = _validated_job_inputs(payload)
    assert '--gui-preselected-options' in argv and '--surface-review' in argv
    assert '--runtime-capture' not in argv
    _, argv, _ = _validated_job_inputs({**payload, 'surface_review': False, 'runtime_capture': True})
    assert '--surface-review' not in argv and '--runtime-capture' in argv


def test_gui_runtime_browser_controls_and_review_expand_all_are_present():
    from utils.gui_server import PROJECT_ROOT
    html = (PROJECT_ROOT/'gui'/'index.html').read_text(encoding='utf-8')
    js = (PROJECT_ROOT/'gui'/'app.js').read_text(encoding='utf-8')
    assert 'Stop Guided Runtime Observation' in html
    assert "j.telemetry?.capture_ready===true" in js
    assert 'reviewExpandAll' in html and 'reviewCollapseAll' in html
    assert 'state.guideOpen.set(key,details.open)' in js
    assert "$('globalJobStatus').addEventListener('click',()=>go('dashboard'));" in js
    assert 'optSurface' in html and 'optCapture' in html


def test_no_gui_preselection_allowed_without_private_worker():
    from utils.gui_server import PROJECT_ROOT
    process = subprocess.run(
        [sys.executable, str(PROJECT_ROOT / 'wca.py'), '--gui-preselected-options',
         '--backend-action', 'capabilities'], capture_output=True, text=True,
        encoding='utf-8',
        env={key: value for key, value in os.environ.items() if key != 'WCA_WEB_WORKER_DIRECTORY'},
    )
    assert process.returncode != 0
    assert 'local GUI worker' in process.stderr
