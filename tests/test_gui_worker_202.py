"""v2.0.5: browser-owned manual checkpoints and background-job safety."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import utils.gui_server as gui
from tests.test_gui_200 import gui_headers, http_request
from utils.web_worker import WebWorkerControl
from utils.gui_catalog import RecentAssessments


def _wait_for(condition, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = condition()
        if result:
            return result
        time.sleep(.06)
    raise AssertionError('Timed out waiting for the background worker.')


def _worker_script():
    return '''import os
from utils.web_worker import WebWorkerControl
from utils.gui_catalog import RecentAssessments
c=WebWorkerControl.from_environment()
print('worker ready', flush=True)
assert c.confirm('Use optional target observation?', default=False)
print('step one', flush=True)
assert c.prompt('Press Enter after tester installation is complete', default='') == ''
print('step two', flush=True)
assert c.prompt('Choose option', choices=['a','b']) == 'b'
print('worker completed', flush=True)
'''


def test_browser_worker_checkpoint_roundtrip_without_console(tmp_path, monkeypatch):
    root = tmp_path / 'case'
    worker = gui.JobManager(version='2.0.5', catalog=RecentAssessments(tmp_path / 'private-catalog.json'))
    command = [sys.executable, '-u', '-c', _worker_script()]
    monkeypatch.setattr(gui, '_validated_job_inputs', lambda payload: (root, command, 'full'))
    try:
        result = worker.start('assessment', {})
        jobid = result['id']
        assert not any('powershell' in str(part).lower() for part in command)
        assert worker.list_jobs()[0]['id'] == jobid
        def checkpoint():
            status = worker.inspect(jobid)
            return status.get('checkpoint')
        first = _wait_for(checkpoint)
        assert first['kind'] == 'confirm' and first['default'] == 'no'
        with pytest.raises(ValueError, match='has changed'):
            worker.respond(jobid, 'wrong', 'yes')
        with pytest.raises(ValueError, match='does not match the pending'):
            worker.respond(jobid, first['id'], 'continue')
        assert worker.respond(jobid, first['id'], 'yes')['accepted']
        with pytest.raises(ValueError, match='already sent'):
            worker.respond(jobid, first['id'], 'yes')
        second = _wait_for(lambda: (cp if (cp := checkpoint()) and cp['id'] != first['id'] else None))
        assert second['kind'] == 'continue'
        worker.respond(jobid, second['id'], 'continue')
        third = _wait_for(lambda: (cp if (cp := checkpoint()) and cp['id'] != second['id'] else None))
        assert third['kind'] == 'choice' and third['choices'] == ['a', 'b']
        worker.respond(jobid, third['id'], 'b')
        final = _wait_for(lambda: (j if (j := worker.inspect(jobid))['state'] == 'COMPLETED' else None))
        assert 'worker completed' in final['log']
        assert 'checkpoint' not in final
        assert worker.list_jobs()[0]['state'] == 'COMPLETED'
    finally:
        for job in worker.jobs.values():
            if job['process'].poll() is None:
                job['process'].kill()
                job['process'].wait(timeout=5)
        worker.close()


def test_browser_worker_api_auth_and_checkpoint_confirmation(monkeypatch, tmp_path):
    root = tmp_path / 'case'
    jobs = gui.JobManager(catalog=RecentAssessments(tmp_path / 'private-catalog.json'))
    monkeypatch.setattr(gui, '_validated_job_inputs',
                        lambda payload: (root, [sys.executable, '-u', '-c', _worker_script()], 'full'))
    server = gui.make_server(port=0, version='2.0.5', jobs=jobs, token='test-web-worker')
    import threading
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        h = gui_headers(server, token='test-web-worker')
        status, _, body = http_request(server, 'POST', '/api/start', headers=h,
                                       body={'confirmed': True, 'kind': 'assessment'})
        assert status == 201, body
        jobid = json.loads(body)['job']['id']
        cp = _wait_for(lambda: jobs.inspect(jobid).get('checkpoint'))
        assert http_request(server, 'GET', '/api/jobs')[0] == 403
        assert http_request(server, 'POST', '/api/job/respond',
                            body={'confirmed': True, 'id': jobid, 'checkpoint_id': cp['id'], 'answer': 'yes'})[0] == 403
        status, _, _ = http_request(server, 'POST', '/api/job/respond', headers=h,
                                     body={'confirmed': False, 'id': jobid,
                                           'checkpoint_id': cp['id'], 'answer': 'yes'})
        assert status == 400
        status, _, body = http_request(server, 'POST', '/api/job/respond', headers=h,
                                       body={'confirmed': True, 'id': jobid,
                                             'checkpoint_id': cp['id'], 'answer': 'yes'})
        assert status == 200 and json.loads(body)['accepted']
        assert http_request(server, 'GET', '/api/jobs', headers=h)[0] == 200
    finally:
        for item in jobs.jobs.values():
            if item['process'].poll() is None:
                item['process'].kill()
                item['process'].wait(timeout=5)
        server.shutdown();server.server_close();thread.join(timeout=5);jobs.close()


def test_closed_worker_input_fails_closed_without_implicit_confirmation(tmp_path, monkeypatch):
    from io import StringIO
    import utils.web_worker as mod
    monkeypatch.setattr(mod.sys, 'stdin', StringIO(''))
    control = WebWorkerControl(tmp_path)
    with pytest.raises(RuntimeError, match='not confirmed'):
        control.ask('Install target manually', kind='continue')
    assert not control.checkpoint_path.exists()


def test_web_worker_source_never_launches_targets_or_pocs():
    source = Path('utils/web_worker.py').read_text(encoding='utf-8')
    gui_source = Path('utils/gui_server.py').read_text(encoding='utf-8')
    assert 'CREATE_NEW_CONSOLE' not in gui_source
    assert 'powershell.exe' not in gui_source
    assert 'CREATE_NO_WINDOW' in gui_source
    assert 'subprocess.Popen' not in source
    assert '/api/job/respond' in gui_source
    script = Path('gui/app.js').read_text(encoding='utf-8')
    assert 'wcaActiveJob' in script
    assert 'renderCheckpoint' in script
    assert 'renderTelemetry' in script
    assert 'Stop capture / Continue' in script


def test_web_mode_uses_tester_confirmations_not_rich_console(monkeypatch):
    import wca
    class FakeControl:
        def __init__(self):
            self.seen = []
        def confirm(self, message, default=False):
            self.seen.append(('confirm', message, default))
            return True
        def prompt(self, message, *, default='', choices=None):
            self.seen.append(('prompt', message, default))
            return 'continue'
    control = FakeControl()
    monkeypatch.setattr(wca, 'WEB_CONTROL', control)
    assert wca.web_confirm('Run optional surface collection?', default=False) is True
    assert wca.web_prompt('Press Enter after approved activity', default='') == 'continue'
    assert [item[0] for item in control.seen] == ['confirm', 'prompt']


def test_live_capture_emits_metrics_and_waits_for_stop(tmp_path):
    job_dir = tmp_path / 'private_job'
    job_dir.mkdir()
    trace = tmp_path / 'trace.pml'
    trace.write_bytes(b'test capture metrics fixture')
    code = '''import os
from pathlib import Path
from utils.web_worker import WebWorkerControl
from utils.gui_catalog import RecentAssessments
c=WebWorkerControl.from_environment()
r=c.capture(pml_path=Path(os.environ['TEST_TRACE_PATH']),started_at=None,runtime_targets=[],exclude_paths=[])
print('CAPTURE_STOPPED',r['final_live_processes'],flush=True)
'''
    env = dict(os.environ, WCA_WEB_WORKER_DIRECTORY=str(job_dir), TEST_TRACE_PATH=str(trace),
               PYTHONUNBUFFERED='1')
    process = subprocess.Popen([sys.executable, '-u', '-c', code], env=env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, cwd=str(Path.cwd()))
    try:
        cp_path = job_dir / 'checkpoint.json'
        cp = _wait_for(lambda: json.loads(cp_path.read_text()) if cp_path.exists() else None)
        telemetry_file = job_dir / 'telemetry.json'
        data = _wait_for(lambda: json.loads(telemetry_file.read_text()) if telemetry_file.exists() else None, timeout=6)
        assert data['pml_size_bytes'] == trace.stat().st_size
        assert data['current_target_processes'] == 0
        assert process.poll() is None  # The capture must NOT end automatically.
        process.stdin.write((json.dumps({'id': cp['id'], 'answer': 'continue'})+'\n').encode())
        process.stdin.flush()
        stdout, stderr = process.communicate(timeout=8)
        assert process.returncode == 0, stderr.decode(errors='replace')
        assert b'CAPTURE_STOPPED' in stdout
        assert not cp_path.exists() and not telemetry_file.exists()
    finally:
        if process.poll() is None:
            process.kill();process.wait(timeout=5)


def test_same_version_recovery_is_eligible_but_cross_version_resume_is_blocked(tmp_path, monkeypatch):
    import utils.backend_service as backend
    from types import SimpleNamespace
    shared = {'framework_version': '2.0.5', 'assessment_name': 'fixture',
              'mode': 'full', 'target': {'type': 'installable'}, 'stages': {}}
    def describe(_root):
        return {'kind': 'structured', 'status': 'IN_PROGRESS', 'stage': 'installation_confirmation',
                'action': 'INSTALL', 'guidance': '', 'state': SimpleNamespace(data=shared)}
    monkeypatch.setattr(backend, 'describe_assessment', describe)
    monkeypatch.setattr(backend, 'verify_assessment', lambda _root: {'status':'FAIL', 'repairable':False,'checks':[], 'damaged':{}})
    current = backend.BackendService(version='2.0.5').execute('status', tmp_path)
    assert 'resume_assessment_cli_only' in current['data']['available_actions']
    shared['framework_version'] = '2.0.1'
    previous = backend.BackendService(version='2.0.5').execute('status', tmp_path)
    assert previous['data']['recovery_action'] == 'HALT'
    assert 'resume_assessment_cli_only' not in previous['data']['available_actions']


def test_capability_text_identifies_gui_mutations_correctly():
    from utils.backend_service import capabilities, envelope
    from utils.backend_format import render_backend_text
    cap = capabilities('2.0.5')
    assert cap['operations']['run_assessment']['mutates'] is True
    assert cap['operations']['guided_runtime']['requires_explicit_tester_action'] is True
    text = render_backend_text('capabilities', envelope(True, 'OK', 'Capabilities', cap))
    assert 'GUI worker / CLI' in text
