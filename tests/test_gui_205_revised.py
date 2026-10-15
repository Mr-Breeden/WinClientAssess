"""Regression coverage for v2.0.5 Windows telemetry and GUI error/catalog fixes."""
from __future__ import annotations

import json
import threading
import http.client
from pathlib import Path
from unittest.mock import patch

from utils.web_worker import WebWorkerControl, atomic_json
from utils.gui_server import JobManager, make_server
from utils.gui_catalog import RecentAssessments
from tests.test_gui_200 import gui_headers, http_request


def test_capture_continues_after_persistent_windows_telemetry_access_denied(tmp_path, monkeypatch, capsys):
    """A failure of non-authoritative GUI statistics cannot abort Procmon."""
    from utils import web_worker
    folder = tmp_path / 'worker'; folder.mkdir()
    pml = tmp_path / 'live.pml'; pml.write_bytes(b'simulated existing Procmon PML')
    control = WebWorkerControl(folder)
    original = web_worker.atomic_json
    attempts = []
    def fail_telemetry(path, record):
        if Path(path).name == 'telemetry.json':
            attempts.append(1)
            raise PermissionError(5, 'Access denied for simulated telemetry write')
        return original(path, record)
    monkeypatch.setattr(web_worker, 'atomic_json', fail_telemetry)
    calls=[]
    def stop(message, **kw):
        assert kw['kind']=='continue' and kw['capture_ready'] is True
        calls.append(1)
        return 'continue'
    monkeypatch.setattr(control, 'ask', stop)
    result = control.capture(pml_path=pml, procmon_path='Procmon64.exe', started_at=0)
    assert calls and result['final_live_processes']==0
    assert len(attempts)==3
    assert control.telemetry_warning_emitted
    assert 'collection continues' in capsys.readouterr().out


def test_atomic_json_preserves_previous_record_after_windows_denied_replace(tmp_path, monkeypatch):
    from utils import web_worker
    target=tmp_path/'telemetry.json'
    atomic_json(target, {'version': 1})
    previous=target.read_bytes()
    def denied(src,dst):
        raise PermissionError(5, 'simulated Windows lock')
    monkeypatch.setattr(web_worker.os, 'replace', denied)
    try:
        atomic_json(target, {'version': 2})
    except PermissionError:
        pass
    else:
        raise AssertionError('Simulated access denied was not propagated')
    assert target.read_bytes()==previous
    assert not list(tmp_path.glob('*.new'))


def test_capture_checkpoint_survives_unavailable_telemetry(tmp_path, monkeypatch):
    folder=tmp_path/'worker';folder.mkdir()
    controller=WebWorkerControl(folder)
    def stop_via_pipe():
        import sys
        record=json.loads(controller.checkpoint_path.read_text())
        assert record['capture_ready'] is True
        # Can be stopped using the checkpoint without a telemetry.json file.
        return record
    def fake_capture_stop():
        for _ in range(200):
            if controller.checkpoint_path.exists():
                cp=stop_via_pipe()
                break
            threading.Event().wait(.01)
        else:
            raise AssertionError('No capture checkpoint')
        monkeypatch.setattr('sys.stdin', type('FakeStdin',(),{
            'readline': lambda self: json.dumps({'id':cp['id'],'answer':'continue'})+'\n'
        })())
    # The snapshot flag is returned to GUI clients independently of telemetry.
    import utils.gui_server as server
    class FakeProc:
        returncode=None
        stdin=None
        def poll(self): return None
    jobs=JobManager(catalog=RecentAssessments(tmp_path/'recent.json'))
    job_dir=Path(jobs.tempdir.name)/'testing';job_dir.mkdir()
    atomic_json(job_dir/'checkpoint.json', {'id':'abcd','kind':'continue',
        'message':'Stop capture', 'default':'', 'choices':[], 'capture_ready':True})
    log=job_dir/'worker.log';log.write_text('running')
    jobs.jobs['testing']={'process':FakeProc(), 'kind':'runtime', 'key':'k',
        'assessment':str(tmp_path), 'interactive':True,'log':log,'directory':job_dir,
        'sent_checkpoint':'','started_at':0}
    try:
        result=jobs.inspect('testing')
        assert result['checkpoint']['capture_ready'] is True
        assert 'telemetry' not in result
    finally:
        jobs.close()


def test_gui_errors_explain_operation_without_leaking_private_paths(tmp_path):
    cat=RecentAssessments(tmp_path/'test-catalog.json')
    jobs=JobManager(catalog=cat)
    srv=make_server(port=0,version='2.0.5', jobs=jobs,catalog=cat,token='testtoken')
    thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
    try:
        headers={'X-WCA-Token':'testtoken','Origin':f'http://127.0.0.1:{srv.server_port}'}
        status,_,body=http_request(srv,'POST','/api/job/respond',headers=headers,
             body={'confirmed':True,'id':'nonexistent','checkpoint_id':'abcd','answer':'continue'})
        data=json.loads(body)
        assert status==400 and data['ok'] is False
        assert data['operation']=='Worker checkpoint' and data['code']=='ACTION_REJECTED'
        assert data['outcome']=='NOT CONFIRMED' and data['next_step']
        assert 'C:\\Users\\' not in json.dumps(data)
        status,_,body=http_request(srv,'POST','/api/start',headers=headers,
             body={'confirmed':True,'kind':'runtime','assessment':'C:\\private\\test'})
        data=json.loads(body)
        assert status==400 and data['operation']=='Start Guided Runtime'
        assert 'C:\\private' not in json.dumps(data)
    finally:
        srv.shutdown();srv.server_close();thread.join(5);jobs.close()



def test_failed_backend_mutation_reports_operation_and_uncertain_outcome(tmp_path):
    cat=RecentAssessments(tmp_path/'private-recent.json')
    jobs=JobManager(catalog=cat)
    srv=make_server(port=0,version='2.0.5',jobs=jobs,catalog=cat,token='testtoken')
    thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
    try:
        headers={'X-WCA-Token':'testtoken','Origin':f'http://127.0.0.1:{srv.server_port}'}
        status,_,body=http_request(srv,'POST','/api/mutate',headers=headers,
              body={'confirmed':True,'action':'save_review','assessment':str(tmp_path/'missing'),
                    'candidate_id':'WCR-MISSING','disposition':'VALIDATED',
                    'fingerprint':'unknown','notes':''})
        reply=json.loads(body)
        assert status==409 and reply['ok'] is False
        assert reply['operation']=='Guided Review save'
        assert reply['outcome']=='NOT CONFIRMED'
        assert reply['next_step']
    finally:
        srv.shutdown();srv.server_close();thread.join(5);jobs.close()

def test_gui_page_offers_dismissible_history_and_capture_fallback():
    from utils.gui_server import PROJECT_ROOT
    html=(PROJECT_ROOT/'gui'/'index.html').read_text()
    js=(PROJECT_ROOT/'gui'/'app.js').read_text()
    css=(PROJECT_ROOT/'gui'/'app.css').read_text()
    assert 'notificationHistory' in html and 'notificationsBtn' in html
    assert 'Dismiss notification' in js and 'Copy diagnostics' in js
    assert 'cp?.capture_ready===true' in js
    assert 'notification-history' in css
    assert '.assessment-check input[type="checkbox"]' in css


def test_regression_tests_never_use_real_tester_catalog():
    from utils.gui_server import PROJECT_ROOT
    for filename in ('test_gui_200.py', 'test_gui_worker_202.py', 'test_gui_203.py'):
        text=(PROJECT_ROOT/'tests'/filename).read_text()
        for line in text.splitlines():
            if 'JobManager(' in line and not line.lstrip().startswith('#'):
                assert 'catalog=' in line, (filename,line)
