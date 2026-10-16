"""M2-p5: UAC privilege preflight, elevation refusal, and CLI exceptions."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import utils.elevation as elev


def test_nonuac_platform_is_safe(monkeypatch):
    monkeypatch.setattr(elev, '_windows', lambda: False)
    assert not elev.is_administrator()
    with pytest.raises(elev.ElevationError, match='Windows'):
        elev.launch_elevated(argv=['--gui'])


def test_runas_preserves_venv_script_arguments_and_cwd(monkeypatch, tmp_path):
    monkeypatch.setattr(elev, '_windows', lambda: True)
    events = []
    monkeypatch.setattr(elev, '_runas', lambda exe, params, cwd: events.append((exe,params,cwd)) or 42)
    script = tmp_path / 'source with spaces' / 'wca.py'
    argv = ['--gui', '--port', '9002', '--target', 'C:\\Some Folder\\installer (1).msi']
    elev.launch_elevated(executable=r'C:\venv\Scripts\python.exe',script=script,argv=argv,cwd=str(tmp_path))
    assert events == [(
        r'C:\venv\Scripts\python.exe',
        subprocess.list2cmdline([str(script.resolve()), *argv, '--wca-elevation-attempted']),
        str(tmp_path),
    )]


@pytest.mark.parametrize('shell_code', [0, 5, 32])
def test_uac_denied_fails_without_privileged_operation(monkeypatch, shell_code):
    monkeypatch.setattr(elev, '_windows', lambda: True)
    monkeypatch.setattr(elev, '_runas', lambda *_: shell_code)
    with pytest.raises(elev.ElevationError, match='declined or'):
        elev.launch_elevated(argv=['--gui'], executable='python.exe', script='wca.py')


def test_uac_os_error_is_caught(monkeypatch):
    monkeypatch.setattr(elev, '_windows', lambda: True)
    def failed(*_):
        raise OSError('cancelled')
    monkeypatch.setattr(elev, '_runas', failed)
    with pytest.raises(elev.ElevationError, match='could not start WCA'):
        elev.launch_elevated(argv=['--gui'], executable='python.exe', script='wca.py')


def test_marker_does_not_trigger_second_uac(monkeypatch):
    monkeypatch.setattr(elev, '_windows', lambda: True)
    monkeypatch.setattr(elev, '_runas', lambda *_: pytest.fail('UAC loop'))
    with pytest.raises(elev.ElevationError, match='already attempted'):
        elev.launch_elevated(argv=['--gui','--wca-elevation-attempted'])


def test_privilege_check_never_escalates_authenticated_gui_worker(monkeypatch):
    import wca
    monkeypatch.setattr(wca, '_windows_host', lambda: True)
    monkeypatch.setattr(wca, '_is_admin', lambda: False)
    monkeypatch.setattr(wca, 'WEB_CONTROL', object(), raising=False)
    monkeypatch.setattr(wca, 'launch_elevated', lambda: pytest.fail('unexpected UAC'))
    args = SimpleNamespace(wca_elevation_attempted=False, gui_preselected_options=True)
    with pytest.raises(SystemExit, match='elevated WCA GUI session'):
        wca._require_administrator(args, 'Full Assessment')


def test_declined_or_failed_uac_keeps_original_gui_closed(monkeypatch):
    import wca
    monkeypatch.setattr(wca, '_windows_host', lambda: True)
    monkeypatch.setattr(wca, '_is_admin', lambda: False)
    monkeypatch.setattr(wca, 'WEB_CONTROL', None, raising=False)
    def deny():
        raise elev.ElevationError('UAC declined')
    monkeypatch.setattr(wca, 'launch_elevated', deny)
    args = SimpleNamespace(wca_elevation_attempted=False, gui_preselected_options=False)
    with pytest.raises(SystemExit, match='UAC declined'):
        wca._require_administrator(args, 'WCA GUI')


def test_successful_uac_exits_unelevated_process(monkeypatch):
    import wca
    monkeypatch.setattr(wca, '_windows_host', lambda: True)
    monkeypatch.setattr(wca, '_is_admin', lambda: False)
    monkeypatch.setattr(wca, 'WEB_CONTROL', None, raising=False)
    started = []
    monkeypatch.setattr(wca, 'launch_elevated', lambda: started.append(True))
    args = SimpleNamespace(wca_elevation_attempted=False, gui_preselected_options=False)
    with pytest.raises(SystemExit) as e:
        wca._require_administrator(args, 'WCA GUI')
    assert e.value.code == 0 and started == [True]


def test_uac_not_repeated_after_failed_elevated_child(monkeypatch):
    import wca
    monkeypatch.setattr(wca, '_windows_host', lambda: True)
    monkeypatch.setattr(wca, '_is_admin', lambda: False)
    monkeypatch.setattr(wca, 'WEB_CONTROL', None, raising=False)
    monkeypatch.setattr(wca, 'launch_elevated', lambda: pytest.fail('unexpected retry'))
    args = SimpleNamespace(wca_elevation_attempted=True, gui_preselected_options=False)
    with pytest.raises(SystemExit, match='no further UAC attempts'):
        wca._require_administrator(args, 'WCA GUI')


def test_already_elevated_never_requests_uac(monkeypatch):
    import wca
    monkeypatch.setattr(wca, '_is_admin', lambda: True)
    monkeypatch.setattr(wca, 'launch_elevated', lambda: pytest.fail('unnecessary UAC'))
    wca._require_administrator(SimpleNamespace(), 'WCA GUI')


def test_early_gui_preflight_precedes_server_start(monkeypatch):
    import wca
    import utils.gui_server as server
    import utils.web_worker as worker
    monkeypatch.setattr(worker.WebWorkerControl, 'from_environment', lambda: None)
    monkeypatch.setattr(wca, '_windows_host', lambda: True)
    monkeypatch.setattr(wca, '_is_admin', lambda: False)
    monkeypatch.setattr(wca, 'launch_elevated', lambda: None)
    monkeypatch.setattr(server, 'serve_gui', lambda **_: pytest.fail('GUI should not start unelevated'))
    args = SimpleNamespace(gui=True, backend_action=None, target=None, installer=None,
                           status=None, review=None, guided_runtime=None, resume=None,
                           client_appendix=None, regenerate_reports=None,
                           gui_preselected_options=False, port=9001, wca_elevation_attempted=False)
    monkeypatch.setattr(wca, 'parse_args', lambda: args)
    with pytest.raises(SystemExit) as e:
        wca.main()
    assert e.value.code == 0


def test_gui_launches_without_reprompt_if_admin(monkeypatch):
    import wca
    import utils.gui_server as server
    import utils.web_worker as worker
    monkeypatch.setattr(worker.WebWorkerControl, 'from_environment', lambda: None)
    monkeypatch.setattr(wca, '_is_admin', lambda: True)
    start = []
    monkeypatch.setattr(server, 'serve_gui', lambda **kwargs: start.append(kwargs))
    args = SimpleNamespace(gui=True, backend_action=None, target=None, installer=None,
                           status=None, review=None, guided_runtime=None, resume=None,
                           client_appendix=None, regenerate_reports=None,
                           gui_preselected_options=False, port=9002, wca_elevation_attempted=False)
    monkeypatch.setattr(wca, 'parse_args', lambda: args)
    wca.main()
    assert start == [{'port':9002, 'version': '2.2.0'}]


def test_help_and_version_run_without_privilege_checks(tmp_path):
    import sys
    root = Path(__file__).resolve().parents[1]
    for arg in ('--version', '--help'):
        process = subprocess.run([sys.executable,str(root/'wca.py'),arg],cwd=root,capture_output=True,text=True,timeout=20)
        assert process.returncode == 0 and (('2.2.0' in process.stdout) if arg=='--version' else ('--gui' in process.stdout))


def _cli_args(mode):
    return SimpleNamespace(gui=False, backend_action=None, backend_format='json',
                           gui_preselected_options=False, wca_elevation_attempted=False,
                           mode=mode, guided_runtime=None, client_appendix=None,
                           review=None, status=None, verify_assessment=None,
                           regenerate_reports=None, resume=None)


def test_explicit_full_mode_requests_elevation_before_input_collection(monkeypatch):
    import wca
    import utils.web_worker as worker
    monkeypatch.setattr(worker.WebWorkerControl, 'from_environment', lambda: None)
    args = _cli_args('full')
    monkeypatch.setattr(wca, 'parse_args', lambda: args)
    monkeypatch.setattr(wca, '_interactive_entry', lambda args: args)
    monkeypatch.setattr(wca, '_windows_host', lambda: True)
    monkeypatch.setattr(wca, '_is_admin', lambda: False)
    monkeypatch.setattr(wca, 'launch_elevated', lambda: None)
    monkeypatch.setattr(wca, 'banner', lambda: None)
    monkeypatch.setattr(wca, 'resolve_inputs', lambda *_: pytest.fail('should not gather target before UAC'))
    with pytest.raises(SystemExit) as e:
        wca.main()
    assert e.value.code == 0


def test_static_cli_input_collection_does_not_request_elevation(monkeypatch):
    import wca
    import utils.web_worker as worker
    monkeypatch.setattr(worker.WebWorkerControl, 'from_environment', lambda: None)
    args = _cli_args('static')
    monkeypatch.setattr(wca, 'parse_args', lambda: args)
    monkeypatch.setattr(wca, '_interactive_entry', lambda args: args)
    monkeypatch.setattr(wca, 'banner', lambda: None)
    monkeypatch.setattr(wca, '_require_administrator', lambda *_: pytest.fail('static mode must not request UAC'))
    def reached_inputs(*_):
        raise RuntimeError('static inputs reached without elevation')
    monkeypatch.setattr(wca, 'resolve_inputs', reached_inputs)
    with pytest.raises(RuntimeError, match='static inputs reached'):
        wca.main()
