"""v2.0.5 navigation, catalog, runtime-history, help, and security regressions."""
from __future__ import annotations

from http.client import HTTPConnection
import json
import threading
from pathlib import Path

import pytest

from utils.gui_catalog import RecentAssessments
from utils.gui_server import JobManager, make_server, overview_snapshot, runtime_history


def fixture_assessment(tmp_path: Path, name='sample-assessment') -> Path:
    root = tmp_path / 'assessments' / name
    (root / 'working').mkdir(parents=True)
    (root / 'reports').mkdir()
    state = {'framework_version': '2.0.5', 'assessment_name': name, 'mode': 'full',
             'status': 'COMPLETED', 'coverage': 'COMPLETE', 'target': {'type': 'installable'},
             'created_at': '2026-10-12T08:00:00Z', 'updated_at': '2026-10-12T09:00:00Z'}
    (root / 'working' / 'assessment_state.json').write_text(json.dumps(state), encoding='utf-8')
    return root


def test_catalog_persists_outside_assessment_and_discovers_selected_siblings(tmp_path):
    root = fixture_assessment(tmp_path, 'full')
    other = fixture_assessment(tmp_path, 'static')
    (other / 'working' / 'assessment_state.json').write_text(json.dumps({
        'framework_version': '2.0.2', 'assessment_name': 'static', 'mode': 'static',
        'status': 'COMPLETED', 'target': {'type': 'installable'}, 'updated_at': '2026-10-11T12:00:00Z'}))
    catalog = RecentAssessments(path=tmp_path / 'tester-only' / 'recent.json')
    catalog.remember(root)
    restarted = RecentAssessments(path=catalog.path)
    rows = restarted.list_recent()
    assert {r['name'] for r in rows} == {'static', 'full'}
    assert all(r['integrity'] == 'NOT VERIFIED' for r in rows)
    assert '2.0.2' in {r['framework_version'] for r in rows}
    assert not (root / 'working' / 'recent.json').exists()
    assert not (root / 'reports' / 'recent.json').exists()
    assert catalog.path.is_file()


def test_catalog_missing_directory_does_not_silently_delete_entry(tmp_path):
    root = fixture_assessment(tmp_path)
    cat = RecentAssessments(tmp_path/'recent.json');cat.remember(root)
    import shutil
    shutil.rmtree(root)
    assert str(root) in cat._read()['paths']
    assert cat.list_recent()[0]['state'] == 'MISSING / UNAVAILABLE'


def test_runtime_history_reports_existing_sessions_without_manual_capture(monkeypatch, tmp_path):
    from utils import gui_server
    root = fixture_assessment(tmp_path)
    data = {'schema_version': 3, 'sessions': [
        {'captured_at': '2026-10-12T12:00:00Z', 'capture': {'status': 'PASS'},
         'session': {'capture_duration_seconds': 35, 'processing_duration_seconds': 88},
         'counts': {'procmon_target_events': 6195, 'target_processes_seen': 9},
         'new_review_candidates': 4},
        {'captured_at': '2026-10-12T13:00:00Z', 'capture': {'status': 'WARN'},
         'session': {'capture_duration_seconds': 12}, 'counts': {'procmon_target_events': 100}},
    ]}
    (root/'working'/'guided_runtime_observations.json').write_text(json.dumps(data))
    monkeypatch.setattr(gui_server, 'verify_assessment', lambda _: {'status': 'PASS'})
    history = runtime_history(root)
    assert history['total'] == 2 and history['state'] == 'COMPLETED WITH GAPS'
    assert history['sessions'][0]['events'] == 100
    assert history['sessions'][1]['target_processes'] == 9
    assert 'examples' not in str(history)
    monkeypatch.setattr(gui_server, 'verify_assessment', lambda _: {'status': 'FAIL'})
    with pytest.raises(ValueError, match='integrity'):
        runtime_history(root)


def test_runtime_history_not_run_and_no_unsafe_file(monkeypatch, tmp_path):
    root = fixture_assessment(tmp_path)
    assert runtime_history(root, verified=True)['state'] == 'NOT RUN'
    (root/'working'/'guided_runtime_observations.json').write_text('wrong')
    with pytest.raises(ValueError):
        runtime_history(root, verified=True)


def http(server, path, method='GET', payload=None, token=True):
    connection = HTTPConnection('127.0.0.1', server.server_port, timeout=6)
    headers = {'Origin': f'http://127.0.0.1:{server.server_port}'}
    if token:
        headers['X-WCA-Token'] = 'session-secret'
    if payload is not None:
        headers['Content-Type'] = 'application/json'
        payload = json.dumps(payload)
    connection.request(method, path, payload, headers)
    response = connection.getresponse()
    result = response.status, json.loads(response.read())
    connection.close()
    return result


@pytest.fixture()
def server(tmp_path):
    cat = RecentAssessments(tmp_path/'tester-only'/'recent.json')
    jobs = JobManager(version='2.0.5', catalog=cat)
    srv = make_server(port=0, version='2.0.5', jobs=jobs, catalog=cat, token='session-secret')
    thread = threading.Thread(target=srv.serve_forever, daemon=True);thread.start()
    yield srv
    srv.shutdown();srv.server_close();thread.join(timeout=6);jobs.close()


def test_new_endpoints_enforce_session_token(server):
    for route in ('/api/about', '/api/recent', '/api/help?doc=getting-started', '/api/runtime-history'):
        assert http(server,route,token=False)[0] == 403
    assert http(server,'/api/select',method='POST',payload={'assessment':'C:/fake'},token=False)[0] == 403


def test_about_help_and_recent_routes(server, tmp_path):
    about = http(server,'/api/about');assert about[0] == 200
    assert about[1]['version'] == '2.0.5' and about[1]['methodology'] == '1.9'
    status, doc = http(server,'/api/help?doc=getting-started')
    assert status == 200 and 'Stop Capture' in doc['content']
    assert http(server,'/api/help?doc=../../wca.py')[0] == 400
    root = fixture_assessment(tmp_path)
    status, info = http(server,'/api/select',method='POST',payload={'assessment':str(root)})
    assert status == 200
    status, info = http(server,'/api/recent')
    assert status == 200 and info['assessments'][0]['name'] == 'sample-assessment'
    assert info['assessments'][0]['integrity'] == 'NOT VERIFIED'
    assert http(server,'/api/select',method='POST',payload={'assessment':str(tmp_path)})[0] == 400


def test_browser_assets_have_stable_browse_and_worker_scrolling_controls():
    js = Path('gui/app.js').read_text(encoding='utf-8')
    html = Path('gui/index.html').read_text(encoding='utf-8')
    assert "querySelectorAll('.browse')" in js
    assert 'loadRecent' in js and '/api/overview?' in js
    assert "log.textContent=incoming" in js and 'nearBottom' in js
    assert "jobData').replaceChildren" not in js
    assert 'state.pollBusy' in js
    assert 'runtimeStopBtn' in js and 'CAPTURING' in js and 'PROCESSING' in js
    assert 'page-management' in html and 'page-help' in html
    assert 'recentTable' in html and 'data-pick="folder"' in html
    assert html.count('id="resumeBtn"') == 1
    assert html.count('id="regenerateBtn"') == 1
    assert 'manual' not in js.lower().split('eval(')  # no shell / eval construction


def test_tool_versions_do_not_execute_external_programs(monkeypatch):
    from utils import tool_versions
    assert tool_versions.pe_version(None) == 'Not verified'
    assert tool_versions.pe_version('fake.bat') == 'Not verified'
    monkeypatch.setattr('utils.tool_detection.detect_tools', lambda: {
        'Mock': {'found': True, 'path': 'C:/fake/tool.exe'},
        'Missing': {'found': False, 'path': None}})
    rows = tool_versions.detected_versions()
    assert rows[0]['version'] == 'Not installed'
    assert rows[1]['version'] == 'Not verified'


def test_windows_script_checks_current_version_exactly():
    script = Path("scripts/validate_windows.ps1").read_text(encoding="utf-8")
    assert "-notmatch 'WCA 2\\.1\\.0'" in script
