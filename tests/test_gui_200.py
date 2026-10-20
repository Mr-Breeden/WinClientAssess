"""v2.0.0 local GUI security, packaging, and assessment CLI delegation tests."""
from __future__ import annotations

import http.client
import json
import re
import threading
from pathlib import Path

import pytest

from utils.gui_catalog import RecentAssessments
from utils.gui_server import (JobManager, _validated_job_inputs,
                              list_reports, make_server, read_report)


@pytest.fixture()
def running_gui(tmp_path):
    jobs = JobManager(catalog=RecentAssessments(tmp_path / 'private-catalog.json'))
    server = make_server(port=0, version='2.0.0', jobs=jobs, token='known-test-token')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        jobs.close()


def http_request(server, method, path, *, headers=None, body=None):
    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
    headers = headers or {}
    if body is not None:
        headers.setdefault('Content-Type', 'application/json')
        body = json.dumps(body)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    raw = response.read()
    result = response.status, dict(response.getheaders()), raw
    connection.close()
    return result


def gui_headers(server, token='known-test-token'):
    return {'X-WCA-Token': token, 'Origin': f'http://127.0.0.1:{server.server_port}'}


def test_loopback_only_listener_and_self_contained_assets(running_gui):
    assert running_gui.server_address[0] == '127.0.0.1'
    status, headers, content = http_request(running_gui, 'GET', '/')
    assert status == 200
    html = content.decode()
    assert 'Windows Client Assessment' in html and 'known-test-token' not in html
    assert '2.0.0' in html and '__WCA_BOOTSTRAP__' not in html
    assert "default-src 'none'" in headers['Content-Security-Policy']
    assert headers['X-Frame-Options'] == 'DENY'
    for resource in ('/app.css', '/app.js'):
        status, _, content = http_request(running_gui, 'GET', resource)
        assert status == 200 and content
    assert 'https://' not in (Path('gui/index.html').read_text() + Path('gui/app.css').read_text())


def test_backend_requires_ephemeral_token(running_gui):
    path = '/api/backend?action=capabilities'
    assert http_request(running_gui, 'GET', path)[0] == 403
    assert http_request(running_gui, 'GET', path, headers={'X-WCA-Token': 'wrong'})[0] == 403
    status, _, content = http_request(running_gui, 'GET', path, headers=gui_headers(running_gui))
    result = json.loads(content)
    assert status == 200 and result['data']['version'] == '2.0.0'
    assert result['data']['interface']['gui'] and result['data']['interface']['http_server']
    assert result['schema'] == '1.0'


def test_rejects_wrong_host_and_cross_origin(running_gui):
    route = '/api/backend?action=capabilities'
    assert http_request(running_gui, 'GET', route, headers={'Host': 'attacker.example', 'X-WCA-Token': 'known-test-token'})[0] == 403
    assert http_request(running_gui, 'GET', route, headers={'X-WCA-Token': 'known-test-token', 'Origin': 'https://attacker.example'})[0] == 403
    assert http_request(running_gui, 'GET', route, headers={'X-WCA-Token': 'known-test-token', 'Sec-Fetch-Site': 'cross-site'})[0] == 403
    assert http_request(running_gui, 'GET', route, headers={'X-WCA-Token': 'known-test-token', 'Origin': f'http://localhost:{running_gui.server_port}'})[0] == 403


def test_mutation_requires_token_and_explicit_confirmation(running_gui):
    payload = {'action': 'export_appendix', 'assessment': '/missing', 'output': '/tmp/result.zip'}
    route = '/api/mutate'
    assert http_request(running_gui, 'POST', route, body=payload)[0] == 403
    assert http_request(running_gui, 'POST', route, headers=gui_headers(running_gui), body=payload)[0] == 400
    payload['confirmed'] = True
    status, _, data = http_request(running_gui, 'POST', route, headers=gui_headers(running_gui), body=payload)
    assert status == 409 and json.loads(data)['ok'] is False
    assert http_request(running_gui, 'POST', '/api/start', headers=gui_headers(running_gui), body={'kind': 'assessment'})[0] == 400


def test_denies_arbitrary_endpoints_and_oversized_payloads(running_gui):
    headers = gui_headers(running_gui)
    assert http_request(running_gui, 'GET', '/api/backend?action=save_review', headers=headers)[0] == 400
    assert http_request(running_gui, 'GET', '/../../README.md')[0] == 404
    assert http_request(running_gui, 'POST', '/api/mutate', headers=headers,
                        body={'action': 'unknown', 'confirmed': True})[0] == 400


def test_report_listing_and_text_safety(tmp_path):
    root = tmp_path / 'case'
    (root / 'reports').mkdir(parents=True)
    (root / 'reports' / 'finding.txt').write_text('A finding', encoding='utf-8')
    (root / 'reports' / 'assessment_report.html').write_text('<script>alert(1)</script>', encoding='utf-8')
    (root / 'working').mkdir()
    (root / 'working' / 'private.txt').write_text('private', encoding='utf-8')
    assert {x['name'] for x in list_reports(root)} == {'finding.txt', 'assessment_report.html'}
    assert '<script>' in read_report(root, 'assessment_report.html')  # safe: JSON text, never HTML execution
    assert read_report(root, 'finding.txt') == 'A finding'
    for path in ('../working/private.txt', '../../README.md', 'C:\\Windows\\win.ini', '/etc/passwd', '..'):
        with pytest.raises(ValueError):
            read_report(root, path)


def test_symlink_report_rejected(tmp_path):
    root = tmp_path / 'case'
    folder = root / 'reports'
    folder.mkdir(parents=True)
    secret = tmp_path / 'secret.txt'
    secret.write_text('SECRET', encoding='utf-8')
    try:
        (folder / 'report.txt').symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip('Symlink creation unavailable')
    assert not list_reports(root)
    with pytest.raises(ValueError):
        read_report(root, 'report.txt')


def test_static_job_uses_existing_cli_and_rejects_reuse(tmp_path):
    target = tmp_path / 'target.msi'
    target.write_bytes(b'fixture')
    parent = tmp_path / 'output'
    parent.mkdir()
    root, argv, mode = _validated_job_inputs({'target': str(target), 'target_type': 'installable',
                                               'name': 'Case_1', 'output': str(parent), 'mode': 'static'})
    assert root == parent / 'Case_1' and mode == 'static'
    assert '--non-interactive' in argv and '--no-gui' in argv
    assert '--target' in argv and str(target) in argv
    (parent / 'Case_1').mkdir()
    with pytest.raises(ValueError, match='already exists'):
        _validated_job_inputs({'target': str(target), 'name': 'Case_1', 'output': str(parent)})


def test_cli_worker_input_validation_no_shell_injection(tmp_path):
    target = tmp_path / 'x.msi'
    target.write_text('test')
    with pytest.raises(ValueError):
        _validated_job_inputs({'target': str(target), 'name': 'Case; Start-Process calc', 'output': str(tmp_path)})
    with pytest.raises(ValueError):
        _validated_job_inputs({'target': '', 'name': 'Case', 'output': str(tmp_path)})
    with pytest.raises(ValueError):
        _validated_job_inputs({'target': str(target), 'name': 'Case', 'output': ''})


def test_gui_api_text_report_is_json_not_html(running_gui, tmp_path):
    root = tmp_path / 'case'
    (root / 'reports').mkdir(parents=True)
    (root / 'reports' / 'test.html').write_text('<svg onload="alert(1)"></svg>', encoding='utf-8')
    h = gui_headers(running_gui)
    from urllib.parse import urlencode
    status, headers, raw = http_request(running_gui, 'GET', '/api/report?' + urlencode({'assessment': str(root), 'name': 'test.html'}), headers=h)
    assert status == 200 and headers['Content-Type'].startswith('application/json')
    data = json.loads(raw)
    assert '<svg' in data['content'] and data['ok']
    status, _, _ = http_request(running_gui, 'GET', '/api/report?' + urlencode({'assessment': str(root), 'name': '../foo.html'}), headers=h)
    assert status == 400


def test_packaging_and_html_security_contract():
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location('release_200', 'scripts/package_release.py')
    release = module_from_spec(spec)
    spec.loader.exec_module(release)
    assert 'gui' in release.TOP_LEVEL_DIRS
    assert 'gui-guide.md' in release.CANONICAL_DOCS
    shipped = {p.relative_to(release.ROOT).as_posix() for p in release.iter_release_files()}
    assert {'gui/index.html', 'gui/app.css', 'gui/app.js', 'docs/gui-guide.md'} <= shipped
    assert 'tool_paths.json' not in shipped
    script = Path('scripts/validate_windows.ps1').read_text(encoding='utf-8')
    assert "| Out-String).Trim()" in script
    assert "WCA 2\\.2\\.1" in script


def test_python_cli_preserves_no_gui_file_dialogs_flag():
    import subprocess
    import sys
    p = subprocess.run([sys.executable, 'wca.py', '--help'], capture_output=True, text=True)
    assert p.returncode == 0
    assert '--gui' in p.stdout and '--port' in p.stdout and '--no-gui' in p.stdout
    p = subprocess.run([sys.executable, 'wca.py', '--gui', '--port', '65536'], capture_output=True, text=True)
    assert p.returncode != 0 and '65535' in p.stderr
