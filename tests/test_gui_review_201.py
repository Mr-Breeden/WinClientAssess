"""v2.0.1 browser Guided Review, privacy, rollback and disconnect regressions."""
from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.test_guided_review_navigation import assessment
from tests.test_gui_200 import gui_headers, http_request, running_gui
from utils.assessment_integrity import verify_assessment
from utils.backend_service import BackendService
from utils.gui_server import build_handler, review_condition_detail
from utils.guided_review import read_review


def tracked_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


def test_gui_detail_shares_existing_playbook_and_reads_notes_without_changes(tmp_path):
    root = assessment(tmp_path, version='2.0.0')
    saved = read_review(root)
    identifier = next(iter(saved['items']))
    # Seed saved notes through the integrity-preserving real backend commit.
    item = saved['items'][identifier]
    saved_result = BackendService(version='2.0.1').execute('save_review', root, confirmed=True,
        candidate_id=identifier, fingerprint=item['fingerprint'], disposition='INFORMATIONAL', notes='Keep these notes')
    assert saved_result['ok'], saved_result
    previous = tracked_hashes(root)
    detail = review_condition_detail(root, identifier)
    assert detail['notes'] == 'Keep these notes'
    assert detail['manual_validation']
    assert detail['prerequisites']
    assert detail['commands']
    assert detail['expected_evidence']
    assert detail['secure'] and detail['not_report']
    assert previous == tracked_hashes(root)
    assert verify_assessment(root)['status'] == 'PASS'


def test_gui_review_detail_api_is_read_only_and_private(running_gui, tmp_path):
    root = assessment(tmp_path, version='2.0.0')
    identifier = next(iter(read_review(root)['items']))
    before = tracked_hashes(root)
    path = '/api/review-detail?assessment=' + __import__('urllib.parse', fromlist=['quote']).quote(str(root)) + '&id=' + identifier
    assert http_request(running_gui, 'GET', path)[0] == 403
    status, _, content = http_request(running_gui, 'GET', path, headers=gui_headers(running_gui))
    assert status == 200
    detail = json.loads(content)['detail']
    assert detail['id'] == identifier and detail['manual_validation']
    assert before == tracked_hashes(root)


def test_review_commit_error_rolls_back_and_clears_temporary_artifacts(tmp_path):
    root = assessment(tmp_path, version='2.0.0')
    item = next(iter(read_review(root)['items'].values()))
    before = tracked_hashes(root)

    def crash_after_partial_write(reporter, *args, **kwargs):
        (root/'reports'/'tester_review.txt.tmp').write_text('partial review', encoding='utf-8')
        (root/'reports'/'tester_review.txt').write_text('new invalid contents', encoding='utf-8')
        raise RuntimeError('injected post-review render failure')

    with patch('utils.reporting.AssessmentReporter.finalize', autospec=True, side_effect=crash_after_partial_write):
        result = BackendService(version='2.0.1').execute('save_review', root, confirmed=True,
            candidate_id=item['id'], fingerprint=item['fingerprint'], disposition='VALIDATED', notes='not committed')
    assert not result['ok'] and result['code'] == 'REVIEW_UPDATE_ROLLED_BACK', result
    assert tracked_hashes(root) == before
    assert verify_assessment(root)['status'] == 'PASS'
    assert read_review(root)['items'][item['id']]['status'] == item['status']
    assert not list(tmp_path.glob('.wca-review-backup-*'))


def test_review_commit_without_notes_parameter_preserves_saved_notes(tmp_path):
    root = assessment(tmp_path, version='2.0.0')
    item = next(iter(read_review(root)['items'].values()))
    service = BackendService(version='2.0.1')
    first = service.execute('save_review', root, confirmed=True, candidate_id=item['id'],
        fingerprint=item['fingerprint'], disposition='INFORMATIONAL', notes='Existing notes')
    assert first['ok'], first
    second = service.execute('save_review', root, confirmed=True, candidate_id=item['id'],
        fingerprint=item['fingerprint'], disposition='VALIDATED')
    assert second['ok'], second
    assert read_review(root)['items'][item['id']]['notes'] == 'Existing notes'
    assert verify_assessment(root)['status'] == 'PASS'


def test_gui_source_has_no_second_review_confirmation():
    js = (Path(__file__).resolve().parents[1]/'gui'/'app.js').read_text(encoding='utf-8')
    assert 'Save decision' in (Path(__file__).resolve().parents[1]/'gui'/'index.html').read_text(encoding='utf-8')
    assert "if(!confirm(`Save" not in js
    assert '/api/review-detail' in js
    assert "$('reviewNotes').value=d.notes||''" in js
    assert 'guideSection(10' in js


def test_server_send_swallows_expected_disconnect(monkeypatch):
    handler = build_handler(token='test', version='2.0.1', jobs=None, port=9001)
    instance = object.__new__(handler)
    instance._headers = lambda status, typ: None
    instance.send_header = lambda *args: None
    instance.end_headers = lambda: None
    class Aborted:
        def write(self, payload):
            raise ConnectionAbortedError(10053, 'local connection closed')
    instance.wfile = Aborted()
    instance.close_connection = False
    instance._send(200, b'data')
    assert instance.close_connection is True
