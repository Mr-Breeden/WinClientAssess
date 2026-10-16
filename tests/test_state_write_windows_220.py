"""WCA 2.2.0 Windows state-file replace regression coverage."""
from __future__ import annotations

import errno
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

import wca
from utils import assessment_state


def test_transient_windows_replace_denial_retries_then_succeeds(tmp_path, monkeypatch):
    target = tmp_path / 'assessment_state.json'
    assessment_state._atomic_json(target, {'status': 'BEFORE'})
    original_replace = assessment_state.os.replace
    calls = []
    sleeps = []

    def temporarily_locked(src, dst):
        calls.append((Path(src), Path(dst)))
        if len(calls) <= 2:
            raise PermissionError(errno.EACCES, 'Simulated Windows access denial')
        return original_replace(src, dst)

    monkeypatch.setattr(assessment_state.os, 'replace', temporarily_locked)
    monkeypatch.setattr(assessment_state.time, 'sleep', lambda secs: sleeps.append(secs))
    assessment_state._atomic_json(target, {'status': 'AFTER'})
    assert len(calls) == 3
    assert len(sleeps) == 2
    assert json.loads(target.read_text())['status'] == 'AFTER'
    assert not list(tmp_path.glob('assessment_state.json.*.tmp'))


def test_permanent_denial_preserves_previous_state_and_cleans_temp(tmp_path, monkeypatch):
    target = tmp_path / 'assessment_state.json'
    assessment_state._atomic_json(target, {'status': 'BEFORE'})
    prior = target.read_bytes()
    attempts = []

    def permanently_locked(*args):
        attempts.append(1)
        raise PermissionError(errno.EACCES, 'Simulated permanent Windows access denial')

    monkeypatch.setattr(assessment_state.os, 'replace', permanently_locked)
    monkeypatch.setattr(assessment_state.time, 'sleep', lambda _secs: None)
    with pytest.raises(PermissionError):
        assessment_state._atomic_json(target, {'status': 'AFTER'})
    assert len(attempts) == assessment_state._REPLACE_ATTEMPTS
    assert target.read_bytes() == prior
    assert not list(tmp_path.glob('assessment_state.json.*.tmp'))


def test_non_locking_os_error_is_not_retried(tmp_path, monkeypatch):
    target = tmp_path / 'assessment_state.json'
    calls = []
    def disk_full(*args):
        calls.append(1)
        raise OSError(errno.ENOSPC, 'disk full')
    monkeypatch.setattr(assessment_state.os, 'replace', disk_full)
    monkeypatch.setattr(assessment_state.time, 'sleep', lambda *_: pytest.fail('unexpected retry'))
    with pytest.raises(OSError) as error:
        assessment_state._atomic_json(target, {'status':'AFTER'})
    assert error.value.errno == errno.ENOSPC
    assert len(calls) == 1
    assert not target.exists()
    assert not list(tmp_path.glob('assessment_state.json.*.tmp'))


def test_state_save_error_does_not_mislabel_collector_as_failed(monkeypatch):
    reporter = Mock()
    reporter.set_status.side_effect = PermissionError(errno.EACCES, 'state replace unavailable')
    monkeypatch.setattr(wca.console, 'print', lambda *_args, **_kw: None)
    try:
        with pytest.raises(PermissionError):
            wca.run_module(reporter, 'Secrets Review', lambda: {'status':'PASS'})
        # Only one status write attempt after successful collection.
        reporter.set_status.assert_called_once_with('Secrets Review', 'PASS', '', coverage_gap=False)
    finally:
        reporter.reset_mock()


def test_genuine_collector_exception_remains_a_module_error(monkeypatch):
    reporter = Mock()
    monkeypatch.setattr(wca.console, 'print', lambda *_args, **_kw: None)
    def collector():
        raise ValueError('fake collector error')
    result = wca.run_module(reporter, 'Secrets Review', collector)
    assert result['status'] == 'ERROR'
    reporter.set_status.assert_called_once_with('Secrets Review', 'ERROR', 'fake collector error')
