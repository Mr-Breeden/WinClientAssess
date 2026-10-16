"""Pre-GUI v1.9.4 correction regression: timeout normalization, validation, release safety."""
from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from utils.command_runner import run_command
from utils.client_appendix import _appendix_html, export_client_appendix
from utils.operation_lock import assessment_operation, lock_path, AssessmentBusyError
from tests.test_client_appendix_190 import _assessment


def test_timeout_with_real_partial_output_is_text():
    result = run_command([sys.executable, '-u', '-c',
                          'import sys,time; print("partial stdout",flush=True); '
                          'print("partial stderr", file=sys.stderr, flush=True); time.sleep(20)'], timeout=5)
    assert result['returncode'] == 124
    assert isinstance(result['stdout'], str)
    assert isinstance(result['stderr'], str)
    assert 'partial stdout' in result['stdout']
    assert 'partial stderr' in result['stderr']
    assert 'Timed out after' in result['stderr']


def test_timeout_none_and_invalid_utf8_bytes_are_normalized():
    with patch('utils.command_runner.subprocess.run', side_effect=subprocess.TimeoutExpired(
            cmd=['x'], timeout=1, output=b'x\xff', stderr=b'y\xfe')):
        result = run_command(['x'], timeout=1)
    assert result['stdout'] == 'x\ufffd'
    assert 'y\ufffd' in result['stderr']
    assert result['returncode'] == 124
    with patch('utils.command_runner.subprocess.run', side_effect=subprocess.TimeoutExpired(
            cmd=['x'], timeout=1)):
        result = run_command(['x'], timeout=1)
    assert result['stdout'] == ''
    assert isinstance(result['stderr'], str)


def test_normal_command_contract_is_unchanged():
    result = run_command([sys.executable, '-c', 'print("ok")'])
    assert result == {'returncode': 0, 'stdout': 'ok\n', 'stderr': ''}


def test_operation_lock_releases_after_exception(tmp_path):
    root = tmp_path / 'case'
    root.mkdir()
    with pytest.raises(RuntimeError, match='controlled'):
        with assessment_operation(root, 'test'):
            assert lock_path(root).is_file()
            with pytest.raises(AssessmentBusyError):
                with assessment_operation(root, 'second'):
                    pass
            raise RuntimeError('controlled')
    assert not lock_path(root).exists()
    with assessment_operation(root, 'retry'):
        assert lock_path(root).exists()


def test_stale_lock_refuses_automatic_recovery(tmp_path):
    root = tmp_path / 'case'
    root.mkdir()
    lock = lock_path(root)
    lock.write_text('stale process metadata', encoding='utf-8')
    with pytest.raises(AssessmentBusyError):
        with assessment_operation(root, 'new'):
            pass
    assert lock.read_text(encoding='utf-8') == 'stale process metadata'


def test_client_appendix_labels_assessed_framework_not_old_hardcode(tmp_path):
    doc = _appendix_html({'assessment_name': 'Synthetic', 'framework_version': '1.9.4'}, [], [], {})
    assert 'Client technical appendix · v1.9.4' in doc
    assert 'Client technical appendix · v1.9.2' not in doc
    root = _assessment(tmp_path)
    exported = export_client_appendix(root, tmp_path / 'client.zip')
    with zipfile.ZipFile(exported) as zf:
        readme = zf.read('README.txt').decode('utf-8')
        assert 'WCA v1.8.6 — CLIENT APPENDIX' in readme  # legacy archive preserves provenance


def test_validation_script_has_exit_checks_and_dev_requirements():
    source = Path('scripts/validate_windows.ps1').read_text(encoding='utf-8')
    assert 'function Invoke-CheckedPython' in source
    assert '$LASTEXITCODE' in source
    for fragment in ("'-m','pytest','-q'", "'--audit-only'", "'--backend-action','capabilities'"):
        assert fragment.replace('package_release.py', 'package_release.py') in source
    assert "WCA 2.2.0 version string not detected" in source
    assert 'pytest' in Path('requirements-dev.txt').read_text(encoding='utf-8')
    assert 'TestDependencies' in Path('install_dependencies.ps1').read_text(encoding='utf-8')
