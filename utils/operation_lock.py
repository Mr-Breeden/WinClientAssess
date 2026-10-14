"""Fail-closed, per-assessment process exclusion for mutating backend operations.

The lock lives *beside* the assessment, never inside an integrity-tracked tree.
A stale lock is not silently removed. An operator must verify the old process
has ended before removing it, or use an independent output directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


class AssessmentBusyError(RuntimeError):
    """Another operation holds the assessment's exclusive mutation lock."""


def lock_path(assessment_dir: Path) -> Path:
    root = Path(assessment_dir).expanduser().resolve()
    digest = hashlib.sha256(os.path.normcase(str(root)).encode('utf-8')).hexdigest()[:20]
    return root.parent / (f'.wca-operation-{digest}.lock')


@contextmanager
def assessment_operation(assessment_dir: Path, action: str) -> Iterator[None]:
    """Block concurrent mutation without silently stealing stale/unknown locks.

    This is an advisory lock: all WCA writers must opt in. It does not replace
    per-file atomic writes, assessment integrity checks or OS access controls.
    """
    if not action or not isinstance(action, str):
        raise ValueError('Operation identifier is required')
    path = lock_path(assessment_dir)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise AssessmentBusyError('Assessment is locked by another operation. Check the active WCA session; do not remove an active lock.') from exc
    try:
        own_inode = os.fstat(descriptor).st_ino
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump({'schema': 1, 'pid': os.getpid(), 'action': action,
                       'started_at': datetime.now(timezone.utc).isoformat(timespec='seconds')}, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        yield
    finally:
        # Do not remove a replacement lock if an operator changed it during a run.
        try:
            if not path.is_symlink() and path.stat().st_ino == own_inode:
                path.unlink()
        except FileNotFoundError:
            pass
