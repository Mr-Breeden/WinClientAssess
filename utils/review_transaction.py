"""Conservative rollback guard for explicitly saved Guided Review decisions.

The assessment manifest is NOT a multi-file transaction. Preserve the exact
pre-save reports, review state, and manifest outside the assessment before
rendering derived reports. On an ordinary error restore *only this operation's*
changes and verify against the original manifest; unexpected process termination
leaves an inspectable backup but never triggers silent cross-run recovery.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import tempfile

from utils.assessment_integrity import verify_assessment


class ReviewUpdateRolledBack(RuntimeError):
    """A failed update was restored to its previous verified state."""


class ReviewUpdateRollbackFailed(RuntimeError):
    """The update failed and the original state could not be safely verified."""


def _restore_original(root: Path, backup: Path, paths: list[Path], report_names: set[str]) -> None:
    for relative in paths:
        original = root / relative
        saved = backup / relative
        if not saved.is_file():
            raise ReviewUpdateRollbackFailed('The original evidence backup is incomplete.')
        staged = original.with_name(original.name + '.rollback-wca-tmp')
        shutil.copy2(saved, staged)
        os.replace(staged, original)
    # The pre-operation manifest passed verification and thus contained no
    # orphan temporary files. Clean only newly created WCA staging files.
    for folder in ('reports', 'working'):
        directory = root / folder
        if directory.is_dir():
            for path in directory.glob('*.tmp'):
                if path.is_file() and not path.is_symlink():
                    path.unlink()
    # A report created for the first time by failed regeneration is not part of
    # the original manifest. A failed post-rollback integrity check leaves the
    # backup for manual investigation instead of inventing a fresh manifest.
    for child in (root / 'reports').iterdir():
        if child.is_file() and not child.is_symlink() and child.name not in report_names:
            if child.suffix.lower() in ('.txt', '.html', '.md'):
                child.unlink()


@contextmanager
def guarded_review_commit(root: Path):
    root = Path(root)
    original = verify_assessment(root)
    if original.get('status') != 'PASS':
        raise ValueError('Review changes require an intact assessment.')
    manifest = original['manifest']
    reports = set((manifest.get('files', {}).get('reports') or {}).keys())
    supporting_review = Path('working/tester_review_state.json')
    manifest_path = Path('working/assessment_manifest.json')
    files = sorted({Path(name) for name in reports} | {supporting_review, manifest_path}, key=str)
    if any(p.is_absolute() or '..' in p.parts for p in files):
        raise ValueError('Invalid assessment manifest paths.')
    backup_path = Path(tempfile.mkdtemp(prefix='.wca-review-backup-', dir=root.parent))
    cleanup_backup = False
    try:
        for relative in files:
            original_file = root / relative
            if original_file.is_symlink() or not original_file.is_file():
                raise ValueError('Verified review file is unavailable.')
            saved = backup_path / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original_file, saved)
        # Breadcrumb for unexpected process termination. It is intentionally
        # outside the assessment tree and is never silently reapplied.
        (backup_path / 'TRANSACTION_INFO.json').write_text(
            json.dumps({'operation': 'save_review', 'assessment': root.name,
                        'instruction': 'Do not manually merge. Preserve for integrity investigation.'}),
            encoding='utf-8')
        try:
            yield
        except BaseException as exc:
            try:
                _restore_original(root, backup_path, files, {Path(x).name for x in reports})
                if verify_assessment(root).get('status') != 'PASS':
                    raise ReviewUpdateRollbackFailed('Original assessment integrity could not be restored.')
            except Exception as failed:
                raise ReviewUpdateRollbackFailed(
                    'Review update failed. Integrity recovery requires manual investigation; backup retained.') from failed
            cleanup_backup = True
            raise ReviewUpdateRolledBack(
                'Review update was interrupted; the original verified assessment was restored.') from exc
        cleanup_backup = True
    finally:
        if cleanup_backup:
            shutil.rmtree(backup_path)
