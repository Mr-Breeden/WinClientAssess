from __future__ import annotations

from pathlib import Path
import shutil

from utils.artifacts import generated_files, GENERATED_DIRECTORIES
from utils.assessment_layout import artifact_path, generated_directory_path


GENERATED_FILES = generated_files()
# Retired duplicate reports from older releases. They are removed on a fresh run
# but are intentionally not part of the current artifact catalog.
LEGACY_GENERATED_FILES = {'new_services.txt', 'new_scheduled_tasks.txt'}


def reset_generated_artifacts(assessment_dir: Path, preserve_paths=None):
    """
    Remove only known Windows Client Assessment-generated artifacts from an existing
    assessment directory so every run reflects current-run evidence.

    Explicitly supplied files (for example --procmon-csv) can be preserved.
    """
    assessment_dir = Path(assessment_dir)
    preserve = set()

    for raw in preserve_paths or []:
        if not raw:
            continue
        try:
            preserve.add(str(Path(raw).expanduser().resolve()).lower())
        except Exception:
            preserve.add(str(raw).lower())

    removed = []

    for name in GENERATED_FILES | LEGACY_GENERATED_FILES:
        path = artifact_path(assessment_dir, name)
        try:
            resolved = str(path.resolve()).lower()
        except Exception:
            resolved = str(path).lower()
        if resolved in preserve:
            continue
        if path.is_file():
            try:
                path.unlink()
                removed.append(str(path))
            except Exception:
                pass

    for name in GENERATED_DIRECTORIES:
        path = generated_directory_path(assessment_dir, name)
        try:
            resolved = str(path.resolve()).lower()
        except Exception:
            resolved = str(path).lower()
        if resolved in preserve:
            continue
        if path.is_dir():
            try:
                shutil.rmtree(path)
                removed.append(str(path))
            except Exception:
                pass

    return removed
