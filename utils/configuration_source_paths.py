"""Resolve configuration-review display paths to verified local extracted files.

Portable placeholders remain in reports. Never interpret arbitrary browser paths,
expand environment variables, or expose paths outside assessment-owned evidence.
"""
from __future__ import annotations

from pathlib import Path
import re

_MAX_REPORT_BYTES = 2_000_000
_SUFFIX = re.compile(r'(?i)^%SOURCE_DIR%\\(?:[^\\\r\n]+\\)*working\\extracted_installer\\(.+)$')


def resolve_configuration_artifact(root: Path, displayed_path: object) -> Path:
    if not isinstance(displayed_path, str) or not (15 <= len(displayed_path) <= 2048):
        raise ValueError('Invalid configuration source selection.')
    match = _SUFFIX.fullmatch(displayed_path.strip())
    if not match:
        raise ValueError('Only assessment-owned extracted artifacts may be resolved.')
    suffix = match.group(1).split('\\')
    if (not suffix or any(part in ('', '.', '..') or ':' in part or '/' in part or '%' in part
                         or '\x00' in part for part in suffix)):
        raise ValueError('Unsafe configuration source path.')
    report = root / 'reports' / 'configuration_review.txt'
    if report.is_symlink() or not report.is_file() or report.stat().st_size > _MAX_REPORT_BYTES:
        raise ValueError('Configuration report is unavailable.')
    # Every selected path must be an exact recorded path, not a fabricated suffix.
    content = report.read_text(encoding='utf-8', errors='replace')
    if not any(displayed_path.casefold() in line.casefold() for line in content.splitlines()):
        raise ValueError('Artifact is not listed in the verified configuration report.')
    base = root / 'working' / 'extracted_installer'
    item = base.joinpath(*suffix)
    resolved_base = base.resolve()
    if base.is_symlink() or item.is_symlink() or any(
        ancestor.is_symlink() for ancestor in item.parents if ancestor != root and root in ancestor.parents
    ):
        raise ValueError('Symlink-backed source paths are not allowed.')
    if not item.is_file() or resolved_base not in item.resolve().parents:
        raise ValueError('The extracted artifact is no longer available in this assessment.')
    return item
