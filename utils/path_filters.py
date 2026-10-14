from __future__ import annotations

import copy
import fnmatch
import os
import re
from collections import Counter


FRAMEWORK_SNAPSHOT_DIR = re.compile(r"(?:^|[\\/])(?:wca|winclientassess)-snapshot-[^\\/]+(?:[\\/]|$)", re.I)


def is_framework_snapshot_path(value) -> bool:
    """Recognize framework-generated raw snapshot temp dirs, not third-party files."""
    return bool(FRAMEWORK_SNAPSHOT_DIR.search(str(value or "")))


def normalize_filter_path(value) -> str:
    return (
        os.path.expandvars(str(value or ""))
        .strip()
        .strip('"')
        .replace("/", "\\")
        .lower()
    )


def path_is_excluded(value, exclude_paths=None) -> bool:
    candidate = normalize_filter_path(value)
    if not candidate:
        return False
    for raw_pattern in exclude_paths or []:
        pattern = normalize_filter_path(raw_pattern)
        if not pattern:
            continue
        if any(char in pattern for char in "*?["):
            if fnmatch.fnmatchcase(candidate, pattern):
                return True
            continue
        pattern = pattern.rstrip("\\")
        if candidate == pattern or candidate.startswith(pattern + "\\"):
            return True
    return False


def record_contains_excluded_path(value, exclude_paths=None) -> bool:
    if isinstance(value, dict):
        return any(record_contains_excluded_path(item, exclude_paths) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(record_contains_excluded_path(item, exclude_paths) for item in value)
    return isinstance(value, str) and path_is_excluded(value, exclude_paths)


def _has_framework_temp_path(record) -> bool:
    if isinstance(record, dict):
        return any(_has_framework_temp_path(value) for value in record.values())
    if isinstance(record, (list, tuple)):
        return any(_has_framework_temp_path(item) for item in record)
    return isinstance(record, str) and is_framework_snapshot_path(record)


def filter_install_diff(diff, exclude_paths=None, exclude_framework_noise=False):
    """Filter derived differential records; framework temp dirs can be stripped always."""
    if not exclude_paths and not exclude_framework_noise:
        return copy.deepcopy(diff or {}), {}
    output = copy.deepcopy(diff or {})
    removed = Counter()
    for category, changes in output.items():
        if not isinstance(changes, dict):
            continue
        for change_type in ("added", "removed", "changed"):
            rows = changes.get(change_type)
            if not isinstance(rows, list):
                continue
            kept = []
            for row in rows:
                if category == "Filesystem" and exclude_framework_noise and _has_framework_temp_path(row):
                    removed[f"{category}.{change_type} (framework temp)"] += 1
                    continue
                if record_contains_excluded_path(row, exclude_paths):
                    removed[f"{category}.{change_type}"] += 1
                else:
                    kept.append(row)
            changes[change_type] = kept
    return output, dict(sorted(removed.items()))


def write_filter_report(path, exclude_paths=None, removed_counts=None, target_only=False):
    lines = [
        "WCA - ASSESSMENT FILTERS",
        "=" * 104,
        "",
        "Purpose:",
        "  Records tester-selected and built-in noise filters applied to derived assessment evidence.",
        "  Framework-created wca-snapshot-* temporary directories (legacy winclientassess-snapshot-* also recognized) are always excluded.",
        "  Framework-created TEMP entries are removed from in-memory and persisted snapshots.",
        "  Other current-run snapshot records remain available; imported Procmon evidence is unchanged.",
        "",
        f"Target-only supporting inventory : {bool(target_only)}",
        "",
        "EXCLUDED PATHS",
        "-" * 104,
    ]
    patterns = [str(item) for item in (exclude_paths or []) if str(item).strip()]
    lines.extend(f"- {item}" for item in patterns)
    if not patterns:
        lines.append("None.")
    lines += ["", "FILTERED DIFFERENTIAL RECORDS", "-" * 104]
    if removed_counts:
        for name, count in sorted(removed_counts.items()):
            lines.append(f"{name:48} {count}")
    else:
        lines.append("None.")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
