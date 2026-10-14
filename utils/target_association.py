"""Conservative association helpers for system-state target scoping.

A system-wide pre/post snapshot captures unrelated Windows and third-party
activity.  Filesystem additions are therefore *not* target evidence merely
because they appeared during the installation window.  This module only treats
an installed path as target-associated when it is backed by stronger evidence:

* the installed file matches an extracted/static payload by filename + size;
* it resides beneath a specific directory established by a new service/task; or
* it resides beneath a specific directory established by another matched
  installed payload.

The helpers intentionally avoid vendor/product allowlists so they remain generic
across client assessments.
"""
from __future__ import annotations

import ntpath
from collections import defaultdict

from utils.component_context import normalize_path
from utils.windows_paths import extract_executable


BINARY_ROOT_EXTS = {".exe", ".dll", ".com"}
BROAD_ROOTS = {
    "c:\\",
    r"c:\windows",
    r"c:\windows\system32",
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\programdata",
}


def _basename(path) -> str:
    return ntpath.basename(str(path or "").strip().strip('"'))


def _size(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _specific_parent(path: str) -> str:
    parent = normalize_path(ntpath.dirname(str(path or "").strip().strip('"'))).rstrip("\\")
    if not parent or parent in BROAD_ROOTS:
        return ""
    # Avoid treating a drive/root or one generic system directory as a product
    # install root merely because a service/task executable happens to sit there.
    if len(parent) < 8:
        return ""
    return parent


def _under_root(path: str, root: str) -> bool:
    candidate = normalize_path(path).rstrip("\\")
    root = normalize_path(root).rstrip("\\")
    return bool(candidate and root and (candidate == root or candidate.startswith(root + "\\")))


def inventory_signatures(file_inventory=None):
    """Return stable filename/size signatures from extracted/static payloads."""
    exact = set()
    names = defaultdict(set)
    for row in file_inventory or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or _basename(row.get("path"))).strip().lower()
        if not name:
            continue
        size = _size(row.get("size_bytes"))
        if size is not None:
            exact.add((name, size))
            names[name].add(size)
    return exact, names


def static_match(item: dict, file_inventory=None) -> bool:
    """Match one installed snapshot item to an extracted/static payload.

    Windows filesystem snapshots include file length, so filename + length is
    preferred.  If a synthetic/legacy snapshot omits length, accept a filename
    only when the static inventory contains exactly one size for that name.
    """
    if not file_inventory or not isinstance(item, dict):
        return False
    exact, names = inventory_signatures(file_inventory)
    name = _basename(item.get("Path")).lower()
    if not name:
        return False
    length = _size(item.get("Length"))
    if length is not None:
        return (name, length) in exact
    return name in names and len(names[name]) == 1


def association_roots(diff=None, file_inventory=None) -> set[str]:
    """Build specific installed roots backed by service/task or payload evidence."""
    diff = diff or {}
    roots: set[str] = set()

    for service in diff.get("Services", {}).get("added", []) or []:
        if not isinstance(service, dict):
            continue
        parent = _specific_parent(extract_executable(service.get("PathName")) or "")
        if parent:
            roots.add(parent)

    for task in diff.get("ScheduledTasks", {}).get("added", []) or []:
        if not isinstance(task, dict):
            continue
        actions = task.get("Actions", []) or []
        if isinstance(actions, dict):
            actions = [actions]
        for action in actions:
            if not isinstance(action, dict):
                continue
            parent = _specific_parent(extract_executable(action.get("Execute")) or "")
            if parent:
                roots.add(parent)

    # A filesystem addition that exactly matches a packaged executable/DLL is a
    # strong installed-target anchor.  Its directory can then associate sibling
    # installed components from the same application tree.
    for item in diff.get("Filesystem", {}).get("added", []) or []:
        if not isinstance(item, dict) or item.get("IsDirectory"):
            continue
        path = str(item.get("Path") or "")
        if ntpath.splitext(path)[1].lower() not in BINARY_ROOT_EXTS:
            continue
        if static_match(item, file_inventory):
            parent = _specific_parent(path)
            if parent:
                roots.add(parent)
    return roots


def classify_installed_path(item: dict, *, diff=None, file_inventory=None, roots=None) -> str:
    """Return the evidence basis for an installed filesystem candidate.

    An empty string means the path is not sufficiently associated with the
    assessed application and should not be promoted into target-scoped analysis.
    When no static inventory is supplied, callers retain legacy behavior for
    backwards-compatible standalone/unit use.
    """
    if not isinstance(item, dict) or item.get("IsDirectory"):
        return ""
    path = str(item.get("Path") or "")
    if not path:
        return ""
    if file_inventory is None:
        return "legacy filesystem differential"
    if static_match(item, file_inventory):
        return "matches extracted/static payload"
    roots = roots if roots is not None else association_roots(diff, file_inventory)
    if any(_under_root(path, root) for root in roots):
        return "beneath target-associated install root"
    return ""
