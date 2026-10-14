"""Conservative child-process attribution for passive Procmon captures.

A direct launch by a target remains evidence of the target's behavior. An
external application's subsequent independent process tree is NOT treated as
first-party client activity. Do not infer trust from a parent PID or name alone.
"""
from __future__ import annotations
import ntpath


def trusted_roots(target_paths):
    """Directories of explicitly associated, absolute target executables only."""
    result = set()
    for value in target_paths or ():
        path = str(value or "").strip().strip('"').replace('/', '\\')
        if not ntpath.isabs(path) or '%' in path or not path.lower().endswith('.exe'):
            continue
        root = ntpath.normcase(ntpath.normpath(ntpath.dirname(path)))
        # Never promote an entire drive, Windows, Program Files or user profile.
        parts = [s for s in root.split('\\') if s]
        if len(parts) < 2 or (len(parts) == 3 and "\\users\\" in root) or root.endswith(('\\windows', '\\system32', '\\program files',
                                          '\\program files (x86)', '\\users', '\\appdata')):
            continue
        result.add(root)
    return frozenset(result)


def in_target_scope(child_path, roots):
    """Only allow a directly created EXE beneath a verified application root."""
    path = str(child_path or "").strip().strip('"').replace('/', '\\')
    if not ntpath.isabs(path) or '%' in path or not path.lower().endswith('.exe'):
        return False
    norm = ntpath.normcase(ntpath.normpath(path))
    return any(norm.startswith(root + '\\') for root in (roots or ()))
