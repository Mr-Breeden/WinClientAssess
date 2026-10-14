from __future__ import annotations

import os
import re
import ntpath


def as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def extract_executable(command: str | None) -> str | None:
    if not command:
        return None
    text = str(command).strip()
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 1 else None
    match = re.match(r"(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|dll))\b", text, flags=re.I)
    if match:
        return match.group(1).strip()
    return text.split()[0] if text.split() else None


def normalized(path: str | None) -> str:
    if not path:
        return ""
    return ntpath.normcase(ntpath.normpath(os.path.expandvars(str(path).strip().strip('"'))))


def is_user_profile_path(path: str | None) -> bool:
    if not path:
        return False
    candidate = normalized(path)
    profile = normalized(os.environ.get("USERPROFILE"))
    return bool(profile and (candidate == profile or candidate.startswith(profile + "\\")))


def is_temp_path(path: str | None) -> bool:
    if not path:
        return False
    candidate = normalized(path)
    temps = [normalized(os.environ.get("TEMP")), normalized(os.environ.get("TMP"))]
    return any(temp and (candidate == temp or candidate.startswith(temp + "\\")) for temp in temps)


def parent_path(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return ntpath.dirname(os.path.expandvars(str(path).strip().strip('"'))) or None
    except Exception:
        return None
