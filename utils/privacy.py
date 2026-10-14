"""Narrow privacy transforms for tester-facing assessment evidence.

Do not use these transforms on in-memory correlation inputs. Target/service paths
and accounts are useful security evidence; only the current tester's known
profile/identity and the selected target source location are removed from reports.
"""
from __future__ import annotations

import ntpath
import os
import re
import csv
import subprocess
from functools import lru_cache
from pathlib import Path

from utils.assessment_layout import artifact_path


def portable_basename(path) -> str:
    """Extract a Windows or POSIX filename independently of the host OS."""
    return ntpath.basename(str(path or "").strip().strip('"').replace("/", "\\"))


def _replace_literal(text: str, needle: str, replacement: str) -> str:
    if not needle:
        return text
    return re.sub(re.escape(needle), lambda _: replacement, text, flags=re.I)




@lru_cache(maxsize=1)
def current_user_sid() -> str:
    """Return the current interactive Windows account SID without persisting it.

    Tests may provide WCA_CURRENT_USER_SID. On non-Windows hosts or when the
    lookup fails, return an empty string and leave unrelated SIDs unchanged.
    """
    injected = str(os.environ.get("WCA_CURRENT_USER_SID") or "").strip()
    if injected:
        return injected
    if os.name != "nt":
        return ""
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, timeout=10, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return ""
        row = next(csv.reader([result.stdout.strip().splitlines()[0]]), [])
        for value in row:
            value = str(value or "").strip()
            if re.fullmatch(r"S-1-5-(?:\d+-){1,14}\d+", value, re.I):
                return value
    except Exception:
        return ""
    return ""


def sanitize_report_text(value, installer=None) -> str:
    """Mask *known tester identity*, not unrelated target users or service SIDs.

    Selected target/source paths are replaced with just the filename, even when sources
    reside outside the tester's profile. Raw snapshots and imported CSVs are
    separately controlled evidence; report transforms must not corrupt them.
    """
    text = str(value or "")
    if installer:
        source = str(installer)
        name = portable_basename(source)
        if source != name and name:
            # Full paths may appear with either slash style (tool output varies).
            for variant in {source, source.replace("\\", "/"), source.replace("/", "\\")}:
                text = _replace_literal(text, variant, name)
            # A published application includes DLL/config sidecars next to the EXE.
            # Mask the original source *directory* for those sibling paths too;
            # keep the filename and meaningful subpath so review guidance works.
            parent = ntpath.dirname(source.replace("/", "\\")).rstrip("\\/")
            if parent and ntpath.splitdrive(parent)[1] not in {"", "\\", "/"}:
                for variant in {parent, parent.replace("\\", "/")}:
                    text = re.sub(
                        re.escape(variant) + r"(?=[\\/]|$)",
                        lambda _: "%SOURCE_DIR%",
                        text,
                        flags=re.I,
                    )
    profile = str(os.environ.get("USERPROFILE") or "").strip().rstrip("\\/")
    username = str(os.environ.get("USERNAME") or "").strip()
    # If this runtime is not Windows, do not treat a generic Unix USER/HOME as
    # the assessed Windows identity. Tests can inject Windows env explicitly.
    candidates = [profile]
    if username and username not in {".", ".."}:
        candidates.extend((rf"C:\Users\{username}", rf"C:/Users/{username}"))
    for candidate in sorted(set(filter(None, candidates)), key=len, reverse=True):
        replacement = "%USERPROFILE%"
        for variant in {candidate, candidate.replace("\\", "/"), candidate.replace("/", "\\")}:
            # Replace an actual profile root only, never the prefix of another
            # account (e.g. C:\Users\Alex should not match Alex2).
            pattern = re.compile(re.escape(variant) + r"(?![A-Za-z0-9_.-])", re.I)
            text = pattern.sub(lambda _: replacement, text)
    tester_sid = current_user_sid()
    if tester_sid:
        # Preserve security-relevant service/domain principals while removing the
        # current tester account SID from portable reports, snapshots and runtime CSV.
        text = re.sub(rf"(?<![A-Za-z0-9-]){re.escape(tester_sid)}(?![A-Za-z0-9-])",
                      "CURRENT_USER_SID", text, flags=re.I)
    hostname = str(os.environ.get("COMPUTERNAME") or "").strip()
    if hostname and len(hostname) > 2:
        text = re.sub(rf"(?<![\w.-]){re.escape(hostname)}(?![\w-])", "CURRENT_HOST", text, flags=re.I)
    if username and len(username) >= 3 and username.upper() not in {"SYSTEM", "ADMINISTRATORS", "LOCAL SERVICE", "NETWORK SERVICE"}:
        # Also protect isolated tester identity inside SAM registry object names,
        # task titles, app-generated filenames and URL-encoded paths. A profile
        # root substitution alone does not cover those common Procmon sources.
        # Exact token boundaries avoid replacing the middle of vendor/product
        # names. This is limited to the known *current* account only.
        # Paths copied into URL parameters sometimes encode separators as %5C
        # or %2F. Handle those without decoding/re-encoding other evidence.
        text = re.sub(
            rf"(?i)(%5C|%2F){re.escape(username)}(?=(?:%5C|%2F|[?#&]|$))",
            lambda m: m.group(1) + "CURRENT_USER", text,
        )
        # Certain Windows per-user named objects join their owner to a fixed
        # object prefix using an underscore. General underscore-separated
        # identifier replacement would corrupt arbitrary product names, so
        # limit this additional rule to recognized Windows object namespaces.
        text = re.sub(
            rf"(?i)(\bUrlZonesSM_){re.escape(username)}(?![A-Za-z0-9_])",
            lambda match: match.group(1) + "CURRENT_USER", text,
        )
        text = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(username)}(?![A-Za-z0-9_])",
            "CURRENT_USER", text, flags=re.I,
        )
    if username:
        # Normalize Windows account values such as DOMAIN\CurrentTester without
        # changing service accounts (SYSTEM/NETWORK SERVICE/etc.).
        account = re.compile(rf"(?<![\w\\/])[A-Za-z0-9_.-]+\\{re.escape(username)}\b", re.I)
        text = account.sub("CURRENT_USER", text)
    # Also redact explicitly labelled credentials in descriptive module/status
    # output. This is a pattern safeguard, not a guarantee for arbitrary blobs.
    from utils.sensitive_data import redact_sensitive_text
    return redact_sensitive_text(text)[0]


def sanitize_report_files(assessment_dir: Path, filenames, installer=None) -> int:
    """Normalize known generated TXT reports after collectors complete.

    Raw/source JSON and structured CSV evidence is intentionally excluded.
    Module authors can write files directly; this post-processing gives them a
    consistent, conservative final privacy boundary for interpreted reports.
    """
    changed = 0
    for filename in filenames:
        if not filename.endswith(".txt"):
            continue
        path = artifact_path(Path(assessment_dir), filename)
        if not path.is_file():
            continue
        original = path.read_text(encoding="utf-8", errors="replace")
        sanitized = sanitize_report_text(original, installer)
        if original != sanitized:
            from utils.assessment_integrity import _atomic_text
            _atomic_text(path, sanitized)
            changed += 1
    return changed


def sanitize_snapshot_for_disk(data):
    """Remove recognized personal identity and credential values from a snapshot.

    The original in-memory snapshot remains available for exact current-run
    differential/correlation. Persisted snapshots are restricted evidence; a
    later stateful-resume release must expand %USERPROFILE% when reloading them.
    """
    import re
    from utils.component_context import account_for_report

    secret_names = re.compile(
        r"PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|"
        r"PRIVATE[_-]?KEY|CREDENTIAL|CONNECTION[_-]?STRING",
        re.I,
    )
    identity_names = {"USERNAME", "COMPUTERNAME", "USERDOMAIN", "USERDNSDOMAIN", "LOGONSERVER"}

    def visit(item):
        if isinstance(item, list):
            return [visit(value) for value in item]
        if isinstance(item, dict):
            result = {key: visit(value) for key, value in item.items()}
            if "Name" in item and "Value" in item and "Scope" in item:
                name = str(item.get("Name") or "").upper()
                if name in identity_names:
                    result["Value"] = "[REDACTED]"
                elif secret_names.search(name):
                    result["Value"] = "[REDACTED]"
                elif name not in {"PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR"}:
                    # The arbitrary content of custom environment variables
                    # cannot be classified reliably as safe. Retain indicator
                    # names/scope for diff analysis, not their raw values.
                    result["Value"] = "[REDACTED]"
            for key in ("Principal", "StartName"):
                if isinstance(item.get(key), str):
                    result[key] = account_for_report(item[key])
            return result
        if isinstance(item, str):
            return sanitize_report_text(item)
        return item

    return visit(data)
