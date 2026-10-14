from __future__ import annotations
from utils.assessment_layout import artifact_path

import ntpath
import os
from pathlib import Path

from utils.acl import get_acl_summaries, broad_write_aces
from utils.component_context import RuntimeContextIndex, normalize_path
from utils.windows_paths import is_user_profile_path, is_temp_path


def _likely_user_writable(path: str):
    candidate = normalize_path(path)
    return is_user_profile_path(path) or is_temp_path(path) or candidate.startswith(r"c:\users\public") or "\\temp\\" in candidate


def _acl_probe_path(path):
    """Resolve redacted tester profile only in volatile ACL collection memory."""
    profile = os.environ.get("USERPROFILE", "").strip()
    prefix = "%USERPROFILE%"
    if profile and path.upper().startswith(prefix):
        return profile + path[len(prefix):]
    return path


def run_dll_search_review(assessment_dir: Path, procmon_data=None, runtime_targets=None, acl_cache=None):
    missing = (procmon_data or {}).get("missing_dlls", []) or []
    context = RuntimeContextIndex(runtime_targets or [], [])

    # De-duplicate identical process/path results.
    unique = []
    seen = set()
    for event in missing:
        process = str(event.get("Process") or "")
        path = str(event.get("Path") or "")
        key = (process.lower(), path.lower())
        if not process or not path or key in seen:
            continue
        seen.add(key)
        unique.append(event)

    parent_paths = []
    for event in unique:
        parent = ntpath.dirname(str(event.get("Path") or ""))
        if parent:
            parent_paths.append(_acl_probe_path(parent))

    acl_map = acl_cache.get_many(parent_paths) if acl_cache else get_acl_summaries(parent_paths)

    records = []
    poi = []
    for idx, event in enumerate(unique, 1):
        process = str(event.get("Process") or "")
        path = str(event.get("Path") or "")
        parent = ntpath.dirname(path)
        privileged, target = context.privileged_for(process_name=process)
        actual_parent = _acl_probe_path(parent)
        acl = acl_map.get(actual_parent.lower())
        if acl is None:
            # A literal %USERPROFILE% cannot be probed as a directory. UNKNOWN
            # is more accurate than FALSE when identity resolution is missing.
            acl = {"Path": parent, "Exists": None if "%USERPROFILE%" in actual_parent.upper() else False,
                   "Owner": None, "Access": []}
        broad = broad_write_aces(acl)
        user_location = _likely_user_writable(parent) or bool(broad)

        record = {
            "ID": f"DLL-{idx:04d}",
            "Process": process,
            "PID": event.get("PID"),
            "MissingDLL": path,
            "SearchDirectory": parent,
            "Result": event.get("Result"),
            "Source": target.get("Source", "Procmon runtime"),
            "Component": target.get("Component", ""),
            "Account": target.get("Account", ""),
            "RunLevel": target.get("RunLevel", ""),
            "PrivilegedContext": privileged,
            "DirectoryExists": acl.get("Exists"),
            "DirectoryOwner": acl.get("Owner"),
            "BroadWriteACEs": broad,
            "LikelyUserWritableLocation": user_location,
        }
        records.append(record)

        # Ordinary user-profile DLL lookup noise is not independently actionable.
        # Require a verified broad-write ACE, or a privileged consumer using a
        # user-controlled lookup directory; preserve every lookup in full list.
        if broad or (privileged and user_location):
            confidence = "HIGH" if privileged and broad else "MEDIUM" if privileged or broad else "LOW"
            poi_record = dict(record)
            poi_record["POI"] = f"POI-DL-{len(poi) + 1:03d}"
            poi_record["Confidence"] = confidence
            poi.append(poi_record)

    width = 112
    lines = [
        "WCA - DLL SEARCH / MISSING DLL REVIEW",
        "=" * width,
        "",
        "Purpose:",
        "  Correlates Procmon NAME NOT FOUND/PATH NOT FOUND DLL lookups with the searched directory,",
        "  runtime component context, and directory ACLs. A missing DLL is not a vulnerability by itself.",
        "",
        f"Unique missing DLL lookups : {len(records)}",
        f"Review points              : {len(poi)}",
        "",
        "POINTS OF INTEREST",
        "-" * width,
    ]

    if not poi:
        lines.append("No missing-DLL lookup was automatically correlated with a broad-write ACL or likely user-writable location.")
        lines.append("The complete lookup list remains available below for manual review.")
        lines.append("")

    for item in poi:
        lines += [
            "=" * width,
            f"[{item['POI']}] {item['Process']} -> {ntpath.basename(item['MissingDLL'])}",
            "=" * width,
            f"Confidence              : {item['Confidence']}",
            f"Process                 : {item['Process']}",
            f"PID                     : {item['PID']}",
            f"Missing DLL             : {item['MissingDLL']}",
            f"Search Directory        : {item['SearchDirectory']}",
            f"Component Source        : {item['Source']}",
            f"Component               : {item['Component'] or 'N/A'}",
            f"Account                 : {item['Account'] or 'N/A'}",
            f"Run Level               : {item['RunLevel'] or 'N/A'}",
            f"Privileged Context      : {item['PrivilegedContext']}",
            f"Directory Exists        : {item['DirectoryExists']}",
            f"Likely User-Writable    : {item['LikelyUserWritableLocation']}",
            f"Broad Write ACE Count   : {len(item['BroadWriteACEs'])}",
            "",
            "Manual Validation:",
            "  Confirm effective standard-user write permissions, verify the application actually attempts",
            "  to load the missing library from this location, and only then determine whether a practical",
            "  DLL search-order/hijacking condition exists across a meaningful privilege boundary.",
            "",
        ]

    lines += ["", "COMPLETE MISSING DLL LOOKUP LIST", "-" * width]
    for record in records:
        lines += [
            f"{record['ID']} | {record['Process']} | {record['Result']} | {record['MissingDLL']}",
            f"         Directory: {record['SearchDirectory']}",
            f"         Broad-write ACEs: {len(record['BroadWriteACEs'])} | Likely user-writable: {record['LikelyUserWritableLocation']}",
            "",
        ]

    (artifact_path(assessment_dir, "dll_search_review.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )
    return {
        "status": "WARN" if poi else "PASS",
        "details": f"{len(records)} missing DLL lookup(s); {len(poi)} DLL search review point(s)",
        "dll_records": records,
        "dll_pois": poi,
    }
