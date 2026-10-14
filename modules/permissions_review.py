from __future__ import annotations
from utils.assessment_layout import artifact_path

import ntpath
from pathlib import Path
from utils.windows_paths import as_list, extract_executable, parent_path
from utils.acl import get_acl_summaries, broad_write_aces


SECURITY_RELEVANT_EXTS = {
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr",
    ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".config", ".json", ".xml", ".ini", ".yaml", ".yml", ".toml",
    ".conf", ".cfg", ".properties",
    ".db", ".sqlite", ".sqlite3",
    ".pfx", ".p12", ".pem", ".key", ".cer", ".crt",
}

MAX_ACL_CANDIDATES = 600


def _normalized(path):
    return ntpath.normcase(ntpath.normpath(str(path or "").strip().strip('"').replace('/', '\\')))


def _specific_scope_root(path):
    """Ignore generic/system roots that cannot prove application ownership."""
    root = _normalized(path).rstrip('\\')
    if not root or not ntpath.isabs(root):
        return ""
    generic = {
        r"c:\windows", r"c:\windows\system32", r"c:\windows\syswow64",
        r"c:\program files", r"c:\program files (x86)",
        r"c:\programdata", r"c:\users", r"c:\users\public",
    }
    if root in generic or root.startswith("c:\\windows\\"):
        return ""
    # Require an actual application-specific child of an install location.
    if len(root.split('\\')) < 3:
        return ""
    return root


def _application_scope_roots(new_services, new_tasks, diff, supplied_roots=None):
    roots = set()
    for path in supplied_roots or []:
        root = _specific_scope_root(path)
        if root:
            roots.add(root)
    for svc in new_services:
        executable = extract_executable(svc.get("PathName"))
        if executable:
            root = _specific_scope_root(ntpath.dirname(executable))
            if root:
                roots.add(root)
    for task in new_tasks:
        actions = as_list(task.get("Actions", []))
        for action in actions:
            executable = extract_executable(action.get("Execute"))
            if executable:
                root = _specific_scope_root(ntpath.dirname(executable))
                if root:
                    roots.add(root)
    # A newly registered application is not proof it belongs to the target.
    # Background software updates commonly run during installer observation.
    # When service/task/tester roots establish ownership, accept an app location
    # only when it overlaps one of those high-confidence roots. Without an
    # anchor, retain the historical installed-application fallback for clients
    # with no services or scheduled tasks, subject to an attribution warning.
    anchors = tuple(roots)
    for app in (diff.get("InstalledApplications", {}).get("added", []) or []):
        if not isinstance(app, dict):
            continue
        root = _specific_scope_root(app.get("InstallLocation") or app.get("InstallPath"))
        if root and (not anchors or any(
            root == anchor or root.startswith(anchor + "\\") or anchor.startswith(root + "\\")
            for anchor in anchors
        )):
            roots.add(root)
    return sorted(roots)


def _under_scope(path, scope_roots):
    normalized = _normalized(path)
    return any(normalized == root or normalized.startswith(root + '\\') for root in scope_roots)


def _filesystem_path(entry):
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("Path") or "").strip()


def _is_security_relevant_file(path: str):
    try:
        return Path(path).suffix.lower() in SECURITY_RELEVANT_EXTS
    except Exception:
        return False


def _add_candidate(rows, priority, kind, component, path, account="", source=""):
    path = str(path or "").strip()
    if not path:
        return
    rows.append(
        {
            "Priority": priority,
            "Kind": kind,
            "Component": component or "",
            "Path": path,
            "Account": account or "",
            "Source": source or "",
        }
    )


def _candidate_paths(pre, post, diff=None, scope_roots=None, runtime_dll_records=None, *, stats=None):
    """
    Build a prioritized ACL target list.

    v0.2.1 reviewed only executables/directories referenced by *new* services and
    scheduled tasks. v0.2.2 also consumes the installation filesystem
    differential so installations that do not create services/tasks still receive
    meaningful ACL review.
    """
    diff = diff or {}
    rows = []

    # Highest priority: paths directly referenced by newly installed services.
    # Prefer the authoritative snapshot diff; retain pre/post fallback for direct module use.
    if isinstance(diff, dict) and "Services" in diff:
        new_services = as_list(diff.get("Services", {}).get("added", []))
    else:
        pre_services = {x.get("Name") for x in as_list((pre or {}).get("Services", []))}
        new_services = [
            service for service in as_list((post or {}).get("Services", []))
            if service.get("Name") not in pre_services
        ]
    for service in new_services:
        executable = extract_executable(service.get("PathName"))
        if executable:
            _add_candidate(
                rows, 0, "Service executable", service.get("Name"),
                executable, service.get("StartName"), "New service"
            )
            parent = parent_path(executable)
            if parent:
                _add_candidate(
                    rows, 1, "Service directory", service.get("Name"),
                    parent, service.get("StartName"), "New service"
                )

    # Highest priority: paths directly referenced by newly installed tasks.
    if isinstance(diff, dict) and "ScheduledTasks" in diff:
        new_tasks = as_list(diff.get("ScheduledTasks", {}).get("added", []))
    else:
        pre_tasks = {
            (x.get("TaskPath"), x.get("TaskName"))
            for x in as_list((pre or {}).get("ScheduledTasks", []))
        }
        new_tasks = [
            task for task in as_list((post or {}).get("ScheduledTasks", []))
            if (task.get("TaskPath"), task.get("TaskName")) not in pre_tasks
        ]
    for task in new_tasks:
        actions = task.get("Actions", [])
        if isinstance(actions, dict):
            actions = [actions]
        for action in actions or []:
            executable = extract_executable(action.get("Execute"))
            if not executable:
                continue
            label = f"{task.get('TaskPath')}{task.get('TaskName')}"
            _add_candidate(
                rows, 2, "Scheduled task executable", label,
                executable, task.get("Principal"), "New scheduled task"
            )
            parent = parent_path(executable)
            if parent:
                _add_candidate(
                    rows, 3, "Scheduled task directory", label,
                    parent, task.get("Principal"), "New scheduled task"
                )

    strong_roots = _application_scope_roots(new_services, new_tasks, diff, scope_roots)
    if stats is not None:
        stats["scoped_roots"] = strong_roots
        stats["out_of_scope_filesystem"] = 0
        stats["unattributed_filesystem"] = not bool(strong_roots)

    fs = diff.get("Filesystem", {}) if isinstance(diff, dict) else {}
    added = fs.get("added", []) or []
    changed = fs.get("changed", []) or []

    # Added application-root directories (directories directly beneath one of the
    # snapshot roots) are useful ACL checkpoints without reviewing every directory.
    for entry in added:
        if not isinstance(entry, dict) or not entry.get("IsDirectory"):
            continue
        path = _filesystem_path(entry)
        root = str(entry.get("Root") or "").rstrip("\\/")
        parent = ntpath.dirname(path) if path else ""
        if root and _normalized(parent) == _normalized(root):
            if strong_roots and not _under_scope(path, strong_roots):
                if stats is not None:
                    stats["out_of_scope_filesystem"] += 1
                continue
            _add_candidate(
                rows, 10, "Added application directory", path,
                path, "", "Filesystem added"
            )

    # Added security-sensitive files and their parent directories.
    for entry in added:
        if not isinstance(entry, dict) or entry.get("IsDirectory"):
            continue
        path = _filesystem_path(entry)
        if not path or not _is_security_relevant_file(path):
            continue
        if strong_roots and not _under_scope(path, strong_roots):
            if stats is not None:
                stats["out_of_scope_filesystem"] += 1
            continue
        _add_candidate(
            rows, 20, "Added security-relevant file", ntpath.basename(path),
            path, "", "Filesystem added"
        )
        parent = parent_path(path)
        if parent:
            _add_candidate(
                rows, 21, "Parent directory of added security-relevant file",
                ntpath.basename(path), parent, "", "Filesystem added"
            )

    # Changed security-sensitive files and their parent directories.
    for entry in changed:
        if not isinstance(entry, dict):
            continue
        after = entry.get("after", {}) if isinstance(entry.get("after"), dict) else {}
        if after.get("IsDirectory"):
            continue
        path = _filesystem_path(after)
        if not path or not _is_security_relevant_file(path):
            continue
        if strong_roots and not _under_scope(path, strong_roots):
            if stats is not None:
                stats["out_of_scope_filesystem"] += 1
            continue
        _add_candidate(
            rows, 30, "Changed security-relevant file", ntpath.basename(path),
            path, "", "Filesystem changed"
        )
        parent = parent_path(path)
        if parent:
            _add_candidate(
                rows, 31, "Parent directory of changed security-relevant file",
                ntpath.basename(path), parent, "", "Filesystem changed"
            )

    # Runtime DLL-search evidence is a second application-specific ACL discovery
    # source.  The caller supplies only target-filtered Procmon observations.
    # Review existing directories with a broad-write match or a plausible
    # writable location; exclude generic/system paths and de-duplicate paths
    # already covered by service/task or filesystem review.
    for record in runtime_dll_records or []:
        if not isinstance(record, dict):
            continue
        parent = str(record.get("SearchDirectory") or "").strip()
        if not _specific_scope_root(parent) or not record.get("DirectoryExists"):
            continue
        if not (record.get("BroadWriteACEs") or record.get("LikelyUserWritableLocation")):
            continue
        process = str(record.get("Process") or "Unknown process")
        missing = ntpath.basename(str(record.get("MissingDLL") or ""))
        _add_candidate(
            rows, 4, "Runtime DLL-search directory", f"{process} -> {missing}",
            parent, str(record.get("Account") or ""), "Runtime DLL search",
        )
        rows[-1]["DLLCorrelations"] = [
            {
                "ID": str(record.get("ID") or ""),
                "Process": process,
                "MissingDLL": missing,
                "PrivilegedContext": bool(record.get("PrivilegedContext")),
            }
        ]

    # Sort by security relevance, then de-duplicate by path. If the same path is
    # referenced by a service and the filesystem differential, the service context
    # wins because it carries more useful privilege information.
    rows.sort(key=lambda x: (x["Priority"], x["Path"].lower()))
    seen = set()
    output = []
    for row in rows:
        key = _normalized(row["Path"])
        if key in seen:
            # Preserve runtime lookup references on an existing higher-priority
            # service/task/filesystem path rather than adding a duplicate ACL.
            if row.get("DLLCorrelations"):
                existing = next(item for item in output if _normalized(item["Path"]) == key)
                for reference in row["DLLCorrelations"]:
                    if reference not in existing.setdefault("DLLCorrelations", []):
                        existing["DLLCorrelations"].append(reference)
            continue
        seen.add(key)
        output.append(row)

    return output


def run_permissions_review(assessment_dir: Path, pre=None, post=None, diff=None, acl_cache=None, scope_roots=None, runtime_dll_records=None):
    triage_stats = {}
    candidates = _candidate_paths(pre, post, diff, scope_roots, runtime_dll_records, stats=triage_stats)
    diff = diff or {}
    discovered_roots = _application_scope_roots(
        as_list(diff.get("Services", {}).get("added", [])),
        as_list(diff.get("ScheduledTasks", {}).get("added", [])),
        diff, scope_roots,
    )
    selected = candidates[:MAX_ACL_CANDIDATES]

    acl_map = acl_cache.get_many([c["Path"] for c in selected]) if acl_cache else get_acl_summaries([c["Path"] for c in selected])
    results = []
    for candidate in selected:
        acl = acl_map.get(
            candidate["Path"].lower(),
            {
                "Path": candidate["Path"],
                "Exists": False,
                "Owner": None,
                "Access": [],
                "Error": "ACL result was not returned.",
            },
        )
        results.append(
            {
                "Kind": candidate["Kind"],
                "Component": candidate["Component"],
                "Account": candidate["Account"],
                "Source": candidate["Source"],
                "DLLCorrelations": candidate.get("DLLCorrelations", []),
                "Path": candidate["Path"],
                "ACL": acl,
                "BroadWrite": broad_write_aces(acl),
            }
        )

    width = 100
    existing = [r for r in results if (r.get("ACL") or {}).get("Exists")]
    missing = [r for r in results if not (r.get("ACL") or {}).get("Exists")]
    suspicious = [r for r in results if r.get("BroadWrite")]

    service_task_count = sum(
        1 for c in candidates
        if c["Source"] in {"New service", "New scheduled task"}
    )
    filesystem_count = sum(
        1 for c in candidates
        if c["Source"] in {"Filesystem added", "Filesystem changed"}
    )
    runtime_correlated = [c for c in candidates if c.get("DLLCorrelations")]

    lines = [
        "WCA - PERMISSIONS REVIEW",
        "=" * width,
        "",
        "Purpose:",
        "  Reviews ACLs associated with newly installed privileged components and security-relevant",
        "  files/directories identified by the installation filesystem differential.",
        "  Broad-write matches are triage indicators and require effective-permission validation.",
        "",
        "ACL CANDIDATE SUMMARY",
        "-" * width,
        f"Service / scheduled-task candidates : {service_task_count}",
        f"Filesystem-differential candidates  : {filesystem_count}",
        f"DLL-search-correlated directories   : {len(runtime_correlated)}",
        f"Total unique candidate paths        : {len(candidates)}",
        f"Candidate limit                     : {MAX_ACL_CANDIDATES}",
        f"Paths selected for ACL review       : {len(selected)}",
        f"Existing paths successfully located : {len(existing)}",
        f"Missing/unavailable paths            : {len(missing)}",
        f"Broad-write review matches           : {len(suspicious)}",
        f"Application-specific ACL roots       : {len(discovered_roots)}",
        f"Out-of-scope filesystem entries     : {triage_stats.get('out_of_scope_filesystem', 0)}",
        f"Unattributed filesystem scope       : {'YES - verify ownership' if triage_stats.get('unattributed_filesystem') else 'NO'}",
        "",
    ]

    if triage_stats.get("unattributed_filesystem"):
        lines += [
            "ATTRIBUTION LIMITATION: no specific application ownership roots were established.",
            "Filesystem ACL candidates are provisional; correlate with target installer evidence.",
            "",
        ]

    if discovered_roots:
        lines += [
            "Scoped ACL triage: filesystem candidates unrelated to the identified application",
            "roots were omitted from automatic ACL checks, not from the system-state differential.",
            "Inspect install_changes.txt for shared components or out-of-tree security-sensitive files observed in the differential.",
            "",
        ]

    if len(candidates) > MAX_ACL_CANDIDATES:
        lines += [
            "NOTE:",
            f"  {len(candidates) - MAX_ACL_CANDIDATES} lower-priority candidate path(s) were not automatically",
            "  queried because the safety/performance limit was reached. Service/task paths and",
            "  security-relevant installed files are prioritized first.",
            "",
        ]

    if not results:
        lines += [
            "No ACL candidates were identified.",
            "",
            "This means the system-state differential did not contain a new service/task path,",
            "an added top-level application directory, or an added/changed security-relevant file",
            "matching the current Windows Client Assessment ACL review rules.",
            "",
        ]

    for idx, result in enumerate(results, 1):
        acl = result.get("ACL", {}) or {}
        all_aces = acl.get("Access", [])
        if isinstance(all_aces, dict):
            all_aces = [all_aces]
        broad_aces = result.get("BroadWrite", []) or []
        if isinstance(broad_aces, dict):
            broad_aces = [broad_aces]

        lines += [
            "=" * width,
            f"[ACL-{idx:03d}] {result['Kind']}",
            "=" * width,
            f"Source    : {result.get('Source')}",
            f"Component : {result.get('Component')}",
            f"Account   : {result.get('Account') or 'N/A'}",
            f"Path      : {result.get('Path')}",
            f"Exists    : {acl.get('Exists')}",
            f"Owner     : {acl.get('Owner')}",
        ]
        if result.get("DLLCorrelations"):
            lines.append("Runtime DLL-search references:")
            for ref in result["DLLCorrelations"]:
                lines.append(
                    f"  {ref['ID'] or 'DLL'} | {ref['Process']} -> {ref['MissingDLL']} "
                    f"| privileged context: {ref['PrivilegedContext']}"
                )
            lines.append("  Cross-reference: dll_search_review.txt. A broad ACE alone does not prove exploitation.")
        if acl.get("Error"):
            lines.append(f"ACL Error : {acl.get('Error')}")
        lines += [
            "",
            f"Broad Write ACEs ({len(broad_aces)})",
            "-" * width,
        ]

        if not broad_aces:
            lines.append("None identified by automated broad-write matching.")
        else:
            for ace_idx, ace in enumerate(broad_aces, 1):
                lines += [
                    f"  [{ace_idx:02d}] Identity : {ace.get('Identity')}",
                    f"       Rights   : {ace.get('Rights')}",
                    f"       Type     : {ace.get('Type')}",
                    f"       Inherited: {ace.get('Inherited')}",
                    "",
                ]

        lines += [
            f"All ACL Entries ({len(all_aces)})",
            "-" * width,
        ]
        if not all_aces:
            lines.append("No ACL entries returned.")
        else:
            for ace_idx, ace in enumerate(all_aces, 1):
                marker = " [BROAD-WRITE REVIEW]" if ace in broad_aces else ""
                lines += [
                    f"  [{ace_idx:02d}]{marker}",
                    f"       Identity : {ace.get('Identity')}",
                    f"       Rights   : {ace.get('Rights')}",
                    f"       Type     : {ace.get('Type')}",
                    f"       Inherited: {ace.get('Inherited')}",
                    "",
                ]
        lines.append("")

    (artifact_path(assessment_dir, "permissions_review.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    findings = []
    if suspicious:
        findings.append(
            {
                "title": "Installed Component Permissions Require Manual Validation",
                "severity": "Informational",
                "description": (
                    "One or more newly installed privileged-component or security-relevant "
                    "filesystem paths include broad write-capable ACL entries. The privilege "
                    "context and effective permissions require validation."
                ),
                "evidence": f"{len(suspicious)} path(s) matched broad write indicators.",
                "recommendation": (
                    "Validate effective permissions as a standard user and determine whether "
                    "modification can influence a higher-privileged component or application behavior."
                ),
            }
        )

    return {
        "status": "WARN" if suspicious or (candidates and not existing) else "PASS",
        "details": (
            f"{len(selected)} ACL candidate path(s) reviewed from "
            f"{service_task_count} service/task, {filesystem_count} filesystem and "
            f"{len(runtime_correlated)} DLL-correlated directories; "
            f"{len(suspicious)} broad-write match(es)"
        ),
        "findings": findings,
        "permission_results": results,
    }
