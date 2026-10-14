from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
import re
import ntpath
from utils.windows_paths import extract_executable, parent_path, is_user_profile_path, is_temp_path
from utils.acl import get_acl_summary, broad_write_aces, broad_create_file_aces
from utils.component_context import privilege_level, is_privileged

CONFIG_EXTS = {
    ".config",
    ".json",
    ".xml",
    ".ini",
    ".yaml",
    ".yml",
    ".toml",
    ".conf",
    ".cfg",
    ".db",
    ".sqlite",
    ".sqlite3",
}


def _priv_level(account):
    level = privilege_level(account, "")
    return level if level in {"SYSTEM", "SERVICE"} else "OTHER"


def _acl_check(path, permission_acl_map=None, acl_cache=None):
    key = str(path or "").lower()
    acl = (permission_acl_map or {}).get(key)
    if acl is None:
        acl = acl_cache.get(path) if acl_cache else get_acl_summary(path)
    return acl, broad_write_aces(acl)




def _unquoted_service_candidates(executable: str) -> list[str]:
    """Return Windows CreateProcess intermediate executable candidates for an unquoted path.

    Example: C:\\Program Files\\Vendor App\\service.exe -> C:\\Program.exe,
    C:\\Program Files\\Vendor.exe. The real service executable is excluded.
    """
    value = str(executable or '').strip().strip('"')
    if not value or ' ' not in value:
        return []
    out=[]
    seen=set()
    for idx, ch in enumerate(value):
        if ch != ' ':
            continue
        candidate=value[:idx] + '.exe'
        if candidate.lower() == value.lower() or candidate.lower() in seen:
            continue
        seen.add(candidate.lower())
        out.append(candidate)
    return out

def _record(records, component_type, component, context, issue, path, evidence, confidence="HIGH"):
    records.append(
        {
            "ComponentType": component_type,
            "Component": component,
            "ExecutionContext": context,
            "Issue": issue,
            "Path": path,
            "Evidence": evidence,
            "Confidence": confidence,
        }
    )


def run_privilege_boundary_review(assessment_dir: Path, diff=None, post=None, permission_results=None, acl_cache=None):
    diff = diff or {}
    records = []
    permission_acl_map = {}
    for item in permission_results or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("Path") or "")
        acl = item.get("ACL")
        if path and isinstance(acl, dict):
            permission_acl_map[path.lower()] = acl
    added_files = [
        x for x in diff.get("Filesystem", {}).get("added", []) if not x.get("IsDirectory")
    ]

    for service in diff.get("Services", {}).get("added", []):
        context = _priv_level(service.get("StartName"))
        if context not in {"SYSTEM", "SERVICE"}:
            continue
        name = service.get("Name") or service.get("DisplayName") or "service"
        executable = extract_executable(service.get("PathName"))

        if executable:
            _, hits = _acl_check(executable, permission_acl_map, acl_cache)
            if hits:
                _record(records, "Service", name, context, "Privileged service executable is broadly writable", executable, hits)

            parent = parent_path(executable)
            if parent:
                _, parent_hits = _acl_check(parent, permission_acl_map, acl_cache)
                if parent_hits:
                    _record(records, "Service", name, context, "Privileged service executable directory is broadly writable", parent, parent_hits)

            if is_user_profile_path(executable) or is_temp_path(executable):
                _record(
                    records,
                    "Service",
                    name,
                    context,
                    "Privileged service executes from a user-profile or temporary path",
                    executable,
                    "Path location is normally user-controlled or transient.",
                )

            try:
                parent_lower = str(Path(executable).parent).lower()
                configs = [
                    x.get("Path")
                    for x in added_files
                    if str(x.get("Path", "")).lower().startswith(parent_lower)
                    and Path(str(x.get("Path", ""))).suffix.lower() in CONFIG_EXTS
                ]
            except Exception:
                configs = []

            for config in configs[:50]:
                _, config_hits = _acl_check(config, permission_acl_map, acl_cache)
                if config_hits:
                    _record(
                        records,
                        "Service",
                        name,
                        context,
                        "Privileged service-adjacent configuration file is broadly writable",
                        config,
                        config_hits,
                    )

            # Correlate broadly writable newly installed data directories whose
            # names overlap the privileged service/vendor identity. This flags
            # locations such as ProgramData vendor roots without claiming that
            # the service necessarily consumes them.
            identity_text = " ".join(
                str(value or "") for value in (name, service.get("DisplayName"), executable)
            ).lower()
            identity_tokens = {token for token in re.findall(r"[a-z0-9]+", identity_text) if len(token) >= 5}
            for candidate_path, candidate_acl in permission_acl_map.items():
                lower_path = candidate_path.lower()
                if "\\programdata\\" not in lower_path or not broad_write_aces(candidate_acl):
                    continue
                if any(token in lower_path for token in identity_tokens):
                    _record(
                        records,
                        "Service",
                        name,
                        context,
                        "Privileged service has a potentially related broadly writable ProgramData directory",
                        candidate_path,
                        broad_write_aces(candidate_acl),
                        "MEDIUM",
                    )

        command = str(service.get("PathName") or "")
        if context == "SYSTEM" and executable and " " in executable and not command.lstrip().startswith('"'):
            candidate_evidence=[]
            writable_candidates=[]
            for candidate in _unquoted_service_candidates(executable):
                parent = ntpath.dirname(candidate) or candidate
                candidate_acl = (permission_acl_map or {}).get(str(parent).lower())
                if candidate_acl is None:
                    candidate_acl = acl_cache.get(parent) if acl_cache else get_acl_summary(parent)
                candidate_hits = broad_create_file_aces(candidate_acl)
                candidate_evidence.append(
                    f"{candidate} | Parent={parent} | CreateFile={len(candidate_hits)}"
                )
                if candidate_hits:
                    writable_candidates.append((candidate, parent, candidate_hits))
            if writable_candidates:
                evidence='; '.join(
                    f"{candidate} via writable parent {parent}: {hits}"
                    for candidate, parent, hits in writable_candidates
                )
                _record(
                    records, "Service", name, context,
                    "Unquoted SYSTEM service path has a writable intermediate candidate",
                    command, evidence, "HIGH",
                )
            else:
                _record(
                    records, "Service", name, context,
                    "Unquoted SYSTEM service path requires intermediate-path validation",
                    command,
                    '; '.join(candidate_evidence) or 'No intermediate CreateProcess candidates could be derived.',
                    "MEDIUM",
                )

    for task in diff.get("ScheduledTasks", {}).get("added", []):
        principal = str(task.get("Principal") or "")
        runlevel = str(task.get("RunLevel") or "")
        privileged = is_privileged(principal, runlevel)
        if not privileged:
            continue

        context = "SYSTEM" if privilege_level(principal, runlevel) == "SYSTEM" else "HIGHEST"
        name = f"{task.get('TaskPath', '')}{task.get('TaskName', '')}"
        actions = task.get("Actions", [])
        if isinstance(actions, dict):
            actions = [actions]

        for action in actions or []:
            executable = extract_executable(action.get("Execute"))
            if not executable:
                continue
            _, hits = _acl_check(executable, permission_acl_map, acl_cache)
            if hits:
                _record(records, "Scheduled Task", name, context, "Privileged scheduled task executable/script is broadly writable", executable, hits)

            parent = parent_path(executable)
            if parent:
                _, parent_hits = _acl_check(parent, permission_acl_map, acl_cache)
                if parent_hits:
                    _record(records, "Scheduled Task", name, context, "Privileged scheduled task directory is broadly writable", parent, parent_hits)

            if is_user_profile_path(executable) or is_temp_path(executable):
                _record(
                    records,
                    "Scheduled Task",
                    name,
                    context,
                    "Privileged scheduled task executes from user-profile or temporary path",
                    executable,
                    "Path location is normally user-controlled or transient.",
                )

            working_dir = str(action.get("WorkingDirectory") or action.get("WorkingDirectoryPath") or "").strip()
            if working_dir:
                _, wd_hits = _acl_check(working_dir, permission_acl_map, acl_cache)
                if wd_hits:
                    _record(
                        records, "Scheduled Task", name, context,
                        "Privileged scheduled task working directory is broadly writable",
                        working_dir, wd_hits,
                    )
                elif is_user_profile_path(working_dir) or is_temp_path(working_dir):
                    _record(
                        records, "Scheduled Task", name, context,
                        "Privileged scheduled task uses a user-profile or temporary working directory",
                        working_dir, "Working directory is normally user-controlled or transient.", "MEDIUM",
                    )

    for entry in diff.get("RunEntries", {}).get("added", []):
        if not str(entry.get("Key", "")).upper().startswith("HKLM:"):
            continue
        executable = extract_executable(entry.get("Value"))
        if not executable:
            continue
        _, hits = _acl_check(executable, permission_acl_map, acl_cache)
        if hits or is_user_profile_path(executable) or is_temp_path(executable):
            _record(
                records,
                "HKLM Startup",
                entry.get("Name"),
                "MACHINE STARTUP",
                "Machine-wide startup entry points to a broadly writable or user-controlled path",
                executable,
                hits or "User-profile/temp path",
            )

    lines = ["Privilege Boundary Review", "=" * 25, "", f"Correlated review points: {len(records)}", ""]
    if not records:
        lines.append("No high-confidence privilege-boundary correlations were identified automatically.")

    for index, record in enumerate(records, 1):
        lines += [
            f"[POI-PB-{index:03d}]",
            f"Component Type: {record['ComponentType']}",
            f"Component: {record['Component']}",
            f"Execution Context: {record['ExecutionContext']}",
            f"Issue: {record['Issue']}",
            f"Path: {record['Path']}",
            f"Evidence: {record['Evidence']}",
            f"Confidence: {record['Confidence']}",
            "Recommended Test: Validate effective access as a standard user and determine whether controlled modification changes privileged execution.",
            "",
        ]

    (artifact_path(assessment_dir, "privilege_boundary_review.txt")).write_text("\n".join(lines), encoding="utf-8")
    high = [record for record in records if record["Confidence"] == "HIGH"]
    findings = []
    if high:
        findings.append(
            {
                "title": "Potential Privilege-Boundary Weaknesses Require Validation",
                "severity": "Informational",
                "description": "Windows Client Assessment correlated one or more higher-privileged services/tasks/startup components with broadly writable or user-controlled paths. These are validation targets, not confirmed vulnerabilities.",
                "evidence": f"{len(high)} high-confidence correlated review point(s) identified.",
                "recommendation": "Validate each POI as a standard user and only elevate to a reportable vulnerability when modification demonstrably influences privileged execution.",
            }
        )

    return {
        "status": "WARN" if records else "PASS",
        "details": f"{len(records)} correlated privilege-boundary review point(s)",
        "findings": findings,
        "records": records,
    }
