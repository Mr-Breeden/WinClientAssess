from __future__ import annotations

import ntpath
import os

from utils.windows_paths import extract_executable

SYSTEM_ACCOUNTS = {
    "localsystem",
    "local system",
    "nt authority\\system",
    "system",
}
SERVICE_ACCOUNTS = SYSTEM_ACCOUNTS | {
    "networkservice",
    "nt authority\\networkservice",
    "nt authority\\network service",
    "localservice",
    "nt authority\\localservice",
    "nt authority\\local service",
}


def basename(path):
    return ntpath.basename(str(path or "").strip().strip('"'))


def normalize_path(path):
    return str(path or "").strip().strip('"').replace("/", "\\").lower()


def privilege_level(account="", run_level=""):
    value = str(account or "").strip().lower()
    compact = value.replace(" ", "")
    if value in SYSTEM_ACCOUNTS or compact in {x.replace(" ", "") for x in SYSTEM_ACCOUNTS}:
        return "SYSTEM"
    if value in SERVICE_ACCOUNTS or compact in {x.replace(" ", "") for x in SERVICE_ACCOUNTS}:
        return "SERVICE"
    if "highest" in str(run_level or "").lower():
        return "HIGHEST"
    return "OTHER"


def is_privileged(account="", run_level=""):
    return privilege_level(account, run_level) in {"SYSTEM", "SERVICE", "HIGHEST"}


def account_for_report(account=""):
    """Normalize the current interactive tester account in persisted evidence."""
    value = str(account or "").strip()
    if not value:
        return ""

    current = str(os.environ.get("USERNAME") or os.environ.get("USER") or "").strip()
    if not current:
        return value

    lowered = value.lower()
    current_lower = current.lower()
    if lowered == current_lower or lowered.endswith("\\" + current_lower) or lowered.endswith("/" + current_lower):
        return "CURRENT_USER"
    return value


def launch_contexts_for_candidate(candidate, diff=None, include_startup=True):
    """
    Correlate an updater/launcher candidate with service, scheduled-task, and
    optional Run/RunOnce launch contexts.
    """
    diff = diff or {}
    path = str(candidate.get("Path") or "")
    name = basename(path).lower()
    path_l = normalize_path(path)
    source = str(candidate.get("Source") or "")
    contexts = []

    for service in diff.get("Services", {}).get("added", []) or []:
        exe = extract_executable(service.get("PathName")) or ""
        basename_fallback = (
            source == "installed differential"
            and bool(name)
            and basename(exe).lower() == name
        )
        if normalize_path(exe) == path_l or basename_fallback:
            contexts.append({
                "Type": "Service",
                "Component": service.get("Name") or service.get("DisplayName"),
                "Account": service.get("StartName"),
                "RunLevel": "",
                "Command": service.get("PathName"),
            })

    for task in diff.get("ScheduledTasks", {}).get("added", []) or []:
        actions = task.get("Actions", []) or []
        if isinstance(actions, dict):
            actions = [actions]
        for action in actions:
            if not isinstance(action, dict):
                continue
            exe = extract_executable(action.get("Execute")) or ""
            basename_fallback = (
                source == "installed differential"
                and bool(name)
                and basename(exe).lower() == name
            )
            if normalize_path(exe) == path_l or basename_fallback:
                contexts.append({
                    "Type": "Scheduled Task",
                    "Component": f"{task.get('TaskPath', '')}{task.get('TaskName', '')}",
                    "Account": task.get("Principal"),
                    "RunLevel": task.get("RunLevel"),
                    "Command": f"{action.get('Execute', '')} {action.get('Arguments', '')}".strip(),
                })

    if include_startup:
        for entry in diff.get("RunEntries", {}).get("added", []) or []:
            value = str(entry.get("Value") or "")
            basename_fallback = (
                source == "installed differential"
                and bool(name)
                and name in value.lower()
            )
            if path_l and path_l in normalize_path(value) or basename_fallback:
                contexts.append({
                    "Type": "Startup Entry",
                    "Component": entry.get("Name"),
                    "Account": "Machine" if str(entry.get("Key", "")).upper().startswith("HKLM:") else "User",
                    "RunLevel": "",
                    "Command": value,
                })

    return contexts


class RuntimeContextIndex:
    """Run-scoped target/process indexes for repeated privilege/path correlation."""

    def __init__(self, runtime_targets=None, runtime_processes=None):
        self.runtime_targets = list(runtime_targets or [])
        self.runtime_processes = list(runtime_processes or [])
        self.target_by_name = {}
        self.target_by_path = {}
        self.processes_by_name = {}
        self.process_by_pid = {}

        for target in self.runtime_targets:
            name = str(target.get("ProcessName") or basename(target.get("Path")) or "").lower()
            path = normalize_path(target.get("Path"))
            if name and name not in self.target_by_name:
                self.target_by_name[name] = target
            if path and path not in self.target_by_path:
                self.target_by_path[path] = target

        for proc in self.runtime_processes:
            name = str(proc.get("Name") or "").lower()
            if name:
                self.processes_by_name.setdefault(name, []).append(proc)
            try:
                pid = int(proc.get("PID"))
            except Exception:
                pid = None
            if pid is not None:
                self.process_by_pid[pid] = proc

    def target_for(self, process=None, process_name=None, exe=None):
        if process:
            process_name = process_name or process.get("Name")
            exe = exe or process.get("Exe")
        path = normalize_path(exe)
        if path and path in self.target_by_path:
            return self.target_by_path[path]
        name = str(process_name or "").lower()
        return self.target_by_name.get(name, {})

    def privileged_for(self, process=None, process_name=None, exe=None):
        indexed_process = None
        explicit_pid = None
        if process:
            try:
                explicit_pid = int(process.get("PID"))
            except Exception:
                explicit_pid = None
            if explicit_pid is not None:
                indexed_process = self.process_by_pid.get(explicit_pid)

        effective_process = indexed_process or process
        target = self.target_for(effective_process, process_name, exe)
        if target and is_privileged(target.get("Account"), target.get("RunLevel")):
            return True, target

        username = str((effective_process or {}).get("Username") or "")
        # If evidence includes a PID but that PID was not present in the runtime
        # process sample, do not borrow privilege from a different process that
        # merely shares the same executable name.
        if not username and process_name and explicit_pid is None:
            for proc in self.processes_by_name.get(str(process_name).lower(), []):
                if is_privileged(proc.get("Username"), ""):
                    return True, target
        if username and is_privileged(username, ""):
            return True, target
        return False, target
