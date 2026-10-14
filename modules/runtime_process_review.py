from __future__ import annotations
from utils.assessment_layout import artifact_path

import ntpath
import hashlib
from functools import lru_cache
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import psutil

from utils.command_runner import run_command
from utils.component_context import normalize_path as _norm, account_for_report
from utils.path_filters import path_is_excluded


MAX_SYSINTERNAL_PROCESSES = 30


def _target_context(runtime_targets):
    names = set()
    exact_paths = set()
    dirs = set()
    portable_hashes = {}
    for target in runtime_targets or []:
        path = str(target.get("Path") or "")
        name = str(target.get("ProcessName") or ntpath.basename(path))
        if name:
            names.add(name.lower())
        if target.get("PortablePrimary") and target.get("PrimarySHA256"):
            portable_hashes[name.lower()] = str(target["PrimarySHA256"]).lower()
        # A relative filename or unresolved %SOURCE_DIR% must not be treated
        # as a Windows directory or as an identity match for another application.
        if path and ntpath.isabs(path) and "%" not in path:
            norm = _norm(path)
            exact_paths.add(norm)
            parent = _norm(ntpath.dirname(path))
            if parent:
                dirs.add(parent)
    return names, exact_paths, dirs, portable_hashes


@lru_cache(maxsize=128)
def _hash_executable(path: str, size: int, mtime_ns: int) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def _matches_primary_hash(path: str, expected: str) -> bool:
    try:
        stat = __import__("os").stat(path)
        return _hash_executable(path, stat.st_size, stat.st_mtime_ns) == expected
    except (OSError, ValueError):
        return False


def _is_target_process(name, exe, names, exact_paths, dirs, observed_names):
    name_l = str(name or "").lower()
    exe_l = _norm(exe)
    if exe_l and exe_l in exact_paths:
        return True
    if exe_l:
        for directory in dirs:
            if directory and exe_l.startswith(directory + "\\"):
                return True
        # When the executable path is available, require path evidence. This
        # prevents a different installed version with the same basename from
        # being borrowed into the target set.
        return False
    if name_l and (name_l in names or name_l in observed_names):
        return True
    return False


def _network_by_pid():
    result = defaultdict(list)
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.pid:
                continue
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            result[conn.pid].append(
                {
                    "Family": str(conn.family),
                    "Type": str(conn.type),
                    "Local": laddr,
                    "Remote": raddr,
                    "Status": str(conn.status),
                }
            )
    except Exception:
        pass
    return result


def collect_runtime_processes(runtime_targets=None, observed_process_names=None, exclude_paths=None):
    names, exact_paths, dirs, primary_hashes = _target_context(runtime_targets)
    observed = {str(x).lower() for x in (observed_process_names or []) if x}
    network = _network_by_pid()
    rows = []
    validated_portable_roots = set()
    candidates = []

    for proc in psutil.process_iter():
        try:
            with proc.oneshot():
                info = {
                    "PID": proc.pid,
                    "PPID": proc.ppid(),
                    "Name": proc.name(),
                    "Exe": proc.exe() or "",
                    "Username": proc.username() or "",
                    "Status": proc.status(),
                    "CommandLine": " ".join(proc.cmdline() or []),
                    "CreateTime": datetime.fromtimestamp(proc.create_time()).isoformat(),
                }
                if path_is_excluded(info["Exe"], exclude_paths):
                    continue
                candidate_name = str(info["Name"] or "").lower()
                hash_expected = primary_hashes.get(candidate_name)
                if hash_expected and info["Exe"] and _matches_primary_hash(info["Exe"], hash_expected):
                    info["IdentitySource"] = "Selected primary executable SHA-256"
                    validated_portable_roots.add(_norm(ntpath.dirname(info["Exe"])))
                elif not hash_expected and _is_target_process(info["Name"], info["Exe"], names, exact_paths, dirs, observed):
                    info["IdentitySource"] = "Verified exact/scope path"
                else:
                    # Defer source-relative helpers until the primary binary's
                    # SHA-256 has established a trusted application directory.
                    candidates.append(info)
                    continue
                try:
                    parent = proc.parent()
                    info["ParentName"] = parent.name() if parent else ""
                    info["ParentExe"] = parent.exe() if parent else ""
                except Exception:
                    info["ParentName"] = ""
                    info["ParentExe"] = ""
                info["NetworkConnections"] = network.get(proc.pid, [])
                try:
                    io = proc.io_counters()
                    info["IoCounters"] = {"read_count": io.read_count, "write_count": io.write_count}
                except (OSError, psutil.AccessDenied, psutil.NoSuchProcess):
                    info["IoCounters"] = {}
                try:
                    times = proc.cpu_times()
                    info["CpuSeconds"] = float(times.user + times.system)
                except (OSError, psutil.AccessDenied, psutil.NoSuchProcess):
                    info["CpuSeconds"] = 0.0
                rows.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    # Allow only explicitly enumerated helper names within a directory whose
    # primary executable was hash-verified in this collection cycle.
    for info in candidates:
        exe = _norm(info.get("Exe"))
        name = str(info.get("Name") or "").lower()
        if name in names and exe and any(exe.startswith(root + "\\") for root in validated_portable_roots):
            info["IdentitySource"] = "Verified portable application directory"
            info["NetworkConnections"] = network.get(info["PID"], [])
            try:
                child = psutil.Process(info["PID"])
                io = child.io_counters()
                info["IoCounters"] = {"read_count": io.read_count, "write_count": io.write_count}
                cpu = child.cpu_times()
                info["CpuSeconds"] = float(cpu.user + cpu.system)
            except (OSError, psutil.AccessDenied, psutil.NoSuchProcess):
                info["IoCounters"] = {}
                info["CpuSeconds"] = 0.0
            rows.append(info)
    rows.sort(key=lambda x: (x["Name"].lower(), x["PID"]))
    return rows


def _capture_sysinternals(processes, assessment_dir: Path, tools):
    listdlls = (tools or {}).get("ListDLLs", {}).get("path")
    handle = (tools or {}).get("Handle", {}).get("path")

    dll_lines = [
        "WCA - RUNTIME LOADED DLLS (LISTDLLS)",
        "=" * 100,
        "",
        "Purpose:",
        "  Raw/supporting Sysinternals ListDLLs evidence for correlated target processes.",
        "  Use dll_search_review.txt and procmon_loaded_images.txt for interpreted DLL-search analysis.",
        "",
    ]
    handle_lines = [
        "WCA - RUNTIME HANDLES (HANDLE)",
        "=" * 100,
        "",
        "Purpose:",
        "  Raw/supporting Sysinternals Handle output for correlated target processes.",
        "  Use ipc_review.txt for interpreted named-pipe/IPC results rather than reviewing every handle manually.",
        "",
    ]

    selected = processes[:MAX_SYSINTERNAL_PROCESSES]
    listdlls_raw_by_pid = {}
    handle_raw_by_pid = {}

    if not listdlls:
        dll_lines += ["ListDLLs was not detected; runtime DLL inventory skipped.", ""]
    if not handle:
        handle_lines += ["Handle was not detected; runtime handle inventory skipped.", ""]

    for proc in selected:
        pid = str(proc["PID"])
        name = proc["Name"]
        if listdlls:
            result = run_command([listdlls, "-v", pid], timeout=90)
            listdlls_raw_by_pid[int(pid)] = result.get("stdout", "")
            dll_lines += [
                "-" * 100,
                f"PROCESS: {name} (PID {pid})",
                "-" * 100,
                result.get("stdout", "").rstrip(),
                result.get("stderr", "").rstrip(),
                "",
            ]

        if handle:
            result = run_command([handle, "-accepteula", "-a", "-v", "-p", pid], timeout=90)
            handle_raw_by_pid[int(pid)] = result.get("stdout", "")
            handle_lines += [
                "-" * 100,
                f"PROCESS: {name} (PID {pid})",
                "-" * 100,
                result.get("stdout", "").rstrip(),
                result.get("stderr", "").rstrip(),
                "",
            ]

    (artifact_path(assessment_dir, "runtime_loaded_dlls.txt")).write_text(
        "\n".join(dll_lines).rstrip() + "\n",
        encoding="utf-8",
    )
    (artifact_path(assessment_dir, "runtime_handles.txt")).write_text(
        "\n".join(handle_lines).rstrip() + "\n",
        encoding="utf-8",
    )
    return {
        "listdlls_raw_by_pid": listdlls_raw_by_pid,
        "handle_raw_by_pid": handle_raw_by_pid,
    }


def run_runtime_process_review(
    assessment_dir: Path,
    runtime_targets=None,
    observed_process_names=None,
    tools=None,
    exclude_paths=None,
):
    processes = collect_runtime_processes(
        runtime_targets, observed_process_names, exclude_paths
    )

    width = 108
    lines = [
        "WCA - RUNTIME PROCESS REVIEW",
        "=" * width,
        "",
        "Purpose:",
        "  Correlates currently running Windows processes with executables identified during",
        "  installation and with process names observed in the Procmon runtime trace.",
        "",
        f"Correlated running processes: {len(processes)}",
        "",
    ]

    for idx, proc in enumerate(processes, 1):
        lines += [
            "-" * width,
            f"[RP-{idx:03d}] {proc['Name']} (PID {proc['PID']})",
            "-" * width,
            f"PID          : {proc['PID']}",
            f"Parent PID   : {proc['PPID']}",
            f"Parent       : {proc.get('ParentName') or 'N/A'}",
            f"Executable   : {proc['Exe'] or 'Unavailable'}",
            f"Execution User: {account_for_report(proc['Username']) or 'Unavailable'}",
            f"Status       : {proc['Status']}",
            f"Command Line : {proc['CommandLine'] or 'N/A'}",
            f"Created      : {proc['CreateTime']}",
            f"Network      : {len(proc.get('NetworkConnections', []))} connection(s)",
        ]
        for conn in proc.get("NetworkConnections", []):
            lines.append(
                f"               {conn.get('Local')} -> {conn.get('Remote')} [{conn.get('Status')}]"
            )
        lines.append("")

    (artifact_path(assessment_dir, "runtime_processes.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )
    network_lines = [
        "WCA - RUNTIME NETWORK CONNECTIONS",
        "=" * width,
        "",
        "Purpose:",
        "  Point-in-time raw connection inventory for correlated runtime processes.",
        "  Use network_surface_review.txt for bind-scope, listener, firewall, and POI interpretation.",
        "",
    ]
    count = 0
    for proc in processes:
        for conn in proc.get("NetworkConnections", []):
            count += 1
            network_lines.append(
                f"{proc['Name']} (PID {proc['PID']}) | "
                f"{conn.get('Local')} -> {conn.get('Remote')} | {conn.get('Status')}"
            )
    if count == 0:
        network_lines.append("No correlated process network connections were identified at collection time.")
    (artifact_path(assessment_dir, "runtime_network_connections.txt")).write_text(
        "\n".join(network_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    sysinternals = _capture_sysinternals(processes, assessment_dir, tools or {})

    return {
        "status": "PASS" if processes else "WARN",
        "details": f"{len(processes)} running process(es) correlated; {count} network connection(s)"
                   + ("; target was not observed" if not processes else ""),
        "coverage_gap": not processes,
        "runtime_processes": processes,
        "handle_raw_by_pid": sysinternals.get("handle_raw_by_pid", {}),
        "listdlls_raw_by_pid": sysinternals.get("listdlls_raw_by_pid", {}),
    }
