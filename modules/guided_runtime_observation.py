from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from modules.procmon_analysis import run_procmon_analysis
from modules.procmon_capture import run_procmon_capture
from modules.runtime_process_review import collect_runtime_processes
from modules.network_surface_review import run_network_surface_review
from modules.ipc_review import run_ipc_review
from utils.assessment_layout import artifact_path, ensure_structured_layout
from utils.assessment_state import _atomic_json
from utils.assessment_integrity import _atomic_text
from utils.privacy import sanitize_report_text

SUGGESTED_ACTIVITIES = (
    ("launch_close", "Launch, close, and relaunch the primary client."),
    ("login_session", "Exercise login/session establishment if the client has an authenticated workflow."),
    ("network_features", "Exercise one normal network-dependent feature."),
    ("privileged_helper", "Exercise a feature that invokes a service, helper, broker, or elevated component when authorized."),
    ("file_config", "Exercise a workflow that creates or changes a target file/configuration setting."),
    ("update_check", "Trigger the product's normal update/check-for-updates workflow when authorized."),
)





def _duration_text(seconds: float) -> str:
    seconds = max(0, int(seconds or 0))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _format_size(size: int) -> str:
    value = float(max(0, int(size or 0)))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} GB"



class GuidedRuntimeLiveController:
    """Interactive Windows heartbeat/dashboard shown while Procmon is capturing.

    The controller intentionally does not parse the live PML. It reports only
    trustworthy heartbeat data available during capture: elapsed time, backing
    file growth, currently correlated processes and their point-in-time network
    connections. Final Procmon event counts are calculated after capture stops.
    """

    def __init__(self, runtime_targets, exclude_paths=None, refresh_seconds: float = 1.0):
        self.runtime_targets = list(runtime_targets or [])
        self.exclude_paths = list(exclude_paths or [])
        self.refresh_seconds = max(0.2, float(refresh_seconds))
        self.seen_processes = set()
        self.previous_metrics = {}
        self.seen_connections = set()
        self.total_io_changes = 0
        self.total_process_starts = 0
        self.total_connection_changes = 0
        self.last_target_activity = None
        self.last_change = "Awaiting target activity"
        self.console = Console()

    def _observe_activity(self, processes, now):
        """Point-in-time process I/O/CPU metrics; NOT live Procmon PML events."""
        current = {}
        io_delta = 0
        cpu_delta = 0.0
        for proc in processes:
            pid = proc.get("PID")
            if not isinstance(pid, int):
                continue
            counters = proc.get("IoCounters") or {}
            io_count = sum(int(counters.get(x) or 0) for x in ("read_count", "write_count"))
            cpu = float(proc.get("CpuSeconds") or 0)
            identity = (pid, proc.get("CreateTime"))
            current[identity] = (io_count, cpu)
            old = self.previous_metrics.get(identity)
            if old:
                io_delta += max(0, io_count - old[0])
                cpu_delta += max(0.0, cpu - old[1])
        starts = len(current.keys() - self.previous_metrics.keys())
        connections = {(p.get("PID"), str(c.get("Local")), str(c.get("Remote")), str(c.get("Status")))
                       for p in processes for c in (p.get("NetworkConnections") or [])}
        new_connections = len(connections - self.seen_connections)
        self.seen_connections.update(connections)
        if starts or io_delta or cpu_delta > 0.01 or new_connections:
            self.last_target_activity = now
            self.last_change = (f"Processes +{starts}; I/O operations +{io_delta}; "
                                f"CPU +{cpu_delta:.2f}s; connections +{new_connections}")
        self.total_io_changes += io_delta
        self.total_process_starts += starts
        self.total_connection_changes += new_connections
        self.previous_metrics = current
        return io_delta, cpu_delta, starts, new_connections

    def _render(self, *, elapsed, pml_size, growth_age, processes, connections, activity=None, now=None):
        table = Table.grid(expand=True)
        table.add_column(ratio=1)
        table.add_column(ratio=1)
        trace_state = "ACTIVE"
        if growth_age is not None and growth_age >= 30:
            trace_state = f"NO CHANGE FOR {int(growth_age)}s (target may be idle)"
        table.add_row("[bold green]CAPTURE ACTIVE[/bold green]", f"Elapsed  {_duration_text(elapsed)}")
        table.add_row("Procmon  ACTIVE", f"Trace  {_format_size(pml_size)}")
        table.add_row("Trace growth (full-host)", trace_state)
        table.add_row("Target activity (live poll)",
                      "ACTIVE" if activity and any(activity) else ("No process I/O/CPU change in latest poll" if processes else "No correlated target currently running"))
        age = int(now - self.last_target_activity) if now is not None and self.last_target_activity is not None else None
        table.add_row("Last correlated activity", f"{age}s ago" if age is not None else "Awaiting observed target activity")
        table.add_row("Latest observed change", self.last_change)
        table.add_row("Process I/O changes (since start)", str(self.total_io_changes))
        table.add_row("Process starts / connection changes", f"{self.total_process_starts} / {self.total_connection_changes}")
        table.add_row("File / Registry / IPC event totals", "Computed from target-scoped Procmon after capture")
        table.add_row("Current target processes", str(len(processes)))
        table.add_row("Target processes seen", str(len(self.seen_processes)))
        table.add_row("Current target connections", str(connections))
        table.add_row("", "")
        table.add_row("[bold]SUGGESTED ACTIVITIES[/bold]", "[dim]No input is required while testing[/dim]")
        for _, label in SUGGESTED_ACTIVITIES:
            table.add_row(f"[dim]•[/dim] {label}", "")
        table.add_row("[dim]Exercise only the workflows that apply to this application.[/dim]", "")
        table.add_row("", "")
        table.add_row("[bold]CURRENT TARGET ACTIVITY[/bold]", "")
        if processes:
            for proc in processes[:8]:
                name = str(proc.get("Name") or "target")
                pid = proc.get("PID")
                conn = len(proc.get("NetworkConnections") or [])
                table.add_row(f"  {name}  PID {pid}", f"connections={conn}")
        else:
            table.add_row("  No correlated target process currently running", "")
        table.add_row("", "")
        table.add_row("[bold]ENTER[/bold]  Finish observation", "Final event counts appear after capture stops")
        return Panel(table, title="Guided Runtime Observation", border_style="cyan")

    def __call__(self, *, pml_path: Path, procmon_path: str, started_at):
        # This UI is Windows-specific because msvcrt provides non-blocking key
        # reads without adding another dependency. The collector itself still
        # has its normal non-live fallback on other platforms.
        if os.name != "nt":
            return {"seen_process_names": []}
        import msvcrt

        start_clock = time.monotonic()
        last_size = -1
        last_growth = start_clock
        latest = []
        connections = 0
        with Live(console=self.console, refresh_per_second=4, transient=False) as live:
            while True:
                now = time.monotonic()
                try:
                    latest = collect_runtime_processes(self.runtime_targets, [], self.exclude_paths)
                except Exception:
                    latest = []
                for proc in latest:
                    name = str(proc.get("Name") or "").strip()
                    if name:
                        self.seen_processes.add(name)
                connections = sum(len(proc.get("NetworkConnections") or []) for proc in latest)
                activity = self._observe_activity(latest, now)
                try:
                    size = int(Path(pml_path).stat().st_size) if Path(pml_path).exists() else 0
                except OSError:
                    size = 0
                if size != last_size:
                    last_size = size
                    last_growth = now
                live.update(self._render(
                    elapsed=now - start_clock, pml_size=size,
                    growth_age=now - last_growth if size > 0 else None,
                    processes=latest, connections=connections, activity=activity, now=now,
                ))

                stop = False
                while msvcrt.kbhit():
                    key = msvcrt.getwch()
                    if key in {"\r", "\n"}:
                        stop = True
                        break
                if stop:
                    break
                time.sleep(self.refresh_seconds)

        return {
            "seen_process_names": sorted(self.seen_processes, key=str.lower),
            "final_live_processes": len(latest),
            "final_live_connections": connections,
            "live_process_starts": self.total_process_starts,
            "live_io_operation_changes": self.total_io_changes,
            "live_connection_changes": self.total_connection_changes,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def load_runtime_targets(root: Path) -> list[dict]:
    """Rehydrate target identity from the portable runtime target report.

    The original in-memory objects are intentionally not persisted as another
    JSON duplicate. This parser only consumes the framework's own stable report
    fields and ignores malformed/partial blocks.
    """
    path = artifact_path(root, "runtime_targets.txt")
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    rows = []
    for block in re.split(r"(?m)^-{20,}\s*$", text):
        if "Priority Score" not in block or "Path" not in block:
            continue
        fields = {}
        for line in block.splitlines():
            match = re.match(r"^([A-Za-z ]+?)\s*:\s*(.*)$", line.strip())
            if match:
                fields[match.group(1).strip()] = match.group(2).strip()
        path_value = fields.get("Path", "")
        if not path_value:
            continue
        # Runtime collectors need the live tester profile to resolve a path that
        # was normalized for portable reporting. No profile value is persisted.
        profile = os.environ.get("USERPROFILE") or ""
        if profile:
            path_value = path_value.replace("%USERPROFILE%", profile)
        try:
            score = int(fields.get("Priority Score", "0") or 0)
        except ValueError:
            score = 0
        rows.append({
            "Score": score,
            "Path": path_value,
            "ProcessName": Path(path_value.replace("\\", "/")).name,
            "Source": fields.get("Source", ""),
            "Component": "" if fields.get("Component") == "N/A" else fields.get("Component", ""),
            "Account": "" if fields.get("Account") == "N/A" else fields.get("Account", ""),
            "RunLevel": "" if fields.get("Run Level") == "N/A" else fields.get("Run Level", ""),
            "Role": fields.get("Role", "Application"),
            "Note": "" if fields.get("Note") == "N/A" else fields.get("Note", ""),
        })
    # Portable selections store only the selected primary executable's hash and
    # basename. Use that identity to correlate live process paths without writing
    # the tester's original source directory into the assessment.
    from utils.assessment_state import AssessmentState
    state = AssessmentState.load(root)
    target = ((state.data.get("target") or {}) if state else {})
    if target.get("type") == "portable":
        selected_name = str(target.get("primary_executable") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        expected = str(target.get("sha256") or "").lower()
        if re.fullmatch(r"[0-9a-f]{64}", expected) and selected_name:
            for row in rows:
                if row["ProcessName"].lower() == selected_name:
                    row["PrimarySHA256"] = expected
                    row["PortablePrimary"] = True
                    break
    # Prefer installed/runtime targets over extraction-only fallbacks with the
    # same basename/path semantics; keep unique paths for strict correlation.
    seen = set()
    output = []
    for row in sorted(rows, key=lambda item: (-item["Score"], item["Path"].lower())):
        key = row["Path"].lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
    return output


def load_assessment_filters(root: Path) -> tuple[list[str], bool]:
    """Reload tester-selected path filters and target-only mode from the portable filter report.

    The assessment state intentionally persists only the count of excluded paths,
    while the authoritative tester-facing filter report retains the actual rules.
    Guided Runtime reuses those rules so post-completion observation does not
    silently broaden scope or reintroduce host noise.
    """
    path = artifact_path(root, "assessment_filters.txt")
    if not path.is_file():
        return [], False
    text = path.read_text(encoding="utf-8", errors="replace")
    target_match = re.search(r"(?mi)^Target-only supporting inventory\s*:\s*(True|False)\s*$", text)
    target_only = bool(target_match and target_match.group(1).casefold() == "true")
    match = re.search(
        r"(?ms)^EXCLUDED PATHS\s*\n-{20,}\s*\n(.*?)(?=^FILTERED DIFFERENTIAL RECORDS\s*$)",
        text,
    )
    if not match:
        return [], target_only
    patterns = []
    for raw in match.group(1).splitlines():
        line = raw.strip()
        if not line or line.casefold() == "none.":
            continue
        if line.startswith("- "):
            value = line[2:].strip()
            if value:
                patterns.append(value)
    return patterns, target_only


def _event_examples(events: list[dict], limit: int = 12) -> list[dict]:
    kept = []
    for event in events[:limit]:
        kept.append({
            "process": sanitize_report_text(event.get("Process", "")),
            "operation": sanitize_report_text(event.get("Operation", "")),
            "path": sanitize_report_text(event.get("Path", "")),
            "result": sanitize_report_text(event.get("Result", "")),
        })
    return kept


def _surface_status(available: bool, count: int) -> str:
    if not available:
        return "COLLECTION UNAVAILABLE"
    return "OBSERVED" if count else "NOT OBSERVED"


def summarize_observation(*, checklist: dict, procmon_result: dict, processes: list[dict],
                          network_result: dict, ipc_result: dict, runtime_targets: list[dict]) -> dict:
    data = procmon_result.get("procmon_data") or {}
    procmon_available = bool(data)
    network_available = bool(network_result) and not bool(network_result.get("coverage_gap"))
    ipc_available = bool(ipc_result) and not bool(ipc_result.get("coverage_gap"))

    target_roles = {
        str(item.get("ProcessName") or "").lower(): str(item.get("Role") or "Application")
        for item in runtime_targets if str(item.get("ProcessName") or "").strip()
    }
    process_snapshot = []
    for proc in processes:
        name = str(proc.get("Name") or "")
        process_snapshot.append({
            "name": sanitize_report_text(name),
            "pid": proc.get("PID"),
            "ppid": proc.get("PPID"),
            "parent": sanitize_report_text(proc.get("ParentName", "")),
            "executable": sanitize_report_text(proc.get("Exe", "")),
            "execution_user": sanitize_report_text(proc.get("Username", "")),
            "role": target_roles.get(name.lower(), "Application"),
            "network_connections": len(proc.get("NetworkConnections") or []),
        })

    privileged_names = {
        str(item.get("ProcessName") or "").lower()
        for item in runtime_targets
        if str(item.get("Role") or "").lower() in {"service", "helper", "scheduled task"}
        or str(item.get("Account") or "").lower() in {"localsystem", "system", "nt authority\\system"}
    }
    privileged_processes = []
    for proc in processes:
        if str(proc.get("Name") or "").lower() in privileged_names:
            privileged_processes.append({
                "name": sanitize_report_text(proc.get("Name", "")),
                "pid": proc.get("PID"),
                "parent": sanitize_report_text(proc.get("ParentName", "")),
                "executable": sanitize_report_text(proc.get("Exe", "")),
                "execution_user": sanitize_report_text(proc.get("Username", "")),
            })

    updater_names = {
        str(item.get("ProcessName") or "").lower()
        for item in runtime_targets
        if str(item.get("Role") or "").lower() == "updater"
        or re.search(r"update|updater|upgrade|patch|launcher", str(item.get("ProcessName") or ""), re.I)
    }
    updater_events = [
        event for event in (data.get("process_activity") or []) + (data.get("network_activity") or [])
        if str(event.get("Process") or "").lower() in updater_names
    ]
    updater_processes = [
        proc for proc in processes if str(proc.get("Name") or "").lower() in updater_names
    ]

    network_records = network_result.get("network_records") or []
    ipc_records = ipc_result.get("ipc_records") or []
    process_events = data.get("process_activity") or []
    file_events = data.get("file_writes") or []
    ipc_write_events = data.get("ipc_writes") or []
    registry_events = data.get("registry_writes") or []
    loaded_images = data.get("loaded_images") or []
    network_events = data.get("network_activity") or []

    surfaces = {
        "process_tree": {
            # psutil process correlation is an integrated point-in-time collector
            # even when Procmon is unavailable. No matching target process is
            # therefore NOT OBSERVED rather than COLLECTION UNAVAILABLE.
            "status": _surface_status(True, len(process_events) or len(processes)),
            "count": len(process_events) if procmon_available else len(processes),
        },
        "privileged_helpers": {
            "status": _surface_status(True, len(privileged_processes)),
            "count": len(privileged_processes),
        },
        "network": {
            "status": _surface_status(network_available or procmon_available, len(network_records) + len(network_events)),
            "count": len(network_records) + len(network_events),
        },
        "named_pipes": {
            "status": _surface_status(ipc_available or bool(ipc_write_events), len(ipc_records) + len(ipc_write_events)),
            "count": len(ipc_records) + len(ipc_write_events),
        },
        "ipc_device_activity": {
            "status": _surface_status(procmon_available, len(ipc_write_events)),
            "count": len(ipc_write_events),
        },
        "file_writes": {
            "status": _surface_status(procmon_available, len(file_events)),
            "count": len(file_events),
        },
        "registry_writes": {
            "status": _surface_status(procmon_available, len(registry_events)),
            "count": len(registry_events),
        },
        "loaded_images": {
            "status": _surface_status(procmon_available, len(loaded_images)),
            "count": len(loaded_images),
        },
        "updater_activity": {
            "status": _surface_status(True, len(updater_events) + len(updater_processes)),
            "count": len(updater_events) + len(updater_processes),
        },
    }

    return {
        "captured_at": utc_now(),
        "checklist": dict(checklist),
        "surfaces": surfaces,
        "counts": {
            "correlated_processes": len(processes),
            "current_target_processes": len(processes),
            "target_processes_seen": len(set(data.get("observed_process_names") or []) | {str(p.get("Name") or "") for p in processes if p.get("Name")}),
            "procmon_target_events": int(data.get("relevant_rows") or 0),
            "process_events": len(process_events),
            "loaded_images": len(loaded_images),
            "file_writes": len(file_events),
            "ipc_device_writes": len(ipc_write_events),
            "registry_writes": len(registry_events),
            "network_events": len(network_events),
            "listeners_or_udp_bounds": len(network_records),
            "network_pois": len(network_result.get("network_pois") or []),
            "named_pipes": len(ipc_records),
            "ipc_pois": len(ipc_result.get("ipc_pois") or []),
            "privileged_or_helper_processes": len(privileged_processes),
            "updater_events": len(updater_events),
            "updater_processes": len(updater_processes),
        },
        "processes": process_snapshot[:50],
        "processes_seen": sorted(set(data.get("observed_process_names") or []) | {str(p.get("Name") or "") for p in processes if p.get("Name")}, key=str.lower)[:100],
        "privileged_processes": privileged_processes[:20],
        "examples": {
            "process_activity": _event_examples(process_events),
            "file_writes": _event_examples(file_events),
            "ipc_device_activity": _event_examples(ipc_write_events),
            "registry_writes": _event_examples(registry_events),
            "network_activity": _event_examples(network_events),
            "loaded_images": _event_examples(loaded_images),
        },
        "network": [
            {
                "process": sanitize_report_text(row.get("ProcessName", "")),
                "protocol": row.get("Protocol", ""),
                "address": row.get("LocalAddress", ""),
                "port": row.get("LocalPort"),
                "scope": row.get("Scope", ""),
                "privileged": bool(row.get("PrivilegedContext")),
            }
            for row in network_records[:50]
        ],
        "pipes": [
            {
                "process": sanitize_report_text(row.get("Process", "")),
                "pipe": sanitize_report_text(row.get("PipeName", "")),
                "pid": row.get("PID"),
                "privileged": bool(row.get("PrivilegedContext")),
                "broad_write_lines": len(row.get("BroadWriteLines") or []),
            }
            for row in ipc_records[:50]
        ],
        "collection": {
            "procmon": "AVAILABLE" if procmon_available else "UNAVAILABLE",
            "process_snapshot": "AVAILABLE" if processes else "NO TARGET PROCESS OBSERVED",
            "network": "AVAILABLE" if network_available else "PARTIAL/UNAVAILABLE",
            "ipc": "AVAILABLE" if ipc_available else "PARTIAL/UNAVAILABLE",
        },
    }


def render_observation_report(summary: dict, sessions: list[dict]) -> str:
    width = 112
    lines = [
        "WCA - GUIDED RUNTIME OBSERVATION",
        "=" * width,
        "",
        "Purpose:",
        "  Tester-driven observation of an already-completed full assessment. Windows Client Assessment does not",
        "  launch, log in to, update, or otherwise exercise the client automatically. The tester performs",
        "  approved workflows while collectors observe target-associated behavior.",
        "",
        "Interpretation:",
        "  OBSERVED means evidence was seen during this observation window.",
        "  NOT OBSERVED means the collector ran but did not see that activity.",
        "  COLLECTION UNAVAILABLE means prerequisites/tooling/evidence were insufficient.",
        "  None of these states independently confirms a vulnerability.",
        "",
        f"Observation sessions retained: {len(sessions)}",
        f"Latest session            : {summary.get('captured_at')}",
        f"Session started           : {(summary.get('session') or {}).get('started_at') or 'Unavailable'}",
        f"Session stopped           : {(summary.get('session') or {}).get('stopped_at') or 'Unavailable'}",
        f"Capture duration          : {_duration_text((summary.get('session') or {}).get('capture_duration_seconds') or (summary.get('session') or {}).get('duration_seconds') or 0)}",
        f"Evidence processing       : {_duration_text((summary.get('session') or {}).get('processing_duration_seconds') or 0)}",
        f"Observed + processing     : {_duration_text((summary.get('session') or {}).get('total_duration_seconds') or 0)}",
        f"Final PML size            : {_format_size((summary.get('session') or {}).get('final_pml_size_bytes') or 0)}",
        f"Target-only scope          : {bool((summary.get('scope') or {}).get('target_only'))}",
        f"Excluded path rules reused : {int((summary.get('scope') or {}).get('exclude_path_count') or 0)}",
        "",
        "SUGGESTED ACTIVITIES",
        "-" * width,
        "These reminders are not tester attestations. Windows Client Assessment derives runtime coverage from observed telemetry.",
    ]
    for _, label in SUGGESTED_ACTIVITIES:
        lines.append("- " + label)
    capture = summary.get("capture") or {}
    session = summary.get("session") or {}
    lines += ["", "CAPTURE / PROCESSING STATUS", "-" * width,
              f"Capture status            : {capture.get('status') or 'UNKNOWN'}",
              f"Capture details           : {capture.get('details') or 'Unavailable'}"]
    if session.get("failure_stage"):
        lines += [f"Failure stage             : {session.get('failure_stage')}",
                  f"Failure reason            : {session.get('failure_reason') or 'Unavailable'}"]
    lines += ["", "OBSERVATION SURFACES", "-" * width]
    for key, item in summary.get("surfaces", {}).items():
        lines.append(f"{key.replace('_', ' ').title():34} {item.get('status','UNKNOWN'):24} count={item.get('count',0)}")
    lines += ["", "COUNTS", "-" * width]
    for key, value in summary.get("counts", {}).items():
        lines.append(f"{key.replace('_', ' ').title():42} {value}")
    lines.append(f"{'New Review Candidates':42} {int(summary.get('new_review_candidates') or 0)}")
    effective = summary.get("effective_runtime_modules") or {}
    if effective:
        lines += ["", "EFFECTIVE RUNTIME MODULE STATUS", "-" * width]
        for module, info in effective.items():
            lines.append(f"{module:40} {str(info.get('status') or 'UNKNOWN'):16} {info.get('details') or ''}")
    lines += ["", "PROCESS COVERAGE", "-" * width]
    lines.append(f"Currently active target processes : {summary.get('counts', {}).get('current_target_processes', 0)}")
    lines.append(f"Target/descendant processes seen  : {summary.get('counts', {}).get('target_processes_seen', 0)}")
    if summary.get("processes_seen"):
        lines.append("Seen process names               : " + ", ".join(summary.get("processes_seen", [])))
    lines += ["", "TARGET PROCESS / PARENT CORRELATION", "-" * width]
    if not summary.get("processes"):
        lines.append("No target-associated process was observed in the point-in-time process snapshot.")
    for item in summary.get("processes", []):
        lines.append(
            f"{item.get('name')} PID {item.get('pid')} PPID {item.get('ppid')} | role={item.get('role')} | "
            f"parent={item.get('parent') or 'Unavailable'} | user={item.get('execution_user') or 'Unavailable'} | "
            f"connections={item.get('network_connections', 0)} | {item.get('executable') or 'Unavailable'}"
        )
    lines += ["", "PRIVILEGED / HELPER PROCESS CORRELATION", "-" * width]
    if not summary.get("privileged_processes"):
        lines.append("No correlated service/helper process was observed at the final point-in-time collection.")
    for item in summary.get("privileged_processes", []):
        lines.append(
            f"{item.get('name')} PID {item.get('pid')} | user={item.get('execution_user') or 'Unavailable'} | "
            f"parent={item.get('parent') or 'Unavailable'} | {item.get('executable') or 'Unavailable'}"
        )
    lines += ["", "NETWORK LISTENERS / UDP BOUNDS", "-" * width]
    if not summary.get("network"):
        lines.append("No correlated target listener/bound endpoint was observed, or collection was unavailable.")
    for item in summary.get("network", []):
        lines.append(
            f"{item.get('process')} | {item.get('protocol')} {item.get('address')}:{item.get('port')} | "
            f"{item.get('scope')} | privileged={item.get('privileged')}"
        )
    lines += ["", "NAMED PIPE CORRELATION", "-" * width]
    if not summary.get("pipes"):
        lines.append("No correlated target named-pipe handle was observed, or collection was unavailable.")
    for item in summary.get("pipes", []):
        lines.append(
            f"{item.get('process')} PID {item.get('pid')} -> \\\\.\\pipe\\{item.get('pipe')} | "
            f"privileged={item.get('privileged')} | broad-write-lines={item.get('broad_write_lines')}"
        )
    lines += ["", "SELECTED PROCMON EXAMPLES", "-" * width]
    for category, events in summary.get("examples", {}).items():
        lines.append(category.replace("_", " ").upper())
        if not events:
            lines.append("  None observed / collection unavailable.")
        for event in events:
            lines.append(
                f"  {event.get('process')} | {event.get('operation')} | {event.get('path')} | {event.get('result')}"
            )
        lines.append("")
    lines += [
        "UPDATER INTERPRETATION",
        "-" * width,
        "Updater activity is only OBSERVED when target-associated updater/launcher process or network activity",
        "appeared in the observation trace. The suggested-activity reminder does not establish that an updater",
        "exists, ran, or has a security weakness.",
        "",
    ]
    return "\n".join(lines).rstrip() + "\n"


def append_session(root: Path, summary: dict) -> list[dict]:
    path = artifact_path(root, "working/guided_runtime_observations.json")
    sessions = []
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and isinstance(existing.get("sessions"), list):
                sessions = existing["sessions"]
        except (OSError, json.JSONDecodeError):
            sessions = []
    sessions.append(summary)
    # Bound history so repeated field observations do not grow without limit.
    sessions = sessions[-20:]
    _atomic_json(path, {"schema_version": 3, "sessions": sessions})
    _atomic_text(artifact_path(root, "guided_runtime_observation.txt"), render_observation_report(summary, sessions))
    return sessions


def run_guided_collectors(root: Path, tools: dict, runtime_targets: list[dict], checklist: dict,
                          *, exclude_paths=None, target_only: bool = False,
                          interactive: bool = True, input_fn=input, output_fn=print,
                          controller_factory=None) -> dict:
    """Collect a single guided runtime observation without overwriting baseline runtime evidence."""
    with tempfile.TemporaryDirectory(prefix="wca-guided-runtime-") as tmp:
        temp_root = Path(tmp)
        ensure_structured_layout(temp_root)

        controller = (controller_factory(runtime_targets, exclude_paths or []) if controller_factory
                      else GuidedRuntimeLiveController(runtime_targets, exclude_paths or [])) if interactive else None
        target_names = [
            str(item.get("ProcessName") or "").strip()
            for item in (runtime_targets or [])
            if str(item.get("ProcessName") or "").strip()
        ]
        # Build capture scope from explicitly inventoried target executables
        # and currently verified live executable identities (including SHA-256
        # matched portable hosts). Never derive a trusted directory from a
        # Procmon child-launch record or arbitrary application it opens.
        verified_paths = [str(row.get("Path") or "") for row in (runtime_targets or [])]
        try:
            live_target_processes = collect_runtime_processes(runtime_targets, [], exclude_paths or [])
            verified_paths.extend(str(row.get("Exe") or "") for row in live_target_processes)
        except Exception:
            pass  # Without a verified path, avoid promoting unknown descendants.
        capture = run_procmon_capture(
            temp_root, tools, 0, interactive=interactive,
            capture_controller=controller, input_fn=input_fn, output_fn=output_fn,
            target_process_names=target_names,
            target_executable_paths=verified_paths,
        )
        procmon_result = {}
        if capture.get("csv_path"):
            output_fn("[•] Analyzing prepared target-scoped Procmon evidence...")
            procmon_result = run_procmon_analysis(
                temp_root, capture["csv_path"], runtime_targets, capture.get("sanitization")
            )
            output_fn(f"[✓] Target-scoped Procmon analysis complete: {int((procmon_result.get('procmon_data') or {}).get('relevant_rows') or 0)} event(s)")
        elif interactive:
            if capture.get("details"):
                output_fn("[!] Procmon evidence unavailable for this observation: " + str(capture.get("details")))
            details = str(capture.get("details") or "").lower()
            # When capture never started (missing Procmon, non-Windows, missing
            # elevation, or start failure), the normal Procmon collector never
            # presented its exercise window. Give the tester an explicit
            # point-in-time fallback rather than silently sampling immediately.
            no_window = any(token in details for token in (
                "not detected", "requires windows", "elevated windows terminal", "unable to start procmon"
            ))
            if no_window:
                output_fn("Procmon capture is unavailable for this session. Exercise any applicable approved workflows now.")
                input_fn("Press Enter when ready for the point-in-time process/network/IPC collection...")

        observed_names = procmon_result.get("observed_process_names", [])
        output_fn("[•] Correlating current target processes...")
        processes = collect_runtime_processes(runtime_targets, observed_names, exclude_paths or [])
        output_fn(f"[✓] Current target processes correlated: {len(processes)}")
        output_fn("[•] Reviewing network surface...")
        network_result = run_network_surface_review(
            temp_root, runtime_targets, observed_names, processes, {}, {}, exclude_paths or [],
            procmon_result.get("procmon_data"),
        )
        output_fn(f"[✓] Network surface collection complete: {len(network_result.get('network_records') or [])} record(s)")
        output_fn("[•] Reviewing named-pipe / IPC surface...")
        ipc_result = run_ipc_review(
            temp_root, tools, runtime_targets, observed_names,
            network_result.get("runtime_processes") or processes,
            None, exclude_paths or [], bool(target_only),
        )
        output_fn(f"[✓] IPC surface collection complete: {len(ipc_result.get('ipc_records') or [])} record(s)")

        # Stage only sanitized framework-owned evidence outside the assessment.
        # Nothing under the verified assessment root is changed until the tester
        # has ended the observation and orchestration is ready to commit.
        stage_dir = Path(tempfile.mkdtemp(prefix="wca-guided-runtime-stage-"))
        staged_evidence = {}
        try:
            # The full host capture is intentionally temporary. Guided Runtime retains only target-scoped sanitized events.
            # Retain only the target-scoped sanitized event subset when available.
            target_source = Path(procmon_result.get("target_filtered_path") or "")
            if target_source.is_file():
                staged = stage_dir / "guided_runtime_target_events.csv"
                shutil.copy2(target_source, staged)
                staged_evidence["working/guided_runtime_target_events.csv"] = str(staged)

            # Promote the interpreted Procmon reports generated from the
            # target-scoped guided trace. The full host CSV remains temporary.
            for report_name in (
                "procmon_summary.txt", "runtime_secrets_review.txt",
                "procmon_process_activity.txt", "procmon_loaded_images.txt",
                "procmon_file_writes.txt", "procmon_registry_writes.txt",
                "procmon_access_denied.txt", "procmon_network_activity.txt",
                "procmon_missing_dlls.txt",
            ):
                source = artifact_path(temp_root, report_name)
                if not source.is_file():
                    continue
                staged = stage_dir / "reports" / report_name
                staged.parent.mkdir(parents=True, exist_ok=True)
                if report_name == "procmon_summary.txt":
                    # Never leave temporary full-host CSV paths advertised as
                    # retained evidence. The only permanent CSV is target scoped.
                    import re
                    body = source.read_text(encoding="utf-8", errors="replace")
                    body = re.sub(r"(?m)^(Source CSV\s*:\s*).*$", r"\1Temporary full-host source (discarded)", body)
                    body = re.sub(r"(?m)^(Sanitized evidence\s*:\s*).*$", r"\1Temporary full-host source (discarded)", body)
                    retained = artifact_path(root, "working/guided_runtime_target_events.csv")
                    body = re.sub(r"(?m)^(Target-only working CSV\s*:\s*).*$",
                                  lambda match: match.group(1) + str(retained), body)
                    staged.write_text(body, encoding="utf-8")
                else:
                    shutil.copy2(source, staged)
                staged_evidence[f"reports/{report_name}"] = str(staged)
        except Exception:
            shutil.rmtree(stage_dir, ignore_errors=True)
            raise

        controller_data = ((capture.get("session") or {}).get("controller") or {})
        summary = summarize_observation(
            checklist={},
            procmon_result=procmon_result,
            processes=processes,
            network_result=network_result,
            ipc_result=ipc_result,
            runtime_targets=runtime_targets,
        )
        seen = set(summary.get("processes_seen") or []) | set(controller_data.get("seen_process_names") or [])
        summary["processes_seen"] = sorted(seen, key=str.lower)[:100]
        summary["counts"]["target_processes_seen"] = len(seen)
        session = dict(capture.get("session") or {})
        session.pop("controller", None)
        summary["session"] = session
        summary["scope"] = {
            "target_only": bool(target_only),
            "exclude_path_count": len([item for item in (exclude_paths or []) if str(item).strip()]),
        }
        summary["capture"] = {
            "status": capture.get("status", "SKIPPED"),
            "details": sanitize_report_text(capture.get("details", "")),
            "redaction_count": int((capture.get("sanitization") or {}).get("redaction_count") or 0),
        }
        return {
            "summary": summary,
            "procmon": procmon_result,
            "network": network_result,
            "ipc": ipc_result,
            "processes": processes,
            "staged_evidence": staged_evidence,
            "staging_dir": str(stage_dir),
        }
