from __future__ import annotations
from utils.assessment_layout import artifact_path

import ntpath
import re
from pathlib import Path

from utils.windows_paths import extract_executable
from utils.component_context import basename as _basename
from utils.path_filters import path_is_excluded
from utils.target_association import association_roots, classify_installed_path


EXEC_EXTS = {".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
MAX_TARGETS = 150

ROLE_PATTERNS = [
    ("Updater", re.compile(r"(update|updater|upgrade|patch|maintenance|bootstrap|launcher|autoupdate)", re.I)),
    ("Service", re.compile(r"(service|svc|agent|daemon)", re.I)),
    ("Helper", re.compile(r"(helper|broker|host|worker|crash|reporter|telemetry)", re.I)),
    ("Uninstaller", re.compile(r"(unins|uninstall|remove)", re.I)),
]


def _ext(path: str) -> str:
    return ntpath.splitext(_basename(path))[1].lower()


def _role(path: str, source: str = "") -> str:
    name = _basename(path)
    if "service" in source.lower():
        return "Service"
    if "scheduled task" in source.lower():
        return "Scheduled Task"
    for role, pattern in ROLE_PATTERNS:
        if pattern.search(name):
            return role
    return "Application"


def _add(rows, score, path, source, component="", account="", run_level="", note=""):
    path = str(path or "").strip().strip('"')
    if not path or _ext(path) not in EXEC_EXTS:
        return
    rows.append(
        {
            "Score": int(score),
            "Path": path,
            "ProcessName": _basename(path),
            "Source": source,
            "Component": component or "",
            "Account": account or "",
            "RunLevel": run_level or "",
            "Role": _role(path, source),
            "Note": note or "",
        }
    )


def _static_candidates(analysis_roots, file_inventory=None):
    rows = []
    if file_inventory is not None:
        for item in file_inventory:
            if str(item.get("extension") or "").lower() == ".exe" and item.get("path"):
                rows.append(str(item["path"]))
        return rows

    for root in analysis_roots or []:
        p = Path(root)
        if p.is_file():
            items = [p]
        elif p.is_dir():
            items = p.rglob("*")
        else:
            continue
        for item in items:
            try:
                if item.is_file() and item.suffix.lower() == ".exe":
                    rows.append(str(item))
            except Exception:
                continue
    return rows


def discover_runtime_targets(
    diff=None, post_snapshot=None, analysis_roots=None, file_inventory=None, exclude_paths=None
):
    diff = diff or {}
    rows = []

    # New services are highest-value runtime targets.
    for svc in diff.get("Services", {}).get("added", []) or []:
        path = extract_executable(svc.get("PathName"))
        _add(
            rows,
            100,
            path,
            "New service",
            component=svc.get("Name"),
            account=svc.get("StartName"),
            note=svc.get("DisplayName"),
        )

    # New scheduled tasks frequently launch helpers/updaters/background components.
    for task in diff.get("ScheduledTasks", {}).get("added", []) or []:
        actions = task.get("Actions", []) or []
        if isinstance(actions, dict):
            actions = [actions]
        for action in actions:
            path = extract_executable(action.get("Execute"))
            _add(
                rows,
                95,
                path,
                "New scheduled task",
                component=f"{task.get('TaskPath', '')}{task.get('TaskName', '')}",
                account=task.get("Principal"),
                run_level=task.get("RunLevel"),
                note=action.get("Arguments"),
            )

    # A system-wide snapshot also captures unrelated software updates.  Promote
    # filesystem-added executables only when stronger evidence ties them to the
    # assessed package: exact extracted/static payload match or a specific
    # install root established by a service/task/matched payload.
    roots = association_roots(diff, file_inventory)
    for item in diff.get("Filesystem", {}).get("added", []) or []:
        if not isinstance(item, dict) or item.get("IsDirectory"):
            continue
        path = str(item.get("Path") or "")
        if _ext(path) != ".exe":
            continue
        association = classify_installed_path(
            item, diff=diff, file_inventory=file_inventory, roots=roots
        )
        if not association:
            continue

        lower = path.lower()
        score = 80
        if association == "matches extracted/static payload":
            score = 92
        elif "\\program files\\" in lower or "\\program files (x86)\\" in lower:
            score = 88
        elif "\\programdata\\" in lower:
            score = 82
        elif "\\appdata\\local\\" in lower:
            score = 76
        elif "\\appdata\\roaming\\" in lower:
            score = 70
        elif "\\temp\\" in lower:
            score = 45

        note = "Target association: " + association + "."
        if "\\temp\\" in lower:
            note += " Executable installed/created beneath a TEMP path."
        _add(rows, score, path, "Filesystem added (target-associated)", note=note)

    # Static/extracted executables are fallback targets. If the same process name
    # already has stronger installed/service/task evidence, do not add a second
    # extraction-tree path for the same runtime identity.
    strong_names = {str(row.get("ProcessName") or "").lower() for row in rows}
    for path in _static_candidates(analysis_roots, file_inventory):
        if _basename(path).lower() in strong_names:
            continue
        _add(rows, 30, path, "Static/extracted candidate")

    # De-duplicate by path while keeping the highest-value context.
    rows.sort(key=lambda x: (-x["Score"], x["Path"].lower()))
    output = []
    seen = set()
    for row in rows:
        if path_is_excluded(row.get("Path"), exclude_paths):
            continue
        key = row["Path"].lower()
        if key in seen:
            continue
        seen.add(key)
        output.append(row)
        if len(output) >= MAX_TARGETS:
            break
    return output


def run_runtime_target_discovery(
    assessment_dir: Path,
    diff=None,
    post_snapshot=None,
    analysis_roots=None,
    file_inventory=None,
    exclude_paths=None,
):
    targets = discover_runtime_targets(
        diff, post_snapshot, analysis_roots, file_inventory, exclude_paths
    )

    width = 108
    lines = [
        "WCA - RUNTIME TARGET DISCOVERY",
        "=" * width,
        "",
        "Purpose:",
        "  Identifies executables most likely to represent the installed client, services, helpers,",
        "  scheduled-task components, launchers, and updater processes for runtime correlation.",
        "  Filesystem additions require target association; unrelated host updates are not promoted",
        "  merely because they occurred between the pre/post installation snapshots.",
        "",
        f"Runtime targets identified: {len(targets)}",
        f"Excluded path rules      : {len(exclude_paths or [])}",
        "",
    ]

    if not targets:
        lines += [
            "No runtime executable targets were identified automatically.",
            "The tester can still use Procmon manually and import a CSV trace with --procmon-csv.",
            "",
        ]

    for idx, target in enumerate(targets, 1):
        lines += [
            "-" * width,
            f"[RT-{idx:03d}] {target['ProcessName']}",
            "-" * width,
            f"Priority Score : {target['Score']}",
            f"Role           : {target['Role']}",
            f"Source         : {target['Source']}",
            f"Path           : {target['Path']}",
            f"Component      : {target['Component'] or 'N/A'}",
            f"Account        : {target['Account'] or 'N/A'}",
            f"Run Level      : {target['RunLevel'] or 'N/A'}",
            f"Note           : {target['Note'] or 'N/A'}",
            "",
        ]

    (artifact_path(assessment_dir, "runtime_targets.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )
    return {
        "status": "PASS" if targets else "WARN",
        "details": f"{len(targets)} runtime target(s) identified",
        "runtime_targets": targets,
    }
