from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
from utils.windows_paths import as_list, extract_executable, parent_path
from utils.report_format import header, section, kv, bool_text
from utils.component_context import account_for_report, is_privileged
from utils.acl import broad_write_aces


def _list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def run_scheduled_tasks_review(assessment_dir: Path, pre=None, post=None, diff=None, acl_cache=None):
    if diff is not None:
        new = as_list((diff or {}).get("ScheduledTasks", {}).get("added", []))
    else:
        old_keys = {
            (x.get("TaskPath"), x.get("TaskName"))
            for x in as_list((pre or {}).get("ScheduledTasks", []))
        }
        new = [
            x for x in as_list((post or {}).get("ScheduledTasks", []))
            if (x.get("TaskPath"), x.get("TaskName")) not in old_keys
        ]

    acl_paths = []
    for task in new:
        for action in _list(task.get("Actions")):
            exe = extract_executable(action.get("Execute")) or ""
            parent = parent_path(exe) if exe else ""
            working = str(action.get("WorkingDirectory") or "")
            acl_paths.extend(x for x in (exe, parent, working) if x)
    acl_map = acl_cache.get_many(acl_paths) if acl_cache and acl_paths else {}

    width = 112
    lines = header(
        "Windows Client Assessment - Scheduled Tasks Review",
        [
            "Reviews scheduled tasks introduced by the installation.",
            "Privileged task actions are correlated with executable, parent and working-directory ACLs where available.",
        ],
        width,
    )
    highest = sum(1 for t in new if "highest" in str(t.get("RunLevel") or "").lower())
    system = sum(1 for t in new if "system" in str(t.get("Principal") or "").lower())
    lines += [
        "SUMMARY", "-" * width,
        kv("New scheduled tasks", len(new)),
        kv("Highest run level", highest),
        kv("SYSTEM principal", system),
        "", "QUICK INDEX", "-" * width,
    ]
    if not new:
        lines.append("No new scheduled tasks were identified.")
    for idx, task in enumerate(new, 1):
        label = f"{task.get('TaskPath')}{task.get('TaskName')}"
        lines.append(
            f"[TASK-{idx:03d}] {label} | Principal={account_for_report(task.get('Principal'))} | "
            f"RunLevel={task.get('RunLevel')} | State={task.get('State')}"
        )

    findings = []
    lines += section("Detailed Task Review", width)
    for idx, task in enumerate(new, 1):
        label = f"{task.get('TaskPath')}{task.get('TaskName')}"
        actions = _list(task.get("Actions"))
        triggers = _list(task.get("Triggers"))
        privileged = is_privileged(task.get("Principal"), task.get("RunLevel"))
        lines += [
            "=" * width,
            f"[TASK-{idx:03d}] {label}",
            "=" * width,
            kv("State", task.get("State")),
            kv("Principal", account_for_report(task.get("Principal"))),
            kv("Run Level", task.get("RunLevel")),
            kv("Privileged", bool_text(privileged)),
            kv("Logon Type", task.get("LogonType")),
            "", f"ACTIONS ({len(actions)})", "-" * width,
        ]
        if not actions:
            lines.append("No action details returned.")
        for action_idx, action in enumerate(actions, 1):
            exe = extract_executable(action.get("Execute")) or str(action.get("Execute") or "")
            parent = parent_path(exe) if exe else ""
            working = str(action.get("WorkingDirectory") or "")
            exe_hits = broad_write_aces(acl_map.get(str(exe).lower(), {})) if exe else []
            parent_hits = broad_write_aces(acl_map.get(str(parent).lower(), {})) if parent else []
            working_hits = broad_write_aces(acl_map.get(str(working).lower(), {})) if working else []
            lines += [
                f"  [ACTION-{action_idx:02d}]",
                kv("Execute", action.get("Execute"), 22, "    "),
                kv("Arguments", action.get("Arguments"), 22, "    "),
                kv("Working Dir", working or "N/A", 22, "    "),
                kv("Executable broad-write", len(exe_hits), 22, "    "),
                kv("Parent broad-write", len(parent_hits), 22, "    "),
                kv("Working-dir broad-write", len(working_hits), 22, "    "),
                "",
            ]
            if privileged and (exe_hits or parent_hits or working_hits):
                findings.append({
                    "title": "Privileged Scheduled Task Action Requires Review",
                    "severity": "Informational",
                    "description": "A newly created privileged task action is associated with a broadly writable executable, parent, or working directory.",
                    "evidence": (
                        f"{label}: {exe}; executable broad-write={len(exe_hits)}; parent broad-write={len(parent_hits)}; "
                        f"working-dir broad-write={len(working_hits)}"
                    ),
                    "recommendation": "Validate effective standard-user write access and whether modifying the referenced object changes privileged scheduled-task execution.",
                })
        lines += [f"TRIGGERS ({len(triggers)})", "-" * width]
        if not triggers:
            lines.append("No trigger details returned.")
        for trig_idx, trigger in enumerate(triggers, 1):
            if isinstance(trigger, dict):
                lines += [
                    f"  [TRIGGER-{trig_idx:02d}]",
                    kv("Type", trigger.get("Type"), 18, "    "),
                    kv("Start", trigger.get("StartBoundary"), 18, "    "),
                    kv("End", trigger.get("EndBoundary"), 18, "    "),
                    kv("Enabled", trigger.get("Enabled"), 18, "    "),
                    "",
                ]
            else:
                lines += [f"  [TRIGGER-{trig_idx:02d}]", kv("Description", trigger, 18, "    "), ""]
        lines += [
            "WHAT TO REVIEW", "-" * width,
            "  - Confirm action executable/script and parent directory permissions.",
            "  - Determine whether arguments or configuration are writable by a lower-privileged user.",
            "  - For SYSTEM/highest tasks, validate any privilege boundary in permissions_review.txt.",
            "",
        ]

    artifact_path(assessment_dir, "scheduled_tasks_review.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    return {
        "status": "WARN" if findings else "PASS",
        "details": f"{len(new)} new task(s); {len(findings)} privileged writable-action review point(s)",
        "findings": findings,
        "new_tasks": new,
    }
