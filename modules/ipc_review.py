from __future__ import annotations
from utils.assessment_layout import artifact_path

import csv
import re
from pathlib import Path

from modules.runtime_process_review import collect_runtime_processes
from utils.command_runner import run_command
from utils.powershell import run_powershell_json
from utils.component_context import RuntimeContextIndex, account_for_report


MAX_PIPE_PERMISSION_CHECKS = 150
BROAD_PRINCIPALS = (
    "everyone",
    "authenticated users",
    "builtin\\users",
    "nt authority\\interactive",
    "users",
)

# A target process can hold a client handle to an operating-system pipe. Handle
# output does not establish that the target created or owns the server endpoint.
# Do not turn broad ACLs on well-known Windows endpoints into product POIs.
SYSTEM_PIPE_NAMES = {
    "atsvc", "browser", "eventlog", "initshutdown", "lsass", "netlogon",
    "ntsvcs", "plugplay", "protected_prefix\\local_service", "samr", "scerpc",
    "srvsvc", "wkssvc",
}


def _is_system_pipe(name: str) -> bool:
    normalized = str(name or "").strip("\\").lower()
    return normalized in SYSTEM_PIPE_NAMES


def _pipe_name_from_object(value: str):
    text = str(value or "").strip().strip('"')
    lower = text.lower()
    markers = [
        "\\device\\namedpipe\\",
        "\\??\\pipe\\",
        "\\pipe\\",
    ]
    for marker in markers:
        pos = lower.find(marker)
        if pos >= 0:
            suffix = text[pos + len(marker):].lstrip("\\")
            return suffix
    return ""


def _is_rpc_alpc(value: str):
    lower = str(value or "").lower()
    return (
        "\\rpc control\\" in lower
        or "alpc port" in lower
        or "\\basenamedobjects\\" in lower
        or "\\sessions\\" in lower and "basenamedobjects" in lower
    )


def _enumerate_pipes_powershell():
    ps = r"""
    $items = @(Get-ChildItem -Path '\\.\pipe\' -ErrorAction SilentlyContinue | ForEach-Object {
      [PSCustomObject]@{Name=$_.Name}
    })
    $items
    """
    data, result = run_powershell_json(ps, timeout=90)
    if isinstance(data, dict):
        return [data], ""
    if isinstance(data, list):
        return data, ""
    return [], result.get("stderr", "") or ""


def _pipelist_inventory(tools):
    pipelist = (tools or {}).get("PipeList", {}).get("path")
    if not pipelist:
        return "", ""
    result = run_command([pipelist], timeout=90)
    return result.get("stdout", ""), result.get("stderr", "")


def _parse_handle_csv(text: str, pid: int, process_name: str):
    pipes = []
    rpc_alpc = []
    if not text:
        return pipes, rpc_alpc

    # Handle may emit a banner before the CSV rows. Parse any line that looks
    # CSV-shaped and preserve all cells for later evidence.
    for line in text.splitlines():
        if "," not in line:
            continue
        try:
            row = next(csv.reader([line]))
        except Exception:
            continue
        cells = [str(x).strip() for x in row]
        joined = " | ".join(cells)
        pipe = _pipe_name_from_object(joined)
        if pipe:
            pipes.append(
                {
                    "Process": process_name,
                    "PID": pid,
                    "PipeName": pipe,
                    "ObjectPath": next(
                        (c for c in cells if _pipe_name_from_object(c)),
                        joined,
                    ),
                    "HandleFields": cells,
                }
            )
        elif _is_rpc_alpc(joined):
            rpc_alpc.append(
                {
                    "Process": process_name,
                    "PID": pid,
                    "Object": joined,
                    "HandleFields": cells,
                }
            )
    return pipes, rpc_alpc


def _target_handle_inventory(processes, tools, handle_raw_by_pid=None):
    handle = (tools or {}).get("Handle", {}).get("path")
    handle_raw_by_pid = handle_raw_by_pid or {}

    pipe_rows = []
    rpc_rows = []
    errors = []

    for proc in processes[:40]:
        pid = int(proc["PID"])
        name = str(proc.get("Name") or "")

        text = handle_raw_by_pid.get(pid) or handle_raw_by_pid.get(str(pid))
        if text is None:
            if not handle:
                errors.append(f"{name} PID {pid}: Handle not detected and no cached runtime Handle output was available.")
                continue
            result = run_command(
                [handle, "-accepteula", "-a", "-v", "-p", str(pid)],
                timeout=120,
            )
            text = result.get("stdout", "")
            if result.get("returncode") not in (0, 1):
                errors.append(
                    f"{name} PID {pid}: {result.get('stderr', '').strip() or 'Handle returned an error.'}"
                )

        pipes, rpc = _parse_handle_csv(text or "", pid, name)
        pipe_rows.extend(pipes)
        rpc_rows.extend(rpc)

    unique_pipes = []
    seen = set()
    for row in pipe_rows:
        key = (row["PID"], row["PipeName"].lower())
        if key in seen:
            continue
        seen.add(key)
        unique_pipes.append(row)

    unique_rpc = []
    seen = set()
    for row in rpc_rows:
        key = (row["PID"], row["Object"].lower())
        if key in seen:
            continue
        seen.add(key)
        unique_rpc.append(row)

    return unique_pipes, unique_rpc, "\n".join(errors)


def _broad_pipe_access_lines(text: str):
    hits = []
    for line in str(text or "").splitlines():
        lower = line.lower()
        if not any(principal in lower for principal in BROAD_PRINCIPALS):
            continue
        writable = (
            re.search(r"(^|\s)rw(\s|$)", lower) is not None
            or re.search(r"(^|\s)w(\s|$)", lower) is not None
            or "generic_write" in lower
            or "write_data" in lower
            or "write" in lower
            or "full control" in lower
            or "fullcontrol" in lower
        )
        if writable:
            hits.append(line.strip())
    return hits


def _pipe_permissions(pipe_rows, tools):
    accesschk = (tools or {}).get("AccessChk", {}).get("path")
    if not accesschk:
        return {}, "AccessChk not detected."

    permissions = {}
    errors = []
    names = []
    seen = set()
    for row in pipe_rows:
        name = str(row.get("PipeName") or "").strip("\\")
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        names.append(name)
    names = names[:MAX_PIPE_PERMISSION_CHECKS]

    for name in names:
        pipe_path = "\\pipe\\" + name
        result = run_command(
            [accesschk, "-accepteula", "-nobanner", "-v", pipe_path],
            timeout=60,
        )
        output = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
        permissions[name.lower()] = {
            "PipeName": name,
            "AccessChkPath": pipe_path,
            "ReturnCode": result.get("returncode"),
            "Output": output,
            "BroadWriteLines": _broad_pipe_access_lines(output),
            "Succeeded": result.get("returncode") in (0, 1)
            and "error getting security" not in output.lower()
            and "no matching objects found" not in output.lower(),
        }
        if not permissions[name.lower()]["Succeeded"]:
            errors.append(f"{name}: pipe permissions unavailable (return code {result.get('returncode')})")
    return permissions, "\n".join(errors)


def run_ipc_review(
    assessment_dir: Path,
    tools,
    runtime_targets=None,
    observed_process_names=None,
    runtime_processes=None,
    handle_raw_by_pid=None,
    exclude_paths=None,
    target_only=False,
):
    processes = runtime_processes or collect_runtime_processes(
        runtime_targets or [],
        observed_process_names or [],
        exclude_paths,
    )
    no_target_process = not processes
    by_pid = {int(p["PID"]): p for p in processes if p.get("PID") is not None}
    context = RuntimeContextIndex(runtime_targets or [], processes)

    if target_only:
        ps_pipes, ps_error = [], ""
        pipelist_text, pipelist_error = "", ""
    else:
        ps_pipes, ps_error = _enumerate_pipes_powershell()
    if not target_only and ps_error:
        pipelist_text, pipelist_error = _pipelist_inventory(tools)
    elif not target_only:
        pipelist_text, pipelist_error = "", ""
    target_pipes, rpc_alpc, handle_error = _target_handle_inventory(processes, tools, handle_raw_by_pid)
    permissions, permission_error = _pipe_permissions(target_pipes, tools)

    records = []
    pois = []
    for idx, pipe in enumerate(target_pipes, 1):
        proc = by_pid.get(int(pipe["PID"]), {})
        privileged, target = context.privileged_for(process=proc)
        perm = permissions.get(str(pipe["PipeName"]).lower(), {})
        broad = perm.get("BroadWriteLines", []) or []

        record = {
            "ID": f"PIPE-{idx:03d}",
            "Process": pipe["Process"],
            "PID": pipe["PID"],
            "PipeName": pipe["PipeName"],
            "ObjectPath": pipe["ObjectPath"],
            "Executable": proc.get("Exe", ""),
            "Username": proc.get("Username", ""),
            "PrivilegedContext": privileged,
            "ComponentSource": target.get("Source", ""),
            "Component": target.get("Component", ""),
            "Account": target.get("Account", ""),
            "RunLevel": target.get("RunLevel", ""),
            "AccessChkPath": perm.get("AccessChkPath", ""),
            "BroadWriteLines": broad,
            "AccessChkOutput": perm.get("Output", ""),
            "SystemPipe": _is_system_pipe(pipe["PipeName"]),
        }
        records.append(record)

        if broad and not record["SystemPipe"]:
            poi = dict(record)
            poi["POI"] = f"POI-IP-{len(pois) + 1:03d}"
            poi["Confidence"] = "HIGH" if privileged else "MEDIUM"
            poi["Reason"] = (
                "A broad principal appears to have write-capable access to a named pipe "
                "opened by a correlated target process. Endpoint ownership must be validated."
            )
            pois.append(poi)

    width = 116
    lines = [
        "WCA - IPC / NAMED PIPE REVIEW",
        "=" * width,
        "",
        "Purpose:",
        "  Correlates target processes with named pipes and other Windows IPC object indicators.",
        "  Named-pipe permissions are reviewed with AccessChk when available. Broad permissions",
        "  are triage signals and require functional authorization/privilege-boundary validation.",
        "",
        f"Correlated target processes : {len(processes)}",
        f"Target runtime correlation  : {'NOT OBSERVED' if no_target_process else 'OBSERVED'}",
        f"System pipes (PowerShell)   : {len(ps_pipes)}",
        f"Target-associated pipe records: {len(records)}",
        f"RPC/ALPC object indicators  : {len(rpc_alpc)}",
        f"Pipe permission POIs        : {len(pois)}",
        f"Target-only inventory       : {bool(target_only)}",
        "",
        "TARGET NAMED PIPES",
        "-" * width,
    ]

    if no_target_process:
        lines += [
            "COVERAGE GAP: No assessed-application process was correlated at collection time.",
            "The absence of target pipes/RPC objects is NOT proof the application has no IPC.",
            "Launch the application and installed services, check runtime_targets.txt, and repeat.",
            "",
        ]

    if not records:
        lines += [
            "No named-pipe handles were correlated to target processes.",
            "If Handle is unavailable or the client creates short-lived pipes, use PipeList/Process",
            "Explorer/Sysmon or repeat runtime activity while the relevant feature is active.",
            "",
        ]

    for item in records:
        lines += [
            f"[{item['ID']}] {item['Process']} (PID {item['PID']})",
            f"  Pipe Name           : \\\\.\\pipe\\{item['PipeName']}",
            f"  Executable          : {item['Executable'] or 'Unavailable'}",
            f"  Execution User      : {account_for_report(item['Username']) or 'Unavailable'}",
            f"  Privileged Context  : {item['PrivilegedContext']}",
            f"  Component Source    : {item['ComponentSource'] or 'N/A'}",
            f"  Account             : {item['Account'] or 'N/A'}",
            f"  Broad Write Lines   : {len(item['BroadWriteLines'])}",
            f"  System Pipe         : {item['SystemPipe']}",
        ]
        for hit in item["BroadWriteLines"]:
            lines.append(f"    - {hit}")
        if item["SystemPipe"] and item["BroadWriteLines"]:
            lines.append("    Note: Known Windows endpoint; target has an open handle, but ownership is not established. POI suppressed.")
        lines.append("")

    lines += ["IPC POINTS OF INTEREST", "-" * width]
    if not pois:
        lines += ["No broad-write named-pipe POIs were generated.", ""]
    for item in pois:
        lines += [
            "=" * width,
            f"[{item['POI']}] {item['Process']} -> \\\\.\\pipe\\{item['PipeName']}",
            "=" * width,
            f"Confidence           : {item['Confidence']}",
            f"Privileged Context   : {item['PrivilegedContext']}",
            f"Account              : {item['Account'] or account_for_report(item['Username']) or 'Unavailable'}",
            f"Reason               : {item['Reason']}",
            "Broad Access Evidence:",
        ]
        for hit in item["BroadWriteLines"]:
            lines.append(f"  - {hit}")
        lines += [
            "Manual Validation:",
            "  Test from an appropriate standard-user context whether the pipe accepts connections and",
            "  whether unauthenticated/unauthorized callers can invoke privileged operations, influence",
            "  trusted data, impersonation behavior, or service actions. Permission alone is not enough",
            "  to establish a reportable security issue.",
            "",
        ]

    lines += ["RPC / ALPC / OBJECT MANAGER INDICATORS", "-" * width]
    if not rpc_alpc:
        lines.append("No RPC/ALPC-related handle indicators were captured.")
    for idx, item in enumerate(rpc_alpc, 1):
        lines.append(
            f"[IPC-OBJ-{idx:03d}] {item['Process']} (PID {item['PID']}) | {item['Object']}"
        )

    warnings = [
        ("PowerShell pipe enumeration", ps_error),
        ("PipeList", pipelist_error),
        ("Handle", handle_error),
        ("AccessChk", permission_error),
    ]
    warnings = [(name, err) for name, err in warnings if err]
    if warnings:
        lines += ["", "COLLECTION NOTES / WARNINGS", "-" * width]
        for name, err in warnings:
            lines += [f"{name}:", err, ""]

    (artifact_path(assessment_dir, "ipc_review.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    target_names = {str(x.get("PipeName") or "").lower() for x in records}
    system_names = []
    seen_system = set()
    for item in ps_pipes:
        name = str(item.get("Name") or "")
        key = name.lower()
        if not name or key in seen_system:
            continue
        seen_system.add(key)
        system_names.append(name)

    other_system = [name for name in system_names if name.lower() not in target_names]

    inventory_lines = [
        "WCA - NAMED PIPE INVENTORY",
        "=" * width,
        "",
        "Purpose:",
        "  Records named pipes observed on the Windows host, with target-associated pipes shown first.",
        "  System-wide pipes are retained as reference data and normally do not require individual review.",
        "",
        "SUMMARY",
        "-" * width,
        f"System pipes observed        : {len(system_names)}",
        f"Target-associated pipes     : {len(records)}",
        f"Other/unassociated pipes    : {len(other_system)}",
        f"IPC permission review POIs  : {len(pois)}",
        "",
        "RECOMMENDED WORKFLOW",
        "-" * width,
        "1. Review TARGET-ASSOCIATED PIPES below.",
        "2. Open ipc_review.txt for process/privilege correlation and POI-IP records.",
        "3. Open named_pipe_permissions.txt for AccessChk results.",
        "4. Prioritize pipes associated with SYSTEM/elevated services or broad write access.",
        "5. Validate actual pipe connection/authorization behavior from a standard-user context.",
        "6. Use OTHER / SYSTEM PIPES only as reference unless another artifact links one to the client.",
        "",
        "TARGET-ASSOCIATED PIPES",
        "-" * width,
    ]

    if not records:
        inventory_lines += [
            "No target-process pipe handles were correlated during collection.",
            "Short-lived pipes may require repeating the surface review while the relevant feature is active.",
            "",
        ]
    for idx, record in enumerate(records, 1):
        poi_match = next((p for p in pois if p.get("PipeName") == record.get("PipeName") and p.get("PID") == record.get("PID")), None)
        inventory_lines += [
            "=" * width,
            f"[PIPE-{idx:03d}] \\\\.\\pipe\\{record.get('PipeName')}",
            "=" * width,
            f"Process              : {record.get('Process')} (PID {record.get('PID')})",
            f"Executable           : {record.get('Executable') or 'Unavailable'}",
            f"Execution Context    : {record.get('Account') or account_for_report(record.get('Username')) or 'Unavailable'}",
            f"Privileged Context   : {record.get('PrivilegedContext')}",
            f"Permissions Reviewed : {'YES' if record.get('AccessChkPath') else 'NO'}",
            f"Broad Write Lines    : {len(record.get('BroadWriteLines') or [])}",
            f"Review POI           : {poi_match.get('POI') if poi_match else 'None'}",
            "",
        ]

    if not target_only:
        inventory_lines += [
            "",
            "OTHER / SYSTEM PIPES",
            "-" * width,
            "The following pipes were observed but were not correlated with the assessed target processes.",
            "They are retained as supporting inventory and normally do not need manual review.",
            "",
        ]
        for name in other_system:
            inventory_lines.append(name)
    else:
        inventory_lines += [
            "",
            "OTHER / SYSTEM PIPES",
            "-" * width,
            "Suppressed by --target-only.",
        ]

    if pipelist_text:
        inventory_lines += [
            "",
            "PIPELIST RAW OUTPUT (SUPPORTING EVIDENCE)",
            "-" * width,
            pipelist_text.rstrip(),
        ]
    if ps_error:
        inventory_lines += ["", "PowerShell enumeration warning:", ps_error]
    if pipelist_error:
        inventory_lines += ["", "PipeList warning:", pipelist_error]
    (artifact_path(assessment_dir, "named_pipe_inventory.txt")).write_text(
        "\n".join(inventory_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    perm_lines = [
        "WCA - NAMED PIPE PERMISSIONS",
        "=" * width,
        "",
        f"Pipes checked: {len(permissions)}",
        f"Safety limit: {MAX_PIPE_PERMISSION_CHECKS}",
        "",
    ]
    for idx, item in enumerate(permissions.values(), 1):
        perm_lines += [
            "-" * width,
            f"[PIPE-ACL-{idx:03d}] \\\\.\\pipe\\{item['PipeName']}",
            "-" * width,
            item.get("Output") or "No AccessChk output returned.",
            "",
        ]
    if not permissions:
        perm_lines.append("No target pipe permissions were queried.")
    (artifact_path(assessment_dir, "named_pipe_permissions.txt")).write_text(
        "\n".join(perm_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    object_lines = [
        "WCA - IPC OBJECT HANDLES",
        "=" * width,
        "",
        "Purpose:",
        "  Advanced supporting inventory of RPC Control, ALPC, and Object Manager indicators.",
        "  Do not investigate every entry; prioritize objects correlated with privileged target components",
        "  or application behavior that requires deeper IPC protocol analysis.",
        "",
    ]
    if not rpc_alpc:
        object_lines.append("No RPC/ALPC/Object Manager indicators were captured for target processes.")
    for idx, item in enumerate(rpc_alpc, 1):
        object_lines += [
            f"[OBJ-{idx:03d}] {item['Process']} (PID {item['PID']})",
            f"  {item['Object']}",
            "",
        ]
    (artifact_path(assessment_dir, "ipc_object_handles.txt")).write_text(
        "\n".join(object_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    findings = []
    if pois:
        findings.append(
            {
                "title": "Named Pipe Access Controls Require Manual Validation",
                "severity": "Informational",
                "description": (
                    "One or more named pipes associated with target processes appear to grant "
                    "write-capable access to a broad Windows principal. Functional authorization "
                    "and privilege-boundary testing is required."
                ),
                "evidence": f"{len(pois)} POI-IP review record(s) generated.",
                "recommendation": (
                    "Validate effective standard-user access and determine whether the pipe permits "
                    "unauthorized privileged operations or trusted-data manipulation."
                ),
            }
        )

    permission_failures = sum(1 for item in permissions.values() if not item.get("Succeeded"))
    target_collection_gap = bool(no_target_process or handle_error or permission_failures)
    return {
        "status": "WARN" if pois or warnings or target_collection_gap else "PASS",
        "details": (
            f"{len(processes)} correlated process(es); {len(records)} target pipe(s); "
            f"{len(rpc_alpc)} RPC/ALPC indicator(s); "
            f"{len(pois)} IPC POI(s); {permission_failures} permission check failure(s)"
            + ("; no target process observed" if no_target_process else "")
            + ("; target handle collection incomplete" if handle_error else "")
        ),
        "findings": findings,
        "ipc_records": records,
        "ipc_pois": pois,
        "runtime_processes": processes,
        "coverage_gap": target_collection_gap,
    }
