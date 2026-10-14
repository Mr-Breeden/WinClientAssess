from __future__ import annotations
from utils.assessment_layout import artifact_path

import re
from collections import defaultdict
from pathlib import Path

from utils.report_format import header, section, kv, bool_text
from utils.component_context import RuntimeContextIndex, basename as _basename, normalize_path as _norm

MANAGED_MARKERS = {
    "mscoree.dll": ".NET Framework bootstrap",
    "clr.dll": ".NET Framework CLR",
    "clrjit.dll": ".NET JIT",
    "mscorlib.dll": ".NET Framework core library",
    "coreclr.dll": ".NET / .NET Core CLR",
    "hostfxr.dll": ".NET host resolver",
    "hostpolicy.dll": ".NET host policy",
    "system.private.corelib.dll": ".NET core library",
}

NATIVE_RUNTIME_PREFIXES = ("vcruntime", "msvcp", "ucrtbase", "kernel32", "kernelbase", "ntdll")
EXECUTION_UTILITIES = {
    "cmd.exe": "Command shell",
    "powershell.exe": "PowerShell",
    "pwsh.exe": "PowerShell",
    "wscript.exe": "Windows Script Host",
    "cscript.exe": "Windows Script Host",
    "mshta.exe": "HTML Application Host",
    "rundll32.exe": "DLL execution host",
    "regsvr32.exe": "COM registration/execution host",
    "msiexec.exe": "Windows Installer",
    "schtasks.exe": "Scheduled-task utility",
    "sc.exe": "Service-control utility",
    "certutil.exe": "Certificate utility",
    "bitsadmin.exe": "BITS utility",
    "curl.exe": "Network transfer utility",
    "reg.exe": "Registry utility",
    "net.exe": "Windows network/account utility",
    "net1.exe": "Windows network/account utility",
}
COMMAND_MARKERS = ("-encodedcommand", "-enc ", "frombase64string", "javascript:", "vbscript:", "downloadstring", "invoke-expression", "iex ")
USER_LOCATION_HINTS = ("\\users\\", "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\desktop\\", "\\public\\")
SYSTEM_PATH_HINTS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\")
COMMAND_LINE_RE = re.compile(
    r"(?i)command\s+line:\s*(.*?)(?=,\s*(?:current\s+directory|pid|parent\s+pid|integrity|user|session|architecture):|$)"
)


def _user_location_hint(value):
    normalized = _norm(value)
    return bool(normalized and any(x in normalized for x in USER_LOCATION_HINTS))


def _path_category(path):
    normalized = _norm(path)
    if not normalized:
        return "Unknown"
    if any(x in normalized for x in SYSTEM_PATH_HINTS):
        return "Windows/System"
    if _user_location_hint(normalized):
        return "User-profile / TEMP hint"
    if "\\program files\\" in normalized or "\\program files (x86)\\" in normalized:
        return "Program Files"
    if "\\programdata\\" in normalized:
        return "ProgramData"
    return "Other"


def _extract_command_line(detail):
    match = COMMAND_LINE_RE.search(str(detail or ""))
    return match.group(1).strip() if match else ""


def _managed_candidate_names(dotnet_result):
    names = set()
    for candidate in (dotnet_result or {}).get("dotnet_candidates", []) or []:
        name = _basename(candidate).lower()
        if name:
            names.add(name)
    return names


def _classify_managed(dotnet_result, loaded_images, runtime_processes, published_host_names=None):
    static_managed = _managed_candidate_names(dotnet_result)
    published_host_names = {str(name).lower() for name in (published_host_names or [])}
    modules_by_process = defaultdict(list)
    for event in loaded_images or []:
        process = str(event.get("Process") or "").lower()
        path = str(event.get("Path") or "")
        if process and path:
            modules_by_process[process].append(path)
    names = set(static_managed) | set(modules_by_process) | published_host_names
    names.update(str(proc.get("Name") or "").lower() for proc in (runtime_processes or []) if proc.get("Name"))
    rows = []
    for process in sorted(x for x in names if x):
        modules = modules_by_process.get(process, [])
        managed_hits, native_examples = [], []
        for module in modules:
            base = _basename(module).lower()
            if base in MANAGED_MARKERS:
                managed_hits.append({"Module": module, "Reason": MANAGED_MARKERS[base]})
            elif any(base.startswith(prefix) for prefix in NATIVE_RUNTIME_PREFIXES):
                native_examples.append(module)
        static_hit = process in static_managed or process in published_host_names
        runtime_hit = bool(managed_hits)
        if runtime_hit and native_examples:
            classification = "Managed runtime with native runtime dependencies"
        elif runtime_hit:
            classification = "Managed runtime observed"
        elif process in published_host_names:
            classification = "Published .NET application host (static evidence; CLR not observed)"
        elif static_hit:
            classification = "Managed candidate from static analysis"
        elif modules:
            classification = "Native / unmanaged runtime observed"
        else:
            classification = "Unknown / no runtime module evidence"
        rows.append({
            "Process": process,
            "Classification": classification,
            "StaticManagedCandidate": static_hit,
            "PublishedHostStaticEvidence": process in published_host_names,
            "ManagedRuntimeObserved": runtime_hit,
            "ManagedRuntimeModules": managed_hits,
            "NativeRuntimeModules": native_examples[:25],
            "LoadedImageCount": len(modules),
        })
    return rows


def _module_boundary(loaded_images, context):
    rows, pois, seen = [], [], set()
    for event in loaded_images or []:
        process, path = str(event.get("Process") or ""), str(event.get("Path") or "")
        if not process or not path:
            continue
        key = (process.lower(), _norm(path))
        if key in seen:
            continue
        seen.add(key)
        privileged, target = context.privileged_for(
            process={"Name": process, "PID": event.get("PID")},
            process_name=process,
        )
        user_hint = _user_location_hint(path)
        row = {
            "Time": event.get("Time", ""), "Process": process, "PID": event.get("PID"),
            "Module": path, "Category": _path_category(path), "PrivilegedContext": privileged,
            "UserControlledLocationHint": user_hint, "TargetAccount": target.get("Account", ""),
            "TargetRunLevel": target.get("RunLevel", ""),
        }
        rows.append(row)
        if privileged and user_hint:
            poi = dict(row)
            poi.update({
                "POI": f"POI-AR-{len(pois)+1:03d}", "Confidence": "HIGH",
                "Issue": "A privileged target process was observed loading an image from a user-profile/TEMP-like location.",
                "RecommendedTest": "Confirm the loaded image belongs to the assessed client, validate effective standard-user write permissions, and determine why the privileged process trusts the location. Actual Load Image evidence is stronger than a missing-DLL lookup, but security impact still requires manual validation.",
            })
            pois.append(poi)
    return rows, pois


def _child_processes(process_activity, context, poi_offset=0):
    rows, pois = [], []
    for event in process_activity or []:
        # Procmon attributes Process Create to the parent. Process Start belongs
        # to the new process itself and does not identify another child launch.
        if str(event.get("Operation") or "").lower() != "process create":
            continue
        parent = str(event.get("Process") or "")
        child_path = str(event.get("Path") or "")
        child_name = _basename(child_path).lower()
        detail = str(event.get("Detail") or "")
        command_line = _extract_command_line(detail)
        privileged, target = context.privileged_for(
            process={"Name": parent, "PID": event.get("PID")},
            process_name=parent,
        )
        execution_role = EXECUTION_UTILITIES.get(child_name, "")
        user_hint = _user_location_hint(child_path) or _user_location_hint(command_line)
        marker_hits = [m for m in COMMAND_MARKERS if m in command_line.lower()]
        row = {
            "Time": event.get("Time", ""), "ParentProcess": parent, "ParentPID": event.get("PID"),
            "ChildPath": child_path, "ChildName": child_name, "CommandLine": command_line,
            "ProcmonDetail": detail, "PrivilegedParent": privileged,
            "ParentAccount": target.get("Account", ""), "ParentRunLevel": target.get("RunLevel", ""),
            "ExecutionUtility": bool(execution_role), "ExecutionUtilityRole": execution_role,
            "UserControlledLocationHint": user_hint, "CommandMarkers": marker_hits,
        }
        rows.append(row)
        reasons, confidence = [], "LOW"
        if privileged and user_hint:
            reasons.append("A privileged target process launched a child from, or with command data referencing, a user-profile/TEMP-like location.")
            confidence = "HIGH"
        if privileged and execution_role:
            reasons.append(f"A privileged target process launched {child_name} ({execution_role}).")
            confidence = "HIGH"
        elif execution_role:
            reasons.append(f"The target process launched {child_name} ({execution_role}); review whether untrusted application input can influence the command or arguments.")
            confidence = "MEDIUM"
        if marker_hits:
            reasons.append("The command line contains a higher-risk execution/encoding marker: " + ", ".join(marker_hits))
            confidence = "HIGH" if privileged else "MEDIUM"
        if reasons:
            poi = dict(row)
            poi.update({
                "POI": f"POI-AR-{poi_offset+len(pois)+1:03d}", "Confidence": confidence,
                "Issue": " ".join(reasons),
                "RecommendedTest": "Trace the application input that reaches the process launch. Confirm execution account/integrity level and determine whether an untrusted user can influence the executable path, arguments, working directory, environment, or script content. Child-process creation by itself is not a vulnerability.",
            })
            pois.append(poi)
    return rows, pois


def _write_managed_context(assessment_dir, rows, runtime_processes=None):
    width = 112
    managed_count = sum(1 for x in rows if x["StaticManagedCandidate"] or x["ManagedRuntimeObserved"])
    lines = header("Windows Client Assessment - Managed Runtime Context", [
        "Correlates static .NET candidates with Procmon Load Image evidence.",
        "Static published-host identity and actual managed-runtime Load Image events are reported separately.",
        "A missing CLR Load Image event does not prove that the application is native-only.",
        "Use this report to decide whether managed diagnostics, native analysis, or mixed-mode review is appropriate.",
    ], width)
    active_names = {str(item.get("Name") or "").lower() for item in (runtime_processes or []) if item.get("Name")}
    actual_rows = [row for row in rows if row["Process"].lower() in active_names]
    static_only = [row for row in rows if row["Process"].lower() not in active_names]
    lines += ["SUMMARY", "-"*width,
              kv("Runtime target process identities classified", len(actual_rows)),
              kv("Static-only assembly/host identities", len(static_only)),
              kv("Static/managed candidate identities", managed_count),
              kv("Managed runtime directly observed", sum(bool(row["ManagedRuntimeObserved"]) for row in actual_rows)),
              "Static assembly entries are not counted as active processes."]
    for idx, row in enumerate(rows, 1):
        lines += ["", "="*width, f"[MCTX-{idx:03d}] {row['Process']}", "="*width,
                  kv("Classification", row["Classification"]), kv("Static .NET Candidate", bool_text(row["StaticManagedCandidate"])),
                  kv("Published Host (Static)", bool_text(row.get("PublishedHostStaticEvidence", False))),
                  kv("Managed Runtime Seen", bool_text(row["ManagedRuntimeObserved"])), kv("Loaded Images", row["LoadedImageCount"]),
                  "Managed Runtime Evidence:"]
        if not row["ManagedRuntimeModules"]:
            lines.append("  - None observed.")
        for item in row["ManagedRuntimeModules"]:
            lines.append(f"  - {item['Module']} ({item['Reason']})")
        if row["NativeRuntimeModules"]:
            lines.append("Native Runtime Examples:")
            lines.extend(f"  - {m}" for m in row["NativeRuntimeModules"][:12])
    (artifact_path(assessment_dir, "runtime_managed_context.txt")).write_text("\n".join(lines).rstrip()+"\n", encoding="utf-8")


def _write_module_boundary(assessment_dir, rows, pois):
    width = 112
    lines = header("Windows Client Assessment - Runtime Module Boundary Review", [
        "Summarizes modules actually observed through Procmon Load Image events and their path trust context.",
        "Prioritize privileged processes loading code from user-profile or temporary locations.",
    ], width)
    lines += ["SUMMARY", "-"*width, kv("Unique process/module pairs", len(rows)), kv("Module-boundary POIs", len(pois))]
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["Process"]].append(row)
    for process, items in sorted(grouped.items()):
        lines += section(process, width, len(items))
        for item in items:
            review = " [REVIEW]" if item["PrivilegedContext"] and item["UserControlledLocationHint"] else ""
            lines.append(f"{item['Module']} | {item['Category']} | Privileged={bool_text(item['PrivilegedContext'])}{review}")
    if pois:
        lines += section("Module Points of Interest", width, len(pois))
        for poi in pois:
            lines += ["="*width, f"[{poi['POI']}] {poi['Process']} -> {poi['Module']}", "="*width,
                      kv("Confidence", poi["Confidence"]), kv("Privileged Context", bool_text(poi["PrivilegedContext"])),
                      kv("Location Category", poi["Category"]), kv("Issue", poi["Issue"]), "Manual Validation:",
                      f"  {poi['RecommendedTest']}", ""]
    (artifact_path(assessment_dir, "runtime_module_boundary.txt")).write_text("\n".join(lines).rstrip()+"\n", encoding="utf-8")


def _write_child_processes(assessment_dir, rows, pois):
    width = 112
    lines = header("Windows Client Assessment - Runtime Child Process / Command Review", [
        "Correlates Procmon process-creation evidence with target privilege context and command-execution utilities.",
        "Shells, interpreters, installers, or helper processes require input/control validation before they become findings.",
    ], width)
    lines += ["SUMMARY", "-"*width, kv("Child-process events", len(rows)), kv("Command-execution POIs", len(pois))]
    if not rows:
        lines += ["", "No Process Create/Start events were retained for target processes."]
    for idx, row in enumerate(rows, 1):
        lines += ["", "-"*width, f"[CHILD-{idx:03d}] {row['ParentProcess']} -> {row['ChildName'] or row['ChildPath']}", "-"*width,
                  kv("Time", row["Time"]), kv("Parent PID", row["ParentPID"]), kv("Parent Privileged", bool_text(row["PrivilegedParent"])),
                  kv("Parent Account", row["ParentAccount"] or "N/A"), kv("Child Path", row["ChildPath"]),
                  kv("Execution Utility", row["ExecutionUtilityRole"] or "NO"), kv("User/TEMP Hint", bool_text(row["UserControlledLocationHint"])),
                  kv("Command Line", row["CommandLine"] or "Not parsed from Procmon detail")]
    if pois:
        lines += section("Child Process Points of Interest", width, len(pois))
        for poi in pois:
            lines += ["="*width, f"[{poi['POI']}] {poi['ParentProcess']} -> {poi['ChildName'] or poi['ChildPath']}", "="*width,
                      kv("Confidence", poi["Confidence"]), kv("Privileged Parent", bool_text(poi["PrivilegedParent"])),
                      kv("Issue", poi["Issue"]), kv("Command Line", poi["CommandLine"] or "Not parsed"),
                      "Manual Validation:", f"  {poi['RecommendedTest']}", ""]
    (artifact_path(assessment_dir, "runtime_child_processes.txt")).write_text("\n".join(lines).rstrip()+"\n", encoding="utf-8")


def _quote(value):
    return f'"{str(value)}"'


def _write_instrumentation_plan(assessment_dir, managed_context, runtime_processes, tools):
    width = 112
    lines = header("Windows Client Assessment - Advanced Runtime Instrumentation Plan", [
        "Tester-assisted workflows for deeper .NET and native analysis.",
        "Windows Client Assessment does not automatically attach debuggers, inject instrumentation, collect traces, or dump process memory.",
    ], width)
    lines += ["GENERAL WORKFLOW", "-"*width,
              "1. Select a high-value process/POI from advanced_runtime_review.txt.",
              "2. Confirm its PID and execution account in runtime_processes.txt.",
              "3. Use the least invasive diagnostic method that answers the test question.",
              "4. Capture only authorized evidence; avoid retaining unrelated user/process secrets.",
              "5. Revert the assessment VM after invasive runtime/debugging work."]
    managed_names = {x["Process"].lower() for x in managed_context if x["StaticManagedCandidate"] or x["ManagedRuntimeObserved"]}
    managed_processes = [p for p in (runtime_processes or []) if str(p.get("Name") or "").lower() in managed_names]
    trace = (tools or {}).get("dotnet-trace", {}).get("path")
    dump = (tools or {}).get("dotnet-dump", {}).get("path")
    counters = (tools or {}).get("dotnet-counters", {}).get("path")
    windbg = (tools or {}).get("WinDbg", {}).get("path")
    frida = (tools or {}).get("Frida", {}).get("path")
    ghidra = (tools or {}).get("Ghidra", {}).get("path")
    ilspy = (tools or {}).get("ILSpyCmd", {}).get("path")
    lines += section(".NET Diagnostics", width)
    lines.append("Use runtime_managed_context.txt to confirm a target appears managed before using dotnet-* diagnostics.")
    if not managed_processes:
        lines.append("No running managed target PID was correlated. Start the relevant client/service and rerun the runtime phase.")
    for proc in managed_processes[:20]:
        pid, name = proc.get("PID"), proc.get("Name")
        lines += ["", f"[{name} PID {pid}]"]
        lines.append(f"  Trace: {_quote(trace)} collect --process-id {pid} --duration 00:00:00:30 --output {_quote(assessment_dir/('dotnet_trace_'+str(pid)+'.nettrace'))}" if trace else "  dotnet-trace: not detected (optional).")
        lines.append(f"  Counters: {_quote(counters)} monitor --process-id {pid} --counters System.Runtime,System.Net.Http,System.Net.Security" if counters else "  dotnet-counters: not detected (optional).")
        lines.append(f"  Dump: {_quote(dump)} collect --process-id {pid} --output {_quote(assessment_dir/('dotnet_dump_'+str(pid)+'.dmp'))}" if dump else "  dotnet-dump: not detected (optional).")
    lines += section("Managed Static Review", width)
    source_report = artifact_path(assessment_dir, "dotnet_source_review.txt")
    if source_report.is_file():
        lines += ["dotnet_source_review.txt is available; correlate its actual source locations with observed runtime events."]
    elif managed_processes:
        lines += ["Managed runtime was observed, but dotnet_source_review.txt was not produced.",
                  "Use runtime classification and approved instrumentation; collect managed source only if available."]
    else:
        lines += ["No managed target PID was correlated, and dotnet_source_review.txt is unavailable.",
                  "Managed-source review is NOT APPLICABLE unless later evidence identifies a managed target."]
    lines.append(f"ILSpyCmd detected: {ilspy}" if ilspy else "ILSpyCmd not detected (optional).")
    lines += section("WinDbg Native / Mixed-Mode Review", width)
    lines += ([f"WinDbg detected: {windbg}", "Attach to a running target PID:", f"  {_quote(windbg)} -p <PID>",
               "Use this for targeted call-stack/module/exception analysis around runtime_module_boundary.txt evidence."]
              if windbg else ["WinDbg not detected (optional)."])
    lines += section("Frida Dynamic Instrumentation", width)
    lines += ([f"Frida detected: {frida}", "List local Frida-visible processes with the frida-ps utility.",
               f"Attach interactively: {_quote(frida)} -p <PID>",
               f"Attach with an approved observation script: {_quote(frida)} -p <PID> -l <approved_script.js>",
               "Prefer narrowly scoped observation hooks for process launch, file/registry, IPC, and selected API boundaries."]
              if frida else ["Frida not detected (optional)."])
    lines += section("Ghidra Native Static Analysis", width)
    if ghidra:
        lines += [f"Ghidra detected: {ghidra}", "Prioritize native EXE/DLL targets identified by runtime_module_boundary.txt."]
        lines += (["Headless import template:", f"  {_quote(ghidra)} <project_directory> <project_name> -import <binary_path>"]
                  if "analyzeheadless" in str(ghidra).lower()
                  else ["Use the Ghidra GUI to import the selected binary and correlate callers/imports with runtime evidence."])
    else:
        lines.append("Ghidra not detected (optional).")
    (artifact_path(assessment_dir, "advanced_instrumentation_plan.txt")).write_text("\n".join(lines).rstrip()+"\n", encoding="utf-8")


def _recover_managed_static_evidence(assessment_dir, dotnet_result, runtime_targets):
    """Recover static candidates lost when Guided Runtime runs in a new CLI session.

    A native apphost PE is not itself a CLR assembly. Treat it as statically
    identified .NET only if the saved analysis declares a published .NET host
    and lists a managed payload DLL sharing the selected primary EXE's stem.
    Absence of CLR Load Image events remains explicitly unobserved.
    """
    result = dict(dotnet_result or {})
    report = artifact_path(assessment_dir, "dotnet_analysis.txt")
    if not report.is_file():
        return result, set()
    text = report.read_text(encoding="utf-8", errors="replace")
    if not result.get("dotnet_candidates"):
        # The authoritative report provides an explicit number. Stop once this
        # many candidates have been read: later sections also contain paths to
        # decompiled assemblies and must not inflate the static inventory.
        match = re.search(r"(?m)^\.NET candidates\s*:\s*(\d+)", text)
        candidate_limit = min(int(match.group(1)), 10000) if match else 0
        candidates = []
        in_candidates = False
        for line in text.splitlines():
            if line.strip() == "CANDIDATES":
                in_candidates = True
                continue
            if not in_candidates or not candidate_limit:
                continue
            value = line.strip()
            if value.lower().endswith((".dll", ".exe")):
                candidates.append(value)
                if len(candidates) >= candidate_limit:
                    break
            elif value and set(value) != {"-"} and not value.startswith(("%SOURCE_DIR%", "%USERPROFILE%")):
                # End of the candidates section: do not borrow later paths.
                break
        result["dotnet_candidates"] = candidates
    hosts = set()
    if "Published .NET host detected: True" in text:
        dll_names = {_basename(p).lower() for p in result.get("dotnet_candidates", [])}
        for item in runtime_targets or []:
            if not (item.get("PortablePrimary") and item.get("PrimarySHA256")):
                continue
            name = str(item.get("ProcessName") or "").lower()
            if name.endswith(".exe") and name[:-4] + ".dll" in dll_names:
                hosts.add(name)
    return result, hosts


def run_advanced_runtime_review(assessment_dir: Path, dotnet_result=None, runtime_targets=None, procmon_data=None, runtime_processes=None, tools=None, mode="static"):
    runtime_targets, runtime_processes, procmon_data, tools = runtime_targets or [], runtime_processes or [], procmon_data or {}, tools or {}
    loaded_images = procmon_data.get("loaded_images", []) or []
    process_activity = procmon_data.get("process_activity", []) or []
    static_evidence, published_hosts = _recover_managed_static_evidence(assessment_dir, dotnet_result, runtime_targets)
    managed = _classify_managed(static_evidence, loaded_images, runtime_processes, published_hosts)
    context = RuntimeContextIndex(runtime_targets, runtime_processes)
    module_rows, module_pois = _module_boundary(loaded_images, context)
    child_rows, child_pois = _child_processes(process_activity, context, len(module_pois))
    pois = module_pois + child_pois
    _write_managed_context(assessment_dir, managed, runtime_processes)
    _write_module_boundary(assessment_dir, module_rows, module_pois)
    _write_child_processes(assessment_dir, child_rows, child_pois)
    _write_instrumentation_plan(assessment_dir, managed, runtime_processes, tools)
    width = 112
    managed_count = sum(1 for x in managed if x["StaticManagedCandidate"] or x["ManagedRuntimeObserved"])
    privileged_children = sum(1 for x in child_rows if x["PrivilegedParent"])
    privileged_user_modules = sum(1 for x in module_rows if x["PrivilegedContext"] and x["UserControlledLocationHint"])
    lines = header("Windows Client Assessment - Advanced .NET / Native Runtime Review", [
        "Correlates static .NET detection, Procmon module loading, target privilege context, and child-process execution.",
        "Automated POIs prioritize manual testing and are not confirmed vulnerabilities.",
    ], width)
    lines += ["SUMMARY", "-"*width, kv("Assessment Mode", mode), kv("Managed static/runtime identities", managed_count),
              kv("Runtime target processes", len({str(x.get("Name") or "").lower() for x in runtime_processes if x.get("Name")})),
              kv("Loaded process/module pairs", len(module_rows)), kv("Child-process events", len(child_rows)),
              kv("Privileged child events", privileged_children), kv("Privileged user/TEMP module loads", privileged_user_modules),
              kv("Advanced runtime POIs", len(pois)), "", "RECOMMENDED WORKFLOW", "-"*width,
              "1. Review runtime_managed_context.txt for managed/native classification.",
              "2. Review runtime_child_processes.txt for shells, interpreters, installers, and privileged child launches.",
              "3. Review runtime_module_boundary.txt for modules loaded from unexpected trust locations.",
              ("4. Correlate available .NET source-review entry points with runtime evidence."
               if artifact_path(assessment_dir, "dotnet_source_review.txt").is_file()
               else "4. No .NET source report was generated; review native evidence or classify a managed target before attempting managed-source correlation."),
              "5. Use advanced_instrumentation_plan.txt only when deeper evidence is required."]
    if not procmon_data:
        lines += ["", "RUNTIME EVIDENCE NOTE", "-"*width,
                  "No Procmon analysis data was supplied. Static managed context and instrumentation guidance were generated,",
                  "but child-process and Load Image correlation require a runtime Procmon capture/import."]
    if pois:
        lines += section("Advanced Runtime Points of Interest", width, len(pois))
        for poi in pois:
            process = poi.get("Process") or poi.get("ParentProcess") or "Unknown"
            subject = poi.get("Module") or poi.get("ChildPath") or "Runtime condition"
            lines += ["="*width, f"[{poi['POI']}] {process} -> {subject}", "="*width,
                      kv("Confidence", poi["Confidence"]), kv("Issue", poi["Issue"]), "Manual Validation:",
                      f"  {poi['RecommendedTest']}", ""]
    (artifact_path(assessment_dir, "advanced_runtime_review.txt")).write_text("\n".join(lines).rstrip()+"\n", encoding="utf-8")
    findings = []
    if pois:
        findings.append({
            "title": "Advanced Runtime Conditions Require Manual Validation", "severity": "Informational",
            "description": "Runtime correlation identified privileged module-loading or child-process/command-execution conditions that deserve targeted validation.",
            "evidence": f"{len(pois)} POI-AR review record(s) generated.",
            "recommendation": "Validate input control, execution privilege, path trust, authorization, and concrete impact before creating a reportable finding.",
        })
    return {"status": "WARN" if pois else "PASS",
            "details": f"{managed_count} managed candidate/process(es); {len(child_rows)} child-process event(s); {len(module_rows)} module pair(s); {len(pois)} advanced runtime POI(s)",
            "findings": findings, "managed_context": managed, "child_processes": child_rows, "module_boundary": module_rows,
            "advanced_runtime_pois": pois}
