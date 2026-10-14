from __future__ import annotations
from utils.assessment_layout import artifact_path

import csv
import ntpath
from collections import Counter
from pathlib import Path

from utils.sensitive_data import redact_sensitive_text, sanitize_procmon_csv, sanitize_procmon_field
from utils.privacy import sanitize_report_text
from utils.procmon_scope import trusted_roots, in_target_scope


MAX_DETAIL_EVENTS = 4000


def _read_csv(path: Path):
    encodings = ["utf-8-sig", "utf-16", "cp1252"]
    last_error = None
    for encoding in encodings:
        try:
            # Validate the complete stream. Procmon CSV headers are commonly ASCII,
            # so checking only the first line can misidentify a cp1252 trace as UTF-8
            # and fail much later when a path contains a non-ASCII character.
            with path.open("r", encoding=encoding, errors="strict", newline="") as probe:
                while probe.read(1024 * 1024):
                    pass
            return path.open("r", encoding=encoding, errors="strict", newline=""), encoding
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"Could not decode Procmon CSV: {last_error}")


def _norm(value):
    return str(value or "").strip()


def _normalized_row(row):
    normalized = {}
    for key, value in row.items():
        if key is None:
            continue
        raw = sanitize_procmon_field(_norm(value), is_detail=str(key).strip().lower() in {"detail", "details"})
        clean, _ = redact_sensitive_text(raw)
        normalized[str(key).strip().lower()] = clean
    return normalized


def _get_field(row, *names):
    for name in names:
        value = row.get(name.lower())
        if value is not None:
            return value
    return ""


def _target_names(runtime_targets):
    names = set()
    for target in runtime_targets or []:
        name = target.get("ProcessName") or ntpath.basename(str(target.get("Path") or ""))
        if name:
            names.add(name.lower())
    return names


def _format_events(title, events, fields):
    width = 112
    guidance = {
        "Procmon Missing DLL Lookups": "Review search paths and directory permissions; a missing DLL lookup alone is not a vulnerability.",
        "Procmon Loaded Images": "Supporting evidence of modules actually loaded by target processes. Use dll_search_review.txt for interpreted DLL-search results.",
        "Procmon Access Denied Events": "ACCESS DENIED is frequently normal. Investigate only when it reveals a broken security assumption, fallback path, or privilege boundary.",
        "Procmon Process Activity": "Use to understand child processes, helpers, launchers, and process lifecycle created during runtime testing.",
        "Procmon Registry Writes": "Review writes affecting persistence, security configuration, credentials, privileged services, or user-controllable settings.",
        "Procmon File Writes": "Review security-sensitive files, TEMP/staging behavior, privileged consumers, and writable configuration.",
        "Procmon Network Activity": "Supporting event inventory. Use network_surface_review.txt and packet/proxy analysis for interpreted network exposure.",
    }
    lines = [
        title.upper(),
        "=" * width,
        "",
        "Purpose:",
        f"  {guidance.get(title, 'Supporting Procmon evidence for manual runtime review.')}",
        "",
        f"Events retained: {len(events)}",
        "",
    ]
    if not events:
        lines.append("None identified.")
        return "\n".join(lines) + "\n"

    for idx, event in enumerate(events, 1):
        lines += ["-" * width, f"[{idx:04d}]", "-" * width]
        for label, key in fields:
            lines.append(f"{label:14}: {event.get(key, '')}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def analyze_procmon_csv(csv_path: Path, runtime_targets=None, filtered_csv_path=None, additional_tracked_names=None):
    target_names = _target_names(runtime_targets)
    tracked_names = set(target_names) | {str(n).lower() for n in (additional_tracked_names or []) if n}
    target_filter_active = bool(target_names)
    trusted_paths = [str(t.get("Path") or "") for t in (runtime_targets or [])]
    first_party_roots = trusted_roots(trusted_paths)

    total_rows = 0
    relevant_rows = 0
    process_counts = Counter()
    operation_counts = Counter()
    result_counts = Counter()

    missing_dlls = []
    loaded_images = []
    access_denied = []
    process_activity = []
    registry_writes = []
    file_writes = []
    ipc_writes = []
    network_activity = []
    observed_process_names = set()

    # Optional working view is generated during the existing analysis pass.
    # The original *sanitized* evidence stays intact, and no second CSV scan
    # or large in-memory event list is needed to produce the filtered view.
    target_view = Path(filtered_csv_path) if filtered_csv_path else None
    temp_view = (target_view.with_name("." + target_view.name + ".tmp") if target_view else None)
    if target_view and (target_view.resolve() == Path(csv_path).resolve()
                        or temp_view.resolve() == Path(csv_path).resolve()):
        raise ValueError("Filtered Procmon working destination must differ from the source CSV")
    if target_view:
        # On reruns, never leave a stale working CSV that might be mistaken for
        # evidence from the current capture.
        target_view.unlink(missing_ok=True)
        temp_view.unlink(missing_ok=True)

    fh, encoding = _read_csv(csv_path)
    filtered_rows = 0
    try:
        with fh:
            reader = csv.DictReader(fh)
            headers = reader.fieldnames or []
            process_header = next(
                (header for header in headers if header.strip().lower() in {"process name", "processname"}),
                None,
            )
            view_file = None
            view_writer = None
            if target_view and target_filter_active:
                target_view.parent.mkdir(parents=True, exist_ok=True)
                view_file = temp_view.open("w", encoding="utf-8-sig", newline="")
                view_writer = csv.DictWriter(view_file, fieldnames=headers, extrasaction="ignore")
                view_writer.writeheader()
            try:
                for row in reader:
                    total_rows += 1
                    # A cheap early filter avoids re-redacting millions of
                    # unrelated rows already sanitized in the source CSV.
                    if target_filter_active and process_header:
                        if _norm(row.get(process_header)).lower() not in tracked_names:
                            continue
                    normalized = _normalized_row(row)
                    process = _get_field(normalized, "Process Name", "ProcessName")
                    operation = _get_field(normalized, "Operation")
                    path = _get_field(normalized, "Path")
                    result = _get_field(normalized, "Result")
                    detail = _get_field(normalized, "Detail")
                    pid = _get_field(normalized, "PID")
                    time_of_day = _get_field(normalized, "Time of Day", "Time")
                    process_l = process.lower()

                    if target_filter_active and process_l not in tracked_names:
                        continue

                    relevant_rows += 1
                    if view_writer:
                        # Sanitize again defensively: analyze_procmon_csv is also
                        # a public helper and might receive a raw caller CSV.
                        view_writer.writerow({
                            header: sanitize_report_text(redact_sensitive_text(row.get(header, ""))[0])
                            for header in headers
                        })
                        filtered_rows += 1
                    if process:
                        observed_process_names.add(process)
                        process_counts[process] += 1
                    if operation:
                        operation_counts[operation] += 1
                    if result:
                        result_counts[result] += 1

                    event = {
                        "Time": time_of_day,
                        "Process": process,
                        "PID": pid,
                        "Operation": operation,
                        "Path": path,
                        "Result": result,
                        "Detail": detail,
                    }

                    op_l = operation.lower()
                    result_l = result.lower()
                    path_l = path.lower()

                    # Only an executable under a verified first-party root
                    # may extend target tracking. Its parent launch event is
                    # still retained even when the child is external.
                    if op_l == "process create" and in_target_scope(path, first_party_roots):
                        child_name = ntpath.basename(path).strip().lower()
                        if child_name:
                            tracked_names.add(child_name)

                    if (
                        op_l == "createfile"
                        and result_l in {"name not found", "path not found"}
                        and path_l.endswith(".dll")
                        and len(missing_dlls) < MAX_DETAIL_EVENTS
                    ):
                        missing_dlls.append(event)

                    if (
                        op_l == "load image"
                        and (path_l.endswith(".dll") or path_l.endswith(".exe"))
                        and len(loaded_images) < MAX_DETAIL_EVENTS
                    ):
                        loaded_images.append(event)

                    if result_l == "access denied" and len(access_denied) < MAX_DETAIL_EVENTS:
                        access_denied.append(event)

                    if op_l in {"process create", "process start", "process exit"} and len(process_activity) < MAX_DETAIL_EVENTS:
                        process_activity.append(event)

                    if (
                        op_l.startswith("regset")
                        or op_l.startswith("regcreate")
                        or op_l.startswith("regdelete")
                    ) and len(registry_writes) < MAX_DETAIL_EVENTS:
                        registry_writes.append(event)

                    if op_l in {
                        "writefile",
                        "setrenameinformationfile",
                        "setdispositioninformationfile",
                        "setendoffileinformationfile",
                    }:
                        # Procmon represents named pipes and other device-backed IPC
                        # as file operations. Keep those events available for IPC
                        # correlation, but do not inflate filesystem-write coverage.
                        if path_l.startswith("\\device\\namedpipe" + "\\") or path_l.startswith("\\\\.\\pipe" + "\\"):
                            if len(ipc_writes) < MAX_DETAIL_EVENTS:
                                ipc_writes.append(event)
                        elif len(file_writes) < MAX_DETAIL_EVENTS:
                            file_writes.append(event)

                    if (
                        op_l.startswith("tcp ")
                        or op_l.startswith("udp ")
                        or "tcp connect" in op_l
                        or "udp send" in op_l
                    ) and len(network_activity) < MAX_DETAIL_EVENTS:
                        network_activity.append(event)

            finally:
                if view_file:
                    view_file.close()
        if view_writer:
            temp_view.replace(target_view)
    except BaseException:
        if temp_view:
            temp_view.unlink(missing_ok=True)
        raise

    return {
        "encoding": encoding,
        "headers": headers,
        "target_filter_active": target_filter_active,
        "target_process_names": sorted(target_names),
        "tracked_process_names": sorted(tracked_names),
        "total_rows": total_rows,
        "relevant_rows": relevant_rows,
        "target_filtered_csv": str(target_view) if target_view and target_filter_active else None,
        "target_filtered_rows": filtered_rows,
        "process_counts": dict(process_counts.most_common()),
        "operation_counts": dict(operation_counts.most_common()),
        "result_counts": dict(result_counts.most_common()),
        "missing_dlls": missing_dlls,
        "loaded_images": loaded_images,
        "access_denied": access_denied,
        "process_activity": process_activity,
        "registry_writes": registry_writes,
        "file_writes": file_writes,
        "ipc_writes": ipc_writes,
        "network_activity": network_activity,
        "observed_process_names": sorted(observed_process_names),
    }


def run_procmon_analysis(
    assessment_dir: Path,
    csv_path,
    runtime_targets=None,
    pre_sanitization=None,
):
    source = Path(csv_path).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Procmon CSV not found: {source}")

    previous = pre_sanitization if isinstance(pre_sanitization, dict) else {}
    imported_sanitized = artifact_path(assessment_dir, "procmon_runtime_sanitized.csv")
    filtered_view = artifact_path(assessment_dir, "working/procmon_target_events.csv")
    # Drop previous-run target evidence even if input sanitization fails before
    # we enter the analysis pass. The full sanitized source is never removed.
    if source != filtered_view.resolve():
        filtered_view.unlink(missing_ok=True)

    # Automated capture already writes a sanitized, retained CSV. Analyze that
    # file directly instead of creating a second byte-for-byte copy. Imported
    # CSV evidence is still sanitized into a framework-owned working copy.
    if previous and source.name.lower() == "procmon_runtime_capture.csv":
        sanitized_source = source
        sanitation = previous
        try:
            if imported_sanitized.exists() and imported_sanitized.resolve() != source:
                imported_sanitized.unlink()
        except OSError:
            pass
    else:
        sanitized_source = imported_sanitized
        sanitation_target = sanitized_source
        if source == sanitized_source.resolve():
            sanitation_target = artifact_path(assessment_dir, ".procmon_runtime_sanitized.tmp.csv")
        sanitation = sanitize_procmon_csv(source, sanitation_target)
        if sanitation_target != sanitized_source:
            sanitation_target.replace(sanitized_source)
    previous_names = Counter(previous.get("sensitive_names") or {})
    current_names = Counter(sanitation.get("sensitive_names") or {})
    sensitive_names = Counter(
        {
            name: max(previous_names.get(name, 0), current_names.get(name, 0))
            for name in set(previous_names) | set(current_names)
        }
    )
    redaction_count = sum(sensitive_names.values())

    data = analyze_procmon_csv(
        sanitized_source, runtime_targets, filtered_view,
        additional_tracked_names=(sanitation.get("tracked_process_names") if previous else None),
    )

    width = 108
    lines = [
        "WCA - PROCMON RUNTIME ANALYSIS",
        "=" * width,
        "",
        "Purpose:",
        "  Summarizes Process Monitor activity for Windows Client Assessment runtime targets. Events are",
        "  triage data and should not be treated as vulnerabilities without manual validation.",
        "",
        f"Source CSV              : {source}",
        f"Sanitized evidence      : {sanitized_source}",
        f"Detected encoding       : {data['encoding']}",
        f"Sensitive values redacted: {redaction_count}",
        f"Total CSV rows          : {data['total_rows']}",
        f"Target-relevant rows    : {data['relevant_rows']}",
        f"Target-only working CSV : {data['target_filtered_csv'] or 'Not generated (no target filtering)'}",
        f"Target-only CSV rows    : {data['target_filtered_rows']}",
        f"Target filtering active : {data['target_filter_active']}",
        f"Target process names    : {', '.join(data['target_process_names']) if data['target_process_names'] else 'ALL PROCESSES'}",
        "",
        "EVENT SUMMARY",
        "-" * width,
        f"Missing DLL lookups     : {len(data['missing_dlls'])}",
        f"Loaded images retained  : {len(data['loaded_images'])}",
        f"Access denied events    : {len(data['access_denied'])}",
        f"Process events          : {len(data['process_activity'])}",
        f"Registry writes         : {len(data['registry_writes'])}",
        f"Filesystem writes       : {len(data['file_writes'])}",
        f"IPC/device writes       : {len(data.get('ipc_writes') or [])}",
        f"Network events          : {len(data['network_activity'])}",
        "",
        "TOP PROCESSES",
        "-" * width,
    ]
    for name, count in list(data["process_counts"].items())[:25]:
        lines.append(f"{name:50} {count:>10}")
    lines += ["", "TOP OPERATIONS", "-" * width]
    for name, count in list(data["operation_counts"].items())[:30]:
        lines.append(f"{name:50} {count:>10}")
    lines += ["", "TOP RESULTS", "-" * width]
    for name, count in list(data["result_counts"].items())[:20]:
        lines.append(f"{name:50} {count:>10}")

    (artifact_path(assessment_dir, "procmon_summary.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    fields = [
        ("Time", "Time"),
        ("Process", "Process"),
        ("PID", "PID"),
        ("Operation", "Operation"),
        ("Path", "Path"),
        ("Result", "Result"),
        ("Detail", "Detail"),
    ]
    outputs = {
        "procmon_missing_dlls.txt": ("Procmon Missing DLL Lookups", data["missing_dlls"]),
        "procmon_loaded_images.txt": ("Procmon Loaded Images", data["loaded_images"]),
        "procmon_access_denied.txt": ("Procmon Access Denied Events", data["access_denied"]),
        "procmon_process_activity.txt": ("Procmon Process Activity", data["process_activity"]),
        "procmon_registry_writes.txt": ("Procmon Registry Writes", data["registry_writes"]),
        "procmon_file_writes.txt": ("Procmon File Writes", data["file_writes"]),
        "procmon_network_activity.txt": ("Procmon Network Activity", data["network_activity"]),
    }
    for filename, (title, events) in outputs.items():
        artifact_path(assessment_dir, filename).write_text(
            _format_events(title, events, fields),
            encoding="utf-8",
        )

    runtime_secret_lines = [
        "WCA - RUNTIME SECRET HANDLING REVIEW",
        "=" * 112,
        "",
        "Purpose:",
        "  Records sensitive environment variables, URL parameters, or authorization values detected",
        "  in Procmon evidence. Values are redacted before derived reports are written.",
        "",
        f"Sensitive values redacted : {redaction_count}",
        f"Sensitive field names      : {', '.join(sorted(sensitive_names)) or 'None'}",
        f"Sanitized evidence         : {sanitized_source}",
        "",
    ]
    if redaction_count:
        runtime_secret_lines += [
            "SECURITY INTERPRETATION",
            "-" * 112,
            "Sensitive values were present in process/runtime evidence. Determine whether the value was",
            "inherited by a less-trusted child/renderer, placed on a command line or URL, reusable after",
            "capture, or exposed to users who can read diagnostic artifacts.",
            "",
            "Archive handling: retain only sanitized CSV/text outputs. Raw PML and raw CSV files must be",
            "treated as credential-bearing evidence.",
        ]
    else:
        runtime_secret_lines.append("No configured sensitive runtime value patterns were detected.")
    (artifact_path(assessment_dir, "runtime_secrets_review.txt")).write_text(
        "\n".join(runtime_secret_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    findings = []
    if redaction_count:
        findings.append(
            {
                "title": "Sensitive Values Exposed in Runtime Process Evidence",
                "severity": "Medium",
                "description": (
                    "Process/runtime evidence contained credential-like environment variables, URL parameters, "
                    "or authorization values. Windows Client Assessment redacted retained text/CSV evidence, but the product "
                    "secret-handling boundary and any separately retained raw captures require validation."
                ),
                "evidence": (
                    f"{redaction_count} sensitive value occurrence(s) redacted; field names: "
                    f"{', '.join(sorted(sensitive_names)) or 'Unavailable'}."
                ),
                "recommendation": (
                    "Determine whether affected values are reusable, invalidate exposed credentials, avoid passing "
                    "secrets through child-process environments/URLs, and restrict or destroy raw runtime captures."
                ),
            }
        )

    return {
        "status": "WARN" if data["missing_dlls"] or data["access_denied"] or redaction_count else "PASS",
        "details": (
            f"{data['relevant_rows']} target-relevant event(s); "
            f"{len(data['missing_dlls'])} missing DLL lookup(s); "
            f"{len(data['access_denied'])} access-denied event(s); "
            f"{redaction_count} sensitive value(s) redacted"
        ),
        "findings": findings,
        "procmon_data": data,
        "observed_process_names": data["observed_process_names"],
        "target_filtered_path": data["target_filtered_csv"],
        "sanitization": {
            "redaction_count": redaction_count,
            "sensitive_names": dict(sorted(sensitive_names.items())),
            "sanitized_path": str(sanitized_source),
        },
    }
