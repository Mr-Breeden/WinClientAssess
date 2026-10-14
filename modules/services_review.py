from __future__ import annotations
from utils.assessment_layout import artifact_path

import ntpath
from pathlib import Path
from utils.windows_paths import as_list, extract_executable, parent_path
from utils.powershell import run_powershell_json
from utils.report_format import header, section, kv, bool_text
from utils.component_context import is_privileged, account_for_report
from utils.acl import broad_write_aces, broad_create_file_aces


def _batch_service_sddl(services):
    names = [str(s.get("Name") or "") for s in services or [] if s.get("Name")]
    if not names:
        return {}

    quoted = ",".join("'" + name.replace("'", "''") + "'" for name in names)
    ps = f"""
    $names = @({quoted})
    $rows = foreach ($name in $names) {{
      $out = & sc.exe sdshow $name 2>&1
      [PSCustomObject]@{{Name=$name; SDDL=($out -join [Environment]::NewLine)}}
    }}
    $rows
    """
    data, _ = run_powershell_json(ps, timeout=max(60, len(names) * 5))
    rows = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    return {str(row.get("Name") or "").lower(): str(row.get("SDDL") or "").strip() for row in rows if isinstance(row, dict)}


def _unquoted_candidates(executable: str):
    """Return Windows CreateProcess-style intermediate EXE candidates.

    Example: C:\\Program Files\\Vendor App\\svc.exe -> C:\\Program.exe and
    C:\\Program Files\\Vendor.exe.  The real executable is intentionally omitted.
    """
    exe = str(executable or "").strip().strip('"')
    if not exe or " " not in exe:
        return []
    candidates = []
    for match in __import__('re').finditer(r"\s+", exe):
        prefix = exe[:match.start()].rstrip()
        if not prefix:
            continue
        candidate = prefix if ntpath.splitext(prefix)[1] else prefix + ".exe"
        if candidate.lower() != exe.lower() and candidate.lower() not in {x.lower() for x in candidates}:
            candidates.append(candidate)
    return candidates


def run_services_review(assessment_dir: Path, pre=None, post=None, tools=None, diff=None, acl_cache=None):
    if diff is not None:
        new = as_list((diff or {}).get("Services", {}).get("added", []))
    else:
        premap = {x.get("Name"): x for x in as_list((pre or {}).get("Services", []))}
        new = [s for s in as_list((post or {}).get("Services", [])) if s.get("Name") not in premap]
    sddl_map = _batch_service_sddl(new)
    width = 112
    findings = []

    # Query executable/parent/unquoted-candidate parent ACLs in one cached batch.
    acl_paths = []
    service_meta = []
    for service in new:
        executable = extract_executable(str(service.get("PathName") or "")) or ""
        parent = parent_path(executable) if executable else ""
        candidates = _unquoted_candidates(executable) if executable and not str(service.get("PathName") or "").lstrip().startswith('"') else []
        candidate_parents = [parent_path(item) for item in candidates if parent_path(item)]
        acl_paths.extend([x for x in [executable, parent, *candidate_parents] if x])
        service_meta.append((service, executable, parent, candidates, candidate_parents))
    acl_map = acl_cache.get_many(acl_paths) if acl_cache and acl_paths else {}

    lines = header(
        "Windows Client Assessment - Services Review",
        [
            "Reviews Windows services introduced by the target installation.",
            "Prioritize privileged services, executable paths, arguments, SDDL, writable dependencies, and actual unquoted-path candidates.",
        ],
        width,
    )
    privileged_count = sum(1 for s in new if is_privileged(s.get("StartName")))
    lines += [
        "SUMMARY",
        "-" * width,
        kv("New services", len(new)),
        kv("Privileged services", privileged_count),
        "",
        "QUICK INDEX",
        "-" * width,
    ]
    if not new:
        lines.append("No new services were identified.")
    for idx, (service, executable, _, _, _) in enumerate(service_meta, 1):
        lines.append(
            f"[SVC-{idx:03d}] {service.get('Name')} | "
            f"{account_for_report(service.get('StartName'))} | {service.get('StartMode')} | "
            f"{'PRIVILEGED' if is_privileged(service.get('StartName')) else 'STANDARD/OTHER'} | {executable}"
        )

    lines += section("Detailed Service Review", width)
    for idx, (service, executable, parent, candidates, candidate_parents) in enumerate(service_meta, 1):
        name = service.get("Name")
        sddl = sddl_map.get(str(name or "").lower(), "")
        privileged = is_privileged(service.get("StartName"))
        exe_acl = acl_map.get(str(executable).lower(), {}) if executable else {}
        parent_acl = acl_map.get(str(parent).lower(), {}) if parent else {}
        exe_broad = broad_write_aces(exe_acl)
        parent_broad = broad_write_aces(parent_acl)
        candidate_rows = []
        for candidate, candidate_parent in zip(candidates, candidate_parents):
            hits = broad_create_file_aces(acl_map.get(str(candidate_parent).lower(), {}))
            candidate_rows.append((candidate, candidate_parent, hits))

        lines += [
            "=" * width,
            f"[SVC-{idx:03d}] {name}",
            "=" * width,
            kv("Display Name", service.get("DisplayName")),
            kv("Execution Account", account_for_report(service.get("StartName"))),
            kv("Privileged", bool_text(privileged)),
            kv("Start Mode", service.get("StartMode")),
            kv("State", service.get("State")),
            kv("Raw Command", service.get("PathName")),
            kv("Executable", executable or "Unable to parse"),
            kv("Executable broad-write ACEs", len(exe_broad)),
            kv("Parent broad-write ACEs", len(parent_broad)),
            "",
            "SERVICE SECURITY DESCRIPTOR (SDDL)",
            "-" * width,
            sddl or "Unavailable",
            "",
            "UNQUOTED SERVICE PATH CANDIDATES",
            "-" * width,
        ]
        if not candidates:
            lines.append("Not applicable: command is quoted or executable path contains no spaces.")
        else:
            for candidate, candidate_parent, hits in candidate_rows:
                lines += [
                    f"  Candidate       : {candidate}",
                    f"  Parent directory: {candidate_parent}",
                    f"  Create-file ACEs: {len(hits)}",
                    "",
                ]
        lines += [
            "WHAT TO REVIEW",
            "-" * width,
            "  - Confirm the executable and parent directory ACLs in permissions_review.txt.",
            "  - Review command arguments and adjacent configuration/scripts used by the service.",
            "  - If privileged, determine whether a standard user can influence any startup/runtime dependency.",
            "  - For an unquoted path, validate the specific intermediate candidate paths above rather than the string alone.",
            "",
        ]

        command = str(service.get("PathName") or "")
        if privileged and executable and " " in executable and not command.lstrip().startswith('"'):
            writable = [(candidate, parent_dir) for candidate, parent_dir, hits in candidate_rows if hits]
            findings.append({
                "title": "Privileged Service Executable Path Requires Review",
                "severity": "Informational",
                "description": (
                    "A newly created privileged service uses an unquoted command line containing spaces. "
                    "WCA enumerated the actual intermediate executable candidates; exploitability still depends on effective create/write access."
                ),
                "evidence": (
                    f"{name}: {command}; candidates={', '.join(c for c, _, _ in candidate_rows) or 'none'}; "
                    f"create-file-capable candidate parents observed={len(writable)}"
                ),
                "recommendation": (
                    "Validate each intermediate candidate parent as a standard user and only demonstrate execution when a lower-privileged user can create the searched executable path."
                ),
            })

    artifact_path(assessment_dir, "services_review.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    return {
        "status": "WARN" if findings else "PASS",
        "details": f"{len(new)} new service(s); {sum(len(x[3]) for x in service_meta)} unquoted-path candidate(s)",
        "findings": findings,
        "new_services": new,
    }
