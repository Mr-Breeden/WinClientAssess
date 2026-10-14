from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
from utils.windows_paths import as_list, extract_executable, parent_path
from utils.report_format import header, kv, bool_text
from utils.powershell import run_powershell_json
from utils.acl import broad_write_aces


def _signature_batch(paths):
    unique = []
    seen = set()
    for raw in paths:
        path = str(raw or "").strip().strip('"')
        if not path or path.lower() in seen:
            continue
        seen.add(path.lower())
        unique.append(path)
    if not unique:
        return {}
    quoted = ",".join("'" + p.replace("'", "''") + "'" for p in unique)
    ps = rf"""
    $paths=@({quoted})
    foreach($p in $paths){{
      if(Test-Path -LiteralPath $p -PathType Leaf){{
        try{{
          $s=Get-AuthenticodeSignature -LiteralPath $p
          [PSCustomObject]@{{Path=$p;Exists=$true;Status=[string]$s.Status;Signer=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{$null}};Timestamped=[bool]$s.TimeStamperCertificate}}
        }}catch{{[PSCustomObject]@{{Path=$p;Exists=$true;Status='Error';Signer=$null;Timestamped=$false}}}}
      }}else{{[PSCustomObject]@{{Path=$p;Exists=$false;Status='Unavailable';Signer=$null;Timestamped=$false}}}}
    }}
    """
    data, _ = run_powershell_json(ps, timeout=max(90, len(unique) * 10))
    rows = [data] if isinstance(data, dict) else (data if isinstance(data, list) else [])
    return {str(row.get("Path") or "").lower(): row for row in rows if isinstance(row, dict)}


def run_drivers_review(assessment_dir: Path, pre=None, post=None, diff=None, acl_cache=None):
    if diff is not None:
        new = as_list((diff or {}).get("Drivers", {}).get("added", []))
    else:
        old = {x.get("Name") for x in as_list((pre or {}).get("Drivers", []))}
        new = [x for x in as_list((post or {}).get("Drivers", [])) if x.get("Name") not in old]

    paths = []
    rows = []
    for driver in new:
        raw_path = str(driver.get("PathName") or "")
        driver_path = extract_executable(raw_path) or raw_path
        parent = parent_path(driver_path) if driver_path else ""
        rows.append((driver, driver_path, parent))
        paths.extend(x for x in (driver_path, parent) if x)
    acl_map = acl_cache.get_many(paths) if acl_cache and paths else {}
    sig_map = _signature_batch([row[1] for row in rows if row[1]])

    width = 112
    lines = header(
        "Windows Client Assessment - Driver Review",
        [
            "Reviews Windows driver services introduced by the installation.",
            "Driver paths are correlated with Authenticode state and executable/parent ACLs when available.",
        ], width
    )
    nonvalid = 0
    writable = 0
    lines += ["SUMMARY", "-" * width, kv("New drivers", len(new))]
    if not new:
        lines += ["", "No new driver services identified."]

    findings = []
    for idx, (driver, driver_path, parent) in enumerate(rows, 1):
        signature = sig_map.get(str(driver_path).lower(), {})
        sig_status = str(signature.get("Status") or "Unavailable")
        if sig_status not in {"Valid", "Unavailable"}:
            nonvalid += 1
        path_hits = broad_write_aces(acl_map.get(str(driver_path).lower(), {})) if driver_path else []
        parent_hits = broad_write_aces(acl_map.get(str(parent).lower(), {})) if parent else []
        if path_hits or parent_hits:
            writable += 1
        lines += [
            "", "=" * width,
            f"[DRV-{idx:03d}] {driver.get('Name')}",
            "=" * width,
            kv("Display Name", driver.get("DisplayName")),
            kv("State", driver.get("State")),
            kv("Start Mode", driver.get("StartMode")),
            kv("Start Account", driver.get("StartName")),
            kv("Service Type", driver.get("ServiceType")),
            kv("Driver Path", driver_path),
            kv("Authenticode Status", sig_status),
            kv("Signer", signature.get("Signer") or "Unavailable"),
            kv("Timestamped", bool_text(signature.get("Timestamped"))),
            kv("Driver broad-write ACEs", len(path_hits)),
            kv("Parent broad-write ACEs", len(parent_hits)),
            "WHAT TO REVIEW", "-" * width,
            "  - Confirm the driver is expected and required by the assessed client.",
            "  - Validate signature/version against the approved product release; a non-valid status requires context.",
            "  - Determine whether standard users can replace the .sys file or influence its parent directory.",
            "  - Identify device interfaces/IOCTLs and validate authorization manually when the driver exposes user-mode access.",
        ]
        if path_hits or parent_hits:
            findings.append({
                "title": "Driver File or Parent Permissions Require Validation",
                "severity": "Informational",
                "description": "A newly installed driver path or parent directory appears broadly writable and requires effective-access validation.",
                "evidence": f"{driver.get('Name')}: {driver_path}; file broad-write={len(path_hits)}; parent broad-write={len(parent_hits)}",
                "recommendation": "Validate effective standard-user modification rights and whether replacement or path influence changes driver loading behavior.",
            })

    lines[lines.index(kv("New drivers", len(new))) + 1:lines.index(kv("New drivers", len(new))) + 1] = [
        kv("Non-valid signature states", nonvalid),
        kv("Broad-writable driver paths", writable),
    ]
    artifact_path(assessment_dir, "new_drivers.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    return {
        "status": "WARN" if new else "PASS",
        "details": f"{len(new)} new driver(s); {writable} writable path review point(s); {nonvalid} non-valid signature state(s)",
        "findings": findings,
        "new_drivers": new,
    }
