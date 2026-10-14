from __future__ import annotations

"""Cross-phase application/technology profile for target scoping.

This report intentionally summarizes already-collected evidence rather than
creating a second source of truth.  It gives the tester one place to understand
package identity, technologies, installed components, runtime ownership,
storage, network/IPC and updater context.
"""

import re
import ntpath
from collections import Counter
from pathlib import Path

from utils.assessment_layout import artifact_path
from utils.privacy import portable_basename, sanitize_report_text
from utils.report_format import header, kv, section
from utils.target_association import association_roots
from utils.target_identity import read_msi_properties, select_target_installed_apps


def _read_summary_value(path: Path, label: str) -> str:
    if not path.is_file():
        return ""
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().lower().startswith(label.lower()) and ":" in line:
                return line.partition(":")[2].strip()
    except OSError:
        pass
    return ""


def _runtime_roots(runtime_targets):
    roots = []
    seen = set()
    for row in runtime_targets or []:
        path = str(row.get("Path") or "").strip().strip('"')
        if not path:
            continue
        parent = ntpath.dirname(path)
        key = parent.lower()
        if parent and key not in seen:
            seen.add(key)
            roots.append(parent)
    return roots


def _architectures(pe_result):
    rows = pe_result.get("pe_rows") or pe_result.get("rows") or []
    if rows:
        counts = Counter(str(row.get("architecture") or "Unknown") for row in rows if not row.get("error"))
        return ", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "Unknown"
    return "See binary_security_review.txt"


def run_application_profile(
    assessment_dir: Path,
    mode="static",
    installer_info=None,
    technology_result=None,
    application_scope=None,
    static_inventory=None,
    pe_result=None,
    dotnet_result=None,
    electron_result=None,
    diff=None,
    runtime_targets=None,
    runtime_processes=None,
    network_result=None,
    ipc_result=None,
    updater_candidates=None,
    local_storage_result=None,
):
    assessment_dir = Path(assessment_dir)
    installer_info = installer_info or {}
    technology_result = technology_result or {}
    application_scope = application_scope or {}
    pe_result = pe_result or {}
    dotnet_result = dotnet_result or {}
    electron_result = electron_result or {}
    diff = diff or {}
    runtime_targets = runtime_targets or []
    runtime_processes = runtime_processes or []
    network_result = network_result or {}
    ipc_result = ipc_result or {}
    updater_candidates = updater_candidates or []
    local_storage_result = local_storage_result or {}

    info = installer_info.get("installer_info", installer_info)
    meta = info.get("version_info") or {}
    technologies = list(technology_result.get("technologies") or [])
    prior_dotnet = _read_summary_value(artifact_path(assessment_dir, "dotnet_analysis.txt"), ".NET candidates")
    dotnet_count = len(dotnet_result.get("dotnet_candidates") or [])
    if not dotnet_count and prior_dotnet.isdecimal():
        dotnet_count = int(prior_dotnet)
    if dotnet_count:
        technologies.append(".NET")
    if electron_result.get("electron_versions") or electron_result.get("electron_signals"):
        technologies.append("Electron")
    technologies = list(dict.fromkeys(str(x) for x in technologies if x))

    # Fallback parsing makes the profile regenerable/reusable from a completed
    # assessment even when the original in-memory module results are absent.
    if not technologies:
        detected = _read_summary_value(artifact_path(assessment_dir, "installer_technology.txt"), "Built-in detections")
        if detected and not detected.lower().startswith("no known"):
            technologies.extend(x.strip() for x in detected.split(",") if x.strip())
    classification = application_scope.get("kind") or _read_summary_value(
        artifact_path(assessment_dir, "application_scope.txt"), "Classification"
    ) or "Unknown"

    services = list((diff.get("Services", {}) or {}).get("added", []) or [])
    tasks = list((diff.get("ScheduledTasks", {}) or {}).get("added", []) or [])
    drivers = list((diff.get("Drivers", {}) or {}).get("added", []) or [])
    installed_apps = list((diff.get("InstalledApplications", {}) or {}).get("added", []) or [])
    association = association_roots(diff, static_inventory)
    msi_properties = read_msi_properties(assessment_dir)
    target_apps = select_target_installed_apps(
        diff=diff, runtime_targets=runtime_targets, roots=association,
        installer_info=installer_info, msi_properties=msi_properties,
    )
    target_app = target_apps[0] if target_apps else {}
    # Guided Runtime regenerates the profile with no original in-memory
    # installer metadata. The privacy-safe target report remains authoritative.
    target_report = artifact_path(assessment_dir, "target_analysis.txt")
    product_name = (meta.get("ProductName") or msi_properties.get("ProductName") or target_app.get("DisplayName") or _read_summary_value(target_report, "Product Name") or "")
    product_version = (meta.get("ProductVersion") or meta.get("FileVersion") or msi_properties.get("ProductVersion") or target_app.get("DisplayVersion") or _read_summary_value(target_report, "Product Version") or _read_summary_value(target_report, "File Version") or "")
    product_publisher = (meta.get("CompanyName") or msi_properties.get("Manufacturer") or target_app.get("Publisher") or _read_summary_value(target_report, "Company") or "")
    roots = _runtime_roots(runtime_targets)
    runtime_names = sorted({str(row.get("ProcessName") or row.get("Name") or "") for row in runtime_targets if row.get("ProcessName") or row.get("Name")}, key=str.lower)
    active_names = sorted({str(row.get("Name") or "") for row in runtime_processes if row.get("Name")}, key=str.lower)
    storage_roots = list(local_storage_result.get("storage_roots") or [])

    width = 116
    lines = header(
        "Windows Client Assessment - Application / Technology Profile",
        [
            "Cross-phase profile built from selected-target, static, system-state and runtime evidence.",
            "The profile is a scoping/navigation aid; individual module reports remain authoritative for detailed observations.",
        ], width,
    )
    lines += [
        "IDENTITY", "-" * width,
        kv("Assessment mode", mode),
        kv("Selected input", info.get("name") or _read_summary_value(artifact_path(assessment_dir, "application_scope.txt"), "Selected executable") or "See target_analysis.txt / installer_analysis.txt"),
        kv("Product name", product_name or "Unavailable"),
        kv("Product version", product_version or "Unavailable"),
        kv("Company / publisher metadata", product_publisher or "Unavailable"),
        kv("Package classification", classification),
        kv("Technologies", ", ".join(technologies) or "No technology conclusively identified"),
        kv("Static source files", len(static_inventory or []) or _read_summary_value(artifact_path(assessment_dir, "application_scope.txt"), "Total static source files") or 0),
        kv("PE architecture summary", _architectures(pe_result)),
        kv("Managed/.NET candidates", dotnet_count),
        kv("Electron version declarations", len(electron_result.get("electron_versions") or [])),
    ]

    lines += section("Observed System Footprint", width)
    lines += [
        kv("Target installed application records", len(target_apps)),
        kv("Other observed installed-app changes", max(0, len(installed_apps) - len(target_apps))),
        kv("New services", len(services)),
        kv("New scheduled tasks", len(tasks)),
        kv("New drivers", len(drivers)),
        kv("Target install/runtime roots", len(roots)),
    ]
    for idx, root in enumerate(roots, 1):
        lines.append(f"  [{idx:02d}] {sanitize_report_text(root)}")

    lines += section("Runtime Ownership", width)
    if mode != "full":
        lines.append("Runtime ownership: NOT COLLECTED (static mode).")
    else:
        lines += [
            kv("Runtime target identities", len(runtime_targets)),
            kv("Target process names", ", ".join(runtime_names) or "COLLECTED / NO OBSERVATION"),
            kv("Processes active at review", ", ".join(active_names) or "NOT OBSERVED / not running at collection time"),
            kv("Network records", len(network_result.get("network_records") or [])),
            kv("IPC/named-pipe records", len(ipc_result.get("ipc_records") or [])),
        ]

    lines += section("Local Storage / Maintenance", width)
    if mode != "full":
        lines += [kv("Local storage", "NOT COLLECTED (static mode)"), kv("Updater candidates", "Static discovery only")]
    else:
        lines += [
            kv("Local storage evidence", local_storage_result.get("evidence_state") or "COLLECTION UNAVAILABLE / not run"),
            kv("Target storage files", len(local_storage_result.get("storage_records") or [])),
            kv("Storage review points", len(local_storage_result.get("storage_pois") or [])),
            kv("Updater / launcher candidates", len(updater_candidates)),
        ]
        for idx, root in enumerate(storage_roots[:30], 1):
            lines.append(f"  Storage root [{idx:02d}]: {sanitize_report_text(root)}")

    lines += section("Scoping Notes", width)
    lines += [
        "- Target identity is based on selected/static files, correlated system-state changes and runtime evidence rather than global host churn.",
        "- A process/path listed here is not automatically vulnerable and does not imply that every sibling file belongs to the product.",
        "- Use --exclude-path and --target-only when the assessment environment contains additional software that overlaps target activity.",
    ]

    artifact_path(assessment_dir, "application_profile.txt").write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8"
    )
    return {
        "status": "PASS",
        "details": (
            f"{len(technologies)} technology label(s); {len(runtime_targets)} runtime target(s); "
            f"{len(storage_roots)} local-storage root(s)"
        ),
        "profile": {
            "product_name": product_name,
            "product_version": product_version,
            "publisher": product_publisher,
            "technologies": technologies,
            "classification": classification,
            "runtime_roots": roots,
            "storage_roots": storage_roots,
        },
    }
