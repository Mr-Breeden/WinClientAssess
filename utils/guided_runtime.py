from __future__ import annotations

import csv
import json
import os
import shutil
import time
from pathlib import Path

from modules.advanced_runtime_review import run_advanced_runtime_review
from modules.application_profile import run_application_profile
from modules.dll_search_review import run_dll_search_review
from modules.guided_runtime_observation import (
    append_session,
    load_assessment_filters,
    load_runtime_targets,
    run_guided_collectors,
)
from modules.ipc_review import run_ipc_review
from modules.attack_surface_correlations import run_attack_surface_correlations
from modules.local_storage_review import run_local_storage_review
from modules.permissions_review import run_permissions_review
from modules.network_surface_review import run_network_surface_review
from modules.runtime_process_review import run_runtime_process_review
from modules.snapshots import compare_snapshots
from modules.test_cases import generate_test_cases
from utils.acl import AclCache
from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_layout import artifact_path
from utils.assessment_state import AssessmentState
from utils.guided_review import read_review, sync_review
from utils.path_filters import filter_install_diff
from utils.reporting import AssessmentReporter
from utils.tool_detection import detect_tools


RUNTIME_REFRESH_MODULES = (
    "Procmon Analysis",
    "DLL Search Review",
    "Runtime Process Review",
    "Advanced .NET / Native Runtime Review",
    "Network Surface Review",
    "IPC / Named Pipe Review",
    "Attack Surface Correlations",
    "Local Storage Review",
    "Permissions Review",
    "Application / Technology Profile",
)


def validate_guided_runtime_eligibility(root: Path, version: str) -> tuple[AssessmentState, dict]:
    root = Path(root)
    state = AssessmentState.load(root)
    if state is None:
        raise ValueError("Guided Runtime requires a structured Windows Client Assessment assessment.")
    if state.data.get("framework_version") != version:
        raise ValueError(
            f"Guided Runtime is version-bound. This assessment was created by "
            f"v{state.data.get('framework_version')}; use that release unchanged or run a fresh v{version} assessment."
        )
    if state.data.get("mode") != "full":
        raise ValueError("Guided Runtime requires a completed full-mode assessment.")
    if state.data.get("status") != "COMPLETED":
        raise ValueError("Guided Runtime is available only after the assessment has completed.")
    verification = verify_assessment(root, expected_framework_version=version)
    if verification.get("status") != "PASS":
        raise ValueError(
            "Assessment integrity must be PASS before Guided Runtime can add evidence. "
            "Resolve tampering, untracked artifacts, or lifecycle issues first."
        )
    render = root / "working" / "report_render_state.json"
    if not render.is_file():
        raise ValueError("Guided Runtime requires verified working/report_render_state.json.")
    return state, verification


def _commit_staged_evidence(root: Path, staged: dict[str, str]) -> None:
    """Atomically replace latest sanitized evidence and derived runtime reports."""
    for relative, source_value in (staged or {}).items():
        source = Path(source_value)
        if not source.is_file():
            continue
        destination = root / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_name(destination.name + ".tmp")
        try:
            shutil.copy2(source, temp)
            with temp.open("rb+") as handle:
                os.fsync(handle.fileno())
            os.replace(temp, destination)
        finally:
            if temp.exists():
                temp.unlink(missing_ok=True)


def _expand_profile(value):
    profile = str(os.environ.get("USERPROFILE") or "")
    if isinstance(value, str):
        return value.replace("%USERPROFILE%", profile) if profile else value
    if isinstance(value, list):
        return [_expand_profile(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_profile(item) for key, item in value.items()}
    return value


def _load_snapshot(root: Path, name: str):
    path = artifact_path(root, name)
    if not path.is_file():
        return None
    try:
        return _expand_profile(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None


def _load_file_inventory(root: Path) -> list[dict]:
    path = artifact_path(root, "file_inventory.csv")
    if not path.is_file():
        return []
    try:
        with path.open("r", newline="", encoding="utf-8-sig") as handle:
            return [_expand_profile(dict(row)) for row in csv.DictReader(handle)]
    except (OSError, csv.Error):
        return []


def _replace_module_result(reporter: AssessmentReporter, module: str, result: dict) -> None:
    """Refresh matching findings while preserving prior independently observed conditions.

    Guided Runtime is supplemental. If an earlier runtime session observed a condition
    that is not repeated in the latest window, that condition must not silently vanish.
    Findings with the same title are refreshed from current evidence; unmatched earlier
    findings remain traceable and keep their stable review identity.
    """
    result = result or {}
    incoming = list(result.get("findings", []) or [])
    incoming_titles = {str(item.get("title") or "") for item in incoming}
    reporter.findings = [
        item for item in reporter.findings
        if item.get("source_module") != module or str(item.get("title") or "") not in incoming_titles
    ]
    for finding in incoming:
        copied = dict(finding)
        copied.pop("source_module", None)
        reporter.add_finding(source_module=module, **copied)
    from utils.collection_provenance import record_native_method
    record_native_method(module, 'guided runtime evidence reanalysis',
                         status='SKIPPED' if result.get('status') == 'SKIPPED' else 'COMPLETED')
    reporter.set_status(
        module,
        result.get("status", "PASS"),
        result.get("details", ""),
        coverage_gap=bool(result.get("coverage_gap", False)),
    )


def _runtime_capabilities(root: Path, diff: dict, procmon_data: dict, network_result: dict, ipc_result: dict) -> dict:
    return {
        "installed_state": bool(diff),
        "filesystem_snapshot": bool(diff),
        "procmon": bool(procmon_data),
        "surface_review": bool(network_result) and bool(ipc_result)
                          and not bool(network_result.get("coverage_gap"))
                          and not bool(ipc_result.get("coverage_gap")),
        "services_added": bool((diff or {}).get("Services", {}).get("added")),
        "tasks_added": bool((diff or {}).get("ScheduledTasks", {}).get("added")),
        "drivers_added": bool((diff or {}).get("Drivers", {}).get("added")),
        "privilege_points": artifact_path(root, "privilege_boundary_review.txt").is_file(),
        "localhost_candidates": any(
            row.get("Scope") == "Loopback only" and row.get("HttpLikePort")
            for row in (network_result.get("network_records") or [])
        ),
        "local_storage": artifact_path(root, "local_storage_review.txt").is_file(),
    }


def _integrate_runtime_analysis(root: Path, reporter: AssessmentReporter, result: dict, runtime_targets: list[dict],
                                tools: dict, exclude_paths: list[str], target_only: bool, output_fn=print) -> dict:
    """Re-run the existing runtime analyses from the target-scoped guided trace."""
    procmon_result = result.get("procmon") or {}
    procmon_data = dict(procmon_result.get("procmon_data") or {})
    if procmon_data:
        procmon_data["guided_runtime"] = True
    if not procmon_data:
        return {"procmon_data": {}, "network": result.get("network") or {}, "ipc": result.get("ipc") or {}, "diff": {}}

    output_fn("[•] Feeding Guided Runtime evidence through the existing runtime analysis pipeline...")
    _replace_module_result(reporter, "Procmon Analysis", procmon_result)

    acl_cache = AclCache()
    dll_result = run_dll_search_review(root, procmon_data, runtime_targets, acl_cache)
    _replace_module_result(reporter, "DLL Search Review", dll_result)
    output_fn(f"[✓] DLL Search Review refreshed: {len(dll_result.get('dll_records') or [])} lookup(s)")

    runtime_process_result = run_runtime_process_review(
        root, runtime_targets, procmon_result.get("observed_process_names"), tools, exclude_paths,
    )
    _replace_module_result(reporter, "Runtime Process Review", runtime_process_result)
    output_fn(f"[✓] Runtime Process Review refreshed: {len(runtime_process_result.get('runtime_processes') or [])} active process(es)")

    advanced_result = run_advanced_runtime_review(
        root, {}, runtime_targets, procmon_data,
        runtime_process_result.get("runtime_processes"), tools, "full",
    )
    _replace_module_result(reporter, "Advanced .NET / Native Runtime Review", advanced_result)
    output_fn(f"[✓] Advanced Runtime Review refreshed: {len(advanced_result.get('advanced_runtime_pois') or [])} review point(s)")

    pre = _load_snapshot(root, "snapshot_pre.json")
    post = _load_snapshot(root, "snapshot_post.json")
    diff = {}
    if pre and post:
        diff = compare_snapshots(pre, post)
        diff, _ = filter_install_diff(diff, exclude_paths, exclude_framework_noise=True)

    # Reconcile runtime-observed DLL search paths with the central ACL report.
    # Only known target-filtered Procmon evidence is eligible for promotion.
    permissions_result = None
    runtime_dll = dll_result.get("dll_records") or []
    if procmon_data.get("target_filter_active") and any(
        row.get("DirectoryExists") and (row.get("BroadWriteACEs") or row.get("LikelyUserWritableLocation"))
        for row in runtime_dll
    ):
        permissions_result = run_permissions_review(
            root, pre, post, diff, acl_cache, None, runtime_dll,
        )
        _replace_module_result(reporter, "Permissions Review", permissions_result)
        output_fn(f"[✓] Permissions Review refreshed: {len(permissions_result.get('permission_results') or [])} ACL candidate(s)")

    file_inventory = _load_file_inventory(root)
    local_storage_result = run_local_storage_review(
        root, diff, procmon_data, runtime_targets, file_inventory, {}, acl_cache, bool(pre and post),
        runtime_process_result.get("runtime_processes") or [],
    )
    _replace_module_result(reporter, "Local Storage Review", local_storage_result)
    output_fn(
        f"[✓] Local Storage Review refreshed: {len(local_storage_result.get('storage_records') or [])} file(s), "
        f"{len(local_storage_result.get('storage_pois') or [])} review point(s)"
    )

    network_result = run_network_surface_review(
        root, runtime_targets, procmon_result.get("observed_process_names"),
        runtime_process_result.get("runtime_processes"), diff, {}, exclude_paths,
        procmon_data,
    )
    _replace_module_result(reporter, "Network Surface Review", network_result)
    ipc_result = run_ipc_review(
        root, tools, runtime_targets, procmon_result.get("observed_process_names"),
        network_result.get("runtime_processes") or runtime_process_result.get("runtime_processes"),
        None, exclude_paths, bool(target_only),
    )
    _replace_module_result(reporter, "IPC / Named Pipe Review", ipc_result)
    output_fn(f"[✓] Network/IPC reports refreshed: {len(network_result.get('network_records') or [])} network record(s), {len(ipc_result.get('ipc_records') or [])} pipe record(s)")

    known = run_attack_surface_correlations(
        root, "full", diff, pre, post, procmon_data, runtime_targets, acl_cache,
    )
    _replace_module_result(reporter, "Attack Surface Correlations", known)
    output_fn(f"[✓] Attack-surface correlations refreshed: {len(known.get('records') or [])} scoped indicator(s)")

    profile = run_application_profile(
        root, "full", {}, {}, {}, file_inventory, {}, {}, {}, diff, runtime_targets,
        runtime_process_result.get("runtime_processes") or [], network_result, ipc_result, [], local_storage_result,
    )
    _replace_module_result(reporter, "Application / Technology Profile", profile)
    output_fn("[✓] Application / Technology Profile refreshed")

    return {
        "procmon_data": procmon_data,
        "dll": dll_result,
        "runtime_process": runtime_process_result,
        "advanced": advanced_result,
        "network": network_result,
        "ipc": ipc_result,
        "known": known,
        "local_storage": local_storage_result,
        "permissions": permissions_result,
        "profile": profile,
        "diff": diff,
    }


def run_guided_runtime(root: Path, *, version: str, methodology_version: str,
                       catalog_version: str, input_fn=input, output_fn=print,
                       interactive_collectors: bool = True, web_control=None) -> dict:
    from utils.collection_provenance import session
    with session(Path(root).expanduser().resolve(), 'guided-runtime'):
        return _run_guided_runtime_impl(root, version=version,
            methodology_version=methodology_version, catalog_version=catalog_version,
            input_fn=input_fn, output_fn=output_fn,
            interactive_collectors=interactive_collectors, web_control=web_control)


def _run_guided_runtime_impl(root: Path, *, version: str, methodology_version: str,
                             catalog_version: str, input_fn=input, output_fn=print,
                             interactive_collectors: bool = True, web_control=None) -> dict:
    root = Path(root).expanduser().resolve()
    state, before = validate_guided_runtime_eligibility(root, version)

    runtime_targets = load_runtime_targets(root)
    if not runtime_targets:
        raise ValueError("No runtime targets are available. Re-run a full assessment with valid system-state/runtime target evidence.")

    render_path = root / "working" / "report_render_state.json"
    render = json.loads(render_path.read_text(encoding="utf-8"))
    if render.get("framework_version") != version or render.get("mode") != "full":
        raise ValueError("Verified report rendering state is inconsistent with the active Guided Runtime release.")

    tools = detect_tools()
    output_fn("")
    output_fn("GUIDED WINDOWS RUNTIME OBSERVATION")
    output_fn("Windows Client Assessment observes only; it does not launch, authenticate to, update, or exercise the client automatically.")
    output_fn("Exercise the applicable application/service workflows normally. No input is required during testing.")
    output_fn("Use Stop Guided Runtime Observation in the browser when testing is complete." if web_control else "Return to this window and press Enter once when runtime testing is complete.")
    output_fn("Raw PML/full-host CSV remains temporary. Only target-scoped sanitized runtime evidence is retained.")

    operation_started = time.monotonic()
    exclude_paths, report_target_only = load_assessment_filters(root)
    target_only = bool((state.data.get("options") or {}).get("target_only", report_target_only))
    result = run_guided_collectors(
        root, tools, runtime_targets, {}, exclude_paths=exclude_paths, target_only=target_only,
        interactive=interactive_collectors, input_fn=input_fn, output_fn=output_fn,
        controller_factory=(lambda targets, filters: (lambda **kw: web_control.capture(
            **kw, runtime_targets=targets, exclude_paths=filters))) if web_control else None,
    )
    from utils.collection_provenance import record_native_method
    record_native_method('Guided Runtime Observation', 'run_guided_collectors',
                         status='COMPLETED' if result.get('summary') else 'UNAVAILABLE')
    staging_value = result.get("staging_dir")
    staging_dir = Path(staging_value) if staging_value else None
    try:
        # v1.7.2 deliberately has no tester workflow-status prompts. Coverage is
        # derived from observed telemetry, not from hotkeys or post-capture attestation.
        result["summary"]["checklist"] = {}

        output_fn("[•] Committing target-scoped sanitized evidence and derived Procmon reports...")
        _commit_staged_evidence(root, result.get("staged_evidence") or {})
        output_fn("[✓] Target-scoped evidence committed; raw/full-host capture discarded")

        reporter = AssessmentReporter(
            root,
            state.data.get("assessment_name") or root.name,
            Path(render.get("installer_filename") or state.data.get("installer", {}).get("filename") or "installer.msi"),
            "full", version, state_tracker=state, target_type=(state.data.get("target") or {}).get("type", "installable"),
        )
        reporter.status = dict(render.get("modules") or state.data.get("modules") or {})
        reporter.findings = list(render.get("findings") or [])

        initial_procmon = dict(reporter.status.get("Procmon Runtime Capture") or {})
        capture_info = result.get("summary", {}).get("capture") or {}
        capture_status = str(capture_info.get("status") or "WARN")
        if capture_status not in {"PASS", "WARN"}:
            capture_status = "WARN"
        session_info = result.get("summary", {}).get("session") or {}
        failure_stage = str(session_info.get("failure_stage") or "")
        procmon_available = bool((result.get("procmon") or {}).get("procmon_data"))
        capture_gap = bool(failure_stage) or not procmon_available
        initial_text = initial_procmon.get("status") or "UNKNOWN"
        capture_details = (
            f"Supplemental Guided Runtime capture; initial assessment runtime-capture status was {initial_text}. "
            + str(capture_info.get("details") or "")
        ).strip()
        reporter.set_status("Procmon Runtime Capture", capture_status, capture_details, coverage_gap=capture_gap)
        if capture_gap and not procmon_available:
            # The initial assessment's Procmon Analysis status may have been PASS.
            # A failed supplemental capture cannot be presented as a successful
            # zero-event Guided Runtime analysis in its effective module table.
            reporter.set_status(
                "Procmon Analysis", "WARN",
                "Guided Runtime Procmon evidence unavailable; no target-event analysis could be completed"
                + (f" ({failure_stage})" if failure_stage else ""),
                coverage_gap=True,
            )

        integrated = _integrate_runtime_analysis(
            root, reporter, result, runtime_targets, tools, exclude_paths, target_only, output_fn,
        )

        surfaces = result["summary"].get("surfaces", {})
        unavailable = [name for name, item in surfaces.items() if item.get("status") == "COLLECTION UNAVAILABLE"]
        pois = len((integrated.get("network") or {}).get("network_pois") or []) + len((integrated.get("ipc") or {}).get("ipc_pois") or [])
        status = "WARN" if unavailable or pois or capture_gap else "PASS"

        result["summary"]["effective_runtime_modules"] = {
            name: dict(reporter.status.get(name) or {}) for name in ("Procmon Runtime Capture",) + RUNTIME_REFRESH_MODULES
        }
        details = (
            f"{result['summary']['counts'].get('current_target_processes', 0)} active target process(es); "
            f"{result['summary']['counts'].get('target_processes_seen', 0)} target/descendant process name(s) seen; "
            f"{result['summary']['counts'].get('procmon_target_events', 0)} target Procmon event(s); "
            f"{pois} current network/IPC POI(s)"
        )
        if unavailable:
            details += "; unavailable: " + ", ".join(name.replace("_", " ") for name in unavailable)
        if failure_stage:
            details += f"; Procmon failure stage: {failure_stage}"
        reporter.set_status("Guided Runtime Observation", status, details, coverage_gap=bool(unavailable))

        capabilities = _runtime_capabilities(
            root, integrated.get("diff") or {}, integrated.get("procmon_data") or {},
            integrated.get("network") or {}, integrated.get("ipc") or {},
        )
        test_result = generate_test_cases(
            root, "full", Path(render.get("target_filename") or render.get("installer_filename") or "").suffix.lower(), capabilities,
        )
        _replace_module_result(reporter, "Test Case Generation", test_result)
        output_fn("[✓] Test cases refreshed from effective current evidence")

        before_review = read_review(root) or {"items": {}}
        before_ids = set((before_review.get("items") or {}).keys())
        predicted_review = sync_review(root, reporter.findings, create=False)
        predicted_ids = set((predicted_review.get("items") or {}).keys())
        new_findings = len(predicted_ids - before_ids)
        result["summary"]["new_review_candidates"] = new_findings

        # Record useful timing before report generation. Capture duration comes
        # from Procmon; processing duration reflects evidence conversion/analysis.
        session = result["summary"].setdefault("session", {})
        elapsed_to_reports = max(0, int(time.monotonic() - operation_started))
        capture_seconds = int(session.get("capture_duration_seconds") or session.get("duration_seconds") or 0)
        session["capture_duration_seconds"] = capture_seconds
        session["processing_duration_seconds"] = max(int(session.get("processing_duration_seconds") or 0),
                                                     max(0, elapsed_to_reports - capture_seconds))
        session["total_duration_seconds"] = max(int(session.get("total_duration_seconds") or 0), elapsed_to_reports)

        sessions = append_session(root, result["summary"])

        output_fn("[•] Refreshing reports, review candidates and dashboard...")
        coverage = reporter.finalize()
        after_review = read_review(root) or {"items": {}}
        after_ids = set((after_review.get("items") or {}).keys())
        actual_new = len(after_ids - before_ids)
        if actual_new != new_findings:
            # Keep the runtime result accurate without forcing a second complete
            # report/dashboard regeneration pass.
            new_findings = actual_new
        output_fn(f"[✓] Review/dashboard refresh complete: {new_findings} new review candidate(s)")

        state.data["coverage"] = coverage
        # The original completion message may describe pre-runtime optional gaps.
        # Preserve initial collection history elsewhere; current lifecycle
        # summary must reflect the effective post-observation coverage.
        state.data["last_message"] = (
            f"Guided Runtime completed; effective coverage: {coverage}."
        )
        state.data["guided_runtime"] = {
            "schema_version": 3,
            "sessions": len(sessions),
            "latest_at": result["summary"].get("captured_at"),
            "latest_status": status,
            "last_new_review_candidates": new_findings,
            "latest_duration_seconds": int((result["summary"].get("session") or {}).get("capture_duration_seconds") or 0),
            "latest_target_events": int(result["summary"].get("counts", {}).get("procmon_target_events") or 0),
        }
        state.data["current_stage"] = "complete"
        state.data["status"] = "COMPLETED"
        state.save()

        output_fn("[•] Refreshing assessment integrity manifest...")
        create_manifest(
            root, framework_version=version,
            methodology_version=methodology_version,
            catalog_version=catalog_version,
        )
        after = verify_assessment(root, expected_framework_version=version)
        if after.get("status") != "PASS":
            raise RuntimeError("Guided Runtime completed, but post-update assessment integrity verification did not PASS.")
        output_fn("[✓] Assessment integrity verified")

        return {
            "before": before,
            "after": after,
            "summary": result["summary"],
            "sessions": len(sessions),
            "new_findings": new_findings,
            "module_status": status,
            "coverage": coverage,
            "operation_total_seconds": max(0, int(time.monotonic() - operation_started)),
        }
    finally:
        if staging_dir is not None and staging_dir.is_dir():
            shutil.rmtree(staging_dir, ignore_errors=True)
