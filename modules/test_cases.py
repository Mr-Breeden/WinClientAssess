from utils.assessment_layout import artifact_path
from pathlib import Path
import re

from utils.artifacts import artifact
from modules.test_case_catalog import TEST_CASES


TEST_CASE_POLICY = {
    "TC-IN-001": {"modes": {"static", "full"}, "files": {artifact("installer_analysis"), artifact("installer_technology")}},
    "TC-TG-001": {"modes": {"static", "full"}, "files": {artifact("target_analysis"), artifact("application_scope")}},
    "TC-SG-001": {"modes": {"static", "full"}, "files": {artifact("signature_review")}},
    "TC-MS-001": {"modes": {"static", "full"}, "installer_exts": {".msi"}, "files": {artifact("msi_analysis")}},
    "TC-PE-001": {"modes": {"static", "full"}, "files": {artifact("binary_security_review")}},
    "TC-CF-001": {"modes": {"static", "full"}, "files": {artifact("configuration_review"), artifact("secrets_review"), artifact("high_value_security_artifacts")}},
    "TC-LS-001": {"modes": {"full"}, "capabilities": {"installed_state"}, "files": {artifact("local_storage_review")}},
    "TC-FS-001": {"modes": {"full"}, "capabilities": {"filesystem_snapshot"}, "files": {artifact("filesystem_changes"), artifact("installed_files"), artifact("installed_directories")}},
    "TC-RG-001": {"modes": {"full"}, "capabilities": {"installed_state"}, "files": {artifact("registry_changes"), artifact("install_changes"), artifact("persistence_review")}},
    "TC-SV-001": {"modes": {"full"}, "capabilities": {"services_added"}, "files": {artifact("services_review"), artifact("permissions_review")}},
    "TC-TS-001": {"modes": {"full"}, "capabilities": {"tasks_added"}, "files": {artifact("scheduled_tasks_review"), artifact("permissions_review")}},
    "TC-PB-001": {"modes": {"full"}, "capabilities": {"privilege_points"}, "files": {artifact("privilege_boundary_review"), artifact("permissions_review")}},
    "TC-DR-001": {"modes": {"full"}, "capabilities": {"drivers_added"}, "files": {artifact("new_drivers")}},
    "TC-PM-001": {"modes": {"full"}, "capabilities": {"procmon"}, "files": {artifact("procmon_summary")}},
    "TC-DL-001": {"modes": {"full"}, "capabilities": {"procmon"}, "files": {artifact("dll_search_review"), artifact("procmon_missing_dlls")}},
    "TC-AR-001": {"modes": {"full"}, "capabilities": {"procmon"}, "files": {artifact("runtime_managed_context"), artifact("advanced_runtime_review")}},
    "TC-AR-002": {"modes": {"full"}, "capabilities": {"procmon"}, "files": {artifact("runtime_child_processes")}},
    "TC-AR-003": {"modes": {"full"}, "capabilities": {"procmon"}, "files": {artifact("runtime_module_boundary")}},
    "TC-AR-004": {"modes": {"full"}, "capabilities": {"procmon"}, "files": {artifact("advanced_instrumentation_plan")}},
    "TC-MC-001": {"modes": {"static", "full"}, "files": {artifact("binary_security_review")}},
    "TC-NW-001": {"modes": {"full"}, "capabilities": {"surface_review"}, "files": {artifact("network_surface_review"), artifact("target_firewall_rules")}},
    "TC-NW-002": {"modes": {"full"}, "capabilities": {"localhost_candidates"}, "files": {artifact("localhost_service_candidates")}},
    "TC-IP-001": {"modes": {"full"}, "capabilities": {"surface_review"}, "files": {artifact("ipc_review")}},
    "TC-IP-002": {"modes": {"full"}, "capabilities": {"surface_review"}, "files": {artifact("named_pipe_permissions"), artifact("ipc_review")}},
    "TC-UP-001": {"modes": {"full"}, "capabilities": {"installed_state"}, "files": {artifact("updater_security_review"), artifact("updater_components")}},
    "TC-UP-002": {"modes": {"full"}, "capabilities": {"installed_state"}, "files": {artifact("updater_signature_review"), artifact("updater_staging_review")}},
    "TC-UP-003": {"modes": {"full"}, "capabilities": {"installed_state"}, "files": {artifact("updater_staging_review"), artifact("updater_permissions")}},
    "TC-UP-004": {"modes": {"full"}, "capabilities": {"procmon"}, "files": {artifact("updater_endpoint_candidates")}},
    "TC-UP-005": {"modes": {"full"}, "capabilities": {"installed_state"}, "files": {artifact("updater_security_review")}},
}


def case_exclusion_reasons(case, assessment_dir, mode, installer_suffix, capabilities):
    """Single authoritative explanation of the case applicability policy.

    Return only names/coverage flags, never file contents or local profile paths.
    """
    policy = TEST_CASE_POLICY.get(case["id"], {"modes": {"static", "full"}})
    reasons = []
    if mode not in policy.get("modes", {"static", "full"}):
        reasons.append('Requires assessment mode: ' + ', '.join(sorted(policy['modes'])))
    if policy.get('installer_exts') and installer_suffix not in policy['installer_exts']:
        reasons.append('Requires installer type: ' + ', '.join(sorted(policy['installer_exts'])))
    missing_caps = sorted(c for c in policy.get('capabilities', set()) if not capabilities.get(c))
    if missing_caps:
        reasons.append('Evidence capabilities unavailable: ' + ', '.join(missing_caps))
    if case['id'] == 'TC-AR-001' and not _has_managed_runtime_evidence(assessment_dir):
        reasons.append('No managed-runtime target evidence recorded')
    missing_reports = sorted(name for name in policy.get('files', set())
                             if not artifact_path(assessment_dir, name).is_file())
    if missing_reports:
        reasons.append('Supporting reports unavailable: ' + ', '.join(missing_reports))
    return reasons


def _case_applicable(case, assessment_dir, mode, installer_suffix, capabilities):
    return not case_exclusion_reasons(case, assessment_dir, mode, installer_suffix, capabilities)


def _has_managed_runtime_evidence(assessment_dir: Path) -> bool:
    report = artifact_path(assessment_dir, "runtime_managed_context.txt")
    if not report.is_file():
        return False
    text = report.read_text(encoding="utf-8", errors="replace")
    summary = re.search(r"^Managed candidates/processes\s*:\s*(\d+)\s*$", text, flags=re.M | re.I)
    if summary:
        return int(summary.group(1)) > 0
    # Backward-compatible fallback for older assessment renderers.
    return bool(re.search(r"^(?:Static \.NET Candidate|Managed Runtime Seen)\s*:\s*YES\s*$", text,
                          flags=re.M | re.I))


def _applicable_case(case: dict, assessment_dir: Path) -> dict:
    """Adjust evidence-dependent instructions without mutating catalog cases."""
    if case["id"] != "TC-AR-001" or artifact_path(assessment_dir, "dotnet_source_review.txt").is_file():
        return case
    adapted = dict(case)
    adapted["title"] = "Managed Runtime Classification (Source Unavailable)"
    adapted["procedure"] = ("Correlate observed managed-runtime modules and target PIDs with runtime process, "
                            "module and command-execution evidence; no decompiled source is available.")
    replacements = {
        "Review dotnet_source_review.txt":
            "No dotnet_source_review.txt was generated. Correlate CLR module evidence with the observed "
            "target process and use approved runtime instrumentation; do not assume decompiled source exists.",
        "Correlate relevant source locations":
            "Correlate managed-runtime module evidence with procmon_process_activity.txt, "
            "procmon_loaded_images.txt, runtime_module_boundary.txt and runtime_child_processes.txt.",
        "Use advanced_instrumentation_plan.txt":
            "Review advanced_instrumentation_plan.txt for optional, authorized runtime-only observation "
            "of a verified managed target PID; no decompiled source is available.",
    }
    adapted["how"] = [next((replacement for prefix, replacement in replacements.items()
                            if step.startswith(prefix)), step) for step in case["how"]]
    return adapted




def generate_test_cases(assessment_dir: Path, mode="static", installer_suffix="", capabilities=None):
    cases = TEST_CASES

    capabilities = capabilities or {}
    installer_suffix = str(installer_suffix or "").lower()

    applicable_cases = [_applicable_case(case, assessment_dir) for case in cases
                        if _case_applicable(case, assessment_dir, mode, installer_suffix, capabilities)]
    excluded = [(case, case_exclusion_reasons(case, assessment_dir, mode, installer_suffix, capabilities))
                for case in cases]
    excluded = [(case, reasons) for case, reasons in excluded if reasons]
    excluded_count = len(excluded)

    width = 96
    lines = [
        "WCA - TEST CASES",
        "=" * width,
        "",
        f"Assessment Mode   : {mode}",
        f"Applicable Cases  : {len(applicable_cases)}",
        f"Excluded Cases    : {excluded_count}",
        "",
        "Applicability:",
        "  This checklist is generated from the assessment mode and evidence actually produced.",
        "  Specific exclusions and the current evidence limitations are listed immediately below.",
        "  Managed-runtime tests require managed target evidence; if decompiled source is absent,",
        "  the procedure uses runtime classification and instrumentation instead.",
        "",
        "Tracking Instructions:",
        "  This generated checklist is a reference, not authoritative review state.",
        "  Complete applicable manual and linked WCR activities in GUI > Tester Workspace > Testing Queue.",
        "  A WCR disposition does not automatically complete the associated manual test requirements.",
        "  Do not edit generated evidence to change its validation status; doing so fails integrity verification.",
        "",
        "Assessment-specific controlled PoC guidance:",
        "  See evidence_guide.txt for the exact WCR candidate commands and controlled demonstration procedures.",
        "  attack_surface_test_plan.txt is optional methodology reference, not a second checklist. It includes tests",
        "  that may need tester-directed validation; use one Testing Queue to track applicable work.",
        "",
    ]

    # Explicit reasons are informational only; they do not create another checklist.
    lines += ['EXCLUDED TEST CASES — APPLICABILITY EXPLANATIONS', '-' * width,
              'Excluded cases are not failed tests. Availability follows collected evidence and selected scope.', '']
    for case, reasons in excluded:
        lines.append(f"  {case['id']} — {case['title']}")
        for reason in reasons:
            lines.append('    - ' + reason)
    lines += ['', 'APPLICABLE MANUAL TEST CASES', '']
    for case in applicable_cases:
        lines += [
            "=" * width,
            f"[ ] {case['id']} - {case['title']}",
            "=" * width,
            f"[ ] Completed    [ ] N/A",
            f"Risk: {case['risk']}",
            "",
            "Procedure:",
            f"  {case['procedure']}",
            "",
            "How to Perform:",
        ]
        for idx, step in enumerate(case["how"], 1):
            lines.append(f"  {idx}. {step}")
        lines += [
            "",
            "Expected Secure Behavior:",
            f"  {case['expected']}",
            "",
            "What to Look For:",
            f"  {case.get('look_for', case['procedure'])}",
            "",
            "Potentially Vulnerable Behavior:",
            f"  {case.get('vulnerable', 'A reproducible deviation from expected security behavior affecting a real trust boundary.')}",
            "",
            "When NOT to Report:",
            f"  {case.get('not_report', 'Do not report an indicator without verifying applicability, unauthorized behavior and meaningful security impact.')}",
            "",
            "Evidence / Tester Notes:",
            "  - Screenshot(s):",
            "  - Command/tool output:",
            "  - Notes:",
            "",
        ]

    (artifact_path(assessment_dir, "test_cases.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )
    return {"status": "PASS", "details": f"{len(applicable_cases)} applicable test case(s) generated; {excluded_count} excluded"}
