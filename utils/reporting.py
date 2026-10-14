from collections import Counter
from pathlib import Path
import json

from utils.artifacts import module_artifacts
from utils.consolidated_report import generate_consolidated_report
from utils.artifacts import generated_files
from utils.privacy import sanitize_report_text, sanitize_report_files
from utils.assessment_layout import artifact_path
from utils.assessment_state import _atomic_json
from utils.assessment_integrity import _atomic_text


MODULE_GROUPS = {
    "Static Analysis": [
        "Target Information", "Installer Information", "Installer Technology", "Application / Package Scope", "Digital Signature Review",
        "Installer Extraction", "MSI Analysis", "PE Security Review",
        ".NET Detection / Source Review", "Configuration Review", "Secrets Review",
        "Electron Security Review", "Component Lifecycle Review", "Application / Technology Profile",
    ],
    "System State / Privilege": [
        "Baseline Snapshot", "Post-Activity Snapshot", "System Change Analysis",
        "Services Review", "Scheduled Tasks", "Permissions Review", "Local Storage Review", "Persistence Review",
        "Driver Review", "Privilege Boundary Review", "Attack Surface Correlations",
    ],
    "Updater / Maintenance": [
        "Updater Review (Static)", "Updater Review (System State)", "Updater Security Correlation",
    ],
    "Runtime": [
        "Runtime Target Discovery", "Guided Runtime Observation", "Procmon Runtime Capture", "Procmon Analysis",
        "DLL Search Review", "Runtime Process Review",
        "Advanced .NET / Native Runtime Review",
    ],
    "Network / IPC": [
        "Network Surface Review", "IPC / Named Pipe Review",
    ],
    "Reporting": ["Test Case Generation"],
}

CRITICAL_MODULES = {
    "Installer Information", "Installer Extraction", "Baseline Snapshot",
    "Post-Activity Snapshot", "System Change Analysis", "MSI Analysis",
}

OPTIONAL_MODULES = {
    "Procmon Runtime Capture", "Procmon Analysis", "DLL Search Review",
    "Runtime Process Review", "Advanced .NET / Native Runtime Review",
    "Network Surface Review", "IPC / Named Pipe Review", "Local Storage Review",
}


class AssessmentReporter:
    def __init__(self, assessment_dir, assessment_name, installer, mode, version, state_tracker=None, target_type="installable"):
        self.assessment_dir = Path(assessment_dir)
        self.assessment_name = assessment_name
        self.installer = Path(installer)
        self.mode = mode
        self.version = version
        self.target_type = str(target_type or "installable").lower()
        self.status = {}
        self.findings = []
        self.state_tracker = state_tracker

    def set_status(self, module, status, details="", coverage_gap=False):
        self.status[module] = {
            "status": status,
            "details": sanitize_report_text(details, self.installer),
            "coverage_gap": bool(coverage_gap),
        }
        if self.state_tracker is not None:
            self.state_tracker.module_status(module, self.status[module])

    def add_finding(
        self,
        title,
        severity="Informational",
        description="",
        evidence="",
        recommendation="",
        source_module="",
        artifacts=None,
    ):
        self.findings.append({
            "title": sanitize_report_text(title, self.installer),
            "severity": severity,
            "description": sanitize_report_text(description, self.installer),
            "evidence": sanitize_report_text(evidence, self.installer),
            "recommendation": sanitize_report_text(recommendation, self.installer),
            "source_module": source_module,
            "artifacts": tuple(artifacts or ()),
        })

    def write_text(self, filename, text):
        path = artifact_path(self.assessment_dir, filename)
        _atomic_text(path, sanitize_report_text(text, self.installer))
        return path

    def write_json(self, filename, data):
        path = artifact_path(self.assessment_dir, filename)
        _atomic_json(path, data)
        return path

    def write_tool_detection(self, tools):
        width=108
        lines=[
            "WCA - TOOL DETECTION",
            "="*width,
            "",
            "Purpose:",
            "  Records external tooling detected for this assessment. Optional/recommended tools enhance",
            "  individual modules but do not necessarily prevent core analysis from running.",
            "",
            "Legend:",
            "  REQUIRED    Core dependency expected for normal framework operation.",
            "  RECOMMENDED Enhances automated analysis or provides stronger evidence.",
            "  OPTIONAL    Advanced/manual analysis capability.",
            "",
            "Usage Meaning:",
            "  INTEGRATED           Invoked directly by Windows Client Assessment.",
            "  INTEGRATED_FALLBACK  Used automatically only if the primary collection method fails.",
            "  MANUAL / MANUAL_GUIDED  Tester-operated tooling referenced by generated guidance.",
            "",
            f"{'Tool':22} {'Level':11} {'Usage':20} {'Status':9} {'Detection Source':16} Path / Note",
            "-"*width,
        ]
        for name,info in tools.items():
            state="FOUND" if info.get("found") else "MISSING"
            source=info.get("source") or "N/A"
            detail=info.get("path") or info.get("note") or ""
            lines.append(f"{name:22} {info.get('level',''):11} {info.get('usage',''):20} {state:9} {source:16} {sanitize_report_text(detail, self.installer)}")
        self.write_text("tool_detection.txt", "\n".join(lines).rstrip() + "\n")

    def finalize(self, *, persist_render_state=True, sanitize_primary=True):
        # Collectors write many TXT reports directly; apply one consistent
        # report-only privacy boundary before creating the HTML evidence index.
        if sanitize_primary:
            sanitize_report_files(self.assessment_dir, generated_files(), self.installer)
        width=112
        review_state = None
        if (self.assessment_dir / 'working').is_dir() and self.version >= '1.5.0':
            from utils.guided_review import sync_review, render_review_reports
            review_state = sync_review(self.assessment_dir, self.findings)
            render_review_reports(self.assessment_dir, review_state)
        identified_findings = []
        for idx, finding in enumerate(self.findings, 1):
            identified = dict(finding)
            identified["report_id"] = f"ARP-{idx:03d}"
            if review_state:
                # Preserve legacy ARP labels for existing report readers, but
                # link them to stable per-object reviewer IDs. An aggregate
                # listener/pipe finding points to all independent POI records.
                related = [item for item in review_state['items'].values()
                           if item['source_module'] == finding.get('source_module')
                           and (item.get('source_record') or item['title'] == finding.get('title'))]
                identified['review_ids'] = [item['id'] for item in related]
                identified['review_statuses'] = {item['id']: item['status'] for item in related}
            identified_findings.append(identified)

        status_lines=[
            "WCA - MODULE STATUS",
            "="*width,
            "",
            "Status Meaning:",
            "  PASS    Module completed without an automated review condition.",
            "  WARN    Module completed but produced one or more items requiring manual tester review.",
            "  SKIPPED Module was not selected or prerequisites/evidence were unavailable.",
            "  NOT APPLICABLE Full-mode prerequisites passed; no relevant component was present.",
            "  ERROR   Module did not complete successfully.",
            "",
            "Important: WARN does not mean a vulnerability was confirmed.",
        ]

        grouped=set()
        for group,names in MODULE_GROUPS.items():
            present=[name for name in names if name in self.status]
            if not present: continue
            status_lines += ["",group.upper(),"-"*width]
            for module in present:
                info=self.status[module]; grouped.add(module)
                line=f"{module:34} {info['status']:8}"
                if info.get("details"): line+=f" {info['details']}"
                status_lines.append(line)

        remaining=[m for m in self.status if m not in grouped]
        if remaining:
            status_lines += ["","OTHER","-"*width]
            for module in remaining:
                info=self.status[module]
                line=f"{module:34} {info['status']:8}"
                if info.get("details"): line+=f" {info['details']}"
                status_lines.append(line)
        self.write_text("module_status.txt", "\n".join(status_lines).rstrip() + "\n")

        counts=Counter(f.get("severity","Informational") for f in identified_findings)
        review_tally = Counter(record['status'] for record in review_state['items'].values()) if review_state else Counter()
        summary=[
            "WCA - AUTOMATED REVIEW SUMMARY",
            "="*width,
            "",
            "Important:",
            "  Windows Client Assessment does not automatically confirm vulnerabilities. Items below are automated",
            "  review points/observations that require manual validation before inclusion in a penetration-test report.",
            "",
            "Confirmed findings (automatic) : 0",
            f"Automated review points       : {len(identified_findings)}",
            f"Distinct guided review items  : {len(review_state['items']) if review_state else 'Not available'}",
            f"Pending tester reviews        : {review_tally['PENDING'] if review_state else 'Not available'}",
            f"Validated by tester           : {review_tally['VALIDATED'] if review_state else 'Not available'}",
            f"Not applicable                : {review_tally['NOT APPLICABLE'] if review_state else 'Not available'}",
            f"Informational                 : {review_tally['INFORMATIONAL'] if review_state else 'Not available'}",
            "  VALIDATED is a tester-selected review status, not independent proof of exploitability.",
            "  Tester notes are optional; evidence may be maintained in the separate penetration test report.",
            "",
            "REVIEW POINTS BY SEVERITY LABEL",
            "-"*width,
        ]
        for sev in ["Critical","High","Medium","Low","Informational"]:
            summary.append(f"{sev:18} {counts.get(sev,0)}")
        self.write_text("findings_summary.txt", "\n".join(summary).rstrip() + "\n")

        out=[
            "WCA - AUTOMATED REVIEW POINTS",
            "="*width,
            "",
            "Purpose:",
            "  Consolidates automated observations generated by individual modules.",
            "",
            "Reporting Rule:",
            "  Do not copy an item directly into a client report. Validate the evidence, exploitability,",
            "  authorization/privilege boundary, and concrete security impact first.",
            "",
        ]
        if not identified_findings:
            out.append("No automated review points were generated.")
        for finding in identified_findings:
            source_module = finding.get("source_module") or "Unspecified module"
            evidence_files = list(finding.get("artifacts") or ())
            if not evidence_files:
                evidence_files = [
                    filename
                    for filename in module_artifacts(source_module)
                    if artifact_path(self.assessment_dir, filename).is_file()
                ]
            out += [
                "="*width,
                f"[{finding['report_id']}] {finding['title']}",
                "="*width,
                f"Severity Label : {finding.get('severity','Informational')}",
                "Classification : Automated Review Point (NOT CONFIRMED; see tester_review.txt for dispositions)",
                f"Source Module  : {source_module}",
                f"Description    : {finding.get('description','')}",
                f"Evidence       : {finding.get('evidence','')}",
                f"Evidence Files : {', '.join(evidence_files) if evidence_files else 'No module-specific evidence file generated'}",
                f"Next Step      : {finding.get('recommendation','')}",
                f"Guided Review  : {', '.join(finding.get('review_ids', [])) or 'See tester_review.txt'}",
                f"Reviewer Status: {', '.join(str(x) for x in finding.get('review_statuses', {}).values()) or 'PENDING'}",
                "",
            ]
        self.write_text("findings.txt", "\n".join(out).rstrip() + "\n")

        errors = [name for name, info in self.status.items() if info.get("status") == "ERROR"]
        critical_warnings = [
            name for name, info in self.status.items()
            if name in CRITICAL_MODULES and info.get("status") == "WARN"
        ]
        optional_skips = [
            name for name, info in self.status.items()
            if name in OPTIONAL_MODULES and info.get("status") == "SKIPPED"
        ]
        optional_gaps = [
            name for name, info in self.status.items()
            if info.get("coverage_gap")
        ]
        if errors or critical_warnings:
            coverage = "INCOMPLETE"
        elif optional_skips or optional_gaps:
            coverage = "COMPLETE_WITH_OPTIONAL_GAPS"
        else:
            coverage = "COMPLETE"
        coverage_lines = [
            "WCA - COVERAGE SUMMARY",
            "=" * width,
            "",
            f"Coverage grade : {coverage}",
            f"Mode           : {self.mode}",
            "",
            "Critical errors/warnings:",
        ]
        coverage_lines += [f"  - {name}" for name in errors + critical_warnings] or ["  None"]
        coverage_lines += ["", "Optional phases skipped:"]
        coverage_lines += [f"  - {name}" for name in optional_skips] or ["  None"]
        not_applicable = [name for name, info in self.status.items() if info.get('status') == 'NOT APPLICABLE']
        coverage_lines += ['', 'Not applicable modules (not failed or untested prerequisites):']
        coverage_lines += [f'  - {name}' for name in not_applicable] or ['  None']
        coverage_lines += ["", "Optional evidence gaps:"]
        coverage_lines += [f"  - {name}" for name in optional_gaps] or ["  None"]
        coverage_lines += [
            "",
            "Interpretation:",
            "  INCOMPLETE means one or more required collectors or analyses did not produce dependable evidence.",
            "  COMPLETE_WITH_OPTIONAL_GAPS means core analysis completed, but optional evidence was NOT COLLECTED or unavailable.",
            "  COMPLETE means all selected and required phases completed without a critical warning or error.",
            "  A module that reports COLLECTED / NO OBSERVATION successfully ran and found no target-scoped condition;",
            "  that is different from SKIPPED / NOT COLLECTED or COLLECTION UNAVAILABLE.",
        ]
        self.write_text("coverage_summary.txt", "\n".join(coverage_lines).rstrip() + "\n")
        generate_consolidated_report(
            assessment_dir=self.assessment_dir,
            assessment_name=self.assessment_name,
            installer=self.installer,
            mode=self.mode,
            version=self.version,
            coverage=coverage,
            status=self.status,
            findings=identified_findings,
            module_groups=MODULE_GROUPS,
            target_type=self.target_type,
        )
        if persist_render_state and (self.assessment_dir / "working").is_dir():
            # Internal, verified report-rendering recipe. Its distinct operational
            # purpose is recovering summaries without re-running collectors or
            # fabricating lost source evidence; not a duplicate tester report.
            _atomic_json(self.assessment_dir / "working" / "report_render_state.json", {
                "schema_version": 1,
                "assessment_name": self.assessment_name,
                "installer_filename": self.installer.name,
                "target_filename": self.installer.name,
                "target_type": self.target_type,
                "mode": self.mode,
                "framework_version": self.version,
                "modules": self.status,
                "findings": [dict(item) for item in self.findings],
                "coverage": coverage,
            })
        return coverage
