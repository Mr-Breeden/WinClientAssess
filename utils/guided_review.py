"""Persistent, evidence-linked manual review workflow.

Automated observations are candidates, never confirmed vulnerabilities. Only
this state file is authoritative for tester dispositions; TXT/HTML are derived.
"""
from __future__ import annotations

import hashlib
import json
import re
import textwrap
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils.assessment_integrity import _atomic_text
from utils.assessment_state import _atomic_json
from utils.assessment_layout import artifact_path
from utils.artifacts import module_artifacts

REVIEW_FILE = 'working/tester_review_state.json'
SCHEMA = 1
DISPOSITIONS = ('PENDING', 'VALIDATED', 'NOT APPLICABLE', 'INFORMATIONAL')
POI_SOURCES = {
    'Network Surface Review': 'network_surface_review.txt',
    'IPC / Named Pipe Review': 'ipc_review.txt',
    'DLL Search Review': 'dll_search_review.txt',
    'Privilege Boundary Review': 'privilege_boundary_review.txt',
    'Advanced .NET / Native Runtime Review': 'advanced_runtime_review.txt',
    'Updater Security Correlation': 'updater_security_review.txt',
    'Local Storage Review': 'local_storage_review.txt',
}
CATEGORY_TESTS = {
    'Digital Signature Review': ['TC-SG-001'], 'MSI Analysis': ['TC-MS-001'],
    'PE Security Review': ['TC-PE-001'], 'Configuration Review': ['TC-CF-001'],
    'Secrets Review': ['TC-CF-001'], 'Services Review': ['TC-SV-001'],
    'Scheduled Tasks': ['TC-TS-001'], 'Permissions Review': ['TC-PB-001'],
    'Privilege Boundary Review': ['TC-PB-001'], 'DLL Search Review': ['TC-DL-001'],
    'Network Surface Review': ['TC-NW-001'], 'IPC / Named Pipe Review': ['TC-IP-001', 'TC-IP-002'],
    'Advanced .NET / Native Runtime Review': ['TC-AR-001', 'TC-AR-002'],
    'Updater Security Correlation': ['TC-UP-001', 'TC-UP-002'],
    'Local Storage Review': ['TC-LS-001'],
    'Attack Surface Correlations': [], 'Guided Runtime Observation': [],
}


def _applicable_test_links(root: Path, module: str) -> list[str]:
    """Only link checklist cases actually generated for this assessment.

    An existing legacy assessment might not have a checklist at all; retain
    historic mapping in that case, without rewriting old review state.
    """
    candidates = CATEGORY_TESTS.get(module, [])
    report = artifact_path(root, 'test_cases.txt')
    if not report.is_file():
        return list(candidates)
    text = report.read_text(encoding='utf8', errors='replace')
    available = set(re.findall(r'^\[ \] (TC-[A-Z]+-\d+)\s+-', text, flags=re.M))
    return [case_id for case_id in candidates if case_id in available]
GUIDANCE = {
    'Network Surface Review': (
        'Confirm owning process and intended bind scope. On the assessment VM inspect '
        'Get-NetTCPConnection -State Listen and Get-NetFirewallRule; test the specific endpoint '
        'from an authorized low-privilege/network context.',
        'Unexpected reachable functionality or authentication/authorization bypass at this endpoint.',
        'Expected restriction to intended interfaces and authenticated/authorized callers.',
        'A wildcard listener or firewall Allow rule alone does not establish unauthorized access.'),
    'IPC / Named Pipe Review': (
        'Verify the exact pipe owner and ACL (AccessChk and the named-pipe handle inventory or targeted pipe inspection). '
        'From a separate standard-user account test only harmless permitted operations; inspect server-side authorization.',
        'Broad effective write access paired with an unauthorized action or privileged trust-boundary crossing.',
        'Unauthorized clients or methods are rejected, regardless of broad transport ACLs.',
        'Everyone write permission alone is not proof of a privileged vulnerability.'),
    'DLL Search Review': (
        'Check the exact failed library load in Procmon, inspect the searched directory with '
        'icacls on the observed directory and AccessChk, and confirm whether the application actually loads a controlled test DLL.',
        'A real load from a lower-privileged writable directory into a more-trusted process.',
        'Library resolution uses protected or authenticated locations.',
        'A NAME NOT FOUND event or broad ACE alone is insufficient; validate effective access and execution context.'),
    'Services Review': (
        'Inspect the service using Get-CimInstance Win32_Service and sc.exe qc with the observed service name; '
        'check binary and each intermediate parent directory with icacls.',
        'Untrusted file creation/modification demonstrably changes a privileged service execution path.',
        'Service executable and path components are protected from lower-privileged modifications.',
        'Unquoted paths with protected intermediate directories may not be exploitable.'),
    'Privilege Boundary Review': (
        'Identify the service/task/user boundary, inspect the exact executable and parent ACLs '
        'with icacls, and test only a harmless proof of control as an authorized standard user.',
        'A lower-privileged principal can influence a protected execution or trusted-data operation.',
        'Privileged components execute only from trusted paths and validate untrusted inputs.',
        'An apparent broad permission is not sufficient without effective access and impact.'),
    'Permissions Review': (
        'Use icacls on the affected path and AccessChk from the standard-user context; '
        'identify what executable, service, DLL or configuration consumes the path.',
        'A standard user can change a security-sensitive object used by a more-trusted component.',
        'Effective write permissions are limited to intended trusted principals.',
        'Writable user data or unrelated files should not be reported as a privilege boundary failure.'),
    'Digital Signature Review': (
        'Compare target origin and expected signing policy; run Get-AuthenticodeSignature '
        '-LiteralPath on the selected package or primary executable and inspect signer/timestamp if supplied.',
        'Invalid or unexpected signature undermines an applicable trust/provenance requirement.',
        'Target provenance matches the expected trusted release; signing is enforced where required.',
        'Unsigned software alone is not necessarily a vulnerability.'),
    'MSI Analysis': (
        'Inspect CustomAction and InstallExecuteSequence in msi_analysis.txt; map deferred actions '
        'to their paths/arguments and the execution context. Check path ACLs before drawing conclusions.',
        'An untrusted input can influence an installer action executed with higher privilege.',
        'Elevated custom actions use protected files and validated arguments.',
        'The presence of a custom action does not establish unsafe execution.'),
    'PE Security Review': (
        'Identify affected native binaries in binary_security_review.txt and validate the PE '
        'mitigation flags with an independent PE-inspection tool.',
        'Missing exploit mitigations on a relevant supported binary, with context for actual impact.',
        'Supported binaries use the intended platform hardening configuration.',
        'Missing mitigation metadata alone does not prove an exploitable memory-corruption bug.'),
    'Secrets Review': (
        'Inspect only the indicated text line or PE printable-string offset locally without copying secret values. Verify whether the string is real, active/reusable, reachable, and accessible to an unintended principal.',
        'An active security-sensitive credential is accessible outside its intended trust boundary.',
        'No active secrets in untrusted distribution or broadly accessible files.',
        'Test data, placeholders or properly scoped credentials may not be reportable.'),
    'Advanced .NET / Native Runtime Review': (
        'Correlate the individual child process/module event with Procmon; identify '
        'command-line input, execution identity, integrity level and whether a low-privileged actor controls it.',
        'Untrusted input alters a higher-trust command or module load.',
        'Child process and module paths are trusted; input is validated.',
        'Expected child-process launches without input control are not a vulnerability.'),
    'Attack Surface Correlations': (
        'Inspect the exact recorded process/path or CLSID from the source event, verify effective lower-trust control, '
        'and demonstrate the actual operation using the relevant controlled proof resource.',
        'Observed unauthorized execution or protected state change across a demonstrated privilege/trust boundary.',
        'Execution resolves only trusted objects, the intended registration is protected, and privileged actions reject untrusted input.',
        'A failed executable lookup, COM/IFEO registration write or newly created junction alone is not an exploit.'),
    'Guided Runtime Observation': (
        'Reproduce the exact runtime surface during the same approved workflow and correlate it with the guided runtime observation report. Verify execution identity, effective access and security impact.',
        'A newly observed runtime surface permits reproducible unauthorized behavior or a demonstrated trust-boundary crossing.',
        'Observed runtime behavior remains restricted to intended callers, protected paths and authorized operations.',
        'A new process, listener, pipe, file write or registry write is not a vulnerability by itself.'),
    '.NET Detection / Source Review': (
        'Review the first-party source paths and line numbers in dotnet_source_review.txt for this exact category; trace inputs into the operation and validate trust boundaries.',
        'Attacker-controlled input reaches an unsafe operation or permits access outside an authorized boundary.',
        'The component enforces authorization and validates input at sensitive operations.',
        'A source-code pattern match alone is not proof of vulnerability.'),
    'Local Storage Review': (
        'Open the exact target-associated storage location and indicated first matching line/schema locally. '
        'Do not copy secret values into WCA. Verify effective read access, whether the value is an active security-sensitive secret, '
        'and whether the application protects it at rest and across users.',
        'A real security-sensitive secret or trusted application state is readable or modifiable outside its intended trust boundary.',
        'Sensitive local state is protected by appropriate ACLs/credential protection and is not exposed to unrelated users.',
        'A keyword match, table/column name, or target-associated file alone is not a reportable information disclosure.'),
    'Updater Security Correlation': (
        'Review updater executable, task/service context, staging directory ACLs, package '
        'signatures and endpoint transport. Exercise an authorized harmless update check when supported.',
        'A lower-privileged or network actor can alter a package/configuration before privileged use.',
        'Updater validates packages, uses protected staging and enforces authorized transport.',
        'An updater component or an unsigned file alone is not proof of an exploitable weakness.'),
}
LOOK_FOR = {
    'Network Surface Review': 'Owning executable, protocol/port, listen/bind scope, correlated firewall rule and actual authentication behavior.',
    'IPC / Named Pipe Review': 'Exact pipe name, owning service identity, effective standard-user connect/write rights and server-side method authorization.',
    'DLL Search Review': 'Failed library resolution at this directory, verified effective create-file rights and an actual subsequent module load.',
    'Services Review': 'Service command-line parsing, intermediate paths containing spaces, account privilege and each path component ACL.',
    'Privilege Boundary Review': 'A distinct low-to-high privilege trust boundary, effective write/input control and a reproducible protected action.',
    'Permissions Review': 'ACL principal/rights (including deny/allow inheritance), owning process context and whether the path is executable or trusted configuration.',
    'Digital Signature Review': 'Publisher certificate chain, signing requirement, release hash and whether unsigned/invalid status is expected.',
    'MSI Analysis': 'Custom-action type/source/target, execution sequence, deferred/impersonation context and caller-writable dependencies.',
    'PE Security Review': 'Which specific binary/architecture lacks mitigations and whether the hardened build supports the required flags.',
    'Secrets Review': 'An active credential or token, its access boundary, rotation status and verified location/first matching line only (never value).',
    'Advanced .NET / Native Runtime Review': 'Child command/module path, source of command arguments, integrity level and user control over its inputs.',
    'Attack Surface Correlations': 'Exact target process, full executable or registry path, collection source, ACL and independently reproduced effect.',
    'Guided Runtime Observation': 'Exact process/endpoint/pipe, workflow that produced it, execution identity, effective access and whether a lower-trust actor can influence the operation.',
    'Local Storage Review': 'Exact target-associated path, first matching line/indicator or SQLite schema name, effective ACL and whether an active secret/trusted state is actually exposed.',
    'Updater Security Correlation': 'Updater run-as identity, protected staging path, package signature enforcement and update endpoint trust.',
}

# The contextual command generator only quotes validated fields from sanitized
# persisted evidence. When a target is ambiguous, provide a discovery command
# instead of guessing or injecting a placeholder into a shell.
def validation_commands(item: dict, root: Path | None = None, *, console_paths: bool = False, tools: dict | None = None) -> tuple[str, ...]:
    """Assessment-specific, CWD-independent commands for saved/live guidance.

    Only interactive terminal commands may show the actual assessment folder.
    Stored HTML/TXT uses standalone file-selection prompts to protect privacy.
    """
    from utils.contextual_checks import checks
    return checks(item, root, console_paths=console_paths, tools=tools)



DEFAULT_GUIDANCE = (
    'Open the linked module evidence and identify the exact affected component; validate '
    'the stated condition with an independent Windows-native check appropriate to the component.',
    'Reproducible unauthorized access or meaningful security impact at the observed component.',
    'The application enforces its documented authorization and trust boundary.',
    'Do not report an automated indicator without applicability, reproducible impact, and supporting evidence.',
)


def _digest(value: str, size: int = 14) -> str:
    return hashlib.sha256(value.encode('utf-8')).hexdigest()[:size]


def _clean(value: Any) -> str:
    return re.sub(r'\s+', ' ', str(value or '')).strip()


def _canonical(value: Any) -> str:
    value = _clean(value).lower().replace('/', '\\')
    value = re.sub(r'\(pid\s*\d+\)', '', value, flags=re.I)
    value = re.sub(r'\bpid\s*:\s*\d+', 'pid:', value, flags=re.I)
    return value


def _poi_candidates(root: Path, *, preserve_legacy=False) -> list[dict]:
    """One review condition per distinct observed behavior, not per repeat event.

    Keep all contributing POI labels for traceability. Separate the same
    component if evidence details differ; event counts never affect the
    candidate fingerprint or a previously saved decision.
    """
    candidates = []
    pattern = re.compile(r'^\[(POI-[A-Z]+-\d+)\](?:\s*(.*))?$', re.M)
    for module, filename in POI_SOURCES.items():
        path = artifact_path(root, filename)
        if not path.is_file():
            continue
        content = path.read_text(encoding='utf-8', errors='replace')
        matches = list(pattern.finditer(content))
        seen = {}
        for idx, match in enumerate(matches):
            raw = content[match.end():matches[idx + 1].start() if idx + 1 < len(matches) else len(content)]
            raw = re.split(r'\n[A-Z][A-Z /()_-]{9,}\n[-=]{12,}', raw, maxsplit=1)[0]
            detail = raw.strip('=\r\n ').strip()
            title = _clean(match.group(2)) or _clean(next(
                (line.partition(':')[2].strip() for line in detail.splitlines()
                 if line.strip().startswith('Component:')), match.group(1)))
            evidence = (title + '\n' + detail)[:12000]
            observed_key = (module, _canonical(title), _canonical(detail))
            if observed_key in seen and not preserve_legacy:
                existing = seen[observed_key]
                existing['source_records'].append(match.group(1))
                existing['occurrence_count'] += 1
                continue
            base_id = f'{module}|poi|{_canonical(title)}'
            # Different details for the same title are independent conditions.
            # The first group retains the v1.5.0 base identity.
            different_detail = any(key[0] == module and key[1] == _canonical(title)
                                   for key in seen)
            identity = (base_id + ('|' + match.group(1) if different_detail else '')
                        if preserve_legacy else
                        base_id + ('|variant-' + _digest(_canonical(detail), 12) if different_detail else ''))
            candidate = {
                'identity': identity, 'title': title, 'severity': 'Informational',
                'source_module': module, 'component': title, 'evidence': evidence,
                'description': 'Individual runtime/system-state point of interest requiring validation.',
                'recommendation': GUIDANCE.get(module, DEFAULT_GUIDANCE)[0],
                'artifacts': [filename], 'source_record': match.group(1),
                'source_records': [match.group(1)], 'occurrence_count': 1,
                'test_cases': _applicable_test_links(root, module),
            }
            seen[observed_key] = candidate
            candidates.append(candidate)
    return candidates


def _finding_candidates(root: Path, findings: list[dict], poi_modules: set[str]) -> list[dict]:
    result = []
    same_identity = defaultdict(int)
    for finding in findings:
        source = str(finding.get('source_module') or 'Unspecified module')
        if source in poi_modules:
            # The aggregated observation remains in findings.txt/HTML; one POI
            # per independent endpoint/pipe/path is the actual review unit.
            continue
        title = str(finding.get('title') or 'Automated review point')
        # Retain structured field boundaries for source-backed correlation
        # candidates. Normalizing every newline to a space loses Category,
        # Process and exact Path, silently merging separate search locations.
        evidence = (str(finding.get('evidence') or '').strip()
                    if source == 'Attack Surface Correlations' else _clean(finding.get('evidence')))
        # Aggregate observation wording/counts can change between captures:
        # use module+title for stable identity unless the text explicitly names
        # ONE affected object (service path, pipe, or listener).
        component = title
        if re.match(r'^[^:]{1,100}:\s*[A-Za-z]:[\\/]', evidence):
            component = evidence.partition(': ')[0].strip()
        elif re.fullmatch(r'[A-Za-z0-9_.-]+\s+-\s+(?:TCP|UDP)\s+[0-9a-fA-F.:]+', evidence):
            component = evidence
        elif re.fullmatch(r'\\\\\.\\pipe\\[^\s]+', evidence, flags=re.I):
            component = evidence
        identity = f'{source}|finding|{_canonical(title)}|{_canonical(component)}'
        if source == 'Attack Surface Correlations':
            # Independent lookup paths / CLSIDs must keep separate, stable WCR
            # identities even if two targets share an executable basename.
            from utils.contextual_checks import _field
            category = _field(evidence, 'Category')
            path = (_field(evidence, 'Path') or _field(evidence, 'Registry Path'))
            process = _field(evidence, 'Process')
            if path and category:
                component = path
                identity = f'{source}|finding|{_canonical(category)}|{_canonical(path)}|{_canonical(process)}'
        same_identity[identity] += 1
        if same_identity[identity] > 1:
            identity += f'|instance-{same_identity[identity]}'
        files = list(finding.get('artifacts') or ())
        if not files:
            files = [f for f in module_artifacts(source) if artifact_path(root, f).is_file() and f.endswith('.txt')]
        result.append({
            'identity': identity, 'title': title, 'severity': str(finding.get('severity') or 'Informational'),
            'source_module': source, 'component': component[:500],
            'evidence': evidence, 'description': str(finding.get('description') or ''),
            'recommendation': str(finding.get('recommendation') or ''), 'artifacts': files,
            'source_record': '', 'test_cases': _applicable_test_links(root, source),
        })
    return result


def _fingerprint(item: dict) -> str:
    # Volatile PIDs and POI row numbers are not changes of attack surface.
    evidence = re.sub(r'\bPOI-[A-Z]+-\d+\b', 'POI', _canonical(item['evidence']), flags=re.I)
    return _digest('|'.join((item['identity'], evidence, _canonical(item['description']))), 64)


def read_review(root: Path) -> dict | None:
    path = Path(root) / REVIEW_FILE
    if not path.is_file() or path.is_symlink():
        return None
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != SCHEMA or not isinstance(data.get('items'), dict):
        raise ValueError('Unsupported or malformed tester review state')
    return data


def sync_review(root: Path, findings: list[dict], *, create=True) -> dict:
    root = Path(root)
    previous = read_review(root)
    old = (previous or {}).get('items', {})
    # A completed v1.5.0 assessment can contain separate IDs for repeated
    # identical events. Retain every such ID and its decisions when re-rendering
    # existing evidence; only new v1.5.1 assessments collapse duplicates.
    # v1.5.0 disambiguated repeated titles with the provider POI ID. New
    # v1.5.1 instances use |variant-<digest> when details really differ.
    # Preserve the *original* ID strategy when reopening a v1.5.0 archive.
    preserve_legacy = any(re.search(r'\|POI-[A-Z]+-\d+$', str(rec.get('identity', '')))
                          for rec in old.values() if rec.get('source_record'))
    poi = _poi_candidates(root, preserve_legacy=preserve_legacy)
    items = _finding_candidates(root, findings, {x['source_module'] for x in poi}) + poi
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    result = {}
    for item in items:
        identity = item['identity']
        stable_id = 'WCR-' + _digest(identity).upper()
        if stable_id in result:
            # Collision, or two indistinguishable aggregate observations.
            # Never silently conflate independent candidates.
            raise ValueError(f'Duplicate review identity: {identity}')
        fingerprint = _fingerprint(item)
        prior = old.get(stable_id) or {}
        unchanged = prior.get('fingerprint') == fingerprint
        status = prior.get('status', 'PENDING') if unchanged else 'PENDING'
        result[stable_id] = {
            **item, 'id': stable_id, 'fingerprint': fingerprint, 'status': status,
            'notes': prior.get('notes', ''), 'evidence_reference': prior.get('evidence_reference', ''),
            'updated_at': prior.get('updated_at', now) if unchanged else now,
            'changed_evidence': bool(prior and not unchanged),
            'previous_status': prior.get('status', '') if prior and not unchanged else '',
        }
    retired = []
    for key, record in old.items():
        if key not in result:
            retired.append({'id': key, 'title': record.get('title',''), 'previous_status': record.get('status','')})
    data = {
        'schema_version': SCHEMA, 'updated_at': now,
        'items': result, 'retired': retired,
    }
    if create:
        _atomic_json(root / REVIEW_FILE, data)
    return data


def counts(state: dict) -> Counter:
    return Counter(record['status'] for record in state['items'].values())


def _guide(item: dict) -> tuple[str, str, str, str]:
    return GUIDANCE.get(item['source_module'], DEFAULT_GUIDANCE)


def render_review_reports(root: Path, state: dict | None = None) -> None:
    state = state or read_review(root)
    if state is None:
        return
    items = list(state['items'].values())
    stats = counts(state)
    width = 110
    lines = ['WCA - GUIDED TESTER REVIEW', '=' * width, '',
             'Automated observations are not confirmed vulnerabilities. Guided Review is the authoritative decision interface.',
             f'Progress: {len(items) - stats["PENDING"]} / {len(items)} completed | {stats["PENDING"]} pending',
             'Dispositions: ' + ' | '.join(f'{x}={stats[x]}' for x in DISPOSITIONS),
             'A VALIDATED selection alone is not proof of exploitability or a confirmed client finding.', '',
             'Edit decisions using the CLI (--review); editing this generated TXT does not change review status.',
             'Refer to applicable test_cases.txt for phase-gated baseline procedures.', '']
    guides = ['WCA - WINDOWS VALIDATION / EVIDENCE GUIDE', '=' * width,
              'Procedures are candidate-specific prompts. Verify applicability and security impact before reporting.', '']
    for item in sorted(items, key=lambda x: (x['status'] != 'PENDING', x['source_module'], x['title'], x['id'])):
        instruction, vulnerable, secure, not_report = _guide(item)
        heading = f"[{item['id']}] {item['title']}"
        shared = [heading, '-' * width, f"Status: {item['status']}", f"Module: {item['source_module']}",
                  f"Affected component: {item['component']}",
                  f"Supporting reports: {', '.join(item['artifacts']) or 'No module-specific report'}",
                  f"Observed matching events: {item.get('occurrence_count', 1)}",
                  f"Source records: {', '.join(item.get('source_records') or ([item['source_record']] if item.get('source_record') else [])) or '(not applicable)'}",
                  f"Related test cases: {', '.join(item['test_cases']) or 'See applicable test_cases.txt'}"]
        lines += shared + [f"Tester notes: {item['notes'] or '(none)'}",
                           'Evidence changed since decision: ' + ('YES - REVALIDATE' if item['changed_evidence'] else 'No'), '']
        # v1.7.2 uses one tester-controlled manual-validation path. The guide
        # separates evidence, prerequisites, checks, tester execution and
        # interpretation without automatic proof execution or routine cleanup.
        def wrap_prose(value):
            return textwrap.fill(str(value).strip(), width=96, break_long_words=False,
                                 break_on_hyphens=False, subsequent_indent='  ')

        excerpt = (item['evidence'] or '').strip()
        if len(excerpt) > 850:
            excerpt = excerpt[:850].rsplit('\n', 1)[0].rstrip() + '\n... see supporting report for the complete observation'
        from utils.poc_playbooks import candidate_validation
        validation = candidate_validation(item, root)
        resource = validation.get('poc_resource') or 'No bundled PoC resource is required/available for this candidate.'
        resource_note = ('Bundled with the Windows Client Assessment tool/source directory, not the assessment output folder.'
                         if validation.get('poc_resource') else '')
        guides += [heading, '=' * 96,
                   f"Decision: {item['status']}  |  Severity: {item['severity']}",
                   f"Module: {item['source_module']}",
                   f"Component: {item['component']}",
                   f"Supporting report: {', '.join(item['artifacts']) or 'See assessment reports'}",
                   f"Related test cases: {', '.join(item['test_cases']) or 'See test_cases.txt'}",
                   f"Matching events: {item.get('occurrence_count', 1)}",
                   f"Source POI labels: {', '.join(item.get('source_records') or ([item['source_record']] if item.get('source_record') else [])) or '(not applicable)'}",
                   '', '1 / 10  OBSERVED EVIDENCE', '-' * 28, excerpt, '',
                   '2 / 10  WHY VALIDATE IT', '-' * 28,
                   wrap_prose(item['description'] or 'Independent validation is needed to establish security impact.'), '',
                   '3 / 10  PREREQUISITES', '-' * 28,
                   wrap_prose(validation['prerequisites']), '',
                   '4 / 10  STARTING CHECKS', '-' * 28,
                   'Read-only starting checks resolved from this assessment evidence:']
        for number, command in enumerate(validation_commands(item, root), 1):
            guides += [f'  {number}.', '    ' + command.replace('\n', '\n    '), '']
        guides += ['5 / 10  MANUAL VALIDATION PROCEDURE', '-' * 28,
                   wrap_prose(instruction), '',
                   '6 / 10  POC RESOURCE', '-' * 28,
                   wrap_prose(resource),
                   *( [wrap_prose(resource_note)] if resource_note else [] )]
        if validation.get('poc_resource'):
            guides += [f"Requires compilation: {validation.get('requires_compilation', 'NO')}",
                       f"Target architecture: {validation.get('target_architecture', 'Not applicable')}"]
            if validation.get('expected_output'):
                guides += [f"Expected output: {validation['expected_output']}"]
            if validation.get('build_or_invocation'):
                guides += ['', 'BUILD / INVOCATION INSTRUCTIONS']
                guides += [f'  {idx}. {step}' for idx, step in enumerate(validation['build_or_invocation'], 1)]
            if validation.get('verification'):
                guides += ['', 'BUILD / RESOURCE VERIFICATION']
                guides += [f'  {idx}. {step}' for idx, step in enumerate(validation['verification'], 1)]
        guides += ['', 'Windows Client Assessment never compiles or executes PoC resources. The tester reviews, builds when required, and runs them manually.', '',
                   '7 / 10  TESTER EXECUTION', '-' * 28,
                   wrap_prose(validation['tester_execution']), '',
                   '8 / 10  EXPECTED EVIDENCE', '-' * 28,
                   wrap_prose(validation['expected_evidence']), '',
                   '9 / 10  INTERPRETATION', '-' * 28,
                   'Expected secure behavior:', wrap_prose(secure), '',
                   'Potential security impact:', wrap_prose(vulnerable), '',
                   '10 / 10  WHEN NOT TO REPORT', '-' * 28,
                   wrap_prose(not_report), '',
                   'Tester notes are optional; evidence may be kept in the separate penetration test report.', '']
    _atomic_text(artifact_path(root, 'tester_review.txt'), '\n'.join(lines).rstrip() + '\n')
    _atomic_text(artifact_path(root, 'evidence_guide.txt'), '\n'.join(guides).rstrip() + '\n')
    from utils.poc_playbooks import render_plan
    render_plan(root, state)


def save_decisions(root: Path, identifiers: list[str], status: str,
                   notes: str, evidence_reference: str = '') -> dict:
    """Atomically commit one decision for identical, explicitly grouped events."""
    if status not in DISPOSITIONS:
        raise ValueError('Unrecognized disposition')
    if not identifiers or len(identifiers) != len(set(identifiers)):
        raise ValueError('Review selection must contain distinct candidate IDs')
    state = read_review(root)
    if state is None or any(identifier not in state['items'] for identifier in identifiers):
        raise ValueError('Unknown review candidate')
    note = str(notes or '')[:4000]
    # Notes are optional for every disposition. The independent pentest report
    # may contain verification evidence instead of duplicating it here.
    from utils.privacy import sanitize_report_text
    note = sanitize_report_text(note)
    evidence = sanitize_report_text(str(evidence_reference or '')[:512])
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    for identifier in identifiers:
        state['items'][identifier].update(
            status=status, notes=note, evidence_reference=evidence,
            updated_at=now, changed_evidence=False, previous_status='')
    state['updated_at'] = now
    _atomic_json(Path(root) / REVIEW_FILE, state)
    return state


def save_decision(root: Path, identifier: str, status: str,
                  notes: str, evidence_reference: str = '') -> dict:
    return save_decisions(root, [identifier], status, notes, evidence_reference)


def collect_tester_notes(input_fn, output_fn, existing: str = '') -> str:
    """Optional single-line or explicit multi-line input without eating menu actions.

    A single '.' on its own line completes multi-line input; :cancel retains
    existing notes. No automatic detection of a clipboard paste is attempted:
    normal one-line input otherwise risks treating the next line as a menu key.
    """
    first = input_fn('Tester notes (optional; Enter = keep/skip; :multi = multiple lines; :clear = erase): ')
    if not first.strip():
        return existing
    choice = first.strip().casefold()
    if choice == ':clear':
        return ''
    if choice != ':multi':
        return first
    output_fn('Multiline notes: paste or enter lines; a single . ends the note. :cancel keeps existing notes.')
    lines = []
    while True:
        line = input_fn('Note line (. to finish): ')
        if line.strip().casefold() == ':cancel':
            return existing
        if line == '.':
            return '\n'.join(lines) if lines else existing
        lines.append(line)
        if sum(len(text) + 1 for text in lines) >= 4000:
            output_fn('Maximum note length reached; saving the first 4000 characters.')
            return '\n'.join(lines)[:4000]


def filter_items(state: dict, *, status='PENDING', severity='', module='') -> list[dict]:
    severity = severity.casefold().strip()
    module = module.casefold().strip()
    items = [item for item in state['items'].values()
             if (not status or item['status'] == status)
             and (not severity or item['severity'].casefold() == severity)
             and (not module or module in item['source_module'].casefold())]
    priority = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}
    return sorted(items, key=lambda item: (priority.get(item['severity'], 9), item['source_module'], item['id']))


def review_queue(state: dict, *, status='PENDING', severity='', module='') -> list[dict]:
    """Collapse identical legacy POIs in the *view* without altering saved IDs.

    Different evidence, decision, notes, or changed-evidence flags remain
    distinct even if the process/title is the same.
    """
    visible = []
    groups = {}
    for record in filter_items(state, status=status, severity=severity, module=module):
        key = None
        if record.get('source_record'):
            key = (record['source_module'], _canonical(record['title']),
                   _canonical(record['evidence']), record['status'],
                   record.get('notes', ''), record.get('evidence_reference', ''),
                   bool(record.get('changed_evidence', False)))
        if key is not None and key in groups:
            group = groups[key]
            group['_linked_ids'].append(record['id'])
            group['_occurrences'] += int(record.get('occurrence_count') or 1)
            group['_linked_records'].append(record.get('source_record', ''))
        else:
            group = dict(record)
            group['_linked_ids'] = [record['id']]
            group['_occurrences'] = int(record.get('occurrence_count') or 1)
            group['_linked_records'] = list(record.get('source_records') or
                                            ([record['source_record']] if record.get('source_record') else []))
            if key is not None:
                groups[key] = group
            visible.append(group)
    return visible


def guided_review_cli(root: Path, *, input_fn=input, output_fn=print) -> None:
    """Numbered review with automatic advancement and a navigable overview.

    Only confirmed user actions change review state. Legacy v1.5.0 archives
    retain all original IDs; identical events are grouped in the presentation
    and committed atomically together when the tester chooses a disposition.
    """
    from utils.assessment_integrity import verify_assessment, create_manifest
    from utils.assessment_state import AssessmentState
    from utils.reporting import AssessmentReporter
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.syntax import Syntax
    from rich.console import Group

    root = Path(root)
    initial = verify_assessment(root)
    if initial['status'] != 'PASS':
        raise ValueError('Review requires a verified assessment. Resolve integrity issues before editing review state.')
    state = read_review(root)
    if state is None:
        raise ValueError('No guided review state was found for this assessment.')
    pretty = output_fn is print
    console = Console() if pretty else None
    # Tool paths are live-session context only. They are never written into the
    # portable review state/reports; this lets copied commands use the exact
    # executable variant Tool Detection found (for example handle.exe).
    from utils.tool_detection import detect_tools
    live_tools = detect_tools()

    def emit(value):
        if pretty:
            console.print(value)
        else:
            output_fn(str(value))

    def overview(queue):
        progress = counts(state)
        total = len(state['items'])
        emit(f'\nGuided Tester Review  |  {total - progress["PENDING"]}/{total} reviewed  |  {progress["PENDING"]} pending')
        emit(f'{len(queue)} distinct conditions in this view; choose a number with J (for example: j 3).')
        emit('For Windows thick-client attack-surface coverage, including unobserved and guided surfaces: reports\\attack_surface_test_plan.txt')
        if pretty:
            table = Table(show_header=True, title='Review queue', expand=True)
            for heading, style in (('#', 'cyan'), ('Severity', 'bold'), ('Decision', 'bold'), ('Module', 'dim'), ('Observed condition', '')):
                table.add_column(heading, style=style, overflow='fold')
            for number, row in enumerate(queue, 1):
                title = row['title'] + (f'  ({row["_occurrences"]} identical events)' if row['_occurrences'] > 1 else '')
                table.add_row(str(number), row['severity'], row['status'], row['source_module'], title)
            console.print(table)
        else:
            for number, row in enumerate(queue, 1):
                suffix = f' [{row["_occurrences"]} identical events]' if row['_occurrences'] > 1 else ''
                output_fn(f'  {number:>2}. {row["status"]:<14} {row["severity"]:<13} {row["source_module"]}: {row["title"]}{suffix}')

    def detail(item, index, total):
        duplicate = (f'{item["_occurrences"]} identical source events grouped'
                     if item['_occurrences'] > 1 else '')
        heading = (f'Pending condition {index + 1} of {total} remaining'
                   if status_filter == 'PENDING' else f'Condition {index + 1}/{total}')
        instruction = _guide(item)[0]
        first_command = validation_commands(item, root, console_paths=True, tools=live_tools)[0]
        if pretty:
            card_width = max(48, min(118, console.size.width - 2))
            title = Text(item['title'], style='bold white')
            meta = Table.grid(padding=(0, 2))
            meta.add_column(style='bold cyan', no_wrap=True)
            meta.add_column(overflow='fold')
            meta.add_row('Severity', item['severity'])
            meta.add_row('Decision', item['status'])
            if duplicate:
                meta.add_row('Occurrences', duplicate)
            meta.add_row('Module', item['source_module'])
            meta.add_row('Candidate ID', item['id'])
            meta.add_row('Supporting File', ', '.join(item['artifacts']) or 'See assessment reports')
            meta.add_row('Test Cases', ', '.join(item['test_cases']) or 'See test_cases.txt')

            body = [title, Text(''), meta,
                    Text('VALIDATION SUMMARY', style='bold cyan'), Text(instruction), Text(''),
                    Text('STARTING CHECK', style='bold cyan'),
                    Syntax(first_command, 'powershell', word_wrap=True, background_color='default'),
                    Text('Press C to copy the complete unwrapped Windows checks to the clipboard.', style='dim'), Text(''),
                    Text('TESTER NOTES', style='bold cyan'), Text(item.get('notes') or '(none)')]
            console.print(Panel(Group(*body), title=heading, title_align='left',
                                subtitle='Enter = next  |  8 = guide  |  C = copy checks',
                                subtitle_align='right', border_style='cyan', expand=False, width=card_width))
            console.print()
        else:
            output_fn('\n' + heading)
            output_fn(item['title'])
            for value in (f'Severity: {item["severity"]}', f'Decision: {item["status"]}',
                          *( [f'Occurrences: {duplicate}'] if duplicate else [] ),
                          f'Module: {item["source_module"]}', f'Candidate ID: {item["id"]}',
                          f'Supporting File: {", ".join(item["artifacts"]) or "See assessment reports"}',
                          f'Test Cases: {", ".join(item["test_cases"]) or "See test_cases.txt"}',
                          'Validation Summary:', instruction, 'Starting Check:', first_command,
                          'C = copy all complete, unwrapped checks',
                          'Tester Notes:', item.get('notes') or '(none)'):
                output_fn(value)
        emit('[1] Validate  [2] Not applicable  [3] Informational  [4] Pending')
        if status_filter == '':
            emit('All view: Save & Next Pending after each disposition; reopen All to revisit completed decisions.')
        emit('[Enter/5] Next  [6] Back  [7] List/jump  [8] Validation guide  [C] Copy checks  [9] Filters  [0] Exit')

    def full_guide(item):
        instruction, vulnerable, secure, not_report = _guide(item)
        observed = item['evidence'].strip()
        if len(observed) > 850:
            observed = observed[:850].rsplit('\n', 1)[0].rstrip() + '\n... continued in supporting report'
        command_steps = validation_commands(item, root, console_paths=True, tools=live_tools)
        from utils.poc_playbooks import candidate_validation
        validation = candidate_validation(item, root, console_paths=True)
        resource = validation.get('poc_resource') or 'No bundled PoC resource is required/available for this candidate.'
        resource_note = ('Bundled with the Windows Client Assessment tool/source directory, not the assessment output folder.'
                         if validation.get('poc_resource') else '')
        if pretty:
            guide_width = max(48, min(118, console.size.width - 2))
            console.print('\n[bold cyan]WINDOWS VALIDATION GUIDE[/bold cyan]  '
                          '[dim](tester-controlled; read-only checks; C copies unwrapped commands)[/dim]')
            context = Text()
            context.append('Component  ', style='bold'); context.append(item['component'] + '\n')
            context.append('Module     ', style='bold'); context.append(item['source_module'] + '\n')
            context.append('Report     ', style='bold'); context.append((', '.join(item['artifacts']) or 'See assessment reports') + '\n\n')
            context.append('OBSERVED EVIDENCE\n', style='bold cyan'); context.append(observed)
            console.print(Panel(context, title='1 / 6  Observed evidence', title_align='left', border_style='cyan', expand=False, width=guide_width))

            why = Text()
            why.append('WHY VALIDATE IT\n', style='bold cyan'); why.append((item.get('description') or 'Independent validation is needed to establish security impact.') + '\n\n')
            why.append('PREREQUISITES\n', style='bold cyan'); why.append(validation['prerequisites'])
            console.print(Panel(why, title='2 / 6  Why validate / prerequisites', title_align='left', border_style='cyan', expand=False, width=guide_width))

            command_renderables = [Text('Run on the authorized assessment VM. These resolved commands do not depend on the current directory.\nLong lines may wrap on screen; choose C below to copy the original unwrapped commands.\n')]
            for number, command in enumerate(command_steps, 1):
                command_renderables.append(Text(f'{number}.  ', style='bold cyan'))
                if command.lstrip().startswith(('Identify ', 'Confirm ', 'Inspect ', 'Review ', 'Record ', 'Validate ', 'Re-test ')):
                    command_renderables.append(Text(command))
                else:
                    command_renderables.append(Syntax(command, 'powershell', word_wrap=True, background_color='default'))
                command_renderables.append(Text(''))
            console.print(Panel(Group(*command_renderables), title='3 / 6  Starting checks', title_align='left', border_style='cyan', expand=False, width=guide_width))

            manual = Text()
            manual.append('MANUAL VALIDATION PROCEDURE\n', style='bold cyan'); manual.append(instruction + '\n\n')
            manual.append('POC RESOURCE\n', style='bold yellow'); manual.append(resource + '\n')
            if resource_note:
                manual.append(resource_note + '\n', style='dim')
            if validation.get('poc_resource'):
                manual.append(f"\nRequires compilation: {validation.get('requires_compilation', 'NO')}\n", style='bold')
                manual.append(f"Target architecture: {validation.get('target_architecture', 'Not applicable')}\n")
                if validation.get('expected_output'):
                    manual.append(f"Expected output: {validation['expected_output']}\n")
                if validation.get('build_or_invocation'):
                    manual.append('\nBUILD / INVOCATION INSTRUCTIONS\n', style='bold cyan')
                    for idx, step in enumerate(validation['build_or_invocation'], 1):
                        manual.append(f'{idx}. {step}\n')
                if validation.get('verification'):
                    manual.append('\nBUILD / RESOURCE VERIFICATION\n', style='bold cyan')
                    for idx, step in enumerate(validation['verification'], 1):
                        manual.append(f'{idx}. {step}\n')
            manual.append('\nWindows Client Assessment never compiles or executes PoC resources. The tester reviews, builds when required, and runs them manually.', style='dim')
            console.print(Panel(manual, title='4 / 6  Manual validation / PoC resource', title_align='left', border_style='yellow', expand=False, width=guide_width))

            execution = Text()
            execution.append('TESTER EXECUTION\n', style='bold cyan'); execution.append(validation['tester_execution'] + '\n\n')
            execution.append('EXPECTED EVIDENCE\n', style='bold green'); execution.append(validation['expected_evidence'])
            console.print(Panel(execution, title='5 / 6  Tester execution / expected evidence', title_align='left', border_style='yellow', expand=False, width=guide_width))

            outcome = Text()
            outcome.append('EXPECTED SECURE BEHAVIOR\n', style='bold green'); outcome.append(secure + '\n\n')
            outcome.append('POTENTIAL SECURITY IMPACT\n', style='bold yellow'); outcome.append(vulnerable + '\n\n')
            outcome.append('WHEN NOT TO REPORT\n', style='bold dim'); outcome.append(not_report + '\n\n')
            outcome.append('Tester notes are optional; keep proof in assessment evidence or the separate penetration-test report.', style='dim')
            console.print(Panel(outcome, title='6 / 6  Interpretation', title_align='left', border_style='green', expand=False, width=guide_width))
        else:
            sections = [
                ('1 / 6  OBSERVED EVIDENCE', [f'Component: {item["component"]}', f'Module: {item["source_module"]}', f'Report: {", ".join(item["artifacts"])}', 'Observed evidence:', observed]),
                ('2 / 6  WHY VALIDATE / PREREQUISITES', ['Why validate it:', item.get('description') or 'Independent validation is needed.', 'Prerequisites:', validation['prerequisites']]),
                ('3 / 6  STARTING CHECKS', ['Read-only checks; C copies complete unwrapped commands:', *(f'{i}. {step}' for i, step in enumerate(command_steps, 1))]),
                ('4 / 6  MANUAL VALIDATION / POC RESOURCE', [
                    'Manual validation procedure:', instruction, 'PoC resource:', resource,
                    *( [resource_note] if resource_note else [] ),
                    *( [f"Requires compilation: {validation.get('requires_compilation', 'NO')}",
                        f"Target architecture: {validation.get('target_architecture', 'Not applicable')}",
                        *( [f"Expected output: {validation['expected_output']}"] if validation.get('expected_output') else [] ),
                        *( ['Build / invocation:', *validation.get('build_or_invocation', ())] if validation.get('build_or_invocation') else [] ),
                        *( ['Verification:', *validation.get('verification', ())] if validation.get('verification') else [] )] if validation.get('poc_resource') else [] ),
                    'Windows Client Assessment never compiles or executes the PoC.']),
                ('5 / 6  TESTER EXECUTION / EXPECTED EVIDENCE', ['Tester execution:', validation['tester_execution'], 'Expected evidence:', validation['expected_evidence']]),
                ('6 / 6  INTERPRETATION', ['Expected secure behavior:', secure, 'Potential security impact:', vulnerable, 'When NOT to report:', not_report]),
            ]
            for title, content in sections:
                output_fn('\n' + title + '\n' + '-' * len(title))
                for line in content:
                    output_fn(line)
        action = input_fn('Press Enter to return to this review condition, or C to copy all unwrapped Windows checks... ').strip().casefold()
        if action in ('c', 'copy'):
            copy_checks(item)

    def copy_checks(item):
        """Never run the checks; copy only when the tester requests it."""
        from utils.validation_clipboard import powershell_checks, copy_windows_text
        full_text = powershell_checks(validation_commands(item, root, console_paths=True, tools=live_tools))
        try:
            copy_windows_text(full_text)
        except (OSError, MemoryError) as exc:
            emit(f'Unable to copy checks: {exc}. Use the corresponding saved evidence guide instead.')
        else:
            command_count = sum(1 for line in full_text.splitlines() if line.strip() and not line.lstrip().startswith('#'))
            emit(f'Copied {command_count} complete PowerShell command' + ('s' if command_count != 1 else '') +
                 ' to the clipboard. Each command is preserved as a single line; multiple commands are separated by line breaks. '
                 'Paste into an authorized PowerShell terminal.')

    def filters():
        selection = input_fn('View: [1/p] Pending  [2/a] All  [3/s] Choose disposition (1): ').strip().casefold() or '1'
        if selection in ('2', 'a', 'all'):
            wanted = ''
        elif selection in ('3', 's', 'status'):
            value = input_fn('Decision (PENDING/VALIDATED/NOT APPLICABLE/INFORMATIONAL): ').strip().upper()
            if value not in DISPOSITIONS:
                emit('Unknown decision; keeping Pending view.')
                wanted = 'PENDING'
            else:
                wanted = value
        else:
            wanted = 'PENDING'
        # Initial entry is concise. Additional filters are available from menu 9.
        return wanted

    status_filter = filters()
    severity_filter = ''
    module_filter = ''
    queue = review_queue(state, status=status_filter)
    cursor = 0
    if not queue:
        emit('No matching review candidates. Select All from the filter menu to revisit completed items.')
        return
    overview(queue)
    while queue:
        cursor = max(0, min(cursor, len(queue) - 1))
        item = queue[cursor]
        detail(item, cursor, len(queue))
        cmd = input_fn('Action (Enter = next): ').strip().casefold()
        if cmd in ('q', 'quit', 'exit', '0'):
            emit('Review progress is saved. Returning to the main menu.')
            return
        if cmd in ('', '5', '>', 'next', 'skip'):
            if cursor + 1 < len(queue):
                cursor += 1
            else:
                emit('End of this view. Showing the review queue; use J to jump or 0 to exit.')
                overview(queue)
            continue
        if cmd in ('6', '<', 'back', 'previous', 'prev'):
            if cursor:
                cursor -= 1
            else:
                emit('Already at the first condition; use 7 for the full list.')
            continue
        if cmd in ('7', 'l', 'list'):
            overview(queue)
            jump = input_fn('Open condition number (blank = current): ').strip()
            if jump.isdecimal() and 1 <= int(jump) <= len(queue):
                cursor = int(jump) - 1
            elif jump and jump not in ('q', '0'):
                emit('Choose a number shown in the table.')
            continue
        if cmd.startswith('j ') or cmd.startswith('goto '):
            number = cmd.partition(' ')[2].strip()
            if number.isdecimal() and 1 <= int(number) <= len(queue):
                cursor = int(number) - 1
            else:
                emit('Enter a valid condition number, such as j 3.')
            continue
        if cmd in ('c', 'copy'):
            copy_checks(item)
            continue
        if cmd in ('8', 'g', 'guide', 'help'):
            full_guide(item)
            continue
        if cmd in ('9', 'f', 'filter', 'a', 'all'):
            status_filter = '' if cmd in ('a', 'all') else filters()
            severity_filter = input_fn('Severity (exact; blank = all): ').strip()
            module_filter = input_fn('Module contains (blank = all): ').strip()
            queue = review_queue(state, status=status_filter, severity=severity_filter, module=module_filter)
            cursor = 0
            if not queue:
                emit('No matching candidates for these filters. Returning to the review menu.')
                return
            overview(queue)
            continue
        selected = {
            '1': 'VALIDATED', 'v': 'VALIDATED', 'validate': 'VALIDATED',
            '2': 'NOT APPLICABLE', 'n': 'NOT APPLICABLE', 'na': 'NOT APPLICABLE',
            '3': 'INFORMATIONAL', 'i': 'INFORMATIONAL', 'info': 'INFORMATIONAL',
            '4': 'PENDING', 'p': 'PENDING', 'pending': 'PENDING',
        }.get(cmd)
        if selected is None:
            emit('Unknown command. Enter a number from 0-9, C to copy checks, or Enter for Next.')
            continue
        if item['_occurrences'] > 1:
            emit(f'This exact observation occurs {item["_occurrences"]} times. One decision will cover all identical records; distinct evidence stays separate.')
        actual_notes = collect_tester_notes(input_fn, emit, item.get('notes', ''))
        if verify_assessment(root)['status'] != 'PASS':
            raise ValueError('Assessment changed during review. Reverify before saving.')
        # All grouped IDs correspond to identical evidence and identical
        # preexisting decisions. Update the complete group in one JSON write.
        # Older reviews can carry evidence_reference; retain that history
        # without requiring a separate Evidence file/ID field going forward.
        state = save_decisions(root, item['_linked_ids'], selected, actual_notes,
                               item.get('evidence_reference', ''))
        assessment = AssessmentState.load(root)
        render = json.loads((root / 'working' / 'report_render_state.json').read_text(encoding='utf-8'))
        reporter = AssessmentReporter(root, assessment.data['assessment_name'], Path(render.get('target_filename') or render['installer_filename']),
                                      assessment.data['mode'], assessment.data['framework_version'],
                                      target_type=(assessment.data.get('target') or {}).get('type', 'installable'))
        reporter.status = render['modules']
        reporter.findings = render['findings']
        reporter.finalize(persist_render_state=False, sanitize_primary=False)
        original_manifest = initial.get('manifest', {})
        create_manifest(root, framework_version=assessment.data['framework_version'],
                        methodology_version=original_manifest.get('methodology_version', '1.1'),
                        catalog_version=original_manifest.get('artifact_catalog_version', '1.1'))
        if verify_assessment(root)['status'] != 'PASS':
            raise ValueError('Saved review did not pass integrity validation.')
        emit(f'Saved {selected}: {item["title"]} ({item["_occurrences"]} event(s)). Automatically advancing.')
        category_pending = sum(1 for record in state['items'].values() if
                               record.get('source_module') == item['source_module']
                               and record.get('status') == 'PENDING')
        emit(f'Category pending: {item["source_module"]}: {category_pending} remaining.')
        # Pending queues shrink as items are reviewed; all-queues do not.
        # Never display the just-saved item again by default.
        previous_id = item['id']
        previous_index = cursor
        queue = review_queue(state, status=status_filter, severity=severity_filter, module=module_filter)
        if not queue:
            emit('All matching conditions reviewed. Progress saved and verified.')
            return
        if status_filter == 'PENDING' and selected != 'PENDING':
            cursor = min(previous_index, len(queue) - 1)
        elif status_filter == '':
            pending_indexes = [j for j, record in enumerate(queue) if record['status'] == 'PENDING'
                               and previous_id not in record['_linked_ids']]
            if not pending_indexes:
                emit('Save & Next Pending: no pending conditions remain. Reopen All to revisit completed decisions.')
                return
            cursor = next((j for j in pending_indexes if j >= previous_index), pending_indexes[0])
        else:
            # In status views, the group remains visible when its new
            # decision matches the filter. Move forward explicitly.
            cursor = next((j for j, record in enumerate(queue)
                           if j >= previous_index and previous_id not in record['_linked_ids']), len(queue))
            if cursor >= len(queue):
                other_pending = [j for j, record in enumerate(queue) if record['status'] == 'PENDING'
                                 and previous_id not in record['_linked_ids']]
                if other_pending:
                    cursor = other_pending[0]
                    emit('End of the list; continuing with a pending condition.')
                else:
                    emit('Reached the end of this review view. Reopen to revisit completed decisions.')
                    return
