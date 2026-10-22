"""Persistent, integrity-aware manual test-case review for WCA v2.2.

Manual testing is distinct from generated evidence and Guided Review candidates.
The source test_cases.txt stays immutable, and recorded decisions do not by
 themselves establish exploitability or reportability.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from datetime import datetime, timezone

from utils.assessment_integrity import create_manifest, verify_assessment
from utils.assessment_state import AssessmentState
from utils.guided_review import read_review
from utils.operation_lock import assessment_operation
from utils.privacy import sanitize_report_text

REVIEW_FILE = Path('working/manual_test_review.json')
STATUSES = ('NOT STARTED', 'IN PROGRESS', 'COMPLETED', 'NOT APPLICABLE', 'BLOCKED', 'ADDRESSED IN GUIDED REVIEW')
CASE_RE = re.compile(r'^\[ \] (TC-[A-Z]{2}-\d{3}) - (.+?)\s*$', re.M)
MAX_INPUT = 4000
# Report mentions are candidates only: links must refer to actual verified
# report files under this assessment, not arbitrary local paths.
REPORT_RE = re.compile(r'(?<![\w./\\-])([A-Za-z][A-Za-z0-9_-]{0,110}\.(?:txt|md|html))\b', re.I)
MAX_LINKABLE_REPORT = 500_000  # Match the local GUI's report-reading limit.


def _case_guidance(root: Path, body: str) -> dict:
    """Extract case-specific guidance and available report links from the verified checklist."""
    sections = {}
    headings = ('Procedure', 'How to Perform', 'Expected Secure Behavior',
                'What to Look For', 'Potentially Vulnerable Behavior', 'When NOT to Report',
                'Evidence / Tester Notes')
    header_pattern = r'^(?P<label>' + '|'.join(re.escape(x) for x in headings) + r'):[ \t]*$'
    positions = [(m.group('label'), m.start(), m.end()) for m in re.finditer(header_pattern, body, re.M)]
    for index, (name, _start, end) in enumerate(positions):
        if name == 'Evidence / Tester Notes':
            continue
        after = positions[index + 1][1] if index + 1 < len(positions) else len(body)
        sections[name] = sanitize_report_text(body[end:after].strip())[:5000]
    mentioned = dict.fromkeys(match.group(1) for match in REPORT_RE.finditer(body))
    reports = []
    for name in mentioned:
        path = root / 'reports' / name
        if (name != 'test_cases.txt' and path.is_file() and not path.is_symlink()
                and path.stat().st_size <= MAX_LINKABLE_REPORT):
            reports.append(name)
    return {'reports': reports[:30], 'guidance': sections}


def _verified_state(root: Path) -> AssessmentState:
    if verify_assessment(root).get('status') != 'PASS':
        raise ValueError('Assessment integrity must PASS before manual testing review.')
    state = AssessmentState.load(root)
    if not state or state.data.get('status') != 'COMPLETED':
        raise ValueError('A completed structured assessment is required.')
    return state


def _cases(root: Path) -> list[dict]:
    path = root / 'reports' / 'test_cases.txt'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 750_000:
        raise ValueError('Verified test_cases.txt is required.')
    content = path.read_text(encoding='utf-8', errors='replace')
    hits = list(CASE_RE.finditer(content))
    if not hits:
        raise ValueError('No applicable test cases in the verified checklist.')
    rows = []
    for i, hit in enumerate(hits):
        body = content[hit.end():hits[i+1].start() if i+1 < len(hits) else len(content)]
        case_id, title = hit.groups()
        if any(x['id'] == case_id for x in rows):
            raise ValueError('Duplicated test-case identifier.')
        # Stable to line-ending differences, sensitive to changes in procedure/evidence.
        fingerprint = hashlib.sha256((case_id + '\n' + title + '\n' +
                                     body.replace('\r\n', '\n').strip()).encode('utf-8')).hexdigest()
        rows.append({'id': case_id, 'title': sanitize_report_text(title)[:160], 'fingerprint': fingerprint,
                     **_case_guidance(root, body)})
    # One contextual application-level activity replaces treating the full
    # attack-surface plan as a second 26-step checklist. Include it only when
    # the plan was actually collected for this assessment.
    plan = root / 'reports' / 'attack_surface_test_plan.txt'
    if plan.is_file() and not plan.is_symlink() and plan.stat().st_size <= 750_000:
        guidance = ("Procedure:\nReview in-scope application security behaviors not already addressed "
                    "by the other Testing Queue activities. Do not repeat completed tests.\n"
                    "How to Perform:\n1. Inspect attack_surface_test_plan.txt for applicable unobserved "
                    "trust boundaries. 2. If the client exposes HTTP(S), WebSockets or APIs, use Burp "
                    "Suite to review authentication, sessions, authorization and input validation. "
                    "3. Where relevant, use Ghidra or ILSpy for code review and Frida or WinDbg for "
                    "tester-controlled runtime validation. 4. Review application-specific input, "
                    "cryptography and client-side trust checks; document detailed findings and screenshots "
                    "only in the separate penetration-test report.\n"
                    "Expected Secure Behavior:\nSecurity-sensitive checks are enforced at the "
                    "appropriate trust boundary; unexpected inputs and unauthorized requests are rejected.\n"
                    "When NOT to Report:\nThe presence of a tool finding or client-only code does "
                    "not independently prove a vulnerability.\n")
        identifier, title = 'TC-AS-001', 'Application-Level and External-Tool Security Review'
        if not any(x['id'] == identifier for x in rows):
            digest = hashlib.sha256((identifier + title + guidance +
              hashlib.sha256(plan.read_bytes()).hexdigest()).encode('utf-8')).hexdigest()
            rows.append({'id': identifier, 'title': title, 'fingerprint': digest,
                         **_case_guidance(root, guidance)})
    return rows


def _review_state(root: Path) -> dict:
    path = root / REVIEW_FILE
    if not path.is_file():
        return {'schema': 1, 'items': {}}
    if path.is_symlink() or path.stat().st_size > 1_500_000:
        raise ValueError('Manual test review state is unavailable.')
    doc = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(doc, dict) or doc.get('schema') != 1 or not isinstance(doc.get('items'), dict):
        raise ValueError('Manual test review state has an invalid format.')
    return doc


def _snapshot(root: Path, *, verified: bool = True) -> dict:
    if verified:
        _verified_state(root)
    cases = _cases(root)
    saved = _review_state(root)['items']
    # Related is not synonymous with tested or covered. This is an explicit
    # catalog link recorded on actual Guided Review candidates, not a guess
    # based on matching filenames/categories. Never change manual status here.
    links = {}
    review = read_review(root)
    for candidate in (review or {}).get('items', {}).values():
        if not isinstance(candidate, dict):
            continue
        identifier = str(candidate.get('id', ''))
        if not identifier.startswith('WCR-'):
            continue
        for case_id in candidate.get('test_cases', []) if isinstance(candidate.get('test_cases'), list) else []:
            if not isinstance(case_id, str):
                continue
            related = links.setdefault(case_id, [])
            if len(related) < 30:
                related.append({'id': identifier,
                                'status': str(candidate.get('status', 'PENDING'))[:30],
                                'changed_evidence': bool(candidate.get('changed_evidence')),
                                'title': sanitize_report_text(str(candidate.get('title', '')))[:160]})
    output = []
    total = {'NOT STARTED': 0, 'IN PROGRESS': 0, 'COMPLETED': 0, 'NOT APPLICABLE': 0, 'BLOCKED': 0, 'ADDRESSED IN GUIDED REVIEW': 0}
    stale = 0
    for case in cases:
        previous = saved.get(case['id'], {})
        matched = isinstance(previous, dict) and previous.get('fingerprint') == case['fingerprint']
        valid = matched and previous.get('status') in STATUSES
        status = previous['status'] if valid else 'NOT STARTED'
        # A recorded guided-coverage affirmation is invalidated by changed / pending
        # related candidates. Guided dispositions never complete tests on their own.
        related = links.get(case['id'], [])
        if status == 'ADDRESSED IN GUIDED REVIEW':
            recorded = previous.get('covered_candidate_ids') or []
            if (not related or set(recorded) != {r['id'] for r in related} or
                    any(r['status'] not in ('VALIDATED', 'NOT APPLICABLE', 'INFORMATIONAL') or r.get('changed_evidence') for r in related)):
                status = 'NOT STARTED'
        total[status] += 1
        if previous and not matched:
            stale += 1
        output.append({**case, 'related_candidates': links.get(case['id'], []), 'status': status, 'notes': sanitize_report_text(previous.get('notes', ''))[:MAX_INPUT] if valid else '',
                       'evidence_reference': sanitize_report_text(previous.get('evidence_reference', ''))[:1000] if valid else '',
                       'client_notes': sanitize_report_text(previous.get('client_notes', ''))[:MAX_INPUT] if valid else '',
                       'changed_evidence': bool(previous and not matched) or (matched and previous.get('status') == 'ADDRESSED IN GUIDED REVIEW' and status == 'NOT STARTED'),
                       'updated_at': str(previous.get('updated_at', ''))[:40] if valid else ''})
    return {'total': len(cases), 'resolved': total['COMPLETED'] + total['NOT APPLICABLE'] + total['ADDRESSED IN GUIDED REVIEW'],
            'remaining': total['NOT STARTED'] + total['IN PROGRESS'] + total['BLOCKED'],
            'by_status': total, 'changed_evidence': stale, 'items': output,
            'note': ('Manual testing outcomes are tester-recorded. COMPLETED and NOT APPLICABLE are not '
                     'evidence of exploitability; review candidates and collection coverage are independent.')}



def testing_queue(root: Path, *, verified: bool = True, manual: dict | None = None) -> dict:
    """One tester activity per applicable manual case, plus unlinked candidates.

    This read-only projection never alters individual saved decisions or creates
    evidence. It is the shared status calculation for Overview and Final Checklist.
    """
    manual = manual if manual is not None else _snapshot(Path(root), verified=verified)
    linked = {c['id'] for case in manual['items'] for c in case['related_candidates']}
    activities = []
    for case in manual['items']:
        pending = [c for c in case['related_candidates']
                   if c['status'] not in ('VALIDATED', 'NOT APPLICABLE', 'INFORMATIONAL')
                   or c.get('changed_evidence')]
        manual_done = case['status'] in ('COMPLETED', 'NOT APPLICABLE', 'ADDRESSED IN GUIDED REVIEW')
        resolved = manual_done and not pending and not case['changed_evidence']
        activities.append({'id': case['id'], 'type': 'manual', 'title': case['title'],
                           'status': case['status'], 'addressed': resolved,
                           'manual_complete': manual_done,
                           'pending_candidates': len(pending),
                           'related_candidates': case['related_candidates'],
                           'changed_evidence': case['changed_evidence']})
    review = read_review(Path(root)) or {}
    for candidate in review.get('items', {}).values():
        if not isinstance(candidate, dict) or candidate.get('id') in linked:
            continue
        resolved = (candidate.get('status') in ('VALIDATED', 'INFORMATIONAL', 'NOT APPLICABLE')
                    and not candidate.get('changed_evidence'))
        activities.append({'id': candidate.get('id', ''), 'type': 'candidate',
                           'title': sanitize_report_text(candidate.get('title', ''))[:160],
                           'status': candidate.get('status', 'PENDING'), 'addressed': resolved,
                           'manual_complete': True, 'pending_candidates': 0 if resolved else 1,
                           'related_candidates': [],
                           'changed_evidence': bool(candidate.get('changed_evidence'))})
    return {'total': len(activities), 'resolved': sum(bool(x['addressed']) for x in activities),
            'remaining': sum(not x['addressed'] for x in activities),
            'pending_guided_review': sum(x['pending_candidates'] for x in activities),
            'pending_manual_testing': sum(not x['manual_complete'] for x in activities),
            'items': activities}

def _excluded_case_explanations(root: Path) -> list[dict]:
    """Summarize only safe case IDs/titles and eligibility reasons from sealed evidence.

    Older assessments lacking this section return an empty array rather than
    guessing why cases are absent or rewriting historical reports.
    """
    report = root / 'reports' / 'test_cases.txt'
    text = report.read_text(encoding='utf-8', errors='replace')
    marker = 'EXCLUDED TEST CASES — APPLICABILITY EXPLANATIONS'
    if marker not in text:
        return []
    section = text.split(marker, 1)[1].split('APPLICABLE MANUAL TEST CASES', 1)[0]
    result = []
    for line in section.splitlines():
        item = re.match(r'^  (TC-[A-Z]{2}-\d{3}) — (.{1,160})$', line)
        if item:
            result.append({'id': item.group(1), 'title': sanitize_report_text(item.group(2))[:160], 'reasons': []})
        elif result and line.startswith('    - '):
            result[-1]['reasons'].append(sanitize_report_text(line[6:])[:500])
    return result[:50]


def read_manual_workflow(root: Path) -> dict:
    """Return minimal listing; private notes are available only per selected case."""
    overview = _snapshot(Path(root))
    overview['excluded_cases'] = _excluded_case_explanations(Path(root))
    overview['testing_queue'] = testing_queue(root, verified=False, manual=overview)
    for item in overview['items']:
        item.pop('notes', None)
        item.pop('evidence_reference', None)
        item.pop('client_notes', None)
        item.pop('guidance', None)
    return overview


def read_manual_detail(root: Path, case_id: str) -> dict:
    """Return optional notes only for a selected integrity-verified case."""
    item = next((x for x in _snapshot(Path(root))['items'] if x['id'] == case_id), None)
    if not item:
        raise ValueError('Unknown manual test case.')
    return item


def save_manual_decision(root: Path, *, case_id: str, fingerprint: str, status: str,
                         notes: str = '', evidence_reference: str = '', client_notes: str = '', current_version: str = '2.2.2') -> dict:
    root = Path(root)
    if (not isinstance(notes, str) or len(notes) > MAX_INPUT or
            not isinstance(client_notes, str) or len(client_notes) > MAX_INPUT or
            not isinstance(evidence_reference, str) or len(evidence_reference) > 1000):
        raise ValueError('Manual review text is too long or invalid.')
    if status not in STATUSES:
        raise ValueError('Unsupported manual test status.')
    with assessment_operation(root, 'save_manual_test'):
        state = _verified_state(root)
        if state.data.get('framework_version') != current_version:
            raise ValueError('Manual test updates require a current-release assessment; prior assessments remain read-only.')
        before = _snapshot(root, verified=False)
        target = next((item for item in before['items'] if item['id'] == case_id), None)
        if not target or target['fingerprint'] != fingerprint:
            raise ValueError('The applicable test case has changed. Reopen before saving.')
        if status == 'ADDRESSED IN GUIDED REVIEW' and (
            not target['related_candidates'] or any(
                c['status'] not in ('VALIDATED', 'NOT APPLICABLE', 'INFORMATIONAL') or c.get('changed_evidence')
                for c in target['related_candidates'])):
            raise ValueError('All linked candidates must be dispositioned before confirming guided coverage.')
        manifest_path = root / 'working' / 'assessment_manifest.json'
        index_path = root / 'reports' / 'artifact_manifest.txt'
        decision_path = root / REVIEW_FILE
        if decision_path.is_symlink() or any(p.is_symlink() for p in (manifest_path, index_path)):
            raise ValueError('Review state contains an untrusted symbolic link.')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        document = _review_state(root)
        document['items'][case_id] = {
            'fingerprint': fingerprint, 'status': status,
            'notes': sanitize_report_text(notes),
            'evidence_reference': sanitize_report_text(evidence_reference),
            'client_notes': sanitize_report_text(client_notes),
            'covered_candidate_ids': ([c['id'] for c in target['related_candidates']]
                                      if status == 'ADDRESSED IN GUIDED REVIEW' else []),
            'updated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        }
        # A backup outside the assessment is retained only if rollback cannot be
        # proven safe. No manual state or temporary backup is exported to clients.
        backup_dir = Path(tempfile.mkdtemp(prefix='.wca-manual-backup-', dir=root.parent))
        previous = {}
        try:
            for item in (manifest_path, index_path, decision_path):
                previous[item] = item.read_bytes() if item.exists() else None
            staged = decision_path.with_name(decision_path.name + '.tmp')
            try:
                with staged.open('w', encoding='utf-8', newline='\n') as handle:
                    json.dump(document, handle, ensure_ascii=True, indent=2, sort_keys=True)
                    handle.write('\n')
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(staged, decision_path)
                create_manifest(root, framework_version=state.data['framework_version'],
                                methodology_version=manifest['methodology_version'],
                                catalog_version=manifest['artifact_catalog_version'])
                if verify_assessment(root).get('status') != 'PASS':
                    raise ValueError('Manual review update did not pass post-save integrity.')
            except BaseException as err:
                staged.unlink(missing_ok=True)
                try:
                    for item, content in previous.items():
                        if content is None:
                            item.unlink(missing_ok=True)
                        else:
                            restore = backup_dir / item.name
                            restore.write_bytes(content)
                            os.replace(restore, item)
                    if verify_assessment(root).get('status') != 'PASS':
                        raise ValueError('Rollback integrity verification failed.')
                except Exception as rollback_error:
                    raise RuntimeError('Manual test update failed; backup retained for manual integrity recovery.') from rollback_error
                raise ValueError('Manual test update failed and original assessment state was restored.') from err
        finally:
            # Never silently discard a backup if integrity is still broken.
            if verify_assessment(root).get('status') == 'PASS':
                shutil.rmtree(backup_dir, ignore_errors=True)
    return read_manual_workflow(root)
