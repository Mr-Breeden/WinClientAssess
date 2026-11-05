"""Read-only, integrity-gated comparison of two existing WCA assessments.

Changes are observations, not vulnerabilities. Missing report != removed item.
No comparison artifacts are persisted within either protected assessment.
"""
from __future__ import annotations
import re
from pathlib import Path
from utils.assessment_integrity import verify_assessment
from utils.assessment_state import AssessmentState
from utils.privacy import sanitize_report_text

REPORTS = {
    'Installer / extracted files': ('installer_analysis.txt', 'installer_extraction.txt', 'installer_technology.txt'),
    'PE mitigations': ('binary_security_review.txt',),
    'Signatures': ('signature_review.txt', 'signing_review.txt', 'digital_signature_review.txt'),
    'Secret indicators (redacted)': ('secrets_review.txt',),
    'Electron / technology': ('electron_security_review.txt', 'application_profile.txt'),
    'Filesystem': ('filesystem_changes.txt', 'installed_files.txt', 'installed_directories.txt'),
    'Registry': ('registry_changes.txt',),
    'Services': ('services_review.txt',),
    'Scheduled tasks': ('scheduled_tasks_review.txt',),
    'Runtime processes / modules': ('runtime_processes.txt', 'advanced_runtime_review.txt', 'dll_search_review.txt'),
    'Network': ('network_surface_review.txt',),
    'IPC': ('ipc_review.txt',),
    'Updater': ('updater_review.txt', 'updater_staging_review.txt'),
}
STATIC_CATEGORIES = tuple(REPORTS)[:5]
MAX_FILE = 5_000_000
MAX_ITEMS = 120
_VOLATILE = re.compile(r'(?i)^\s*(?:execution refs|tools|audit details|live recheck|source csv|captured|generated|updated|elapsed|timestamp|session|current pid|process id|target-only working csv)\s*:')


def _canonical_evidence_line(raw: str, assessment_name: str) -> str:
    """Remove *collection-root* noise while retaining meaningful target paths.

    Only paths inside working/extracted_installer become relative. Installed
    filesystem paths remain absolute: moving a privileged DLL is significant.
    """
    line = sanitize_report_text(raw.strip()).replace(assessment_name, '<ASSESSMENT>')
    marker = re.search(r'(?i)working[\\/]extracted_installer', line)
    if marker:
        before = line[:marker.start()]
        # Source prefix can vary with WCA privacy sanitization between patches.
        root_prefix = re.search(r'(?i)(?:%SOURCE_DIR%|%USERPROFILE%|[A-Za-z]:[\\/])', before)
        if root_prefix:
            before = before[:root_prefix.start()]
        after = line[marker.end():].replace('/', '\\')
        line = before + '<EXTRACTED_ROOT>' + after
    line = re.sub(r'(?i)\bPID\s+\d+\b', 'PID <runtime>', line)
    return line


def _records(root: Path, filename: str):
    file = root / 'reports' / filename
    if file.is_symlink() or not file.is_file():
        return None
    if file.resolve().parent != (root / 'reports').resolve() or file.stat().st_size > MAX_FILE:
        return None
    lines = file.read_text(encoding='utf-8', errors='replace').splitlines()
    # PE records are compared by extracted-file identity, not report sequence IDs.
    # This prevents a single insertion from renumbering every subsequent PE.
    result=set()
    current_pe=None
    for raw in lines:
        line=_canonical_evidence_line(raw,root.name)
        match=re.match(r'^\[PE-\d+\]\s+(.+)$',line)
        if filename=='binary_security_review.txt' and match:
            current_pe=match[1].strip().casefold()
            result.add(f'PE {current_pe}: OBSERVED')
            continue
        if filename=='binary_security_review.txt' and current_pe and raw.startswith('  '):
            field=line.strip()
            if field and ':' in field:
                result.add(f'PE {current_pe}: {field}')
            continue
        if filename=='binary_security_review.txt' and not raw.startswith('  '):
            current_pe=None
        if (not line or len(line)>450 or line.startswith(('-', '=')) or _VOLATILE.match(line)
                or line in ('COLLECTION PROVENANCE','END COLLECTION PROVENANCE')):
            continue
        result.add(line)
    return result



def _payload_fingerprints(root: Path) -> dict[str, str] | None:
    """Read only manifest hashes after verify_assessment() has passed."""
    import json
    file=root/'working'/'assessment_manifest.json'
    if file.is_symlink() or not file.is_file() or file.stat().st_size>5_000_000:
        return None
    data=json.loads(file.read_text(encoding='utf-8'))
    if not isinstance(data,dict):return None
    files=data.get('files',{}).get('payloads',{})
    if not isinstance(files,dict):return None
    result={}
    for path,row in files.items():
        norm=str(path).replace('\\','/').casefold()
        if not norm.startswith('working/extracted_installer/') or not isinstance(row,dict):continue
        checksum=row.get('sha256')
        if not isinstance(checksum,str) or not re.fullmatch(r'[0-9a-f]{64}',checksum):continue
        result[norm.removeprefix('working/extracted_installer/')]=checksum
    return result


def _compare_payloads(before: Path, after: Path) -> dict:
    old,new=_payload_fingerprints(before),_payload_fingerprints(after)
    if not old or not new:
        return {'report':'Verified payload hashes','status':'NOT_COMPARABLE',
                'reason':'At least one assessment did not collect a comparable extracted payload inventory.',
                'new':[],'removed':[],'unchanged':0}
    fresh=sorted(new.keys()-old.keys())
    missing=sorted(old.keys()-new.keys())
    modified=sorted(path for path in old.keys() & new.keys() if old[path]!=new[path])
    return {'report':'Verified payload hashes','status':'COMPARED',
            'new':[f'{p} (SHA-256 {new[p][:12]}…)' for p in fresh[:MAX_ITEMS]],
            'removed':[f'{p} (SHA-256 {old[p][:12]}…)' for p in missing[:MAX_ITEMS]],
            'changed':[{'before':f'{p} (SHA-256 {old[p][:12]}…)',
                        'after':f'{p} (SHA-256 {new[p][:12]}…)'} for p in modified[:MAX_ITEMS]],
            'new_total':len(fresh),'removed_total':len(missing),'changed_total':len(modified),
            'unchanged':sum(old[p]==new[p] for p in old.keys() & new.keys()),
            'truncated':any(len(group)>MAX_ITEMS for group in (fresh,missing,modified))}


def compare_assessments(baseline: Path, comparison: Path) -> dict:
    baseline, comparison = Path(baseline), Path(comparison)
    if baseline.resolve() == comparison.resolve():
        raise ValueError('Choose two different assessments.')
    roots = (baseline, comparison)
    for root in roots:
        if verify_assessment(root).get('status') != 'PASS':
            raise ValueError('Both assessments must pass integrity verification before comparison.')
    states = [AssessmentState.load(root) for root in roots]
    if not all(states):
        raise ValueError('Assessment state missing.')
    modes = [str(s.data.get('mode', '')).lower() for s in states]
    if modes[0] != modes[1] or modes[0] not in ('static', 'full'):
        raise ValueError('Only Static-to-Static or Full-to-Full comparisons are supported.')
    categories = STATIC_CATEGORIES if modes[0]=='static' else tuple(REPORTS)
    sections=[]
    for category in categories:
        items=[]
        for filename in REPORTS[category]:
            old,new = (_records(root, filename) for root in roots)
            if old is None and new is None:
                continue  # Neither assessment collected this optional report.
            if old is None or new is None:
                items.append({'report': filename, 'status':'NOT_COMPARABLE',
                              'reason':'Report missing or unsupported in at least one assessment; missing evidence is not removed evidence.',
                              'new':[], 'removed':[], 'unchanged':0})
                continue
            added=set(new-old)
            removed=set(old-new)
            # Conservative structured changes: only infer a changed field when
            # there is a unique key/value pair on both sides; repeated fields
            # in a multi-object report remain independent observations.
            def unique_fields(lines):
                values={} 
                for line in lines:
                    matched=re.match(r'^([A-Za-z][A-Za-z /_-]{3,45})\s*:\s*(.{1,250})$',line)
                    if not matched and line.startswith('PE '):
                        # Group by assessment-relative binary and mitigation flag.
                        matched=re.match(r'^(PE .+?:\s+[A-Za-z][A-Za-z0-9 /._-]{2,40})\s*:\s*(.{1,250})$',line)
                    if matched:values.setdefault(matched[1].casefold(),set()).add(line)
                return {k:next(iter(v)) for k,v in values.items() if len(v)==1}
            before,after=unique_fields(removed),unique_fields(added)
            changed=[]
            for key in sorted(before.keys() & after.keys()):
                old_line,new_line=before[key],after[key]
                removed.discard(old_line);added.discard(new_line)
                changed.append({'before':old_line,'after':new_line})
            new_items=sorted(added)
            old_items=sorted(removed)
            items.append({'report':filename,'status':'COMPARED','new':new_items[:MAX_ITEMS],
                          'removed':old_items[:MAX_ITEMS], 'unchanged':len(old&new),
                          'new_total':len(new_items),'removed_total':len(old_items),
                          'truncated':len(new_items)>MAX_ITEMS or len(old_items)>MAX_ITEMS or len(changed)>MAX_ITEMS,
                          'changed':changed[:MAX_ITEMS], 'changed_total':len(changed)})
        sections.append({'category':category,'reports':items})
    sections.append({'category':'Extracted payload identity (SHA-256)',
                     'reports':[_compare_payloads(baseline,comparison)]})
    return {'mode':modes[0], 'baseline':baseline.name, 'comparison':comparison.name,
            'sections':sections,'note':('Read-only comparison of sanitized, normalized report observations; extracted-file paths are assessment-relative. '
             'Unobserved does not prove removed, and differences are not vulnerability findings. '
             'Runtime session/capture conditions may differ.')}
