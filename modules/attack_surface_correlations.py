"""Conservative target-specific attack-surface indicators, never exploit claims.

The module correlates a small set of Windows execution/registry/filesystem
conditions that can be derived reliably from already-collected target evidence.
It is intentionally not the complete WCA methodology: unobserved and manual-only
attack surfaces remain documented in ``attack_surface_test_plan.txt``.
"""
from __future__ import annotations

import csv
import ntpath
import re
from pathlib import Path

from utils.acl import broad_write_aces
from utils.assessment_layout import artifact_path
from utils.assessment_integrity import _atomic_text
from utils.privacy import sanitize_report_text
from utils.windows_paths import is_user_profile_path, is_temp_path

MAX_CANDIDATES = 40
_IFEO = re.compile(r'(?i)\\image file execution options\\([^\\]+\.exe)(?:\\|$)')
_COM = re.compile(r'(?i)\\classes\\clsid\\(\{[0-9a-f-]{36}\})\\(?:inprocserver32|localserver32)(?:\\|$)')


def _target_names(targets, diff):
    # Runtime Target Discovery already performs the stronger target-association
    # checks. Do not re-promote every filesystem-added executable here: a
    # system-wide pre/post snapshot can include unrelated Edge/OneDrive/etc.
    # updates that happened during the installation window.
    names = {str(t.get('ProcessName') or ntpath.basename(str(t.get('Path') or ''))).lower()
             for t in targets or [] if isinstance(t, dict)}
    return {x for x in names if x.endswith('.exe') and len(x) <= 128}


def _target_csvs(root, procmon):
    if not (procmon or {}).get('target_filter_active'):
        return []
    candidates = []
    baseline = artifact_path(root, 'working/procmon_target_events.csv')
    guided = artifact_path(root, 'working/guided_runtime_target_events.csv')
    if baseline.is_file() and not baseline.is_symlink():
        candidates.append(baseline)
    if (procmon or {}).get('guided_runtime') and guided.is_file() and not guided.is_symlink():
        candidates.append(guided)
    return candidates


def _exe_search_events(root, procmon, names):
    """Only exact missing executable opens from verified target-scoped CSV."""
    paths = _target_csvs(root, procmon)
    if not paths:
        return [], False
    result = []
    seen = set()
    for path in paths:
        with path.open('r', encoding='utf-8-sig', newline='', errors='replace') as fh:
            for row in csv.DictReader(fh):
                event = {str(k).lower().strip(): str(v or '').strip() for k, v in row.items() if k}
                process = event.get('process name') or event.get('processname') or ''
                operation = event.get('operation', '').lower()
                status = event.get('result', '').lower()
                target = event.get('path', '')
                # A missing executable open is not necessarily a subsequent launch:
                # retain the distinction in both report and review guide.
                if (process.lower() not in names or operation != 'createfile' or
                        status not in ('name not found', 'path not found') or
                        not re.match(r'(?i)^[a-z]:\\', target) or not target.lower().endswith('.exe') or
                        len(target) > 240 or is_user_profile_path(target)):
                    continue
                key = (process.lower(), target.lower())
                if key not in seen:
                    seen.add(key)
                    result.append({'Process': process, 'Path': target, 'Result': status})
                    if len(result) >= MAX_CANDIDATES:
                        return result, True
    return result, True



def _target_install_roots(targets, diff, names):
    """Scope reparse observations to a verified installed executable family.

    A system-wide pre/post filesystem diff includes unrelated scheduled host
    activity. Only candidate directories associated with target executable
    paths (or additions of those exact executable names) are reliable enough
    to create review points. Related ProgramData paths are matched by a
    non-generic product directory name, without any application-specific code.
    """
    roots = set()
    for target in targets or []:
        if not isinstance(target, dict):
            continue
        path = str(target.get('Path') or '')
        if re.match(r'(?i)^[a-z]:\\', path) and ntpath.basename(path).lower() in names:
            roots.add(ntpath.dirname(path).lower().rstrip('\\'))
    for entry in (diff or {}).get('Filesystem', {}).get('added', []) or []:
        path = str(entry.get('Path') or '')
        if (re.match(r'(?i)^[a-z]:\\', path) and
                ntpath.basename(path).lower() in names):
            roots.add(ntpath.dirname(path).lower().rstrip('\\'))
    broad = {'c:\\', r'c:\windows', r'c:\windows\system32',
             r'c:\program files', r'c:\program files (x86)', r'c:\programdata'}
    return {r for r in roots if r not in broad and len(r) >= 8}


def _associated_reparse_path(path, roots):
    if not re.match(r'(?i)^[a-z]:\\', path):
        return False
    path = path.lower().rstrip('\\')
    generic = {'bin', 'app', 'application', 'client', 'server', 'common files', 'windows', 'temp', 'tmp'}
    for root in roots:
        if path == root or path.startswith(root + '\\'):
            return True
        product = ntpath.basename(root)
        if len(product) >= 4 and product not in generic and ('\\' + product + '\\') in (path + '\\'):
            return True
    return False


def _filesystem_reparse(diff, pre, post, roots):
    """Only new/changed reparse objects in the verified install differential."""
    if not pre or not post or not pre.get('Metadata', {}).get('FilesystemIncluded') or not roots:
        return [], False
    # v1.6.1 snapshots have no reparse metadata. Never infer absence.
    pre_files = pre.get('Filesystem') or []
    post_files = post.get('Filesystem') or []
    supported = (bool(pre_files and post_files)
                 and all('IsReparsePoint' in item for item in pre_files[:1] + post_files[:1]))
    if not supported:
        return [], False
    rows = []
    for entry in (diff or {}).get('Filesystem', {}).get('added', []) or []:
        if entry.get('IsReparsePoint') is True and _associated_reparse_path(str(entry.get('Path') or ''), roots):
            rows.append({'Path': entry.get('Path', ''), 'Type': entry.get('LinkType') or 'Reparse point'})
    for change in (diff or {}).get('Filesystem', {}).get('changed', []) or []:
        before, after = change.get('before', {}), change.get('after', {})
        if (after.get('IsReparsePoint') is True and not before.get('IsReparsePoint') and
                _associated_reparse_path(str(after.get('Path') or ''), roots)):
            rows.append({'Path': after.get('Path', ''), 'Type': after.get('LinkType') or 'Reparse point'})
    return rows[:MAX_CANDIDATES], True


def detect_indicators(root: Path, *, mode: str, diff=None, pre=None, post=None,
                      procmon=None, targets=None, acl_cache=None):
    """Pure classification (apart from reading the already-sanitized scoped CSV)."""
    diff, procmon = diff or {}, procmon or {}
    names = _target_names(targets, diff)
    enabled = mode == 'full' and bool(diff)
    results = []
    coverage = {'Executable/helper search-path hijacking': 'COLLECTION UNAVAILABLE',
                'Reparse point / symlink / junction abuse': 'COLLECTION UNAVAILABLE',
                'IFEO / SilentProcessExit injection': 'COLLECTION UNAVAILABLE',
                'COM registration and activation hijacking': 'COLLECTION UNAVAILABLE'}
    if not enabled:
        return results, coverage

    exe_events, csv_collected = _exe_search_events(root, procmon, names)
    coverage['Executable/helper search-path hijacking'] = ('NOT OBSERVED' if csv_collected else 'COLLECTION UNAVAILABLE')
    # Batch ACLs only for exact target-owned search events, never the entire PATH.
    parent_dirs = sorted({ntpath.dirname(e['Path']) for e in exe_events})
    acl_map = acl_cache.get_many(parent_dirs) if acl_cache and parent_dirs else {}
    for row in exe_events:
        directory = ntpath.dirname(row['Path'])
        acl = acl_map.get(directory.lower(), {})
        broad = broad_write_aces(acl)
        likely = bool(broad) or is_temp_path(directory) or directory.lower().startswith('c:\\users\\public\\')
        if not likely:
            continue  # missing file in a protected path is not a candidate
        results.append({'Category': 'Executable/helper search-path hijacking',
                        'Title': row['Process'] + ' -> ' + ntpath.basename(row['Path']),
                        'Process': row['Process'], 'Path': row['Path'], 'Directory': directory,
                        'Evidence': 'Target-scoped CreateFile returned ' + row['Result'],
                        'Caveat': 'Missing executable lookup + possible writable location; a later launch and impact are NOT proven.',
                        'ACL': 'Broad-write ACE' if broad else 'Location hint; effective rights unverified'})
    if any(item['Category'] == 'Executable/helper search-path hijacking' for item in results):
        coverage['Executable/helper search-path hijacking'] = 'AUTOMATIC INDICATOR'

    target_roots = _target_install_roots(targets, diff, names)
    reparse, reparse_collected = _filesystem_reparse(diff, pre or {}, post or {}, target_roots)
    coverage['Reparse point / symlink / junction abuse'] = ('AUTOMATIC INDICATOR' if reparse else
                                             'NOT OBSERVED' if reparse_collected else 'COLLECTION UNAVAILABLE')
    for row in reparse:
        if len(results) >= MAX_CANDIDATES:
            break
        results.append({'Category': 'Reparse point / symlink / junction abuse', 'Title': 'New reparse object',
                        'Path': row['Path'], 'Evidence': 'New or changed reparse object (' + row['Type'] + ')',
                        'Caveat': 'An observed reparse point alone does not establish a writable target or privileged traversal. '
                                  'Installer-time file operations were NOT captured.'})

    registry = procmon.get('registry_writes') or []
    # Value-level IFEO and COM information comes from target-scoped runtime only;
    # the pre/post RegistryKeys inventory cannot tell whether Debugger values changed.
    scoped_registry = bool(procmon.get('target_filter_active')) and bool(names)
    for row in registry:
        process = str(row.get('Process') or '').lower()
        path = str(row.get('Path') or '')
        if not scoped_registry or process not in names or len(path) > 500:
            continue
        ifeo = _IFEO.search(path)
        if ifeo and ifeo.group(1).lower() in names:
            results.append({'Category': 'IFEO / SilentProcessExit injection', 'Title': 'Target-associated IFEO write',
                            'Process': str(row.get('Process') or ''), 'Registry Path': path,
                            'Evidence': str(row.get('Operation') or '') + ' by target process',
                            'Caveat': 'A registry write alone neither proves standard-user access nor an elevated Debugger launch.'})
        com = _COM.search(path)
        if com and (path.lower().startswith('hkcu\\') or
                    path.lower().startswith('hkey_current_user\\')):
            results.append({'Category': 'COM registration and activation hijacking', 'Title': 'Target-associated per-user COM server write',
                            'Process': str(row.get('Process') or ''), 'Registry Path': path,
                            'Evidence': str(row.get('Operation') or '') + ' for CLSID ' + com.group(1),
                            'Caveat': 'HKCU COM registration alone is legitimate in many apps; consumer activation and a trust boundary are unproven.'})
        if len(results) >= MAX_CANDIDATES:
            break
    for category in ('IFEO / SilentProcessExit injection', 'COM registration and activation hijacking'):
        found = any(item['Category'] == category for item in results)
        coverage[category] = ('AUTOMATIC INDICATOR' if found else 'NOT OBSERVED' if scoped_registry else 'COLLECTION UNAVAILABLE')
    return results[:MAX_CANDIDATES], coverage


def run_attack_surface_correlations(root: Path, mode='static', diff=None, pre=None, post=None,
                                  procmon=None, targets=None, acl_cache=None):
    records, coverage = detect_indicators(root, mode=mode, diff=diff, pre=pre, post=post,
                                          procmon=procmon, targets=targets, acl_cache=acl_cache)
    lines = ['WCA - TARGET-SCOPED ATTACK SURFACE CORRELATIONS', '=' * 106, '',
             'Indicators are opportunities for manual testing, never confirmed vulnerabilities.',
             'A completed full-mode collection is NOT equivalent to exhaustive attack-surface testing.',
             'Reparse observations are scoped to target-associated executable families; other host paths are excluded.',
             'Absence from target-scoped collection is NOT proof of secure behavior.', '', 'CATEGORY COLLECTION', '-' * 106]
    for name, status in coverage.items():
        lines.append(f'{name:31} : {status}')
    lines += ['', 'REVIEW POINTS', '-' * 106]
    findings = []
    if not records:
        lines.append('No additional narrowly correlated indicators identified in available collection.')
    for i, record in enumerate(records, 1):
        lines.extend(['', '=' * 106, f'[ASC-{i:03d}] {record["Title"]}', '=' * 106])
        for key, value in record.items():
            lines.append(f'{key:19} : {sanitize_report_text(str(value))}')
        evidence = '\n'.join(f'{key}: {value}' for key, value in record.items()
                             if key not in ('Title', 'Caveat'))
        findings.append({'title': record['Category'] + ': ' + record['Title'],
                         'severity': 'Informational',
                         'description': record['Caveat'],
                         'evidence': evidence,
                         'recommendation': 'Inspect only the exact recorded path/object and manually demonstrate relevant control, execution and boundary before reporting.',
                         'artifacts': ['attack_surface_correlations.txt']})
    _atomic_text(artifact_path(root, 'attack_surface_correlations.txt'),
                 sanitize_report_text('\n'.join(lines).rstrip() + '\n'))
    return {'status': 'WARN' if findings else ('PASS' if mode == 'full' and diff else 'SKIPPED'),
            'details': f'{len(records)} scoped indicators; ' + ', '.join(f'{k}={v}' for k, v in coverage.items()),
            'findings': findings, 'coverage': coverage, 'records': records,
            'coverage_gap': mode == 'full' and any(v == 'COLLECTION UNAVAILABLE' for v in coverage.values())}
