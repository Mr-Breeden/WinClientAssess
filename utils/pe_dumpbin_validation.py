"""Tester-invoked, read-only PE metadata validation using Microsoft DUMPBIN.

No original WCA assessment artifact is written. All execution and outputs are
outside the verified assessment. No shell / CMD interpolation is used.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time

from utils import tool_detection

MAX_SELECTED = 150
MAX_RAW_OUTPUT = 2_000_000
TIMEOUT_PER_FILE = 35


def parse_cfg_dumpbin(output: str, *, success: bool = True) -> dict:
    """Report what PE metadata says, not runtime mitigation effectiveness."""
    text = str(output or '')
    if not success or not re.search(r'(?im)^\s*PE signature found\s*$', text):
        return {'guard': None, 'instrumented': None, 'fid': None,
                'result': 'INCONCLUSIVE', 'reason': 'DUMPBIN failed or did not provide valid PE headers.'}
    lines = text.splitlines()
    header_index = next((i for i, line in enumerate(lines)
                         if re.search(r'(?i)\bDLL characteristics\s*$', line)), None)
    guard = None
    if header_index is not None:
        # DUMPBIN prints DLL characteristics immediately after this numeric line.
        section = lines[header_index+1:header_index+20]
        for entry in section:
            if re.search(r'(?i)\bsize of stack reserve\b|\bnumber of directories\b|\bloader flags\b', entry):
                break
            if re.fullmatch(r'\s*Guard\s*', entry, flags=re.I):
                guard = True
        if guard is None:
            guard = False
    flags_index = next((i for i, line in enumerate(lines) if re.search(r'(?i)\bGuard Flags\s*$', line)), None)
    instrumented = fid = None
    if flags_index is not None:
        section = lines[flags_index+1:flags_index+15]
        for entry in section:
            if re.search(r'(?i)\bCode Integrity Flags\s*$', entry):
                break
            if re.search(r'(?i)^\s*CF instrumented\s*$', entry):
                instrumented = True
            if re.search(r'(?i)^\s*FID table present\s*$', entry):
                fid = True
        instrumented = bool(instrumented)
        fid = bool(fid)
    else:
        # A parsed PE without load-config Guard Flags cannot prove CFG setup.
        instrumented = False
        fid = False
    if guard is None:
        result = 'INCONCLUSIVE'
        reason = 'DUMPBIN did not show a recognizable DLL characteristics section.'
    elif guard and instrumented and fid:
        result = 'VERIFIED_METADATA'
        reason = 'All three documented CFG metadata indicators are present; runtime policy is not established.'
    else:
        result = 'REVIEW_REQUIRED'
        reason = 'One or more CFG metadata indicators are missing. Assess applicability before reporting.'
    return {'guard': guard, 'instrumented': instrumented, 'fid': fid, 'result': result, 'reason': reason}


def _evidence_root(assessment_root: Path) -> Path:
    """Create output adjacent to, never inside, the integrity-protected assessment."""
    assessment_root = assessment_root.resolve(strict=True)
    parent = assessment_root.parent
    target = parent / (assessment_root.name + '-TC-PE-001-DUMPBIN')
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError('Manual evidence directory is unsafe or unavailable.')
    target.mkdir(mode=0o700, exist_ok=True)
    if target.resolve() == assessment_root or assessment_root in target.resolve().parents:
        raise ValueError('Manual evidence directory cannot be inside the assessment.')
    return target


def _safe_filename(row: dict) -> str:
    base = str(row['path']).replace('/', '\\').split('\\')[-1]
    base = re.sub(r'[^a-zA-Z0-9_.-]', '_', base)[:90].strip('.') or 'PE'
    return f"TC-PE-001-{row['id']}-{base}_dump.txt"


def _run_one(dumpbin: Path, row: dict, directory: Path) -> dict:
    path = Path(row['path'])
    filename = _safe_filename(row)
    result = {'id': row['id'], 'name': path.name, 'raw_file': '',
              'guard': None, 'instrumented': None, 'fid': None, 'result': 'INCONCLUSIVE', 'reason': ''}
    if not path.is_file() or path.is_symlink():
        result['reason'] = 'Source PE file unavailable or symbolic link; original assessment not modified.'
        return result
    # A direct executable invocation avoids CMD injection and does not require
    # a Developer Command Prompt; loader/setup errors are reported as inconclusive.
    try:
        completed = subprocess.run([str(dumpbin), '/headers', '/loadconfig', str(path)],
                                   capture_output=True, timeout=TIMEOUT_PER_FILE, check=False,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        result['reason'] = 'DUMPBIN could not run. Check Tool Readiness / VC dependencies, or use the manual Developer CMD method. ' + type(exc).__name__
        return result
    data = completed.stdout + b'\n' + completed.stderr
    if len(data) > MAX_RAW_OUTPUT:
        result['reason'] = 'DUMPBIN output exceeded the safety limit; inspect manually.'
        return result
    text = data.decode('utf-8', errors='replace')
    with (directory / filename).open('x', encoding='utf-8', newline='\n') as fd:
        fd.write(text)
    result['raw_file'] = str(directory / filename)
    flags = parse_cfg_dumpbin(text, success=completed.returncode == 0)
    result.update(flags)
    result['exit_code'] = completed.returncode
    return result


def selected_pe_rows(rows: list[dict], mode: str, identifier: str = '') -> list[dict]:
    if mode not in ('all', 'flagged', 'single'):
        raise ValueError('Select All, flagged mitigation headers, or one PE entry.')
    valid = [r for r in rows if not r.get('error') or r.get('error') == 'None']
    if mode == 'flagged':
        valid = [r for r in valid if any(r.get(k) == 'False' for k in ('cfg', 'aslr', 'dep'))]
    elif mode == 'single':
        valid = [r for r in valid if r['id'] == identifier]
    if not valid:
        raise ValueError('No applicable analyzed PE entries for the selected scope.')
    if len(valid) > MAX_SELECTED:
        raise ValueError(f'Selection exceeds the {MAX_SELECTED}-file per-run limit; choose flagged or a single file.')
    return valid


class PeDumpbinJobs:
    """In-memory authenticated GUI jobs; never part of assessment evidence/state."""
    def __init__(self):
        self.mutex = threading.RLock()
        self.jobs: dict[str, dict] = {}

    def start(self, root: Path, rows: list[dict], mode: str, identifier: str) -> dict:
        selected = selected_pe_rows(rows, mode, identifier)
        detection = tool_detection.detect_tools().get('DUMPBIN') or {}
        dumpbin = Path(str(detection.get('path') or ''))
        if (not detection.get('found') or dumpbin.name.casefold() != 'dumpbin.exe'
                or not dumpbin.is_file() or dumpbin.is_symlink()):
            raise ValueError('DUMPBIN is not ready. Configure a valid dumpbin.exe in Tool Readiness.')
        # Establish safe output *before* queuing; no modifications to protected files.
        parent = _evidence_root(root)
        with self.mutex:
            for job in self.jobs.values():
                if job['assessment'] == str(root) and job['state'] == 'RUNNING':
                    raise ValueError('A PE/DUMPBIN verification is already running for this assessment.')
            if len(self.jobs) >= 30:
                self.jobs = dict(list(self.jobs.items())[-15:])
            ident = secrets.token_hex(12)
            folder = parent / ('Run-' + time.strftime('%Y%m%d-%H%M%S') + '-' + ident[:6])
            folder.mkdir(mode=0o700)
            job = {'id': ident, 'assessment': str(root), 'state': 'RUNNING',
                   'done': 0, 'total': len(selected), 'rows': [], 'folder': str(folder),
                   'summary': '', 'error': ''}
            self.jobs[ident] = job
        thread = threading.Thread(target=self._process, args=(ident, dumpbin, selected, folder), daemon=True)
        thread.start()
        return self.inspect(ident, root)

    def inspect(self, ident: str, root: Path) -> dict:
        with self.mutex:
            job = self.jobs.get(str(ident))
            if not job or job['assessment'] != str(root):
                raise ValueError('PE verification job not found for the selected assessment.')
            return {key: value for key, value in job.items() if key != 'assessment'} | {'rows': [dict(r) for r in job['rows']]}

    def package(self, ident: str, root: Path) -> tuple[bytes, str]:
        """Zip tester-invoked evidence using WCA's own readable job folder."""
        from io import BytesIO
        from zipfile import ZipFile, ZIP_DEFLATED
        job = self.inspect(ident, root)
        if job['state'] == 'RUNNING':
            raise ValueError('Wait for DUMPBIN verification to finish before packaging.')
        folder = Path(job['folder'])
        expected = _evidence_root(root)
        if folder.parent.resolve() != expected.resolve() or folder.is_symlink() or not folder.is_dir():
            raise ValueError('DUMPBIN evidence directory is unavailable or unsafe.')
        files = [f for f in folder.iterdir() if f.is_file() and not f.is_symlink() and f.suffix.lower() == '.txt']
        raw = [f for f in files if f.name.endswith('_dump.txt')]
        if not raw:
            raise ValueError('No raw DUMPBIN output files exist; an empty ZIP will not be generated.')
        if len(files) > MAX_SELECTED + 5 or sum(f.stat().st_size for f in files) > 120_000_000:
            raise ValueError('DUMPBIN evidence exceeds safe packaging bounds.')
        buf = BytesIO()
        with ZipFile(buf, 'w', ZIP_DEFLATED) as z:
            for item in sorted(files):
                z.write(item, item.name)
        return buf.getvalue(), f'{root.name}-TC-PE-001-DUMPBIN.zip'

    def _process(self, ident: str, dumpbin: Path, rows: list[dict], directory: Path) -> None:
        try:
            results = []
            for row in rows:
                result = _run_one(dumpbin, row, directory)
                results.append(result)
                with self.mutex:
                    job = self.jobs[ident]
                    job['rows'] = list(results)
                    job['done'] = len(results)
            title = ['WCA TC-PE-001 — INDEPENDENT DUMPBIN CFG METADATA VALIDATION',
                     'Tester-invoked read-only checks; no original assessment artifact modified.',
                     'All paths and raw outputs are local engagement evidence, NOT sanitized client deliverables.',
                     'VERIFIED_METADATA proves all three PE metadata markers, not runtime mitigation efficacy.',
                     'REVIEW_REQUIRED is not a confirmed vulnerability. Missing FID may be context-dependent.', '']
            for row in results:
                def state(x):
                    return 'PRESENT' if x is True else 'ABSENT' if x is False else 'UNKNOWN'
                title += [f"[{row['id']}] {row['name']}",
                          f"  Guard (PE header) : {state(row['guard'])}",
                          f"  CF instrumented   : {state(row['instrumented'])}",
                          f"  FID table present : {state(row['fid'])}",
                          f"  Result            : {row['result']}",
                          f"  Interpretation    : {row['reason']}",
                          f"  Raw output        : {row['raw_file'] or '(not created)'}", '']
            summary = directory / 'TC-PE-001-CFG-Summary.txt'
            with summary.open('x', encoding='utf-8', newline='\n') as fd:
                fd.write('\n'.join(title) + '\n')
            raw_count = sum(bool(row.get('raw_file')) for row in results)
            with self.mutex:
                self.jobs[ident].update(
                    state='COMPLETED' if raw_count else 'INCOMPLETE',
                    summary=str(summary),
                    error='' if raw_count else 'No raw DUMPBIN files were created; inspect the summary and Tool Readiness before exporting.'
                )
        except Exception as exc:
            with self.mutex:
                self.jobs[ident].update(state='FAILED', error='PE verification failed: ' + type(exc).__name__)
