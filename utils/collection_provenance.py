"""Privacy-preserving, execution-derived collection provenance (schema 1).

The working JSON is operational state, not a duplicate tester-facing report. Only
sanitized command *shapes* are retained. Raw scripts, environment variables,
stdout/stderr and arbitrary positional arguments must never enter this record.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import json
import re
import ntpath

from utils.artifacts import ARTIFACTS, MODULE_ARTIFACT_KEYS
from utils.assessment_layout import artifact_path
from utils.assessment_state import _atomic_json
from utils.assessment_integrity import _atomic_text
from utils.provenance_recipes import RECHECK_RECIPES

_ACTIVE = ContextVar('wca_provenance_session', default=None)
_MODULE = ContextVar('wca_provenance_module', default='Orchestration')
_STATE = 'working/collection_provenance_state.json'
_REPORT = 'collection_provenance.txt'
_HEAD = 'COLLECTION PROVENANCE\n' + '-' * 72 + '\n'
_TAIL_MARKER = '\nCOLLECTION PROVENANCE\n' + '-' * 72 + '\n'
# Only evidence/collector reports receive an inline section. Generated review,
# test plans, summaries, diagnostics, and operational inventories remain clean.
_EVIDENCE_PHASES = frozenset({'static', 'installed_state', 'surface', 'runtime', 'updater_security'})
_NON_EVIDENCE_REPORTS = frozenset({
    'advanced_instrumentation_plan.txt', 'procmon_capture_instructions.txt',
    'attack_surface_test_plan.txt',
})
# External commands are recorded by execution; native Python APIs are described
# as analysis methods, never as hypothetical command-line invocations.
_SAFE_FLAGS = frozenset({'-accepteula', '-quiet', '-minimized', '-terminate', '-v', '-a',
                         '-y', '-q', '-p', '-x', 'x', '-openlog', '-saveas', '-backingfile',
                         '-nologo', '-noprofile', '-noninteractive', '-executionpolicy',
                         'bypass', '-command', '-depth', '-compress'})
_SENSITIVE_FLAGS = re.compile(r'(pass|secret|token|key|auth|credential|cookie)', re.I)
_CMDLET = re.compile(r'\b(?:Get|Select|Where|ForEach|ConvertTo|Test|Export|Import|Measure|Sort|Format)-[A-Za-z][A-Za-z0-9-]*\b')


def safe_command_shape(command) -> str:
    """Show *executed command structure* without persisting arbitrary arguments.

    PowerShell scripts can contain arbitrary customer data. Only recognizable
    cmdlet names are shown; full raw scripts must never be copied to evidence.
    """
    if not isinstance(command, (list, tuple)) or not command:
        return '<COMMAND_UNAVAILABLE>'
    exe = ntpath.basename(str(command[0]).replace('/', '\\'))
    exe = re.sub(r'[^A-Za-z0-9_.+-]', '_', exe)[:60] or '<TOOL>'
    args = [str(a) for a in command[1:]]
    if exe.lower() in {'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'}:
        try:
            idx = next(i for i, a in enumerate(args) if a.lower() == '-command')
            names = list(dict.fromkeys(_CMDLET.findall(' '.join(args[idx+1:]))))[:15]
        except StopIteration:
            names = []
        return exe + ' -NoProfile -NonInteractive -Command <SCRIPT_REDACTED>' + (
            ' [cmdlets: ' + ', '.join(names) + ']' if names else '')
    sanitized = [exe]
    for arg in args[:40]:
        low = arg.lower()
        if low in _SAFE_FLAGS:
            sanitized.append(arg)
        elif low.startswith('-o') and len(arg) > 2 and exe.lower().startswith(('7z', '7za')):
            sanitized.append('-o<OUTPUT_DIR>')
        elif _SENSITIVE_FLAGS.search(low) and arg.startswith('-'):
            sanitized.append('<SENSITIVE_OPTION>')
        elif low.startswith('-') and re.fullmatch(r'-{1,2}[a-zA-Z][\w-]{0,25}', arg):
            sanitized.append(arg)  # only switch name; next value always redacted
        elif re.fullmatch(r'\d+', arg):
            sanitized.append('<NUMBER>')
        elif re.match(r'^https?://', arg, re.I):
            sanitized.append('<URL>')
        else:
            sanitized.append('<ARG>')
    if len(args) > 40:
        sanitized.append('<ADDITIONAL_ARGUMENTS>')
    return ' '.join(sanitized)[:1400]


class Session:
    def __init__(self, root: Path, label: str, *, retain: bool = True):
        self.root = Path(root)
        self.label = label
        self.records = []
        state = self.root / _STATE
        if retain and state.is_file():
            data = json.loads(state.read_text(encoding='utf-8'))
            if data.get('schema_version') != 1 or not isinstance(data.get('records'), list):
                raise ValueError('Collection provenance working state has an invalid schema')
            self.records = list(data['records'])
        self.next_id = 1 + max((int(r['id'].split('-')[-1]) for r in self.records
                                if re.fullmatch(r'PROV-\d{5}', str(r.get('id', '')))), default=0)

    def add(self, *, module, tool, method, status, command=None):
        item = {
            'id': f'PROV-{self.next_id:05d}', 'session': self.label,
            'module': re.sub(r'[^\w .,/()+-]', '', str(module))[:95],
            'tool': re.sub(r'[^A-Za-z0-9_.+ -]', '', str(tool))[:65],
            'method': method, 'execution': status,
        }
        if command is not None:
            item['command'] = safe_command_shape(command)
        self.records.append(item)
        self.next_id += 1
        return item

    def record_command(self, command, code):
        if not isinstance(command, (list, tuple)) or not command:
            return
        exe = ntpath.basename(str(command[0]).replace('/', '\\'))
        status = 'COMPLETED' if code == 0 else ('UNAVAILABLE' if code == 127 else 'TIMED OUT' if code == 124 else 'FAILED')
        self.add(module=_MODULE.get(), tool=exe, method='External executable invocation',
                 status=status, command=command)


@contextmanager
def session(root: Path, label: str, *, retain: bool = True):
    """Stage command records in memory; only finalization writes them to disk."""
    existing = _ACTIVE.get()
    if existing is not None and existing.root == Path(root):
        yield existing
        return
    active = Session(Path(root), label, retain=retain)
    token = _ACTIVE.set(active)
    try:
        yield active
    finally:
        _ACTIVE.reset(token)


@contextmanager
def module_scope(name: str):
    token = _MODULE.set(name)
    try:
        yield
    finally:
        _MODULE.reset(token)


def record_executed(command, returncode):
    active = _ACTIVE.get()
    if active is not None:
        active.record_command(command, returncode)


def record_native_method(module: str, method: str, *, status='COMPLETED', tool='WCA Python'):
    active = _ACTIVE.get()
    if active is not None:
        active.add(module=module, method=re.sub(r'[^\w .,/()+-]', '', method)[:140],
                   tool=tool, status=status)


def _report_modules(filename: str) -> list[str]:
    return [module for module, keys in MODULE_ARTIFACT_KEYS.items()
            if filename in [ARTIFACTS[key]['filename'] for key in keys if key in ARTIFACTS]]


def _is_evidence_report(spec: dict) -> bool:
    return (spec.get('phase') in _EVIDENCE_PHASES and
            spec.get('filename') not in _NON_EVIDENCE_REPORTS)


def _clean_old_header(text: str) -> str:
    """Remove older terminal sections and our own inline block idempotently."""
    text = re.sub(
        r'\n+COLLECTION PROVENANCE\n-{8,}\nTools: [^\n]*\nMethod: [^\n]*\n'
        r'Details: collection_provenance\.txt\s*\Z', '\n', text,
    )
    start = text.find(_HEAD)
    if start >= 0:
        end_marker = 'END COLLECTION PROVENANCE\n'
        end = text.find(end_marker, start)
        if end >= 0:
            prefix = text[:start].rstrip('\n')
            suffix = text[end + len(end_marker):].lstrip('\n')
            text = (prefix + '\n\n' if prefix else '') + suffix
    return text


def _insert_near_title(text: str, block: str) -> str:
    """Keep report title first; place the provenance block before the body."""
    lines = text.splitlines(keepends=True)
    title = next((i for i, line in enumerate(lines[:8]) if line.strip()), None)
    if title is not None:
        for i in range(title + 1, min(title + 5, len(lines))):
            divider = lines[i].strip()
            if len(divider) >= 8 and set(divider) <= {'=', '-'}:
                pos = i + 1
                while pos < len(lines) and not lines[pos].strip():
                    pos += 1
                return ''.join(lines[:pos]) + block + '\n' + ''.join(lines[pos:])
        # Short synthetic/legacy reports without a divider still keep the title.
        pos = title + 1
        while pos < len(lines) and not lines[pos].strip():
            pos += 1
        return ''.join(lines[:pos]).rstrip('\n') + '\n\n' + block + '\n' + ''.join(lines[pos:])
    return block + '\n' + text


def _summary_block(filename: str, refs: list[dict], skipped: bool) -> str:
    if refs:
        tools = list(dict.fromkeys(r['tool'] for r in refs))
        ids = ', '.join(r['id'] for r in refs[:12])
        if len(refs) > 12:
            ids += f' (+{len(refs)-12} in central report)'
        provenance = f'Execution refs : {ids}\nTools          : {", ".join(tools[:8])}'
    else:
        provenance = ('Execution refs : Collection unavailable or skipped; no command recorded' if skipped
                      else 'Execution refs : No invocation attributed; WCA Python processing/analysis')
    lines = [_HEAD.rstrip('\n'), provenance,
             'Audit details  : collection_provenance.txt (report index and execution log)']
    recipe = RECHECK_RECIPES.get(filename)
    if recipe:
        topic, command, limitation = recipe
        lines.extend(['', f'LIVE RECHECK (manual example, NOT the recorded WCA invocation)',
                      f'Verifies       : {topic}', f'Command        : {command}',
                      f'Limitations    : {limitation}'])
    else:
        lines.append('Live recheck  : No validated single-command recipe for this report; follow method and evidence references.')
    lines.extend(['END COLLECTION PROVENANCE', ''])
    return '\n'.join(lines) + '\n'


def _central_report(records: list[dict], reports: list[tuple]) -> str:
    from collections import Counter
    counts = Counter(str(r.get('execution', 'UNKNOWN')) for r in records)
    exceptions = [r for r in records if r.get('execution') not in {'COMPLETED'}]
    lines = [
        'WCA - COLLECTION PROVENANCE', '=' * 88,
        'Purpose: explain where technical evidence came from and how to recheck it.',
        'Execution history is recorded; live recheck commands are independent examples.',
        'Privacy: original PowerShell bodies, sensitive arguments and paths are not retained.',
        'A zero process exit code does not validate a security finding.', '',
        'AT A GLANCE', '-' * 88,
        f'Execution records     : {len(records)}',
        f'Completed             : {counts.get("COMPLETED", 0)}',
        f'Failed                : {counts.get("FAILED", 0)}',
        f'Timed out             : {counts.get("TIMED OUT", 0)}',
        f'Unavailable           : {counts.get("UNAVAILABLE", 0)}',
        f'Evidence reports      : {len(reports)}',
        f'Live recheck recipes  : {sum(name in RECHECK_RECIPES for name, *_ in reports)}', '',
        'COLLECTION ISSUES / NONCOMPLETED EXECUTIONS', '-' * 88,
    ]
    if not exceptions:
        lines.append('None recorded. This does not independently prove complete collection coverage.')
    for r in exceptions:
        lines.append(f'  {r["id"]} | {r["execution"]} | {r["module"]} | {r["tool"]}')
        if r.get('command'):
            lines.append('    Executed shape: ' + r['command'])
    lines += ['', 'RECHECK COMMANDS (MANUAL EXAMPLES - NOT EXECUTED BY WCA)', '-' * 88,
              'Use placeholders for the selected client artifact and run only in an authorized',
              'environment. Recheck output can differ after the application or OS changes.', '']
    for filename, _, _, _ in reports:
        recipe = RECHECK_RECIPES.get(filename)
        if not recipe:
            continue
        topic, cmd, limit = recipe
        lines += [filename, '  Verifies  : ' + topic,
                  '  Command   : ' + cmd, '  Caveat    : ' + limit, '']
    lines += ['EVIDENCE REPORT INDEX', '-' * 88]
    for filename, related, refs, skipped in reports:
        tag = ', '.join(r['id'] for r in refs) if refs else ('NOT COLLECTED / N/A' if skipped else 'Python analysis / no invocation attributed')
        lines.append(f'  {filename} : {tag}')
    lines += ['', 'EXECUTION AUDIT (RECORDED HISTORY; COMMANDS ARE SANITIZED SHAPES)', '-' * 88]
    if not records:
        lines.append('No tool executions or explicit native methods recorded.')
    for r in records:
        lines.append(f'[{r["id"]}] {r["execution"]} | {r["session"]} | {r["module"]} | {r["tool"]}')
        lines.append('  Method    : ' + r['method'])
        if 'command' in r:
            lines.append('  Recorded  : ' + r['command'])
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'

def finalize(root: Path, statuses: dict | None = None, installer=None):
    """Persist operational state and regenerate the two-tier reports.

    Idempotent when called for reviewer-only or derived-report regeneration:
    existing records are reused, with no invented re-executions.
    """
    root = Path(root)
    active = _ACTIVE.get()
    if active is not None and active.root != root:
        raise ValueError('Provenance session assessment mismatch')
    if active is None:
        state_file = root / _STATE
        if not state_file.is_file():
            return  # do not backfill older schema assessments with invented history
        active = Session(root, 'report-only')
    statuses = statuses or {}
    # Privacy boundary: records store only command shapes and conservative method labels.
    _atomic_json(root / _STATE, {'schema_version': 1, 'records': active.records})
    reports = []
    for key, spec in sorted(ARTIFACTS.items()):
        filename = spec['filename']
        if (not filename.endswith('.txt') or '/' in filename or
                filename in {_REPORT, 'artifact_manifest.txt'}):
            continue
        path = artifact_path(root, filename)
        if not path.is_file() or path.is_symlink():
            continue
        original = path.read_text(encoding='utf-8', errors='replace')
        clean = _clean_old_header(original)
        if not _is_evidence_report(spec):
            # A legacy all-report footer must be removed from summaries/plans.
            if clean != original:
                _atomic_text(path, clean)
            continue
        related = _report_modules(filename)
        matched = [r for r in active.records if r.get('module') in related]
        seen = set()
        refs = [r for r in matched if not (r['id'] in seen or seen.add(r['id']))]
        relevant_statuses = [str(statuses.get(mod, {}).get('status', '')).upper() for mod in related]
        skipped = bool(relevant_statuses) and all(status in {'SKIPPED', 'NOT APPLICABLE'} for status in relevant_statuses)
        revised = _insert_near_title(clean, _summary_block(filename, refs, skipped))
        if revised != original:
            _atomic_text(path, revised)
        reports.append((filename, related, refs, skipped))

    _atomic_text(artifact_path(root, _REPORT), _central_report(active.records, reports))
