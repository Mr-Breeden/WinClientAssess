"""WCA v2.2.2 loopback-only GUI adapter.

No new collectors. Mutations are delegated to the v1.9.6-derived BackendService
or to private Python workers, where tester checkpoints are acknowledged in the browser.
This module intentionally has no third-party HTTP dependencies.
"""
from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from utils.backend_service import BackendService
from utils.assessment_state import AssessmentState
from utils.gui_catalog import RecentAssessments
from utils.guided_review import counts
from utils.assessment_integrity import verify_assessment
from utils.guided_review import read_review, validation_commands, _guide
from utils.poc_playbooks import candidate_validation
from utils.privacy import sanitize_report_text
from utils.web_worker import atomic_json
from utils.manual_test_workflow import read_manual_workflow, read_manual_detail, save_manual_decision, testing_queue

PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSETS = PROJECT_ROOT / 'gui'
READ_ACTIONS = frozenset(('capabilities', 'tool_readiness', 'status', 'verify', 'review', 'appendix_readiness'))
WRITE_ACTIONS = frozenset(('save_review', 'export_appendix', 'regenerate_reports'))
REPORT_TYPES = frozenset(('.txt', '.md', '.html'))
MAX_BODY = 32_768
MAX_REPORT = 500_000
HELP_DOCUMENTS = {
    'getting-started': 'getting-started.md',
    'windows-setup': 'windows-environment-setup.md',
    'optional-tools': 'optional-tools.md',
    'gui-guide': 'gui-guide.md',
}


def runtime_history(root: Path, verified: bool = False) -> dict:
    """Load only the small, documented observation summaries. No raw evidence."""
    if not verified and verify_assessment(root).get('status') != 'PASS':
        raise ValueError('Assessment integrity must be PASS to view verified runtime history.')
    history = root / 'working' / 'guided_runtime_observations.json'
    if history.is_symlink() or not history.is_file():
        return {'state': 'NOT RUN', 'total': 0, 'sessions': []}
    if history.stat().st_size > 2_000_000:
        raise ValueError('Runtime history is larger than expected.')
    data = json.loads(history.read_text(encoding='utf-8'))
    sessions = data.get('sessions', []) if isinstance(data, dict) else []
    if not isinstance(sessions, list):
        raise ValueError('Invalid runtime history.')
    rows = []
    for item in sessions[-30:]:
        if not isinstance(item, dict):
            continue
        capture = item.get('capture') or {}
        session = item.get('session') or {}
        counts_data = item.get('counts') or {}
        status = str(capture.get('status') or 'UNKNOWN')[:30]
        rows.append({'captured_at': str(item.get('captured_at') or session.get('stopped_at') or '')[:40],
                     'capture_status': status,
                     'duration_seconds': session.get('capture_duration_seconds', 0),
                     'processing_seconds': session.get('processing_duration_seconds', 0),
                     'events': counts_data.get('procmon_target_events', 0),
                     'target_processes': counts_data.get('target_processes_seen', 0),
                     'new_review_candidates': item.get('new_review_candidates', 0)})
    overall = 'NOT RUN' if not rows else ('COMPLETED' if all(x['capture_status']=='PASS' for x in rows) else 'COMPLETED WITH GAPS')
    return {'state': overall, 'total': len(sessions), 'sessions': list(reversed(rows))}


def overview_snapshot(root: Path, service: BackendService) -> dict:
    """One verified status read, then only lightweight state for display."""
    status = service.execute('status', root)
    if not status.get('ok'):
        return status
    info = status['data']
    review_summary = {'total': 0, 'pending': 0}
    runtime = {'state': 'UNAVAILABLE', 'total': 0, 'sessions': []}
    if info.get('integrity', {}).get('status') == 'PASS':
        review = read_review(root)
        if review:
            counter = counts(review)
            review_summary = {'total': len(review.get('items') or {}),
                              'pending': counter.get('PENDING', 0)}
        runtime = runtime_history(root, verified=True)
    manual = {'total': 0, 'resolved': 0, 'remaining': 0, 'available': False}
    if info.get('integrity', {}).get('status') == 'PASS' and info.get('status') == 'COMPLETED':
        try:
            manual = {**read_manual_workflow(root), 'available': True}
            manual.pop('items', None)
        except (OSError, ValueError, KeyError, TypeError):
            pass
    return {'ok': True, 'code': 'OK', 'message': 'Overview available.',
            'data': {'status': info, 'review': review_summary, 'runtime': runtime, 'manual': manual}}



def sanitize_gui_text(value: object, limit: int = 4000) -> str:
    return sanitize_report_text(str(value or ''))[:limit]


def safe_assessment_root(value: object) -> Path:
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError('Select a valid assessment directory.')
    candidate = Path(value).expanduser()
    if candidate.is_symlink():
        raise ValueError('Symbolic-link assessment directories are not supported.')
    result = candidate.resolve()
    if not result.is_dir():
        raise ValueError('Assessment directory not found.')
    return result


def list_reports(root: Path) -> list[dict]:
    directory = root / 'reports'
    if not directory.is_dir() or directory.is_symlink():
        return []
    entries = []
    for child in directory.iterdir():
        if child.is_symlink() or not child.is_file() or child.suffix.lower() not in REPORT_TYPES:
            continue
        if child.stat().st_size <= MAX_REPORT:
            entries.append({'name': child.name, 'size': child.stat().st_size})
    return sorted(entries, key=lambda item: item['name'].casefold())[:250]


def read_report(root: Path, name: object) -> str:
    if (not isinstance(name, str) or len(name) > 180 or not name
            or name in ('.', '..') or Path(name).name != name
            or '/' in name or '\\' in name or Path(name).suffix.lower() not in REPORT_TYPES):
        raise ValueError('Invalid report name.')
    folder = root / 'reports'
    child = folder / name
    if folder.is_symlink() or child.is_symlink() or not child.is_file():
        raise ValueError('Report unavailable.')
    if child.resolve().parent != folder.resolve() or child.stat().st_size > MAX_REPORT:
        raise ValueError('Report is too large or outside the report directory.')
    return sanitize_gui_text(child.read_text(encoding='utf-8', errors='replace'), MAX_REPORT)



def review_condition_detail(root: Path, identifier: object) -> dict:
    """Return one integrity-verified, session-private review card and its validation plan.

    Unlike the stable read-only backend / CLI response, this GUI-only endpoint
    intentionally includes the selected condition's existing notes. Never return
    the full review state or notes for unrelated candidates.
    """
    if not isinstance(identifier, str) or not 3 <= len(identifier) <= 100:
        raise ValueError('Invalid review candidate.')
    if verify_assessment(root).get('status') != 'PASS':
        raise ValueError('Assessment integrity verification failed.')
    state = read_review(root)
    item = (state or {}).get('items', {}).get(identifier)
    if not isinstance(item, dict) or item.get('id') != identifier:
        raise ValueError('Review condition is no longer available.')
    manual, impact, secure, not_report = _guide(item)
    plan = candidate_validation(item, root)
    # Reuse exactly the manual guidance sources that power assessment_report.html
    # and evidence_guide.txt, without letting the browser execute a command.
    safe = lambda value, n=4500: sanitize_gui_text(value, n)
    commands = list(validation_commands(item, root))[:24]
    return {
        'id': identifier,
        'title': safe(item.get('title'), 500),
        'module': safe(item.get('source_module'), 200),
        'severity': safe(item.get('severity'), 40),
        'status': str(item.get('status') or 'PENDING'),
        'fingerprint': str(item.get('fingerprint') or ''),
        'changed_evidence': bool(item.get('changed_evidence')),
        'component': safe(item.get('component'), 650),
        'matching_events': item.get('occurrence_count', 1),
        'artifacts': [Path(str(a)).name for a in (item.get('artifacts') or [])][:30],
        'test_cases': [safe(case, 80) for case in (item.get('test_cases') or [])][:30],
        'notes': safe(item.get('notes'), 4000),
        'client_notes': safe(item.get('client_notes'), 4000),
        'evidence': safe(item.get('evidence'), 6000),
        'description': safe(item.get('description'), 4500),
        'prerequisites': safe(plan.get('prerequisites')),
        'commands': [safe(command, 3500) for command in commands],
        'manual_validation': safe(manual),
        'poc': {
            'resource': safe(plan.get('poc_resource'), 1200),
            'relative': safe(plan.get('poc_resource_relative'), 400),
            'requires_compilation': safe(plan.get('requires_compilation'), 30),
            'architecture': safe(plan.get('target_architecture'), 100),
            'expected_output': safe(plan.get('expected_output'), 300),
            'build_or_invocation': [safe(x, 2500) for x in plan.get('build_or_invocation', ())][:12],
            'verification': [safe(x, 2500) for x in plan.get('verification', ())][:12],
        },
        'tester_execution': safe(plan.get('tester_execution')),
        'expected_evidence': safe(plan.get('expected_evidence')),
        'impact': safe(impact), 'secure': safe(secure), 'not_report': safe(not_report),
    }


def _validated_job_inputs(payload: dict) -> tuple[Path, list[str], str]:
    """Only existing CLI flags are accepted; never inject arbitrary shell commands."""
    if not str(payload.get('target') or '').strip() or not str(payload.get('output') or '').strip():
        raise ValueError('Target and output directory are required.')
    target = Path(str(payload.get('target'))).expanduser().resolve()
    target_type = str(payload.get('target_type') or 'installable')
    mode = str(payload.get('mode') or 'static')
    name = str(payload.get('name') or '').strip()
    output = Path(str(payload.get('output') or '')).expanduser().resolve()
    primary = str(payload.get('primary_executable') or '').strip()
    if target_type not in ('installable', 'portable') or mode not in ('static', 'full'):
        raise ValueError('Unsupported target type or mode.')
    if not target.exists() or (target_type == 'installable' and (not target.is_file() or target.suffix.lower() not in ('.msi', '.exe'))):
        raise ValueError('Installer or target does not exist.')
    if target_type == 'portable' and not (target.is_dir() or (target.is_file() and target.suffix.lower() == '.exe')):
        raise ValueError('Portable target must be an EXE or an application directory.')
    if not name or len(name) > 100 or not re.fullmatch(r'[\w. -]+', name, re.UNICODE) or name in ('.', '..'):
        raise ValueError('Assessment name must use letters, numbers, spaces, dots, underscores or hyphens.')
    if not output.is_dir() or output.is_symlink():
        raise ValueError('Choose an existing output parent directory.')
    root = output / name
    if root.exists():
        raise ValueError('Assessment output already exists. Choose a new name.')
    if mode == 'full' and os.name != 'nt':
        raise ValueError('Full assessment requires an elevated Windows console.')
    argv = [sys.executable, str(PROJECT_ROOT / 'wca.py'), '--target', str(target),
            '--target-type', target_type, '--assessment-name', name, '--output', str(output),
            '--mode', mode, '--no-gui']
    if target_type == 'portable' and primary:
        argv += ['--primary-executable', primary]
    # All four values are explicit booleans, never user-controlled CLI strings.
    # Absent options retain backwards-compatible defaults for older GUI clients.
    options = {
        'extract_installer': payload.get('extract_installer', True),
        'filesystem_snapshot': payload.get('filesystem_snapshot', True),
        'surface_review': payload.get('surface_review', True),
        'runtime_capture': payload.get('runtime_capture', False),
    }
    if any(type(value) is not bool for value in options.values()):
        raise ValueError('Assessment options must be explicit Yes/No selections.')
    if not options['extract_installer']:
        argv.append('--no-extract')
    if not options['filesystem_snapshot']:
        argv.append('--no-filesystem-snapshot')
    if mode == 'full':
        if options['surface_review']:
            argv.append('--surface-review')
        if options['runtime_capture']:
            argv.append('--runtime-capture')
        # A GUI-only override suppresses *optional* Yes/No prompts and folds
        # network readiness into the mandatory install/activity checkpoint.
        # CLI behavior and its manual choices remain unchanged.
        argv.append('--gui-preselected-options')
    else:
        if options['runtime_capture']:
            raise ValueError('Procmon capture requires full assessment mode.')
        argv.append('--non-interactive')
    return root, argv, mode


class JobManager:
    """One CLI worker per assessment; never launches a target or PoC itself."""
    def __init__(self, version: str = '2.2.2', catalog: RecentAssessments | None = None):
        self.catalog = catalog or RecentAssessments()
        self.version = version
        self.jobs: dict[str, dict] = {}
        self.mutex = threading.Lock()
        self.tempdir = tempfile.TemporaryDirectory(prefix='wca-gui-')

    def start(self, kind: str, payload: dict) -> dict:
        if kind == 'assessment':
            root, argv, mode = _validated_job_inputs(payload)
            interactive = mode == 'full'
        elif kind == 'runtime':
            root = safe_assessment_root(payload.get('assessment'))
            data = BackendService(version=self.version).execute('status', root)
            if (not data['ok'] or data['data'].get('status') != 'COMPLETED'
                    or data['data'].get('framework_version') != self.version
                    or data['data'].get('mode') != 'full'
                    or data['data'].get('integrity', {}).get('status') != 'PASS'):
                raise ValueError('Guided Runtime requires an intact, completed assessment from the current release.')
            argv = [sys.executable, str(PROJECT_ROOT / 'wca.py'), '--guided-runtime', str(root)]
            interactive = True
        elif kind == 'resume':
            root = safe_assessment_root(payload.get('assessment'))
            data = BackendService(version=self.version).execute('status', root)
            if (not data['ok'] or data['data'].get('framework_version') != self.version
                    or 'resume_assessment_cli_only' not in data['data'].get('available_actions', [])):
                raise ValueError('This assessment cannot be resumed safely in this release.')
            argv = [sys.executable, str(PROJECT_ROOT / 'wca.py'), '--resume', str(root), '--no-gui']
            interactive = True
        else:
            raise ValueError('Unsupported CLI operation.')
        key = os.path.normcase(str(root))
        with self.mutex:
            for job in self.jobs.values():
                if job['key'] == key and job['process'].poll() is None:
                    raise ValueError('An operation is already active for this assessment.')
            if len(self.jobs) > 60:
                self.jobs = {jid: j for jid, j in self.jobs.items() if j['process'].poll() is None}
            job_id = secrets.token_hex(12)
            job_dir = Path(self.tempdir.name) / job_id
            job_dir.mkdir(mode=0o700)
            log = job_dir / 'worker.log'
            env = dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1',
                       WCA_WEB_WORKER_DIRECTORY=str(job_dir))
            # All modes run the EXISTING CLI engine, redirected to a private
            # background process. The worker never installs/launches a target.
            # CREATE_NO_WINDOW prevents even a transient console on Windows.
            flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            try:
                with log.open('wb') as output:
                    proc = subprocess.Popen(argv, cwd=str(PROJECT_ROOT),
                                            stdin=subprocess.PIPE, stdout=output,
                                            stderr=subprocess.STDOUT, env=env,
                                            creationflags=flags, close_fds=True)
            except OSError as exc:
                raise ValueError('Unable to start the private assessment worker.') from exc
            try:
                self.catalog.remember(root)
            except (OSError, ValueError):
                pass  # A local history write must never abort an already started worker.
            self.jobs[job_id] = {'process': proc, 'kind': kind, 'key': key, 'assessment': str(root),
                                 'interactive': interactive, 'log': log, 'directory': job_dir,
                                 'sent_checkpoint': '', 'started_at': time.time()}
            return {'id': job_id, 'state': 'RUNNING', 'interactive': interactive,
                    'message': 'Background worker started. Follow checkpoints in this browser.'}

    def list_jobs(self) -> list[dict]:
        with self.mutex:
            jobs = list(self.jobs.items())[-25:]
        return [{'id': ident, 'assessment': job['assessment'], 'kind': job['kind'],
                 'state': 'RUNNING' if job['process'].poll() is None else
                          ('COMPLETED' if job['process'].returncode == 0 else 'FAILED')}
                for ident, job in jobs]

    def respond(self, job_id: str, checkpoint_id: str, answer: str) -> dict:
        with self.mutex:
            job = self.jobs.get(job_id)
            if not job or job['process'].poll() is not None:
                raise ValueError('The assessment job is no longer running.')
            # The worker may remove checkpoint.json as soon as it consumes a
            # response. Check the last acknowledged ID first so a duplicate
            # cannot race that cleanup and produce an inconsistent error.
            if job.get('sent_checkpoint') == checkpoint_id:
                raise ValueError('Checkpoint response was already sent.')
            checkpoint_path = job['directory'] / 'checkpoint.json'
            if not checkpoint_path.is_file():
                raise ValueError('There is no pending tester checkpoint.')
            checkpoint = json.loads(checkpoint_path.read_text(encoding='utf-8'))
            if not secrets.compare_digest(str(checkpoint.get('id')), str(checkpoint_id)):
                raise ValueError('Checkpoint has changed. Refresh the job view.')
            kind = checkpoint.get('kind')
            if not isinstance(answer, str) or len(answer) > 2048:
                raise ValueError('Invalid response.')
            if ((kind == 'continue' and answer != 'continue') or
                (kind == 'confirm' and answer not in ('yes', 'no')) or
                (kind == 'choice' and answer not in checkpoint.get('choices', [])) or
                kind not in ('continue', 'confirm', 'choice', 'text')):
                raise ValueError('Response does not match the pending checkpoint.')
            if job['process'].stdin is None:
                raise ValueError('Worker input channel is unavailable.')
            try:
                job['process'].stdin.write((json.dumps({'id': checkpoint_id, 'answer': answer})+'\n').encode('utf-8'))
                job['process'].stdin.flush()
            except (OSError, BrokenPipeError) as exc:
                raise ValueError('Worker connection closed before response delivery.') from exc
            job['sent_checkpoint'] = checkpoint_id
        return {'accepted': True, 'message': 'Checkpoint response delivered to the worker.'}

    def inspect(self, job_id: str) -> dict:
        with self.mutex:
            job = self.jobs.get(job_id)
        if not job:
            raise ValueError('Unknown job ID.')
        code = job['process'].poll()
        result = {'id': job_id, 'kind': job['kind'], 'assessment': job['assessment'],
                  'state': 'RUNNING' if code is None else ('COMPLETED' if code == 0 else 'FAILED'),
                  'interactive': job['interactive'], 'exit_code': code,
                  'message': 'Follow the browser checkpoints; no additional console is required.'}
        try:
            saved = AssessmentState.load(Path(job['assessment']))
            if saved:
                stages = saved.data.get('stages') or {}
                all_stages = list(stages.items())
                # A completed static run never enters installation/snapshot/runtime
                # phases. Display their eligibility without rewriting its sealed state.
                static_skipped = {'pre_install_snapshot', 'installation_confirmation',
                                  'post_install_snapshot', 'installed_state_analysis',
                                  'runtime_optional', 'surface_optional'} if (
                    saved.data.get('mode') == 'static' and saved.data.get('status') == 'COMPLETED') else set()
                eligible = [(name, entry) for name, entry in all_stages if name not in static_skipped]
                result['progress'] = {
                    'stage': str(saved.data.get('current_stage') or ''),
                    'status': str(saved.data.get('status') or ''),
                    'completed': sum(1 for name, entry in eligible
                                     if isinstance(entry, dict) and entry.get('status') == 'COMPLETED'),
                    'total': len(eligible),
                    'not_applicable': len(all_stages) - len(eligible),
                    'message': sanitize_gui_text(saved.data.get('last_message'), 200),
                }
        except (OSError, ValueError, TypeError):
            pass
        checkpoint_path = job['directory'] / 'checkpoint.json'
        if code is None and checkpoint_path.is_file():
            try:
                cp = json.loads(checkpoint_path.read_text(encoding='utf-8'))
                if isinstance(cp, dict) and cp.get('kind') in ('continue', 'confirm', 'choice', 'text'):
                    result['checkpoint'] = {k: cp[k] for k in ('id', 'kind', 'message', 'default', 'choices', 'capture_ready') if k in cp}
                    result['checkpoint']['submitted'] = job.get('sent_checkpoint') == cp['id']
            except (OSError, ValueError, KeyError):
                pass
        telemetry = job['directory'] / 'telemetry.json'
        if code is None and telemetry.is_file():
            try:
                result['telemetry'] = json.loads(telemetry.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                pass
        if job['log'].exists():
            with job['log'].open('rb') as stream:
                stream.seek(max(0, job['log'].stat().st_size - 8000))
                result['log'] = sanitize_gui_text(stream.read().decode('utf-8', errors='replace'), 8000)
        return result

    def close(self):
        # Do not kill manually controlled assessment operations when closing UI.
        try:
            self.tempdir.cleanup()
        except OSError:
            pass


def build_handler(*, token: str, version: str, jobs: JobManager, port: int,
                  catalog: RecentAssessments | None = None):
    """Handler factory isolates per-process auth state for testability."""
    service = BackendService(version=version)
    catalog = catalog or (jobs.catalog if jobs is not None else RecentAssessments())

    def safe_action_error(route: str, payload: dict | None, exc: Exception) -> dict:
        """Stable, non-sensitive diagnostics without exposing local paths or notes."""
        operations = {'/api/manual-tests': 'Manual test decision', '/api/mutate': 'Assessment maintenance', '/api/select': 'Open assessment',
                      '/api/start': 'Start assessment job', '/api/job/respond': 'Worker checkpoint',
                      '/api/pick': 'Browse for a file or folder'}
        operation = operations.get(route, 'GUI action')
        if route == '/api/mutate' and isinstance(payload, dict):
            operation = {'save_review': 'Guided Review save', 'export_appendix': 'Client Appendix export',
                         'regenerate_reports': 'Derived report regeneration'}.get(
                         payload.get('action'), 'Assessment maintenance')
        if route == '/api/start' and isinstance(payload, dict) and payload.get('kind') == 'runtime':
            operation = 'Start Guided Runtime'
        value = str(exc).lower() if isinstance(exc, ValueError) else ''
        if 'checkpoint has changed' in value or 'already sent' in value or 'no pending tester checkpoint' in value:
            code, message, guidance = ('CHECKPOINT_CHANGED', 'The pending checkpoint changed or was already answered.',
                                       'Refresh the active job before responding again.')
        elif route == '/api/start' and isinstance(payload, dict) and payload.get('kind') == 'assessment' and 'assessment output already exists' in value:
            code, message, guidance = ('ASSESSMENT_ALREADY_EXISTS',
                                       'An assessment with this name already exists in the selected output folder.',
                                       'Choose a different assessment name or open the existing assessment from Recent Assessments.')
        elif route == '/api/start' and isinstance(payload, dict) and payload.get('kind') == 'assessment' and ('installer or target does not exist' in value or 'portable target must' in value):
            code, message, guidance = ('TARGET_NOT_FOUND',
                                       'The selected installer or application path is missing or unsupported.',
                                       'Browse to an existing MSI, EXE, or supported portable application directory.')
        elif route == '/api/start' and isinstance(payload, dict) and payload.get('kind') == 'assessment' and 'existing output parent directory' in value:
            code, message, guidance = ('OUTPUT_DIRECTORY_INVALID',
                                       'The selected assessment output folder does not exist or is not eligible.',
                                       'Choose an existing writable parent folder for the new assessment.')
        elif route == '/api/start' and isinstance(payload, dict) and payload.get('kind') == 'assessment' and 'assessment name must use' in value:
            code, message, guidance = ('ASSESSMENT_NAME_INVALID',
                                       'The assessment name contains unsupported characters or exceeds the allowed length.',
                                       'Use letters, numbers, spaces, dots, underscores or hyphens (maximum 100 characters).')
        elif route == '/api/start' and isinstance(payload, dict) and payload.get('kind') == 'assessment' and 'target and output directory are required' in value:
            code, message, guidance = ('ASSESSMENT_INPUT_REQUIRED',
                                       'Both a target and an assessment output folder are required.',
                                       'Select the target and an existing output parent folder.')
        elif route == '/api/tool-configuration' and isinstance(exc, ValueError):
            if 'filename does not match' in value:
                code, message, guidance = ('TOOL_EXECUTABLE_MISMATCH',
                    'The selected executable does not match the tool name.',
                    'Choose the supported executable for the selected tool.')
            elif 'existing absolute executable file path' in value or 'supported executable or launcher' in value:
                code, message, guidance = ('TOOL_EXECUTABLE_INVALID',
                    'The tool path must identify an existing supported executable.',
                    'Use Browse to select the executable itself, not its containing folder.')
            elif 'configuration' in value:
                code, message, guidance = ('TOOL_CONFIG_INVALID',
                    'The local tool configuration could not be verified.',
                    'Check tool_paths.json for malformed content, symbolic links or access problems.')
            else:
                code, message, guidance = ('TOOL_OVERRIDE_REJECTED',
                    'The tool override could not be saved or verified.',
                    'Confirm the selected executable path, then retry.')
        elif 'already active' in value:
            code, message, guidance = ('ASSESSMENT_BUSY', 'Another operation is active for this assessment.',
                                       'Open the Assessment Worker to inspect its progress.')
        elif 'current release' in value or 'cannot be resumed' in value:
            code, message, guidance = ('VERSION_OR_RECOVERY_BLOCKED',
                                       'The selected assessment is not eligible for this operation.',
                                       'Review assessment version, lifecycle, and integrity in Assessment Management.')
        elif 'integrity' in value or 'structured wca assessment' in value:
            code, message, guidance = ('ASSESSMENT_NOT_ELIGIBLE',
                                       "The assessment did not pass this action's prerequisites.",
                                       'Verify assessment integrity and review the required state.')
        elif isinstance(exc, OSError):
            code, message, guidance = ('LOCAL_IO_ERROR', 'A local file or Windows operation was unavailable.',
                                       'Check permissions and current integrity before attempting the action again.')
        else:
            code, message, guidance = ('ACTION_REJECTED', 'The requested action was not accepted.',
                                       'Check the selected assessment, requested values, and operation eligibility.')
        return {'ok': False, 'code': code, 'operation': operation, 'outcome': 'NOT CONFIRMED',
                'message': message, 'next_step': guidance}

    class GUIHandler(BaseHTTPRequestHandler):
        server_version = 'WCA-GUI'
        sys_version = ''

        def log_message(self, fmt, *args):
            # No raw browser query strings, filesystem paths, or user data in logs.
            return

        def _headers(self, status: int, content_type: str):
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

        def _send(self, status: int, payload: bytes, content_type: str = 'application/json; charset=utf-8'):
            try:
                self._headers(status, content_type)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                # A browser navigating away, reload, or endpoint security can
                # close a local socket while a response is in flight. The
                # operation has already finished; do not write a second error
                # reply into the same broken connection.
                self.close_connection = True

        def _json(self, data: dict, status: int = 200):
            self._send(status, json.dumps(data, ensure_ascii=True, sort_keys=True).encode('utf-8'))

        def _trusted(self, need_token: bool = True) -> bool:
            host = self.headers.get('Host', '').lower().strip()
            valid_hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
            if host not in valid_hosts:
                return False
            origin = self.headers.get('Origin')
            if origin and origin.lower().rstrip('/') != f'http://{host}':
                return False
            if self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site':
                return False
            if need_token and not hmac.compare_digest(self.headers.get('X-WCA-Token', ''), token):
                return False
            return True

        def _get_params(self) -> tuple[str, dict]:
            parsed = urlsplit(self.path)
            return parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        def do_GET(self):
            route, query = self._get_params()
            if not self._trusted(need_token=route.startswith('/api/')):
                self._json({'ok': False, 'message': 'Forbidden.'}, 403)
                return
            try:
                if route == '/':
                    # The initial HTML contains NO session credential. Only the
                    # private launch-URL fragment carries it; HTTP never sees
                    # URL fragments, which prevents drive-by local token harvest.
                    page = (ASSETS / 'index.html').read_text(encoding='utf-8')
                    page = page.replace('__WCA_BOOTSTRAP__', json.dumps({'version': version}))
                    self._send(200, page.encode('utf-8'), 'text/html; charset=utf-8')
                    return
                if route in ('/app.js', '/app.css'):
                    typ = 'application/javascript; charset=utf-8' if route.endswith('js') else 'text/css; charset=utf-8'
                    self._send(200, (ASSETS / route.lstrip('/')).read_bytes(), typ)
                    return
                if route == '/api/backend':
                    action = query.get('action', '')
                    if action not in READ_ACTIONS:
                        raise ValueError('Unsupported read-only operation.')
                    result = service.execute(action, query.get('assessment'))
                    self._json(result, status=200 if result['ok'] else 409)
                    return
                if route == '/api/overview':
                    root = safe_assessment_root(query.get('assessment'))
                    self._json(overview_snapshot(root, service))
                    return
                if route == '/api/recent':
                    self._json({'ok': True, 'assessments': catalog.list_recent(jobs.list_jobs())})
                    return
                if route == '/api/client-notes':
                    from utils.client_appendix import client_note_preview
                    root = safe_assessment_root(query.get('assessment'))
                    self._json({'ok': True, 'notes': client_note_preview(root)})
                    return
                if route == '/api/manual-tests':
                    root = safe_assessment_root(query.get('assessment'))
                    self._json({'ok': True, 'data': read_manual_workflow(root)})
                    return
                if route == '/api/manual-test':
                    root = safe_assessment_root(query.get('assessment'))
                    self._json({'ok': True, 'data': read_manual_detail(root, query.get('case_id'))})
                    return
                if route == '/api/runtime-history':
                    root = safe_assessment_root(query.get('assessment'))
                    self._json({'ok': True, 'history': runtime_history(root)})
                    return
                if route == '/api/tool-configuration':
                    from utils.tool_configuration import configured_tools
                    self._json({'ok': True, 'tools': configured_tools()})
                    return
                if route == '/api/tool-versions':
                    from utils.tool_versions import detected_versions
                    self._json({'ok': True, 'tools': detected_versions()})
                    return
                if route == '/api/about':
                    from utils.backend_service import API_SCHEMA
                    self._json({'ok': True, 'framework': 'WCA', 'version': version,
                                'backend_schema': API_SCHEMA, 'methodology': '1.9',
                                'artifact_catalog': '1.9', 'python_version': sys.version.split()[0],
                                'external_versions': 'Not verified. See Tool Readiness for detection status.'})
                    return
                if route == '/api/help':
                    name = HELP_DOCUMENTS.get(query.get('doc', ''))
                    if not name:
                        raise ValueError('Unsupported help document.')
                    source = PROJECT_ROOT / 'docs' / name
                    self._json({'ok': True, 'name': name,
                                'content': sanitize_gui_text(source.read_text(encoding='utf-8'), 90000)})
                    return
                if route == '/api/review-detail':
                    root = safe_assessment_root(query.get('assessment'))
                    self._json({'ok': True, 'detail': review_condition_detail(root, query.get('id'))})
                    return
                if route == '/api/reports':
                    root = safe_assessment_root(query.get('assessment'))
                    self._json({'ok': True, 'reports': list_reports(root)})
                    return
                if route == '/api/report':
                    root = safe_assessment_root(query.get('assessment'))
                    self._json({'ok': True, 'name': str(query.get('name') or ''),
                                'content': read_report(root, query.get('name'))})
                    return
                if route == '/api/jobs':
                    self._json({'ok': True, 'jobs': jobs.list_jobs()})
                    return
                if route == '/api/job':
                    self._json({'ok': True, 'job': jobs.inspect(query.get('id', ''))})
                    return
                self._json({'ok': False, 'message': 'Not found.'}, 404)
            except (ValueError, OSError, UnicodeError):
                self._json({'ok': False, 'message': 'Requested information unavailable.'}, 400)

        def do_POST(self):
            route, _ = self._get_params()
            if not self._trusted():
                self._json({'ok': False, 'message': 'Forbidden.'}, 403)
                return
            length = self.headers.get('Content-Length', '')
            if not length.isdecimal() or not (0 < int(length) <= MAX_BODY):
                self._json({'ok': False, 'message': 'Invalid request size.'}, 413)
                return
            payload = None
            try:
                payload = json.loads(self.rfile.read(int(length)).decode('utf-8'))
                if not isinstance(payload, dict):
                    raise ValueError('Invalid request.')
                if route == '/api/mutate':
                    action = payload.get('action')
                    if action not in WRITE_ACTIONS or payload.get('confirmed') is not True:
                        raise ValueError('An explicit tester-confirmed action is required.')
                    kwargs = {'confirmed': True}
                    if action == 'save_review':
                        kwargs.update(candidate_id=payload.get('candidate_id'),
                                      disposition=payload.get('disposition'),
                                      fingerprint=payload.get('fingerprint'),
                                      notes=payload.get('notes', ''),
                                      client_notes=payload.get('client_notes', ''))
                        if not isinstance(kwargs['notes'], str) or len(kwargs['notes']) > 8000:
                            raise ValueError('Invalid review notes.')
                    if action == 'export_appendix':
                        kwargs['output'] = payload.get('output')
                    response = service.execute(action, payload.get('assessment'), **kwargs)
                    if not response['ok']:
                        # The backend owns the safe result code; label the requested
                        # operation so the GUI does not show an anonymous toast.
                        response = {**response,
                            'operation': {'save_review': 'Guided Review save',
                                          'export_appendix': 'Client Appendix export',
                                          'regenerate_reports': 'Derived report regeneration'}[action],
                            'outcome': 'NOT CONFIRMED',
                            'next_step': 'Verify the current assessment state and integrity before retrying.'}
                    self._json(response, 200 if response['ok'] else 409)
                    return
                if route == '/api/manual-tests':
                    if payload.get('confirmed') is not True:
                        raise ValueError('Explicit tester confirmation required.')
                    root = safe_assessment_root(payload.get('assessment'))
                    saved = save_manual_decision(root, case_id=payload.get('case_id'),
                        fingerprint=payload.get('fingerprint'), status=payload.get('status'),
                        notes=payload.get('notes', ''),
                        evidence_reference=payload.get('evidence_reference', ''),
                        client_notes=payload.get('client_notes', ''),
                        current_version=version)
                    self._json({'ok': True, 'message': 'Manual test decision saved and integrity verified.',
                                'data': saved})
                    return
                if route == '/api/tool-configuration':
                    if payload.get('confirmed') is not True:
                        raise ValueError('Explicit tester confirmation required.')
                    from utils.tool_configuration import configure_tool
                    configure_tool(payload.get('name'), payload.get('path'))
                    self._json({'ok': True, 'message': 'Tool configuration saved locally. Refresh Tool Readiness to verify detection.'})
                    return
                if route == '/api/select':
                    root = safe_assessment_root(payload.get('assessment'))
                    if AssessmentState.load(root) is None:
                        raise ValueError('Not a structured WCA assessment.')
                    catalog.remember(root)
                    self._json({'ok': True, 'message': 'Assessment remembered locally.'})
                    return
                if route == '/api/start':
                    if payload.get('confirmed') is not True:
                        raise ValueError('Start requires an explicit tester action.')
                    job = jobs.start(str(payload.get('kind') or ''), payload)
                    self._json({'ok': True, 'job': job}, 201)
                    return
                if route == '/api/job/respond':
                    if payload.get('confirmed') is not True:
                        raise ValueError('Tester must explicitly submit the checkpoint.')
                    receipt = jobs.respond(str(payload.get('id') or ''),
                                           str(payload.get('checkpoint_id') or ''),
                                           payload.get('answer'))
                    self._json({'ok': True, **receipt})
                    return
                if route == '/api/pick':
                    kind = payload.get('kind')
                    if os.name != 'nt' or kind not in ('file', 'folder'):
                        raise ValueError('Native picker unavailable.')
                    # Tk must own its dialog on the *main* thread of a dedicated
                    # interpreter. ThreadingHTTPServer request threads cannot use
                    # Tk dialogs reliably on Windows (RuntimeError: main thread).
                    from utils.native_picker import pick_native_path
                    path = pick_native_path(kind)
                    self._json({'ok': True, 'path': path})
                    return
                self._json({'ok': False, 'message': 'Not found.'}, 404)
            except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
                self._json(safe_action_error(route, payload, exc), 400)

    return GUIHandler


def make_server(port: int = 9001, *, version: str = '2.2.2', jobs: JobManager | None = None,
                token: str | None = None, catalog: RecentAssessments | None = None) -> ThreadingHTTPServer:
    if not 0 <= port <= 65535:
        raise ValueError('Invalid port.')
    if catalog is None:
        catalog = jobs.catalog if jobs is not None else RecentAssessments()
    if jobs is None:
        jobs = JobManager(version=version, catalog=catalog)
    secret = token or secrets.token_urlsafe(32)
    # Never bind to 0.0.0.0, a LAN interface, or an externally supplied host.
    server = ThreadingHTTPServer(('127.0.0.1', port), build_handler(token=secret,
                                     version=version, jobs=jobs, port=port, catalog=catalog))
    server.daemon_threads = True
    # Ephemeral test port 0 needs the actual bound port for Host/Origin checking.
    if port == 0:
        server.RequestHandlerClass = build_handler(token=secret, version=version,
                                                   jobs=jobs, port=server.server_port, catalog=catalog)
    server.wca_token = secret
    server.wca_jobs = jobs
    return server


def serve_gui(port: int = 9001, version: str = '2.2.2'):
    server = make_server(port=port, version=version)
    url = f'http://127.0.0.1:{server.server_port}/#session={server.wca_token}'
    print(f'WCA v{version} private GUI session URL: {url}')
    print('Treat this URL as an access credential for this local GUI session.')
    print('Loopback only. Assessment actions require explicit tester input.')
    print('Press Ctrl+C to stop the GUI server. Active workers use private pipes and fail closed if disconnected.')
    try:
        webbrowser.open_new_tab(url)
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print('\nWCA GUI server stopped.')
    finally:
        server.server_close()
        # Do not delete a static worker's live log while it is still running.
        if not any(job['process'].poll() is None for job in server.wca_jobs.jobs.values()):
            server.wca_jobs.close()
