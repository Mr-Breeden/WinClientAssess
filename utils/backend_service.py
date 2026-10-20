"""WCA v2.2.1 in-process backend contract for future local GUI adapters.

The loopback GUI adapter is separate; no target launch or automatic PoC invocation.
The JSON-safe envelopes intentionally exclude raw manifest paths, secrets,
source code, tester notes and private tool paths. Every mutation is explicit.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from utils.assessment_integrity import create_manifest, regenerate_derived_reports, verify_assessment
from utils.assessment_state import AssessmentState, describe_assessment
from utils.client_appendix import export_client_appendix, export_readiness
from utils.guided_review import DISPOSITIONS, counts, read_review, save_decision
from utils.operation_lock import AssessmentBusyError, assessment_operation
from utils.privacy import sanitize_report_text
from utils.review_transaction import guarded_review_commit, ReviewUpdateRolledBack, ReviewUpdateRollbackFailed
from utils.tool_detection import detect_tools

API_SCHEMA = '1.0'
SUPPORTED_TARGETS = ('installable', 'portable')
SUPPORTED_MODES = ('static', 'full')


class BackendError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _safe(value: object) -> str:
    return sanitize_report_text(str(value or ''))


def envelope(ok: bool, code: str, message: str, data: dict | None = None,
             errors: list[dict] | None = None) -> dict[str, Any]:
    """Stable JSON-safe shape; no embedded Path/Counter/exception objects."""
    return {'schema': API_SCHEMA, 'ok': bool(ok), 'code': code, 'message': _safe(message),
            'data': data if data is not None else {}, 'errors': errors or []}


def capabilities(version: str = '2.2.1') -> dict[str, Any]:
    return {
        'framework': 'WCA', 'version': version, 'api_schema': API_SCHEMA,
        'target_types': list(SUPPORTED_TARGETS), 'assessment_modes': list(SUPPORTED_MODES),
        'review_dispositions': list(DISPOSITIONS),
        'interface': {'cli': True, 'in_process_backend': True, 'http_server': True, 'gui': True},
        'operations': {
            'capabilities': {'requires_assessment': False, 'mutates': False},
            'tool_readiness': {'requires_assessment': False, 'mutates': False},
            'status': {'requires_assessment': True, 'mutates': False},
            'verify': {'requires_assessment': True, 'mutates': False},
            'review': {'requires_assessment': True, 'mutates': False},
            'appendix_readiness': {'requires_assessment': True, 'mutates': False},
            'save_review': {'requires_assessment': True, 'mutates': True, 'requires_explicit_tester_action': True},
            'export_appendix': {'requires_assessment': True, 'mutates': True, 'requires_explicit_tester_action': True},
            'regenerate_reports': {'requires_assessment': True, 'mutates': True, 'requires_explicit_tester_action': True},
            'run_assessment': {'availability': 'cli_and_gui_worker', 'mutates': True, 'requires_explicit_tester_action': True, 'requires_tester_control': True},
            'guided_runtime': {'availability': 'cli_and_gui_worker', 'mutates': True, 'requires_explicit_tester_action': True, 'requires_tester_control': True},
            'resume_assessment': {'availability': 'cli_and_gui_worker', 'mutates': True, 'requires_explicit_tester_action': True, 'requires_tester_control': True},
        },
        'migration_policy': 'read_only_legacy; no_silent_cross_version_resume_or_conversion',
        'safety': {'automatic_target_execution': False, 'automatic_poc_execution': False,
                   'appendix_requires_integrity_and_review': True},
    }


def _require_root(root: Path | None) -> Path:
    if root is None:
        raise BackendError('ASSESSMENT_REQUIRED', 'Specify the assessment directory for this action.')
    requested = Path(root).expanduser()
    if requested.is_symlink():
        raise BackendError('ASSESSMENT_UNTRUSTED', 'Assessment directory cannot be a symbolic link.')
    root = requested.resolve()
    if not root.is_dir():
        raise BackendError('ASSESSMENT_NOT_FOUND', 'Assessment directory does not exist or is untrusted.')
    return root


def _verification_summary(result: dict) -> dict:
    return {'status': result.get('status', 'FAIL'), 'repairable': bool(result.get('repairable')),
            'checks': [{'name': _safe(c.get('name')), 'status': c.get('status', 'FAIL'),
                        'details': _safe(c.get('details')),
                        'issue_count': len(c.get('issues') or [])} for c in result.get('checks', [])],
            'damaged_counts': {name: len(items) for name, items in result.get('damaged', {}).items()}}


def _status(root: Path, current_version: str = '2.2.1') -> dict:
    info = describe_assessment(root)
    data = {'kind': info.get('kind', 'unknown'), 'status': info.get('status', 'UNKNOWN'),
            'stage': info.get('stage', 'unknown'), 'recovery_action': info.get('action', 'NONE'),
            'recovery_guidance': _safe(info.get('guidance'))}
    state = info.get('state')
    if state:
        saved = state.data
        data.update({'name': _safe(saved.get('assessment_name')),
                     'mode': saved.get('mode'), 'target_type': (saved.get('target') or {}).get('type', 'installable'),
                     'framework_version': saved.get('framework_version'),
                     'coverage': saved.get('coverage', ''),
                     'stages': {key: (value or {}).get('status', 'PENDING')
                                for key, value in (saved.get('stages') or {}).items()}})
        if saved.get('framework_version') != current_version and data['recovery_action'] in ('INSTALL', 'POST_INSTALL', 'ANALYSIS'):
            data['recovery_action'] = 'HALT'
            data['recovery_guidance'] = 'Cross-version resume is blocked. Use the original release with unchanged VM evidence.'
    if info.get('kind') == 'structured':
        verification = verify_assessment(root)
        data['integrity'] = _verification_summary(verification)
        data['available_actions'] = ['verify']
        if data['recovery_action'] in ('INSTALL', 'POST_INSTALL', 'ANALYSIS'):
            data['available_actions'].append('resume_assessment_cli_only')
        if verification.get('repairable'):
            data['available_actions'].append('regenerate_reports_with_confirmation')
        if verification.get('status') == 'PASS' and data['status'] == 'COMPLETED':
            data['available_actions'].append('review')
            try:
                export_readiness(root)
            except (ValueError, OSError):
                pass
            else:
                data['available_actions'].append('export_appendix_with_confirmation')
    return data


def _review(root: Path) -> dict:
    if verify_assessment(root).get('status') != 'PASS':
        raise BackendError('INTEGRITY_FAILED', 'Review requires a verified assessment.')
    state = read_review(root)
    if state is None:
        raise BackendError('REVIEW_UNAVAILABLE', 'No compatible Guided Review state was found.')
    items = []
    for item in state.get('items', {}).values():
        items.append({'id': item.get('id'), 'title': _safe(item.get('title')),
                      'module': _safe(item.get('source_module')),
                      'severity': item.get('severity', 'Informational'),
                      'status': item.get('status', 'PENDING'),
                      'fingerprint': item.get('fingerprint'),
                      'changed_evidence': bool(item.get('changed_evidence')),
                      'artifacts': [Path(a).name for a in (item.get('artifacts') or [])]})
    items.sort(key=lambda row: (row['module'], row['title'], str(row['id'])))
    summary = counts(state)
    return {'total': len(items), 'pending': summary['PENDING'],
            'by_disposition': {key: summary[key] for key in DISPOSITIONS}, 'items': items}


def _require_verified(root: Path) -> AssessmentState:
    verification = verify_assessment(root)
    if verification.get('status') != 'PASS':
        raise BackendError('INTEGRITY_FAILED', 'Assessment integrity must be PASS before modification.')
    state = AssessmentState.load(root)
    if state is None or state.data.get('status') != 'COMPLETED':
        raise BackendError('ASSESSMENT_INCOMPLETE', 'Assessment has not completed.')
    return state


def _commit_review(root: Path, identifier: str, status: str, fingerprint: str, notes: str | None, client_notes: str | None = None) -> dict:
    # Exact state/evidence fingerprint is an optimistic concurrency token, not
    # an exploitability claim. Never invent a decision when evidence changes.
    state = _require_verified(root)
    review = read_review(root)
    item = (review or {}).get('items', {}).get(identifier)
    if not item:
        raise BackendError('REVIEW_UNKNOWN_ID', 'Review condition no longer exists.')
    if not fingerprint or item.get('fingerprint') != fingerprint:
        raise BackendError('REVIEW_CHANGED', 'Review evidence has changed; reopen the condition before saving.')
    if status not in DISPOSITIONS:
        raise BackendError('INVALID_DISPOSITION', 'Unsupported review disposition.')
    with guarded_review_commit(root):
        from utils.reporting import AssessmentReporter
        updated = save_decision(root, identifier, status, item.get('notes', '') if notes is None else notes)
        if client_notes is not None:
            if not isinstance(client_notes, str) or len(client_notes) > 4000:
                raise ValueError('Invalid client-facing review notes.')
            from utils.guided_review import REVIEW_FILE, _atomic_json
            updated['items'][identifier]['client_notes'] = sanitize_report_text(client_notes)
            _atomic_json(root / REVIEW_FILE, updated)
        render_file = root / 'working' / 'report_render_state.json'
        render = json.loads(render_file.read_text(encoding='utf-8'))
        reporter = AssessmentReporter(root, state.data['assessment_name'],
                                      Path(render.get('target_filename') or render['installer_filename']),
                                      state.data['mode'], state.data['framework_version'],
                                      target_type=(state.data.get('target') or {}).get('type', 'installable'))
        reporter.status = render['modules']
        reporter.findings = render['findings']
        reporter.finalize(persist_render_state=False, sanitize_primary=False)
        # Only metadata from the already-verified *prechange* manifest is needed.
        # This is obtained below from on-disk manifest while still under exclusive lock.
        manifest = json.loads((root / 'working' / 'assessment_manifest.json').read_text(encoding='utf-8'))
        create_manifest(root, framework_version=state.data['framework_version'],
                        methodology_version=manifest['methodology_version'],
                        catalog_version=manifest['artifact_catalog_version'])
        if verify_assessment(root).get('status') != 'PASS':
            raise BackendError('POSTCOMMIT_INTEGRITY_FAILED', 'Updated review did not pass assessment integrity.')
    return {'candidate_id': identifier, 'disposition': status,
            'pending': counts(updated)['PENDING']}


class BackendService:
    """Backend facade; local GUI adapter may call it after authorization checks."""
    def __init__(self, *, version: str = '2.2.1'):
        self.version = version

    def execute(self, action: str, assessment_dir: str | Path | None = None, **kwargs) -> dict[str, Any]:
        try:
            if action == 'capabilities':
                return envelope(True, 'OK', 'Capabilities available.', capabilities(self.version))
            if action == 'tool_readiness':
                detected = detect_tools()
                listing = [{'name': str(name), 'found': bool(info.get('found')),
                            'level': str(info.get('level', '')), 'usage': str(info.get('usage', ''))}
                           for name, info in sorted(detected.items())]
                return envelope(True, 'OK', 'Tool availability checked.', {'tools': listing})
            if action not in capabilities(self.version)['operations'] or action in ('run_assessment', 'guided_runtime', 'resume_assessment'):
                raise BackendError('UNSUPPORTED_ACTION', 'Action is not supported by the in-process backend.')
            root = _require_root(assessment_dir)
            if action == 'status':
                return envelope(True, 'OK', 'Assessment status available.', _status(root, self.version))
            if action == 'verify':
                result = _verification_summary(verify_assessment(root))
                return envelope(result['status'] == 'PASS', 'OK' if result['status'] == 'PASS' else 'INTEGRITY_FAILED',
                                'Assessment verification complete.', result)
            if action == 'review':
                return envelope(True, 'OK', 'Review conditions available.', _review(root))
            if action == 'appendix_readiness':
                verification, state, items = export_readiness(root)
                return envelope(True, 'OK', 'Client Appendix is ready for explicit export.',
                                {'ready': True, 'reviewed_items': len(items), 'integrity': verification['status']})
            if action == 'export_appendix':
                if not kwargs.get('confirmed'):
                    raise BackendError('CONFIRMATION_REQUIRED', 'An explicit tester confirmation is required.')
                output = kwargs.get('output')
                if not output:
                    raise BackendError('OUTPUT_REQUIRED', 'An output ZIP path is required.')
                with assessment_operation(root, action):
                    path = export_client_appendix(root, Path(output))
                return envelope(True, 'OK', 'Client Appendix exported and verified.', {'filename': path.name})
            if action == 'save_review':
                if not kwargs.get('confirmed'):
                    raise BackendError('CONFIRMATION_REQUIRED', 'An explicit tester decision is required.')
                with assessment_operation(root, action):
                    updated = _commit_review(root, str(kwargs.get('candidate_id', '')),
                                             str(kwargs.get('disposition', '')),
                                             str(kwargs.get('fingerprint', '')),
                                             kwargs.get('notes'), kwargs.get('client_notes'))
                return envelope(True, 'OK', 'Review decision saved.', updated)
            if action == 'regenerate_reports':
                if not kwargs.get('confirmed'):
                    raise BackendError('CONFIRMATION_REQUIRED', 'Regeneration requires explicit tester confirmation.')
                with assessment_operation(root, action):
                    result = regenerate_derived_reports(root)
                return envelope(result.get('status') == 'PASS', 'OK' if result.get('status') == 'PASS' else 'INTEGRITY_FAILED',
                                'Derived-report regeneration finished.', _verification_summary(result))
            raise BackendError('UNSUPPORTED_ACTION', 'Action is not supported.')
        except ReviewUpdateRolledBack as exc:
            return envelope(False, 'REVIEW_UPDATE_ROLLED_BACK', str(exc),
                            errors=[{'code': 'REVIEW_UPDATE_ROLLED_BACK', 'message': _safe(str(exc))}])
        except ReviewUpdateRollbackFailed as exc:
            return envelope(False, 'REVIEW_UPDATE_INCOMPLETE', str(exc),
                            errors=[{'code': 'REVIEW_UPDATE_INCOMPLETE', 'message': _safe(str(exc))}])
        except BackendError as exc:
            return envelope(False, exc.code, str(exc), errors=[{'code': exc.code, 'message': _safe(str(exc))}])
        except AssessmentBusyError:
            return envelope(False, 'ASSESSMENT_BUSY', 'Assessment is locked by another WCA operation.',
                            errors=[{'code': 'ASSESSMENT_BUSY', 'message': 'An assessment operation is already active.'}])
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, json.JSONDecodeError):
            # Do not leak OS profile paths, raw evidence, exception messages or
            # secret values into an eventual front-end transport.
            return envelope(False, 'OPERATION_FAILED', 'Operation failed; consult the local WCA logs and assessment status.',
                            errors=[{'code': 'OPERATION_FAILED', 'message': 'Operation could not be completed.'}])
