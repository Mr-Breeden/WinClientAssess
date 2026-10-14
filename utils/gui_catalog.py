"""Small tester-local recent-assessment index, never stored with assessment evidence.

Only explicitly selected assessment parents are searched, and discovery is bounded.
No directory-wide workstation search, background scanner or file contents indexed.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from utils.assessment_state import AssessmentState
from utils.guided_review import counts, read_review

MAX_RECENT = 40
MAX_CHILDREN = 80


def default_catalog_path() -> Path:
    base = os.environ.get('LOCALAPPDATA') if os.name == 'nt' else None
    if base:
        return Path(base) / 'WCA' / 'gui_recent.json'
    return Path.home() / '.wca' / 'gui_recent.json'


class RecentAssessments:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path is not None else default_catalog_path()
        self.lock = threading.RLock()

    def _read(self) -> dict:
        if self.path.is_symlink() or not self.path.is_file():
            return {'paths': [], 'parents': []}
        try:
            value = json.loads(self.path.read_text(encoding='utf-8'))
            if not isinstance(value, dict):
                return {'paths': [], 'parents': []}
            return {'paths': [s for s in value.get('paths', []) if isinstance(s, str)][:MAX_RECENT],
                    'parents': [s for s in value.get('parents', []) if isinstance(s, str)][:MAX_RECENT]}
        except (OSError, ValueError):
            return {'paths': [], 'parents': []}

    def remember(self, root: Path) -> None:
        """Register only an explicitly selected/created assessment or its parent."""
        root = Path(root)
        if root.is_symlink() or root.parent.is_symlink():
            raise ValueError('Symbolic-link assessment directories are not supported.')
        full = root.expanduser().resolve()
        with self.lock:
            data = self._read()
            data['paths'] = [str(full)] + [x for x in data['paths'] if os.path.normcase(x) != os.path.normcase(str(full))]
            data['parents'] = [str(full.parent)] + [x for x in data['parents'] if os.path.normcase(x) != os.path.normcase(str(full.parent))]
            data['paths'] = data['paths'][:MAX_RECENT]
            data['parents'] = data['parents'][:MAX_RECENT]
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.path.is_symlink():
                raise ValueError('Refusing to overwrite a symbolic-link catalog.')
            temp = self.path.with_name(self.path.name + f'.{os.getpid()}.{threading.get_ident()}.new')
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                with os.fdopen(os.open(temp, flags, 0o600), 'w', encoding='utf-8') as handle:
                    json.dump(data, handle, ensure_ascii=True, sort_keys=True)
                    handle.write('\n')
                    handle.flush()
                    os.fsync(handle.fileno())
                if os.name != 'nt':
                    os.chmod(temp, 0o600)
                os.replace(temp, self.path)
            finally:
                temp.unlink(missing_ok=True)

    def list_recent(self, jobs: list[dict] | None = None) -> list[dict]:
        """Lightweight summaries. No SHA scan: NOT VERIFIED until selected and checked.

        These summaries never gate mutations, exports or recovery decisions.
        """
        with self.lock:
            index = self._read()
        candidates = list(index['paths'])
        # Explicitly selected parents only; no recursive filesystem searching.
        for parent_str in index['parents'][:8]:
            parent = Path(parent_str)
            if not parent.is_dir() or parent.is_symlink():
                continue
            try:
                for i, child in enumerate(sorted(parent.iterdir(), key=lambda x: x.name.casefold())):
                    if i >= MAX_CHILDREN:
                        break
                    if child.is_dir() and not child.is_symlink() and (child / 'working' / 'assessment_state.json').is_file():
                        candidates.append(str(child))
            except OSError:
                continue
        active = {os.path.normcase(x.get('assessment', '')): x for x in (jobs or [])}
        rows, seen = [], set()
        for path in candidates:
            root = Path(path)
            norm = os.path.normcase(str(root))
            if norm in seen or root.is_symlink():
                continue
            seen.add(norm)
            try:
                state = AssessmentState.load(root)
            except (OSError, ValueError, TypeError):
                continue
            if not state:
                if str(root) in index['paths']:
                    rows.append({'path': str(root), 'name': root.name[:120], 'mode': '',
                                 'target_type': '', 'state': 'MISSING / UNAVAILABLE',
                                 'coverage': '', 'framework_version': '', 'last_activity': '',
                                 'review': {'completed': 0, 'total': 0},
                                 'integrity': 'NOT VERIFIED', 'job': ''})
                continue
            data = state.data
            review_summary = {'completed': 0, 'total': 0}
            try:
                review = read_review(root)
                if review:
                    summary = counts(review)
                    review_summary = {'completed': sum(n for k, n in summary.items() if k != 'PENDING'),
                                      'total': len(review.get('items', {}))}
            except (OSError, TypeError, ValueError):
                pass
            rows.append({'path': str(root), 'name': str(data.get('assessment_name') or root.name)[:120],
                         'mode': data.get('mode', ''), 'target_type': (data.get('target') or {}).get('type', ''),
                         'state': data.get('status', 'UNKNOWN'), 'coverage': data.get('coverage', ''),
                         'framework_version': data.get('framework_version', ''),
                         'last_activity': data.get('updated_at') or data.get('created_at') or '',
                         'review': review_summary,
                         'integrity': 'NOT VERIFIED',
                         'job': (active.get(norm) or {}).get('state', '')})
        rows.sort(key=lambda x: x['last_activity'], reverse=True)
        return rows[:MAX_RECENT]
