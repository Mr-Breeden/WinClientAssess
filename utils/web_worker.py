"""Private, tester-confirmed browser checkpoint transport for the existing CLI engine.

The worker is a regular Python process with redirected IO, not a PowerShell
window. Only the loopback GUI can acknowledge checkpoints. Worker state lives
outside assessment integrity-tracked evidence, and is never included in exports.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time


def atomic_json(path: Path, record: dict) -> None:
    # Unique staging name prevents overlapping writers from sharing a .new file.
    # Never modify the previous complete record until the replacement succeeds.
    tmp = path.with_name(path.name + f'.{os.getpid()}.{secrets.token_hex(6)}.new')
    try:
        with tmp.open('x', encoding='utf-8') as out:
            json.dump(record, out, ensure_ascii=True, sort_keys=True)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


class WebWorkerControl:
    def __init__(self, directory: Path):
        self.directory = directory.resolve()
        if not self.directory.is_dir() or self.directory.is_symlink():
            raise ValueError('Invalid private GUI worker directory.')
        self.checkpoint_path = self.directory / 'checkpoint.json'
        self.telemetry_path = self.directory / 'telemetry.json'
        self.telemetry_warning_emitted = False

    def _publish_telemetry(self, record: dict) -> None:
        """Best effort ONLY: live UI statistics are not assessment evidence.

        Windows security scanners/readers can temporarily deny an atomic rename.
        Never let that abort a successfully initialized Procmon capture.
        """
        for attempt in range(3):
            try:
                atomic_json(self.telemetry_path, record)
                return
            except OSError:
                if attempt < 2:
                    time.sleep(0.05 * (attempt + 1))
        if not self.telemetry_warning_emitted:
            self.telemetry_warning_emitted = True
            print('[!] GUI capture telemetry unavailable; Procmon collection continues. '
                  'Use Stop Guided Runtime Observation in the browser.', flush=True)

    @classmethod
    def from_environment(cls):
        value = os.environ.get('WCA_WEB_WORKER_DIRECTORY', '')
        return cls(Path(value)) if value else None

    def ask(self, message: str, *, kind: str = 'continue', default: str = '', choices=(), capture_ready: bool = False) -> str:
        choices = [str(choice) for choice in choices]
        ident = secrets.token_hex(12)
        record = {'id': ident, 'kind': kind, 'message': str(message)[:1500],
                  'default': str(default), 'choices': choices, 'created': time.time(),
                  'capture_ready': bool(capture_ready)}
        atomic_json(self.checkpoint_path, record)
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    raise RuntimeError('GUI worker input closed; tester checkpoint not confirmed.')
                try:
                    result = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(result, dict) or result.get('id') != ident:
                    continue
                value = result.get('answer')
                if not isinstance(value, str) or len(value) > 2048:
                    continue
                if kind == 'continue' and value != 'continue':
                    continue
                if kind == 'confirm' and value not in ('yes', 'no'):
                    continue
                if kind == 'choice' and value not in choices:
                    continue
                return value
        finally:
            try:
                if json.loads(self.checkpoint_path.read_text(encoding='utf-8')).get('id') == ident:
                    self.checkpoint_path.unlink(missing_ok=True)
            except (OSError, ValueError, TypeError):
                pass

    def confirm(self, message: str, default=False):
        return self.ask(message, kind='confirm', default='yes' if default else 'no') == 'yes'

    def prompt(self, message: str, *, default='', choices=None):
        if choices:
            return self.ask(message, kind='choice', default=str(default or ''), choices=choices)
        if message.lower().startswith('press enter'):
            self.ask(message, kind='continue')
            return ''
        return self.ask(message, kind='text', default=str(default or ''))

    def capture(self, *, pml_path: Path, procmon_path=None, started_at, runtime_targets=(), exclude_paths=()):
        """Keep full-host Procmon data local; publish only small scoped metrics.

        A single pending Stop checkpoint controls capture duration. A background
        input reader lets the collector update metrics even on Windows pipes.
        """
        import threading
        # The capture-controller contract includes procmon_path; the collection
        # module owns Procmon startup and termination. The browser controller
        # must NOT launch or terminate the tool a second time.
        # Report CAPTURING only once the PML backing file is being populated.
        deadline = time.monotonic() + 20
        while True:
            try:
                if pml_path.is_file() and pml_path.stat().st_size > 0:
                    break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('Procmon capture did not initialize its PML backing file; stop requested for safety.')
            time.sleep(0.25)
        import threading
        from modules.guided_runtime_observation import GuidedRuntimeLiveController
        from modules.runtime_process_review import collect_runtime_processes
        control = GuidedRuntimeLiveController(runtime_targets, exclude_paths, refresh_seconds=1.0)
        done = threading.Event()
        failure = []
        def await_stop():
            try:
                self.ask('Procmon is capturing. Exercise approved target workflows, then click Stop capture.', kind='continue', capture_ready=True)
            except Exception as exc:
                failure.append(exc)
            finally:
                done.set()
        threading.Thread(target=await_stop, daemon=True, name='wca-web-capture-stop').start()
        started = time.monotonic()
        self._publish_telemetry({
            'capture_ready': True, 'duration_seconds': 0,
            'pml_size_bytes': pml_path.stat().st_size,
            'trace_active': True, 'current_target_processes': 0,
            'target_processes_seen': 0, 'current_connections': 0,
            'process_starts': 0, 'io_changes': 0, 'connection_changes': 0,
        })
        last_size = -1
        last_growth = started
        latest = []
        while not done.wait(1.0):
            now = time.monotonic()
            try:
                latest = collect_runtime_processes(runtime_targets, [], exclude_paths)
            except (OSError, ValueError, RuntimeError):
                latest = []
            for row in latest:
                name = str(row.get('Name') or '').strip()
                if name:
                    control.seen_processes.add(name)
            connections = sum(len(p.get('NetworkConnections') or []) for p in latest)
            activity = control._observe_activity(latest, now)
            try:
                size = int(pml_path.stat().st_size)
            except OSError:
                size = 0
            if size != last_size:
                last_size = size
                last_growth = now
            self._publish_telemetry({
                'capture_ready': True, 'duration_seconds': round(now-started), 'pml_size_bytes': size,
                'trace_active': bool(size and now-last_growth < 15),
                'current_target_processes': len(latest), 'target_processes_seen': len(control.seen_processes),
                'current_connections': connections, 'process_starts': control.total_process_starts,
                'io_changes': control.total_io_changes, 'connection_changes': control.total_connection_changes,
            })
        try:
            self.telemetry_path.unlink(missing_ok=True)
        except OSError:
            pass  # Optional UI metadata must not invalidate the capture.
        if failure:
            raise failure[0]
        return {'seen_process_names': sorted(control.seen_processes, key=str.lower),
                'final_live_processes': len(latest),
                'live_process_starts': control.total_process_starts,
                'live_io_operation_changes': control.total_io_changes,
                'live_connection_changes': control.total_connection_changes}
