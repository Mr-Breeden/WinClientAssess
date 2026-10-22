"""Local-only explicit external tool overrides; never writes assessment evidence.

Do not execute configured tools just to test the path. The canonical detector
remains responsible for validation during collection.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from utils import tool_detection

_LOCK = threading.RLock()


def _read() -> dict:
    path = tool_detection.OVERRIDE_FILE
    if path.is_symlink():
        raise ValueError('Tool configuration cannot be a symbolic link.')
    if not path.exists():
        return {}
    if not path.is_file() or path.stat().st_size > 32768:
        raise ValueError('Tool configuration is invalid or too large.')
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Tool configuration is not valid JSON; repair it before saving.') from exc
    if not isinstance(data, dict):
        raise ValueError('Tool configuration must contain a JSON object.')
    return data


def configured_tools() -> list[dict]:
    with _LOCK:
        entries = _read()
        detection = tool_detection.detect_tools()
        return [dict(name=name, level=level, usage=usage,
                     found=detection[name]['found'], source=detection[name]['source'],
                     configured_path=str(entries.get(name) or entries.get(name.lower()) or ''))
                for name, (_, level, usage) in tool_detection.TOOLS.items()]


def configure_tool(name: object, path: object) -> None:
    if not isinstance(name, str) or name not in tool_detection.TOOLS:
        raise ValueError('Choose a supported tool from Tool Readiness.')
    if not isinstance(path, str) or len(path) > 2048 or '\x00' in path:
        raise ValueError('Select a valid executable path.')
    with _LOCK:
        data = _read()
        # Empty means remove an override and restore automatic discovery.
        if path.strip():
            candidate = Path(path.strip())
            if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file():
                raise ValueError('Provide an existing absolute executable file path.')
            if candidate.suffix.lower() not in ('.exe', '.bat', '.cmd', '.com', '.ps1'):
                raise ValueError('Expected a supported executable or launcher file.')
            names = {x.casefold() for x in tool_detection.TOOLS[name][0]}
            if candidate.name.casefold() not in names:
                raise ValueError('Executable filename does not match the selected tool.')
            # Remove a legacy lowercase alias only if it is a DISTINCT key.
            # For lessmsi and dotnet-trace the canonical key is already lowercase.
            if name.lower() != name:
                data.pop(name.lower(), None)
            data[name] = str(candidate.resolve())
        else:
            data.pop(name, None)
            if name.lower() != name:
                data.pop(name.lower(), None)
        output = tool_detection.OVERRIDE_FILE
        if output.is_symlink():
            raise ValueError('Tool configuration cannot be a symbolic link.')
        fd, temp_name = tempfile.mkstemp(prefix='.wca-tools-', suffix='.tmp', dir=str(output.parent))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
                json.dump(data, stream, indent=2, ensure_ascii=False)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, output)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        # Fail closed on an unexpectedly lost override or stale detection.
        saved = _read()
        if path.strip():
            if saved.get(name) != str(candidate.resolve()):
                raise ValueError('The tool override was not retained. Check local configuration permissions.')
            actual = tool_detection.detect_tools().get(name) or {}
            if not actual.get('found') or actual.get('source') != 'tool_paths.json':
                raise ValueError('The saved tool is not detected. Review the selected executable and retry.')
        elif name in saved or (name.lower() != name and name.lower() in saved):
            raise ValueError('The tool override could not be cleared.')
