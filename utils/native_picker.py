"""Main-thread Windows Tk file picker launched in a separate private process.

The GUI HTTP handler never initializes Tcl/Tk in its request thread. Cancellation
is successful with an empty path; failures are sanitized and bounded.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys


def pick_native_path(kind: str) -> str:
    if os.name != 'nt' or kind not in ('file', 'folder'):
        raise ValueError('Native picker unavailable.')
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        result = subprocess.run([sys.executable, '-m', 'utils.native_picker', kind],
                                capture_output=True, text=True, encoding='utf-8',
                                timeout=240, creationflags=flags, check=False,
                                cwd=str(__import__('pathlib').Path(__file__).resolve().parents[1]))
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('Native picker could not complete. Enter the full path manually.') from exc
    if result.returncode != 0:
        raise ValueError('Native picker could not open. Enter the full path manually.')
    try:
        answer = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError('Native picker returned an invalid response.') from exc
    path = answer.get('path', '') if isinstance(answer, dict) else None
    if not isinstance(path, str) or len(path) > 4096:
        raise ValueError('Native picker returned an invalid path.')
    return path


def main():
    if os.name != 'nt' or len(sys.argv) != 2 or sys.argv[1] not in ('file','folder'):
        return 2
    try:
        import tkinter as tk
        from tkinter import filedialog
        parent = tk.Tk()
        try:
            parent.withdraw()
            parent.attributes('-topmost', True)
            parent.update_idletasks()
            if sys.argv[1] == 'file':
                path = filedialog.askopenfilename(parent=parent,
                    title='Choose target executable / installer',
                    filetypes=[('EXE / MSI', '*.exe *.msi'), ('All files','*.*')])
            else:
                path = filedialog.askdirectory(parent=parent, title='Choose directory')
        finally:
            parent.destroy()
        print(json.dumps({'path':path or ''}))
        return 0
    except Exception:
        return 1

if __name__ == '__main__':
    sys.exit(main())
