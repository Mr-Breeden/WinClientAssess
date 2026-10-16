"""Windows UAC launcher for explicitly privileged WCA operations.

No assessment state is written by this helper. The original (unelevated)
process exits after Windows accepts the elevated-process launch; it does not
continue to create assessment artifacts or start background collectors.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import sys
from typing import Sequence


class ElevationError(RuntimeError):
    """The requested elevated process could not be launched."""


def _windows() -> bool:
    return os.name == "nt"


def is_administrator() -> bool:
    """True only if the current Windows token is elevated."""
    if not _windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError, ValueError):
        return False


def _runas(executable: str, parameters: str, cwd: str) -> int:
    """Request Windows UAC via the OS shell, retaining the current CWD."""
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    launcher = shell32.ShellExecuteW
    launcher.argtypes = (
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
    )
    launcher.restype = ctypes.c_void_p
    return int(launcher(None, "runas", executable, parameters, cwd, 1) or 0)


def launch_elevated(
    *,
    argv: Sequence[str] | None = None,
    executable: str | None = None,
    script: str | Path | None = None,
    cwd: str | None = None,
) -> None:
    """Launch a new elevated WCA process; raise when UAC is declined/failed.

    The hidden attempted marker prevents the elevated child from opening an
    endless UAC prompt when its token still lacks Administrator privileges.
    The marker does not grant privileges or override the token check.
    """
    if not _windows():
        raise ElevationError("UAC elevation is only available on Windows.")
    executable = str(executable or sys.executable)
    script = str(Path(script or (Path(__file__).resolve().parents[1] / "wca.py")).resolve())
    cwd = str(cwd or os.getcwd())
    forwarded = list(argv if argv is not None else sys.argv[1:])
    if "--wca-elevation-attempted" in forwarded:
        raise ElevationError("An elevation request was already attempted; WCA will not retry UAC indefinitely.")
    parameters = subprocess.list2cmdline([script, *forwarded, "--wca-elevation-attempted"])
    try:
        result = _runas(executable, parameters, cwd)
    except (OSError, AttributeError, ValueError) as exc:
        raise ElevationError("Windows could not start WCA with Administrator privileges. Launch an elevated PowerShell window and try again.") from exc
    if result <= 32:
        raise ElevationError(
            "Windows UAC approval was declined or the elevated launch failed. "
            "WCA did not start a privileged operation. Open Administrator PowerShell and retry if appropriate."
        )
