"""Opt-in, Windows-only clipboard export for complete unwrapped validation checks.

Never execute copied commands. The live review supplies resolved paths; portable
TXT/HTML guidance retains explicit Read-Host file selection to avoid persisting
personal assessment locations.
"""
from __future__ import annotations

import os

# These exact prefixes are emitted by contextual_checks and are read-only
# inspection commands except for explicitly tester-operated benign lab probes.
_COMMAND_PREFIXES = (
    'get-', 'import-csv ', 'test-', 'icacls ', 'sc.exe ',
    'handle64.exe ', 'handle.exe ', 'powershell ', 'python ', '& ', '$',
)


def powershell_checks(steps: tuple[str, ...] | list[str]) -> str:
    """Give copy/paste a single clean line per check; prose becomes comments."""
    lines = ['# Windows Client Assessment: candidate-specific checks. Run only on the authorized assessment VM.']
    for step in steps:
        raw = str(step).strip()
        if not raw:
            continue
        # An unexpected multiline evidence value must never smuggle executable
        # lines through an instruction or a hand-assembled command.
        if '\n' in raw or '\r' in raw:
            lines.extend('# ' + line for line in raw.splitlines())
            continue
        if raw.casefold().startswith(_COMMAND_PREFIXES):
            lines.append(raw)
        else:
            lines.append('# ' + raw)
    return '\r\n'.join(lines) + '\r\n'


def copy_windows_text(text: str) -> None:
    """Place UTF-16 Unicode in the Windows clipboard; explicit action only."""
    if os.name != 'nt':
        raise OSError('Clipboard copying is available in the Windows console.')
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.CloseClipboard.restype = wintypes.BOOL
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL

    if not user32.OpenClipboard(None):
        raise OSError('Cannot open clipboard (possibly in use).')
    memory = None
    try:
        encoded = (text + '\0').encode('utf-16-le')
        memory = kernel32.GlobalAlloc(0x0002, len(encoded))  # GMEM_MOVEABLE
        if not memory:
            raise MemoryError('Unable to allocate clipboard memory.')
        pointer = kernel32.GlobalLock(memory)
        if not pointer:
            raise OSError('Unable to lock clipboard memory.')
        try:
            ctypes.memmove(pointer, encoded, len(encoded))
        finally:
            kernel32.GlobalUnlock(memory)
        if not user32.EmptyClipboard():
            raise OSError('Cannot clear clipboard.')
        if not user32.SetClipboardData(13, memory):  # CF_UNICODETEXT
            raise OSError('Cannot set Unicode clipboard contents.')
        memory = None  # Clipboard owns this allocation on success.
    finally:
        if memory:
            kernel32.GlobalFree(memory)
        user32.CloseClipboard()
