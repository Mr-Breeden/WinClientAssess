"""Read-only, best-effort PE resource version reporting for detected tools.

Never invokes third-party programs to discover versions. A missing file-version
resource is reported as NOT VERIFIED rather than guessed from file names.
"""
from __future__ import annotations

from pathlib import Path


def pe_version(path: str | None) -> str:
    if not path:
        return 'Not verified'
    p = Path(path)
    try:
        if p.suffix.lower() not in ('.exe', '.dll') or not p.is_file() or p.is_symlink() or p.stat().st_size > 120_000_000:
            return 'Not verified'
        import pefile
        exe = pefile.PE(str(p), fast_load=True)
        try:
            exe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            for block in getattr(exe, 'FileInfo', []) or []:
                for entry in block if isinstance(block, list) else [block]:
                    if hasattr(entry, 'StringTable'):
                        for table in entry.StringTable:
                            d = table.entries
                            for key in (b'ProductVersion', b'FileVersion'):
                                text = d.get(key) or d.get(key.decode())
                                if text:
                                    if isinstance(text, bytes):
                                        text = text.decode('utf-8', 'replace')
                                    text = str(text).strip().replace('\x00', '')
                                    if text and len(text) <= 75:
                                        return text
            for entry in getattr(exe, 'VS_FIXEDFILEINFO', []) or []:
                major, minor = entry.FileVersionMS >> 16, entry.FileVersionMS & 65535
                patch, build = entry.FileVersionLS >> 16, entry.FileVersionLS & 65535
                if major or minor or patch or build:
                    return f'{major}.{minor}.{patch}.{build}'
        finally:
            exe.close()
    except Exception:
        # Optional/untrusted PE metadata is never allowed to break Help & About.
        pass
    return 'Not verified'


def detected_versions() -> list[dict]:
    from utils.tool_detection import detect_tools
    return [{'name': name, 'found': bool(info['found']),
             'version': pe_version(info.get('path')) if info['found'] else 'Not installed'}
            for name, info in sorted(detect_tools().items())]
