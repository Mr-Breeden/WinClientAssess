from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

TOOLS = {
    "Python": (["python.exe", "python", "python3.exe", "python3", "py.exe", "py"], "REQUIRED", "INTEGRATED"),
    "PowerShell": (["powershell.exe", "powershell", "pwsh.exe", "pwsh"], "REQUIRED", "INTEGRATED"),
    "7-Zip": (["7z.exe", "7z"], "REQUIRED", "INTEGRATED"),
    "Sigcheck": (["sigcheck64.exe", "sigcheck.exe"], "OPTIONAL", "MANUAL"),
    "Strings": (["strings64.exe", "strings.exe"], "OPTIONAL", "MANUAL"),
    "AccessChk": (["accesschk64.exe", "accesschk.exe"], "RECOMMENDED", "INTEGRATED"),
    "Autorunsc": (["autorunsc64.exe", "autorunsc.exe"], "OPTIONAL", "MANUAL"),
    "Procmon": (["procmon64.exe", "procmon.exe"], "RECOMMENDED", "INTEGRATED"),
    "Process Explorer": (["procexp64.exe", "procexp.exe"], "OPTIONAL", "MANUAL"),
    "Tcpvcon": (["tcpvcon64.exe", "tcpvcon.exe"], "OPTIONAL", "MANUAL"),
    "Handle": (["handle64.exe", "handle.exe"], "RECOMMENDED", "INTEGRATED"),
    "PipeList": (["pipelist64.exe", "pipelist.exe"], "OPTIONAL", "INTEGRATED_FALLBACK"),
    "ListDLLs": (["listdlls64.exe", "listdlls.exe"], "RECOMMENDED", "INTEGRATED"),
    "Detect It Easy": (["diec.exe", "die.exe"], "RECOMMENDED", "INTEGRATED"),
    "lessmsi": (["lessmsi.exe"], "RECOMMENDED", "INTEGRATED"),
    "ILSpyCmd": (["ilspycmd.exe", "ilspycmd"], "RECOMMENDED", "INTEGRATED"),
    "Wireshark": (["wireshark.exe", "tshark.exe"], "OPTIONAL", "MANUAL"),
    "Ghidra": (["ghidraRun.bat", "analyzeHeadless.bat"], "OPTIONAL", "MANUAL"),
    "DUMPBIN": (["dumpbin.exe"], "OPTIONAL", "MANUAL_GUIDED"),
    "PESecurity": (["Get-PESecurity.psm1"], "OPTIONAL", "MANUAL_GUIDED"),
    "WinDbg": (["windbg.exe", "windbgx.exe"], "OPTIONAL", "MANUAL"),
    "Frida": (["frida.exe", "frida"], "OPTIONAL", "MANUAL"),
    "dotnet-trace": (["dotnet-trace.exe", "dotnet-trace"], "OPTIONAL", "MANUAL_GUIDED"),
    "dotnet-dump": (["dotnet-dump.exe", "dotnet-dump"], "OPTIONAL", "MANUAL_GUIDED"),
    "dotnet-counters": (["dotnet-counters.exe", "dotnet-counters"], "OPTIONAL", "MANUAL_GUIDED"),
}


PROJECT_ROOT = Path(__file__).resolve().parent.parent
OVERRIDE_FILE = PROJECT_ROOT / "tool_paths.json"


def _env_path(name: str):
    value = os.environ.get(name)
    return Path(value) if value else None


def _existing(path):
    try:
        p = Path(path).expanduser()
        return str(p.resolve()) if p.is_file() else None
    except Exception:
        return None


def _load_overrides():
    if not OVERRIDE_FILE.exists():
        return {}

    try:
        data = json.loads(OVERRIDE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}



def _msvc_dumpbin_paths(installation_root: Path):
    """Find x64-hosted dumpbin in versioned MSVC folders, newest first.

    Limit enumeration to Visual Studio's published layout; never walk the
    whole system or execute a third-party binary for this search.
    """
    try:
        paths = list(installation_root.glob('VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe'))
    except OSError:
        return []

    def version_key(path):
        try:
            return tuple(int(part) for part in path.parts[-5].split('.'))
        except (ValueError, IndexError):
            return (0,)

    return sorted(paths, key=version_key, reverse=True)


def _vswhere_installations(program_files: Path | None, program_files_x86: Path | None):
    """Ask the Microsoft installer for non-default VS installation roots.

    vswhere ships with the Visual Studio installer. A bounded query is
    preferable to recursively scanning arbitrary fixed drives.
    """
    for base in (program_files_x86, program_files):
        if not base:
            continue
        vswhere = base / 'Microsoft Visual Studio' / 'Installer' / 'vswhere.exe'
        if not vswhere.is_file():
            continue
        try:
            result = subprocess.run(
                [str(vswhere), '-all', '-products', '*', '-property', 'installationPath'],
                capture_output=True, text=True, timeout=3, check=False,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
        except (OSError, subprocess.TimeoutExpired, ValueError):
            continue
        if result.returncode == 0:
            for location in result.stdout.splitlines():
                if location.strip():
                    yield Path(location.strip())


def _visual_studio_roots(program_files: Path | None, program_files_x86: Path | None):
    """Support year-named releases and numeric VS 2026+ (18) folders."""
    seen = set()
    for root in _vswhere_installations(program_files, program_files_x86):
        name = str(root).casefold()
        if name not in seen:
            seen.add(name)
            yield root
    for base in (program_files, program_files_x86):
        if not base:
            continue
        vs_root = base / 'Microsoft Visual Studio'
        try:
            versions = [path for path in vs_root.iterdir() if path.is_dir()]
        except OSError:
            continue
        for version_dir in versions:
            try:
                editions = [path for path in version_dir.iterdir() if path.is_dir()]
            except OSError:
                continue
            for edition_dir in editions:
                name = str(edition_dir).casefold()
                if name not in seen:
                    seen.add(name)
                    yield edition_dir


def _pesecurity_module_paths():
    """Locate the module in standard PSModulePath and approved tools folders.

    Merely checks module file paths. Discovery never imports or runs PS code.
    """
    names = ('Get-PESecurity', 'PESecurity')
    roots = [Path(s.strip().strip('"')) for s in os.environ.get('PSModulePath', '').split(os.pathsep) if s.strip()]
    home = _env_path('USERPROFILE')
    program_files = _env_path('ProgramFiles')
    if home:
        roots.extend([home / 'Documents' / 'PowerShell' / 'Modules',
                      home / 'Documents' / 'WindowsPowerShell' / 'Modules'])
    if program_files:
        roots.extend([program_files / 'PowerShell' / 'Modules',
                      program_files / 'WindowsPowerShell' / 'Modules'])

    for root in roots:
        yield root / 'Get-PESecurity.psm1'
        for name in names:
            module_dir = root / name
            yield module_dir / 'Get-PESecurity.psm1'
            try:
                yield from module_dir.glob('*/Get-PESecurity.psm1')
            except OSError:
                pass

    # Common location from NetSPI's manual-install instructions.
    yield Path('C:/Tools/PESecurity/Get-PESecurity.psm1')
    yield Path('C:/Tools/Get-PESecurity/Get-PESecurity.psm1')


def _tool_specific_candidates(display: str):
    program_files = _env_path("ProgramFiles")
    program_files_x86 = _env_path("ProgramFiles(x86)")
    local_appdata = _env_path("LOCALAPPDATA")
    user_profile = _env_path("USERPROFILE")
    program_data = _env_path("ProgramData")

    candidates = []

    if display in {"dotnet-trace", "dotnet-dump", "dotnet-counters"}:
        exe_names = TOOLS[display][0]
        if user_profile:
            for exe in exe_names:
                candidates += [
                    user_profile / ".dotnet" / "tools" / exe,
                    user_profile / "scoop" / "shims" / exe,
                ]
        if local_appdata:
            for exe in exe_names:
                candidates += [
                    local_appdata / "Programs" / "dotnet" / exe,
                    local_appdata / "Microsoft" / "dotnet" / "tools" / exe,
                ]

    elif display == "ILSpyCmd":
        if user_profile:
            candidates += [
                user_profile / ".dotnet" / "tools" / "ilspycmd.exe",
                user_profile / "scoop" / "shims" / "ilspycmd.exe",
                user_profile / "scoop" / "apps" / "ilspy" / "current" / "ilspycmd.exe",
            ]
        if local_appdata:
            candidates += [
                local_appdata / "Programs" / "ILSpy" / "ilspycmd.exe",
                local_appdata / "ILSpy" / "ilspycmd.exe",
            ]
        if program_files:
            candidates += [
                program_files / "ILSpy" / "ilspycmd.exe",
                program_files / "ILSpyCmd" / "ilspycmd.exe",
            ]
        if program_files_x86:
            candidates += [
                program_files_x86 / "ILSpy" / "ilspycmd.exe",
                program_files_x86 / "ILSpyCmd" / "ilspycmd.exe",
            ]

    elif display == "DUMPBIN":
        vc_tools = _env_path('VCToolsInstallDir')
        if vc_tools:
            candidates.append(vc_tools / 'bin' / 'Hostx64' / 'x64' / 'dumpbin.exe')
        vs_dir = _env_path('VSINSTALLDIR')
        if vs_dir:
            candidates.extend(_msvc_dumpbin_paths(vs_dir))
        for vs_root in _visual_studio_roots(program_files, program_files_x86):
            candidates.extend(_msvc_dumpbin_paths(vs_root))

    elif display == "PESecurity":
        candidates.extend(_pesecurity_module_paths())
        for base in (user_profile, program_files, local_appdata):
            if base:
                candidates.extend([base / 'Tools' / 'PESecurity' / 'Get-PESecurity.psm1',
                                   base / 'PESecurity' / 'Get-PESecurity.psm1'])

    elif display == "lessmsi":
        if program_files:
            candidates += [
                program_files / "lessmsi" / "lessmsi.exe",
                program_files / "LessMSI" / "lessmsi.exe",
            ]
        if program_files_x86:
            candidates += [
                program_files_x86 / "lessmsi" / "lessmsi.exe",
                program_files_x86 / "LessMSI" / "lessmsi.exe",
            ]
        if local_appdata:
            candidates += [
                local_appdata / "Programs" / "lessmsi" / "lessmsi.exe",
                local_appdata / "lessmsi" / "lessmsi.exe",
            ]
        if user_profile:
            candidates += [
                user_profile / "scoop" / "shims" / "lessmsi.exe",
                user_profile / "scoop" / "apps" / "lessmsi" / "current" / "lessmsi.exe",
            ]
        if program_data:
            candidates += [
                program_data / "chocolatey" / "bin" / "lessmsi.exe",
                program_data / "chocolatey" / "lib" / "lessmsi" / "tools" / "lessmsi.exe",
            ]

    elif display == "7-Zip":
        if program_files:
            candidates.append(program_files / "7-Zip" / "7z.exe")
        if program_files_x86:
            candidates.append(program_files_x86 / "7-Zip" / "7z.exe")

    elif display == "Wireshark":
        if program_files:
            candidates += [
                program_files / "Wireshark" / "wireshark.exe",
                program_files / "Wireshark" / "tshark.exe",
            ]

    elif display == "Detect It Easy":
        for base in [program_files, program_files_x86, local_appdata]:
            if base:
                candidates += [
                    base / "Detect It Easy" / "die.exe",
                    base / "Detect It Easy" / "diec.exe",
                    base / "DIE" / "die.exe",
                    base / "DIE" / "diec.exe",
                ]

    elif display in {
        "Sigcheck", "Strings", "AccessChk", "Autorunsc", "Procmon",
        "Process Explorer", "Tcpvcon", "Handle", "PipeList", "ListDLLs"
    }:
        exe_names = TOOLS[display][0]
        for base in [program_files, program_files_x86, local_appdata, user_profile]:
            if base:
                for folder in ["Sysinternals", "SysinternalsSuite", "Tools", "bin"]:
                    for exe in exe_names:
                        candidates.append(base / folder / exe)
        if user_profile:
            for exe in exe_names:
                candidates += [
                    user_profile / "Downloads" / "SysinternalsSuite" / exe,
                    user_profile / "Desktop" / "SysinternalsSuite" / exe,
                    user_profile / "scoop" / "shims" / exe,
                ]

    return candidates



def _optional_tools_dir_candidates(display: str, names, *, tools_root=None):
    """Bounded, last-resort C:/Tools discovery, never an installation default.

    We inspect only conventional tool subfolders and exact recognized names,
    never recursively crawl arbitrary customer/tester directories. Tool
    Readiness overrides, PATH, standard locations and WinGet are preferred.
    """
    root = Path(tools_root) if tools_root is not None else Path('C:/Tools')
    aliases = {
        'PESecurity': ('PESecurity', 'Get-PESecurity'),
        'Process Explorer': ('ProcessExplorer', 'Sysinternals'),
        'Detect It Easy': ('DetectItEasy', 'DIE'),
        '7-Zip': ('7-Zip',),
    }.get(display, ())
    folder_names = (display.replace(' ', ''), display, *aliases)
    directories = [root, root / 'bin', root / 'Sysinternals', root / 'SysinternalsSuite']
    directories.extend(root / name for name in folder_names)
    seen = set()
    for folder in directories:
        for name in names:
            candidate = folder / name
            key = str(candidate).casefold()
            if key not in seen:
                seen.add(key)
                yield candidate


def _build_winget_index():
    local_appdata = _env_path("LOCALAPPDATA")
    if not local_appdata:
        return {}
    root = local_appdata / "Microsoft" / "WinGet" / "Packages"
    if not root.is_dir():
        return {}

    wanted = {name.lower() for names, _, _ in TOOLS.values() for name in names}
    index = {}
    try:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            name = path.name.lower()
            if name in wanted and name not in index:
                index[name] = str(path.resolve())
    except Exception:
        pass
    return index


def _winget_candidate(names, winget_index):
    for name in names:
        hit = winget_index.get(str(name).lower())
        if hit:
            return hit
    return None


def _find(display: str, names, overrides, winget_index):
    for key in (display, display.lower()):
        override = overrides.get(key)
        if override:
            hit = _existing(override)
            if hit:
                return hit, "tool_paths.json"

    for name in names:
        hit = shutil.which(name)
        if hit:
            return hit, "PATH"

    for candidate in _tool_specific_candidates(display):
        hit = _existing(candidate)
        if hit:
            return hit, "known location"

    hit = _winget_candidate(names, winget_index)
    if hit:
        return hit, "WinGet package"

    # Optional secondary root. Never required and never created by WCA.
    if os.name == 'nt':
        for candidate in _optional_tools_dir_candidates(display, names):
            hit = _existing(candidate)
            if hit:
                return hit, "C:\\Tools (optional)"

    return None, None


def detect_tools():
    overrides = _load_overrides()
    winget_index = _build_winget_index()
    result = {}

    for display, (names, level, usage) in TOOLS.items():
        path, source = _find(display, names, overrides, winget_index)
        result[display] = {
            "found": bool(path),
            "path": path,
            "level": level,
            "usage": usage,
            "source": source or "",
            "note": "" if path else f"{level} dependency not detected",
        }

    return result
