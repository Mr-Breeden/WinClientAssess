from __future__ import annotations

import json
import os
import shutil
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
