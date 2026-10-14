from __future__ import annotations
import json
import os
import ntpath
import shutil
from .command_runner import run_command


def powershell_path():
    # Windows PowerShell provides the most reliable access to Windows-only COM,
    # CIM, ScheduledTasks, and registry providers used by the assessment engine.
    return shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh.exe") or shutil.which("pwsh")


def _powershell_environment(executable):
    env = os.environ.copy()
    if ntpath.basename(str(executable).replace("/", "\\")).lower() in {"powershell", "powershell.exe"}:
        # A process launched from PowerShell 7 can inherit its PSModulePath. Windows
        # PowerShell may then discover incompatible PowerShell 7 modules before its
        # own Windows-native modules. Removing the inherited value lets Windows
        # PowerShell rebuild its normal module path during startup.
        for key in list(env):
            if key.lower() == "psmodulepath":
                env.pop(key, None)
    return env


def run_powershell(script, timeout=120):
    ps = powershell_path()
    if not ps:
        return {"returncode": 127, "stdout": "", "stderr": "PowerShell not found"}
    return run_command(
        [ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout=timeout,
        env=_powershell_environment(ps),
    )


def run_powershell_json(script, timeout=120):
    result = run_powershell(f"& {{ {script} }} | ConvertTo-Json -Depth 8 -Compress", timeout=timeout)
    if result["returncode"] != 0 or not result["stdout"].strip():
        return None, result
    try:
        return json.loads(result["stdout"].strip()), result
    except json.JSONDecodeError:
        return None, result
