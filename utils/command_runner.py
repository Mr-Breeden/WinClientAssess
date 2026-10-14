from __future__ import annotations
import subprocess


def _output_text(value):
    """TimeoutExpired may expose bytes even when subprocess.run uses text=True."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def run_command(command, timeout=120, cwd=None, env=None):
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env=env,
            shell=False,
        )
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except FileNotFoundError as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        stderr = _output_text(exc.stderr)
        failure = f"Timed out after {timeout} seconds"
        return {"returncode": 124, "stdout": _output_text(exc.stdout),
                "stderr": f"{stderr}\n{failure}" if stderr else failure}
