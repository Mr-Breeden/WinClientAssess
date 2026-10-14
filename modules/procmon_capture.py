from __future__ import annotations
from utils.assessment_layout import artifact_path

import ctypes
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from utils.command_runner import run_command
from utils.report_format import format_bytes
from utils.sensitive_data import sanitize_procmon_csv


def _is_admin():
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _write_instructions(assessment_dir: Path, procmon_path: str | None):
    proc = procmon_path or r"C:\Path\To\Procmon64.exe"
    text = f"""Windows Client Assessment Procmon Runtime Capture Instructions
===================================================

Automated capture was not completed. You can capture a trace manually and import
the resulting CSV into Windows Client Assessment with --procmon-csv.

Recommended capture workflow:

1. Run Process Monitor elevated.
2. Reset old filters so the trace is not unintentionally filtered.
3. Start a backing-file trace:
   "{proc}" -accepteula -backingfile "C:\\Temp\\WCA_Runtime.pml" -quiet -minimized

4. Fully exit and relaunch the target client so Process Start/Create events are captured.
5. Exercise normal client functionality and, when authorized, explicitly trigger its
   check-for-updates/update workflow.
6. Stop the trace:
   "{proc}" -terminate -quiet

7. Export the PML to CSV:
   "{proc}" -openlog "C:\\Temp\\WCA_Runtime.pml" -saveas "C:\\Temp\\WCA_Runtime.csv" -quiet

8. Analyze the CSV:
   python .\\wca.py ... --procmon-csv "C:\\Temp\\WCA_Runtime.csv"

Keep runtime captures reasonably scoped. Large unfiltered captures can consume
significant disk space and produce excessive background Windows activity.

Important privacy note:
Procmon Process Start/Create records can include complete process environments.
Those environments may contain tokens or passwords. Windows Client Assessment sanitizes
automated CSV captures and does not retain the raw PML. Treat manually captured
PML/CSV files as sensitive evidence and store or destroy them accordingly.
"""
    path = artifact_path(assessment_dir, "procmon_capture_instructions.txt")
    path.write_text(text, encoding="utf-8")
    return path


def _duration_text(seconds: float) -> str:
    seconds = max(0, int(seconds or 0))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _adaptive_export_timeout(pml_size: int) -> int:
    """Allow large Procmon captures enough conversion time while remaining bounded."""
    gib = max(0.0, float(pml_size or 0) / float(1024 ** 3))
    return min(3600, max(600, int(600 + gib * 600)))


def _run_with_heartbeat(command, *, timeout: int, output_fn=print, verb: str = "Processing", interval: float = 15.0):
    """Run a quiet Windows helper while periodically explaining that work is active.

    communicate(timeout=...) continuously drains stdout/stderr on Windows while
    still letting us emit heartbeat messages. This avoids the pipe-fill deadlock
    risk of polling a child whose redirected output is not consumed until exit.
    """
    started = time.monotonic()
    interval = max(2.0, float(interval or 15.0))
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc), "elapsed_seconds": 0}
    except Exception as exc:
        return {"returncode": 1, "stdout": "", "stderr": str(exc), "elapsed_seconds": 0}

    while True:
        elapsed = time.monotonic() - started
        remaining = float(timeout) - elapsed
        if remaining <= 0:
            try:
                proc.kill()
            except Exception:
                pass
            stdout, stderr = proc.communicate()
            return {
                "returncode": 124,
                "stdout": stdout or "",
                "stderr": f"Timed out after {timeout} seconds" + (("; " + stderr.strip()) if stderr else ""),
                "elapsed_seconds": int(time.monotonic() - started),
            }
        try:
            stdout, stderr = proc.communicate(timeout=min(interval, remaining))
            return {
                "returncode": proc.returncode,
                "stdout": stdout or "",
                "stderr": stderr or "",
                "elapsed_seconds": int(time.monotonic() - started),
            }
        except subprocess.TimeoutExpired:
            output_fn(f"    {verb}... elapsed {_duration_text(time.monotonic() - started)}")


def _session_payload(*, started_at, stopped_at, pml: Path, controller_result: dict,
                     processing_started: float | None = None, failure_stage: str = "",
                     failure_reason: str = "") -> dict:
    now = datetime.now(timezone.utc)
    stopped = stopped_at or now
    capture_seconds = max(0, int((stopped - started_at).total_seconds()))
    processing_seconds = max(0, int(time.monotonic() - processing_started)) if processing_started is not None else 0
    total_seconds = max(0, int((now - started_at).total_seconds()))
    try:
        pml_size = int(pml.stat().st_size) if pml.exists() else 0
    except OSError:
        pml_size = 0
    return {
        "started_at": started_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "stopped_at": stopped.isoformat(timespec="seconds").replace("+00:00", "Z"),
        # duration_seconds remains the capture-window duration for backwards compatibility.
        "duration_seconds": capture_seconds,
        "capture_duration_seconds": capture_seconds,
        "processing_duration_seconds": processing_seconds,
        "total_duration_seconds": total_seconds,
        "final_pml_size_bytes": pml_size,
        "controller": controller_result or {},
        "failure_stage": failure_stage,
        "failure_reason": failure_reason,
    }


def run_procmon_capture(
    assessment_dir: Path,
    tools,
    capture_seconds: int = 0,
    interactive: bool = True,
    capture_controller=None,
    input_fn=input,
    output_fn=print,
    *,
    target_process_names=None,
    target_executable_paths=None,
):
    procmon = (tools or {}).get("Procmon", {}).get("path")
    _write_instructions(assessment_dir, procmon)

    if not procmon:
        return {
            "status": "SKIPPED",
            "details": "Procmon not detected; manual capture instructions generated",
            "csv_path": None,
            "pml_path": None,
        }

    if os.name != "nt":
        return {
            "status": "SKIPPED",
            "details": "Automated Procmon capture requires Windows",
            "csv_path": None,
            "pml_path": None,
        }

    if not _is_admin():
        return {
            "status": "WARN",
            "details": "Run Windows Client Assessment from an elevated Windows terminal for automated Procmon capture",
            "csv_path": None,
            "pml_path": None,
        }

    # Raw Procmon files can contain complete process environments. Keep them in
    # an automatically cleaned temporary directory and retain only sanitized CSV.
    # Guided Runtime can additionally filter to target/descendant processes in
    # this same pass so no sanitized full-host duplicate is written to disk.
    capture_temp = tempfile.TemporaryDirectory(prefix="wca-procmon-")
    capture_work = Path(capture_temp.name)
    pml = capture_work / "procmon_runtime_capture.pml"
    raw_csv = capture_work / "procmon_runtime_capture.raw.csv"
    csv_path = artifact_path(assessment_dir, "procmon_runtime_capture.csv")
    log_path = artifact_path(assessment_dir, "procmon_capture_log.txt")

    for path in (artifact_path(assessment_dir, "procmon_runtime_capture.pml"), csv_path):
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass

    target_names = sorted({str(name or "").strip() for name in (target_process_names or []) if str(name or "").strip()})
    log = [
        "WCA - PROCMON CAPTURE LOG",
        "=" * 88,
        "",
        f"Procmon: {procmon}",
        "Raw PML/CSV: temporary; discarded after sanitization",
        f"Sanitized CSV: {csv_path}",
        f"Target-scoped streaming filter: {bool(target_names)}",
        "",
    ]

    command = [procmon, "-accepteula", "-backingfile", str(pml), "-quiet", "-minimized"]
    started_at = datetime.now(timezone.utc)
    controller_result = {}
    try:
        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        log.append("Capture start command issued successfully.")
    except Exception as exc:
        log.append(f"Capture start failed: {exc}")
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        return {"status": "WARN", "details": f"Unable to start Procmon: {exc}", "csv_path": None, "pml_path": None}

    time.sleep(2)
    interaction_error = ""
    try:
        if interactive and capture_seconds <= 0:
            if callable(capture_controller):
                controller_result = capture_controller(pml_path=pml, procmon_path=procmon, started_at=started_at) or {}
            else:
                output_fn("")
                output_fn("Procmon runtime capture is active.")
                output_fn("Fully exit and relaunch the target application, then exercise its key workflows.")
                output_fn("When authorized, explicitly trigger check-for-updates so updater behavior is captured.")
                input_fn("Press Enter when runtime testing is complete and the capture should stop...")
        else:
            seconds = capture_seconds if capture_seconds > 0 else 60
            output_fn(f"Procmon runtime capture active for {seconds} seconds.")
            time.sleep(seconds)
    except KeyboardInterrupt:
        interaction_error = "Capture window interrupted by tester; Procmon was stopped and partial evidence was sanitized."
        output_fn("\n[!] Guided runtime capture interrupted; stopping Procmon safely...")
    except Exception as exc:
        interaction_error = f"Capture controller error: {exc}"
        output_fn(f"\n[!] Capture controller error; stopping Procmon safely: {exc}")

    stopped_at = datetime.now(timezone.utc)
    processing_started = time.monotonic()
    output_fn("[•] Stopping Procmon capture...")
    stop = run_command([procmon, "-terminate", "-quiet"], timeout=120)
    log += [
        "", "Terminate command:",
        f"  Return code: {stop.get('returncode')}",
        f"  STDOUT: {stop.get('stdout', '').strip()}",
        f"  STDERR: {stop.get('stderr', '').strip()}",
    ]

    # Give Procmon a moment to flush the backing file.
    time.sleep(2)
    if interaction_error:
        log.append('Capture controller failed; partial raw evidence is discarded rather than presented as a successful capture.')
        log.append(interaction_error)
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        return {
            "status": "WARN", "details": interaction_error,
            "csv_path": None, "pml_path": None,
            "session": _session_payload(
                started_at=started_at, stopped_at=stopped_at, pml=pml,
                controller_result=controller_result, processing_started=processing_started,
                failure_stage="capture_controller", failure_reason=interaction_error,
            ),
        }
    if not pml.exists():
        reason = "Procmon capture ended but PML backing file was not created"
        log.append("PML backing file was not found after capture.")
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        output_fn(f"[!] {reason}")
        return {
            "status": "WARN", "details": reason, "csv_path": None, "pml_path": None,
            "session": _session_payload(
                started_at=started_at, stopped_at=stopped_at, pml=pml,
                controller_result=controller_result, processing_started=processing_started,
                failure_stage="capture_flush", failure_reason=reason,
            ),
        }

    pml_size = int(pml.stat().st_size)
    capture_duration = max(0, int((stopped_at - started_at).total_seconds()))
    output_fn(f"[✓] Procmon stopped: capture {_duration_text(capture_duration)}; trace {format_bytes(pml_size)}")

    export_timeout = _adaptive_export_timeout(pml_size)
    output_fn("[•] Exporting Procmon PML to a temporary CSV...")
    output_fn(
        f"    Large captures can require several minutes. Export limit for this trace: {_duration_text(export_timeout)}; "
        "status updates appear every 15 seconds."
    )
    export = _run_with_heartbeat(
        [procmon, "-openlog", str(pml), "-saveas", str(raw_csv), "-quiet"],
        timeout=export_timeout, output_fn=output_fn, verb="Still exporting Procmon evidence", interval=15,
    )
    run_command([procmon, "-terminate", "-quiet"], timeout=60)

    log += [
        "", "CSV export command:",
        f"  Return code: {export.get('returncode')}",
        f"  STDOUT: {export.get('stdout', '').strip()}",
        f"  STDERR: {export.get('stderr', '').strip()}",
        f"  Export elapsed: {_duration_text(export.get('elapsed_seconds') or 0)}",
        f"  Raw CSV exists: {raw_csv.exists()}",
        f"  PML size: {format_bytes(pml_size)}",
        f"  Raw CSV size: {format_bytes(raw_csv.stat().st_size if raw_csv.exists() else 0)}",
    ]

    if export.get("returncode") != 0 or not raw_csv.exists():
        reason = "PML captured but automatic CSV export did not complete"
        if export.get("returncode") == 124:
            reason += f" within {_duration_text(export_timeout)}"
        detail = (export.get("stderr") or "").strip()
        if detail:
            reason += f" ({detail})"
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        output_fn(f"[!] {reason}. Process/network/IPC collection will continue without Procmon events.")
        return {
            "status": "WARN", "details": reason, "csv_path": None, "pml_path": None,
            "session": _session_payload(
                started_at=started_at, stopped_at=stopped_at, pml=pml,
                controller_result=controller_result, processing_started=processing_started,
                failure_stage="pml_to_csv_export", failure_reason=reason,
            ),
        }

    output_fn("[•] Sanitizing Procmon evidence" + (" and filtering to target/descendant processes..." if target_names else "..."))
    sanitize_started = time.monotonic()

    def _progress(info):
        output_fn(
            f"    Sanitizing/filtering... {int(info.get('source_rows') or 0):,} rows scanned; "
            f"{int(info.get('retained_rows') or 0):,} retained; elapsed {_duration_text(info.get('elapsed_seconds') or 0)}"
        )

    try:
        sanitation = sanitize_procmon_csv(
            raw_csv, csv_path,
            target_process_names=target_names or None,
            target_executable_paths=target_executable_paths,
            progress_fn=_progress,
            progress_interval=15,
        )
        sanitize_elapsed = int(time.monotonic() - sanitize_started)
        log += [
            "", "Privacy sanitization / target scoping:",
            f"  Source rows scanned: {sanitation.get('source_rows', sanitation.get('rows', 0))}",
            f"  Rows retained: {sanitation['rows']}",
            f"  Sensitive values redacted: {sanitation['redaction_count']}",
            f"  Sensitive field names: {', '.join(sanitation['sensitive_names']) or 'None'}",
            f"  Target filter active: {bool(sanitation.get('target_filter_active'))}",
            f"  Sanitization elapsed: {_duration_text(sanitize_elapsed)}",
            "  Raw PML/CSV retained: False",
        ]
        output_fn(
            f"[✓] Procmon evidence prepared: {int(sanitation.get('rows') or 0):,} row(s) retained from "
            f"{int(sanitation.get('source_rows') or 0):,}; elapsed {_duration_text(sanitize_elapsed)}"
        )
    except Exception as exc:
        reason = f"Procmon capture completed but privacy sanitization/target filtering failed: {exc}"
        log += ["", reason, "Raw PML/CSV retained: False"]
        log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
        output_fn(f"[!] {reason}. Process/network/IPC collection will continue without Procmon events.")
        return {
            "status": "WARN", "details": reason, "csv_path": None, "pml_path": None,
            "session": _session_payload(
                started_at=started_at, stopped_at=stopped_at, pml=pml,
                controller_result=controller_result, processing_started=processing_started,
                failure_stage="sanitize_target_filter", failure_reason=reason,
            ),
        }

    log += [f"  Sanitized CSV size: {format_bytes(csv_path.stat().st_size if csv_path.exists() else 0)}"]
    log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
    details = (
        ("Target-scoped " if target_names else "")
        + "Procmon runtime CSV captured and sanitized; raw PML/full-host CSV discarded; "
        + f"{sanitation['redaction_count']} sensitive value(s) redacted"
        + (f"; {interaction_error}" if interaction_error else "")
    )
    return {
        "status": "WARN" if sanitation["redaction_count"] or interaction_error else "PASS",
        "details": details,
        "csv_path": str(csv_path),
        "pml_path": None,
        "sanitization": sanitation,
        "session": _session_payload(
            started_at=started_at, stopped_at=stopped_at, pml=pml,
            controller_result=controller_result, processing_started=processing_started,
        ),
    }
