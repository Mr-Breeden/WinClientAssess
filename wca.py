#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table

from utils.reporting import AssessmentReporter
from utils.tool_detection import detect_tools
from modules.installer_info import run_installer_info
from modules.target_info import run_target_info
from modules.installer_technology import run_installer_technology
from modules.application_scope import (
    detect_application_scope, write_application_scope, installation_footprint_status,
)
from modules.signature_review import run_signature_review
from modules.installer_extract import run_installer_extract, finalize_extraction_report
from modules.msi_analysis import run_msi_analysis
from modules.pe_analysis import run_pe_analysis
from modules.dotnet_analysis import run_dotnet_analysis
from modules.configuration_review import run_configuration_review
from modules.secrets_review import run_secrets_review
from modules.electron_security_review import run_electron_security_review
from modules.component_lifecycle_review import run_component_lifecycle_review
from modules.snapshots import capture_snapshot, compare_snapshots, write_snapshot_diff
from modules.services_review import run_services_review
from modules.scheduled_tasks import run_scheduled_tasks_review
from modules.permissions_review import run_permissions_review
from modules.persistence_review import run_persistence_review
from modules.drivers_review import run_drivers_review
from modules.privilege_boundary_review import run_privilege_boundary_review
from modules.updater_review import run_updater_review, discover_updater_candidates
from modules.updater_security_review import run_updater_security_review
from modules.test_cases import generate_test_cases
from modules.runtime_targets import run_runtime_target_discovery
from modules.procmon_capture import run_procmon_capture
from modules.procmon_analysis import run_procmon_analysis
from modules.dll_search_review import run_dll_search_review
from modules.runtime_process_review import run_runtime_process_review
from modules.network_surface_review import run_network_surface_review
from modules.ipc_review import run_ipc_review
from modules.advanced_runtime_review import run_advanced_runtime_review
from modules.attack_surface_correlations import run_attack_surface_correlations
from modules.local_storage_review import run_local_storage_review
from modules.application_profile import run_application_profile
from utils.file_inventory import build_file_inventory, write_file_inventory_csv
from utils.artifact_policy import reset_generated_artifacts
from utils.acl import AclCache
from utils.path_filters import filter_install_diff, write_filter_report
from utils.assessment_layout import ensure_structured_layout, artifact_path, is_structured_layout
from utils.assessment_state import AssessmentState, describe_assessment
from utils.assessment_integrity import create_manifest, verify_assessment, regenerate_derived_reports, format_verification
from utils.guided_review import guided_review_cli, read_review, counts as review_counts
from utils.guided_runtime import run_guided_runtime
from utils.client_appendix import export_client_appendix, ClientAppendixError
from utils.operation_lock import assessment_operation, AssessmentBusyError
from utils.backend_service import BackendService
from utils.elevation import is_administrator, launch_elevated, ElevationError

VERSION = "2.2.2"
METHODOLOGY_VERSION = "1.9"
ARTIFACT_CATALOG_VERSION = "2.0"
PRODUCT_SHORT = "WCA"
PRODUCT_NAME = "Windows Client Assessment"
AUTHOR = "Matthew B."
ACTIVE_STATE = None
console = Console()


def _stretch_banner_row(row: str, width: int) -> str:
    """Nearest-neighbor stretch of a block-art row to the requested width."""
    if width <= 0 or not row:
        return row
    if len(row) == width:
        return row
    return "".join(row[min(len(row) - 1, int(i * len(row) / width))] for i in range(width))


def banner():
    # Borderless, terminal-width-aware WCA wordmark. Keep a two-column margin
    # so Windows Terminal/PowerShell does not soft-wrap the final display cell.
    console_width = max(20, int(getattr(console.size, "width", 120) or 120))
    if console_width < 70:
        compact = [
            "██╗    ██╗ ██████╗ █████╗",
            "██║    ██║██╔════╝██╔══██╗",
            "██║ █╗ ██║██║     ███████║",
            "██║███╗██║██║     ██╔══██║",
            "╚███╔███╔╝╚██████╗██║  ██║",
            " ╚══╝╚══╝  ╚═════╝╚═╝  ╚═╝",
        ]
        for row in compact:
            console.print(row, style="bold cyan", justify="center", soft_wrap=True)
    else:
        target_width = console_width - 2
        base_rows = [
            "#       #   #######     ###   ",
            "#       #  ##          ## ##  ",
            "#       #  #          ##   ## ",
            "#   #   #  #         ##     ##",
            "#  # #  #  #         #########",
            "# #   # #  ##        ##     ##",
            "##     ##   #######  ##     ##",
        ]
        for row in base_rows:
            rendered = row.replace("#", "█")
            console.print(_stretch_banner_row(rendered, target_width), style="bold cyan", soft_wrap=True)
    console.print()
    console.print(f"[bold]{PRODUCT_NAME}[/bold]", justify="center")
    console.print(f"Author: {AUTHOR}", justify="center")
    console.print(f"Version: v{VERSION}", justify="center")
    console.print()


def _is_admin():
    """Compatibility wrapper used by full-mode privilege checks."""
    return is_administrator()


def _windows_host() -> bool:
    return os.name == "nt"


def _require_administrator(args, operation: str) -> None:
    """Elevate before privileged collection, or exit without writing state."""
    if _is_admin():
        return
    if not _windows_host():
        raise SystemExit(f"{operation} requires Administrator privileges on Windows.")
    if args.wca_elevation_attempted:
        raise SystemExit(
            f"{operation} requires Administrator privileges. The elevation request "
            "did not result in an elevated token; no further UAC attempts will be made."
        )
    # Worker requests must inherit elevation from their trusted local GUI
    # process; they must not independently trigger unexpected UAC prompts.
    if args.gui_preselected_options or WEB_CONTROL is not None:
        raise SystemExit(
            f"{operation} requires an elevated WCA GUI session. "
            "Restart the GUI with Administrator privileges."
        )
    console.print(f"[yellow]{operation} requires Administrator privileges. Requesting Windows UAC approval...[/yellow]")
    try:
        launch_elevated()
    except ElevationError as exc:
        raise SystemExit(str(exc)) from exc
    console.print("[green]Elevated WCA process launched. Continue in its new console window.[/green]")
    # This unelevated process must not continue into any assessment writes.
    raise SystemExit(0)


def parse_args():
    parser = argparse.ArgumentParser(description="Assess installable or portable Windows thick clients.")
    parser.add_argument("-t", "--target", help="Path to installer, portable executable, or portable application directory")
    parser.add_argument("-i", "--installer", help="Backward-compatible alias for an installable .msi or .exe target")
    parser.add_argument("--target-type", type=str.lower, choices=["installable", "portable"],
                        help="Assessment target type")
    parser.add_argument("--primary-executable", metavar="EXE",
                        help="Portable directory target: primary executable filename/path")
    parser.add_argument("-n", "--assessment-name", help="Assessment name")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-m", "--mode", type=str.lower, choices=["static", "full"],
                        help="Assessment mode (case-insensitive)")
    parser.add_argument("--no-extract", action="store_true", help="Skip installer extraction")
    parser.add_argument(
        "--application-dir", metavar="DIRECTORY",
        help="Read-only deployed EXE folder when auto publishing-sidecar discovery is insufficient",
    )
    parser.add_argument(
        "--no-filesystem-snapshot",
        action="store_true",
        help="Full mode: skip recursive filesystem snapshot/differential",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt for missing values (static mode only)",
    )
    parser.add_argument("--no-gui", action="store_true", help="Use text prompts instead of Windows file/folder dialogs")
    parser.add_argument("--gui", action="store_true", help="Start the local browser interface (loopback only)")
    parser.add_argument("--port", type=int, default=9001, metavar="PORT", help="GUI loopback TCP port (default: 9001)")
    parser.add_argument(
        "--runtime-capture",
        action="store_true",
        help="Full mode: perform optional Procmon-assisted runtime capture after system-state analysis",
    )
    parser.add_argument(
        "--runtime-seconds",
        type=int,
        default=0,
        help="Runtime capture duration in seconds; 0 uses an interactive press-Enter stop in interactive mode",
    )
    parser.add_argument(
        "--procmon-csv",
        help="Analyze an existing Procmon CSV instead of, or in addition to, automated runtime capture",
    )
    parser.add_argument("--gui-preselected-options", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--wca-elevation-attempted", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--surface-review",
        action="store_true",
        help="Full mode: collect network-listener and IPC/named-pipe surface data",
    )
    parser.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        metavar="PATH_OR_GLOB",
        help=(
            "Repeatable full-mode exclusion for path-associated differential/runtime evidence; "
            "supports Windows path prefixes and glob patterns"
        ),
    )
    parser.add_argument(
        "--target-only",
        action="store_true",
        help="Omit unrelated host-wide supporting inventory such as unassociated system pipes",
    )
    parser.add_argument("--status", metavar="ASSESSMENT_DIR", help="Show lifecycle/status plus automatic integrity verification and exit")
    parser.add_argument("--resume", metavar="ASSESSMENT_DIR", help="Resume a structured assessment from verified checkpoints")
    parser.add_argument("--verify-assessment", metavar="ASSESSMENT_DIR", help="Read-only SHA-256 verification of a finalized structured assessment")
    parser.add_argument("--review", metavar="ASSESSMENT_DIR", help="Interactive guided review of a completed verified assessment")
    parser.add_argument("--client-appendix", metavar="ASSESSMENT_DIR", help="Export an integrity-verified, reviewed client appendix from a completed assessment")
    parser.add_argument("--appendix-output", metavar="ZIP_PATH", help="Destination for --client-appendix (must be outside assessment directory)")
    parser.add_argument("--guided-runtime", metavar="ASSESSMENT_DIR", help="Tester-driven runtime observation for a completed verified full assessment")
    parser.add_argument("--regenerate-reports", metavar="ASSESSMENT_DIR", help="Restore only tampered/missing derived reports after all primary evidence verifies")
    parser.add_argument("--backend-action", choices=["capabilities", "tool_readiness", "status", "verify", "review", "appendix_readiness"],
                        help="Emit one machine-readable, read-only backend response and exit (no GUI/server)")
    parser.add_argument("--backend-assessment", metavar="ASSESSMENT_DIR",
                        help="Assessment directory for --backend-action other than capabilities")
    parser.add_argument("--backend-format", choices=("json", "text"), default="json",
                        help="Backend CLI output: JSON for integrations (default), text for testers")
    parser.add_argument("--version", action="version", version=f"{PRODUCT_SHORT} {VERSION}; {PRODUCT_NAME}; Author: {AUTHOR}; methodology {METHODOLOGY_VERSION}; artifact catalog {ARTIFACT_CATALOG_VERSION}")
    return parser.parse_args()


def _browse_for_installer(initial_dir=None):
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askopenfilename(
            title="Select Windows Installer",
            initialdir=str(initial_dir or Path.cwd()),
            filetypes=[
                ("Windows Installers", "*.msi *.exe"),
                ("MSI Packages", "*.msi"),
                ("Executable Installers", "*.exe"),
                ("All Files", "*.*"),
            ],
        )
        root.destroy()
        return selected or None
    except Exception as exc:
        console.print(f"[yellow][!] Native file picker unavailable: {exc}[/yellow]")
        return None


def _browse_for_portable_executable(initial_dir=None):
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askopenfilename(
            title="Select Portable Application Executable",
            initialdir=str(initial_dir or Path.cwd()),
            filetypes=[("Windows Executables", "*.exe"), ("All Files", "*.*")],
        )
        root.destroy()
        return selected or None
    except Exception as exc:
        console.print(f"[yellow][!] Native file picker unavailable: {exc}[/yellow]")
        return None


def _portable_executables(folder: Path) -> list[Path]:
    """Return a bounded, deterministic primary-EXE candidate list for a portable tree."""
    folder = Path(folder).resolve()
    candidates = []
    for depth, pattern in ((0, "*.exe"), (1, "*/*.exe")):
        for path in sorted(folder.glob(pattern), key=lambda p: str(p).lower()):
            try:
                if not path.is_file() or path.is_symlink():
                    continue
                resolved = path.resolve()
                resolved.relative_to(folder)
            except (OSError, ValueError):
                continue
            name = resolved.name.lower()
            penalty = 0
            if any(token in name for token in ("uninstall", "unins", "setup", "install", "update", "updater", "crash", "helper")):
                penalty += 25
            candidates.append((depth * 10 + penalty, resolved))
    candidates.sort(key=lambda item: (item[0], str(item[1]).lower()))
    seen = set()
    result = []
    for _, path in candidates:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            result.append(path)
    return result[:80]


def _resolve_portable_primary(source: Path, requested=None, *, interactive=True) -> tuple[Path, Path]:
    """Return (source, primary_executable) for a portable EXE or directory target."""
    source = Path(source).expanduser().resolve()
    if source.is_file():
        if source.suffix.lower() != ".exe":
            raise SystemExit("Portable file targets must be Windows .exe files.")
        return source, source
    if not source.is_dir():
        raise SystemExit(f"Portable application target not found: {source}")

    candidates = _portable_executables(source)
    if requested:
        candidate = Path(requested).expanduser()
        if not candidate.is_absolute():
            candidate = source / candidate
        candidate = candidate.resolve()
        try:
            candidate.relative_to(source)
        except ValueError as exc:
            raise SystemExit("--primary-executable must remain inside the selected portable application directory.") from exc
        if not candidate.is_file() or candidate.suffix.lower() != ".exe":
            raise SystemExit(f"Portable primary executable not found: {candidate}")
        return source, candidate

    if not candidates:
        raise SystemExit("No .exe files were found in the selected portable application directory.")
    if len(candidates) == 1:
        return source, candidates[0]
    if not interactive:
        choices = ", ".join(path.name for path in candidates[:8])
        raise SystemExit(
            "Multiple portable executables were found. Use --primary-executable to select the intended entry point. "
            f"Candidates include: {choices}"
        )

    console.print("\n[bold]Portable executable candidates[/bold]")
    for index, path in enumerate(candidates[:20], 1):
        try:
            display = path.relative_to(source)
        except ValueError:
            display = path.name
        console.print(f"{index}) {display}")
    if len(candidates) > 20:
        console.print(f"[dim]{len(candidates) - 20} additional executables omitted from the menu; use --primary-executable if needed.[/dim]")
    choice = web_prompt("Primary executable", choices=[str(i) for i in range(1, min(len(candidates), 20) + 1)], default="1")
    return source, candidates[int(choice) - 1]


def _browse_for_output(initial_dir=None, title="Select Assessment Output Directory"):
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askdirectory(
            title=title,
            initialdir=str(initial_dir or Path.cwd()),
            mustexist=False,
        )
        root.destroy()
        return selected or None
    except Exception as exc:
        console.print(f"[yellow][!] Native folder picker unavailable: {exc}[/yellow]")
        return None


def _choose_assessment_directory(title="Select WCA Assessment Directory"):
    selected = _browse_for_output(Path.cwd(), title=title) if os.name == "nt" else None
    if not selected:
        selected = Prompt.ask("Assessment directory")
    return Path(selected).expanduser().resolve()


def _print_assessment_status(path: Path):
    info = describe_assessment(path)
    old_state = info.get("state")
    if (old_state and old_state.data.get("framework_version") != VERSION
            and info.get("action") in {"INSTALL", "POST_INSTALL", "ANALYSIS"}):
        info["action"] = "HALT"
        info["guidance"] = ("Previous-version checkpoints are readable, but cross-version resume is blocked. "
                            f"Use the original version on the unchanged VM, or start a new v{VERSION} assessment. "
                            "Existing completed review state can be opened with --review.")
    console.print("\n[bold]Assessment Status / Recovery[/bold]")
    console.print(f"Directory: {path}")
    console.print(f"Status:    {info['status']}")
    console.print(f"Stage:     {info['stage']}")
    console.print(f"Recovery:  {info['action']}")
    console.print(f"Guidance:  {info['guidance']}")
    state = info.get("state")
    if state:
        data = state.data
        console.print(f"Assessment: {data.get('assessment_name','')}")
        console.print(f"Mode:       {data.get('mode','')}")
        target = data.get("target") or {}
        installer = data.get("installer", {})
        target_type = str(target.get("type") or "installable").lower()
        console.print(f"Target type:{' ' * 2}{target_type}")
        if target_type == "portable":
            console.print(f"Target:     {target.get('source_name') or target.get('primary_executable') or installer.get('filename','')}")
            console.print(f"Primary EXE:{' ' * 2}{target.get('primary_executable') or installer.get('filename','')}")
        else:
            console.print(f"Installer:  {installer.get('filename','')}")
        stages = data.get("stages", {})
        console.print("\nStage checkpoints:")
        for name, record in stages.items():
            console.print(f"  {name:28} {record.get('status','PENDING')}")
    return info


def _combined_assessment_status(path: Path):
    """Show lifecycle/recovery and integrity together, returning both results.

    Integrity is always attempted for structured assessments. During an
    unfinished assessment a final manifest may not exist yet; that is reported
    as not-finalized rather than implying that report regeneration is safe.
    """
    info = _print_assessment_status(path)
    verification = None
    if info.get("kind") != "structured":
        console.print("\n[dim]Integrity verification is available for structured assessments only.[/dim]")
        return info, verification

    verification = verify_assessment(path)
    manifest_missing = any(
        "Missing or invalid working/assessment_manifest.json" in issue
        for check in verification.get("checks", []) for issue in check.get("issues", [])
    )
    if manifest_missing and info.get("status") not in {"COMPLETED", "COMPLETE"}:
        console.print("\n[bold]Assessment Integrity[/bold]")
        console.print("Status:    NOT FINALIZED")
        console.print("Guidance:  A finalized SHA-256 manifest is created when assessment reporting completes.")
    else:
        console.print("\n" + format_verification(verification))
    return info, verification


def _status_available_actions(info: dict, verification: dict | None):
    """Return context-safe management actions for the combined status screen."""
    actions = []
    if verification and verification.get("repairable"):
        actions.append(("regenerate", "Regenerate Derived Reports"))
    if info.get("kind") == "structured" and info.get("action") in {"INSTALL", "POST_INSTALL", "ANALYSIS"}:
        actions.append(("resume", "Resume Assessment"))
    return actions


def _interactive_entry(args):
    direct = any([getattr(args, "target", None), getattr(args, "installer", None), getattr(args, "target_type", None), args.assessment_name, args.output, args.mode, args.status, args.resume,
                  args.verify_assessment, args.regenerate_reports, args.review, args.guided_runtime, args.client_appendix, args.non_interactive])
    if direct:
        return args
    console.print("\n[bold]Main Menu[/bold]\n---------")
    console.print("1) Start New Assessment")
    console.print("2) Assessment Status")
    console.print("3) Guided Tester Review")
    console.print("4) Guided Runtime Observation")
    console.print("5) Export Client Appendix")
    console.print("6) Exit")
    choice = Prompt.ask("Selection", choices=["1", "2", "3", "4", "5", "6"], default="1")
    if choice == "6":
        raise SystemExit(0)
    if choice == "5":
        args.client_appendix = str(_choose_assessment_directory("Select Completed Reviewed Assessment for Client Appendix"))
        return args
    if choice == "4":
        args.guided_runtime = str(_choose_assessment_directory("Select Completed Full Assessment for Guided Runtime"))
        return args
    if choice == "3":
        args.review = str(_choose_assessment_directory("Select Completed Assessment to Review"))
        return args
    if choice == "2":
        path = _choose_assessment_directory()
        info, verification = _combined_assessment_status(path)
        actions = _status_available_actions(info, verification)
        if not actions:
            console.print("\nNo repair or recovery action is currently available.")
            raise SystemExit(0)
        console.print("\n[bold]Available Actions[/bold]")
        for idx, (_, label) in enumerate(actions, 1):
            console.print(f"{idx}) {label}")
        console.print(f"{len(actions)+1}) Return")
        selected = Prompt.ask(
            "Selection",
            choices=[str(i) for i in range(1, len(actions)+2)],
            default=str(len(actions)+1),
        )
        if int(selected) == len(actions)+1:
            raise SystemExit(0)
        action = actions[int(selected)-1][0]
        if action == "regenerate":
            if not Confirm.ask("Regenerate only the damaged derived reports from verified authoritative state?", default=False):
                raise SystemExit(0)
            args.regenerate_reports = str(path)
            return args
        if action == "resume":
            if Confirm.ask("Resume this assessment from the saved checkpoint?", default=False):
                args.resume = str(path)
                return args
            raise SystemExit(0)
    return args


def _load_snapshot_for_resume(path: Path):
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    profile = os.environ.get("USERPROFILE") or ""
    def expand(value):
        if isinstance(value, str):
            return value.replace("%USERPROFILE%", profile) if profile else value
        if isinstance(value, list):
            return [expand(item) for item in value]
        if isinstance(value, dict):
            return {key: expand(item) for key, item in value.items()}
        return value
    return expand(data)


def _resume_inputs(args):
    assessment_dir = Path(args.resume).expanduser().resolve()
    state = AssessmentState.load(assessment_dir)
    if state is None:
        raise SystemExit("No structured assessment_state.json was found. Legacy flat assessments cannot be resumed implicitly.")
    if state.data.get("framework_version") != VERSION:
        raise SystemExit(f"Cross-version full-mode resume is blocked. Use the original framework on the unchanged VM or start a fresh v{VERSION} assessment. Completed review state remains accessible via --review.")
    action, guidance = state.recovery_action()
    if action in {"NONE", "HALT", "RESTART"}:
        raise SystemExit(guidance)

    target_meta = state.data.get("target") or {}
    target_type = str(target_meta.get("type") or "installable").lower()
    selected = getattr(args, "target", None) or getattr(args, "installer", None)
    if not selected:
        if target_type == "portable":
            source_kind = str(target_meta.get("source_kind") or "executable")
            if os.name == "nt" and not args.no_gui:
                console.print("[cyan][+][/cyan] Re-select the portable target so its primary executable SHA-256 can be verified.")
                if source_kind == "directory":
                    selected = _browse_for_output(Path.cwd(), title="Re-select Portable Application Directory")
                else:
                    selected = _browse_for_portable_executable()
            if not selected:
                selected = Prompt.ask("Portable target path")
        else:
            if os.name == "nt" and not args.no_gui:
                console.print("[cyan][+][/cyan] Re-select the original installer so its SHA-256 can be verified.")
                selected = _browse_for_installer()
            if not selected:
                selected = Prompt.ask("Original installer path")

    selected_path = Path(selected).expanduser().resolve()
    if target_type == "portable":
        requested_primary = getattr(args, "primary_executable", None) or target_meta.get("primary_executable")
        source_path, primary = _resolve_portable_primary(
            selected_path, requested_primary, interactive=not args.non_interactive,
        )
    else:
        source_path = selected_path
        primary = selected_path
        if not primary.is_file():
            raise SystemExit(f"Installer not found: {primary}")

    valid, message = state.validate_target(primary, source_path=source_path, target_type=target_type)
    if not valid:
        raise SystemExit(message)
    console.print(f"[green][+] {message}[/green]")
    saved = state.data.get("options", {})
    args.no_filesystem_snapshot = bool(saved.get("no_filesystem_snapshot", args.no_filesystem_snapshot))
    args.target_only = bool(saved.get("target_only", args.target_only))
    return primary, source_path, target_type, state.data.get("assessment_name") or assessment_dir.name, assessment_dir, state.data.get("mode") or "full", state, action

def resolve_inputs(args):
    selected = getattr(args, "target", None) or getattr(args, "installer", None)
    if getattr(args, "target", None) and getattr(args, "installer", None) and Path(args.target).expanduser() != Path(args.installer).expanduser():
        raise SystemExit("Use either --target or --installer, not two different target paths.")

    name = args.assessment_name
    output = args.output
    mode = args.mode
    target_type = (getattr(args, "target_type", None) or ("installable" if getattr(args, "installer", None) else "")).lower() or None
    use_gui = os.name == "nt" and not args.no_gui

    if not args.non_interactive:
        if not target_type:
            target_type = Prompt.ask(
                "Assessment target type",
                choices=["installable", "portable"],
                default="installable",
                case_sensitive=False,
            ).lower()

        if not selected:
            if target_type == "installable":
                if use_gui:
                    console.print("\n[cyan][+][/cyan] Select the MSI or EXE installer from the Windows file browser.")
                    selected = _browse_for_installer()
                if not selected:
                    selected = Prompt.ask("Installer path (.msi/.exe)")
            else:
                source_kind = Prompt.ask(
                    "Portable target source",
                    choices=["executable", "folder"],
                    default="executable",
                    case_sensitive=False,
                ).lower()
                if source_kind == "folder":
                    if use_gui:
                        console.print("\n[cyan][+][/cyan] Select the portable application directory.")
                        selected = _browse_for_output(Path.cwd(), title="Select Portable Application Directory")
                    if not selected:
                        selected = Prompt.ask("Portable application directory")
                else:
                    if use_gui:
                        console.print("\n[cyan][+][/cyan] Select the portable application executable.")
                        selected = _browse_for_portable_executable()
                    if not selected:
                        selected = Prompt.ask("Portable executable path (.exe)")

        default_name = Path(selected).stem if selected and Path(selected).suffix else (Path(selected).name if selected else "WindowsClientAssessment")
        name = name or Prompt.ask("Assessment name", default=default_name)
        mode = (mode or Prompt.ask("Assessment mode", choices=["static", "full"],
                                   default="static", case_sensitive=False)).lower()

        if not output:
            default_output = Path.cwd() / "assessments"
            if use_gui:
                console.print("[cyan][+][/cyan] Select the parent folder where assessment results should be saved.")
                output = _browse_for_output(default_output.parent)
            if not output:
                output = Prompt.ask("Assessment output directory", default=str(default_output))

    target_type = (target_type or "installable").lower()
    missing = [
        key
        for key, value in {
            "target": selected,
            "assessment name": name,
            "output": output,
            "mode": mode,
            "target type": target_type,
        }.items()
        if not value
    ]
    if missing:
        raise SystemExit("Missing required values: " + ", ".join(missing))

    selected_path = Path(selected).expanduser().resolve()
    if target_type == "installable":
        if not selected_path.is_file():
            raise SystemExit(f"Installer not found: {selected_path}")
        if selected_path.suffix.lower() not in {".msi", ".exe"}:
            raise SystemExit("Installable targets must be an .msi or .exe file.")
        source_path = selected_path
        primary_executable = selected_path
    else:
        source_path, primary_executable = _resolve_portable_primary(
            selected_path, getattr(args, "primary_executable", None), interactive=not args.non_interactive,
        )

    safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in name).strip()
    if not safe_name:
        raise SystemExit("Assessment name must contain at least one letter, number, dot, underscore, or hyphen.")
    if args.non_interactive and mode == "full":
        raise SystemExit(
            "Non-interactive full mode is not supported because Windows Client Assessment must pause between "
            "baseline and post-activity collection. Use interactive full mode, or use static mode for unattended analysis."
        )
    assessment_dir = Path(output).expanduser().resolve() / safe_name
    return primary_executable, source_path, target_type, safe_name, assessment_dir, mode

def show_tool_status(tools):
    table = Table(title="Tool Detection")
    table.add_column("Tool")
    table.add_column("Level")
    table.add_column("Usage")
    table.add_column("Status")
    table.add_column("Path / Note")
    for tool, info in tools.items():
        status = "[green]FOUND[/green]" if info["found"] else "[yellow]MISSING[/yellow]"
        table.add_row(tool, info["level"], info.get("usage", ""), status, info.get("path") or info.get("note") or "")
    console.print(table)


def run_module(reporter, name, func, *args, **kwargs):
    console.print(f"\n[cyan][+][/cyan] {name}")
    try:
        from utils.collection_provenance import module_scope
        with module_scope(name):
            result = func(*args, **kwargs) or {}
        status = result.get("status", "PASS") if isinstance(result, dict) else "PASS"
        details = result.get("details", "") if isinstance(result, dict) else ""
        if isinstance(result, dict):
            for finding in result.get("findings", []):
                finding_with_source = dict(finding)
                finding_with_source.setdefault("source_module", name)
                reporter.add_finding(**finding_with_source)
        coverage_gap = result.get("coverage_gap", False) if isinstance(result, dict) else False
    except Exception as exc:
        # Only collector errors are module failures. A failure writing the
        # authoritative lifecycle state is fatal, not a failed Secrets Review.
        reporter.set_status(name, "ERROR", str(exc))
        console.print(f"[red][!][/red] {name} failed: {exc}")
        return {"status": "ERROR", "details": str(exc)}
    reporter.set_status(name, status, details, coverage_gap=coverage_gap)
    from utils.collection_provenance import record_native_method
    record_native_method(name, getattr(func, '__name__', 'internal collector'),
                         status=('SKIPPED' if status in {'SKIPPED', 'NOT APPLICABLE'} else
                                 'FAILED' if status == 'ERROR' else 'COMPLETED'))
    return result if isinstance(result, dict) else {"status": status}


# The CLI remains the original entry point. The GUI supplies manual decisions
# through a private worker protocol rather than creating another terminal.
WEB_CONTROL = None


def web_prompt(message, *, default='', choices=None, **kwargs):
    if WEB_CONTROL is not None:
        return WEB_CONTROL.prompt(message, default=default, choices=choices)
    return Prompt.ask(message, default=default, choices=choices, **kwargs)


def web_confirm(message, *, default=False, **kwargs):
    if WEB_CONTROL is not None:
        return WEB_CONTROL.confirm(message, default=default)
    return Confirm.ask(message, default=default, **kwargs)


def main():
    global ACTIVE_STATE, WEB_CONTROL
    args = parse_args()
    from utils.web_worker import WebWorkerControl
    WEB_CONTROL = WebWorkerControl.from_environment()
    if args.gui_preselected_options and WEB_CONTROL is None:
        raise SystemExit("Preselected GUI options require an authenticated local GUI worker.")
    if args.gui:
        if args.backend_action or args.target or args.installer or args.status or args.review or args.guided_runtime or args.resume or args.client_appendix or args.regenerate_reports:
            raise SystemExit("--gui is a standalone launch mode; use the browser to start operations.")
        if not 1 <= args.port <= 65535:
            raise SystemExit("--port must be between 1 and 65535")
        _require_administrator(args, "WCA GUI")
        from utils.gui_server import serve_gui
        serve_gui(port=args.port, version=VERSION)
        return
    if args.backend_format != "json" and not args.backend_action:
        raise SystemExit("--backend-format requires --backend-action")
    if args.backend_action:
        if args.backend_action != "capabilities" and not args.backend_assessment:
            response = BackendService(version=VERSION).execute(args.backend_action)
        else:
            response = BackendService(version=VERSION).execute(args.backend_action, args.backend_assessment)
        if args.backend_format == "text":
            from utils.backend_format import render_backend_text
            print(render_backend_text(args.backend_action, response), end="")
        else:
            print(json.dumps(response, sort_keys=True))
        if not response["ok"]:
            raise SystemExit(9)
        return
    banner()
    args = _interactive_entry(args)
    if args.mode == "full" or args.guided_runtime:
        _require_administrator(args, "Guided Runtime" if args.guided_runtime else "Full Assessment")
    if args.client_appendix:
        source = Path(args.client_appendix).expanduser().resolve()
        destination = (Path(args.appendix_output).expanduser().resolve() if args.appendix_output
                       else source.parent / (source.name + "-ClientAppendix.zip"))
        try:
            if not args.appendix_output and not Confirm.ask("Export approved sanitized, reviewed evidence to a separate client appendix?", default=False):
                return
            with assessment_operation(source, "client_appendix"):
                result = export_client_appendix(source, destination)
        except (OSError, ValueError, ClientAppendixError, AssessmentBusyError) as exc:
            console.print(f"[red]Client Appendix blocked: {exc}[/red]")
            raise SystemExit(9) from exc
        console.print(f"[green]Client Appendix verified:[/green] {result}")
        return
    if args.review:
        try:
            review_root = Path(args.review).expanduser().resolve()
            with assessment_operation(review_root, "guided_review"):
                guided_review_cli(review_root)
        except (OSError, ValueError, AssessmentBusyError) as exc:
            console.print(f"[red]Guided Review unavailable: {exc}[/red]")
            raise SystemExit(9) from exc
        return
    if args.guided_runtime:
        try:
            runtime_root = Path(args.guided_runtime).expanduser().resolve()
            with assessment_operation(runtime_root, "guided_runtime"):
                result = run_guided_runtime(
                    runtime_root, version=VERSION, methodology_version=METHODOLOGY_VERSION,
                    catalog_version=ARTIFACT_CATALOG_VERSION,
                    input_fn=(lambda message: WEB_CONTROL.prompt(message)) if WEB_CONTROL else input,
                    web_control=WEB_CONTROL,
                )
        except (OSError, ValueError, RuntimeError, AssessmentBusyError) as exc:
            console.print(f"[red]Guided Runtime unavailable: {exc}[/red]")
            raise SystemExit(9) from exc
        summary = result.get("summary") or {}
        counts = summary.get("counts") or {}
        session = summary.get("session") or {}
        capture_duration = int(session.get("capture_duration_seconds") or session.get("duration_seconds") or 0)
        processing_duration = int(session.get("processing_duration_seconds") or 0)
        total_duration = int(result.get("operation_total_seconds") or session.get("total_duration_seconds") or 0)
        def _clock(value):
            h, rem = divmod(max(0, int(value or 0)), 3600); m, sec = divmod(rem, 60)
            return f"{h:02d}:{m:02d}:{sec:02d}"
        console.print("\n[bold green]Guided Runtime Observation complete.[/bold green]")
        console.print(f"Capture duration:       {_clock(capture_duration)}")
        console.print(f"Evidence processing:    {_clock(processing_duration)}")
        console.print(f"Total operation:        {_clock(total_duration)}")
        if session.get("failure_stage"):
            console.print(f"Procmon result:         COLLECTION UNAVAILABLE ({session.get('failure_stage')})")
        console.print(f"Current target processes: {counts.get('current_target_processes', 0)}")
        console.print(f"Target processes seen:  {counts.get('target_processes_seen', 0)}")
        console.print(f"Target Procmon events:  {counts.get('procmon_target_events', 0)}")
        console.print(f"Sessions retained:      {result['sessions']}")
        console.print(f"New review candidates:  {result['new_findings']}")
        console.print(f"Effective coverage:     {result.get('coverage')}")
        console.print(format_verification(result['after']))
        return
    if args.status:
        _combined_assessment_status(Path(args.status).expanduser().resolve())
        return
    if args.verify_assessment:
        root = Path(args.verify_assessment).expanduser().resolve()
        existing = AssessmentState.load(root)
        # Read-only verification accepts original intact manifests from earlier
        # releases. A reviewer-only update must not require re-collecting or
        # silently migrating completed assessment evidence.
        expected = VERSION if existing and existing.data.get('framework_version') == VERSION else None
        result = verify_assessment(root, expected_framework_version=expected)
        console.print(format_verification(result))
        if result["status"] == "FAIL":
            raise SystemExit(9)
        return
    if args.regenerate_reports:
        try:
            regen_root = Path(args.regenerate_reports).expanduser().resolve()
            with assessment_operation(regen_root, "regenerate_reports"):
                result = regenerate_derived_reports(regen_root)
        except (OSError, ValueError, AssessmentBusyError) as exc:
            console.print(f"[red]Regeneration refused: {exc}[/red]")
            raise SystemExit(9) from exc
        console.print(format_verification(result))
        if result["status"] != "PASS":
            raise SystemExit(9)
        return
    resume_action = None
    state = None
    if args.resume:
        installer, target_source, target_type, assessment_name, assessment_dir, mode, state, resume_action = _resume_inputs(args)
    else:
        installer, target_source, target_type, assessment_name, assessment_dir, mode = resolve_inputs(args)
        existing = describe_assessment(assessment_dir) if assessment_dir.exists() else {"kind": "unknown"}
        if existing.get("kind") in {"structured", "legacy"}:
            raise SystemExit(
                "The selected assessment directory already contains Windows Client Assessment data. "
                f"v{VERSION} will not overwrite it silently. Choose a new assessment name or use Assessment Status / Recovery."
            )
    if mode == "full":
        _require_administrator(args, "Full Assessment")
    try:
        with assessment_operation(assessment_dir, "assessment_execution"):
            return _run_assessment_engine(args, installer, target_source, target_type, assessment_name,
                                          assessment_dir, mode, state, resume_action)
    except AssessmentBusyError as exc:
        raise SystemExit(f"Assessment operation blocked: {exc}") from exc


def _run_assessment_engine(args, installer, target_source, target_type, assessment_name,
                           assessment_dir, mode, state, resume_action):
    from utils.collection_provenance import session
    with session(assessment_dir, 'full-assessment' if mode == 'full' else 'static-assessment', retain=state is not None):
        return _run_assessment_engine_impl(args, installer, target_source, target_type,
                                           assessment_name, assessment_dir, mode, state, resume_action)


def _run_assessment_engine_impl(args, installer, target_source, target_type, assessment_name,
                                assessment_dir, mode, state, resume_action):
    """Existing v1.9.2 assessment orchestration, guarded by a per-assessment lock.

    Moving orchestration here does not modify module order, prompts, evidence
    collection, state/checkpoints, or tester-only target execution policy.
    """
    global ACTIVE_STATE
    assessment_dir.mkdir(parents=True, exist_ok=True)
    ensure_structured_layout(assessment_dir)

    if state is None:
        preserve_paths = []
        if args.procmon_csv:
            preserve_paths.append(args.procmon_csv)
        removed_artifacts = reset_generated_artifacts(assessment_dir, preserve_paths=preserve_paths)
        if removed_artifacts:
            console.print(
                f"[dim]Cleared {len(removed_artifacts)} stale Windows Client Assessment-generated artifact(s) "
                "from the existing assessment directory.[/dim]"
            )
    write_filter_report(
        artifact_path(assessment_dir, "assessment_filters.txt"),
        args.exclude_path,
        {},
        args.target_only,
    )

    tools = detect_tools()
    if state is None:
        state = AssessmentState.create(
            assessment_dir, assessment_name=assessment_name, installer=installer, mode=mode, framework_version=VERSION,
            target_type=target_type, target_source=target_source,
            options={
                "no_extract": bool(args.no_extract),
                "no_filesystem_snapshot": bool(args.no_filesystem_snapshot),
                "target_only": bool(args.target_only),
                "exclude_path_count": len(args.exclude_path),
                "runtime_capture_requested": bool(args.runtime_capture),
                "surface_review_requested": bool(args.surface_review),
                "application_dir_supplied": bool(args.application_dir),
                "target_type": target_type,
            },
            tools=tools,
        )
    ACTIVE_STATE = state
    reporter = AssessmentReporter(assessment_dir, assessment_name, installer, mode, VERSION, state_tracker=state, target_type=target_type)
    show_tool_status(tools)
    reporter.write_tool_detection(tools)
    state.checkpoint("static_analysis", "STARTED", "Static analysis started or refreshed.")

    console.print(f"\n[bold]Target type:[/bold] {target_type}")
    if target_type == "portable":
        console.print(f"[bold]Portable source:[/bold] {target_source}")
        console.print(f"[bold]Primary executable:[/bold] {installer}")
    else:
        console.print(f"[bold]Installer:[/bold] {installer}")
    console.print(f"[bold]Mode:[/bold] {mode}")
    console.print(f"[bold]Output:[/bold] {assessment_dir}")

    console.print(f"[bold]Framework:[/bold] Windows Client Assessment v{VERSION}")
    console.print(
        f"[bold]Filesystem snapshot:[/bold] "
        f"{'disabled' if args.no_filesystem_snapshot else 'enabled when full mode is used'}"
    )
    if args.exclude_path:
        console.print(f"[bold]Excluded paths:[/bold] {len(args.exclude_path)} configured")
    console.print(f"[bold]Target-only inventory:[/bold] {bool(args.target_only)}")


    if target_type == "portable":
        installer_result = run_module(
            reporter, "Target Information", run_target_info, installer, assessment_dir,
            source_path=target_source, target_type=target_type,
        )
        reporter.set_status("Installer Information", "NOT APPLICABLE", "Portable application target")
        reporter.set_status("Installer Technology", "NOT APPLICABLE", "Portable application target")
        technology_result = {"status": "NOT APPLICABLE", "technologies": [], "die_output": ""}
        explicit_scope = target_source if Path(target_source).is_dir() else args.application_dir
    else:
        reporter.set_status("Target Information", "NOT APPLICABLE", "Installable application target")
        installer_result = run_module(reporter, "Installer Information", run_installer_info, installer, assessment_dir)
        technology_result = run_module(
            reporter, "Installer Technology", run_installer_technology,
            installer, assessment_dir, tools, installer_result.get("installer_prefix"),
        )
        explicit_scope = args.application_dir

    try:
        application_scope = detect_application_scope(
            installer, assessment_dir, technology_result.get("technologies"),
            technology_result.get("die_output", ""), explicit_scope, target_type=target_type,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    # A selected portable EXE or published .NET host may have companion files.
    # Never enumerate arbitrary neighboring files without an explicit tester opt-in.
    if (application_scope["kind"] in {"dotnet_apphost_unbundled", "portable_executable"}
            and not explicit_scope and not args.non_interactive and not args.gui_preselected_options):
        prompt = (
            "Select the portable/deployed application folder containing companion files?"
            if target_type == "portable"
            else "Select a deployed application folder containing companion DLLs?"
        )
        if web_confirm(prompt, default=False):
            folder = _browse_for_output(
                installer.parent, title="Select Application Folder"
            ) if os.name == "nt" and not args.no_gui else None
            if not folder:
                folder = web_prompt("Application directory", default=str(installer.parent))
            try:
                application_scope = detect_application_scope(
                    installer, assessment_dir, technology_result.get("technologies"),
                    technology_result.get("die_output", ""), folder, target_type=target_type,
                )
            except ValueError as exc:
                raise SystemExit(str(exc)) from exc

    write_application_scope(assessment_dir, installer, application_scope)
    reporter.set_status(
        "Application / Package Scope",
        "WARN" if application_scope["truncated"] else "PASS",
        f"{application_scope['kind']}; {len(application_scope['roots'])} source file(s) scoped",
        coverage_gap=application_scope["truncated"],
    )
    if target_type == "portable":
        console.print(f"[cyan][+][/cyan] Portable application scope: {application_scope['kind']}")
        if application_scope["kind"] == "portable_executable":
            console.print("[yellow][!] Only the selected executable is in static scope; select an application folder for companion files when needed.[/yellow]")
    elif application_scope["kind"] in {"dotnet_published_application", "dotnet_apphost_unbundled"}:
        console.print("[cyan][+][/cyan] Published .NET application host detected; not treated as a setup package.")
        if application_scope["kind"] == "dotnet_apphost_unbundled":
            console.print("[yellow][!] No matching managed DLL or publishing sidecar found; "
                          "use --application-dir for a deployed folder, or assess a single-file bundle manually.[/yellow]")
    elif application_scope["kind"] == "explicit_application_directory":
        console.print(f"[cyan][+][/cyan] Explicit application folder scoped: "
                      f"{len(application_scope['roots'])} source file(s)")

    run_module(reporter, "Digital Signature Review", run_signature_review, installer, assessment_dir, "Portable primary executable" if target_type == "portable" else "Installer package")

    if target_type == "portable":
        extraction_result = {"status": "NOT APPLICABLE", "extract_dir": None}
        reporter.set_status("Installer Extraction", "NOT APPLICABLE", "Portable application target")
        reporter.set_status("MSI Analysis", "NOT APPLICABLE", "Portable application target")
    else:
        if args.no_extract:
            extraction_result = {"status": "SKIPPED", "extract_dir": None}
            reporter.set_status("Installer Extraction", "SKIPPED", "--no-extract used",
                                coverage_gap=bool(application_scope["known_installer"]))
        else:
            extraction_result = run_module(
                reporter, "Installer Extraction", run_installer_extract, installer, assessment_dir,
                tools, True, application_scope,
            )

        if installer.suffix.lower() == ".msi":
            run_module(reporter, "MSI Analysis", run_msi_analysis, installer, assessment_dir)
        else:
            reporter.set_status("MSI Analysis", "NOT APPLICABLE", "Selected installable target is not an MSI")

    analysis_roots = list(application_scope["roots"])
    if extraction_result.get("extract_dir"):
        analysis_roots.append(Path(extraction_result["extract_dir"]))

    static_inventory = build_file_inventory(analysis_roots)
    write_file_inventory_csv(static_inventory, artifact_path(assessment_dir, "file_inventory.csv"), installer)
    if extraction_result.get("extract_dir"):
        finalize_extraction_report(assessment_dir, extraction_result, static_inventory)
    console.print(f"[bold]Static file inventory:[/bold] {len(static_inventory)} file(s)")

    pe_result = run_module(reporter, "PE Security Review", run_pe_analysis, analysis_roots, assessment_dir, static_inventory)
    dotnet_result = run_module(
        reporter,
        ".NET Detection / Source Review",
        run_dotnet_analysis,
        analysis_roots,
        assessment_dir,
        tools,
        static_inventory,
        pe_result,
        application_scope,
    )
    run_module(reporter, "Configuration Review", run_configuration_review, analysis_roots, assessment_dir, static_inventory)
    run_module(reporter, "Secrets Review", run_secrets_review, analysis_roots, assessment_dir, static_inventory, application_scope)
    electron_result = run_module(
        reporter,
        "Electron Security Review",
        run_electron_security_review,
        analysis_roots,
        assessment_dir,
        static_inventory,
    )
    run_module(
        reporter,
        "Component Lifecycle Review",
        run_component_lifecycle_review,
        analysis_roots,
        assessment_dir,
        static_inventory,
        electron_result,
    )
    static_updater_candidates = discover_updater_candidates(
        static_inventory, None, exclude_paths=args.exclude_path
    )
    if mode == "static":
        run_module(
            reporter,
            "Updater Review (Static)",
            run_updater_review,
            assessment_dir,
            None,
            None,
            static_updater_candidates,
        )
    else:
        reporter.set_status(
            "Updater Review (Static)",
            "SKIPPED",
            "Static candidates collected in memory and consolidated into the full installed updater review",
        )

    state.checkpoint("static_analysis", "COMPLETED", "Static analysis completed.")

    pre = {}
    post = {}
    diff = {}
    runtime_targets_result = {}
    installed_updater_result = {}
    network_result = {}
    ipc_result = {}
    permissions_result = {}
    privilege_result = {}
    local_storage_result = {}
    application_profile_result = {}
    acl_cache = AclCache()
    full_install_state_ready = False
    full_snapshot_failed = False

    if mode == "full":
        include_filesystem = not args.no_filesystem_snapshot
        console.print("\n[bold yellow]Full mode:[/bold yellow] capturing expanded baseline snapshot before tester-controlled target activity.")
        saved_pre = _load_snapshot_for_resume(artifact_path(assessment_dir, "snapshot_pre.json")) if resume_action in {"INSTALL", "POST_INSTALL", "ANALYSIS"} else None
        if saved_pre is not None:
            pre = {"status": "PASS", "details": "Loaded trusted baseline snapshot from saved checkpoint", "snapshot": saved_pre}
            reporter.set_status("Baseline Snapshot", "PASS", pre["details"])
        else:
            state.checkpoint("pre_install_snapshot", "STARTED", "Capturing baseline snapshot.")
            pre = run_module(
                reporter,
                "Baseline Snapshot",
                capture_snapshot,
                artifact_path(assessment_dir, "snapshot_pre.json"),
                include_filesystem,
            )
            if pre.get("snapshot"):
                try:
                    state.record_snapshot_integrity("pre_install_snapshot", "snapshot_pre.json")
                    state.checkpoint("pre_install_snapshot", "COMPLETED", "Baseline snapshot completed and pinned by SHA-256.")
                except (ValueError, OSError) as exc:
                    pre = {"status": "ERROR", "details": str(exc), "snapshot": None}
                    reporter.set_status("Baseline Snapshot", "ERROR", str(exc))

        if not pre.get("snapshot"):
            full_snapshot_failed = True
            console.print(
                "\n[bold red][!] Baseline snapshot failed.[/bold red] "
                "The state-differential phase will not continue because no valid baseline exists."
            )
            console.print(
                "[yellow]Review snapshot_pre.json, correct the PowerShell/snapshot issue, "
                "and rerun from the clean VM baseline.[/yellow]"
            )
            reporter.set_status(
                "Post-Activity Snapshot",
                "SKIPPED",
                "Baseline snapshot failed; target activity was not requested",
            )
            reporter.set_status(
                "System Change Analysis",
                "SKIPPED",
                "Baseline snapshot unavailable",
            )
            run_module(
                reporter,
                "Updater Review (Static)",
                run_updater_review,
                assessment_dir,
                None,
                None,
                static_updater_candidates,
            )
            for module_name in [
                "Services Review",
                "Scheduled Tasks",
                "Permissions Review",
                "Persistence Review",
                "Driver Review",
                "Privilege Boundary Review",
                "Local Storage Review",
                "Updater Review (System State)",
            ]:
                reporter.set_status(
                    module_name,
                    "SKIPPED",
                    "Baseline snapshot failed; system-state differential unavailable",
                )
        else:
            saved_post = _load_snapshot_for_resume(artifact_path(assessment_dir, "snapshot_post.json")) if resume_action == "ANALYSIS" else None
            if saved_post is not None:
                post = {"status": "PASS", "details": "Loaded trusted post-activity snapshot from saved checkpoint", "snapshot": saved_post}
                reporter.set_status("Post-Activity Snapshot", "PASS", post["details"])
            else:
                if resume_action != "POST_INSTALL":
                    if target_type == "portable":
                        console.print("\nLaunch the portable application and exercise the representative in-scope workflows using the approved assessment procedure.")
                        console.print("[dim]WCA does not launch or exercise the target automatically.[/dim]")
                        web_prompt("Press Enter after representative portable-application activity is complete", default="")
                        state.checkpoint("installation_confirmation", "COMPLETED", "Tester confirmed portable application activity completed.")
                    else:
                        console.print("\nInstall the target application using the approved assessment procedure.")
                        web_prompt("Press Enter after installation is complete", default="")
                        state.checkpoint("installation_confirmation", "COMPLETED", "Tester confirmed installation completed.")
                state.checkpoint("post_install_snapshot", "STARTED", "Capturing post-activity snapshot.")
                post = run_module(
                    reporter,
                    "Post-Activity Snapshot",
                    capture_snapshot,
                    artifact_path(assessment_dir, "snapshot_post.json"),
                    include_filesystem,
                )
                if post.get("snapshot"):
                    try:
                        state.record_snapshot_integrity("post_install_snapshot", "snapshot_post.json")
                        state.checkpoint("post_install_snapshot", "COMPLETED", "Post-activity snapshot completed and pinned by SHA-256.")
                    except (ValueError, OSError) as exc:
                        post = {"status": "ERROR", "details": str(exc), "snapshot": None}
                        reporter.set_status("Post-Activity Snapshot", "ERROR", str(exc))

            if post.get("snapshot"):
                diff = compare_snapshots(pre["snapshot"], post["snapshot"])
                diff, removed_by_filters = filter_install_diff(
                    diff, args.exclude_path, exclude_framework_noise=True,
                )
                write_filter_report(
                    artifact_path(assessment_dir, "assessment_filters.txt"),
                    args.exclude_path,
                    removed_by_filters,
                    args.target_only,
                )
                write_snapshot_diff(diff, assessment_dir)
                full_install_state_ready = True
                install_status, install_details = installation_footprint_status(diff, application_scope)
                reporter.set_status("System Change Analysis", install_status, install_details)

                run_module(
                    reporter,
                    "Services Review",
                    run_services_review,
                    assessment_dir,
                    pre.get("snapshot"),
                    post.get("snapshot"),
                    tools,
                    diff,
                    acl_cache,
                )
                run_module(
                    reporter,
                    "Scheduled Tasks",
                    run_scheduled_tasks_review,
                    assessment_dir,
                    pre.get("snapshot"),
                    post.get("snapshot"),
                    diff,
                    acl_cache,
                )
                permissions_result = run_module(
                    reporter,
                    "Permissions Review",
                    run_permissions_review,
                    assessment_dir,
                    pre.get("snapshot"),
                    post.get("snapshot"),
                    diff,
                    acl_cache,
                    [application_scope["application_dir"]] if application_scope.get("application_dir") else [],
                )
                run_module(
                    reporter,
                    "Persistence Review",
                    run_persistence_review,
                    assessment_dir,
                    pre.get("snapshot"),
                    post.get("snapshot"),
                    diff,
                    static_inventory,
                    acl_cache,
                )
                run_module(
                    reporter,
                    "Driver Review",
                    run_drivers_review,
                    assessment_dir,
                    pre.get("snapshot"),
                    post.get("snapshot"),
                    diff,
                    acl_cache,
                )
                privilege_result = run_module(
                    reporter,
                    "Privilege Boundary Review",
                    run_privilege_boundary_review,
                    assessment_dir,
                    diff,
                    post.get("snapshot"),
                    permissions_result.get("permission_results"),
                    acl_cache,
                )
                installed_updater_result = run_module(
                    reporter,
                    "Updater Review (System State)",
                    run_updater_review,
                    assessment_dir,
                    None,
                    diff,
                    static_updater_candidates,
                    args.exclude_path,
                    static_inventory,
                )
                state.checkpoint("installed_state_analysis", "COMPLETED", "System-state analysis completed.")
            else:
                full_snapshot_failed = True
                reporter.set_status(
                    "System Change Analysis",
                    "SKIPPED",
                    "Post-activity snapshot failed; comparison unavailable",
                )
                console.print(
                    "\n[bold red][!] Post-activity snapshot failed.[/bold red] "
                    "Differential-dependent modules will be skipped rather than generating empty results."
                )
                console.print(
                    "[yellow]Revert the VM to the clean assessment baseline before rerunning a complete full-mode assessment.[/yellow]"
                )
                run_module(
                    reporter,
                    "Updater Review (Static)",
                    run_updater_review,
                    assessment_dir,
                    None,
                    None,
                    static_updater_candidates,
                )
                for module_name in [
                    "Services Review",
                    "Scheduled Tasks",
                    "Permissions Review",
                    "Persistence Review",
                    "Driver Review",
                    "Privilege Boundary Review",
                    "Local Storage Review",
                    "Updater Review (System State)",
                ]:
                    reporter.set_status(
                        module_name,
                        "SKIPPED",
                        "Post-activity snapshot failed; system-state differential unavailable",
                    )
    else:
        for module_name in [
            "Baseline Snapshot",
            "Post-Activity Snapshot",
            "System Change Analysis",
            "Services Review",
            "Scheduled Tasks",
            "Permissions Review",
            "Persistence Review",
            "Driver Review",
            "Privilege Boundary Review",
            "Local Storage Review",
            "Updater Review (System State)",
        ]:
            reporter.set_status(module_name, "SKIPPED", "Static mode")

    supplied_procmon_csv = None
    if args.procmon_csv:
        supplied_csv = Path(args.procmon_csv).expanduser().resolve()
        if supplied_csv.is_file():
            supplied_procmon_csv = str(supplied_csv)
        else:
            reporter.set_status(
                "Procmon Analysis",
                "ERROR",
                f"Procmon CSV not found: {supplied_csv}",
            )
            console.print(f"[red][!] Procmon CSV not found: {supplied_csv}[/red]")

    runtime_phase_applicable = bool(full_install_state_ready or supplied_procmon_csv)
    if runtime_phase_applicable:
        state.checkpoint("runtime_optional", "STARTED", "Runtime analysis stage started.")
        runtime_targets_result = run_module(
            reporter,
            "Runtime Target Discovery",
            run_runtime_target_discovery,
            assessment_dir,
            diff,
            post.get("snapshot") if isinstance(post, dict) else None,
            analysis_roots,
            static_inventory,
            args.exclude_path,
        )
        runtime_targets = runtime_targets_result.get("runtime_targets", [])
    else:
        runtime_targets_result = {}
        runtime_targets = []
        reporter.set_status(
            "Runtime Target Discovery",
            "SKIPPED",
            "Runtime phase not applicable to this run",
        )

    if args.runtime_capture and (mode != "full" or not full_install_state_ready):
        reason = (
            "--runtime-capture requires full mode"
            if mode != "full"
            else "Snapshot differential unavailable"
        )
        console.print(
            "[yellow][!] Procmon runtime capture skipped because a valid system-state "
            "full-mode differential is unavailable.[/yellow]"
        )
        reporter.set_status("Procmon Runtime Capture", "SKIPPED", reason)
        runtime_capture_requested = False
    else:
        runtime_capture_requested = bool(args.runtime_capture)

    if (
        mode == "full"
        and full_install_state_ready
        and not args.non_interactive
        and not runtime_capture_requested
        and not args.procmon_csv
        and not args.gui_preselected_options
    ):
        runtime_capture_requested = web_confirm(
            "Run optional Procmon/runtime capture now?",
            default=False,
        )

    procmon_csv_path = None
    capture_result = {}

    if runtime_capture_requested:
        capture_result = run_module(
            reporter,
            "Procmon Runtime Capture",
            run_procmon_capture,
            assessment_dir,
            tools,
            args.runtime_seconds,
            not args.non_interactive,
            input_fn=(lambda message: WEB_CONTROL.prompt(message)) if WEB_CONTROL else input,
        )
        procmon_csv_path = capture_result.get("csv_path")
    elif not supplied_procmon_csv:
        reporter.set_status(
            "Procmon Runtime Capture",
            "SKIPPED",
            "Optional runtime capture not selected",
        )

    if supplied_procmon_csv:
        procmon_csv_path = supplied_procmon_csv
        if not runtime_capture_requested:
            reporter.set_status(
                "Procmon Runtime Capture",
                "SKIPPED",
                "Using existing Procmon CSV supplied with --procmon-csv",
            )

    procmon_result = {}
    runtime_process_result = {}
    if procmon_csv_path:
        procmon_result = run_module(
            reporter,
            "Procmon Analysis",
            run_procmon_analysis,
            assessment_dir,
            procmon_csv_path,
            runtime_targets,
            capture_result.get("sanitization"),
        )
        dll_result = run_module(
            reporter,
            "DLL Search Review",
            run_dll_search_review,
            assessment_dir,
            procmon_result.get("procmon_data"),
            runtime_targets,
            acl_cache,
        )
        # Permissions Review runs before runtime capture. Refresh the *same*
        # authoritative TXT report only for target-filtered DLL lookups; do not
        # introduce a second ACL report or duplicate an existing finding.
        runtime_dll = dll_result.get("dll_records", [])
        if (
            full_install_state_ready
            and procmon_result.get("procmon_data", {}).get("target_filter_active")
            and any(row.get("BroadWriteACEs") or row.get("LikelyUserWritableLocation") for row in runtime_dll)
        ):
            console.print("[cyan][+][/cyan] Correlating runtime DLL-search paths with Permissions Review")
            try:
                refreshed = run_permissions_review(
                    assessment_dir,
                    pre.get("snapshot"),
                    post.get("snapshot"),
                    diff,
                    acl_cache,
                    [application_scope["application_dir"]] if application_scope.get("application_dir") else [],
                    runtime_dll,
                )
                previous_titles = {f["title"] for f in permissions_result.get("findings", [])}
                for finding in refreshed.get("findings", []):
                    if finding["title"] not in previous_titles:
                        reporter.add_finding(source_module="Permissions Review", **finding)
                permissions_result = refreshed
                reporter.set_status(
                    "Permissions Review", refreshed["status"], refreshed["details"],
                )
            except Exception as exc:
                # Do not silently report the old installation-only ACL result
                # when a requested runtime correlation could not be completed.
                reporter.set_status("Permissions Review", "ERROR", f"Runtime DLL ACL correlation failed: {exc}")
                console.print(f"[red][!][/red] Runtime DLL ACL correlation failed: {exc}")
        runtime_process_result = run_module(
            reporter,
            "Runtime Process Review",
            run_runtime_process_review,
            assessment_dir,
            runtime_targets,
            procmon_result.get("observed_process_names"),
            tools,
            args.exclude_path,
        )
    else:
        if "Procmon Analysis" not in reporter.status:
            reporter.set_status("Procmon Analysis", "SKIPPED", "No Procmon CSV available")
        reporter.set_status("DLL Search Review", "SKIPPED", "No Procmon analysis data")
        reporter.set_status(
            "Runtime Process Review",
            "SKIPPED",
            "Runtime capture/import not selected",
        )

    if procmon_result.get("procmon_data"):
        run_module(
            reporter,
            "Advanced .NET / Native Runtime Review",
            run_advanced_runtime_review,
            assessment_dir,
            dotnet_result,
            runtime_targets,
            procmon_result.get("procmon_data"),
            runtime_process_result.get("runtime_processes"),
            tools,
            "full" if full_install_state_ready else "static",
        )
    else:
        reporter.set_status(
            "Advanced .NET / Native Runtime Review",
            "SKIPPED",
            "No Procmon runtime evidence available",
        )

    if mode == "full" and full_install_state_ready:
        local_storage_result = run_module(
            reporter,
            "Local Storage Review",
            run_local_storage_review,
            assessment_dir,
            diff,
            procmon_result.get("procmon_data"),
            runtime_targets,
            static_inventory,
            installer_result,
            acl_cache,
            not args.no_filesystem_snapshot,
            runtime_process_result.get("runtime_processes") or [],
        )
    elif "Local Storage Review" not in reporter.status:
        reporter.set_status(
            "Local Storage Review", "SKIPPED",
            "Static mode" if mode != "full" else "System-state differential unavailable",
            coverage_gap=(mode == "full"),
        )

    if args.surface_review and (mode != "full" or not full_install_state_ready):
        reason = (
            "--surface-review requires full mode"
            if mode != "full"
            else "Snapshot differential unavailable"
        )
        console.print(
            "[yellow][!] Network/IPC surface review skipped because a valid system-state "
            "full-mode differential is unavailable.[/yellow]"
        )
        reporter.set_status("Network Surface Review", "SKIPPED", reason)
        reporter.set_status("IPC / Named Pipe Review", "SKIPPED", reason)
        surface_review_requested = False
    else:
        surface_review_requested = bool(args.surface_review)

    if (mode == "full" and full_install_state_ready and not args.non_interactive
            and not surface_review_requested and not args.gui_preselected_options):
        surface_review_requested = web_confirm(
            "Run network/IPC surface review now?",
            default=True,
        )

    if surface_review_requested and mode == "full" and full_install_state_ready:
        state.checkpoint("surface_optional", "STARTED", "Network/IPC surface review started.")
        if not args.non_interactive and not args.gui_preselected_options:
            console.print(
                "\n[cyan][+][/cyan] Ensure the target client and relevant background/service "
                "components are running before surface collection."
            )
            web_prompt("Press Enter when the client is ready for network/IPC collection", default="")
        elif args.gui_preselected_options:
            console.print("[+] Network/IPC review was preselected in the browser; "
                          "using the target readiness confirmed at the installation/activity checkpoint.")

        observed_names = procmon_result.get("observed_process_names", [])
        network_result = run_module(
            reporter,
            "Network Surface Review",
            run_network_surface_review,
            assessment_dir,
            runtime_targets,
            observed_names,
            None,
            diff,
            electron_result,
            args.exclude_path,
            procmon_result.get("procmon_data"),
        )
        surface_processes = network_result.get("runtime_processes", [])

        ipc_result = run_module(
            reporter,
            "IPC / Named Pipe Review",
            run_ipc_review,
            assessment_dir,
            tools,
            runtime_targets,
            observed_names,
            surface_processes,
            None,
            args.exclude_path,
            args.target_only,
        )
        state.checkpoint("surface_optional", "COMPLETED", "Network/IPC surface review completed.")
    else:
        if "Network Surface Review" not in reporter.status:
            reporter.set_status("Network Surface Review", "SKIPPED", "Optional network/IPC surface review not selected")
        if "IPC / Named Pipe Review" not in reporter.status:
            reporter.set_status("IPC / Named Pipe Review", "SKIPPED", "Optional network/IPC surface review not selected")

    updater_candidates = (
        installed_updater_result.get("updater_candidates", [])
        if full_install_state_ready and installed_updater_result
        else []
    )
    if full_install_state_ready and updater_candidates:
        run_module(
            reporter,
            "Updater Security Correlation",
            run_updater_security_review,
            assessment_dir,
            updater_candidates,
            diff,
            post.get("snapshot") if isinstance(post, dict) else None,
            procmon_result.get("procmon_data"),
            runtime_process_result.get("runtime_processes"),
            "full",
            not args.no_filesystem_snapshot,
            acl_cache,
        )
    elif full_install_state_ready and not updater_candidates:
        # Not an error: a complete system-state differential found no updater.
        # Do not pretend that a non-existent updater was security-tested.
        reporter.set_status("Updater Security Correlation", "NOT APPLICABLE",
                            "Full-mode system-state differential completed; "
                            "no updater/launcher candidates were identified; no updater tested")
    else:
        reporter.set_status("Updater Security Correlation", "SKIPPED",
                            "Updater review unavailable: a valid full-mode system-state "
                            "differential was not collected; investigate upstream checkpoint/collector status")

    # Target-specific attack-surface correlations use only verified differential
    # and optional target-filtered/sanitized Procmon evidence. They do not
    # execute the application or claim a vulnerability has been confirmed.
    if full_install_state_ready:
        run_module(
            reporter, "Attack Surface Correlations", run_attack_surface_correlations,
            assessment_dir, "full", diff,
            pre.get("snapshot"), post.get("snapshot"),
            procmon_result.get("procmon_data"), runtime_targets, acl_cache,
        )
    else:
        reporter.set_status(
            "Attack Surface Correlations", "SKIPPED",
            "No verified full-mode system-state differential; no target-specific attack-surface correlation performed",
            coverage_gap=(mode == "full"),
        )

    application_profile_result = run_module(
        reporter,
        "Application / Technology Profile",
        run_application_profile,
        assessment_dir,
        mode,
        installer_result,
        technology_result,
        application_scope,
        static_inventory,
        pe_result,
        dotnet_result,
        electron_result,
        diff,
        runtime_targets,
        runtime_process_result.get("runtime_processes"),
        network_result,
        ipc_result,
        updater_candidates,
        local_storage_result,
    )

    test_capabilities = {
        "installed_state": bool(full_install_state_ready and diff),
        "filesystem_snapshot": bool(full_install_state_ready and not args.no_filesystem_snapshot and diff),
        "procmon": bool(procmon_result.get("procmon_data")),
        "surface_review": bool(
            reporter.status.get("Network Surface Review", {}).get("status") in {"PASS", "WARN"}
            and reporter.status.get("IPC / Named Pipe Review", {}).get("status") in {"PASS", "WARN"}
            and not network_result.get("coverage_gap", True)
            and not ipc_result.get("coverage_gap", True)
        ),
        "services_added": bool(diff.get("Services", {}).get("added")),
        "tasks_added": bool(diff.get("ScheduledTasks", {}).get("added")),
        "drivers_added": bool(diff.get("Drivers", {}).get("added")),
        "privilege_points": bool(privilege_result.get("records")),
        "local_storage": bool(local_storage_result.get("storage_records") or local_storage_result.get("registry_records")),
        "localhost_candidates": any(
            record.get("Scope") == "Loopback only" and record.get("HttpLikePort")
            for record in network_result.get("network_records", [])
        ),
    }
    state.checkpoint("runtime_optional", "COMPLETED", "Runtime stage completed or was intentionally skipped.")
    state.checkpoint("reporting", "STARTED", "Final reporting started.")

    run_module(
        reporter,
        "Test Case Generation",
        generate_test_cases,
        assessment_dir,
        mode,
        installer.suffix.lower(),
        test_capabilities,
    )

    coverage = reporter.finalize()
    state.checkpoint("reporting", "COMPLETED", "Final reports generated.")
    state.mark_complete(coverage)
    try:
        manifest = create_manifest(
            assessment_dir, framework_version=VERSION,
            methodology_version=METHODOLOGY_VERSION,
            catalog_version=ARTIFACT_CATALOG_VERSION,
        )
        verification = verify_assessment(assessment_dir)
        console.print(format_verification(verification))
        if verification["status"] == "FAIL":
            raise RuntimeError("Assessment integrity verification failed at finalization; inspect the affected artifact(s).")
    except (ValueError, OSError) as exc:
        raise RuntimeError(f"Assessment integrity finalization failed: {exc}") from exc
    ACTIVE_STATE = None
    if full_snapshot_failed:
        console.print(
            "\n[bold yellow]Assessment incomplete due to snapshot failure.[/bold yellow]"
        )
        console.print(
            "[yellow]Do not treat this run as a complete full-mode assessment. "
            "Correct the issue and rerun from the appropriate clean VM baseline.[/yellow]"
        )
    elif coverage == "COMPLETE":
        console.print("\n[bold green]Assessment complete.[/bold green]")
    elif coverage == "COMPLETE_WITH_OPTIONAL_GAPS":
        console.print("\n[bold yellow]Assessment complete with optional coverage gaps.[/bold yellow]")
    else:
        console.print("\n[bold red]Assessment incomplete; review module_status.txt and coverage_summary.txt.[/bold red]")
    console.print(f"Results: {assessment_dir}")
    console.print(f"Tester reports: {assessment_dir / 'reports'}")
    console.print(f"Internal working data: {assessment_dir / 'working'}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        persisted = False
        if ACTIVE_STATE is not None:
            try:
                ACTIVE_STATE.mark_interrupted("Assessment interrupted by the tester. Use Assessment Status / Recovery before continuing.")
                persisted = True
            except OSError:
                console.print("[red]Could not save interrupted assessment state. Preserve evidence and inspect file access before recovery.[/red]")
        if persisted:
            console.print("\n[yellow]Assessment interrupted. Saved lifecycle state was preserved.[/yellow]")
        else:
            console.print("\n[yellow]Assessment interrupted. State preservation could not be confirmed.[/yellow]")
        raise SystemExit(130)
    except Exception as exc:
        if ACTIVE_STATE is not None:
            try:
                ACTIVE_STATE.mark_interrupted(f"Assessment stopped unexpectedly: {type(exc).__name__}")
            except OSError:
                # Do not mask the original failure with another state-write
                # traceback or claim the interrupted status was saved.
                console.print("[red]Unable to persist interruption state; preserve this assessment directory and check Windows file access.[/red]")
        raise
