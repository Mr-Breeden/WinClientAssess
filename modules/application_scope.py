"""Identify target application roots without executing the supplied EXE.

A directory is *not* scanned merely because an EXE was selected: executables may
reside beside unrelated or sensitive files. Automatic adjacent-file scope requires
exact-stem .NET publishing sidecars; testers may opt in explicitly with
--application-dir or select a portable application directory.
"""
from __future__ import annotations
from utils.assessment_layout import artifact_path

import os
from pathlib import Path

from utils.report_format import header, kv
from utils.privacy import sanitize_report_text

INSTALLER_FAMILIES = {
    "Windows Installer (MSI)", "WiX Burn", "Inno Setup", "NSIS",
    "InstallShield", "Advanced Installer", "Squirrel",
}
MAX_FILES = 4000
MAX_BYTES = 3 * 1024 * 1024 * 1024


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _inventory_directory(folder: Path, assessment_dir: Path):
    """Bound, deterministic, non-following inventory; never follow external symlinks."""
    items, bytes_seen, truncated = [], 0, False
    root = folder.resolve()
    excluded = Path(assessment_dir).resolve()
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(
            d for d in dirs
            if not (current_path / d).is_symlink()
            and not _within(current_path / d, excluded)
        )
        for name in sorted(files):
            path = current_path / name
            if path.is_symlink() or not _within(path, root) or _within(path, excluded):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if len(items) >= MAX_FILES or bytes_seen + size > MAX_BYTES:
                truncated = True
                return items, truncated
            items.append(path)
            bytes_seen += size
    return items, truncated


def detect_application_scope(
    installer: Path, assessment_dir: Path, technologies=None, die_output="", explicit_dir=None,
    target_type: str = "installable",
):
    installer = Path(installer).resolve()
    assessment_dir = Path(assessment_dir).resolve()
    technologies = set(technologies or ())
    target_type = str(target_type or "installable").lower()
    known_installer = target_type == "installable" and (
        installer.suffix.lower() == ".msi" or bool(technologies & INSTALLER_FAMILIES)
    )
    sidecars = [
        installer.with_name(installer.stem + suffix)
        for suffix in (".runtimeconfig.json", ".deps.json", ".dll")
    ]
    present = [p for p in sidecars if p.is_file() and not p.is_symlink()]
    die_dotnet = "net core" in str(die_output).lower() or "dotnet" in str(die_output).lower()
    dotnet_host = (bool(present) or die_dotnet) and installer.suffix.lower() == ".exe" and not known_installer

    root = None
    if explicit_dir is not None:
        root = Path(explicit_dir).expanduser().resolve()
        if installer.suffix.lower() != ".exe":
            raise ValueError("--application-dir is for EXE application deployments only")
        if not root.is_dir():
            raise ValueError(f"Application directory not found: {root}")
        if _within(root, assessment_dir) or _within(assessment_dir, root):
            raise ValueError("Application directory cannot be the assessment output or contain it")
        kind = "portable_application_directory" if target_type == "portable" else "explicit_application_directory"
    elif target_type == "portable" and dotnet_host and present:
        root = installer.parent
        kind = "portable_dotnet_application"
    elif target_type == "portable":
        kind = "portable_executable"
    elif dotnet_host and present:
        root = installer.parent
        kind = "dotnet_published_application"
    elif dotnet_host:
        kind = "dotnet_apphost_unbundled"
    elif known_installer:
        kind = "installer"
    else:
        kind = "unclassified_executable"

    siblings, truncated = _inventory_directory(root, assessment_dir) if root else ([], False)
    roots = [installer]
    seen = {str(installer).casefold()}
    for path in siblings:
        key = str(path.resolve()).casefold()
        if key not in seen:
            seen.add(key)
            roots.append(path)

    if kind == "portable_application_directory":
        explanation = "Tester-selected portable application directory included read-only; no installer semantics are assumed."
    elif kind == "portable_dotnet_application":
        explanation = "Portable .NET executable with exact-stem publishing sidecars; adjacent deployment files included."
    elif kind == "portable_executable":
        explanation = "Portable executable selected; neighboring files are excluded unless the tester explicitly selects the application directory."
    elif kind == "dotnet_published_application":
        explanation = "Exact-stem .NET publishing sidecars identified; adjacent deployment files included."
    elif kind == "dotnet_apphost_unbundled":
        explanation = "Native .NET loader identified without sidecars; may be single-file or an incomplete deployment."
    elif kind == "explicit_application_directory":
        explanation = "Tester-selected deployed application directory included (read-only)."
    elif kind == "installer":
        explanation = "Recognized setup/archive package; extraction remains applicable."
    else:
        explanation = "No verified publishing sidecars; neighboring files intentionally excluded."

    return {
        "kind": kind, "roots": roots, "application_dir": root,
        "dotnet_host": dotnet_host, "sidecars": present,
        "known_installer": known_installer, "skip_extraction": dotnet_host or target_type == "portable",
        "target_type": target_type,
        "truncated": truncated, "explanation": explanation,
    }


def write_application_scope(assessment_dir: Path, installer: Path, scope):
    assessment_dir = Path(assessment_dir)
    lines = header("Windows Client Assessment - Application / Package Scope", [
        "Read-only discovery; adjacent files are included only when target scope is explicitly or strongly established.",
        "A published EXE is not automatically an installable setup package.",
    ], 104)
    lines += [
        "SUMMARY", "-" * 104,
        kv("Selected executable", Path(installer).name),
        kv("Classification", scope["kind"]),
        kv("Directory scoped", sanitize_report_text(scope.get("application_dir") or "Not inferred", installer)),
        kv("Exact-stem .NET sidecars", len(scope["sidecars"])),
        kv("Total static source files", len(scope["roots"])),
        kv("Inventory truncated", scope["truncated"]),
        "", scope["explanation"], "",
    ]
    if scope["sidecars"]:
        lines.extend(["PUBLISHING SIDECARS", "-" * 104])
        lines.extend(sanitize_report_text(str(path), installer) for path in scope["sidecars"])
        lines.append("")
    if scope["truncated"]:
        lines.append("AT CATALOG LIMIT: choose a more focused --application-dir; static coverage is partial.")
    if scope["kind"] in {"dotnet_apphost_unbundled", "portable_executable"}:
        lines.append("Use --application-dir for a deployed tree, or inspect the single-file bundle manually.")
    (artifact_path(assessment_dir, "application_scope.txt")).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def installation_footprint_status(diff, scope):
    """Describe an observed differential without inventing installation evidence."""
    observed = any(
        (diff or {}).get(category, {}).get("added")
        for category in ("Filesystem", "InstalledApplications", "Services",
                         "ScheduledTasks", "Drivers", "RegistryKeys", "RunEntries")
    )
    portable = scope.get("kind") in {
        "dotnet_published_application", "dotnet_apphost_unbundled",
        "explicit_application_directory", "portable_application_directory",
        "portable_dotnet_application", "portable_executable",
    } and not scope.get("known_installer")
    if not observed and portable:
        return "PASS", (
            "No installation footprint observed; consistent with a portable/deployed application. "
            "Correlate with runtime evidence."
        )
    if not observed:
        return "WARN", (
            "No installation footprint observed for a setup workflow. Verify that installation "
            "occurred and repeat from a clean baseline if needed."
        )
    return "PASS", (
        f"{len((diff or {}).get('Filesystem', {}).get('added', []))} filesystem additions; "
        f"{len((diff or {}).get('RegistryKeys', {}).get('added', []))} registry-key additions"
    )
