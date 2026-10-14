from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
import re

from utils.report_format import header, section, kv
from utils.component_context import basename, launch_contexts_for_candidate
from utils.path_filters import path_is_excluded
from utils.target_association import association_roots, classify_installed_path

# Broad filename triage: updater terms may be embedded in CamelCase names such as
# UpdateService.exe or ClientAutoUpdater.exe. These are candidates, not findings.
UPDATE_RE = re.compile(r"update|updater|upgrade|patch|maintenance|bootstrap|launcher|autoupdate", re.I)
EXEC_EXTS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".msi", ".com"}


def _is_name_candidate(path, ext):
    name = basename(path)
    if not UPDATE_RE.search(name):
        return False
    # Front-end libraries such as bootstrap.min.js are not launchers merely
    # because their filename contains a generic UI-framework term.
    if ext == ".js" and re.search(r"(^|[._-])bootstrap([._-]|$)", name, re.I):
        return False
    return True


def _candidate_role(path):
    name = basename(path).lower()
    if "launcher" in name or "bootstrap" in name:
        return "Launcher/Bootstrap"
    if "patch" in name:
        return "Patch Component"
    if "maintenance" in name:
        return "Maintenance Component"
    if "upgrade" in name:
        return "Upgrade Component"
    return "Updater/Update Component"


def discover_updater_candidates(
    file_inventory=None, diff=None, seed_candidates=None, exclude_paths=None, target_inventory=None
):
    """Discover and merge updater candidates without writing a report."""
    hits = [
        dict(item)
        for item in (seed_candidates or [])
        if not path_is_excluded(item.get("Path"), exclude_paths)
    ]
    seen = {str(item.get("Path") or "").lower() for item in hits if item.get("Path")}

    for row in file_inventory or []:
        path = str(row.get("path") or "")
        if path_is_excluded(path, exclude_paths):
            continue
        ext = str(row.get("extension") or Path(path).suffix).lower()
        if ext not in EXEC_EXTS or not _is_name_candidate(path, ext):
            continue
        key = path.lower()
        if key not in seen:
            seen.add(key)
            hits.append({"Path": path, "Source": "static/extracted"})

    roots = association_roots(diff or {}, target_inventory) if target_inventory is not None else set()
    for item in (diff or {}).get("Filesystem", {}).get("added", []) or []:
        path = str(item.get("Path") or "")
        if path_is_excluded(path, exclude_paths):
            continue
        ext = Path(path).suffix.lower()
        association = classify_installed_path(
            item, diff=diff or {}, file_inventory=target_inventory, roots=roots
        ) if target_inventory is not None else "legacy filesystem differential"
        if (
            path
            and association
            and not item.get("IsDirectory")
            and ext in EXEC_EXTS
            and _is_name_candidate(path, ext)
            and path.lower() not in seen
        ):
            seen.add(path.lower())
            hits.append({
                "Path": path,
                "Source": "installed differential",
                "Association": association,
            })

    for hit in hits:
        hit["Role"] = _candidate_role(hit.get("Path"))
        hit["ProcessName"] = basename(hit.get("Path"))
        hit["LaunchContexts"] = launch_contexts_for_candidate(hit, diff or {}, include_startup=True)

    return hits


def write_updater_review(assessment_dir: Path, hits):
    width = 104
    lines = header(
        "Windows Client Assessment - Updater / Maintenance Candidate Review",
        [
            "Identifies updater, launcher, bootstrap, patch, and maintenance components by filename/path.",
            "In full mode this consolidated report includes both static/extracted and installed-differential candidates.",
        ],
        width,
    )
    lines += ["SUMMARY", "-" * width, kv("Candidates", len(hits))]
    static_count = sum(1 for h in hits if h.get("Source") == "static/extracted")
    installed_count = sum(1 for h in hits if h.get("Source") == "installed differential")
    correlated = sum(1 for h in hits if h.get("LaunchContexts"))
    lines += [
        kv("Static/extracted", static_count),
        kv("Installed differential", installed_count),
        kv("Launch-context correlated", correlated),
    ]
    lines += section("Recommended Review Workflow", width)
    lines += [
        "1. Use this file as the updater candidate index.",
        "2. In full mode, use updater_security_review.txt for signature, ACL, staging, privilege, and runtime correlation.",
        "3. Exercise the application's update/check-for-updates workflow during Procmon capture when authorized.",
        "4. Validate actual package integrity/signature enforcement and lower-privileged influence before reporting an issue.",
    ]

    for idx, hit in enumerate(hits, 1):
        path = hit.get("Path") or ""
        lines += [
            "", "=" * width, f"[UPD-{idx:03d}] {basename(path)}", "=" * width,
            kv("Role", hit.get("Role")), kv("Source", hit.get("Source")), kv("Path", path),
            kv("Target Association", hit.get("Association") or ("Static/extracted payload" if hit.get("Source") == "static/extracted" else "N/A")),
            kv("Extension", Path(path).suffix.lower()), kv("Launch Contexts", len(hit.get("LaunchContexts", []))),
        ]
        for cidx, context in enumerate(hit.get("LaunchContexts", []), 1):
            lines += [
                f"  [LAUNCH-{cidx:02d}] {context.get('Type')}: {context.get('Component')}",
                kv("Account", context.get("Account"), 18, "    "),
                kv("Run Level", context.get("RunLevel") or "N/A", 18, "    "),
                kv("Command", context.get("Command"), 18, "    "),
            ]
        lines += [
            "Tester Focus:",
            "  Execution privilege | package integrity | download endpoint | writable staging/config | rollback/downgrade behavior",
        ]

    (artifact_path(assessment_dir, "updater_review.txt")).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def run_updater_review(
    assessment_dir: Path,
    file_inventory=None,
    diff=None,
    seed_candidates=None,
    exclude_paths=None,
    target_inventory=None,
):
    hits = discover_updater_candidates(
        file_inventory, diff, seed_candidates, exclude_paths, target_inventory
    )
    write_updater_review(assessment_dir, hits)
    return {
        "status": "WARN" if hits else "PASS",
        "details": f"{len(hits)} updater/launcher candidate(s)",
        "updater_candidates": hits,
    }
