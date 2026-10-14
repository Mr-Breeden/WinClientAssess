"""Assessment artifact integrity and conservative derived-report restoration.

SHA-256 manifests detect accidental or unapproved changes, not an adversary who
can rewrite both the evidence and unsigned manifest. Never repair raw evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from utils.artifacts import ARTIFACTS, GENERATED_DIRECTORIES
from utils.assessment_layout import artifact_path, generated_directory_path
from utils.assessment_state import AssessmentState, sha256_file, _atomic_json

MANIFEST_SCHEMA = 1
MANIFEST_NAME = "working/assessment_manifest.json"
INDEX_NAME = "reports/artifact_manifest.txt"
DERIVED_REPORTS = frozenset({
    "reports/module_status.txt", "reports/coverage_summary.txt",
    "reports/findings.txt", "reports/findings_summary.txt",
    "reports/assessment_report.html", "reports/artifact_manifest.txt",
    "reports/tester_review.txt", "reports/evidence_guide.txt",
    "reports/attack_surface_test_plan.txt",
})
IGNORED = frozenset({MANIFEST_NAME})
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("Invalid manifest artifact path")
    item = PurePosixPath(relative)
    if item.is_absolute() or any(p in ("", ".", "..") for p in item.parts):
        raise ValueError("Manifest path escapes the assessment directory")
    if item.parts[0] not in ("reports", "working"):
        raise ValueError("Manifest path is outside recognized assessment areas")
    target = root.joinpath(*item.parts)
    if target.is_symlink() or any(part.is_symlink() for part in list(target.parents) if part != root and root in part.parents):
        raise ValueError("Symlink-backed assessment artifacts are not trusted")
    return target


def _walk_files(root: Path):
    for folder in (root / "reports", root / "working"):
        if not folder.is_dir() or folder.is_symlink():
            continue
        for path in folder.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"Symlink found within assessment: {path.relative_to(root)}")
            if path.is_file():
                relative = path.relative_to(root).as_posix()
                if relative not in IGNORED and relative != INDEX_NAME:
                    yield relative, path


def _record(path: Path) -> dict[str, Any]:
    return {"size": path.stat().st_size, "sha256": sha256_file(path)}


def _known_paths(root: Path) -> dict[str, str]:
    known = {}
    for spec in ARTIFACTS.values():
        if spec.get("cleanup_only"):
            continue
        path = artifact_path(root, spec["filename"])
        try:
            known[path.relative_to(root).as_posix()] = spec["phase"]
        except ValueError:
            continue
    return known


def _tree_digest(items: dict[str, dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for name, record in sorted(items.items()):
        digest.update(f"{name}\0{record['size']}\0{record['sha256']}\n".encode("utf-8"))
    return digest.hexdigest()


def _inventory(root: Path) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {"reports": {}, "supporting": {}, "payloads": {}}
    payload_roots = [generated_directory_path(root, name).relative_to(root).as_posix() + "/" for name in GENERATED_DIRECTORIES]
    for relative, path in _walk_files(root):
        group = ("payloads" if any(relative.startswith(prefix) for prefix in payload_roots)
                 else "reports" if relative.startswith("reports/") else "supporting")
        grouped[group][relative] = _record(path)
    return grouped


def _atomic_text(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(contents)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _human_index(manifest: dict[str, Any]) -> str:
    lines = ["WCA - ARTIFACT MANIFEST", "=" * 88,
             "SHA-256 inventory of generated artifacts; machine-readable authoritative index:",
             "  working/assessment_manifest.json", "",
             "This manifest detects changed or missing artifacts, not malicious alteration of both files.", ""]
    for group, heading in (("reports", "TESTER REPORTS"), ("supporting", "AUTHORITATIVE STATE / EVIDENCE"), ("payloads", "RETAINED EXTRACTION / DECOMPILATION")):
        entries = manifest["files"][group]
        lines += [heading, "-" * 88, f"Recorded files: {len(entries)}"]
        for filename, record in sorted(entries.items()):
            lines.append(f"{record['sha256']}  {record['size']:>12}  {filename}")
        lines.append("")
    for dirname, record in sorted(manifest["extraction_trees"].items()):
        lines.append(f"Tree SHA-256: {record['sha256']}  files={record['files']}  {dirname}")
    return "\n".join(lines).rstrip() + "\n"


def create_manifest(root: Path, *, framework_version: str, methodology_version="1.0", catalog_version="1.0") -> dict[str, Any]:
    """Record exactly the files retained by a finalized structured assessment."""
    root = Path(root)
    state = AssessmentState.load(root)
    if state is None:
        raise ValueError("Assessment state is missing: cannot finalize an integrity manifest")
    grouped = _inventory(root)
    trees = {}
    for dirname in sorted(GENERATED_DIRECTORIES):
        directory = generated_directory_path(root, dirname)
        if directory.is_dir():
            prefix = directory.relative_to(root).as_posix() + "/"
            entries = {p: r for p, r in grouped["payloads"].items() if p.startswith(prefix)}
            trees[directory.relative_to(root).as_posix()] = {"sha256": _tree_digest(entries), "files": len(entries)}
    manifest = {
        "schema_version": MANIFEST_SCHEMA, "framework": "WinClientAssess",
        "framework_version": framework_version, "methodology_version": methodology_version,
        "artifact_catalog_version": catalog_version,
        "mode": state.data.get("mode"),
        "state_schema_version": state.data.get("schema_version"),
        "artifact_schema_version": state.data.get("artifact_schema_version"),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": grouped, "extraction_trees": trees,
    }
    # Write the human index before hashing it. The machine manifest intentionally
    # excludes itself to avoid a self-referential digest.
    index = root / INDEX_NAME
    _atomic_text(index, _human_index(manifest))
    grouped["reports"][INDEX_NAME] = _record(index)
    _atomic_json(root / MANIFEST_NAME, manifest)
    return manifest


def _check(label: str, issues: list[str], detail: str = "", attention: bool = False, warning: bool = False):
    return {"name": label, "status": "FAIL" if issues else "ATTN" if attention else "WARN" if warning else "PASS",
            "details": detail, "issues": issues}


def _orphan_temp(relative: str) -> bool:
    # Vendor-controlled extraction/decompilation content can legitimately
    # contain .tmp payloads; only the framework's own write areas are checked.
    if relative.startswith(("working/extracted_installer/", "working/decompiled_dotnet/")):
        return False
    name = PurePosixPath(relative).name.lower()
    return name.endswith((".tmp", ".tmp.csv", ".partial", ".part")) or name.startswith(".wca-tmp-")


def verify_assessment(root: Path, expected_framework_version: str | None = None) -> dict[str, Any]:
    root = Path(root)
    path = root / MANIFEST_NAME
    if not path.is_file() or path.is_symlink():
        return {"status": "FAIL", "checks": [_check("Assessment manifest", ["Missing or invalid working/assessment_manifest.json"])],
                "damaged": {}, "unexpected": [], "repairable": False}
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("schema_version") != MANIFEST_SCHEMA or manifest.get("framework") != "WinClientAssess":
            raise ValueError("Unsupported assessment manifest schema/framework")
        if (not isinstance(manifest.get("framework_version"), str)
                or not isinstance(manifest.get("methodology_version"), str)
                or not isinstance(manifest.get("artifact_catalog_version"), str)
                or manifest.get("mode") not in {"static", "full"}
                or not isinstance(manifest.get("extraction_trees"), dict)):
            raise ValueError("Missing or invalid manifest version/mode/tree metadata")
        files = manifest["files"]
        if not isinstance(files, dict) or any(not isinstance(files.get(group), dict) for group in ("reports", "supporting", "payloads")):
            raise ValueError("Malformed grouped artifact inventory")
        all_recorded = {}
        for group, records in files.items():
            if group not in ("reports", "supporting", "payloads"):
                raise ValueError("Unknown artifact group")
            for relative, item in records.items():
                _safe_path(root, relative)
                if (relative in all_recorded or relative == MANIFEST_NAME
                        or (group == "reports" and not relative.startswith("reports/"))
                        or (group != "reports" and not relative.startswith("working/"))
                        or (group == "payloads" and not relative.startswith(("working/extracted_installer/", "working/decompiled_dotnet/")))):
                    raise ValueError("Duplicate, self-referential, or miscategorized manifest entry")
                if not isinstance(item, dict) or not isinstance(item.get("size"), int) or item["size"] < 0 or not _SHA.fullmatch(str(item.get("sha256"))):
                    raise ValueError("Invalid artifact size/digest")
                all_recorded[relative] = group
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return {"status": "FAIL", "checks": [_check("Assessment manifest", [str(exc)])],
                "damaged": {}, "unexpected": [], "repairable": False}
    checks = [_check("Assessment manifest", [], f"Schema {manifest['schema_version']}; framework {manifest['framework_version']}",
                     warning=bool(expected_framework_version and expected_framework_version != manifest.get("framework_version")))]
    damaged: dict[str, list[str]] = {}
    for group, label in (("reports", "Report artifact integrity"), ("supporting", "Supporting state integrity"), ("payloads", "Extracted payload integrity")):
        issues = []
        for relative, expected in files[group].items():
            try:
                target = _safe_path(root, relative)
                if not target.is_file():
                    issues.append(f"Missing: {relative}")
                elif target.stat().st_size != expected["size"] or sha256_file(target) != expected["sha256"]:
                    issues.append(f"Modified: {relative}")
            except (OSError, ValueError) as exc:
                issues.append(f"Untrusted: {relative}: {exc}")
        damaged[group] = issues
        checks.append(_check(label, issues, f"{len(files[group])} recorded file(s)"))
    # Independently recalculate extraction tree digests. File-level verification
    # also detects a removed/mutated payload within the recorded tree.
    tree_issues = []
    trees = manifest.get("extraction_trees") or {}
    if not isinstance(trees, dict):
        tree_issues.append("Invalid extraction-tree inventory")
    else:
        for dirname, expected in trees.items():
            try:
                directory = _safe_path(root, dirname)
                if not directory.is_dir():
                    tree_issues.append(f"Missing retained directory: {dirname}")
                    continue
                prefix = dirname + "/"
                records = {name: item for name, item in files["payloads"].items() if name.startswith(prefix)}
                if expected.get("files") != len(records) or expected.get("sha256") != _tree_digest(records):
                    tree_issues.append(f"Invalid recorded extraction tree: {dirname}")
            except (ValueError, AttributeError) as exc:
                tree_issues.append(str(exc))
    if tree_issues:
        damaged["payloads"].extend(tree_issues)
        checks[3] = _check("Extracted payload integrity", damaged["payloads"], f"{len(files['payloads'])} recorded file(s)")
    try:
        actual = dict(_walk_files(root))
    except ValueError as exc:
        actual = {}
        inventory_issues = [str(exc)]
    else:
        inventory_issues = []
    # The human index is tracked and hashed as a derived tester report.
    if (root / INDEX_NAME).is_file():
        actual[INDEX_NAME] = root / INDEX_NAME
    known = _known_paths(root)
    unexpected = sorted(set(actual) - set(all_recorded))
    unknown_untracked = []
    for relative in unexpected:
        if relative in known or relative.startswith("working/extracted_installer/") or relative.startswith("working/decompiled_dotnet/"):
            inventory_issues.append(f"Unrecorded generated artifact: {relative}")
        elif not _orphan_temp(relative):
            unknown_untracked.append(relative)
    for relative in actual:
        if manifest.get("mode") == "static" and relative in known and known[relative] in ("installed_state", "runtime", "surface", "updater_security"):
            inventory_issues.append(f"Mode-inapplicable artifact in static assessment: {relative}")
    state = AssessmentState.load(root)
    if state is None or state.data.get("mode") != manifest.get("mode") or state.data.get("framework_version") != manifest.get("framework_version"):
        inventory_issues.append("Assessment identity/state inconsistent with manifest")
    checks.append(_check("Artifact inventory consistency", inventory_issues,
                         f"Mode: {manifest.get('mode')}", attention=bool(unknown_untracked)))
    temporary = sorted({relative for relative in actual if _orphan_temp(relative)})
    # orphan temp files must be detected even when an earlier _walk_files failed
    for folder in (root / "reports", root / "working"):
        if folder.is_dir():
            for path in folder.iterdir():
                if path.is_file() and _orphan_temp(path.name):
                    temporary.append(path.relative_to(root).as_posix())
    temporary = sorted(set(temporary))
    checks.append(_check("Atomic-write cleanup", [f"Orphaned temporary file: {p}" for p in temporary]))
    status = ("FAIL" if any(item["status"] == "FAIL" for item in checks)
              else "ATTN" if any(item["status"] == "ATTN" for item in checks)
              else "WARN" if any(item["status"] == "WARN" for item in checks)
              else "PASS")
    # Only derived report damage is repairable. Unknown untracked files merit
    # attention but cannot be silently added to the inventory by repair.
    report_damaged_paths = [item.partition(": ")[2] for item in damaged["reports"]]
    repairable = (
        bool(report_damaged_paths)
        and all(name in DERIVED_REPORTS for name in report_damaged_paths)
        and not damaged["supporting"] and not damaged["payloads"]
        and not inventory_issues and not temporary and not unknown_untracked
    )
    return {"status": status, "checks": checks, "damaged": damaged,
            "unexpected": unexpected, "untracked_notes": unknown_untracked,
            "repairable": repairable, "manifest": manifest}


def regenerate_derived_reports(root: Path) -> dict[str, Any]:
    """Fail closed: restore generated summaries only if every source artifact verifies."""
    root = Path(root)
    verification = verify_assessment(root)
    if not verification.get("repairable"):
        raise ValueError("Only altered/missing derived reports can be regenerated; supporting evidence and primary reports must verify unchanged")
    state = AssessmentState.load(root)
    render_path = root / "working" / "report_render_state.json"
    render = json.loads(render_path.read_text(encoding="utf-8"))
    if (render.get("modules") != state.data.get("modules")
            or render.get("mode") != state.data.get("mode")
            or render.get("installer_filename") != state.data.get("installer", {}).get("filename")):
        raise ValueError("Report rendering state is inconsistent with authoritative assessment state")
    if not isinstance(render.get("findings"), list):
        raise ValueError("Report rendering state does not contain original generated findings")
    from utils.reporting import AssessmentReporter
    reporter = AssessmentReporter(root, state.data["assessment_name"],
                                  Path(render.get("target_filename") or render["installer_filename"]), render["mode"],
                                  state.data["framework_version"], target_type=(state.data.get("target") or {}).get("type", "installable"))
    reporter.status = render["modules"]
    reporter.findings = render["findings"]
    reporter.finalize(persist_render_state=False, sanitize_primary=False)
    create_manifest(root, framework_version=state.data["framework_version"],
                    methodology_version=verification["manifest"].get("methodology_version", "1.0"),
                    catalog_version=verification["manifest"].get("artifact_catalog_version", "1.0"))
    return verify_assessment(root)


def format_verification(result: dict[str, Any]) -> str:
    lines = ["Assessment Integrity Verification", "=" * 48]
    for check in result["checks"]:
        lines.append(f"{check['status']:5} {check['name']} - {check.get('details', '')}")
        lines.extend("      " + item for item in check["issues"][:25])
    for note in result.get("untracked_notes", []):
        lines.append("ATTN  Untracked user/unknown file: " + note)
    lines += ["", "Overall status: " + result["status"]]
    if result.get("repairable"):
        lines.append("Only derived reports were changed: --regenerate-reports can restore them.")
    return "\n".join(lines)
