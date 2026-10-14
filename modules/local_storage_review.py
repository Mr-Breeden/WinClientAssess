from __future__ import annotations

"""Focused target-associated Windows local-storage review.

The collector is deliberately conservative: global pre/post snapshots contain a
large amount of unrelated host churn, so a storage object is promoted only when
it is associated with the assessed application by target process activity,
packaged/install-root evidence, or product/component identity tokens.

Secret *values* are never persisted. Text/config files are inspected only for
indicator names and the first matching line number per indicator type. SQLite
files are inspected read-only for table/column names only; row values are never
queried.
"""

import ntpath
import re
import sqlite3
from pathlib import Path
from typing import Iterable

from utils.acl import broad_read_aces
from utils.assessment_layout import artifact_path
from utils.component_context import normalize_path
from utils.privacy import sanitize_report_text
from utils.report_format import header, kv, section, bool_text
from utils.target_association import association_roots, classify_installed_path
from utils.target_identity import read_msi_properties, target_identity_tokens, path_has_target_identity

TEXT_EXTS = {
    ".json", ".xml", ".config", ".ini", ".yaml", ".yml", ".toml",
    ".conf", ".cfg", ".properties", ".txt", ".log", ".bak", ".tmp",
}
SQLITE_EXTS = {".db", ".sqlite", ".sqlite3"}
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_FILES = 250

OS_EXECUTION_HISTORY = ("\\services\\bam\\", "\\services\\dam\\", "\\appcompatcache\\", "\\userassist\\")
REGISTRY_SENSITIVE_FIELD = re.compile(r"(?i)(?:password|passwd|pwd|token|secret|credential|api[_-]?key|private[_-]?key|session[_-]?key)")


def _is_os_execution_history(path):
    normalized = str(path or "").replace("/", "\\").casefold()
    return any(part in normalized for part in OS_EXECUTION_HISTORY)


SENSITIVE_INDICATORS = {
    "Password-like key": re.compile(r"(?i)\b(?:password|passwd|pwd)\b"),
    "Token-like key": re.compile(r"(?i)\b(?:access[_-]?token|refresh[_-]?token|bearer[_-]?token|token)\b"),
    "Secret/API key-like key": re.compile(r"(?i)\b(?:client[_-]?secret|api[_-]?key|secret[_-]?key|secret)\b"),
    "Credential-like key": re.compile(r"(?i)\b(?:credential|credentials|username|user[_-]?name)\b"),
    "Private-key/certificate key": re.compile(r"(?i)\b(?:private[_-]?key|certificate|cert[_-]?password|pfx[_-]?password)\b"),
    "Connection-string key": re.compile(r"(?i)\b(?:connection[_-]?string|connectionstring|datasource|data[_-]?source)\b"),
}

def _norm(value) -> str:
    return normalize_path(str(value or "")).replace("/", "\\")


def _storage_area(path: str) -> str:
    p = _norm(path)
    if "\\appdata\\roaming\\" in p or p.endswith("\\appdata\\roaming"):
        return "%APPDATA%"
    if "\\appdata\\local\\" in p or p.endswith("\\appdata\\local"):
        return "%LOCALAPPDATA%"
    if "\\programdata\\" in p or p.endswith("\\programdata"):
        return "%ProgramData%"
    return ""


def _target_process_names(runtime_targets) -> set[str]:
    return {
        str(row.get("ProcessName") or ntpath.basename(str(row.get("Path") or ""))).lower()
        for row in runtime_targets or []
        if row.get("ProcessName") or row.get("Path")
    }


def _portable_roots_from_loaded_images(procmon_data, runtime_targets):
    """Derive application-root locations from target-owned loaded executable images.

    Do not promote a directory based on mere sibling names or host churn.
    The Procmon trace has already been target-scoped, and both owner process and
    exact executable basename must agree. Paths remain sanitized in reports.
    """
    names = _target_process_names(runtime_targets)
    roots = set()
    for event in (procmon_data or {}).get("loaded_images", []) or []:
        owner = str(event.get("Process") or "").lower()
        path = str(event.get("Path") or "")
        if owner not in names or ntpath.basename(path).lower() != owner:
            continue
        parent = _norm(ntpath.dirname(path))
        if parent and "\\windows\\" not in parent and len(parent) > 10:
            roots.add(parent)
    return roots


def _in_verified_portable_root(path, roots):
    normalized = _norm(path)
    return any(normalized.startswith(root + "\\") for root in roots)


def _portable_roots_from_verified_processes(runtime_targets, runtime_processes):
    """Use only the already SHA-256 verified selected portable executable.

    Runtime process paths exist in memory for correlation. Convert the source
    directory to the same privacy-safe representation as the sanitized Procmon
    CSV before matching; do not persist the original tester directory.
    """
    expected_names = {
        str(row.get("ProcessName") or "").lower()
        for row in runtime_targets or []
        if row.get("PortablePrimary") and row.get("PrimarySHA256")
    }
    roots = set()
    for proc in runtime_processes or []:
        name = str(proc.get("Name") or "").lower()
        exe = str(proc.get("Exe") or "")
        if name not in expected_names or proc.get("IdentitySource") != "Selected primary executable SHA-256":
            continue
        if ntpath.basename(exe).lower() != name or not ntpath.isabs(exe):
            continue
        directory = ntpath.dirname(exe)
        if "\\windows\\" in _norm(directory) or len(directory) < 10:
            continue
        roots.add(_norm(sanitize_report_text(directory)))
    return roots


def _runtime_storage_paths(procmon_data, runtime_targets, runtime_processes=None):
    target_names = _target_process_names(runtime_targets)
    verified_roots = _portable_roots_from_verified_processes(runtime_targets, runtime_processes)
    portable_roots = _portable_roots_from_loaded_images(procmon_data, runtime_targets) | verified_roots
    files = {}
    registry = {}
    for event in (procmon_data or {}).get("file_writes", []) or []:
        process = str(event.get("Process") or "").lower()
        path = str(event.get("Path") or "")
        in_portable_root = _in_verified_portable_root(path, portable_roots)
        if process in target_names and (_storage_area(path) or in_portable_root):
            files[_norm(path)] = {
                "Path": path,
                "Source": "Procmon target-process write",
                "Area": _storage_area(path) or (
                    "Application directory (verified primary process)"
                    if _in_verified_portable_root(path, verified_roots)
                    else "Application directory (loaded-image correlated)"
                ),
                "Process": event.get("Process") or "",
                "Operation": event.get("Operation") or "",
            }
    for event in (procmon_data or {}).get("registry_writes", []) or []:
        process = str(event.get("Process") or "").lower()
        path = str(event.get("Path") or "")
        if process in target_names:
            registry[_norm(path)] = {
                "Path": path,
                "Source": "Procmon target-process registry write",
                "Process": event.get("Process") or "",
                "Operation": event.get("Operation") or "",
            }
    return files, registry


def _first_text_indicators(path: Path) -> list[dict]:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return []
    found = []
    seen = set()
    for number, line in enumerate(text.splitlines(), 1):
        for label, pattern in SENSITIVE_INDICATORS.items():
            if label not in seen and pattern.search(line):
                seen.add(label)
                found.append({"Type": label, "Line": number, "Source": "Text/config key name"})
        if len(seen) == len(SENSITIVE_INDICATORS):
            break
    return found


def _sqlite_indicators(path: Path) -> list[dict]:
    found = []
    try:
        uri = path.resolve().as_uri() + "?mode=ro"
        con = sqlite3.connect(uri, uri=True, timeout=1)
        try:
            tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 200")]
            seen = set()
            for table in tables:
                safe_table = str(table).replace("'", "''")
                try:
                    columns = [str(row[1]) for row in con.execute(f"PRAGMA table_info('{safe_table}')")]
                except sqlite3.Error:
                    continue
                for column in columns:
                    for label, pattern in SENSITIVE_INDICATORS.items():
                        if label in seen:
                            continue
                        if pattern.search(column):
                            seen.add(label)
                            found.append({
                                "Type": label,
                                "Line": "N/A",
                                "Source": f"SQLite schema: {table}.{column}",
                            })
        finally:
            con.close()
    except (OSError, sqlite3.Error, ValueError):
        pass
    return found


def _inspect_file(path_text: str) -> list[dict]:
    path = Path(path_text)
    suffix = path.suffix.lower()
    if not path.is_file():
        return []
    if suffix in TEXT_EXTS:
        return _first_text_indicators(path)
    if suffix in SQLITE_EXTS:
        return _sqlite_indicators(path)
    return []


def _added_or_changed_files(diff) -> Iterable[dict]:
    fs = (diff or {}).get("Filesystem", {})
    for item in fs.get("added", []) or []:
        if isinstance(item, dict) and not item.get("IsDirectory"):
            yield item
    for change in fs.get("changed", []) or []:
        after = change.get("after", {}) if isinstance(change, dict) else {}
        if isinstance(after, dict) and not after.get("IsDirectory"):
            yield after


def run_local_storage_review(
    assessment_dir: Path,
    diff=None,
    procmon_data=None,
    runtime_targets=None,
    file_inventory=None,
    installer_info=None,
    acl_cache=None,
    filesystem_evidence=True,
    runtime_processes=None,
):
    diff = diff or {}
    procmon_data = procmon_data or {}
    runtime_targets = runtime_targets or []
    width = 116

    if not filesystem_evidence and not procmon_data:
        lines = header(
            "Windows Client Assessment - Local Storage Review",
            ["Target-associated AppData/ProgramData and registry storage review."], width,
        )
        lines += [
            "COLLECTION STATE", "-" * width,
            kv("Filesystem storage", "COLLECTION UNAVAILABLE"),
            kv("Runtime storage writes", "COLLECTION UNAVAILABLE"),
            "",
            "No filesystem snapshot or target-scoped Procmon evidence was available. Local storage was not tested.",
        ]
        artifact_path(assessment_dir, "local_storage_review.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return {
            "status": "SKIPPED",
            "details": "Local-storage collection unavailable (no filesystem snapshot or target Procmon evidence)",
            "coverage_gap": True,
            "storage_records": [],
            "storage_pois": [],
            "storage_roots": [],
        }

    roots = association_roots(diff, file_inventory)
    msi_properties = read_msi_properties(assessment_dir)
    tokens, target_apps = target_identity_tokens(
        diff=diff, runtime_targets=runtime_targets, roots=roots,
        installer_info=installer_info, msi_properties=msi_properties,
    )
    runtime_files, runtime_registry = _runtime_storage_paths(procmon_data, runtime_targets, runtime_processes)

    records = {}
    for item in _added_or_changed_files(diff):
        path = str(item.get("Path") or "")
        area = _storage_area(path)
        if not area:
            continue
        basis = classify_installed_path(item, diff=diff, file_inventory=file_inventory, roots=roots)
        if not basis and not path_has_target_identity(path, tokens) and _norm(path) not in runtime_files:
            continue
        records[_norm(path)] = {
            "Path": path,
            "Area": area,
            "Source": "Filesystem differential",
            "Association": basis or ("target identity in storage path" if path_has_target_identity(path, tokens) else "target process runtime write"),
            "Process": runtime_files.get(_norm(path), {}).get("Process", ""),
        }
    for key, row in runtime_files.items():
        records.setdefault(key, {
            "Path": row["Path"], "Area": row.get("Area") or _storage_area(row["Path"]),
            "Source": row["Source"], "Association": "target process runtime write",
            "Process": row.get("Process", ""),
        })

    selected = list(records.values())[:MAX_FILES]
    acl_paths = [row["Path"] for row in selected]
    acl_map = acl_cache.get_many(acl_paths) if acl_cache and acl_paths else {}
    for row in selected:
        acl = acl_map.get(str(row["Path"]).lower(), {})
        row["BroadReadACEs"] = broad_read_aces(acl)
        row["Indicators"] = _inspect_file(row["Path"])
        row["ExistsAtReview"] = bool(acl.get("Exists")) if acl else Path(row["Path"]).is_file()

    # Registry state: only key names/paths are retained; values are not collected
    # by the snapshot and runtime details are not copied into this report.
    registry_records = {}
    for item in (diff.get("RegistryKeys", {}).get("added", []) or []):
        if not isinstance(item, dict):
            continue
        path = str(item.get("Path") or "")
        if path and not _is_os_execution_history(path) and path_has_target_identity(path, tokens):
            registry_records[_norm(path)] = {"Path": path, "Source": "Registry differential", "Process": ""}
    for key, row in runtime_registry.items():
        path = row["Path"]
        # A target process can legitimately touch large amounts of generic Windows
        # state. Promote registry storage only when the key itself carries a
        # correlated target/product identity; target-process ownership alone is
        # not sufficient evidence that the key is application storage.
        if not _is_os_execution_history(path) and path_has_target_identity(path, tokens):
            registry_records.setdefault(key, {"Path": path, "Source": row["Source"], "Process": row.get("Process", "")})

    pois = []
    for row in selected:
        if row.get("Indicators") and row.get("BroadReadACEs"):
            poi = dict(row)
            poi["POI"] = f"POI-LS-{len(pois) + 1:03d}"
            pois.append(poi)

    # A sensitive registry *name* warrants a manual storage review even when
    # ACL collection cannot prove broad access. Values are never collected.
    for record in registry_records.values():
        name = ntpath.basename(record["Path"].rstrip("\\"))
        if REGISTRY_SENSITIVE_FIELD.search(name):
            poi = dict(record)
            poi.update({"POI": f"POI-LS-{len(pois) + 1:03d}", "Area": "Registry",
                        "Association": "target-identifying registry path",
                        "Indicators": [{"Type": "Sensitive registry value/key name", "Line": "N/A", "Source": "Registry path only"}],
                        "BroadReadACEs": []})
            pois.append(poi)

    storage_roots = sorted({ntpath.dirname(str(row["Path"])) for row in selected if row.get("Path")}, key=str.lower)
    state = "OBSERVED" if selected or registry_records else "COLLECTED / NO OBSERVATION"
    fs_state = "OBSERVED" if selected else ("COLLECTED / NO OBSERVATION" if filesystem_evidence else "COLLECTION UNAVAILABLE")
    runtime_state = "OBSERVED" if runtime_files or runtime_registry else ("COLLECTED / NO OBSERVATION" if procmon_data else "NOT COLLECTED (optional)")

    lines = header(
        "Windows Client Assessment - Local Storage Review",
        [
            "Reviews target-associated AppData, ProgramData, portable application directories and registry storage without retaining secret values.",
            "Text/config evidence records only indicator type and first matching line number; SQLite review uses schema names only.",
            "A sensitive-looking key is not a vulnerability. Report only after validating real data, access and security impact.",
        ], width,
    )
    lines += [
        "SUMMARY", "-" * width,
        kv("Overall evidence state", state),
        kv("Filesystem storage state", fs_state),
        kv("Runtime storage state", runtime_state),
        kv("Target-associated files", len(selected)),
        kv("Target-associated registry paths", len(registry_records)),
        kv("Potential-secret indicator files", sum(bool(r.get("Indicators")) for r in selected)),
        kv("Broad-readable indicator files", sum(bool(r.get("Indicators")) and bool(r.get("BroadReadACEs")) for r in selected)),
        kv("Sensitive registry name review points", sum(p.get("Area") == "Registry" for p in pois)),
        kv("Storage roots", len(storage_roots)),
        kv("Correlated target installed-app records", len(target_apps)),
    ]

    lines += section("Target-Associated Storage Files", width, len(selected))
    if not selected:
        lines.append("No target-associated AppData/ProgramData files were observed in the available evidence.")
    for idx, row in enumerate(selected, 1):
        lines += [
            f"[STORE-{idx:03d}] {sanitize_report_text(row['Path'])}",
            kv("Area", row.get("Area"), 24, "  "),
            kv("Source", row.get("Source"), 24, "  "),
            kv("Association", row.get("Association"), 24, "  "),
            kv("Process", row.get("Process") or "N/A", 24, "  "),
            kv("Broad read ACE count", len(row.get("BroadReadACEs") or []), 24, "  "),
            kv("Sensitive indicators", len(row.get("Indicators") or []), 24, "  "),
        ]
        for indicator in row.get("Indicators") or []:
            lines.append(
                f"    Indicator: {indicator['Type']} | First match line: {indicator['Line']} | {indicator['Source']}"
            )
        lines.append("")

    lines += section("Registry Storage", width, len(registry_records))
    if not registry_records:
        lines.append("No target-associated registry storage paths were observed in the available evidence.")
    for idx, row in enumerate(sorted(registry_records.values(), key=lambda x: str(x.get("Path") or "").lower()), 1):
        lines += [
            f"[REGSTORE-{idx:03d}] {sanitize_report_text(row['Path'])}",
            kv("Source", row.get("Source"), 18, "  "),
            kv("Process", row.get("Process") or "N/A", 18, "  "),
            "",
        ]

    lines += section("Points of Interest", width, len(pois))
    if not pois:
        lines += [
            "No sensitive storage name plus file-read exposure correlated to this target in available evidence.",
            "This does not prove that sensitive information is absent; review observed storage in application context.",
        ]
    for poi in pois:
        indicator_summary = ", ".join(f"{x['Type']}@{x['Line']}" for x in poi.get("Indicators") or [])
        lines += [
            "", "=" * width,
            f"[{poi['POI']}] {sanitize_report_text(poi['Path'])}",
            "=" * width,
            kv("Area", poi.get("Area")),
            kv("Association", poi.get("Association")),
            kv("Potential-secret indicators", indicator_summary or "None"),
            kv("Broad read ACE count", len(poi.get("BroadReadACEs") or [])),
            "Manual Validation:",
            "  Inspect the indicated key/schema locations locally without copying values into WCA. Confirm whether real",
            "  credentials/tokens/sensitive records are present, which principals can read them, and whether the data",
            "  crosses the intended application/user trust boundary before reporting.",
        ]

    artifact_path(assessment_dir, "local_storage_review.txt").write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8"
    )

    findings = []
    if pois:
        findings.append({
            "title": "Potential Sensitive Local Storage Requires Validation",
            "severity": "Informational",
            "description": (
                "WCA correlated target-associated storage with sensitive-looking file/schema/registry names and, where available, broad read access. "
                "No secret values were retained and the condition requires manual validation."
            ),
            "evidence": f"{len(pois)} POI-LS review point(s) from target-associated storage files and registry names.",
            "recommendation": (
                "Inspect only the indicated locations, confirm whether real sensitive data is present, validate effective read access, "
                "and report only when unauthorized disclosure or another meaningful trust-boundary impact is demonstrated."
            ),
        })

    return {
        "status": "WARN" if pois else "PASS",
        "details": f"{len(selected)} target-associated storage file(s); {len(registry_records)} registry path(s); {len(pois)} POI-LS review point(s)",
        "coverage_gap": bool(not filesystem_evidence and not procmon_data),
        "findings": findings,
        "storage_records": selected,
        "registry_records": list(registry_records.values()),
        "storage_pois": pois,
        "storage_roots": storage_roots,
        "target_installed_apps": target_apps,
        "evidence_state": state,
    }
