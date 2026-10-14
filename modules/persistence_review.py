from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
from utils.windows_paths import as_list, extract_executable, parent_path
from utils.report_format import header, section, kv
from utils.privacy import sanitize_snapshot_for_disk
from utils.target_association import association_roots, classify_installed_path
from utils.acl import broad_write_aces


def _new(pre, post, keys):
    old = {tuple(str(x.get(k, "")) for k in keys) for x in as_list(pre)}
    return [x for x in as_list(post) if tuple(str(x.get(k, "")) for k in keys) not in old]


def _association_for_command(command: str, diff, file_inventory):
    exe = extract_executable(command) or ""
    if not exe:
        return "", ""
    fs_items = [x for x in (diff or {}).get("Filesystem", {}).get("added", []) or [] if isinstance(x, dict)]
    exact = next((x for x in fs_items if str(x.get("Path") or "").lower() == exe.lower()), None)
    if exact:
        basis = classify_installed_path(exact, diff=diff, file_inventory=file_inventory,
                                        roots=association_roots(diff, file_inventory))
        if basis:
            return exe, basis
    roots = association_roots(diff, file_inventory)
    lower = exe.lower()
    if any(lower == root or lower.startswith(root.rstrip("\\") + "\\") for root in roots):
        return exe, "beneath target-associated install root"
    return exe, "UNATTRIBUTED"


def run_persistence_review(assessment_dir: Path, pre=None, post=None, diff=None, file_inventory=None, acl_cache=None):
    pre = pre or {}
    post = post or {}
    if diff is not None:
        run_entries = as_list((diff or {}).get("RunEntries", {}).get("added", []))
        protocols = as_list((diff or {}).get("ProtocolHandlers", {}).get("added", []))
        associations = as_list((diff or {}).get("FileAssociations", {}).get("added", []))
        environment = as_list((diff or {}).get("EnvironmentVariables", {}).get("added", []))
    else:
        run_entries = _new(pre.get("RunEntries", []), post.get("RunEntries", []), ["Key", "Name", "Value"])
        protocols = _new(pre.get("ProtocolHandlers", []), post.get("ProtocolHandlers", []), ["Root", "Scheme", "Command"])
        associations = _new(pre.get("FileAssociations", []), post.get("FileAssociations", []), ["Root", "Extension", "ProgId"])
        environment = _new(pre.get("EnvironmentVariables", []), post.get("EnvironmentVariables", []), ["Scope", "Name", "Value"])

    environment = sanitize_snapshot_for_disk(environment)
    command_rows = []
    acl_paths = []
    for kind, items, field in (("Run", run_entries, "Value"), ("Protocol", protocols, "Command")):
        for item in items:
            exe, basis = _association_for_command(str(item.get(field) or ""), diff or {}, file_inventory)
            parent = parent_path(exe) if exe else ""
            command_rows.append((kind, item, exe, parent, basis))
            acl_paths.extend(x for x in (exe, parent) if x)
    acl_map = acl_cache.get_many(acl_paths) if acl_cache and acl_paths else {}

    width = 112
    target_associated = sum(1 for _, _, _, _, basis in command_rows if basis and basis != "UNATTRIBUTED")
    lines = header(
        "Windows Client Assessment - Persistence Review",
        [
            "Summarizes startup and shell-integration changes introduced during the installation window.",
            "Command-bearing entries are explicitly attributed to target-associated or UNATTRIBUTED paths to reduce host-noise assumptions.",
        ], width
    )
    lines += [
        "SUMMARY", "-" * width,
        kv("Run/RunOnce", len(run_entries)),
        kv("Protocol handlers", len(protocols)),
        kv("File associations", len(associations)),
        kv("Environment changes", len(environment)),
        kv("Target-associated command entries", target_associated),
    ]

    row_lookup = {(kind, id(item)): (exe, parent, basis) for kind, item, exe, parent, basis in command_rows}
    lines += section("Run / RunOnce", width, len(run_entries))
    if not run_entries:
        lines.append("None.")
    for idx, item in enumerate(run_entries, 1):
        exe, parent, basis = row_lookup.get(("Run", id(item)), ("", "", ""))
        exe_hits = broad_write_aces(acl_map.get(exe.lower(), {})) if exe else []
        parent_hits = broad_write_aces(acl_map.get(parent.lower(), {})) if parent else []
        lines += [
            f"[RUN-{idx:03d}]",
            kv("Registry Key", item.get("Key"), 20, "  "),
            kv("Value Name", item.get("Name"), 20, "  "),
            kv("Command/Value", item.get("Value"), 20, "  "),
            kv("Executable", exe or "Unable to parse", 20, "  "),
            kv("Target association", basis or "Unknown", 20, "  "),
            kv("Executable broad-write", len(exe_hits), 20, "  "),
            kv("Parent broad-write", len(parent_hits), 20, "  "),
            "  Review: Confirm target ownership, quoting/arguments, and whether lower-privileged modification changes startup behavior.",
            "",
        ]

    lines += section("Protocol Handlers", width, len(protocols))
    if not protocols:
        lines.append("None.")
    for idx, item in enumerate(protocols, 1):
        exe, parent, basis = row_lookup.get(("Protocol", id(item)), ("", "", ""))
        exe_hits = broad_write_aces(acl_map.get(exe.lower(), {})) if exe else []
        parent_hits = broad_write_aces(acl_map.get(parent.lower(), {})) if parent else []
        lines += [
            f"[PROTO-{idx:03d}] {item.get('Scheme')}",
            kv("Root", item.get("Root"), 20, "  "),
            kv("Command Executed", item.get("Command"), 20, "  "),
            kv("Executable", exe or "Unable to parse", 20, "  "),
            kv("Target association", basis or "Unknown", 20, "  "),
            kv("Executable broad-write", len(exe_hits), 20, "  "),
            kv("Parent broad-write", len(parent_hits), 20, "  "),
            "  Review: Validate argument handling and whether untrusted URI content reaches a privileged/sensitive command path.",
            "",
        ]

    lines += section("File Associations", width, len(associations))
    if not associations:
        lines.append("None.")
    for idx, item in enumerate(associations, 1):
        lines += [
            f"[ASSOC-{idx:03d}]",
            kv("Root", item.get("Root"), 18, "  "),
            kv("Extension", item.get("Extension"), 18, "  "),
            kv("ProgId", item.get("ProgId"), 18, "  "),
            "",
        ]

    lines += section("Environment Variables", width, len(environment))
    if not environment:
        lines.append("None.")
    for idx, item in enumerate(environment, 1):
        lines += [
            f"[ENV-{idx:03d}]",
            kv("Scope", item.get("Scope"), 18, "  "),
            kv("Name", item.get("Name"), 18, "  "),
            kv("Value", item.get("Value"), 18, "  "),
            "",
        ]

    artifact_path(assessment_dir, "persistence_review.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {
        "status": "PASS",
        "details": (
            f"{len(run_entries)} run entries; {len(protocols)} protocols; {len(associations)} associations; "
            f"{len(environment)} environment changes; {target_associated} target-associated command entries"
        ),
        "persistence": {"run": run_entries, "protocols": protocols, "associations": associations, "environment": environment},
    }
