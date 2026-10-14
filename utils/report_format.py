from __future__ import annotations

from collections import defaultdict
import ntpath
import re

DEFAULT_WIDTH = 104


def header(title: str, purpose_lines=None, width: int = DEFAULT_WIDTH):
    lines = [title.upper(), "=" * width, ""]
    if purpose_lines:
        lines += ["Purpose:"]
        for line in purpose_lines:
            lines.append(f"  {line}")
        lines.append("")
    return lines


def section(title: str, width: int = DEFAULT_WIDTH, count=None):
    label = f"{title} ({count})" if count is not None else title
    return ["", label.upper(), "-" * width]


def kv(label, value, label_width=22, indent=""):
    return f"{indent}{label:<{label_width}}: {value}"


def bool_text(value):
    return "YES" if bool(value) else "NO"


def windows_root_group(path: str, explicit_root: str = ""):
    p = str(path or "").replace("/", "\\")
    lower = p.lower()
    root = str(explicit_root or "").replace("/", "\\")

    # Windows Store/MSIX maintenance frequently appears during broad pre/post
    # captures. Keep these entries visible, but never silently attribute them
    # to the assessed thick client without evidence.
    windowsapps_markers = ("\\program files\\windowsapps", "\\program files (x86)\\windowsapps")
    if any(marker + "\\" in lower or lower.endswith(marker)
           or marker + "\\" in root.lower() or root.lower().endswith(marker)
           for marker in windowsapps_markers):
        return "WindowsApps (unattributed)"

    groups = [
        ("Program Files (x86)", "\\program files (x86)\\"),
        ("Program Files", "\\program files\\"),
        ("ProgramData", "\\programdata\\"),
        ("LocalAppData", "\\appdata\\local\\"),
        ("Roaming AppData", "\\appdata\\roaming\\"),
        ("Windows", "\\windows\\"),
        ("TEMP", "\\temp\\"),
    ]
    for label, marker in groups:
        if marker in lower:
            return label

    if root:
        rl = root.lower()
        if "program files (x86)" in rl:
            return "Program Files (x86)"
        if "program files" in rl:
            return "Program Files"
        if "programdata" in rl:
            return "ProgramData"
        if "appdata\\local" in rl:
            return "LocalAppData"
        if "appdata\\roaming" in rl:
            return "Roaming AppData"
        if "temp" in rl:
            return "TEMP"
        return root

    drive, _ = ntpath.splitdrive(p)
    if drive:
        return f"Other ({drive})"
    return "Other"


def group_paths(items, path_getter=lambda x: x, root_getter=None):
    groups = defaultdict(list)
    for item in items or []:
        path = path_getter(item)
        root = root_getter(item) if root_getter else ""
        groups[windows_root_group(path, root)].append(item)
    preferred = [
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "LocalAppData",
        "Roaming AppData",
        "TEMP",
        "Windows",
        "WindowsApps (unattributed)",
    ]
    ordered = []
    seen = set()
    for name in preferred:
        if name in groups:
            ordered.append((name, groups[name]))
            seen.add(name)
    for name in sorted(groups):
        if name not in seen:
            ordered.append((name, groups[name]))
    return ordered


def format_bytes(value, unavailable="N/A"):
    if value is None or value == "":
        return unavailable
    try:
        size = float(value)
    except (TypeError, ValueError):
        return str(value)
    if size < 0:
        return str(value)

    units = ("B", "KB", "MB", "GB", "TB", "PB")
    idx = 0
    while size >= 1024.0 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1

    if idx == 0:
        return f"{int(size)} B"
    rendered = f"{size:.2f}".rstrip("0").rstrip(".")
    return f"{rendered} {units[idx]}"


def humanize_size_references(text: str) -> str:
    if not text:
        return text

    size_label = re.compile(
        r"(?i)(\b(?:physical\s+size|headers\s+size|packed\s+size|unpacked\s+size|"
        r"compressed\s+size|archive\s+size|file\s+size|size|length)\b\s*[:=]\s*)"
        r"(\d+)"
        r"(?!\s*(?:KB|KIB|MB|MIB|GB|GIB|TB|TIB|PB|PIB)\b)"
        r"(?:\s*bytes?\b)?"
    )
    bytes_value = re.compile(r"(?i)\b(\d+)\s+bytes?\b")

    text = size_label.sub(lambda m: f"{m.group(1)}{format_bytes(m.group(2))}", str(text))
    return bytes_value.sub(lambda m: format_bytes(m.group(1)), text)
