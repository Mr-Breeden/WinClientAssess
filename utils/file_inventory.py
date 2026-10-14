from __future__ import annotations

import csv
from pathlib import Path

from utils.report_format import format_bytes
from utils.privacy import sanitize_report_text


INVENTORY_FIELDS = ["root", "path", "name", "extension", "size_bytes", "size_human"]


def _safe_csv_cell(value):
    """Prevent spreadsheet applications from interpreting untrusted paths as formulas."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def build_file_inventory(roots):
    """
    Enumerate analysis roots once and return reusable file metadata.

    Downstream static modules filter this inventory instead of recursively
    traversing the extracted installer tree independently.
    """
    rows = []
    seen = set()

    for root in roots or []:
        path = Path(root)

        if path.is_file():
            items = [path]
        elif path.is_dir():
            items = path.rglob("*")
        else:
            continue

        try:
            root_text = str(path.resolve())
        except Exception:
            root_text = str(path)

        for item in items:
            try:
                if not item.is_file():
                    continue
                resolved = item.resolve()
                key = str(resolved).lower()
                if key in seen:
                    continue
                seen.add(key)
                stat = resolved.stat()
                rows.append({
                    "root": root_text,
                    "path": str(resolved),
                    "name": resolved.name,
                    "extension": resolved.suffix.lower(),
                    "size_bytes": stat.st_size,
                    "size_human": format_bytes(stat.st_size),
                })
            except Exception:
                continue

    return rows


def write_file_inventory_csv(inventory, output_file: Path, installer=None):
    """Write the complete shared static file inventory."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=INVENTORY_FIELDS)
        writer.writeheader()
        for row in inventory or []:
            writer.writerow({field: _safe_csv_cell(sanitize_report_text(row.get(field, ""), installer)
                if field in {"root", "path"} else row.get(field, "")) for field in INVENTORY_FIELDS})


def inventory_stats(inventory, root=None):
    """Return file count/size, optionally restricted to a specific inventory root."""
    root_key = None
    if root is not None:
        try:
            root_key = str(Path(root).resolve()).lower()
        except Exception:
            root_key = str(root).lower()

    selected = [
        row for row in (inventory or [])
        if root_key is None or str(row.get("root") or "").lower() == root_key
    ]
    return {
        "file_count": len(selected),
        "size_bytes": sum(int(row.get("size_bytes") or 0) for row in selected),
    }
