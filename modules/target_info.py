from __future__ import annotations

from pathlib import Path

from utils.assessment_layout import artifact_path
from utils.hashing import file_hashes
from utils.powershell import run_powershell_json
from utils.privacy import portable_basename
from utils.report_format import format_bytes, header, kv


def run_target_info(primary_executable: Path, assessment_dir: Path, *, source_path: Path | None = None,
                    target_type: str = "portable"):
    """Record the identity of a selected portable executable without executing it.

    The report intentionally mirrors the useful identity/hash fields from installer
    analysis while avoiding installer-specific semantics.  When a directory is the
    selected portable target, ``primary_executable`` is the tester-selected/derived
    entry executable and ``source_path`` identifies the application directory.
    """
    primary_executable = Path(primary_executable)
    source_path = Path(source_path) if source_path is not None else primary_executable
    stat = primary_executable.stat()
    hashes = file_hashes(primary_executable, prefix_bytes=32 * 1024 * 1024)
    data = {
        "path": str(primary_executable),
        "name": portable_basename(primary_executable),
        "extension": primary_executable.suffix.lower(),
        "size_bytes": stat.st_size,
        "size_human": format_bytes(stat.st_size),
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "prefix_bytes": hashes.get("prefix_bytes", b""),
        "target_type": target_type,
        "source_kind": "directory" if source_path.is_dir() else "executable",
        "source_name": source_path.name,
    }
    safe = str(primary_executable).replace("'", "''")
    ps = f"""
    $p = Get-Item -LiteralPath '{safe}'
    [PSCustomObject]@{{
      ProductName=$p.VersionInfo.ProductName; ProductVersion=$p.VersionInfo.ProductVersion;
      FileVersion=$p.VersionInfo.FileVersion; CompanyName=$p.VersionInfo.CompanyName;
      OriginalFilename=$p.VersionInfo.OriginalFilename; Description=$p.VersionInfo.FileDescription
    }}
    """
    winmeta, _ = run_powershell_json(ps)
    if isinstance(winmeta, dict):
        data["version_info"] = winmeta

    meta = data.get("version_info", {}) or {}
    width = 104
    lines = header(
        "Windows Client Assessment - Target Information",
        [
            "Records the selected portable target identity, primary executable metadata, size, and cryptographic hashes.",
            "The source location is not persisted; filename/directory name plus the primary executable SHA-256 identify the target.",
        ],
        width,
    )
    lines += [
        "IDENTITY", "-" * width,
        kv("Target Type", "Portable application"),
        kv("Selected Source", source_path.name),
        kv("Source Kind", data["source_kind"]),
        kv("Primary Executable", data["name"]),
        kv("Source Location", "Omitted from saved reports"),
        kv("Size", data["size_human"]),
        kv("Product Name", meta.get("ProductName")),
        kv("Product Version", meta.get("ProductVersion")),
        kv("File Version", meta.get("FileVersion")),
        kv("Company", meta.get("CompanyName")),
        kv("Original Filename", meta.get("OriginalFilename")),
        kv("Description", meta.get("Description")),
        "",
        "HASHES", "-" * width,
        kv("SHA-256", data["sha256"]),
        kv("SHA-1", data["sha1"]),
        kv("MD5", data["md5"]),
    ]
    artifact_path(assessment_dir, "target_analysis.txt").write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8"
    )
    prefix = data.pop("prefix_bytes", b"")
    # Keep the historical key name as an in-memory compatibility surface for
    # application_profile/target-identity helpers.  It is not serialized as an
    # installer artifact for portable targets.
    return {
        "status": "PASS",
        "details": f"Primary executable SHA256 {data['sha256']}",
        "installer_info": data,
        "target_info": data,
        "installer_prefix": prefix,
    }
