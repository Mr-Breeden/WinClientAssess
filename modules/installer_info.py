from utils.assessment_layout import artifact_path
from pathlib import Path
from utils.hashing import file_hashes
from utils.powershell import run_powershell_json
from utils.report_format import header, kv, format_bytes
from utils.privacy import portable_basename


def run_installer_info(installer: Path, assessment_dir: Path):
    stat = installer.stat()
    hashes = file_hashes(installer, prefix_bytes=32 * 1024 * 1024)
    data = {
        "path": str(installer),
        "name": portable_basename(installer),
        "extension": installer.suffix.lower(),
        "size_bytes": stat.st_size,
        "size_human": format_bytes(stat.st_size),
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
        "prefix_bytes": hashes.get("prefix_bytes", b""),
    }
    safe = str(installer).replace("'", "''")
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

    meta=data.get("version_info",{}) or {}
    width=104
    lines=header(
        "Windows Client Assessment - Installer Information",
        ["Records installer identity, version metadata, size, and cryptographic hashes used throughout the assessment."],
        width
    )
    lines += [
        "IDENTITY",
        "-"*width,
        kv("File Name",data["name"]),
        kv("Source Location", "Omitted from saved reports; filename and SHA-256 identify the installer"),
        kv("Type",data["extension"]),
        kv("Size", data["size_human"]),
        kv("Product Name",meta.get("ProductName")),
        kv("Product Version",meta.get("ProductVersion")),
        kv("File Version",meta.get("FileVersion")),
        kv("Company",meta.get("CompanyName")),
        kv("Original Filename",meta.get("OriginalFilename")),
        kv("Description",meta.get("Description")),
        "",
        "HASHES",
        "-"*width,
        kv("SHA-256",data["sha256"]),
        kv("SHA-1",data["sha1"]),
        kv("MD5",data["md5"]),
    ]
    (artifact_path(assessment_dir, "installer_analysis.txt")).write_text("\n".join(lines).rstrip()+"\n", encoding="utf-8")
    prefix = data.pop("prefix_bytes", b"")
    return {"status":"PASS","details":f"SHA256 {data['sha256']}","installer_info":data,"installer_prefix":prefix}
