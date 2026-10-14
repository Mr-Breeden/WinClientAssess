from __future__ import annotations
from utils.assessment_layout import artifact_path, generated_directory_path

import os
import shutil
from pathlib import Path

from utils.command_runner import run_command
from utils.file_inventory import inventory_stats
from utils.report_format import header, kv, format_bytes, humanize_size_references


def _lessmsi_extract(installer: Path, extract_dir: Path, lessmsi: str):
    dest = str(extract_dir)
    if not dest.endswith(("\\", "/")):
        dest += os.sep
    return run_command([lessmsi, "x", str(installer), dest], timeout=300)


def _write_report(assessment_dir, method, result, extract_dir, installer=None, notes=None, stats=None):
    width = 104
    stats = stats or {"file_count": 0, "size_bytes": 0}
    lines = header(
        "Windows Client Assessment - Installer Extraction",
        [
            "Extracts installer contents for downstream static analysis.",
            "Extraction statistics are derived from the shared static file inventory to avoid a second directory traversal.",
            "Raw extraction tool output is retained below as supporting evidence.",
        ],
        width,
    )
    lines += [
        "SUMMARY", "-" * width,
        kv("Method", method),
        kv("Return Code", result.get("returncode")),
        kv("Destination", extract_dir),
        kv("Source Installer Size", format_bytes(installer.stat().st_size) if installer and installer.exists() else "N/A"),
        kv("Files Extracted", stats["file_count"]),
        kv("Extracted Content Size", format_bytes(stats["size_bytes"])),
    ]
    if notes:
        lines += ["", "Notes:"] + [f"  {x}" for x in notes]
    if result.get("stdout", "").strip():
        lines += ["", "TOOL OUTPUT (SIZE VALUES HUMANIZED)", "-" * width,
                  humanize_size_references(result.get("stdout", "")).rstrip()]
    elif method.startswith("NOT APPLICABLE") and not result.get("stderr", "").strip():
        lines += ["", "No extraction tool invoked; static analysis continues on the supplied executable/deployment."]
    if result.get("stderr", "").strip():
        lines += ["", "STDERR", "-" * width, humanize_size_references(result.get("stderr", "")).rstrip()]
    (artifact_path(assessment_dir, "installer_extraction.txt")).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def finalize_extraction_report(assessment_dir: Path, extraction_result, static_inventory):
    """Finalize a successful extraction report using the already-built static inventory."""
    if not extraction_result or not extraction_result.get("extract_dir"):
        return
    stats = inventory_stats(static_inventory, extraction_result.get("extract_dir"))
    _write_report(
        assessment_dir,
        extraction_result.get("method", "Unknown"),
        extraction_result.get("tool_result", {}),
        Path(extraction_result["extract_dir"]),
        Path(extraction_result["installer"]),
        extraction_result.get("notes") or [],
        stats,
    )


def run_installer_extract(installer: Path, assessment_dir: Path, tools, defer_report=False, application_scope=None):
    application_scope = application_scope or {}
    extract_dir = generated_directory_path(assessment_dir, "extracted_installer")
    notes = []
    if application_scope.get("skip_extraction"):
        notes.append(
            "Selected file is a published .NET application host rather than a setup archive. "
            "Adjacent publishing files, when present, are inventoried read-only."
        )
        _write_report(
            assessment_dir, "NOT APPLICABLE - published application", {"returncode": "N/A"},
            extract_dir, installer, notes,
        )
        return {"status": "SKIPPED", "details": "Published .NET apphost; extraction not applicable",
                "extract_dir": None}
    # Recovery reruns static analysis. Earlier extraction outputs from another
    # tool (e.g. 7-Zip followed by lessmsi) must not accumulate or count twice.
    # Delete only our fixed generated subtree, never an externally chosen dir.
    root = Path(assessment_dir).resolve()
    expected = generated_directory_path(root, "extracted_installer")
    if extract_dir.is_symlink() or expected.resolve() != extract_dir.resolve() or root not in extract_dir.resolve().parents:
        raise ValueError("Untrusted generated extraction directory")
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=False)

    def success(method, result, status="PASS", details=None):
        payload = {
            "status": status,
            "details": details or f"Extracted with {method} to {extract_dir}",
            "extract_dir": str(extract_dir),
            "method": method,
            "tool_result": result,
            "notes": list(notes),
            "installer": str(installer),
            "coverage_gap": status == "WARN",
        }
        if not defer_report:
            _write_report(assessment_dir, method, result, extract_dir, installer, notes)
        return payload

    if installer.suffix.lower() == ".msi":
        lessmsi = tools.get("lessmsi", {}).get("path")
        if lessmsi:
            result = _lessmsi_extract(installer, extract_dir, lessmsi)
            if result["returncode"] == 0:
                return success("lessmsi", result)
            notes.append("lessmsi extraction failed; 7-Zip fallback attempted.")

    seven = tools.get("7-Zip", {}).get("path") or shutil.which("7z") or shutil.which("7z.exe")
    if not seven:
        result = {"returncode": 127, "stdout": "", "stderr": "7-Zip was not detected. No fallback extraction method is available."}
        _write_report(assessment_dir, "Unavailable", result, extract_dir, installer, notes)
        if application_scope.get("known_installer"):
            return {"status": "WARN", "details": "Known installer could not be extracted: no extraction tool",
                    "coverage_gap": True, "extract_dir": None}
        return {"status": "SKIPPED", "details": "No usable extraction tool detected",
                "coverage_gap": True, "extract_dir": None}

    result = run_command([seven, "x", "-y", f"-o{extract_dir}", str(installer)], timeout=300)
    if result["returncode"] not in (0, 1):
        output = (result.get("stderr", "") + "\n" + result.get("stdout", "")).lower()
        not_archive = any(phrase in output for phrase in (
            "cannot open the file as archive", "can't open as archive", "is not archive",
        ))
        if installer.suffix.lower() == ".exe" and not application_scope.get("known_installer") and not_archive:
            notes.append(
                "7-Zip confirmed no extractable archive. This is not an extraction error "
                "for a standalone executable; the EXE is still analyzed."
            )
            _write_report(assessment_dir, "NOT APPLICABLE - executable without archive", result,
                          extract_dir, installer, notes)
            try:
                extract_dir.rmdir()
            except OSError:
                pass
            return {"status": "SKIPPED", "details": "Executable is not an archive; binary analysis continues",
                    "coverage_gap": application_scope.get("kind") == "unclassified_executable",
                    "extract_dir": None}
        notes.append("The selected package could not be extracted; static payload coverage is incomplete.")
        _write_report(assessment_dir, "7-Zip - failed", result, extract_dir, installer, notes)
        return {"status": "WARN", "details": "Package extraction failed; payload analysis incomplete",
                "coverage_gap": True, "extract_dir": None}
    if result["returncode"] == 1:
        notes.append("7-Zip completed with warnings; extracted content may be incomplete.")
        return success(
            "7-Zip",
            result,
            status="WARN",
            details="7-Zip completed with warnings; static-analysis coverage may be incomplete",
        )
    return success("7-Zip", result)
