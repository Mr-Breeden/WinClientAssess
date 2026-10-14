from utils.assessment_layout import artifact_path
"""PE security-mitigation review.

Windows Installer extractors sometimes retain MSI File table keys instead of
original names. Discover PE images from their DOS/NT headers, not extensions.
The shared static inventory avoids a second filesystem walk when provided.
"""
from pathlib import Path
import struct

try:
    import pefile
except ImportError:
    pefile = None


PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}


def _has_pe_header(path):
    """Read only the DOS header and NT signature; never load/execute the image.

    A bare MZ prefix is not sufficient: installers and unrelated DOS files may
    begin with MZ but lack a valid PE signature at e_lfanew.
    """
    with Path(path).open("rb") as fh:
        dos = fh.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            return False
        nt_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        if nt_offset < 64:
            return False
        fh.seek(nt_offset)
        return fh.read(4) == b"PE\x00\x00"


def _iter_candidates(roots, file_inventory=None):
    """Yield all PE images once, including extensionless MSI payloads.

    For known PE extensions, keep unreadable files in scope so the analyzer
    records a coverage failure rather than silently omitting them. An unreadable
    file with an arbitrary extension has no evidence that it is a PE image.
    """
    seen = set()
    if file_inventory is not None:
        paths = (Path(row["path"]) for row in file_inventory if row.get("path"))
    else:
        def root_files():
            for root in roots or ():
                p = Path(root)
                if p.is_file():
                    yield p
                elif p.is_dir():
                    yield from (item for item in p.rglob("*") if item.is_file())
        paths = root_files()

    for candidate in paths:
        key = str(candidate).casefold()
        if key in seen:
            continue
        seen.add(key)
        try:
            if _has_pe_header(candidate):
                yield candidate
        except OSError:
            if candidate.suffix.casefold() in PE_EXTS:
                # Retain the path to produce a parse error/coverage failure.
                yield candidate


def _analyze(path):
    row = {
        "path": str(path), "architecture": "", "aslr": "", "dep_nx": "",
        "cfg": "", "high_entropy_va": "", "dotnet": "", "error": "",
    }
    if pefile is None:
        row["error"] = "pefile Python package not installed"
        return row
    try:
        pe = pefile.PE(str(path), fast_load=False)
        try:
            row["architecture"] = {
                0x14c: "x86", 0x8664: "x64", 0xAA64: "ARM64",
            }.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
            chars = pe.OPTIONAL_HEADER.DllCharacteristics
            row["aslr"] = bool(chars & 0x0040)
            row["dep_nx"] = bool(chars & 0x0100)
            row["high_entropy_va"] = bool(chars & 0x0020)
            row["cfg"] = bool(chars & 0x4000)
            try:
                row["dotnet"] = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
            except (IndexError, AttributeError):
                row["dotnet"] = False
        finally:
            pe.close()
    except Exception as exc:
        row["error"] = str(exc)
    return row


def run_pe_analysis(roots, assessment_dir, file_inventory=None):
    """Generate TXT-only PE report; distinguish recognition from successful analysis."""
    rows = [_analyze(path) for path in _iter_candidates(roots, file_inventory)]
    parsed = [row for row in rows if not row["error"]]
    failed = [row for row in rows if row["error"]]
    no_aslr = sum(row["aslr"] is False for row in parsed)
    no_dep = sum(row["dep_nx"] is False for row in parsed)
    no_cfg = sum(row["cfg"] is False for row in parsed)
    dotnet_count = sum(row["dotnet"] is True for row in parsed)
    width = 104
    lines = [
        "WCA - PE SECURITY REVIEW",
        "=" * width,
        "",
        "Purpose:",
        "  Identifies executable images by their PE headers, including extensionless MSI-extracted",
        "  payloads. Missing mitigation flags are review points, not confirmed vulnerabilities.",
        "",
        "SUMMARY",
        "-" * width,
        f"PE files discovered   : {len(rows)}",
        f"Files analyzed        : {len(parsed)}",
        f"Files not analyzed    : {len(failed)}",
        f"ASLR missing          : {no_aslr}",
        f"DEP/NX missing        : {no_dep}",
        f"CFG missing           : {no_cfg}",
        f".NET assemblies       : {dotnet_count}",
        f"Parse errors          : {len(failed)}",
        "",
        "COVERAGE",
        "-" * width,
    ]
    if failed:
        lines.append("  INCOMPLETE: one or more recognized PE images could not be analyzed.")
    elif parsed:
        lines.append("  Complete: all discovered PE images were analyzed.")
    else:
        lines.append("  No valid PE headers discovered in the supplied analysis scope.")
    lines += ["", "PER-FILE REVIEW", "-" * width]
    for idx, row in enumerate(rows, 1):
        lines += [
            f"[PE-{idx:04d}] {row['path']}",
            f"  Architecture : {row['architecture']}",
            f"  ASLR         : {row['aslr']}",
            f"  DEP/NX       : {row['dep_nx']}",
            f"  CFG          : {row['cfg']}",
            f"  HighEntropyVA: {row['high_entropy_va']}",
            f"  .NET         : {row['dotnet']}",
            f"  Error        : {row['error'] or 'None'}",
            "",
        ]
    artifact_path(assessment_dir, "binary_security_review.txt").write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8",
    )

    baseline_weak = [row for row in parsed if row["aslr"] is False or row["dep_nx"] is False]
    cfg_weak = [row for row in parsed if row["cfg"] is False]
    weak = [row for row in parsed if row in baseline_weak or row in cfg_weak]
    findings = []
    if baseline_weak:
        names = ", ".join(Path(row["path"]).name for row in baseline_weak[:12])
        findings.append({
            "title": "PE Files Lack Baseline Exploit Mitigations",
            "severity": "Low",
            "description": "One or more native binaries lack ASLR and/or DEP/NX, reducing resistance to memory-corruption exploitation.",
            "evidence": (
                f"{len(baseline_weak)} PE file(s) lack ASLR and/or DEP/NX "
                f"(ASLR missing: {no_aslr}; DEP/NX missing: {no_dep}): {names}."
            ),
            "recommendation": "Rebuild affected binaries with dynamic-base and NX-compatible linker settings and validate compatibility in supported environments.",
        })
    if cfg_weak:
        findings.append({
            "title": "Control Flow Guard Coverage Requires Improvement",
            "severity": "Informational",
            "description": "Control Flow Guard metadata is absent from one or more native binaries.",
            "evidence": f"CFG missing from {len(cfg_weak)} of {len(parsed)} successfully analyzed PE file(s).",
            "recommendation": "Enable CFG for supported native components and document exceptions for third-party or compatibility-constrained binaries.",
        })

    if failed:
        status = "ERROR"
        details = f"{len(rows)} PE file(s) discovered; {len(parsed)} analyzed; {len(failed)} failed"
    elif weak:
        status = "WARN"
        details = f"{len(parsed)} PE file(s) analyzed; {len(weak)} require mitigation review"
    elif parsed:
        status = "PASS"
        details = f"{len(parsed)} PE file(s) analyzed"
    else:
        status = "PASS"
        details = "0 PE files discovered (no valid PE headers in analysis scope)"
    return {
        "status": status,
        "details": details,
        "coverage_gap": bool(failed),
        "pe_rows": rows,
        "findings": findings,
        "discovered": len(rows),
        "analyzed": len(parsed),
        "failed": len(failed),
    }
