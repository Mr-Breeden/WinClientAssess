from __future__ import annotations
from utils.assessment_layout import artifact_path

import re
from collections import defaultdict
from pathlib import Path

from utils.report_format import header, kv, section


KNOWLEDGE_DATE = "2026-09-01"
OPENSSL_102_EOL = "2020-01-01"
ELECTRON_32_EOL = "2025-03-04"
OPENSSL_SOURCE = "https://www.openssl-library.org/news/vulnerabilities-1.0.2/"
ELECTRON_SOURCE = "https://releases.electronjs.org/schedule"
OPENSSL_PATTERN = re.compile(rb"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]*)", re.I)


def _clean_version(value: str) -> str:
    match = re.search(r"\d+(?:\.\d+){0,3}(?:[a-z]+)?", str(value or ""), re.I)
    return match.group(0) if match else str(value or "").strip()


def _openssl_components(file_inventory):
    rows = []
    seen = set()
    for item in file_inventory or []:
        path = Path(str(item.get("path") or ""))
        name = path.name.lower()
        if not path.is_file() or not any(token in name for token in ("ssl", "crypto", "libeay", "ssleay")):
            continue
        size = int(item.get("size_bytes") or 0)
        if size <= 0 or size > 64 * 1024 * 1024:
            continue
        try:
            data = path.read_bytes()
        except Exception:
            continue
        versions = set()
        for match in OPENSSL_PATTERN.finditer(data):
            suffix = data[match.end():match.end() + 48].lower()
            # OpenSSL libraries can contain build-template labels for other
            # development branches (for example "1.1.0-fips-dev xx XXX").
            # Those are not the linked component's runtime version.
            if b"-dev" in suffix[:24] or b"xx xxx" in suffix[:32]:
                continue
            versions.add(match.group(1).decode("ascii", errors="ignore"))
        for version in sorted(versions):
            key = (str(path).lower(), version.lower())
            if key not in seen:
                seen.add(key)
                rows.append({"Component": "OpenSSL", "Version": version, "Path": str(path)})
    return rows


def _electron_components(electron_result):
    rows = []
    for item in (electron_result or {}).get("electron_versions", []) or []:
        rows.append(
            {
                "Component": "Electron",
                "Version": _clean_version(item.get("Version")),
                "Path": str(item.get("Path") or ""),
            }
        )
    return rows


def _lifecycle(component: str, version: str):
    if component == "OpenSSL" and version.lower().startswith("1.0.2"):
        return {
            "Status": "END OF LIFE",
            "EndOfLife": OPENSSL_102_EOL,
            "Source": OPENSSL_SOURCE,
            "Reason": "OpenSSL 1.0.2 is no longer publicly supported or receiving public security updates.",
        }
    if component == "Electron":
        match = re.match(r"(\d+)", version)
        if match and int(match.group(1)) <= 32:
            return {
                "Status": "END OF LIFE",
                "EndOfLife": ELECTRON_32_EOL if int(match.group(1)) == 32 else "Before 2025-03-04",
                "Source": ELECTRON_SOURCE,
                "Reason": "This Electron major is outside the supported release window represented by the bundled lifecycle data.",
            }
    return {
        "Status": "UNKNOWN / NOT EVALUATED",
        "EndOfLife": "Unknown",
        "Source": "",
        "Reason": "No matching lifecycle rule is bundled for this component/version.",
    }


def run_component_lifecycle_review(
    roots,
    assessment_dir: Path,
    file_inventory=None,
    electron_result=None,
):
    components = _openssl_components(file_inventory) + _electron_components(electron_result)
    for item in components:
        item.update(_lifecycle(item["Component"], item["Version"]))

    width = 112
    lines = header(
        "Windows Client Assessment - Component Lifecycle Review",
        [
            "Inventories selected security-sensitive bundled components and compares them with a dated,",
            "offline lifecycle knowledge base. This is not a complete SBOM or vulnerability scan.",
        ],
        width,
    )
    eol = [item for item in components if item["Status"] == "END OF LIFE"]
    lines += [
        "SUMMARY",
        "-" * width,
        kv("Knowledge base date", KNOWLEDGE_DATE),
        kv("Component records", len(components)),
        kv("End-of-life records", len(eol)),
        kv("Coverage", "Electron declarations and OpenSSL version strings"),
    ]
    lines += section("Component Records", width, len(components))
    if not components:
        lines.append("No supported component/version signatures were identified.")
    for idx, item in enumerate(components, 1):
        lines += [
            f"[COMPONENT-{idx:03d}] {item['Component']} {item['Version']}",
            f"  Status      : {item['Status']}",
            f"  End of life : {item['EndOfLife']}",
            f"  Path        : {item['Path']}",
            f"  Rationale   : {item['Reason']}",
            f"  Source      : {item['Source'] or 'N/A'}",
            "",
        ]
    lines += section("Limitations", width)
    lines += [
        "- Component detection is signature-based and does not replace a vendor-provided SBOM.",
        "- Vendors may backport fixes without changing an upstream-looking version string.",
        "- Confirm reachability and vendor patch status before assigning a CVE or exploit severity.",
        "- Update the bundled lifecycle knowledge before relying on it after the stated knowledge date.",
    ]
    (artifact_path(assessment_dir, "component_lifecycle_review.txt")).write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8"
    )

    findings = []
    grouped = defaultdict(list)
    for item in eol:
        grouped[(item["Component"], item["Version"], item["EndOfLife"], item["Source"])].append(item["Path"])
    for (component, version, eol_date, source), paths in sorted(grouped.items()):
        findings.append(
            {
                "title": f"End-of-Life {component} Component Identified",
                "severity": "Medium",
                "description": (
                    f"The package contains {component} {version}, which the bundled lifecycle knowledge marks end of life. "
                    "Unsupported components may not receive public security fixes."
                ),
                "evidence": f"{len(paths)} file/declaration record(s); EOL: {eol_date}; source: {source}",
                "recommendation": (
                    f"Obtain vendor confirmation of backported fixes and upgrade {component} to a supported release. "
                    "Validate the final SBOM and applicable CVEs before production acceptance."
                ),
            }
        )

    return {
        "status": "WARN" if eol else "PASS",
        "details": f"{len(components)} component record(s); {len(eol)} end-of-life record(s)",
        "findings": findings,
        "components": components,
    }
