from __future__ import annotations
from utils.assessment_layout import artifact_path

import json
import re
from pathlib import Path

from utils.report_format import header, kv, section


TEXT_EXTS = {".js", ".json", ".html", ".htm"}
MAX_SOURCE_SIZE = 6 * 1024 * 1024
SIGNALS = {
    "Node integration enabled": re.compile(r"\bnodeIntegration\s*:\s*true\b", re.I),
    "Context isolation disabled": re.compile(r"\bcontextIsolation\s*:\s*false\b", re.I),
    "Remote module enabled": re.compile(r"\benableRemoteModule\s*:\s*true\b|remoteMain\.enable\s*\(", re.I),
    "Webview tag enabled": re.compile(r"\bwebviewTag\s*:\s*true\b", re.I),
    "Loopback HTTP content loaded": re.compile(r"(?:loadURL\s*\([^\n]*|['\"])http://127\.0\.0\.1", re.I),
    "Unsafe CSP script policy": re.compile(r"script-src[^\r\n]*(?:'unsafe-inline'|'unsafe-eval')", re.I),
    "Secret appended to URL": re.compile(r"(?:CLIENT_SECRET|clientSecret)[\s\S]{0,10000}(?:[?&]secret=|['\"]\?secret=)", re.I),
}
NAVIGATION_GUARDS = re.compile(r"will-navigate|setWindowOpenHandler|will-redirect", re.I)
PORT_KEY = re.compile(r"jsonData\.([A-Za-z0-9_]*PORT[A-Za-z0-9_]*)")


def _source_files(file_inventory):
    for row in file_inventory or []:
        path = Path(str(row.get("path") or ""))
        extension = str(row.get("extension") or path.suffix).lower()
        size = int(row.get("size_bytes") or 0)
        if extension in TEXT_EXTS and size <= MAX_SOURCE_SIZE and path.is_file():
            yield path


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _electron_versions(paths):
    versions = []
    for path in paths:
        if path.name.lower() != "package.json" or "node_modules" in {part.lower() for part in path.parts}:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for area in ("dependencies", "devDependencies", "optionalDependencies"):
            value = (data.get(area) or {}).get("electron") if isinstance(data, dict) else None
            if value:
                versions.append({"Path": str(path), "Version": str(value), "Source": area})
    return versions


def run_electron_security_review(roots, assessment_dir: Path, file_inventory=None):
    paths = list(_source_files(file_inventory))
    versions = _electron_versions(paths)
    hits = []
    port_keys = set()
    electron_source_seen = bool(versions)
    files_with_navigation_guard = set()

    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if "BrowserWindow" in text or "electron" in path.as_posix().lower():
            electron_source_seen = True
        if NAVIGATION_GUARDS.search(text):
            files_with_navigation_guard.add(str(path))
        port_keys.update(PORT_KEY.findall(text))
        for name, pattern in SIGNALS.items():
            for match in pattern.finditer(text):
                hits.append(
                    {
                        "Signal": name,
                        "Path": str(path),
                        "Line": _line_number(text, match.start()),
                    }
                )

        if "certificate-error" in text and re.search(r"callback\s*\(\s*true\s*\)", text):
            match = re.search(r"certificate-error", text)
            hits.append(
                {
                    "Signal": "Certificate errors unconditionally accepted",
                    "Path": str(path),
                    "Line": _line_number(text, match.start()) if match else 1,
                }
            )

    signal_names = {item["Signal"] for item in hits}
    remote_content = "Loopback HTTP content loaded" in signal_names
    privileged_renderer = bool(
        signal_names.intersection(
            {"Node integration enabled", "Context isolation disabled", "Remote module enabled"}
        )
    )
    navigation_limited = bool(files_with_navigation_guard)

    width = 112
    lines = header(
        "Windows Client Assessment - Electron Security Review",
        [
            "Reviews extracted Electron configuration for renderer isolation, content trust, navigation,",
            "certificate handling, and secret propagation. Matches are review points, not proof of exploitation.",
        ],
        width,
    )
    lines += [
        "SUMMARY",
        "-" * width,
        kv("Electron source detected", electron_source_seen),
        kv("Declared Electron versions", len(versions)),
        kv("Security signals", len(hits)),
        kv("Loopback HTTP loading", remote_content),
        kv("Navigation guard detected", navigation_limited),
        kv("Referenced port keys", ", ".join(sorted(port_keys)) or "None"),
    ]
    if versions:
        lines += section("Declared Electron Versions", width, len(versions))
        for item in versions:
            lines += [
                f"Path    : {item['Path']}",
                f"Version : {item['Version']} ({item['Source']})",
                "",
            ]
    lines += section("Security Signals", width, len(hits))
    if not hits:
        lines.append("No configured Electron security patterns matched.")
    for idx, item in enumerate(hits, 1):
        lines += [
            f"[ELECTRON-{idx:03d}] {item['Signal']}",
            f"  File : {item['Path']}",
            f"  Line : {item['Line']}",
            "",
        ]
    if remote_content and not navigation_limited:
        lines += section("Navigation Boundary", width)
        lines.append(
            "HTTP/URL content loading was detected without will-navigate, will-redirect, or setWindowOpenHandler controls."
        )
    (artifact_path(assessment_dir, "electron_security_review.txt")).write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8"
    )

    findings = []
    if remote_content and privileged_renderer:
        enabled = sorted(
            signal_names.intersection(
                {
                    "Node integration enabled",
                    "Context isolation disabled",
                    "Remote module enabled",
                    "Webview tag enabled",
                    "Unsafe CSP script policy",
                }
            )
        )
        findings.append(
            {
                "title": "Electron Renderer Trust Boundary Requires Remediation",
                "severity": "High",
                "description": (
                    "Electron loads HTTP content into a renderer with privileged web preferences. A content injection, "
                    "redirect, compromised local service response, or port-confusion weakness could turn script execution "
                    "into native code execution in the Electron user's context."
                ),
                "evidence": "; ".join(enabled) + ("; no navigation guard detected" if not navigation_limited else ""),
                "recommendation": (
                    "Disable Node integration and remote access, enable context isolation and sandboxing, use a narrow "
                    "preload/contextBridge API, enforce allowed origins/navigation, and avoid loading privileged renderers over HTTP."
                ),
            }
        )
    if "Certificate errors unconditionally accepted" in signal_names:
        findings.append(
            {
                "title": "Electron Certificate Validation Can Be Bypassed",
                "severity": "Medium",
                "description": "An Electron certificate-error handler appears to accept certificate failures without validating the URL or certificate.",
                "evidence": "certificate-error and callback(true) were identified in the same Electron main-process source file.",
                "recommendation": "Remove blanket certificate overrides or strictly validate the expected origin and certificate before allowing an exception.",
            }
        )
    if "Secret appended to URL" in signal_names:
        findings.append(
            {
                "title": "Electron Secret Is Propagated Through a URL",
                "severity": "Medium",
                "description": "Electron source reads a client secret and appends it to a renderer URL, increasing exposure to renderer code and diagnostic artifacts.",
                "evidence": "CLIENT_SECRET/clientSecret data flow to a secret query parameter was detected.",
                "recommendation": "Use a short-lived, one-time authenticated IPC exchange and keep secrets out of URLs, command lines, and child-process environments.",
            }
        )

    return {
        "status": "WARN" if findings else "PASS",
        "details": f"{len(versions)} Electron version declaration(s); {len(hits)} security signal(s); {len(findings)} review point(s)",
        "findings": findings,
        "electron_versions": versions,
        "electron_signals": hits,
        "local_http_port_keys": sorted(port_keys),
        "dynamic_loopback_http": remote_content,
    }
