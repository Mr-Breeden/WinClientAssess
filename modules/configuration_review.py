from utils.assessment_layout import artifact_path
from pathlib import Path
from collections import Counter, defaultdict
import re
import json
import xml.etree.ElementTree as ET
from utils.report_format import header, section, kv, format_bytes

EXTS = {
    ".config",".json",".xml",".ini",".yaml",".yml",".toml",".properties",".conf",".cfg",".txt",
    ".db",".sqlite",".sqlite3",".ps1",".bat",".cmd",".vbs",".js"
}
HIGH = {".pfx",".p12",".pem",".key",".cer",".crt",".db",".sqlite",".sqlite3"}

CATEGORY = {
    ".config":"Configuration", ".json":"Configuration", ".xml":"Configuration", ".ini":"Configuration",
    ".yaml":"Configuration", ".yml":"Configuration", ".toml":"Configuration", ".properties":"Configuration",
    ".conf":"Configuration", ".cfg":"Configuration", ".txt":"Text/Other",
    ".ps1":"Script", ".bat":"Script", ".cmd":"Script", ".vbs":"Script", ".js":"Script",
    ".db":"Database", ".sqlite":"Database", ".sqlite3":"Database",
    ".pfx":"Certificate/Key", ".p12":"Certificate/Key", ".pem":"Certificate/Key", ".key":"Certificate/Key",
    ".cer":"Certificate/Key", ".crt":"Certificate/Key",
}


def _iter_files(roots):
    seen=set()
    for root in roots:
        p=Path(root); items=[p] if p.is_file() else (p.rglob("*") if p.is_dir() else [])
        for item in items:
            if item.is_file():
                k=str(item.resolve())
                if k not in seen:
                    seen.add(k)
                    yield item


def _pem_description(path):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")[:262144]
    except Exception:
        return "PEM material; contents could not be classified automatically."
    if "PRIVATE KEY-----" in text:
        return "PEM contains a private-key block; validate authorization, protection, and application use."
    cert_count = text.count("-----BEGIN CERTIFICATE-----")
    if cert_count > 1:
        return f"CA/certificate bundle containing {cert_count} certificate blocks; no private-key marker detected."
    if cert_count == 1:
        return "PEM certificate; no private-key marker detected. Review trust purpose and replacement permissions."
    return "PEM material; no certificate or private-key block marker was recognized."


def _risk_reason(path):
    ext = Path(path).suffix.lower()
    if ext == ".pem":
        return _pem_description(path)
    if ext in {".pfx",".p12",".key"}:
        return "May contain private key material or client certificates."
    if ext in {".cer",".crt"}:
        return "Certificate material; review trust purpose and associated private-key handling."
    if ext in {".db",".sqlite",".sqlite3"}:
        return "Local database; review for credentials, tokens, personal/sensitive data, and writable security configuration."
    return "Security-relevant local artifact."


def _review_priority(path):
    lower = str(path).replace("/", "\\").lower()
    name = Path(path).name.lower()
    if "\\locales\\" in lower or "\\node_modules\\" in lower or name.endswith(".min.js"):
        return "LOW"
    if any(token in name for token in ("config", "setting", "policy", "auth", "update", "main.js", "package.json")):
        return "HIGH"
    return "MEDIUM"


# Configuration weakness indicators are deliberately exact-value checks, not
# keyword-only findings. They still require examination of actual code paths.
_SECURITY_SETTING_RULES = {
    "ignoresslerrors": ("TLS verification disabled", lambda v: v.lower() in {"true", "1", "yes"}),
    "skipcertificatevalidation": ("TLS verification disabled", lambda v: v.lower() in {"true", "1", "yes"}),
    "allowinvalidcertificates": ("TLS verification disabled", lambda v: v.lower() in {"true", "1", "yes"}),
    "logpasswords": ("Sensitive credential logging enabled", lambda v: v.lower() in {"true", "1", "yes"}),
    "logsecrets": ("Sensitive credential logging enabled", lambda v: v.lower() in {"true", "1", "yes"}),
    "debug": ("Debug configuration enabled", lambda v: v.lower() in {"true", "1", "yes"}),
    "hashalgorithm": ("Legacy hash algorithm configured", lambda v: v.lower() in {"md5", "sha1", "sha-1"}),
    "algorithm": ("Legacy cipher configured", lambda v: v.lower() in {"des", "rc2", "rc4", "3des", "tripledes"}),
    "updateserverurl": ("Unencrypted update endpoint configured", lambda v: v.lower().startswith("http://")),
    "allowunsignedupdates": ("Unsigned updates permitted by configuration", lambda v: v.lower() in {"true", "1", "yes"}),
    "allowuntrustedplugins": ("Untrusted plugins permitted by configuration", lambda v: v.lower() in {"true", "1", "yes"}),
    "enableunsafedeserialization": ("Unsafe deserialization mode enabled", lambda v: v.lower() in {"true", "1", "yes"}),
    "allowcommandexecution": ("Command execution feature enabled", lambda v: v.lower() in {"true", "1", "yes"}),
}


def _configuration_indicators(rows):
    """Read scoped configuration artifacts; retain only the setting name and signal.

    Supports XML, JSON and conventional key/value configuration. Does not store
    the potentially sensitive input values, even for a matched setting.
    """
    indicators = []
    for row in rows:
        path = Path(row["path"])
        ext = path.suffix.lower()
        if ext not in {".xml", ".config", ".json", ".ini", ".cfg", ".conf", ".properties", ".yaml", ".yml"}:
            continue
        try:
            if path.stat().st_size > 2 * 1024 * 1024:
                continue
            if ext in {".xml", ".config"}:
                root = ET.parse(path).getroot()
                pairs = ((element.tag.rsplit("}", 1)[-1], (element.text or "").strip())
                         for element in root.iter())
            elif ext == ".json":
                obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))

                def walk(value, depth=0):
                    if depth > 12:
                        return
                    if isinstance(value, dict):
                        for k, v in value.items():
                            if not isinstance(v, (dict, list)):
                                yield str(k), str(v)
                            else:
                                yield from walk(v, depth + 1)
                    elif isinstance(value, list):
                        for v in value:
                            yield from walk(v, depth + 1)
                pairs = walk(obj)
            else:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                pairs = ((match.group(1), match.group(2).strip().strip('"\''))
                         for line in lines
                         if (match := re.match(r"^\s*([\w.-]{1,80})\s*[:=]\s*(.*?)\s*$", line)))
            for key, value in pairs:
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                rule = _SECURITY_SETTING_RULES.get(normalized)
                if rule and rule[1](value):
                    indicators.append({"path": str(path), "setting": key, "category": rule[0]})
                    if len(indicators) >= 250:
                        return indicators
        except (OSError, ET.ParseError, ValueError, TypeError, json.JSONDecodeError):
            continue
    return indicators


def run_configuration_review(roots, assessment_dir, file_inventory=None):
    rows=[]; high=[]
    if file_inventory is not None:
        source_rows = file_inventory
    else:
        source_rows = []
        for p in _iter_files(roots):
            try:
                source_rows.append({
                    "path": str(p),
                    "extension": p.suffix.lower(),
                    "size_bytes": p.stat().st_size,
                    "size_human": format_bytes(p.stat().st_size),
                })
            except Exception:
                continue

    for item in source_rows:
        path = str(item.get("path") or "")
        ext = str(item.get("extension") or Path(path).suffix).lower()
        if ext in EXTS:
            rows.append({
                "path": path,
                "extension": ext,
                "size_bytes": item.get("size_bytes", 0),
                "size_human": item.get("size_human") or format_bytes(item.get("size_bytes", 0)),
                "category": CATEGORY.get(ext, "Other"),
                "priority": _review_priority(path),
            })
        if ext in HIGH:
            high.append({"path":path,"extension":ext,"reason":_risk_reason(path)})

    width=104
    counts=Counter(r["category"] for r in rows)
    lines=header(
        "Windows Client Assessment - Configuration Review",
        [
            "Inventories configuration, script, local database, and related text artifacts from the installer/extracted content.",
            "Use this file to prioritize manual review; presence of an artifact is not itself a vulnerability.",
        ], width
    )
    lines += ["SUMMARY","-"*width, kv("Total artifacts",len(rows))]
    for name in ["Configuration","Script","Database","Text/Other","Other"]:
        if counts.get(name):
            lines.append(kv(name,counts[name]))
    lines += section("Recommended Review Workflow",width)
    lines += [
        "1. Review configuration files for endpoints, authentication options, update settings, paths, and security controls.",
        "2. Review scripts for command execution, writable inputs, privileged actions, and embedded secrets.",
        "3. Review local databases for credentials/tokens/sensitive data and access permissions.",
        "4. Correlate security-relevant artifacts with secrets_review.txt and privilege_boundary_review.txt.",
    ]

    grouped=defaultdict(list)
    for row in rows: grouped[row["category"]].append(row)
    for category in ["Configuration","Script","Database","Text/Other","Other"]:
        items=sorted(grouped.get(category,[]), key=lambda row: ({"HIGH":0,"MEDIUM":1,"LOW":2}[row["priority"]], row["path"].lower()))
        if not items: continue
        lines += section(category,width,len(items))
        for idx,row in enumerate(items,1):
            lines.append(f"[{category[:3].upper()}-{idx:03d}] Priority={row['priority']} | {row['path']} | Size: {row['size_human']}")

    indicators = _configuration_indicators(rows)
    lines += section("Security-Relevant Configuration Indicators", width, len(indicators))
    lines += ["Exact-value checks on XML/configuration fields. A detected setting is a validation lead, not proof the setting is active or exploitable.",
              "Only file location, setting name and indicator category are retained; settings values are not persisted."]
    for index, indicator in enumerate(indicators, 1):
        from utils.privacy import sanitize_report_text
        lines.extend([f"[CFG-S-{index:03d}] {indicator['category']}",
                      kv("File", sanitize_report_text(indicator["path"]), 14, "  "),
                      kv("Setting", indicator["setting"], 14, "  "), ""])
    (artifact_path(assessment_dir, "configuration_review.txt")).write_text("\n".join(lines).rstrip()+"\n",encoding="utf-8")

    high_lines=header(
        "Windows Client Assessment - High Value Security Artifacts",
        [
            "Lists local artifacts that commonly deserve targeted security review.",
            "The reason for inclusion is shown so testers know what to validate.",
        ], width
    )
    high_lines += ["SUMMARY","-"*width,kv("High-value artifacts",len(high))]
    if not high:
        high_lines += ["","No high-value certificate/key/database artifacts were identified."]
    for idx,item in enumerate(high,1):
        high_lines += [
            "",
            "="*width,
            f"[HVA-{idx:03d}] {Path(item['path']).name}",
            "="*width,
            kv("Path",item["path"]),
            kv("Type",item["extension"]),
            kv("Why Review",item["reason"]),
            "Tester Action:",
            "  Validate contents, effective file permissions, whether the application actually uses the artifact,",
            "  and whether exposure/modification creates a meaningful security impact.",
        ]
    (artifact_path(assessment_dir, "high_value_security_artifacts.txt")).write_text("\n".join(high_lines).rstrip()+"\n",encoding="utf-8")

    findings=[]
    if indicators:
        findings.append({
            "title":"Security-Relevant Configuration Requires Validation","severity":"Informational",
            "description":"Configuration contains security-sensitive settings that may reduce protection if active and reachable.",
            "evidence":f"{len(indicators)} scoped configuration indicator(s) identified. Refer to configuration_review.txt; values are omitted.",
            "recommendation":"Verify which settings are active, their trust boundaries and whether unintended principals can influence them."
        })
    if high:
        findings.append({
            "title":"High-Value Local Artifacts Identified","severity":"Informational",
            "description":"Potentially sensitive certificate, key, or local database artifacts were identified.",
            "evidence":f"{len(high)} high-value artifact(s) identified.",
            "recommendation":"Review identified artifacts for sensitive data, private keys, credentials, or writable security-sensitive configuration."
        })
    return {"status":"WARN" if indicators else "PASS",
            "details":f"{len(rows)} configuration artifacts; {len(indicators)} security-setting review point(s)",
            "security_indicators":indicators,"findings":findings}
