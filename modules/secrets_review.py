from utils.assessment_layout import artifact_path
from pathlib import Path
import re
from collections import Counter, defaultdict
from utils.report_format import header, section, kv
from utils.text_utils import newline_offsets, line_number
from utils.privacy import sanitize_report_text
from modules.pe_analysis import _has_pe_header

TEXT_EXTS={".env",".config",".json",".xml",".ini",".yaml",".yml",".toml",".properties",".conf",".cfg",".txt",".ps1",".bat",".cmd",".vbs",".js",".cs",".vb"}
PATTERNS=[
("Generic password assignment",re.compile(r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["\']?([^"\'\s]{4,})')),
("Generic secret assignment",re.compile(r'(?i)\b(client_secret|api[_-]?key|secret)\b\s*[:=]\s*["\']?([^"\'\s]{6,})')),
("Bearer token",re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._~+/\-=]{12,}')),
("AWS access key",re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
("Private key marker",re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
("Connection string",re.compile(r'(?i)(Server|Data Source)\s*=.+?(Password|Pwd)\s*=',re.DOTALL)),
# Only the value shape is inspected; the matched value is never persisted.
("XML credential element",re.compile(
    r'(?is)<(?P<key>[A-Za-z_][\w.-]{0,80})\s*>\s*(?P<value>[^<\r\n]{4,4096}?)\s*</(?P=key)\s*>'
)),
("JSON credential property",re.compile(
    r'(?i)"(?P<key>[A-Za-z_][\w.-]{0,80}?(?:password|passwd|passphrase|secret|token|apikey|api_key|encryptionkey|masterkey|deploymentkey|privatekey|licenseblob)[\w.-]{0,30})"\s*:\s*"(?P<value>[^"\r\n]{4,4096})"'
)),
("Named credential assignment",re.compile(
    r'(?im)\b(?:[A-Za-z_][\w.-]{0,50})?(?:password|passwd|passphrase|secret|token|api[_-]?key|encryption[_-]?key|master[_-]?key|deployment[_-]?key)\s*[:=]\s*["\']?([^"\'\s<>]{4,})'
)),
]

CONFIDENCE={
    "Private key marker":"HIGH",
    "AWS access key":"HIGH",
    "Bearer token":"MEDIUM",
    "Connection string":"MEDIUM",
    "Generic password assignment":"LOW",
    "Generic secret assignment":"LOW",
    "XML credential element":"MEDIUM",
    "JSON credential property":"MEDIUM",
    "Named credential assignment":"LOW",
}

MAX_TEXT_BYTES = 10 * 1024 * 1024
MAX_PE_BYTES = 50 * 1024 * 1024
MAX_MATCHES = 1000
MAX_TEXT_MATCHES = 600
MAX_PE_MATCHES = 400
MAX_PE_MATCHES_PER_IMAGE = 24
MAX_PE_MATCHES_PER_IMAGE_TYPE = 8
_ASCII_STRING = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def _iter(roots):
    seen=set()
    for root in roots:
        p=Path(root); items=[p] if p.is_file() else (p.rglob("*") if p.is_dir() else [])
        for item in items:
            try: size=item.stat().st_size
            except Exception: continue
            if item.is_file() and item.suffix.lower() in TEXT_EXTS and size<=MAX_TEXT_BYTES:
                k=str(item.resolve())
                if k not in seen:
                    seen.add(k); yield item


def _inventory_paths(roots, file_inventory):
    """Return unique static files without doing a second tree walk when inventory exists."""
    if file_inventory is not None:
        paths = [Path(row["path"]) for row in file_inventory if row.get("path")]
    else:
        paths = []
        for root in roots or ():
            p=Path(root)
            if p.is_file():
                paths.append(p)
            elif p.is_dir():
                paths.extend(item for item in p.rglob("*") if item.is_file())
    out=[]; seen=set()
    for p in paths:
        key=str(p).casefold()
        if key not in seen:
            seen.add(key); out.append(p)
    return out


def _is_credential_field(name, value):
    """Filter XML leaf elements by field *name*, never reveal or report values."""
    key = re.sub(r"[^a-z0-9]", "", str(name).lower())
    if key in {"logpasswords", "logsecrets", "accesskeyid", "publickey", "keysize", "keylength"}:
        return False
    if str(value).strip().lower() in {"true", "false", "yes", "no", "none", "null", "enabled", "disabled"}:
        return False
    return any(token in key for token in (
        "password", "passwd", "passphrase", "secret", "token", "apikey",
        "accesskey", "privatekey", "masterkey", "encryptionkey", "deploymentkey",
        "licenseblob", "connectionstring", "credential",
    ))


def _text_matches(source_files, matches):
    for p in sorted(source_files, key=lambda x: str(x).casefold()):
        seen = set()
        try: text=p.read_text(encoding="utf-8",errors="ignore")
        except Exception: continue
        starts = newline_offsets(text)
        for label,pattern in PATTERNS:
            # XML/JSON matches are scoped to the corresponding file format.
            if label == "XML credential element" and p.suffix.lower() not in {".xml", ".config"}:
                continue
            if label == "JSON credential property" and p.suffix.lower() != ".json":
                continue
            for m in pattern.finditer(text):
                # Exclude recognized non-secret key identifiers and placeholders;
                # they can still be examined in configuration review.
                key = str(m.groupdict().get("key") or "").lower()
                if label == "XML credential element" and not _is_credential_field(key, m.group("value")):
                    continue
                if key.endswith(("accesskeyid", "publickey")):
                    continue
                match_key = (label, line_number(starts, m.start()), (m.groupdict().get("key") or "").casefold())
                if match_key in seen:
                    continue
                seen.add(match_key)
                matches.append({
                    "type":label,
                    "path":str(p),
                    "location_type":"Text line",
                    "location":str(line_number(starts,m.start())),
                    "line":line_number(starts,m.start()),
                    "encoding":"Text",
                    "redacted":"[REDACTED]",
                    "confidence":CONFIDENCE.get(label,"LOW"),
                })
                if len(matches)>=MAX_TEXT_MATCHES: return


def _pe_matches(paths, matches):
    scanned=0
    binary_matches = 0
    for p in paths:
        if binary_matches >= MAX_PE_MATCHES or len(matches) >= MAX_MATCHES: break
        file_count = 0
        file_types = Counter()
        try:
            size=p.stat().st_size
            if size <= 0 or size > MAX_PE_BYTES or not _has_pe_header(p):
                continue
            blob=p.read_bytes()
        except (OSError, ValueError):
            continue
        scanned += 1
        for encoding, string_re in (("ASCII", _ASCII_STRING), ("UTF-16LE", _UTF16LE_STRING)):
            for sm in string_re.finditer(blob):
                try:
                    raw=sm.group(0)
                    text=(raw.decode("ascii", errors="ignore") if encoding == "ASCII"
                          else raw.decode("utf-16le", errors="ignore"))
                except Exception:
                    continue
                # Binary strings are examined in memory only. The actual string and
                # matched value are deliberately never persisted to assessment output.
                for label, pattern in PATTERNS:
                    if pattern.search(text):
                        if file_types[label] >= MAX_PE_MATCHES_PER_IMAGE_TYPE:
                            continue
                        matches.append({
                            "type":label,
                            "path":str(p),
                            "location_type":"PE file offset",
                            "location":f"0x{sm.start():X}",
                            "line":None,
                            "encoding":encoding,
                            "redacted":"[REDACTED]",
                            "confidence":CONFIDENCE.get(label,"LOW"),
                        })
                        binary_matches += 1
                        file_count += 1
                        file_types[label] += 1
                        if (binary_matches >= MAX_PE_MATCHES or len(matches) >= MAX_MATCHES
                                or file_count >= MAX_PE_MATCHES_PER_IMAGE):
                            break
                        break
                if (binary_matches >= MAX_PE_MATCHES or len(matches) >= MAX_MATCHES
                        or file_count >= MAX_PE_MATCHES_PER_IMAGE):
                    break
            if (binary_matches >= MAX_PE_MATCHES or len(matches) >= MAX_MATCHES
                    or file_count >= MAX_PE_MATCHES_PER_IMAGE):
                break
    return scanned


def run_secrets_review(roots, assessment_dir, file_inventory=None, application_scope=None):
    matches=[]
    all_paths = _inventory_paths(roots, file_inventory)
    if file_inventory is not None:
        size_by_path = {str(row.get("path") or "").casefold(): int(row.get("size_bytes") or 0)
                        for row in file_inventory if row.get("path")}
        source_files = [p for p in all_paths
                        if p.suffix.lower() in TEXT_EXTS
                        and size_by_path.get(str(p).casefold(), MAX_TEXT_BYTES + 1) <= MAX_TEXT_BYTES]
    else:
        source_files = list(_iter(roots))

    _text_matches(source_files, matches)
    scope = application_scope or {}
    primary_roots = scope.get("roots") or []
    primary_stem = Path(primary_roots[0]).stem.casefold() if primary_roots else ""
    sidecars = {Path(item).stem.casefold() for item in scope.get("sidecars") or []}
    def priority(path):
        name = path.stem.casefold()
        framework = name.startswith(("system.", "microsoft.", "runtime.", "presentation")) or name in {"mscorlib", "netstandard", "accessibility"}
        first = name in sidecars or bool(primary_stem and (name == primary_stem or name.startswith(primary_stem + ".")))
        return (0 if first else 2 if framework else 1, str(path).casefold())
    pe_scanned = _pe_matches(sorted(all_paths, key=priority), matches) if len(matches) < MAX_MATCHES else 0

    width=112
    counts=Counter(m["type"] for m in matches)
    text_count=sum(1 for m in matches if m.get("location_type") == "Text line")
    binary_count=len(matches)-text_count
    lines=header(
        "Windows Client Assessment - Secrets / Sensitive String Review",
        [
            "Pattern-based triage for possible embedded credentials, tokens, private keys, and connection strings.",
            "Text-like files and printable strings in PE images are reviewed. Values are never persisted; every match is redacted.",
            "A match is a review point, not proof that a credential/secret is real, reusable, reachable, or security relevant.",
        ], width
    )
    lines += ["SUMMARY","-"*width,kv("Potential matches",len(matches)),
              kv("Text-file matches",text_count), kv("PE printable-string matches",binary_count),
              kv("PE images string-triaged",pe_scanned),
              kv("Text/PE budgets",f"{MAX_TEXT_MATCHES}/{MAX_PE_MATCHES}; max {MAX_PE_MATCHES_PER_IMAGE} per PE"),
              "Repetitive PE-string indicators are limited per image/type; counts are not distinct vulnerabilities."]
    for name,count in counts.most_common():
        # Count labels must not themselves resemble secret-name assignments
        # (a final privacy pass may otherwise redact the numerical count).
        lines.append(kv(name + " indicators", count))
    lines += section("Recommended Validation",width)
    lines += [
        "1. Start with HIGH-confidence private-key/AWS-key matches, then MEDIUM token/connection-string matches.",
        "2. For text matches, inspect only the referenced file and line locally; do not paste sensitive values into reports.",
        "3. For PE matches, independently inspect printable strings/decompiled code at the indicated file/offset using approved tooling.",
        "4. Determine whether the value is real, reusable, in scope, reachable by the intended attacker, and security relevant.",
        "5. Do not report placeholders, documentation examples, test values, dead code, or unusable fragments.",
        "6. XML and JSON credential-property matches identify the containing line, never the value.",
    ]

    by_type=defaultdict(list)
    for m in matches: by_type[m["type"]].append(m)
    match_numbers = {id(item): idx for idx, item in enumerate(matches, 1)}
    for label in [p[0] for p in PATTERNS]:
        items=by_type.get(label,[])
        if not items: continue
        lines += section(label,width,len(items))
        for item in items:
            sid=f"SECRET-{match_numbers[id(item)]:03d}"
            lines += [
                f"[{sid}] Confidence={item['confidence']}",
                kv("File",sanitize_report_text(item["path"]),18,"  "),
                kv("Line" if item["location_type"] == "Text line" else item["location_type"],item["location"],18,"  "),
                kv("String encoding",item.get("encoding") or "",18,"  "),
                kv("Match", "[REDACTED]",18,"  "),
                "",
            ]

    artifact_path(assessment_dir, "secrets_review.txt").write_text("\n".join(lines).rstrip()+"\n",encoding="utf-8")
    actionable = [m for m in matches if m.get("confidence") in {"HIGH", "MEDIUM"}]
    findings=[]
    if actionable:
        findings.append({
            "title":"Potential Embedded Secrets Require Validation","severity":"Informational",
            "description":"Static review identified values or printable PE strings that may represent sensitive data. Values are redacted and require manual validation.",
            "evidence":f"{len(actionable)} medium/high-confidence potential secret match(es) identified; values are redacted.",
            "recommendation":"Validate each match locally and report only confirmed reusable or otherwise security-relevant secrets."
        })
    return {
        "status":"WARN" if actionable else "PASS",
        "details":f"{len(matches)} potential match(es); {binary_count} from PE strings; {len(actionable)} medium/high confidence" if matches else f"No configured secret patterns matched; {pe_scanned} PE image(s) string-triaged",
        "findings":findings,
        "matches":matches,
        "pe_images_scanned":pe_scanned,
    }
