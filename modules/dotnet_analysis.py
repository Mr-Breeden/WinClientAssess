from __future__ import annotations
from utils.assessment_layout import artifact_path, generated_directory_path

from pathlib import Path
import re
import shutil
from utils.command_runner import run_command
from utils.text_utils import newline_offsets, line_number
from utils.privacy import sanitize_report_text

SOURCE_PATTERNS = {
    "Process execution": re.compile(r"\b(Process\.Start|ProcessStartInfo)\b", re.I),
    "Registry access": re.compile(r"\b(Microsoft\.Win32\.Registry|RegistryKey|Registry\.)\b", re.I),
    "Named pipe IPC": re.compile(r"\b(NamedPipeServerStream|NamedPipeClientStream)\b", re.I),
    "HTTP client": re.compile(r"\b(HttpClient|WebClient|HttpWebRequest)\b", re.I),
    "Native interop": re.compile(r"(DllImport|Marshal\.|NativeLibrary\.(?:Load|TryLoad)|LoadLibrary)", re.I),
    "Dynamic assembly loading": re.compile(r"(Assembly\.(?:Load|LoadFrom|LoadFile|LoadModule)|AssemblyLoadContext|AppDomain\.Load)", re.I),
    "Reflection / dynamic activation": re.compile(r"(Activator\.CreateInstance|MethodInfo\.Invoke|GetMethod\(|GetType\()", re.I),
    "Deserialization": re.compile(r"(BinaryFormatter|LosFormatter|NetDataContractSerializer|ObjectStateFormatter|JavaScriptSerializer)", re.I),
    "File / process boundary": re.compile(r"(File\.(?:WriteAllText|WriteAllBytes|Move|Copy)|Directory\.CreateDirectory|ProcessStartInfo)", re.I),
    "Certificate handling": re.compile(r"\b(X509Certificate|X509Store|SslStream)\b", re.I),
    "Credential/secret terms": re.compile(r"\b(password|client_secret|api[_-]?key|access[_-]?token|bearer)\b", re.I),
    "Connection strings": re.compile(r"\b(connectionString|Data Source=|Server=)\b", re.I),
    "Localhost endpoint": re.compile(r"https?://(?:localhost|127\.0\.0\.1|\[::1\])", re.I),
    "Updater logic": re.compile(r"\b(update|updater|upgrade|patch|maintenance)\b", re.I),
    # Extra cross-application review indicators. No indicator alone proves exploitability.
    "TLS validation bypass": re.compile(r"ServerCertificateValidationCallback|DangerousAcceptAnyServerCertificateValidator|SslPolicyErrors\.None|CertificateValidationCallback", re.I),
    "Dynamic plugin / assembly load": re.compile(r"Assembly\.(?:LoadFrom|LoadFile)|AssemblyLoadContext|LoadFromAssemblyPath|Directory\.GetFiles\([^;]*\.dll", re.I),
    "OS command execution": re.compile(r"Process\.Start|ProcessStartInfo|cmd\.exe|powershell\.exe|UseShellExecute\s*=\s*true", re.I),
    "SQL execution / query composition": re.compile(r"SqliteCommand|SqlCommand|ExecuteSqlRaw|ExecuteNonQuery|ExecuteReader|\bSELECT\b.+\bFROM\b", re.I),
    "Weak hash or password storage": re.compile(r"\b(?:MD5|SHA1|SHA256Managed|Rfc2898DeriveBytes)\b|PasswordHash|VerifyPassword", re.I),
    "Weak crypto / predictable keys": re.compile(r"\b(?:DES|TripleDES|RC2|RijndaelManaged|ECB|CipherMode\.ECB|Random\()\b|Encoding\.UTF8\.GetBytes", re.I),
    "Predictable randomness": re.compile(r"\bnew\s+Random\s*\(|Random\.Shared|Guid\.NewGuid\(", re.I),
    "Filesystem traversal boundary": re.compile(r"Path\.Combine|GetFullPath|Directory\.GetFiles|ExtractToDirectory|ZipArchive|File\.ReadAllText|File\.Open", re.I),
    "Client-side authorization / role gate": re.compile(r"\bIsAdmin\b|\bIsAdministrator\b|\bHasPermission\b|\bIsAuthorized\b|\bRole\s*==|\bAccessDenied\b", re.I),
    "Insecure serialization / parsing": re.compile(r"BinaryFormatter|TypeNameHandling|DeserializeObject|JsonConvert\.Deserialize|XmlDocument|XmlReaderSettings|XmlResolver", re.I),
    "Plaintext credential or logging sink": re.compile(r"WriteAllText|AppendAllText|LogInformation|LogDebug|Console\.WriteLine|Trace\.WriteLine", re.I),
    "Update channel / binary replacement": re.compile(r"DownloadFile|DownloadData|DownloadString|HttpClient\.Get|WebClient|File\.Replace|Process\.Start", re.I),
    "Registry and persistence write": re.compile(r"SetValue\(|CreateSubKey\(|Registry\.CurrentUser|Registry\.LocalMachine|TaskScheduler", re.I),
    "Native memory / unsafe code": re.compile(r"Marshal\.Copy|AllocHGlobal|FreeHGlobal|stackalloc|\bunsafe\b|Buffer\.MemoryCopy", re.I),
    "IPC trust boundary": re.compile(r"NamedPipeServerStream|NamedPipeClientStream|PipeSecurity|\bMemoryMappedFile\b|\bTcpListener\b", re.I),
}


def _looks_dotnet(path):
    try:
        data = path.read_bytes()[:65536]
        return b"BSJB" in data or b"mscoree.dll" in data.lower()
    except Exception:
        return False


SOURCE_TOTAL_LIMIT = 2000
SOURCE_FIRST_PARTY_LIMIT = 1600
SOURCE_DEPENDENCY_LIMIT = 400
SOURCE_CATEGORY_FIRST_PARTY_LIMIT = 95
SOURCE_CATEGORY_DEPENDENCY_LIMIT = 18


def _source_review(base: Path, assessment_dir: Path, application_scope=None):
    """Review application-owned assemblies before dependencies with independent quotas.

    Deduplicate identical category/line hits. Never persist matched source snippets:
    credentials and payloads in decompiled source must remain in working evidence.
    """
    from collections import Counter, defaultdict
    from utils.report_format import header, section, kv

    scope = application_scope or {}
    roots = scope.get("roots") or []
    stem = Path(roots[0]).stem.casefold() if roots else ""
    sidecars = {Path(v).stem.casefold() for v in scope.get("sidecars") or []
                if Path(v).suffix.casefold() == ".dll"}
    framework_prefixes = ("system.", "microsoft.", "windowsbase", "presentation",
                          "runtime.", "netstandard", "accessibility", "mscorlib")

    def is_first_party(directory):
        # Each decompilation directory has the format NN_AssemblyName; this
        # order is generated from selected primary EXE and first-party sidecars.
        name = re.sub(r"^\d{2}_", "", directory.name).casefold()
        return bool(name in sidecars or (stem and (name == stem or name.startswith(stem + "."))))

    dirs = sorted((d for d in base.iterdir() if d.is_dir()), key=lambda d: d.name.casefold()) if base.is_dir() else []
    first_party = [d for d in dirs if is_first_party(d)]
    dependency = [d for d in dirs if d not in first_party]
    # If no explicit first-party identity is available, use the earliest
    # non-framework decompilation folder as the primary candidate.
    if not first_party and dependency and not scope:
        first_party = [d for d in dependency if not re.sub(r"^\d{2}_", "", d.name).casefold().startswith(framework_prefixes)][:1]
        dependency = [d for d in dependency if d not in first_party]

    hits = []
    counters = {"first-party": Counter(), "dependency": Counter()}
    visited = set()
    def scan(directories, level, total_limit, category_limit):
        added = 0
        for directory in directories:
            for src in sorted(directory.rglob("*.cs"), key=lambda x: str(x).casefold()):
                try:
                    content = src.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                starts = newline_offsets(content)
                for label, pattern in SOURCE_PATTERNS.items():
                    if counters[level][label] >= category_limit:
                        continue
                    for match in pattern.finditer(content):
                        ln = line_number(starts, match.start())
                        key = (label, str(src).casefold(), ln)
                        if key in visited:
                            continue
                        visited.add(key)
                        hits.append((label, str(src), ln, "[INDICATOR REDACTED]"))
                        counters[level][label] += 1
                        added += 1
                        if added >= total_limit or counters[level][label] >= category_limit:
                            break
                    if added >= total_limit:
                        return

    scan(first_party, "first-party", SOURCE_FIRST_PARTY_LIMIT, SOURCE_CATEGORY_FIRST_PARTY_LIMIT)
    scan(dependency, "dependency", SOURCE_DEPENDENCY_LIMIT, SOURCE_CATEGORY_DEPENDENCY_LIMIT)
    width = 104
    counts = Counter(label for label, _, _, _ in hits)
    lines = header("Windows Client Assessment - .NET Source Review", [
        "Indexes categorized review indicators from ILSpyCmd decompilation, prioritizing first-party assemblies.",
        "Matches are code-navigation hints, not automatic vulnerabilities. Source text and potential values are never printed.",
    ], width)
    lines += ["SUMMARY", "-" * width,
              kv("Potential review points", len(hits)),
              kv("First-party review points", sum(counters["first-party"].values())),
              kv("Dependency review points", sum(counters["dependency"].values())),
              kv("First-party assembly directories", len(first_party)),
              kv("Dependency assembly directories", len(dependency)),
              kv("Limits", f"first-party {SOURCE_FIRST_PARTY_LIMIT}; dependency {SOURCE_DEPENDENCY_LIMIT}; per category {SOURCE_CATEGORY_FIRST_PARTY_LIMIT}/{SOURCE_CATEGORY_DEPENDENCY_LIMIT}"),
              "Category counts represent unique source lines within each category, not confirmed security issues."]
    for label in SOURCE_PATTERNS:
        if counts[label]:
            lines.append(kv(label, f"{counts[label]} (first-party {counters['first-party'][label]}, dependency {counters['dependency'][label]})"))
    lines += section("Recommended Review Workflow", width)
    lines += [
        "1. Review FIRST-PARTY source paths first. Trace untrusted input to sensitive operations and privilege boundaries.",
        "2. Open the referenced decompiled .cs file at the specified line; values and code snippets are intentionally omitted.",
        "3. Validate SQL parameterization, authorization enforced server-side, TLS policy, credential persistence, plugin origins, and process arguments.",
        "4. Correlate code with observed runtime evidence; indicator matches alone are not findings.",
    ]
    grouped = defaultdict(list)
    for index, hit in enumerate(hits, 1):
        grouped[hit[0]].append((index, hit))
    for label in SOURCE_PATTERNS:
        items = grouped.get(label, [])
        if not items:
            continue
        lines += section(label, width, len(items))
        for index, (_, path, number, _) in items:
            lines += [f"[SRC-{index:04d}]", kv("File", sanitize_report_text(path), 12, "  "),
                      kv("Line", number, 12, "  "),
                      kv("Scope", "FIRST-PARTY" if any(Path(path).is_relative_to(d) for d in first_party) else "DEPENDENCY", 12, "  "),
                      kv("Code indicator", label, 12, "  "), ""]
    artifact_path(assessment_dir, "dotnet_source_review.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return hits


def _prioritized_candidates(candidates, application_scope):
    """Decompile selected application's managed code before framework libraries.

    This is intentionally vendor-neutral: derive identity from selected EXE and
    .NET publishing sidecars, never from known application/training names.
    """
    scope = application_scope or {}
    roots = scope.get("roots") or []
    stem = Path(roots[0]).stem.casefold() if roots else ""
    sidecar_stems = {Path(item).stem.casefold() for item in (scope.get("sidecars") or []) if Path(item).suffix.lower() == ".dll"}
    if not stem and sidecar_stems:
        stem = sorted(sidecar_stems, key=len)[0]
    framework_prefixes = ("system.", "microsoft.", "windowsbase", "presentation", "runtime.", "netstandard", "accessibility")

    def key(path):
        name = path.stem.casefold()
        if name == stem or name in sidecar_stems:
            level = 0
        elif stem and name.startswith(stem + "."):
            level = 1
        elif name.startswith(framework_prefixes) or name in {"system", "mscorlib"}:
            level = 4
        else:
            level = 2
        return (level, name, str(path).casefold())

    return sorted(candidates, key=key)


def run_dotnet_analysis(roots, assessment_dir, tools, file_inventory=None, pe_result=None, application_scope=None):
    application_scope = application_scope or {}
    candidates = []
    seen = set()
    classified_paths = set()

    # Reuse PE analysis as the authoritative managed/native classification when
    # pefile successfully parsed a binary. Only parse headers again for files that
    # PE analysis could not classify.
    for row in (pe_result or {}).get("pe_rows", []) or []:
        path_text = str(row.get("path") or "")
        if not path_text:
            continue
        key = path_text.lower()
        if not row.get("error") and isinstance(row.get("dotnet"), bool):
            classified_paths.add(key)
        if row.get("error") or row.get("dotnet") is not True:
            continue
        path = Path(path_text)
        if path.suffix.lower() not in {".exe", ".dll"}:
            continue
        if key not in seen:
            seen.add(key)
            candidates.append(path)

    if file_inventory is not None:
        items = [
            Path(row["path"])
            for row in file_inventory
            if str(row.get("extension") or "").lower() in {".exe", ".dll"}
        ]
    else:
        items = []
        for root in roots:
            path = Path(root)
            items.extend([path] if path.is_file() else (path.rglob("*") if path.is_dir() else []))

    fallback_checks = 0
    for item in items:
        try:
            key = str(item.resolve()).lower()
            if key in seen or key in classified_paths or not item.is_file() or item.suffix.lower() not in {".exe", ".dll"}:
                continue
            fallback_checks += 1
            if _looks_dotnet(item):
                seen.add(key)
                candidates.append(item)
        except Exception:
            continue

    lines = [
        "WCA - .NET DETECTION / DECOMPILATION",
        "=" * 104,
        "",
        "Purpose:",
        "  Identifies managed .NET assemblies and optionally decompiles them with ILSpyCmd.",
        "  Use dotnet_source_review.txt for categorized security-review entry points.",
        "",
        f"Published .NET host detected: {bool(application_scope.get('dotnet_host'))}",
        f"Publishing sidecars: {len(application_scope.get('sidecars') or [])}",
        f".NET candidates: {len(candidates)}",
        f"Fallback header checks: {fallback_checks}",
        "",
        "CANDIDATES",
        "-" * 104,
    ] + [str(c) for c in candidates]
    ilspy = tools.get("ILSpyCmd", {}).get("path") or shutil.which("ilspycmd")
    base = generated_directory_path(assessment_dir, "decompiled_dotnet")
    decompiled = 0
    failed_decompilations = 0
    prioritized = _prioritized_candidates(candidates, application_scope)
    decompilation_limit_reached = len(candidates) > 50
    lines.extend(["", "DECOMPILATION PRIORITY (first-party/sidecars first)", "-" * 104])
    lines.extend(str(item) for item in prioritized[:50])

    if ilspy and candidates:
        base.mkdir(exist_ok=True)
        for index, candidate in enumerate(prioritized[:50], 1):
            target = base / f"{index:02d}_{candidate.stem}"
            target.mkdir(exist_ok=True)
            result = run_command([ilspy, "-p", "-o", str(target), str(candidate)], timeout=240)
            lines.extend(["", f"[ilspycmd] {candidate}", f"Return code: {result['returncode']}", result.get("stderr", "")])
            if result["returncode"] == 0:
                decompiled += 1
            else:
                failed_decompilations += 1
    elif candidates:
        lines.extend(["", "ilspycmd not detected; automatic .NET decompilation skipped."])
    if decompilation_limit_reached:
        lines.extend(["", f"Only the 50 highest-priority of {len(candidates)} assemblies were submitted to ILSpyCmd; remaining assemblies require manual review."])

    (artifact_path(assessment_dir, "dotnet_analysis.txt")).write_text("\n".join(lines), encoding="utf-8")
    source_hits = _source_review(base, assessment_dir, application_scope) if base.exists() else []
    missing_payload = bool(application_scope.get("dotnet_host")) and not candidates
    if missing_payload:
        lines.extend([
            "", "MANUAL REVIEW NEEDED",
            "-" * 104,
            "Native .NET application host identified, but no managed assembly was found.",
            "A self-contained single-file deployment may need dedicated bundle inspection;",
            "otherwise supply the actual publish folder with --application-dir.",
        ])
        (artifact_path(assessment_dir, "dotnet_analysis.txt")).write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    coverage_gap = missing_payload or decompilation_limit_reached or bool(candidates and (not ilspy or failed_decompilations))
    status = "WARN" if coverage_gap else "PASS"
    details = f"{len(candidates)} .NET candidate(s); {decompiled} decompiled; {len(source_hits)} source review point(s)"
    if missing_payload:
        details += "; published .NET host has no managed payload for ILSpy review"
    elif failed_decompilations:
        details += f"; {failed_decompilations} ILSpyCmd failure(s)"
    if decompilation_limit_reached:
        details += "; 50-assembly automatic decompilation limit reached"
    scope_roots = application_scope.get("roots") or []
    scope_stem = Path(scope_roots[0]).stem.casefold() if scope_roots else ""
    owned_stems = {Path(v).stem.casefold() for v in application_scope.get("sidecars") or []}
    def is_owned_source(hit):
        try:
            directory = Path(hit[1]).relative_to(base).parts[0]
        except (ValueError, IndexError):
            return False
        assembly = re.sub(r"^\d{2}_", "", directory).casefold()
        return bool(assembly in owned_stems or (scope_stem and (assembly == scope_stem or assembly.startswith(scope_stem + "."))))
    from collections import Counter
    source_count_by_label = Counter(item[0] for item in source_hits if is_owned_source(item))
    # Small set of independent review categories. No claim of exploitable behavior.
    groups = {
        "SQL / input handling": ("SQL execution / query composition", "Filesystem traversal boundary", "Insecure serialization / parsing"),
        "Authentication / authorization": ("Client-side authorization / role gate", "Weak hash or password storage", "Credential/secret terms"),
        "Cryptography / TLS": ("TLS validation bypass", "Weak crypto / predictable keys", "Predictable randomness"),
        "Process / plugin execution": ("OS command execution", "Dynamic assembly loading", "Dynamic plugin / assembly load"),
        "IPC / native trust boundaries": ("IPC trust boundary", "Named pipe IPC", "Native memory / unsafe code"),
        "Updater / replacement": ("Updater logic", "Update channel / binary replacement"),
    }
    source_findings = []
    for name, indicators in groups.items():
        observed = {indicator: source_count_by_label[indicator] for indicator in indicators if source_count_by_label[indicator]}
        if not observed:
            continue
        source_findings.append({
            "title": f"Managed Source {name} Requires Validation",
            "severity": "Informational",
            "description": "Decompiled .NET source contains potential security-sensitive operations. Pattern-based indicators do not prove a vulnerability.",
            "evidence": f"{sum(observed.values())} first-party categorized source-line indicator(s) in dotnet_source_review.txt; check actual paths and data flow.",
            "recommendation": "Prioritize first-party source, identify attacker-controlled inputs, verify the consumer identity and trust boundary, then validate behavior manually.",
        })
    return {
        "findings": source_findings,
        "status": status,
        "details": details,
        "coverage_gap": coverage_gap,
        "dotnet_candidates": [str(c) for c in candidates],
        "decompiled_dir": str(base) if base.exists() else None,
        "source_hits": len(source_hits),
        "decompilation_candidates": [str(c) for c in prioritized[:50]],
    }
