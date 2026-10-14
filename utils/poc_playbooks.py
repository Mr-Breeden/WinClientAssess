"""Windows thick-client attack-surface manual test plan.

The plan is vendor-neutral and intentionally broader than any single training
application.  Automatic observations are linked when available, but every
surface remains tester-controlled: WCA never compiles, deploys, triggers, or
executes a proof of concept automatically.
"""
from __future__ import annotations
from pathlib import Path
import os
import ntpath
import re
from utils.assessment_integrity import _atomic_text
from utils.assessment_layout import artifact_path
from utils.contextual_checks import checks
from utils.privacy import sanitize_report_text

# Each entry is:
#   name, direct source-module association, discovery/prerequisites,
#   tester-controlled validation procedure, objective evidence criterion,
#   historical cleanup note (not rendered in the current disposable-VM workflow).
#
# This is a broad Windows thick-client methodology, not an exhaustive taxonomy.
# New surfaces can be added without coupling WCA to a specific product or vendor.
CATEGORIES = (
 ('DLL search-order hijacking', 'DLL Search Review',
  'Verify the exact missing-DLL lookup, searched directory order, target architecture, and effective CreateFiles permission from the lower-trust tester context. Do not replace a legitimate DLL.',
  'Use scripts/poc/marker_dll.c only after confirming a writable earlier lookup directory. Build the marker for the exact target architecture and observed DLL name, place it in the verified test location, manually trigger the observed consumer, and capture Process Monitor Load Image plus the marker result.',
  'A controlled DLL loaded from the lower-trust location by the target process establishes code-loading control. Record process identity/integrity separately; a NAME NOT FOUND event alone does not.',
  'Restore the disposable VM snapshot.'),
 ('Executable/helper search-path hijacking', '',
  'Enumerate actual child launches, relative CreateProcess/ShellExecute targets, working directories, PATH search order, application-controlled helper names, and effective ACLs.',
  'Where a verified writable earlier search location exists, manually place a harmless architecture-matched marker EXE using the exact expected filename and trigger only the specific authorized launch. Record parent/child paths, user and integrity level.',
  'Only an observed launch of the controlled executable from the lower-trust location establishes executable search-path control.',
  'Restore the disposable VM snapshot.'),
 ('Reparse point / symlink / junction abuse', '',
  'Identify privileged or trusted file operations that consume a lower-trust writable path. Review the exact parent with Get-Acl/icacls and inspect existing reparse state with Get-Item -Force and fsutil reparsepoint query before creating a test object.',
  'On the disposable VM, choose a dedicated harmless source directory and harmless destination, create a test junction/symlink manually (for example cmd /c mklink /J <test-link> <harmless-target>), then trigger one authorized file/install/update operation while Process Monitor records the effective destination. Never redirect to a destructive system target.',
  'Confirmation requires a trusted/higher-privilege operation to cross the intended boundary and modify or consume the controlled destination. Merely accepting or enumerating a reparse point is insufficient.',
  'Restore the disposable VM snapshot.'),
 ('IFEO / SilentProcessExit injection', '',
  'For target executables, query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options and SilentProcessExit with reg.exe/PowerShell. Inspect Debugger, GlobalFlag and MonitorProcess values plus registry ACLs using Get-Acl on the exact Registry:: path.',
  'Only when a lower-trust principal can modify the relevant target key and an appropriate higher-trust launch exists, manually configure a dedicated marker executable in the isolated VM and trigger the exact target. Record the Debugger/monitor process path, user and integrity. WCA does not write the key.',
  'A writable or existing IFEO key alone is not a vulnerability. Demonstrate lower-trust control of the registration and actual execution across the relevant trust boundary.',
  'Restore the disposable VM snapshot.'),
 ('Service path and configuration abuse', 'Services Review',
  'Review service account, ImagePath/PathName quoting, executable arguments, service SDDL, executable/parent/configuration ACLs, and all concrete intermediate executable candidates produced by Windows unquoted-path parsing.',
  'From the intended standard-user context, verify actual create/modify capability at the exact candidate or configuration path. Where authorized, place only a harmless marker at a verified unoccupied candidate location and manually trigger the service lifecycle approved for the assessment.',
  'Impact requires the privileged service to consume or execute lower-trust controlled content. An unquoted path, writable sibling, or service existence alone is not confirmation.',
  'Restore the disposable VM snapshot.'),
 ('Scheduled task privilege boundary', 'Scheduled Tasks',
  'Review newly observed or target-associated tasks, principals/run level, action executable, arguments, working directory, triggers, task-file/registry ACLs, and writable dependencies.',
  'From a lower-trust context, test only whether an identified action/dependency can be changed and whether the trusted task subsequently consumes that controlled value during an authorized trigger.',
  'Confirmation requires lower-trust control that changes higher-trust scheduled execution or trusted state; a high-privilege task by itself is expected Windows behavior.',
  'Restore the disposable VM snapshot.'),
 ('Driver and kernel-facing attack surface', 'Driver Review',
  'Identify target-installed/associated drivers, signature state, file/parent ACLs, service configuration and exposed device interfaces. Use Device Manager, WinObj/Process Explorer, sc.exe and Get-CimInstance for independent confirmation.',
  'Do not fuzz a production driver. In the disposable VM, enumerate only authorized device handles/IOCTL surfaces and validate whether an unprivileged caller can reach sensitive operations. Escalate to focused driver analysis only when the engagement permits it.',
  'A reportable condition requires an unsafe reachable kernel trust boundary such as unauthorized privileged operation, memory corruption, or lower-trust modification of driver code/configuration.',
  'Restore the disposable VM snapshot.'),
 ('COM registration and activation hijacking', '',
  'Enumerate target-used CLSID/AppID/ProgID registrations across HKCU/HKLM and merged views. Query InprocServer32/LocalServer32 values with reg.exe/PowerShell, inspect effective ACLs, and correlate the class to an actual target activation.',
  'In the disposable VM, use a controlled per-user registration only for the exact class the target activates and point it to a harmless COM-compatible marker. Capture registry resolution, Load Image/process creation, consumer identity and integrity. Do not assume every HKCU CLSID is unsafe.',
  'Only actual activation of the controlled registration by a relevant higher-trust consumer establishes a COM hijack.',
  'Restore the disposable VM snapshot.'),
 ('Registry persistence and execution abuse', 'Persistence Review',
  'Review Run/RunOnce, protocol handlers, file associations, startup configuration, environment variables and other target-associated execution keys. Determine the consumer identity and exact effective registry/path permissions.',
  'Where a lower-trust principal can influence a trusted execution registration, manually substitute only a harmless marker in the disposable VM and invoke the specific authorized consumer/launch path.',
  'Confirmation requires lower-trust control to alter a trusted or privileged execution path; registry presence alone is informational.',
  'Restore the disposable VM snapshot.'),
 ('Process creation and command construction', 'Advanced .NET / Native Runtime Review',
  'Correlate target child processes, command lines, working directories and interpreters with application-controlled input. Pay special attention to cmd.exe, PowerShell, script hosts, rundll32, msiexec, service/task utilities and relative helper paths.',
  'Reproduce the exact feature while observing Process Monitor. Modify only controlled test input to determine whether executable selection or security-sensitive arguments can be changed. Avoid destructive commands; use marker-only behavior.',
  'Confirmation requires user-controlled data to alter security-sensitive execution or arguments across a meaningful trust/authorization boundary.',
  'Restore the disposable VM snapshot.'),
 ('Process injection and cross-process memory access', '',
  'Identify target PID, user/integrity level, process DACL, protected-process state and the requested access rights. Use Process Explorer/AccessChk/debugger tooling to determine whether a lower-trust principal can obtain memory/thread-manipulation rights.',
  'Against a dedicated disposable test instance, perform only an approved harmless instrumentation/injection attempt using debugger or assessment tooling. Record OpenProcess/handle rights, operation result, target token and any privilege/consent requirement. WCA never performs injection automatically.',
  'A process handle or tool error is not enough. Require unauthorized code execution or sensitive memory access across a relevant trust boundary.',
  'Restore the disposable VM snapshot.'),
 ('Named pipe and local IPC authorization', 'IPC / Named Pipe Review',
  'Record the exact pipe/IPC endpoint, owning process and token, SDDL/effective ACL, message framing and expected caller identity. Test from a separate standard-user session when appropriate.',
  'Use the bundled pipe connection probe only for connection-level validation, then manually send only a known harmless supported request if the application protocol is understood. Compare unauthorized and authorized behavior.',
  'Broad transport permission alone is not impact. Demonstrate an unauthorized sensitive operation, trusted-data modification, impersonation problem, or privileged boundary crossing.',
  'Restore the disposable VM snapshot.'),
 ('Localhost service / local API authorization', 'Network Surface Review',
  'Identify target loopback listeners, protocol, owning PID, authentication, origin/CSRF assumptions and security-sensitive methods. Confirm ownership with Get-NetTCPConnection/TCPView and protocol with Wireshark or an appropriate client.',
  'From a separate lower-trust local context, manually invoke only harmless methods. For HTTP/S/WebSocket endpoints, use curl/browser/Burp when proxying is supported and verify authentication/authorization and origin controls.',
  'Confirmation requires unauthorized access to a sensitive local operation or data. A loopback listener alone is not a vulnerability.',
  'Restore the disposable VM snapshot.'),
 ('Network transport and remote trust', 'Network Surface Review',
  'Map outbound/listening endpoints and identify the actual application protocol. Capture representative traffic with Wireshark and determine whether sensitive data is plaintext, remote identity is authenticated, redirects/proxies are trusted safely, and message integrity is enforced where required.',
  'For HTTP/S or WebSocket traffic, use an authorized interception proxy where the application supports it; for raw TCP/UDP use protocol-appropriate capture/proxy tooling. Compare baseline traffic with a harmless modified response/request. Absence of certificate pinning by itself is not a vulnerability.',
  'Report only demonstrable exposure such as sensitive plaintext, failure to authenticate the intended peer, or accepted attacker-modified trusted data under a realistic network position.',
  'Restore the disposable VM snapshot.'),
 ('Local storage, embedded secrets and information disclosure', 'Secrets Review',
  'Review secrets_review.txt, local_storage_review.txt, decompiled/static source, binary printable-string indicators, runtime_secrets_review.txt, logs/databases/configuration and registry state. Determine which principal can read the data without copying genuine secret values into WCA reports.',
  'Inspect only the indicated local line/string offset/schema/path. Validate whether the value is real, reusable and accessible outside the intended trust boundary. Where needed, use Sysinternals Strings or a debugger string-reference search against the exact PE while retaining only redacted evidence.',
  'Confirmation requires sensitive/reusable data reaching an unintended principal or insecure storage boundary; keyword matches, schema names and privileged diagnostic evidence alone are insufficient.',
  'Restore the disposable VM snapshot.'),
 ('Update mechanism integrity, staging and rollback', 'Updater Security Correlation',
  'Identify updater/launcher components, privilege context, staging paths, package/signature/hash verification, endpoints, proxy behavior and rollback/version policy.',
  'Exercise the legitimate check/update workflow while monitoring target-scoped runtime activity. Where authorized, use a benign modified test artifact or older approved package to verify rejection before privileged consumption. Never replace production update content.',
  'Confirmation requires lower-trust/network-controlled content to influence a trusted update action, bypass authenticity, exploit a staging/TOCTOU boundary, or force a disallowed downgrade.',
  'Restore the disposable VM snapshot.'),
 ('Digital signing and provenance', 'Digital Signature Review',
  'Confirm the selected package/binary source, expected publisher/signing policy, Authenticode status, signer chain, timestamp and hashes. Examine high-value embedded/installed executables separately.',
  'Run Get-AuthenticodeSignature and Get-FileHash on the exact file and compare with authorized release information. For portable targets, treat the primary executable and security-sensitive companion binaries independently.',
  'Unsigned/invalid is a factual observation; a reportable issue requires an applicable trust/provenance requirement or demonstrated unsafe acceptance path.',
  'Read-only verification.'),
 ('PE exploit mitigations and memory hardening', 'PE Security Review',
  'Independently inspect ASLR, DEP/NX, CFG header/load-config metadata, architecture and other compiler/linker protections on exact affected PE files.',
  'Use pefile, dumpbin, Detect It Easy or equivalent to capture mitigation state. Correlate missing hardening with a real memory-corruption surface rather than treating metadata alone as code execution.',
  'Missing mitigations are independently verifiable hardening observations; exploitability requires a separate reproducible corruption primitive.',
  'Read-only verification.'),
 ('Stack memory corruption', '',
  'Identify an input that reaches native stack-backed copying/parsing code. Establish a valid-input baseline under WinDbg, configure first-chance access-violation handling (for example sxe av), and record target architecture/mitigations.',
  'Increase a bounded test input gradually until the fault is reproducible. Capture !analyze -v, registers (r), stack/backtrace (kb) and the faulting instruction. When appropriate, use a cyclic non-secret pattern to determine whether control data/instruction-pointer state is influenced. Do not jump directly from a crash to shellcode.',
  'Confirmation requires reproducible input-driven memory corruption; stronger impact requires evidence of control-flow/control-data influence. A hang, timeout or unexplained crash is insufficient.',
  'Restore the disposable VM snapshot.'),
 ('Heap memory corruption', '',
  'Identify an input that reaches native heap allocation/copy/free behavior. Establish a normal baseline, then use WinDbg plus Application Verifier/PageHeap when appropriate. GFlags full PageHeap can be enabled manually for the target process in the disposable VM.',
  'Reproduce the malformed input with PageHeap/Application Verifier enabled, capture !analyze -v and relevant heap diagnostics (for example !heap -p -a <address>) and determine whether the failure is an out-of-bounds write/read, use-after-free, double-free or other input-controlled heap corruption.',
  'Confirmation requires a reproducible input-driven heap corruption condition. High memory usage, leaks, generic crashes or allocator diagnostics without attacker-controlled input are not sufficient.',
  'Restore the disposable VM snapshot.'),
 ('Cryptography and key management', '',
  'Review configuration, decompiled/static source, binary imports/strings and runtime behavior for hard-coded keys/IVs, obsolete algorithms/modes, predictable randomness, reversible password storage and home-grown cryptography.',
  'Use known non-sensitive test data to compare encryption outputs, key derivation and storage. Validate actual algorithm/mode/parameters with source/runtime evidence before reporting. Do not retain real plaintext secrets in WCA artifacts.',
  'Confirmation requires a concrete cryptographic weakness affecting confidentiality/integrity/authentication, not merely the presence of a cryptographic API or algorithm name.',
  'Restore the disposable VM snapshot.'),
 ('Installer and custom-action privilege boundary', 'MSI Analysis',
  'For installer-based targets, inspect custom actions, deferred/elevated actions, repair/rollback behavior, scripts/DLLs/executables, arguments, extraction paths and user-controllable properties. For non-MSI installers use equivalent package/runtime evidence.',
  'Trace each security-sensitive action to exact files/arguments and ACLs. In the disposable VM, vary only authorized low-risk properties/files to determine whether lower-trust input reaches elevated installer execution.',
  'Confirmation requires lower-trust control over elevated installer behavior or trusted state; the existence of a custom action alone is not a vulnerability.',
  'Restore the disposable VM snapshot.'),
 ('.NET / managed runtime dynamic behavior', '.NET Detection / Source Review',
  'Review managed source/runtime evidence for Process.Start/shell execution, reflection, Assembly.Load, dynamic code, P/Invoke/native interop, deserialization, IPC, update and credential handling entry points.',
  'Correlate decompiled source with observed target process/module/child-process activity. Use dotnet-trace/dotnet-dump/WinDbg/Frida only when necessary and authorized, collecting the minimum data needed to answer the security question.',
  'Confirmation requires an unsafe reachable managed-runtime behavior with attacker-controlled input or broken trust/authorization, not simply use of reflection/PInvoke/dynamic loading.',
  'Restore the disposable VM snapshot.'),
 ('Electron / WebView / embedded browser surface', 'Electron Security Review',
  'Identify Electron/WebView/embedded-browser components, versions and security settings. Review nodeIntegration/contextIsolation/sandbox/preload/IPC/navigation/origin behavior and locally exposed web content/APIs where applicable.',
  'Exercise only in-scope renderer/navigation/IPC paths using harmless test input. Validate whether untrusted content can reach privileged native/Node capabilities or trusted local APIs across the renderer/main-process boundary.',
  'Confirmation requires an exploitable trust-boundary failure such as privileged native capability from untrusted content; framework presence/version alone is insufficient.',
  'Restore the disposable VM snapshot.'),
 ('Authentication, authorization and client-side trust', '',
  'Identify local/remote authentication state, role/entitlement checks, feature gating and any security decision enforced only in the client. Compare behavior across intended low/high privilege or account roles.',
  'Using authorized test accounts/data, alter only client-controllable requests/state and verify whether the authoritative component independently enforces identity, object ownership and privileged operations. UI hiding or disabled controls are not authorization.',
  'Confirmation requires unauthorized access/action or a security decision that can be bypassed by manipulating the client.',
  'Restore the disposable VM snapshot.'),
 ('Input handling and local data-access flaws', '',
  'Identify user-controlled input reaching local SQL/SQLite queries, filesystem paths, command/config parsers, serialization/deserialization or template/interpreter boundaries. Prefer source/decompiled correlation before active testing.',
  'Use bounded non-destructive test payloads against the exact local feature to validate injection, path traversal, unsafe deserialization or parser confusion. Preserve database/filesystem state through the disposable VM workflow and avoid destructive payloads.',
  'Confirmation requires reproducible unauthorized data access, code/command execution, path escape or equivalent security impact; parser errors alone are not sufficient.',
  'Restore the disposable VM snapshot.'),
)


def category_matches(category: str, module: str, items: list[dict]) -> list[dict]:
    # An indicator from the new correlation module is keyed by its actual
    # category, never counted as unrelated attack-surface observations.
    found = [item for item in items if (module and item.get('source_module') == module)
             or (item.get('source_module') == 'Attack Surface Correlations'
                 and ('Category: ' + category).lower() in item.get('evidence', '').lower())]
    if category == 'Local storage, embedded secrets and information disclosure':
        found.extend(item for item in items if item.get('source_module') == 'Local Storage Review')
        dedup = {item.get('id') or id(item): item for item in found}
        found = list(dedup.values())
    return found




PROJECT_ROOT = Path(__file__).resolve().parents[1]


def poc_resource_display(relative: str, *, console_paths: bool = False) -> str:
    """Resolve a bundled PoC resource against the WCA tool tree.

    Live console guidance shows the exact source-tree path. Persisted guidance
    normalizes the current tester profile while still making the tool directory
    explicit. On non-Windows portable test hosts, avoid leaking the build path.
    """
    relative = str(relative or "").strip().replace("\\", "/")
    if not relative:
        return ""
    resolved = (PROJECT_ROOT / Path(relative)).resolve()
    if console_paths:
        return str(resolved)
    if os.name == "nt":
        return sanitize_report_text(str(resolved))
    return "WCA tool directory\\" + relative.replace("/", "\\")


RESOURCE_BY_CATEGORY = {
    'DLL search-order hijacking': 'scripts/poc/marker_dll.c',
    'Executable/helper search-path hijacking': 'scripts/poc/marker_exe.c',
    'Service path and configuration abuse': 'scripts/poc/marker_exe.c',
    'IFEO / SilentProcessExit injection': 'scripts/poc/marker_exe.c',
    'Named pipe and local IPC authorization': 'scripts/poc/pipe_connect_probe.ps1',
    'Reparse point / symlink / junction abuse': 'scripts/poc/reparse_inventory.ps1',
    'COM registration and activation hijacking': 'scripts/poc/com_registration_probe.ps1',
}


def _report_text(root: Path | None, name: str) -> str:
    if root is None:
        return ''
    path = artifact_path(root, name)
    if not path.is_file() or path.is_symlink():
        return ''
    return path.read_text(encoding='utf-8', errors='replace')[:1_000_000]


def _field(text: str, label: str) -> str:
    match = re.search(r'(?im)^\s*' + re.escape(label) + r'\s*:\s*(.+?)\s*$', str(text or ''))
    return match.group(1).strip() if match else ''


def _candidate_process_name(item: dict) -> str:
    evidence = str(item.get('evidence') or '')
    for label in ('Process', 'Executable'):
        value = _field(evidence, label)
        if value:
            return ntpath.basename(value.strip('"\''))
    title = str(item.get('title') or '')
    if '->' in title:
        return ntpath.basename(title.split('->', 1)[0].strip())
    component = str(item.get('component') or '')
    if component.lower().endswith(('.exe', '.dll')):
        return ntpath.basename(component)
    return ''


def _architecture_for_name(root: Path | None, name: str) -> str:
    """Read the existing PE report; never execute the target to infer architecture."""
    if not name:
        return ''
    report = _report_text(root, 'binary_security_review.txt')
    wanted = name.casefold()
    blocks = re.split(r'(?m)^\[PE-\d+\]\s+', report)[1:]
    for block in blocks:
        first = block.splitlines()[0].strip() if block.splitlines() else ''
        if ntpath.basename(first).casefold() != wanted:
            continue
        arch = _field(block, 'Architecture')
        if arch:
            return arch
    return ''


def _resource_output_name(item: dict, relative: str) -> str:
    evidence = str(item.get('evidence') or '')
    if relative.endswith('marker_dll.c'):
        missing = _field(evidence, 'Missing DLL')
        return ntpath.basename(missing) if missing else 'marker.dll'
    if relative.endswith('marker_exe.c'):
        path = _field(evidence, 'Path')
        if path and ntpath.splitext(path)[1].lower() == '.exe':
            return ntpath.basename(path)
        return 'marker.exe'
    return ''


def _powershell_path_expr(display: str) -> str:
    """Return an executable PowerShell path expression for privacy-safe display paths."""
    value = str(display or '')
    prefix = '%USERPROFILE%\\'
    if value.upper().startswith(prefix):
        suffix = value[len(prefix):].replace("'", "''")
        return f"(Join-Path $env:USERPROFILE '{suffix}')"
    if value.startswith('WCA tool directory\\'):
        expected = ntpath.basename(value).replace("'", "''")
        return f"(Read-Host 'Full path to bundled WCA resource {expected}')"
    return "'" + value.replace("'", "''") + "'"


def _powershell_resource_invocation(item: dict, display: str, relative: str) -> str:
    evidence = str(item.get('evidence') or '')
    title = str(item.get('title') or '')
    quoted = _powershell_path_expr(display)
    if relative.endswith('pipe_connect_probe.ps1'):
        match = re.search(r'\\\\\.\\pipe\\([A-Za-z0-9_.-]{1,128})', title + '\n' + evidence, re.I)
        if match:
            return f"& {quoted} -PipeName '{match.group(1)}'"
        return f"& {quoted} -PipeName (Read-Host 'Observed pipe name without \\\\.\\pipe\\ prefix')"
    if relative.endswith('reparse_inventory.ps1'):
        path = _field(evidence, 'Path')
        arg = "'" + path.replace("'", "''") + "'" if path else "(Read-Host 'Observed reparse path')"
        return f"& {quoted} -LiteralPath {arg}"
    if relative.endswith('com_registration_probe.ps1'):
        clsid = _field(evidence, 'CLSID') or _field(evidence, 'Clsid')
        arg = "'" + clsid.replace("'", "''") + "'" if clsid else "(Read-Host 'Observed CLSID')"
        return f"& {quoted} -Clsid {arg}"
    return f"& {quoted}"


def poc_resource_details(item: dict, root: Path | None = None, *, console_paths: bool = False) -> dict:
    """Return candidate-specific build or invocation guidance for a bundled helper.

    WCA only renders instructions. It never compiles, copies, registers, launches,
    restarts, or triggers a proof resource automatically.
    """
    category = _candidate_category(item)
    relative = RESOURCE_BY_CATEGORY.get(category[0], '') if category else ''
    if not relative:
        return {
            'resource': '', 'relative': '', 'requires_compilation': 'NO',
            'target_architecture': 'Not applicable', 'expected_output': '',
            'build_or_invocation': (), 'verification': (),
        }
    display = poc_resource_display(relative, console_paths=console_paths)
    suffix = Path(relative).suffix.lower()
    process_name = _candidate_process_name(item)
    arch = _architecture_for_name(root, process_name)
    architecture = arch or ('Determine from the affected PE before compiling' if suffix == '.c' else 'Not applicable')
    if suffix == '.ps1':
        return {
            'resource': display,
            'relative': relative,
            'requires_compilation': 'NO',
            'target_architecture': 'Not applicable',
            'expected_output': 'PowerShell console output / observed target behavior',
            'build_or_invocation': (_powershell_resource_invocation(item, display, relative),),
            'verification': ('Get-FileHash -LiteralPath ' + _powershell_path_expr(display) + ' -Algorithm SHA256',),
        }

    output = _resource_output_name(item, relative)
    source_name = Path(relative).name
    output_q = output.replace('"', '')
    if relative.endswith('marker_dll.c'):
        cl = f'cl /nologo /LD /Fe:{output_q} {source_name} advapi32.lib'
        mingw64 = f'x86_64-w64-mingw32-gcc -shared -O2 -o {output_q} {source_name} -ladvapi32'
        mingw32 = f'i686-w64-mingw32-gcc -shared -O2 -o {output_q} {source_name} -ladvapi32'
    else:
        cl = f'cl /nologo /Fe:{output_q} {source_name} advapi32.lib'
        mingw64 = f'x86_64-w64-mingw32-gcc -O2 -o {output_q} {source_name} -ladvapi32'
        mingw32 = f'i686-w64-mingw32-gcc -O2 -o {output_q} {source_name} -ladvapi32'
    location_note = f"Change to the directory containing {source_name} (the PoC resource directory shown above) before running a build command."
    if arch == 'x86':
        commands = (location_note,
                    'Visual Studio x86 Developer Command Prompt: ' + cl,
                    'MinGW-w64 x86: ' + mingw32)
    elif arch in ('x64', 'ARM64'):
        # ARM64 marker compilation is not bundled; do not silently claim x64 is compatible.
        if arch == 'ARM64':
            commands = (location_note,
                        'Target is ARM64. Use an ARM64 Visual Studio Developer Command Prompt and adapt the documented cl recipe; bundled MinGW examples do not claim ARM64 support.')
        else:
            commands = (location_note,
                        'Visual Studio x64 Developer Command Prompt: ' + cl,
                        'MinGW-w64 x64: ' + mingw64)
    else:
        commands = (location_note,
                    'Determine target architecture first. Then use the matching Visual Studio Developer Command Prompt:', cl,
                    'MinGW-w64 x64: ' + mingw64,
                    'MinGW-w64 x86: ' + mingw32)
    verify_target = output_q
    verification = (
        f"Get-FileHash -LiteralPath '.\\{verify_target}' -Algorithm SHA256",
        "python -c \"import pefile,sys; p=pefile.PE(sys.argv[1]); print({0x14c:'x86',0x8664:'x64',0xAA64:'ARM64'}.get(p.FILE_HEADER.Machine,hex(p.FILE_HEADER.Machine)))\" '.\\" + verify_target + "'",
    )
    return {
        'resource': display,
        'relative': relative,
        'requires_compilation': 'YES',
        'target_architecture': architecture,
        'expected_output': output,
        'build_or_invocation': commands,
        'verification': verification,
    }

def _candidate_category(item: dict):
    source = item.get('source_module', '')
    from utils.contextual_checks import _field
    explicit = _field(str(item.get('evidence') or ''), 'Category')
    if source in {'Local Storage Review', 'Secrets Review'}:
        return next((entry for entry in CATEGORIES if entry[0] == 'Local storage, embedded secrets and information disclosure'), None)
    return next((entry for entry in CATEGORIES if
                 (source == 'Attack Surface Correlations' and entry[0].lower() == explicit.lower()) or
                 (source != 'Attack Surface Correlations' and entry[1] and entry[1] == source)), None)


def candidate_validation(item: dict, root: Path | None = None, *, console_paths: bool = False) -> dict:
    """Return tester-controlled validation details for one exact review candidate."""
    source = item.get('source_module', '')
    category = _candidate_category(item)
    resource_details = poc_resource_details(item, root, console_paths=console_paths)
    if source == 'Permissions Review':
        return {
            'category': 'Permissions / trust-boundary correlation',
            'prerequisites': 'Confirm effective create/modify rights from the intended lower-trust tester context and identify the actual executable, DLL, service, or configuration consumer.',
            'poc_resource': '',
            'poc_resource_relative': '',
            'tester_execution': 'Use the associated component-specific playbook only after the consumer and security boundary are established. The tester manually runs any marker/helper; Windows Client Assessment never executes it.',
            'expected_evidence': 'A controlled marker or other objective effect is consumed by the identified higher-trust component under the expected execution identity. An ACL alone is not proof of impact.',
            'requires_compilation': 'NO', 'target_architecture': 'Not applicable',
            'expected_output': '', 'build_or_invocation': (), 'verification': (),
        }
    if category:
        return {
            'category': category[0],
            'prerequisites': category[2],
            'poc_resource': resource_details['resource'],
            'poc_resource_relative': resource_details['relative'],
            'tester_execution': category[3],
            'expected_evidence': category[4],
            'requires_compilation': resource_details['requires_compilation'],
            'target_architecture': resource_details['target_architecture'],
            'expected_output': resource_details['expected_output'],
            'build_or_invocation': resource_details['build_or_invocation'],
            'verification': resource_details['verification'],
        }
    return {
        'category': '',
        'prerequisites': 'Review the condition-specific Starting Checks and linked evidence. Establish the exact affected object, execution context, effective access, and trust boundary before attempting a proof.',
        'poc_resource': '',
        'poc_resource_relative': '',
        'tester_execution': 'Choose and manually execute a non-destructive test appropriate to the observed component. Windows Client Assessment does not run proof actions automatically.',
        'expected_evidence': 'Record objective observed behavior that demonstrates the security impact or establishes that the condition is not applicable. Missing telemetry alone is inconclusive.',
        'requires_compilation': 'NO', 'target_architecture': 'Not applicable',
        'expected_output': '', 'build_or_invocation': (), 'verification': (),
    }


def candidate_poc(item: dict, root: Path | None = None) -> tuple[str, ...]:
    """Backward-compatible compact proof plan; routine cleanup is intentionally omitted."""
    plan = candidate_validation(item, root)
    steps = [plan['prerequisites']]
    if plan.get('poc_resource'):
        steps.append('Bundled tester resource: ' + plan['poc_resource'])
    steps.extend((plan['tester_execution'], 'Evidence criterion: ' + plan['expected_evidence']))
    return tuple(steps)


def render_plan(root: Path, state: dict) -> None:
    items = list(state.get('items', {}).values())
    collection = {}
    correlation = artifact_path(root, 'attack_surface_correlations.txt')
    if correlation.is_file() and not correlation.is_symlink():
        import re
        observed = correlation.read_text(encoding='utf-8', errors='replace')[:40_000]
        collection = {m.group(1).strip(): m.group(2) for m in re.finditer(
            r'(?m)^([^\n:]{4,55}?)\s+: (AUTOMATIC INDICATOR|NOT OBSERVED|COLLECTION UNAVAILABLE)\s*$', observed)}
    lines = ['WCA - WINDOWS THICK CLIENT ATTACK SURFACE TEST PLAN', '=' * 104, '',
             'This vendor-neutral methodology covers a broad set of Windows thick-client attack surfaces and is not tied to any single application, framework, or training fixture.',
             'The list is intentionally extensible rather than a claim that every possible application-specific weakness fits a fixed taxonomy.',
             'AUTOMATIC INDICATOR is a related observation, NOT a confirmed vulnerability or proof of impact.',
             'NOT OBSERVED means no indicator in scoped evidence, NOT that the attack surface was exhaustively tested.',
             'COLLECTION UNAVAILABLE means required telemetry was missing or out of scope.',
             'GUIDED ONLY means WCA provides tester methodology but has not established automatic detection or completed testing for that surface.',
             'All proof actions are tester-controlled and manually executed. Windows Client Assessment never runs a PoC automatically.',
             'Routine cleanup/restore instructions are omitted because the supported invasive-testing workflow uses a disposable VM restored from a known-good snapshot between tests.', '']
    for index, (name, module, prerequisite, poc, success, cleanup) in enumerate(CATEGORIES, 1):
        matches = category_matches(name, module, items)
        source_coverage = collection.get(name, '')
        if matches:
            status = 'AUTOMATIC INDICATOR - MANUAL VALIDATION REQUIRED'
        elif source_coverage == 'NOT OBSERVED':
            status = 'NOT OBSERVED IN COLLECTED EVIDENCE - MANUAL VALIDATION REMAINS AVAILABLE'
        elif source_coverage == 'COLLECTION UNAVAILABLE':
            status = 'COLLECTION UNAVAILABLE - GUIDED TEST AVAILABLE'
        else:
            status = 'GUIDED ONLY - NOT AUTOMATICALLY DETECTED'
        lines.extend([f'{index:02d}. {name.upper()}', '-' * 104, 'Coverage: ' + status,
                      'Linked review candidates: ' + (', '.join(v['id'] for v in matches) if matches else '(none)'),
                      '', 'PRECONDITIONS / DISCOVERY', prerequisite, ''])
        if matches:
            for item in matches:
                lines.extend(['Candidate: ' + item['id'] + ' | ' + item['title'], 'Assessment-specific starting checks:'])
                lines.extend('  ' + cmd for cmd in checks(item, root)[:8])
                lines.append('')
        resource = RESOURCE_BY_CATEGORY.get(name)
        if resource:
            display_resource = poc_resource_display(resource, console_paths=False)
            lines += ['BUNDLED TEST RESOURCE', display_resource,
                      'Location: bundled with the WCA tool/source directory, not the assessment output folder.']
            if matches:
                detail = candidate_validation(matches[0], root)
                lines += [f"Requires compilation: {detail['requires_compilation']}",
                          f"Target architecture: {detail['target_architecture']}"]
                if detail.get('expected_output'):
                    lines += [f"Expected output: {detail['expected_output']}"]
                if detail.get('build_or_invocation'):
                    lines += ['Build / invocation:'] + ['  ' + x for x in detail['build_or_invocation']]
                if detail.get('verification'):
                    lines += ['Verification:'] + ['  ' + x for x in detail['verification']]
            else:
                lines += ['Candidate-specific architecture/build details are emitted when an applicable review candidate exists.',
                          'See scripts/poc/README.md for generic build recipes.']
            lines.append('')
        lines.extend(['TESTER-CONTROLLED MANUAL VALIDATION', poc, '',
                      'EXPECTED MARKER / WHAT CONFIRMS THE ISSUE', success, '',
                      'NEGATIVE RESULT / STOP CONDITIONS',
                      'If the target path is not writable by the intended lower-trust identity, a legitimate file already exists, '
                      'the application/service action is not authorized, or the expected event cannot be reproduced, stop. '
                      'An unsuccessful marker or missing telemetry is inconclusive, not proof of safety.', '',
                      'Do not mark this category complete based only on a reviewer disposition.', ''])
    _atomic_text(artifact_path(root, 'attack_surface_test_plan.txt'), '\n'.join(lines).rstrip() + '\n')
