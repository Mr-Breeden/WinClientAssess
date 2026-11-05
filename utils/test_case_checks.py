"""Explicit, read-only, case-aware validation for the local WCA Testing Queue.

The GUI never accepts commands or paths from the browser for execution. Every
selected check is reconstructed from integrity-verified assessment reports.
Check results are ephemeral: neither original reports nor review decisions are
changed. Execution does not substitute for standard-user or app-layer testing.
"""
from __future__ import annotations

import base64
import ntpath
import os
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from utils import tool_detection
from utils.powershell import _powershell_environment

from utils.assessment_integrity import verify_assessment
from utils.manual_test_workflow import read_manual_detail
from utils.privacy import sanitize_report_text

MAX_REPORT_BYTES = 12_000_000  # Bounded verified-report parsing; never read unrelated host trees.
MAX_CHECKS = 22
MAX_OUTPUT = 18_000
MAX_SECONDS = 18

# Only explicitly approved report inputs. A report that is not available never
# causes fallback to arbitrary paths, other assessments, or a whole-drive scan.
ACL_CASE_REPORTS = {
    'TC-LS-001': ('local_storage_review.txt',),
    'TC-FS-001': ('filesystem_changes.txt', 'installed_directories.txt', 'installed_files.txt'),
    'TC-PB-001': ('privilege_boundary_review.txt',),
    'TC-DL-001': ('dll_search_review.txt',),
    'TC-AR-003': ('runtime_module_boundary.txt',),
    'TC-UP-003': ('updater_staging_review.txt',),
}


def _verified(root: Path, case_id: str) -> dict:
    root = Path(root)
    if verify_assessment(root).get('status') != 'PASS':
        raise ValueError('Assessment integrity must PASS for independent checks.')
    # Confirms applicability, completed state and identifier; no unsupported case.
    return read_manual_detail(root, case_id)


def _report(root: Path, name: str) -> str:
    if not re.fullmatch(r'[a-z][a-z0-9_]*\.txt', name):
        return ''
    parent = root / 'reports'
    f = parent / name
    if parent.is_symlink() or f.is_symlink() or not f.is_file() or f.stat().st_size > MAX_REPORT_BYTES:
        return ''
    return f.read_text(encoding='utf-8', errors='replace')


def _local_path(value: str) -> str | None:
    value = str(value or '').strip().strip('"')
    if value.casefold().startswith('%userprofile%\\'):
        profile = os.environ.get('USERPROFILE', '')
        if not re.match(r'^[A-Za-z]:\\', profile):
            return None
        value = profile + value[len('%USERPROFILE%'):]
    if (len(value) > 900 or not re.match(r'^[A-Za-z]:\\', value)
            or any(x in value for x in ('\n', '\r', '\x00', '"', ';', '|', '<', '>', '*', '?', '%', '!', '^'))
            or '..' in value.replace('/', '\\').split('\\')):
        return None
    return value


def _ps(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _add(out: list, *, kind: str, target: str, title: str, detail: str, source: str, shell='PowerShell'):
    if any(x['kind'] == kind and x['target'].casefold() == target.casefold() for x in out):
        return
    if len(out) >= MAX_CHECKS:
        return
    out.append({'id': f'CHECK-{len(out)+1:03d}', 'kind': kind,
                'target': target, 'title': sanitize_report_text(title)[:150],
                'detail': detail, 'source': source, 'shell': shell})


# Parse only explicitly recorded, case-specific targets. Do not harvest generic
# filesystem ACL candidates from unrelated evidence surfaces.
INDEXED_PATH = re.compile(r'(?m)^\[\d{1,6}\]\s+((?:[A-Za-z]:\\|%USERPROFILE%\\)[^\r\n|]+)')

def _case_paths(case_id: str, name: str, body: str) -> list[str]:
    if case_id == 'TC-LS-001':
        return re.findall(r'(?m)^\[STORE-\d+\]\s+(.+?)\s*$', body)[:MAX_CHECKS]
    if case_id == 'TC-FS-001':
        # Differential files: only the added entries, never unrelated Windows
        # changed-metadata rows. The two authoritative inventories supplement it.
        if name == 'filesystem_changes.txt':
            if 'ADDED FILES (' not in body: return []
            body = body.split('ADDED FILES (', 1)[1].split('REMOVED (', 1)[0]
        return [m.group(1).strip() for m in INDEXED_PATH.finditer(body)][:MAX_CHECKS]
    if case_id == 'TC-PB-001':
        # A privileged trust-boundary observation has a POI-specific Path.
        result = []
        for block in re.split(r'(?m)^\[POI-PB-\d+\]', body)[1:]:
            result += re.findall(r'(?m)^Path:\s*(.+?)\s*$', block)[:1]
        return result[:MAX_CHECKS]
    if case_id == 'TC-DL-001':
        # Prefer the report's actual POIs and explicitly recorded likely-writable
        # directories, not every benign missing-DLL lookup in Program Files.
        priority = []
        for block in re.split(r'(?m)^\[POI-DL-\d+\]', body)[1:]:
            priority += re.findall(r'(?mi)^\s*Search Directory\s*:\s*(.+?)\s*$', block)[:1]
        listed = []
        for match in re.finditer(r'(?mi)^\s*Directory:\s*(.+?)\s*\n\s*Broad-write ACEs:\s*(\d+)\s*\|\s*Likely user-writable:\s*(True|False)', body):
            directory, broad, writable = match.groups()
            if int(broad)>0 or writable.lower()=='true':
                listed.append(directory)
        candidates = priority + listed
        if not candidates and 'COMPLETE MISSING DLL LOOKUP LIST' not in body:
            # Legacy/partial reports without ACL metadata: prioritize observed
            # application directories outside the normal OS/install locations.
            legacy = re.findall(r'(?mi)^\s*(?:Search Directory|Directory):\s*(.+?)\s*$', body)
            candidates = [p for p in legacy if not re.match(
                r'(?i)^[A-Z]:\\(?:Windows|Program Files(?: \(x86\))?)(?:\\|$)', p.strip())]
        unique=[]
        for value in candidates:
            if not re.match(r'(?i)^[A-Z]:\\Windows(?:\\|$)', value.strip()) and value.casefold() not in [p.casefold() for p in unique]:
                unique.append(value)
        return unique[:MAX_CHECKS * 4]
    if case_id == 'TC-AR-003':
        # Do not turn OS DLL inventory into a list of application write checks.
        # Only privileged, non-Windows module paths are credible initial targets.
        out = []
        for match in re.finditer(r'(?mi)^((?:[A-Za-z]:\\|%USERPROFILE%\\)[^\r\n|]+)\s*\|\s*([^|\r\n]+)\|\s*Privileged=YES', body):
            path, scope = match.groups()
            if 'Windows/System' not in scope and ntpath.splitext(path.strip())[1].lower() in ('.dll','.ocx','.node','.pyd'):
                out.append(path.strip())
        for block in re.split(r'(?m)^\[POI-AR-\d+\]', body)[1:]:
            out += re.findall(r'(?mi)^(?:Module Path|Path)\s*:\s*(.+?)\s*$', block)[:1]
        return out[:MAX_CHECKS]
    if case_id == 'TC-UP-003':
        # No generic permissions fallback: a staging item must be observed.
        out = []
        for block in re.split(r'(?m)^\[(?:POI-UP|UPD-STAGE|UPD-ACL|STAGE|UPDATER)-\d+\]', body)[1:]:
            out += re.findall(r'(?mi)^(?:Path|Staging Path|Package Path|Executable|Configuration)\s*:\s*(.+?)\s*$', block)[:2]
        return out[:MAX_CHECKS]
    return []

def _case_target_notice(root: Path, case_id: str) -> str:
    reports = ACL_CASE_REPORTS.get(case_id, ())
    if not reports: return ''
    unavailable, oversized = [], []
    for name in reports:
        path = root / 'reports' / name
        if not path.is_file() or path.is_symlink(): unavailable.append(name)
        elif path.stat().st_size > MAX_REPORT_BYTES: oversized.append(name)
    if oversized:
        return 'Verified report exceeds the bounded target-enumeration limit: ' + ', '.join(oversized) + '. No inference about ACL safety was made.'
    if len(unavailable) == len(reports):
        return 'Required recorded evidence unavailable: ' + ', '.join(unavailable) + '. This does not indicate a successful security check.'
    return 'No safely resolved, case-specific live targets were extracted. Read the linked evidence and perform the remaining manual procedures.'


def _raw_checks(root: Path, case: dict) -> list[dict]:
    case_id = case['id']
    out = []
    # Existing reports are linked within How to Perform or Additional References. They are
    # not executable tests and must never appear as Run Check actions.
    for name in ACL_CASE_REPORTS.get(case_id, ()):
        body = _report(root, name)
        candidates = _case_paths(case_id, name, body)
        for candidate in candidates:
            # Keep report metadata separate from the path, including MSI size
            # notes. An invalid path is not a runnable validation check.
            candidate = re.split(r'\s*;\s*(?:candidates?|reason|status|count|notes?)\s*=', candidate, maxsplit=1, flags=re.I)[0].strip()
            candidate = candidate.split(' | ', 1)[0].strip()
            path = _local_path(candidate)
            if path:
                _add(out, kind='acl', target=path, title='Inspect ACL: ' + ntpath.basename(path.rstrip('\\')),
                     detail='Observed in ' + name + '. Inspect object and parent; confirm target attribution and standard-user effective access independently.',
                     source=name)
    if case_id == 'TC-SV-001':
        body = _report(root, 'services_review.txt')
        for block in re.split(r'(?m)^\[SVC-\d+\]', body)[1:]:
            match = re.search(r'(?mi)^Executable\s*:\s*(.+?)\s*$', block)
            path = _local_path(match.group(1)) if match else None
            if path:
                _add(out, kind='acl', target=path, title='Inspect service executable ACL: ' + ntpath.basename(path),
                     detail='Read live executable/parent ACL; elevated-token access does not prove unprivileged write.',source='services_review.txt')
    if case_id in ('TC-SV-001', 'TC-PB-001'):
        body = _report(root, 'services_review.txt')
        # TC-PB-001 validates only an actual privilege-boundary POI, not the
        # entire set of installed services already covered by TC-SV-001.
        observed = set()
        if case_id == 'TC-PB-001':
            pb = _report(root, 'privilege_boundary_review.txt')
            for block in re.split(r'(?m)^\[POI-PB-\d+\]', pb)[1:]:
                identity = re.search(r'(?mi)^Component\s*:\s*([^\r\n]+)', block)
                if identity:
                    observed.add(identity.group(1).strip().casefold())
        for name in re.findall(r'(?m)^\[SVC-\d+\]\s+([^\r\n|]+)', body)[:8]:
            service = name.strip()
            if case_id == 'TC-PB-001' and service.casefold() not in observed:
                continue
            if re.fullmatch(r'[\w .()\-]{1,180}', service):
                _add(out, kind='service', target=service, title='Inspect service: ' + service,
                     detail='Read live service configuration and identity; does not modify service state.',
                     source='services_review.txt' if case_id == 'TC-SV-001' else 'privilege_boundary_review.txt')
                if case_id == 'TC-SV-001':
                    _add(out, kind='service_acl', target=service, title='Inspect service object SDDL: ' + service,
                         detail='Read-only service object permissions; does not verify standard-user effective rights.',
                         source='services_review.txt')
    if case_id == 'TC-TS-001':
        body = _report(root, 'scheduled_tasks_review.txt')
        for name in re.findall(r'(?m)^\[TASK-\d+\]\s+([^\r\n|]+)', body)[:8]:
            task = name.strip()
            if task and len(task) < 180:
                _add(out, kind='task', target=task, title='Inspect task: ' + task,
                     detail='Read configured principal, actions and run level; no task execution.',
                     source='scheduled_tasks_review.txt')
    if case_id == 'TC-RG-001':
        body = _report(root, 'registry_changes.txt')
        for name in re.findall(r'(?m)^\[\d+\]\s+\+\s+(HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\[^\r\n]+)', body)[:48]:
            # Windows RestartManager, BAM, compatibility and other OS keys
            # are high-noise background effects, not app-specific ACL targets.
            # Only offer app/vendor software keys and installed service keys.
            if re.match(r'(?i)^HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\(?:Microsoft|Policies|Classes|WOW6432Node\\Microsoft)(?:\\|$)', name):
                continue
            if re.match(r'(?i)^HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\(?:SYSTEM|HARDWARE|SAM|SECURITY)\\', name):
                continue
            if not re.match(r'(?i)^HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\', name):
                continue
            if len(name) < 450 and not any(x in name for x in ('\r','\n','"',"'",'|')):
                _add(out, kind='registry', target=name,
                     title='Inspect registry ACL: ' + name.rsplit('\\', 1)[-1],
                     detail='Inspect key ownership and ACL, not effective access or exploitability.',
                     source='registry_changes.txt')
    if case_id in ('TC-NW-001', 'TC-IP-001'):
        body = _report(root, 'network_surface_review.txt')
        for process, pid in re.findall(r'(?m)^\[NW-\d+\]\s+([^\r\n(]+)\s+\(PID\s+(\d+)\)', body)[:12]:
            if 0 < int(pid) < 1_000_000 and re.fullmatch(r'[\w .()\-]{1,140}', process.strip()):
                _add(out, kind='network', target=f'{pid}|{process.strip()}',
                     title=f'Inspect current sockets for {process.strip()} (PID {pid})',
                     detail='Revalidate the live PID and process name before showing sockets; process/PID may have changed.',
                     source='network_surface_review.txt')
    if case_id in ('TC-IP-001', 'TC-IP-002'):
        body = _report(root, 'ipc_review.txt')
        for pipe in re.findall(r'(?m)^\s*Pipe Name\s*:\s*(\\\\\.\\pipe\\[^\r\n]+)', body)[:12]:
            pipe = pipe.strip()
            if len(pipe) < 190 and not any(c in pipe for c in ('"', '<', '>', '|', '%', '!', '^')):
                _add(out, kind='pipe', target=pipe,
                     title='Inspect pipe permissions: ' + pipe.split('\\')[-1],
                     detail='Run read-only AccessChk when available. Pipe ACLs do not prove application-layer authorization.',
                     source='ipc_review.txt', shell='AccessChk')
    # TC-CF-001 secret evidence is presented by the dedicated Potential Secret Indicator Review.
    # Do not create a duplicate generic redacted-indicator recheck.
    if case_id == 'TC-PE-001':
        # The dedicated, field-tested DUMPBIN panel is authoritative.
        pass
    return out


def available_checks(root: Path, case_id: str) -> dict:
    case = _verified(Path(root), case_id)
    checks = _raw_checks(Path(root), case)
    fallback = _case_target_notice(Path(root), case_id) if not checks else ''
    missing_sources = []
    for name in ACL_CASE_REPORTS.get(case_id, ()):
        source = Path(root) / 'reports' / name
        if not source.is_file() or source.is_symlink():
            missing_sources.append(name + ' unavailable')
        elif source.stat().st_size > MAX_REPORT_BYTES:
            missing_sources.append(name + ' above bounded enumeration limit')
    additional = (' Partial evidence: ' + '; '.join(missing_sources) + '.' if checks and missing_sources else '')
    return {'case_id': case_id, 'checks': checks,
            'notice': 'Results are read-only observations, not test-case completion or vulnerability confirmation. '
                      'WCA is normally elevated: ACLs do not establish standard-user effective rights. '
                      'At most 22 distinct live checks are offered; omitted items require manual review. '
                      'A missing observation or unavailable live target remains inconclusive.' + additional,
            'none': fallback or 'No verified targets for an automated check. Follow How to Perform for manual validation.'}


def _secrets(root: Path) -> dict:
    body = _report(root, 'secrets_review.txt')
    pe = [line for line in body.splitlines() if 'PE file offset' in line]
    lines = [line for line in body.splitlines() if re.search(r'^\s*Line\s*:', line)]
    # Do NOT re-emit matching string values or surrounding secret context.
    output = f'PE offset entries: {len(pe)}\nText-file line references: {len(lines)}\n'
    output += '\n'.join(sanitize_report_text(x)[:180] for x in (pe[:12] + lines[:12]))
    return {'status': 'EVIDENCE_REVIEW', 'output': output,
            'command': 'WCA redacted-indicator summary; no OS command executed', 
            'interpretation': 'Only redacted indicator locations are summarized. Inspect full report privately; zero matches do not exclude secrets.'}


def _script(kind: str, target: str) -> str:
    # All possible commands are fixed templates; browser-supplied code is NEVER
    # used. Every target originates in a verified WCA report.
    prefix = "$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n"
    if kind == 'acl':
        arg = _ps(target)
        return prefix + f"""$p={arg}
if (-not (Test-Path -LiteralPath $p)) {{ Write-Output 'NOT PRESENT: original path no longer exists'; exit 3 }}
Write-Output ('INSPECTED TARGET: ' + $p)
Write-Output 'FILE OR DIRECTORY ACL:'
Get-Acl -LiteralPath $p | Select-Object Owner,AccessToString | Format-List | Out-String -Width 180
Write-Output 'TARGET ACL (ICACLS RIGHTS: F=Full Control, M=Modify, RX=Read/Execute, W=Write):'
& icacls.exe $p | Out-String -Width 180
Write-Output 'PARENT DIRECTORY ACL:'
$parent=Split-Path -Parent $p
Write-Output ('INSPECTED PARENT: ' + $parent)
if ($parent -and (Test-Path -LiteralPath $parent)) {{
  Get-Acl -LiteralPath $parent | Select-Object Owner,AccessToString | Format-List | Out-String -Width 180
  Write-Output 'PARENT ACL (ICACLS RIGHTS):'
  & icacls.exe $parent | Out-String -Width 180
}}
"""
    if kind == 'service':
        return prefix + f"""$n={_ps(target)}
$svc=Get-CimInstance Win32_Service | Where-Object {{ $_.Name -eq $n }} | Select-Object -First 1
if ($null -eq $svc) {{ Write-Output 'SERVICE NOT PRESENT: no current exact-name match'; exit 3 }}
$svc | Select-Object Name,StartName,PathName,StartMode,State | Format-List | Out-String -Width 180
"""
    if kind == 'service_acl':
        return prefix + f"""$n={_ps(target)}
Write-Output 'SERVICE OBJECT SECURITY DESCRIPTOR (SDDL):'
$details = & sc.exe sdshow $n 2>&1
if ($LASTEXITCODE -ne 0) {{ Write-Output 'SDDL UNAVAILABLE: sc.exe could not retrieve the service descriptor'; exit 4 }}
$details | Out-String -Width 180
"""
    if kind == 'task':
        return prefix + f"""$n={_ps(target)}
$t=Get-ScheduledTask | Where-Object {{ ($_.TaskPath+$_.TaskName) -eq $n -or $_.TaskName -eq $n }} | Select-Object -First 1
if ($null -eq $t) {{ Write-Output 'TASK NOT PRESENT: no current exact-name match'; exit 3 }}
$t | Select-Object TaskName,TaskPath,Principal,Actions | Format-List | Out-String -Width 180
"""
    if kind == 'registry':
        # Prefix is reconstructed from a restricted recorded registry path.
        hive, sub = target.split('\\', 1)
        provider = ('Registry::' + hive + '\\' + sub)
        return prefix + f"""$p={_ps(provider)}
if (-not (Test-Path -LiteralPath $p)) {{ Write-Output 'REGISTRY KEY NOT PRESENT'; exit 3 }}
Get-Acl -LiteralPath $p | Select-Object Owner,AccessToString | Format-List | Out-String -Width 180
"""
    if kind == 'network':
        pid, proc = target.split('|', 1)
        return prefix + f"""$expected={_ps(proc)}
$process=Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue
if ($null -eq $process -or ($process.ProcessName+'.exe') -ine $expected) {{ Write-Output 'STALE PID OR PROCESS NAME: no live recheck performed'; exit 3 }}
if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) -or -not (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {{ Write-Output 'NETWORK CMDLETS UNAVAILABLE'; exit 2 }}
$tcp=@(Get-NetTCPConnection -OwningProcess {int(pid)} -ErrorAction SilentlyContinue)
$udp=@(Get-NetUDPEndpoint -OwningProcess {int(pid)} -ErrorAction SilentlyContinue)
if ($tcp.Count -eq 0 -and $udp.Count -eq 0) {{ Write-Output 'NO CURRENT SOCKETS: process exists, but no TCP/UDP sockets were observed at check time'; exit 0 }}
$tcp | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -AutoSize | Out-String -Width 180
$udp | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize | Out-String -Width 180
"""
    raise ValueError('Unsupported read-only check type.')


def _decode_process_output(data: bytes) -> str:
    """Decode Windows PowerShell stdout/stderr without leaking CLIXML markup."""
    if not data:
        return ''
    if data.startswith((b'\xff\xfe', b'\xfe\xff')):
        return data.decode('utf-16', errors='replace')
    # PowerShell native-output encoding varies with host settings.
    return data.decode('utf-8-sig', errors='replace')


def _readable_error(raw: str) -> str:
    """Extract human-facing errors from Windows PowerShell serialized stderr."""
    if '#< CLIXML' not in raw and '<Objs ' not in raw:
        return raw.strip()
    body = raw[raw.find('<Objs '):] if '<Objs ' in raw else ''
    if body:
        try:
            root = ET.fromstring(body)
            messages = []
            for node in root.iter():
                if node.tag.rsplit('}', 1)[-1] == 'S' and node.attrib.get('S') == 'Error' and node.text:
                    value = re.sub(r'_x([0-9a-fA-F]{4})_', lambda m: chr(int(m.group(1), 16)), node.text)
                    value = value.strip()
                    if value and value not in messages:
                        messages.append(value)
            if messages:
                return '\n'.join(messages)[:MAX_OUTPUT]
        except ET.ParseError:
            pass
    # Never show opaque serialized markup as a result.
    return 'PowerShell reported an error; inspect the command or rerun in an interactive shell.'


def _powershell(script: str) -> dict:
    exe = shutil.which('powershell.exe') or (r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' if os.name == 'nt' else None)
    if not exe or os.name != 'nt':
        return {'status': 'UNAVAILABLE', 'output': 'Windows PowerShell is required; the check did not run.',
                'command': 'PowerShell read-only check', 'interpretation': 'No live check occurred.'}
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    try:
        # WCA may be started from PowerShell 7. Its PSModulePath can leak through
        # Python into Windows PowerShell 5.1, breaking native cmdlets such as
        # Get-Acl by resolving incompatible Microsoft.PowerShell.Security modules.
        # Use the same sanitized child environment as the main WCA collector.
        result = subprocess.run([exe, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                shell=False, capture_output=True, timeout=MAX_SECONDS,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                                env=_powershell_environment(exe), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'INCONCLUSIVE', 'output': type(exc).__name__, 'command': script[:1500],
                'interpretation': 'PowerShell execution unavailable or timed out.'}
    stdout = _decode_process_output(result.stdout)
    stderr = _readable_error(_decode_process_output(result.stderr))
    missing = bool(re.search(r'(?m)^(?:REGISTRY KEY NOT PRESENT|SERVICE NOT PRESENT|TASK NOT PRESENT|NOT PRESENT|STALE PID OR PROCESS NAME)[^\r\n]*', stdout))
    if missing:
        status = 'NOT_PRESENT'
        interpretation = 'The recorded target is absent or no longer matches this live session. No ACL or security outcome was established. Registry HKCU may reference a different user context.'
        output = stdout.strip()
    elif 'NETWORK CMDLETS UNAVAILABLE' in stdout:
        status = 'UNAVAILABLE'
        interpretation = 'Windows network cmdlets could not be loaded. Use the documented manual TCPView/Tcpvcon verification.'
        output = stdout.strip()
    elif result.returncode == 0 and not stderr:
        status = 'OBSERVED'
        interpretation = ('The recorded process is present, but no TCP/UDP sockets were observed at check time. '
                          'Historical connections may be transient; this is not proof the app never uses the network.'
                          if 'NO CURRENT SOCKETS:' in stdout else
                          'Read-only metadata collected. An elevated WCA token cannot establish effective access for an unprivileged user.')
        output = stdout.strip() or 'Command completed but produced no data.'
    else:
        status = 'INCONCLUSIVE'
        interpretation = 'The check failed or returned ambiguous output. No security conclusion was established.'
        output = '\n'.join(x for x in (stdout.strip(), stderr) if x)
    return {'status': status,
            'output': sanitize_report_text(output or 'No check output was returned.')[:MAX_OUTPUT],
            'command': sanitize_report_text(script)[:1800], 'interpretation': interpretation,
            'exit_code': result.returncode}


def _pipe_accesschk(pipe: str) -> dict:
    # A direct external invocation avoids CMD, PowerShell and metacharacter expansion.
    found = tool_detection.detect_tools().get('AccessChk', {})
    exe = Path(found.get('path') or '') if found.get('found') else None
    if not exe or not exe.is_file() or exe.is_symlink():
        return {'status': 'UNAVAILABLE', 'output': 'AccessChk not detected in Tool Readiness.',
                'command': 'accesschk.exe -accepteula -nobanner -v <observed pipe>',
                'interpretation': 'Install/configure AccessChk or use manual procedures. No pipe permission check ran.'}
    argv = [str(exe), '-accepteula', '-nobanner', '-v', pipe]
    try:
        outcome = subprocess.run(argv, shell=False, capture_output=True, check=False,
                                 timeout=MAX_SECONDS, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'INCONCLUSIVE', 'output': type(exc).__name__, 'command': ' '.join(argv),
                'interpretation': 'Pipe inspection could not complete.'}
    output = (outcome.stdout + b'\n' + outcome.stderr)[:MAX_OUTPUT].decode('utf-8', errors='replace')
    return {'status': 'OBSERVED' if outcome.returncode == 0 else 'INCONCLUSIVE',
            'output': sanitize_report_text(output), 'command': ' '.join(argv),
            'interpretation': 'Pipe access rights alone do not establish an unauthorized operation. Validate with a suitable user token and IPC request.',
            'exit_code': outcome.returncode}


def run_check(root: Path, case_id: str, check_id: str) -> dict:
    root = Path(root)
    case = _verified(root, case_id)
    check = next((x for x in _raw_checks(root, case) if x['id'] == check_id), None)
    if not check:
        raise ValueError('Check unavailable or stale; refresh the selected case.')
    if check['kind'] == 'secrets':
        result = _secrets(root)
    elif check['kind'] == 'pipe':
        result = _pipe_accesschk(check['target'])
    else:
        result = _powershell(_script(check['kind'], check['target']))
    target = sanitize_report_text(check['target'])
    parent = sanitize_report_text(ntpath.dirname(check['target'])) if check['kind'] == 'acl' else ''
    return {'case_id': case_id, 'check_id': check_id, 'title': check['title'],
            'source': check['source'], 'shell': check['shell'],
            'target': target, 'parent': parent, 'target_detail': check['detail'],
            **result, 'recorded': False, 'completes_test_case': False}
