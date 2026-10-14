"""Evidence-driven, shell-quoted Windows checks for persisted review candidates.

Only interpolate recognized fields from persisted, sanitized assessment reports;
never execute input, pick ambiguous ACL targets, or silently invent an object.
"""
from __future__ import annotations
import re
import ntpath
from pathlib import Path
from utils.assessment_layout import artifact_path

PATH_RE = re.compile(r'(?<![\w])([A-Za-z]:\\[^\r\n<>|"*?]+)')


def _quote_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _known_path(value: str) -> str | None:
    value = value.strip().strip('"\'').rstrip('.,;) ')
    if ('\n' in value or '\r' in value or '\x00' in value or
            not re.match(r'^[A-Za-z]:\\', value) or len(value) > 240 or
            '<' in value or '>' in value):
        return None
    # Avoid persisting personal full paths in newly derived instructions.
    if re.search(r'(?i)^C:\\Users\\(?!Public\\|Default\\)', value):
        return None
    return value


def _file_arg(root: Path | None, filename: str, *, console_paths: bool = False) -> str:
    """One standalone PowerShell argument; never depend on the terminal CWD.

    Live-console only: resolve an existing, verified assessment artifact to an
    absolute path. Portable TXT/HTML guidance: ask the tester to choose the
    relevant file without persisting their personal assessment location.
    """
    safe_name = filename.replace("\\", "/")
    if not re.fullmatch(r"(?:reports|working)/[A-Za-z0-9_.-]+\.(?:txt|csv)", safe_name):
        raise ValueError("Unsafe validation artifact name")
    if console_paths and root is not None:
        candidate = Path(root) / Path(safe_name)
        if candidate.is_file() and not candidate.is_symlink():
            return _quote_ps(str(candidate.resolve()))
        # Legacy, flat-layout reports are supported, but do not guess paths.
        if safe_name.startswith("reports/"):
            legacy = Path(root) / Path(safe_name).name
            if legacy.is_file() and not legacy.is_symlink():
                return _quote_ps(str(legacy.resolve()))
    return "(Read-Host " + _quote_ps("Full path to " + safe_name) + ")"


def _report_ref(root: Path | None, name: str, *, console_paths: bool = False) -> str:
    return _file_arg(root, "reports/" + name, console_paths=console_paths)


def _working_ref(root: Path | None, name: str, *, console_paths: bool = False) -> str:
    return _file_arg(root, "working/" + name, console_paths=console_paths)


def _working_directory_ref(root: Path | None, *, console_paths: bool = False) -> str:
    if console_paths and root is not None:
        folder = Path(root) / 'working' / 'extracted_installer'
        if folder.is_dir() and not folder.is_symlink():
            return _quote_ps(str(folder.resolve()))
    return "(Read-Host 'Full path to working/extracted_installer')"


def _poc_script_command(name: str, arguments: str = "", *, console_paths: bool = False) -> str:
    """Return a copy/paste-safe command for a bundled proof helper.

    Live Guided Review resolves the helper from the running source tree so the
    tester is not asked for a path that Windows Client Assessment already knows. Portable
    TXT/HTML guidance cannot retain the tester's source-project path, so it uses
    a guarded selection loop that rejects blank, missing, directory, or wrong
    helper paths before invocation.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ps1", name):
        raise ValueError("Unsafe proof-resource name")
    if console_paths:
        candidate = Path(__file__).resolve().parents[1] / "scripts" / "poc" / name
        if candidate.is_file() and not candidate.is_symlink():
            return "& " + _quote_ps(str(candidate)) + ((" " + arguments) if arguments else "")
    prompt = _quote_ps("Full path to extracted framework scripts/poc/" + name)
    warning = _quote_ps(
        "Enter the full path to " + name
        + ". Blank values, directories, and other files are not accepted."
    )
    expected = _quote_ps(name)
    selector = (
        "$poc = $null; do { "
        "$poc = (Read-Host " + prompt + ").Trim().Trim([char]34).Trim([char]39); "
        "if (-not (Test-Path -LiteralPath $poc -PathType Leaf) -or "
        "(Split-Path -Leaf $poc) -ine " + expected + ") { "
        "Write-Warning " + warning + "; $poc = $null } "
        "} until ($poc); "
    )
    return selector + "& $poc" + ((" " + arguments) if arguments else "")


def _report(root: Path | None, filename: str) -> str:
    if root is None:
        return ''
    p = artifact_path(root, filename)
    if not p.is_file() or p.is_symlink():
        return ''
    return p.read_text(encoding='utf-8', errors='replace')[:800_000]


def _field(evidence: str, label: str) -> str:
    found = re.search(r'(?im)^\s*' + re.escape(label) + r'\s*:\s*(.+?)\s*$', evidence)
    return found.group(1).strip() if found else ''


def _broad_acl_paths(root: Path | None) -> list[str]:
    """Only suggest actual broad-write ACL matches, never an arbitrary candidate."""
    data = _report(root, 'permissions_review.txt')
    results = []
    for block in re.split(r'(?m)^\[ACL-\d+\]', data)[1:]:
        path = _known_path(_field(block, 'Path'))
        match = re.search(r'Broad Write ACEs\s*\((\d+)\)', block, re.I)
        if path and match and int(match.group(1)) > 0 and path.lower() not in [x.lower() for x in results]:
            results.append(path)
    return results[:12]


def _tool_command(display: str, arguments: str, *, console_paths: bool = False, tools: dict | None = None) -> str:
    """Resolve the executable variant actually detected for live guidance.

    Portable TXT/HTML guidance must not persist a tester-specific tool path, so
    it discovers any supported executable variant at execution time instead.
    """
    from utils.tool_detection import TOOLS

    names = tuple(TOOLS.get(display, ((display,), '', ''))[0])
    if console_paths and tools:
        info = tools.get(display, {}) if isinstance(tools, dict) else {}
        path = str(info.get('path') or '').strip()
        if info.get('found') and path:
            return '& ' + _quote_ps(path) + ((' ' + arguments) if arguments else '')

    # Do not assume the 64-bit filename exists merely because that is the first
    # preferred detector candidate. Resolve any supported installed variant.
    candidates = ','.join(_quote_ps(name) for name in names)
    warning = f'{display} was not found. Re-run Tool Detection or configure tool_paths.json.'
    return (
        '$tool = Get-Command ' + candidates + ' -ErrorAction SilentlyContinue | Select-Object -First 1; '
        'if ($tool) { & $tool.Source' + ((' ' + arguments) if arguments else '') + ' } '
        'else { Write-Warning ' + _quote_ps(warning) + ' }'
    )


def checks(item: dict, root: Path | None = None, *, console_paths: bool = False, tools: dict | None = None) -> tuple[str, ...]:
    module = str(item.get('source_module') or '')
    evidence = str(item.get('evidence') or '')
    title = str(item.get('title') or '')
    artifacts = [v for v in item.get('artifacts', []) if isinstance(v, str)]
    report = lambda name: _report_ref(root, name, console_paths=console_paths)
    # Guided Runtime stores the committed filtered CSV under a distinct name.
    # Select existing evidence, never refer to a discarded/nonexistent baseline.
    def working(name):
        selected = name
        if name == "procmon_target_events.csv" and root is not None:
            baseline = Path(root) / "working" / name
            guided = Path(root) / "working" / "guided_runtime_target_events.csv"
            if not baseline.is_file() and guided.is_file() and not guided.is_symlink():
                selected = guided.name
        return _working_ref(root, selected, console_paths=console_paths)
    if module == 'Guided Runtime Observation':
        # Guided-runtime candidates are already exact surface observations. Keep
        # validation CWD-independent and point back to the single observation
        # report rather than inventing a different target.
        port_match = re.search(r'(?i)\b(?:TCP|UDP)\s+([^\s:]+):([0-9]{1,5})', title + '\n' + evidence)
        if port_match:
            port = int(port_match.group(2))
            return (
                f'Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {{ $_.LocalPort -eq {port} }} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess',
                'Get-Content -LiteralPath ' + report('guided_runtime_observation.txt') + ' | Select-String -Pattern ' + _quote_ps(str(port)) + ' -Context 2,3',
            )
        pipe_match = re.search(r'\\\\\.\\pipe\\([A-Za-z0-9_.-]{1,128})', title + '\n' + evidence, re.I)
        if pipe_match:
            return (
                _tool_command('Handle', '-accepteula -a ' + _quote_ps(pipe_match.group(1)), console_paths=console_paths, tools=tools),
                'Get-Content -LiteralPath ' + report('guided_runtime_observation.txt') + ' | Select-String -Pattern ' + _quote_ps(pipe_match.group(1)) + ' -Context 2,3',
            )
        return ('Get-Content -LiteralPath ' + report('guided_runtime_observation.txt') + ' | Select-Object -First 220',)
    if module == 'Attack Surface Correlations':
        category = _field(evidence, 'Category').lower()
        observed_path = _known_path(_field(evidence, 'Path'))
        directory = _known_path(_field(evidence, 'Directory'))
        registry = _field(evidence, 'Registry Path')
        if category == 'executable/helper search-path hijacking':
            if not observed_path:
                return ('Get-Content -LiteralPath ' + report('attack_surface_correlations.txt') + ' | Select-String -Pattern "search-path|Path|Directory" -Context 0,3',)
            return ('icacls ' + _quote_ps(directory or ntpath.dirname(observed_path)),
                    'Test-Path -LiteralPath ' + _quote_ps(observed_path),
                    'Import-Csv -LiteralPath ' + working('procmon_target_events.csv') + ' | Where-Object { $_.Path -eq '
                    + _quote_ps(observed_path) + ' } | Select-Object \'Process Name\',Operation,Result,Detail',
                    'Verify a later launch from the controlled location; a failed lookup alone is not code execution.')
        if category == 'reparse point / symlink / junction abuse' and observed_path:
            return ('Get-Item -LiteralPath ' + _quote_ps(observed_path) + ' -Force | Select-Object FullName,LinkType,Target,Attributes',
                    'icacls ' + _quote_ps(ntpath.dirname(observed_path)),
                    'Do not modify links or invoke an elevated installer until a disposable VM snapshot is available.')
        if category == 'ifeo / silentprocessexit injection' and registry and re.fullmatch(r'(?i)(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[A-Za-z0-9_\\.{} -]{1,350}', registry):
            return ('Get-ItemProperty -LiteralPath ' + _quote_ps('Registry::' + registry.replace('HKLM\\','HKEY_LOCAL_MACHINE\\').replace('HKCU\\','HKEY_CURRENT_USER\\')) + ' -ErrorAction SilentlyContinue | Select-Object Debugger,GlobalFlag,ReportingMode',
                    'Inspect key ACL and compare verified baseline; do not change the original IFEO key.')
        if category == 'com registration and activation hijacking' and registry and re.fullmatch(r'(?i)(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[A-Za-z0-9_\\.{} -]{1,350}', registry):
            safe = 'Registry::' + registry.replace('HKLM\\','HKEY_LOCAL_MACHINE\\').replace('HKCU\\','HKEY_CURRENT_USER\\')
            return ('Get-Item -LiteralPath ' + _quote_ps(safe) + ' -ErrorAction SilentlyContinue | Format-List *',
                    'Get-Acl -LiteralPath ' + _quote_ps(safe) + ' | Format-List Owner,AccessToString',
                    'Read-only registration checks do not prove that a privileged consumer activates the CLSID.')
        return ('Get-Content -LiteralPath ' + report('attack_surface_correlations.txt') + ' | Select-Object -First 120',)
    if module == '.NET Detection / Source Review' and title.startswith('Managed Source '):
        category_patterns = {
            'Authentication / authorization': r'^(CLIENT-SIDE AUTHORIZATION / ROLE GATE|CREDENTIAL/SECRET TERMS|WEAK HASH OR PASSWORD STORAGE)',
            'Updater / replacement': r'^(UPDATER LOGIC|UPDATE CHANNEL / BINARY REPLACEMENT)',
            'Process / plugin execution': r'^(PROCESS EXECUTION|OS COMMAND EXECUTION|DYNAMIC PLUGIN / ASSEMBLY LOAD)',
            'SQL / input handling': r'^(SQL EXECUTION / QUERY COMPOSITION|FILESYSTEM TRAVERSAL BOUNDARY)',
            'IPC / native trust boundaries': r'^(NAMED PIPE IPC|IPC TRUST BOUNDARY|NATIVE INTEROP)',
            'Cryptography / TLS': r'^(TLS VALIDATION BYPASS|WEAK CRYPTO / PREDICTABLE KEYS|WEAK HASH OR PASSWORD STORAGE)',
        }
        topic = title[len('Managed Source '):].split(' Requires Validation')[0]
        topic_re = category_patterns.get(topic)
        if topic_re:
            return (
                'Get-Content -LiteralPath ' + report('dotnet_source_review.txt') + ' | Select-String -Pattern ' + _quote_ps(topic_re) + ' -Context 0,42',
                'Get-Content -LiteralPath ' + report('dotnet_source_review.txt') + ' | Select-String -Pattern ' + _quote_ps(r'Scope\s*:\s*FIRST-PARTY') + ' -Context 3,1 | Select-Object -First 100',
                'Open the indicated FIRST-PARTY decompiled source file and line in working/decompiled_dotnet; validate data flow and exploitability before reporting.',
            )
    if module == 'DLL Search Review':
        directory = _known_path(_field(evidence, 'Search Directory'))
        missing = _known_path(_field(evidence, 'Missing DLL'))
        if missing and not directory:
            directory = missing.rsplit('\\', 1)[0]
        if directory:
            cmds = ['icacls ' + _quote_ps(directory),
                    'Test-Path -LiteralPath ' + _quote_ps(directory) + ' -PathType Container']
        else:
            cmds = ['Get-Content -LiteralPath ' + report('dll_search_review.txt') + ' | Select-String -Pattern "Search Directory|Missing DLL" -Context 1,1',
                    'Select a verified missing-DLL lookup directory from the report, then inspect its effective ACL.']
        if missing:
            # comparison-safe filter; no operator interpolation
            cmds.append('Import-Csv -LiteralPath ' + working('procmon_target_events.csv') + ' | Where-Object { $_.Path -eq '
                        + _quote_ps(missing) + ' } | Select-Object -First 20')
        return tuple(cmds)
    if module == 'IPC / Named Pipe Review':
        name_match = re.search(r'\\\\\.\\pipe\\([A-Za-z0-9_.-]{1,128})', title + '\n' + evidence, re.I)
        if name_match:
            return (_tool_command('Handle', '-accepteula -a ' + _quote_ps(name_match.group(1)), console_paths=console_paths, tools=tools),
                    _poc_script_command('pipe_connect_probe.ps1', '-PipeName ' + _quote_ps(name_match.group(1)), console_paths=console_paths),
                    'Inspect the exact pipe ACL, server identity and supported operations; connection is not exploitation.')
        return ('Get-Content -LiteralPath ' + report('ipc_review.txt') + ' | Select-String -Pattern "pipe\\|Broad Access Evidence" -Context 1,2',)
    if module in ('Services Review', 'Privilege Boundary Review'):
        # A broad-write DLL directory unrelated to this service must never
        # become an asserted service/privilege-boundary target.
        service = _field(evidence, 'Component')
        path = _known_path(_field(evidence, 'Path'))
        if not path:
            found = re.search(r'(?m)^\s*[A-Za-z0-9_.-]+:\s*([A-Za-z]:\\[^\r\n]+\.exe)', evidence, re.I)
            if found:
                path = _known_path(found.group(1))
        if not service or service == 'N/A':
            match = re.search(r'(?m)^\s*([A-Za-z0-9_.-]+):\s*[A-Za-z]:\\', evidence)
            service = match.group(1) if match else ''
        if module == 'Privilege Boundary Review' and (not service or not path):
            text = _report(root, 'privilege_boundary_review.txt')
            service = service or _field(text, 'Component')
            path = path or _known_path(_field(text, 'Path'))
        commands = []
        if service and re.fullmatch(r'[A-Za-z0-9_.-]{1,120}', service):
            commands.extend(('sc.exe qc ' + _quote_ps(service),
                             'Get-CimInstance Win32_Service -Filter ' + _quote_ps('Name="' + service + '"') + ' | Select-Object Name,StartName,PathName,State'))
        else:
            commands.append('Get-Content -LiteralPath ' + report('services_review.txt') + ' | Select-String -Pattern "Name|Path|Account" -Context 1,3')
        if path:
            parent = ntpath.dirname(path)
            if parent:
                commands.append('icacls ' + _quote_ps(parent))
            # Check possible unquoted parsing candidates only when the source
            # evidence explicitly describes an unquoted command, never treat
            # an ordinary quoted service as a hijack.
            detail = (evidence + ' ' + _report(root, 'privilege_boundary_review.txt')[:3000]).lower()
            if 'unquoted' in detail and ' ' in path:
                fragments = path.split(' ')
                for j in range(1, len(fragments)):
                    earlier_exe = ' '.join(fragments[:j]) + '.exe'
                    directory = ntpath.dirname(earlier_exe)
                    if directory and directory.lower() != parent.lower():
                        command = 'icacls ' + _quote_ps(directory) + '  # Could an unprivileged user create ' + _quote_ps(earlier_exe) + '?'
                        if command not in commands:
                            commands.append(command)
        else:
            commands.append('Get-Content -LiteralPath ' + report('permissions_review.txt') + ' | Select-String -Pattern "Service executable|Service directory|Broad Write ACEs" -Context 0,4')
        return tuple(commands)
    if module == 'Permissions Review':
        paths = _broad_acl_paths(root)
        # Exact candidate path wins. A generic aggregate finding may legitimately
        # enumerate all matched broad-write directories; unrelated ACLs are excluded.
        specific = _known_path(_field(evidence, 'Path'))
        if specific:
            paths = [p for p in paths if p.lower() == specific.lower()]
        if not specific and item.get('source_record') and re.fullmatch(r'ACL-\d{3,5}', str(item['source_record'])):
            report = _report(root, 'permissions_review.txt')
            tag = '[' + item['source_record'] + ']'
            block = report.split(tag, 1)[-1].split('[ACL-', 1)[0] if tag in report else ''
            target = _known_path(_field(block, 'Path'))
            paths = [p for p in paths if p.lower() == target.lower()] if target else []
        if paths:
            commands = []
            for path in paths:
                commands.extend(('icacls ' + _quote_ps(path), 'Get-Acl -LiteralPath ' + _quote_ps(path) + ' | Format-List Owner,AccessToString'))
            return tuple(commands)
        return ('Get-Content -LiteralPath ' + report('permissions_review.txt') + ' | Select-String -Pattern "^Path\\s+:|Broad Write ACEs" -Context 0,3',
                'No broad-write ACL candidate was correlated; choose a relevant installed path only after reviewing the report.')
    if module == 'Digital Signature Review':
        # The original source path is deliberately not persisted. Accept a
        # pasted quoted path, but reject directories/nonexistent/non-Windows
        # executable/package input before running signature or hash checks.
        select_target = (
            "$target = $null; do { $target = (Read-Host 'Full path to the selected MSI or EXE target').Trim().Trim([char]34).Trim([char]39); "
            "if (-not (Test-Path -LiteralPath $target -PathType Leaf) -or ([IO.Path]::GetExtension($target) -notin '.msi','.exe')) "
            "{ Write-Warning 'Enter the full path to an existing MSI or EXE file, including the filename.'; $target = $null } "
            "} until ($target); Get-AuthenticodeSignature -LiteralPath $target | Format-List *"
        )
        return (select_target, 'Get-FileHash -LiteralPath $target -Algorithm SHA256')
    if module == 'Advanced .NET / Native Runtime Review':
        proc = re.search(r'\b([\w.-]+\.exe)\s*->', title, re.I)
        if proc:
            return ('Get-CimInstance Win32_Process | Where-Object { $_.Name -eq ' + _quote_ps(proc.group(1)) + ' } | Select-Object ProcessId,ParentProcessId,CommandLine',
                    'Get-Content -LiteralPath ' + report('advanced_runtime_review.txt') + ' | Select-String -Pattern "Process|Child|Integrity" -Context 0,2')
        return ('Get-Content -LiteralPath ' + report('advanced_runtime_review.txt'),)
    if module == 'Network Surface Review':
        port = re.search(r'\b(?:TCP|UDP)\s+(?:[\d.]+|\[[\da-f:]+\]):(\d{1,5})', title, re.I)
        if port and 1 <= int(port.group(1)) <= 65535:
            return ('Get-NetTCPConnection -State Listen -LocalPort ' + port.group(1) + ' | Select-Object LocalAddress,LocalPort,OwningProcess',
                    'Test-NetConnection -ComputerName 127.0.0.1 -Port ' + port.group(1),
                    'Get-Content -LiteralPath ' + report('network_surface_review.txt') + ' | Select-String -Pattern ' + _quote_ps(port.group(1)) + ' -Context 2,3')
        return ('Get-Content -LiteralPath ' + report('network_surface_review.txt'),)
    if module == 'Local Storage Review':
        candidate = _known_path(title)
        if not candidate:
            candidate = _known_path(_field(evidence, 'Path'))
        if candidate:
            return (
                'Get-Item -LiteralPath ' + _quote_ps(candidate) + ' -Force | Select-Object FullName,Length,LastWriteTime,Attributes',
                'Get-Acl -LiteralPath ' + _quote_ps(candidate) + ' | Format-List Owner,AccessToString',
                'icacls ' + _quote_ps(candidate),
                'Inspect only the indicated line/schema locally; do not paste secret values into WCA or portable evidence.',
            )
        return (
            'Get-Content -LiteralPath ' + report('local_storage_review.txt') + ' | Select-Object -First 180',
            'Choose only a target-associated storage item from the report and inspect its effective ACL before reviewing content.',
        )
    if module == 'Procmon Analysis' and ('Sensitive' in title or 'secret' in title.lower()):
        return ('Get-Content -LiteralPath ' + report('runtime_secrets_review.txt'),
                'Get-Content -LiteralPath ' + report('procmon_summary.txt') + ' | Select-String -Pattern "redact|sensitive" -Context 1,2',
                'Inspect only the redacted evidence; never copy credential values into review notes.')
    if module == 'MSI Analysis':
        return ('Get-Content -LiteralPath ' + report('msi_analysis.txt') + ' | Select-String -Pattern "CustomAction|InstallExecuteSequence" -Context 0,6',
                'Review each actual custom action target in the MSI table before choosing a path for ACL testing.')
    if module == 'PE Security Review':
        pe_report = _report(root, 'binary_security_review.txt')
        installed = _report(root, 'installed_files.txt')
        installed_paths = {}
        for row in installed.splitlines():
            found = re.match(r'^\s*\[\d+\]\s+([A-Za-z]:\\[^|\r\n]+)', row)
            if found:
                candidate = _known_path(found.group(1).strip())
                if candidate:
                    installed_paths.setdefault(ntpath.basename(candidate).lower(), []).append(candidate)
        cmds = []
        for block in re.split(r'(?m)^\[PE-\d+\]\s+', pe_report)[1:]:
            name = ntpath.basename(block.splitlines()[0].strip())
            if not re.fullmatch(r'[A-Za-z0-9_.-]+\.(?:exe|dll)', name, re.I):
                continue
            flagged = (bool(re.search(r'(?m)^\s*CFG\s*:\s*False', block, re.I)) if
                       'control flow guard' in title.lower() else
                       bool(re.search(r'(?m)^\s*(?:ASLR|DEP/NX)\s*:\s*False', block, re.I)))
            if not flagged:
                continue
            actual = installed_paths.get(name.lower(), [])
            if len(actual) == 1:
                cmd = (
                    'python -c "import pefile,sys; p=pefile.PE(sys.argv[1]); '
                    'd=p.OPTIONAL_HEADER.DllCharacteristics; '
                    "print('ASLR',bool(d&0x40),'DEP/NX',bool(d&0x100),"
                    "'CFG flag',bool(d&0x4000))\" "
                    + _quote_ps(actual[0])
                )
                cmds.append(cmd)
            else:
                cmds.append('Get-ChildItem -LiteralPath ' + _working_directory_ref(root, console_paths=console_paths)
                            + ' -Recurse -File -Filter ' + _quote_ps(name) + ' | Select-Object FullName')
        if cmds:
            return tuple(cmds + ['Inspect GuardCF load-config metadata separately; header flags alone do not prove CFG instrumentation.'])
        return ('Get-Content -LiteralPath ' + report('binary_security_review.txt') + ' | Select-String -Pattern "ASLR|DEP|CFG" -Context 0,3',
                '$binary = Read-Host "Full path to one affected PE from the extracted inventory"; python -c "import pefile,sys; p=pefile.PE(sys.argv[1]); d=p.OPTIONAL_HEADER.DllCharacteristics; print(\'ASLR\',bool(d&0x40),\'DEP/NX\',bool(d&0x100),\'CFG flag\',bool(d&0x4000))" $binary')
    if artifacts:
        filename = next((f for f in artifacts if f.endswith('.txt') and re.fullmatch(r'[a-zA-Z0-9_.-]+\.txt', f)), None)
        if filename:
            return ('Get-Content -LiteralPath ' + report(filename) + ' | Select-Object -First 100',)
    return ('Get-Content -LiteralPath ' + report('test_cases.txt') + ' | Select-String -Pattern ' + _quote_ps(title[:70]) + ' -Context 2,8',)
