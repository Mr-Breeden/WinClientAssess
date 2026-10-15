"""Curated, read-only *manual recheck* examples for evidence reports.

These are intentionally not execution history. They use placeholders, never
captured target paths, usernames, secrets or arbitrary command arguments.
New recipes require manual Windows verification before general release.
"""
from __future__ import annotations

# filename: (scope of independent check, PowerShell/shell command, caveat)
RECHECK_RECIPES: dict[str, tuple[str, str, str]] = {
    'services_review.txt': (
        'Service identity, configured executable, account and state',
        'Get-CimInstance Win32_Service -Filter "Name=\'<SERVICE_NAME>\'" | Select-Object Name,StartName,PathName,StartMode,State',
        'Service-path candidate and executable ACL conclusions require separate inspection.'),
    'permissions_review.txt': (
        'File or directory access control entries',
        '(Get-Acl -LiteralPath "<TARGET_PATH>").Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited -AutoSize',
        'Review effective rights and inheritance for the correct account separately.'),
    'signature_review.txt': (
        'Windows Authenticode signature status',
        'Get-AuthenticodeSignature -LiteralPath "<FILE_PATH>" | Format-List Status,StatusMessage,SignerCertificate',
        'Confirm trust-chain context and certificate validity at demonstration time.'),
    'binary_security_review.txt': (
        'PE header mitigation flags (Python with pefile installed)',
        'python -c "import pefile; p=pefile.PE(r\'<PE_FILE>\'); d=p.OPTIONAL_HEADER.DllCharacteristics; print(dict(ASLR=bool(d&64), DEP_NX=bool(d&256), CFG=bool(d&16384)))"',
        'These are PE flags; missing flags alone do not establish a vulnerability.'),
    'network_surface_review.txt': (
        'Current TCP listeners and owning process IDs',
        'Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess',
        'Filter by the target PID; endpoint state changes and UDP uses Get-NetUDPEndpoint.'),
    'runtime_network_connections.txt': (
        'Current TCP connections and owning process IDs',
        'Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess',
        'Capture a fresh observation with the application running; it may differ from the original.'),
    'named_pipe_inventory.txt': (
        'Named pipe handles held by a specific process (Sysinternals Handle)',
        'handle.exe -accepteula -a -p <TARGET_PID>',
        'Inspect the named-pipe entries; only currently open handles will be visible.'),
    'named_pipe_permissions.txt': (
        'Named pipe permissions (Sysinternals AccessChk)',
        'accesschk.exe -accepteula -nobanner -v "\\\\.\\pipe\\<PIPE_NAME>"',
        'An observed pipe name and the correct tool access are required.'),
    'scheduled_tasks_review.txt': (
        'Scheduled task principal and action',
        'Get-ScheduledTask -TaskName "<TASK_NAME>" | Select-Object TaskName,TaskPath,Principal,Actions',
        'Check task ACLs separately; task names alone do not prove privilege risk.'),
    'local_storage_review.txt': (
        'ACL of a local storage artifact',
        '(Get-Acl -LiteralPath "<STORAGE_PATH>").Access | Format-Table IdentityReference,FileSystemRights,AccessControlType',
        'This does not reproduce WCA secret-indicator scanning or disclose data values.'),
    'runtime_processes.txt': (
        'Current process command line and executable (CIM)',
        'Get-CimInstance Win32_Process -Filter "ProcessId=<TARGET_PID>" | Select-Object ProcessId,Name,ExecutablePath,CommandLine',
        'Process command lines can contain secrets; do not save or display sensitive arguments to clients.'),
    'target_firewall_rules.txt': (
        'Current target-associated firewall rule configuration',
        'Get-NetFirewallRule -DisplayName "<RULE_DISPLAY_NAME>" | Format-List Name,DisplayName,Enabled,Direction,Action',
        'Port/application/address filters require separate Get-NetFirewall*Filter queries.'),
    'new_drivers.txt': (
        'Driver service configuration',
        'Get-CimInstance Win32_SystemDriver -Filter "Name=\'<DRIVER_SERVICE_NAME>\'" | Select-Object Name,StartName,PathName,State',
        'Signature and write-permission checks are separate steps.'),
}
