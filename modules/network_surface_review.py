from __future__ import annotations
from utils.assessment_layout import artifact_path

import ipaddress
import json
import os
from pathlib import Path

import psutil

from modules.runtime_process_review import collect_runtime_processes
from utils.powershell import run_powershell_json
from utils.component_context import RuntimeContextIndex, account_for_report
from utils.privacy import sanitize_report_text


HTTP_LIKE_PORTS = {
    80, 443, 3000, 3001, 5000, 5001, 7000, 7001,
    8000, 8001, 8080, 8081, 8088, 8443, 8888, 9000, 9443,
}


def _addr_text(addr):
    if not addr:
        return "", None
    try:
        return str(addr.ip), int(addr.port)
    except AttributeError:
        try:
            return str(addr[0]), int(addr[1])
        except Exception:
            return str(addr), None


def _scope(address: str):
    value = str(address or "").strip()
    if value in {"0.0.0.0", "::", "*"}:
        return "Wildcard / all interfaces"
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
        if ip.is_loopback:
            return "Loopback only"
        if ip.is_unspecified:
            return "Wildcard / all interfaces"
        if ip.is_link_local:
            return "Link-local interface"
        return "Non-loopback interface"
    except Exception:
        return "Unknown"


def _collect_connections(target_pids, additional_http_ports=None):
    endpoints = []
    errors = []
    http_ports = set(HTTP_LIKE_PORTS)
    http_ports.update(int(x) for x in (additional_http_ports or []) if str(x).isdigit())
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as exc:
        return [], [str(exc)]

    for conn in connections:
        if not conn.pid or conn.pid not in target_pids:
            continue
        local_addr, local_port = _addr_text(conn.laddr)
        remote_addr, remote_port = _addr_text(conn.raddr)

        sock_type = "TCP" if conn.type == getattr(__import__("socket"), "SOCK_STREAM") else "UDP"
        status = str(conn.status or "")
        listener = sock_type == "TCP" and status.upper() == "LISTEN"
        udp_bound = sock_type == "UDP"

        endpoints.append(
            {
                "PID": conn.pid,
                "Protocol": sock_type,
                "LocalAddress": local_addr,
                "LocalPort": local_port,
                "RemoteAddress": remote_addr,
                "RemotePort": remote_port,
                "Status": status,
                "Listener": listener,
                "UdpBound": udp_bound,
                "Scope": _scope(local_addr),
                "HttpLikePort": bool(local_port in http_ports if local_port is not None else False),
            }
        )
    return endpoints, errors


def _configured_local_http_ports(installed_diff, application_hints):
    hints = application_hints or {}
    keys = {str(x) for x in (hints.get("local_http_port_keys") or []) if x}
    if not hints.get("dynamic_loopback_http") or not keys:
        return set(), []

    records = []
    filesystem = (installed_diff or {}).get("Filesystem", {})
    records.extend(filesystem.get("added", []) or [])
    for change in filesystem.get("changed", []) or []:
        if isinstance(change, dict) and isinstance(change.get("after"), dict):
            records.append(change["after"])

    ports = set()
    sources = []
    for record in records:
        if not isinstance(record, dict) or record.get("IsDirectory"):
            continue
        path = Path(str(record.get("Path") or ""))
        if path.suffix.lower() != ".json":
            continue
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        matched = False
        for key in keys:
            value = data.get(key)
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                ports.add(port)
                matched = True
        if matched:
            sources.append(str(path))
    return ports, sources


def _firewall_rules(program_paths):
    if os.name != "nt" or not program_paths:
        return [], ""

    quoted = ",".join("'" + str(p).replace("'", "''") + "'" for p in program_paths)
    ps = rf"""
    $targets = @({quoted}) | ForEach-Object {{ $_.ToLowerInvariant() }}
    $out = @()
    foreach($rule in @(Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction SilentlyContinue)) {{
      try {{
        $apps = @($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)
        $ports = @($rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
        $addresses = @($rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue)
        foreach($app in $apps) {{
          $program = [string]$app.Program
          if($program -and $program -ne 'Any' -and $targets -contains $program.ToLowerInvariant()) {{
            if($ports.Count -eq 0) {{ $ports = @([PSCustomObject]@{{Protocol='Any';LocalPort='Any';RemotePort='Any'}}) }}
            foreach($port in $ports) {{
              [PSCustomObject]@{{
                Name=$rule.Name
                DisplayName=$rule.DisplayName
                Action=[string]$rule.Action
                Profile=[string]$rule.Profile
                Program=$program
                Protocol=[string]$port.Protocol
                LocalPort=[string]$port.LocalPort
                RemotePort=[string]$port.RemotePort
                LocalAddress=(@($addresses | ForEach-Object {{$_.LocalAddress}}) -join ',')
                RemoteAddress=(@($addresses | ForEach-Object {{$_.RemoteAddress}}) -join ',')
              }}
            }}
          }}
        }}
      }} catch {{}}
    }}
    $out
    """
    # The objects are emitted directly in the foreach loop; no $out assignment is needed.
    data, result = run_powershell_json(ps, timeout=240)
    if isinstance(data, dict):
        return [data], ""
    if isinstance(data, list):
        return data, ""
    return [], result.get("stderr", "") or ""


def run_network_surface_review(
    assessment_dir: Path,
    runtime_targets=None,
    observed_process_names=None,
    runtime_processes=None,
    installed_diff=None,
    application_hints=None,
    exclude_paths=None,
    procmon_data=None,
):
    processes = runtime_processes or collect_runtime_processes(
        runtime_targets or [],
        observed_process_names or [],
        exclude_paths,
    )
    target_pids = {int(p["PID"]) for p in processes if p.get("PID") is not None}
    by_pid = {int(p["PID"]): p for p in processes if p.get("PID") is not None}

    context = RuntimeContextIndex(runtime_targets or [], processes)
    configured_http_ports, port_sources = _configured_local_http_ports(installed_diff, application_hints)
    endpoints, endpoint_errors = _collect_connections(target_pids, configured_http_ports)
    # A successful collector invocation is not equivalent to examining the
    # assessed client.  Preserve the report for diagnostics but expose the
    # missing target correlation as an optional runtime coverage gap.
    no_target_process = not processes
    listeners = [
        e for e in endpoints
        if e["Listener"] or e["UdpBound"]
    ]
    active = [
        e for e in endpoints
        if not e["Listener"] and not e["UdpBound"]
    ]

    program_paths = sorted({
        str(p.get("Exe") or "")
        for p in processes
        if p.get("Exe")
    })
    firewall_rules, firewall_error = _firewall_rules(program_paths)

    # Index firewall rules by normalized program path for report enrichment.
    fw_by_program = {}
    for rule in firewall_rules:
        fw_by_program.setdefault(str(rule.get("Program") or "").lower(), []).append(rule)

    records = []
    pois = []
    for endpoint in listeners:
        proc = by_pid.get(endpoint["PID"], {})
        privileged, target = context.privileged_for(process=proc)
        exe = str(proc.get("Exe") or "")
        endpoint["ProcessName"] = proc.get("Name", "")
        endpoint["Executable"] = exe
        endpoint["Username"] = proc.get("Username", "")
        endpoint["PrivilegedContext"] = privileged
        endpoint["ComponentSource"] = target.get("Source", "")
        endpoint["Component"] = target.get("Component", "")
        endpoint["FirewallRules"] = fw_by_program.get(exe.lower(), [])
        records.append(endpoint)

        scope = endpoint["Scope"]
        reasons = []
        confidence = None

        if scope == "Wildcard / all interfaces":
            reasons.append("Listener is bound to all interfaces.")
            confidence = "HIGH" if privileged else "MEDIUM"
        elif scope in {"Non-loopback interface", "Link-local interface"}:
            reasons.append("Listener is reachable beyond the loopback interface.")
            confidence = "HIGH" if privileged else "MEDIUM"
        elif scope == "Loopback only" and endpoint["HttpLikePort"]:
            reasons.append("Loopback listener uses a port commonly associated with HTTP/S or developer web services.")
            confidence = "LOW"

        if reasons:
            poi = dict(endpoint)
            poi["POI"] = f"POI-NW-{len(pois) + 1:03d}"
            poi["Confidence"] = confidence or "LOW"
            poi["Reasons"] = reasons
            pois.append(poi)

    width = 116
    lines = [
        "WCA - NETWORK SURFACE REVIEW",
        "=" * width,
        "",
        "Purpose:",
        "  Correlates currently running target processes with TCP listeners, UDP endpoints, active",
        "  connections, bind scope, and target-specific inbound Windows Firewall rules.",
        "  Listener exposure is a review point, not an automatic vulnerability.",
        "",
        f"Correlated target processes : {len(processes)}",
        f"Target runtime correlation : {'NOT OBSERVED' if no_target_process else 'OBSERVED'}",
        f"TCP/UDP endpoint records    : {len(endpoints)}",
        f"Listening/bound endpoints   : {len(listeners)}",
        f"Active connections          : {len(active)}",
        f"Firewall rules correlated   : {len(firewall_rules)}",
        f"Network POIs                : {len(pois)}",
        f"Configured local HTTP ports : {', '.join(str(x) for x in sorted(configured_http_ports)) or 'None'}",
        f"Port configuration sources  : {', '.join(port_sources) or 'None'}",
        "",
        "LISTENING / BOUND ENDPOINTS",
        "-" * width,
    ]

    if no_target_process:
        lines += [
            "COVERAGE GAP: No assessed-application process was correlated at collection time.",
            "The empty endpoint list must not be interpreted as evidence that the application",
            "does not listen or communicate. Launch its client and background services, then",
            "repeat the review. Verify runtime_targets.txt paths if correlation still fails.",
            "",
        ]

    if not records:
        lines.append("No listening TCP or bound UDP endpoints were identified for the correlated target processes.")
        lines.append("")

    for idx, item in enumerate(records, 1):
        local = f"{item['LocalAddress']}:{item['LocalPort']}"
        lines += [
            f"[NW-{idx:03d}] {item['ProcessName']} (PID {item['PID']})",
            f"  Protocol            : {item['Protocol']}",
            f"  Local Endpoint      : {local}",
            f"  State               : {item['Status'] or 'BOUND'}",
            f"  Bind Scope          : {item['Scope']}",
            f"  HTTP/S-like Port    : {item['HttpLikePort']}",
            f"  Executable          : {item['Executable'] or 'Unavailable'}",
            f"  Execution User      : {account_for_report(item['Username']) or 'Unavailable'}",
            f"  Privileged Context  : {item['PrivilegedContext']}",
            f"  Component Source    : {item['ComponentSource'] or 'N/A'}",
            f"  Firewall Rule Count : {len(item['FirewallRules'])}",
            "",
        ]

    lines += ["NETWORK POINTS OF INTEREST", "-" * width]
    if not pois:
        lines += ["No network-surface POIs were generated.", ""]
    for item in pois:
        lines += [
            "=" * width,
            f"[{item['POI']}] {item['ProcessName']} - {item['Protocol']} {item['LocalAddress']}:{item['LocalPort']}",
            "=" * width,
            f"Confidence           : {item['Confidence']}",
            f"Bind Scope           : {item['Scope']}",
            f"Privileged Context   : {item['PrivilegedContext']}",
            f"HTTP/S-like Port     : {item['HttpLikePort']}",
            f"Executable           : {item['Executable'] or 'Unavailable'}",
            "Why Review:",
        ]
        for reason in item["Reasons"]:
            lines.append(f"  - {reason}")
        lines += [
            "Manual Validation:",
            "  Confirm the listener belongs to the assessed client, determine whether it is expected,",
            "  test authentication/authorization from the appropriate local or network context, and",
            "  only create a finding when unauthorized access or another concrete weakness is validated.",
            "",
        ]

    lines += ["ACTIVE CONNECTIONS", "-" * width]
    if not active:
        lines.append("No active target-process TCP connections were captured at collection time.")
    for item in active:
        proc = by_pid.get(item["PID"], {})
        lines.append(
            f"{proc.get('Name', 'Unknown')} (PID {item['PID']}) | "
            f"{item['Protocol']} | {item['LocalAddress']}:{item['LocalPort']} -> "
            f"{item['RemoteAddress']}:{item['RemotePort']} | {item['Status']}"
        )

    history = (procmon_data or {}).get("network_activity") or []
    lines += ["", "HISTORICAL TARGET NETWORK EVENTS (PROCMON)", "-" * width,
              f"Historical network events retained: {len(history)}",
              "These are target-scoped historical operations, not verified listeners, current sockets, traffic content, or proof of plaintext/authentication failure.",
              "Live collection and historical operations are independently reported."]
    if not history:
        lines.append("No historical target network operations were collected.")
    else:
        from collections import Counter
        operations = Counter(str(item.get("Operation") or "Unknown") for item in history)
        for operation, count in operations.most_common(12):
            lines.append(f"  {operation}: {count}")
        seen_history = set()
        for item in history:
            identity = (str(item.get("Process") or ""), str(item.get("Operation") or ""), str(item.get("Path") or ""))
            if identity in seen_history:
                continue
            seen_history.add(identity)
            lines.append("  " + sanitize_report_text(
                f"{identity[0]} | {identity[1]} | {identity[2]}"))
            if len(seen_history) >= 15:
                break
        lines.append("Complete retained historical observations: procmon_network_activity.txt")

    if endpoint_errors:
        lines += ["", "COLLECTION WARNINGS", "-" * width]
        lines.extend(f"- {x}" for x in endpoint_errors)
    if firewall_error:
        lines += [
            "",
            "FIREWALL CORRELATION WARNING",
            "-" * width,
            firewall_error,
        ]

    (artifact_path(assessment_dir, "network_surface_review.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    allow_count = sum(1 for r in firewall_rules if str(r.get("Action") or "").lower() == "allow")
    block_count = sum(1 for r in firewall_rules if str(r.get("Action") or "").lower() == "block")
    broad_remote = sum(
        1 for r in firewall_rules
        if str(r.get("RemoteAddress") or "").strip().lower() in {"", "any", "*", "0.0.0.0/0", "::/0"}
    )
    profiles = {}
    for rule in firewall_rules:
        profile = str(rule.get("Profile") or "Unknown")
        profiles[profile] = profiles.get(profile, 0) + 1

    firewall_lines = [
        "WCA - TARGET FIREWALL RULES",
        "=" * width,
        "",
        "Purpose:",
        "  Shows enabled inbound Windows Firewall rules correlated to target executable paths.",
        "  Broad allow rules should be validated against the expected network exposure of the client.",
        "",
        "SUMMARY",
        "-" * width,
        f"Correlated enabled inbound rules : {len(firewall_rules)}",
        f"Allow rules                      : {allow_count}",
        f"Block rules                      : {block_count}",
        f"Broad/Any remote-address rules   : {broad_remote}",
    ]
    for profile, count in sorted(profiles.items()):
        firewall_lines.append(f"Profile {profile:26}: {count}")
    firewall_lines += ["", "RULE DETAILS", "-" * width]
    for idx, rule in enumerate(firewall_rules, 1):
        firewall_lines += [
            f"[FW-{idx:03d}] {rule.get('DisplayName') or rule.get('Name')}",
            f"  Action        : {rule.get('Action')}",
            f"  Profile       : {rule.get('Profile')}",
            f"  Program       : {rule.get('Program')}",
            f"  Protocol      : {rule.get('Protocol')}",
            f"  Local Port    : {rule.get('LocalPort')}",
            f"  Remote Port   : {rule.get('RemotePort')}",
            f"  Local Address : {rule.get('LocalAddress')}",
            f"  Remote Address: {rule.get('RemoteAddress')}",
            "",
        ]
    if firewall_error:
        firewall_lines += ["Collection warning:", firewall_error, ""]
    (artifact_path(assessment_dir, "target_firewall_rules.txt")).write_text(
        "\n".join(firewall_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    local_candidates = [
        item for item in records
        if item["Scope"] == "Loopback only" and item["HttpLikePort"]
    ]
    local_lines = [
        "WCA - LOCALHOST SERVICE CANDIDATES",
        "=" * width,
        "",
        "These endpoints are not actively probed by Windows Client Assessment.",
        "",
    ]
    if not local_candidates:
        local_lines.append("No loopback listeners on common HTTP/S-like ports were identified.")
    for idx, item in enumerate(local_candidates, 1):
        local_lines += [
            f"[LH-{idx:03d}] {item['ProcessName']} (PID {item['PID']})",
            f"  Endpoint   : {item['LocalAddress']}:{item['LocalPort']}",
            f"  Executable : {item['Executable']}",
            "  Tester Action:",
            "    Determine the protocol manually. If HTTP/S is confirmed, assess authentication,",
            "    authorization, CSRF/origin assumptions, privileged operations, and whether a lower-",
            "    privileged local process/user can invoke functionality intended for a trusted client.",
            "",
        ]
    (artifact_path(assessment_dir, "localhost_service_candidates.txt")).write_text(
        "\n".join(local_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    findings = []
    if pois:
        findings.append(
            {
                "title": "Runtime Network Interfaces Require Manual Validation",
                "severity": "Informational",
                "description": (
                    "Windows Client Assessment identified target-process listening interfaces that are exposed "
                    "beyond loopback and/or resemble local web-service endpoints based on common ports "
                    "or application configuration. These are review points and are not automatically vulnerabilities."
                ),
                "evidence": f"{len(pois)} POI-NW review record(s) generated.",
                "recommendation": (
                    "Validate expected exposure, authentication, authorization, and reachable "
                    "functionality from the appropriate local/network privilege context."
                ),
            }
        )

    return {
        "status": "WARN" if pois or no_target_process or endpoint_errors or firewall_error else "PASS",
        "details": (
            f"{len(processes)} correlated process(es); {len(records)} listening/bound endpoint(s); "
            f"{len(active)} active connection(s); {len(pois)} network POI(s)"
            + ("; no target process observed" if no_target_process else "")
            + ("; connection collection errors" if endpoint_errors else "")
            + ("; firewall correlation incomplete" if firewall_error else "")
        ),
        "findings": findings,
        "network_records": records,
        "historical_network_events": len(history),
        "network_pois": pois,
        "runtime_processes": processes,
        "coverage_gap": bool(no_target_process or endpoint_errors or firewall_error),
    }
