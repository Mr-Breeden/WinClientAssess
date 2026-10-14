from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
import json
import re
import tempfile
from utils.powershell import run_powershell
from utils.report_format import group_paths, format_bytes
from utils.privacy import sanitize_report_text, sanitize_snapshot_for_disk
from utils.path_filters import is_framework_snapshot_path


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _clean_error_text(value: str) -> str:
    return sanitize_report_text(ANSI_ESCAPE_RE.sub("", str(value or "")).strip())


def _ps_quote(value: str) -> str:
    return value.replace("'", "''")


def _as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []



def _snapshot_description(output_file: Path) -> tuple[str, str]:
    name = output_file.name.lower()
    if "post" in name:
        return (
            "Post-activity Windows system snapshot captured after the tester-controlled target workflow completed.",
            "Compare this file with snapshot_pre.json to identify services, tasks, registry keys, filesystem entries, drivers, persistence mechanisms, installed applications, and other system changes observed during the target activity window. Network state is collected separately during the dedicated Network Surface Review because point-in-time connections are volatile."
        )
    if "pre" in name:
        return (
            "Baseline Windows system snapshot captured before tester-controlled target activity.",
            "This file provides the comparison point used with snapshot_post.json to determine what changed during the target activity window."
        )
    return (
        "Windows system snapshot captured by Windows Client Assessment.",
        "This file records Windows state used by Windows Client Assessment differential-analysis modules."
    )


def _enrich_snapshot_metadata(data: dict, output_file: Path) -> dict:
    description, purpose = _snapshot_description(output_file)

    if isinstance(data, dict):
        filesystem = data.get("Filesystem", [])
        if isinstance(filesystem, dict):
            filesystem = [filesystem]
        if isinstance(filesystem, list):
            for entry in filesystem:
                if not isinstance(entry, dict):
                    continue
                length = entry.get("Length")
                entry["LengthHuman"] = format_bytes(length) if length not in (None, "") else None
    # Rebuild in the desired order so a human opening the JSON immediately sees why it exists.
    enriched = {
        "Description": description,
        "Purpose": purpose,
        "GeneratedBy": "WinClientAssess",
        "SnapshotFile": output_file.name,
    }
    metadata = data.get("Metadata", {}) if isinstance(data, dict) else {}
    if isinstance(metadata, dict):
        enriched["Metadata"] = metadata
    if isinstance(data, dict):
        for key, value in data.items():
            if key != "Metadata":
                enriched[key] = value
    return enriched


def capture_snapshot(output_file: Path, include_filesystem: bool = True):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    # PowerShell writes raw source state outside the assessment directory.
    # Only the privacy-filtered snapshot is ever written to the assessment.
    raw_temp = tempfile.TemporaryDirectory(prefix="wca-snapshot-")
    raw_output = Path(raw_temp.name) / "raw_snapshot.json"
    out = _ps_quote(str(raw_output))
    exclude_root = _ps_quote(str(output_file.parent))
    fs_flag = "$true" if include_filesystem else "$false"
    ps = rf"""
    $ErrorActionPreference = 'SilentlyContinue'
    $IncludeFilesystem = {fs_flag}
    $ExcludeRoot = '{exclude_root}'
    $SnapshotTempPrefix = if ($env:TEMP) {{ Join-Path $env:TEMP 'wca-snapshot-' }} else {{ '' }}
    $collectionErrors = @()

    try {{
      $services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId,Description)
      if($services.Count -eq 0) {{ throw 'Service enumeration returned zero records.' }}
    }} catch {{
      $services = @()
      $collectionErrors += "Services: $($_.Exception.Message)"
    }}

    try {{ $tasks = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object {{
      $task = $_
      [PSCustomObject]@{{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        State = [string]$task.State
        Principal = if($null -ne $task.Principal) {{$task.Principal.UserId}} else {{$null}}
        RunLevel = if($null -ne $task.Principal) {{[string]$task.Principal.RunLevel}} else {{""}}
        LogonType = if($null -ne $task.Principal) {{[string]$task.Principal.LogonType}} else {{""}}
        Actions = @($task.Actions | Where-Object {{ $null -ne $_ }} | ForEach-Object {{
          [PSCustomObject]@{{Execute=$_.Execute;Arguments=$_.Arguments;WorkingDirectory=$_.WorkingDirectory}}
        }})
        Triggers = @($task.Triggers | Where-Object {{ $null -ne $_ }} | ForEach-Object {{
          $trigger = $_
          $triggerType = ""
          $startBoundary = ""
          $endBoundary = ""
          $triggerEnabled = $null

          try {{
            if($null -ne $trigger.CimClass -and $null -ne $trigger.CimClass.CimClassName) {{
              $triggerType = [string]$trigger.CimClass.CimClassName
            }} else {{
              $triggerType = [string]$trigger.GetType().Name
            }}
          }} catch {{
            if($null -ne $trigger) {{ $triggerType = [string]$trigger.GetType().Name }}
          }}

          try {{ $startBoundary = [string]$trigger.StartBoundary }} catch {{ $startBoundary = "" }}
          try {{ $endBoundary = [string]$trigger.EndBoundary }} catch {{ $endBoundary = "" }}
          try {{ $triggerEnabled = [bool]$trigger.Enabled }} catch {{ $triggerEnabled = $null }}

          [PSCustomObject]@{{
            Type = $triggerType
            StartBoundary = $startBoundary
            EndBoundary = $endBoundary
            Enabled = $triggerEnabled
          }}
        }})
      }}
    }}) }} catch {{
      $tasks = @()
      $collectionErrors += "ScheduledTasks: $($_.Exception.Message)"
    }}

    $run = @()
    $runKeys = @(
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach($k in $runKeys) {{
      if(Test-Path $k) {{
        $props=Get-ItemProperty $k
        foreach($p in $props.PSObject.Properties) {{
          if($p.Name -notmatch '^PS') {{ $run += [PSCustomObject]@{{Key=$k;Name=$p.Name;Value=[string]$p.Value}} }}
        }}
      }}
    }}

    $envVars = @()
    foreach($entry in [Environment]::GetEnvironmentVariables('Machine').GetEnumerator()) {{
      $envVars += [PSCustomObject]@{{Scope='Machine';Name=[string]$entry.Key;Value=[string]$entry.Value}}
    }}
    foreach($entry in [Environment]::GetEnvironmentVariables('User').GetEnumerator()) {{
      $envVars += [PSCustomObject]@{{Scope='User';Name=[string]$entry.Key;Value=[string]$entry.Value}}
    }}

    try {{
      $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ServiceType)
      if($drivers.Count -eq 0) {{ throw 'Driver enumeration returned zero records.' }}
    }} catch {{
      $drivers = @()
      $collectionErrors += "Drivers: $($_.Exception.Message)"
    }}

    $installedApps = @()
    $uninstallRoots = @(
      'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
      'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
      'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach($root in $uninstallRoots) {{
      $installedApps += @(Get-ItemProperty $root | Where-Object {{$_.DisplayName}} | ForEach-Object {{
        [PSCustomObject]@{{
          DisplayName=$_.DisplayName; DisplayVersion=$_.DisplayVersion; Publisher=$_.Publisher;
          InstallLocation=$_.InstallLocation; UninstallString=$_.UninstallString; PSPath=$_.PSPath
        }}
      }})
    }}

    $protocols = @()
    $fileAssoc = @()
    foreach($classRoot in @('HKLM:\Software\Classes','HKCU:\Software\Classes')) {{
      if(Test-Path $classRoot) {{
        foreach($k in Get-ChildItem $classRoot) {{
          $name = $k.PSChildName
          if($name.StartsWith('.')) {{
            $default = $k.GetValue('', $null)
            $fileAssoc += [PSCustomObject]@{{Root=$classRoot;Extension=$name;ProgId=[string]$default}}
          }} else {{
            try {{
              $url = $k.GetValue('URL Protocol', $null)
              if($null -ne $url) {{
                $cmdKey = Join-Path $k.PSPath 'shell\open\command'
                $cmd = $null
                if(Test-Path $cmdKey) {{ $cmdItem = Get-Item -LiteralPath $cmdKey; $cmd = $cmdItem.GetValue('', $null) }}
                $protocols += [PSCustomObject]@{{Root=$classRoot;Scheme=$name;Command=[string]$cmd}}
              }}
            }} catch {{}}
          }}
        }}
      }}
    }}

    $registryKeys = @()
    foreach($root in @('HKLM:\Software','HKLM:\Software\WOW6432Node','HKCU:\Software')) {{
      if(Test-Path $root) {{
        foreach($k1 in Get-ChildItem $root) {{
          $registryKeys += [PSCustomObject]@{{Path=$k1.Name}}
          foreach($k2 in Get-ChildItem $k1.PSPath) {{ $registryKeys += [PSCustomObject]@{{Path=$k2.Name}} }}
        }}
      }}
    }}

    $filesystem = @()
    if($IncludeFilesystem) {{
      $roots = @($env:ProgramFiles, ${{env:ProgramFiles(x86)}}, $env:ProgramData, $env:LOCALAPPDATA, $env:APPDATA) |
        Where-Object {{ $_ -and (Test-Path $_) }} | Select-Object -Unique
      foreach($root in $roots) {{
        $filesystem += [PSCustomObject]@{{Path=$root;IsDirectory=$true;Length=$null;LastWriteTimeUtc=$null;Root=$root;IsReparsePoint=$false;LinkType=$null}}
        $filesystem += @(Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object {{
          -not $_.FullName.StartsWith($ExcludeRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
          (-not $SnapshotTempPrefix -or -not $_.FullName.StartsWith($SnapshotTempPrefix, [System.StringComparison]::OrdinalIgnoreCase))
        }} | ForEach-Object {{
          [PSCustomObject]@{{
            Path=$_.FullName
            IsDirectory=[bool]$_.PSIsContainer
            Length=if($_.PSIsContainer){{$null}}else{{$_.Length}}
            LastWriteTimeUtc=$_.LastWriteTimeUtc.ToString('o')
            Root=$root
            IsReparsePoint=[bool](($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            LinkType=if(($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){{[string]$_.LinkType}}else{{$null}}
          }}
        }})
      }}
      if($env:TEMP -and (Test-Path $env:TEMP)) {{
        $filesystem += @(Get-ChildItem -LiteralPath $env:TEMP -Force | Where-Object {{
          -not $_.FullName.StartsWith($ExcludeRoot, [System.StringComparison]::OrdinalIgnoreCase) -and
          (-not $SnapshotTempPrefix -or -not $_.FullName.StartsWith($SnapshotTempPrefix, [System.StringComparison]::OrdinalIgnoreCase))
        }} | ForEach-Object {{
          [PSCustomObject]@{{
            Path=$_.FullName; IsDirectory=[bool]$_.PSIsContainer;
            Length=if($_.PSIsContainer){{$null}}else{{$_.Length}};
            LastWriteTimeUtc=$_.LastWriteTimeUtc.ToString('o'); Root=$env:TEMP;
            IsReparsePoint=[bool](($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0);
            LinkType=if(($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){{[string]$_.LinkType}}else{{$null}}
          }}
        }})
      }}
    }}

    $snapshot = [PSCustomObject]@{{
      Metadata=[PSCustomObject]@{{Captured=(Get-Date).ToString('o');FilesystemIncluded=$IncludeFilesystem;CollectionErrors=@($collectionErrors)}}
      Services=$services
      ScheduledTasks=$tasks
      RunEntries=$run
      EnvironmentVariables=$envVars
      Drivers=$drivers
      InstalledApplications=$installedApps
      ProtocolHandlers=$protocols
      FileAssociations=$fileAssoc
      RegistryKeys=$registryKeys
      Filesystem=$filesystem
    }}
    $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath '{out}' -Encoding UTF8
    """
    try:
        result = run_powershell(ps, timeout=1200)
        if result["returncode"] != 0 or not raw_output.exists():
            error_text = _clean_error_text(result.get("stderr") or result.get("stdout") or "Unknown PowerShell error")
            output_file.write_text(
                json.dumps(
                    {
                        "error": error_text,
                        "note": "Snapshot capture failed. Full-mode differential results are not valid for this run.",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            first_line = error_text.splitlines()[0] if error_text else "Unknown PowerShell error"
            return {
                "status": "WARN",
                "details": f"Windows snapshot capture failed: {first_line}",
                "snapshot": None,
            }
        try:
            data = json.loads(raw_output.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            output_file.write_text(json.dumps({"error": "Snapshot JSON invalid", "note": "Critical baseline unavailable"}, indent=2), encoding="utf-8")
            return {"status": "WARN", "details": f"Snapshot JSON could not be parsed: {exc}", "snapshot": None}

        # The in-flight temporary JSON directory can itself be enumerated by the
        # Windows TEMP inventory; remove it from both in-memory and persisted data.
        if isinstance(data, dict):
            filesystem = _as_list(data.get("Filesystem"))
            clean = [entry for entry in filesystem if not (
                isinstance(entry, dict) and is_framework_snapshot_path(entry.get("Path"))
            )]
            if len(clean) != len(filesystem):
                data["Filesystem"] = clean
                metadata = data.get("Metadata")
                if isinstance(metadata, dict):
                    metadata["FrameworkTempEntriesExcluded"] = len(filesystem) - len(clean)
        data = _enrich_snapshot_metadata(data, output_file)
        output_file.write_text(json.dumps(sanitize_snapshot_for_disk(data), indent=2, default=str), encoding="utf-8")

        metadata = data.get("Metadata", {}) if isinstance(data, dict) else {}
        collection_errors = _as_list(metadata.get("CollectionErrors", []))
        if collection_errors:
            return {
                "status": "WARN",
                "details": "Critical snapshot collection failed: " + "; ".join(str(x) for x in collection_errors),
                "snapshot": None,
                "partial_snapshot": data,
            }

        fs_count = len(_as_list(data.get("Filesystem", [])))
        return {
            "status": "PASS",
            "details": f"Snapshot written to {output_file.name}; {fs_count} filesystem entries",
            "snapshot": data,
        }
    finally:
        raw_temp.cleanup()


def _keyed(items, keys):
    out = {}
    for item in _as_list(items):
        if isinstance(item, dict):
            out["|".join(str(item.get(k, "")) for k in keys)] = item
    return out


def _diff(pre_items, post_items, keys):
    pre = _keyed(pre_items, keys)
    post = _keyed(post_items, keys)
    return {
        "added": [post[k] for k in sorted(set(post) - set(pre))],
        "removed": [pre[k] for k in sorted(set(pre) - set(post))],
        "changed": [
            {"before": pre[k], "after": post[k]}
            for k in sorted(set(pre) & set(post))
            if pre[k] != post[k]
        ],
    }


def compare_snapshots(pre, post):
    return {
        "Services": _diff(pre.get("Services", []), post.get("Services", []), ["Name"]),
        "ScheduledTasks": _diff(pre.get("ScheduledTasks", []), post.get("ScheduledTasks", []), ["TaskPath", "TaskName"]),
        "RunEntries": _diff(pre.get("RunEntries", []), post.get("RunEntries", []), ["Key", "Name"]),
        "EnvironmentVariables": _diff(pre.get("EnvironmentVariables", []), post.get("EnvironmentVariables", []), ["Scope", "Name"]),
        "Drivers": _diff(pre.get("Drivers", []), post.get("Drivers", []), ["Name"]),
        "InstalledApplications": _diff(pre.get("InstalledApplications", []), post.get("InstalledApplications", []), ["DisplayName", "DisplayVersion", "Publisher"]),
        "ProtocolHandlers": _diff(pre.get("ProtocolHandlers", []), post.get("ProtocolHandlers", []), ["Root", "Scheme"]),
        "FileAssociations": _diff(pre.get("FileAssociations", []), post.get("FileAssociations", []), ["Root", "Extension"]),
        "RegistryKeys": _diff(pre.get("RegistryKeys", []), post.get("RegistryKeys", []), ["Path"]),
        "Filesystem": _diff(pre.get("Filesystem", []), post.get("Filesystem", []), ["Path"]),
    }


def _write_items(path: Path, title: str, items, formatter=lambda x: json.dumps(x, default=str)):
    width = 104
    lines = [
        title.upper(),
        "=" * width,
        "",
        "Purpose:",
        "  Provides a grouped inventory of changes observed between baseline/post-activity snapshots.",
        "  Observed change does not establish target causation; corroborate target ownership.",
        "  WindowsApps entries are separately labeled UNATTRIBUTED, not silently assigned to the client.",
        "",
        f"Total entries: {len(items)}",
    ]
    grouped = group_paths(
        items,
        path_getter=lambda x: str(x.get("Path", "")) if isinstance(x, dict) else str(x),
        root_getter=lambda x: str(x.get("Root", "")) if isinstance(x, dict) else "",
    )
    lines += ["", "SUMMARY BY ROOT", "-" * width]
    for group, group_items in grouped:
        lines.append(f"{group:28} {len(group_items):>8}")
    for group, group_items in grouped:
        lines += ["", group.upper(), "-" * width]
        for idx, item in enumerate(group_items, 1):
            lines.append(f"[{idx:04d}] {formatter(item)}")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _humanize_category(name: str) -> str:
    """
    Convert internal snapshot keys such as FileAssociations and ScheduledTasks
    into human-readable report labels.
    """
    import re

    text = str(name or "").strip()
    if not text:
        return text

    # Handle common acronyms before generic CamelCase splitting.
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _section_banner(title: str, width: int = 88):
    return [
        "",
        "=" * width,
        title.upper(),
        "=" * width,
        "",
    ]


def _subsection(title: str, count: int, width: int = 88):
    return [
        "",
        f"{title} ({count})",
        "-" * width,
    ]


def _append_mapping(lines, item, indent="    "):
    if not isinstance(item, dict):
        lines.append(f"{indent}{item}")
        return

    preferred = [
        "Path", "Name", "DisplayName", "TaskName", "TaskPath", "Key", "Scheme",
        "Extension", "DisplayVersion", "Publisher", "StartName", "StartMode",
        "PathName", "Principal", "RunLevel", "Value", "LocalAddress", "LocalPort",
        "RemoteAddress", "RemotePort", "State", "OwningProcess", "IsDirectory",
        "LengthHuman", "Length", "LastWriteTimeUtc", "Root",
    ]
    ordered = [key for key in preferred if key in item]
    ordered += [key for key in item if key not in ordered]

    for key in ordered:
        value = item.get(key)
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, indent=2, default=str)
            rendered_lines = rendered.splitlines()
            lines.append(f"{indent}{key}:")
            lines.extend(f"{indent}  {line}" for line in rendered_lines)
        else:
            if key in {"Length", "FileSize", "SizeBytes", "size_bytes"} and value not in (None, ""):
                value = format_bytes(value)
            lines.append(f"{indent}{key}: {value}")


def _append_change_record(lines, number: int, item, change_type: str, *, unattributed=False):
    lines.append(f"[{number:04d}] {change_type}")
    if unattributed:
        lines.append("    Attribution: WindowsApps / UNATTRIBUTED; correlate before linking to the target")
    if change_type == "CHANGED" and isinstance(item, dict):
        lines.append("    Before:")
        _append_mapping(lines, item.get("before", {}), indent="        ")
        lines.append("    After:")
        _append_mapping(lines, item.get("after", {}), indent="        ")
    else:
        _append_mapping(lines, item, indent="    ")
    lines.append("")


def _windowsapps_entry(item) -> bool:
    """Flag only WindowsApps paths; retain records and original evidence."""
    if not isinstance(item, dict):
        return False
    if "before" in item or "after" in item:
        return any(_windowsapps_entry(part) for part in (item.get("before"), item.get("after")))
    path = str(item.get("Path") or "").replace("/", "\\").casefold()
    markers = ("\\program files\\windowsapps", "\\program files (x86)\\windowsapps")
    return any(marker + "\\" in path or path.endswith(marker) for marker in markers)


def _attribution_summary(filesystem: dict, width: int) -> list[str]:
    added = filesystem.get("added", [])
    removed = filesystem.get("removed", [])
    changed = filesystem.get("changed", [])
    windowsapps = [sum(_windowsapps_entry(item) for item in group)
                   for group in (added, removed, changed)]
    other = [len(group) - count for group, count in zip((added, removed, changed), windowsapps)]
    return ["", "FILESYSTEM ATTRIBUTION TRIAGE", "-" * width,
            "Snapshot differences are temporal observations, not proof the assessed target caused each change.",
            "WindowsApps activity is UNATTRIBUTED host activity unless separately correlated to the target.",
            f"{'Observed group':40} {'Added':>8} {'Removed':>8} {'Changed':>8}",
            f"{'WindowsApps (unattributed)':40} {windowsapps[0]:>8} {windowsapps[1]:>8} {windowsapps[2]:>8}",
            f"{'Other (still requires correlation)':40} {other[0]:>8} {other[1]:>8} {other[2]:>8}",
            "All observed changes remain in the detailed inventories and authoritative snapshots.", ""]


def write_snapshot_diff(diff, assessment_dir: Path):
    # Reporting copy only: preserve raw in-memory diff for current-run analysis.
    diff = sanitize_snapshot_for_disk(diff)
    width = 88
    lines = [
        "WCA - SYSTEM CHANGE ANALYSIS",
        "=" * width,
        "",
        "Purpose:",
        "  Summarizes differences between the baseline and post-activity Windows",
        "  snapshots. Each category is separated into ADDED, REMOVED, and CHANGED records so",
        "  individual entries can be reviewed and captured as assessment evidence.",
        "  Broad snapshots may include unrelated Windows/system maintenance; validate attribution.",
        "",
        "CHANGE SUMMARY",
        "-" * width,
        f"{'Category':28} {'Added':>10} {'Removed':>10} {'Changed':>10}",
        "-" * width,
    ]

    for category, changes in diff.items():
        display_category = _humanize_category(category)
        lines.append(
            f"{display_category:28} "
            f"{len(changes.get('added', [])):>10} "
            f"{len(changes.get('removed', [])):>10} "
            f"{len(changes.get('changed', [])):>10}"
        )

    filesystem = diff.get("Filesystem", {})
    lines += _attribution_summary(filesystem, width)

    for category, changes in diff.items():
        display_category = _humanize_category(category)
        lines += _section_banner(f"{display_category} Changes", width)
        lines += [
            f"Added:   {len(changes.get('added', []))}",
            f"Removed: {len(changes.get('removed', []))}",
            f"Changed: {len(changes.get('changed', []))}",
        ]

        added = changes.get("added", [])
        removed = changes.get("removed", [])
        changed = changes.get("changed", [])

        lines += _subsection("ADDED", len(added), width)
        if not added:
            lines.append("None")
        for idx, item in enumerate(added, 1):
            _append_change_record(lines, idx, item, "ADDED", unattributed=category == "Filesystem" and _windowsapps_entry(item))

        lines += _subsection("REMOVED", len(removed), width)
        if not removed:
            lines.append("None")
        for idx, item in enumerate(removed, 1):
            _append_change_record(lines, idx, item, "REMOVED", unattributed=category == "Filesystem" and _windowsapps_entry(item))

        lines += _subsection("CHANGED", len(changed), width)
        if not changed:
            lines.append("None")
        for idx, item in enumerate(changed, 1):
            _append_change_record(lines, idx, item, "CHANGED", unattributed=category == "Filesystem" and _windowsapps_entry(item))

    (artifact_path(assessment_dir, "install_changes.txt")).write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    added_files = [x for x in filesystem.get("added", []) if not x.get("IsDirectory")]
    added_dirs = [x for x in filesystem.get("added", []) if x.get("IsDirectory")]
    _write_items(
        artifact_path(assessment_dir, "installed_files.txt"),
        "Snapshot Added Files (Attribution Requires Correlation)",
        added_files,
        lambda x: (
            f"{x.get('Path', '')} | Size: {format_bytes(x.get('Length'))}"
            if x.get("Length") not in (None, "")
            else str(x.get("Path", ""))
        ),
    )
    _write_items(
        artifact_path(assessment_dir, "installed_directories.txt"),
        "Snapshot Added Directories (Attribution Requires Correlation)",
        added_dirs,
        lambda x: str(x.get("Path", "")),
    )

    fs_lines = [
        "FILESYSTEM CHANGES",
        "=" * width,
        "",
        "Summary",
        "-" * width,
        f"Added files:        {len(added_files)}",
        f"Added directories:  {len(added_dirs)}",
        f"Removed entries:    {len(filesystem.get('removed', []))}",
        f"Changed metadata:   {len(filesystem.get('changed', []))}",
        "",
        *_attribution_summary(filesystem, width),
        "ADDED ENTRY SUMMARY BY ROOT",
        "-" * width,
    ]
    added_grouped = group_paths(
        filesystem.get("added", []),
        path_getter=lambda x: str(x.get("Path", "")),
        root_getter=lambda x: str(x.get("Root", "")),
    )
    for group_name, group_items in added_grouped:
        fs_lines.append(f"{group_name:28} {len(group_items):>8}")
    fs_sections = [
        ("ADDED FILES", added_files, lambda x: (
            f"{x.get('Path', '')} | Size: {format_bytes(x.get('Length'))}"
            if x.get("Length") not in (None, "")
            else str(x.get("Path", ""))
        )),
        ("ADDED DIRECTORIES", added_dirs, lambda x: str(x.get("Path", ""))),
        ("REMOVED", filesystem.get("removed", []), lambda x: (
            f"{x.get('Path', '')} | Size: {format_bytes(x.get('Length'))}"
            if x.get("Length") not in (None, "")
            else str(x.get("Path", ""))
        )),
        ("CHANGED METADATA", filesystem.get("changed", []), lambda x: str(x.get("after", {}).get("Path", ""))),
    ]
    for title, items, formatter in fs_sections:
        fs_lines += _subsection(title, len(items), width)
        if not items:
            fs_lines.append("None")
        else:
            # Show non-WindowsApps entries first; background-prone changes are
            # still retained in full but cannot swamp the target triage view.
            unrelated = [item for item in items if _windowsapps_entry(item)]
            other = [item for item in items if not _windowsapps_entry(item)]
            for label, partition in (("OTHER CHANGES (ATTRIBUTION REQUIRES CORRELATION)", other),
                                     ("WINDOWSAPPS (UNATTRIBUTED HOST ACTIVITY)", unrelated)):
                if not partition:
                    continue
                fs_lines += ["", f"{label}: {len(partition)}", "." * min(width, len(label) + 14)]
                for idx, item in enumerate(partition, 1):
                    fs_lines.append(f"[{idx:04d}] {formatter(item)}")

    (artifact_path(assessment_dir, "filesystem_changes.txt")).write_text(
        "\n".join(fs_lines).rstrip() + "\n",
        encoding="utf-8",
    )

    registry = diff.get("RegistryKeys", {})
    reg_lines = [
        "REGISTRY CHANGES",
        "=" * width,
        "",
        "Summary",
        "-" * width,
        f"Added keys:   {len(registry.get('added', []))}",
        f"Removed keys: {len(registry.get('removed', []))}",
    ]

    for title, items, prefix_symbol in [
        ("ADDED KEYS", registry.get("added", []), "+"),
        ("REMOVED KEYS", registry.get("removed", []), "-"),
    ]:
        reg_lines += _subsection(title, len(items), width)
        if not items:
            reg_lines.append("None")
        for idx, item in enumerate(items, 1):
            reg_lines.append(f"[{idx:04d}] {prefix_symbol} {item.get('Path', '')}")

    (artifact_path(assessment_dir, "registry_changes.txt")).write_text(
        "\n".join(reg_lines).rstrip() + "\n",
        encoding="utf-8",
    )
