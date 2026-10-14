"""Read-only Windows Installer table review.

The MSI COM automation interface exposes record fields as indexed properties.
Enumerate _Tables and _Columns instead of assuming optional tables exist or
trusting PowerShell's dynamic binding of Record.FieldCount (which returned zero
on a real Windows field test even though records were fetched).
"""
from __future__ import annotations
from utils.assessment_layout import artifact_path

from pathlib import Path
import re

from utils.powershell import run_powershell_json
from utils.privacy import sanitize_report_text
from utils.report_format import header, section, kv, format_bytes


TABLES = [
    "Property", "Directory", "Component", "File", "Registry",
    "ServiceInstall", "ServiceControl", "CustomAction",
    "InstallExecuteSequence", "Environment", "Shortcut", "Binary",
]
CORE_TABLES = {"Property", "Directory", "Component", "File"}

# Legacy index mapping for tests or an older collector that returns Field1 etc.
# The native p3 collector returns the authoritative _Columns column names.
SCHEMAS = {
    "Property": ["Property", "Value"],
    "Directory": ["Directory", "Directory_Parent", "DefaultDir"],
    "Component": ["Component", "ComponentId", "Directory_", "Attributes", "Condition", "KeyPath"],
    "File": ["File", "Component_", "FileName", "FileSize", "Version", "Language", "Attributes", "Sequence"],
    "Registry": ["Registry", "Root", "Key", "Name", "Value", "Component_"],
    "ServiceInstall": ["ServiceInstall", "Name", "DisplayName", "ServiceType", "StartType", "ErrorControl", "LoadOrderGroup", "Dependencies", "StartName", "Password", "Arguments", "Component_", "Description"],
    "ServiceControl": ["ServiceControl", "Name", "Event", "Arguments", "Wait", "Component_"],
    "CustomAction": ["Action", "Type", "Source", "Target", "ExtendedType"],
    "InstallExecuteSequence": ["Action", "Condition", "Sequence"],
    "Environment": ["Environment", "Name", "Value", "Component_"],
    "Shortcut": ["Shortcut", "Directory_", "Name", "Component_", "Target", "Arguments", "Description", "Hotkey", "Icon_", "IconIndex", "ShowCmd", "WkDir"],
    "Binary": ["Name", "Data"],
}

PRIORITY_TABLES = [
    "CustomAction", "InstallExecuteSequence", "ServiceInstall",
    "ServiceControl", "Registry", "Environment",
]

# A field test found real MSI tables and row counts, but *every row was empty*.
# These key columns must exist and have values for non-empty tables. Empty rows
# are never evidence of a successful MSI review.
ROW_IDENTIFIERS = {name: schema[0] for name, schema in SCHEMAS.items()}
MANDATORY_ROW_VALUES = {
    "Directory": ("Directory", "DefaultDir"),
    "Component": ("Component", "Directory_"),
    "File": ("File", "Component_", "FileName"),
    "CustomAction": ("Action", "Type"),
    "InstallExecuteSequence": ("Action", "Sequence"),
}


def _powershell_query(msi: Path) -> str:
    safe = str(msi).replace("'", "''")
    table_array = ",".join(f"'{name}'" for name in TABLES)
    return rf"""
    $ErrorActionPreference = 'Stop'
    $tableNames = @({table_array})
    $all = [ordered]@{{}}
    $errors = [ordered]@{{}}
    $absent = @()

    # Windows Installer's Record.StringData and Record.IntegerData are indexed
    # COM properties, not ordinary .NET methods. InvokeMember/GetProperty avoids
    # the PowerShell dynamic FieldCount/StringData issue seen in v1.2.3-p2.
    function Read-MsiString($record, [int]$position) {{
      return [string]$record.GetType().InvokeMember(
        'StringData', [System.Reflection.BindingFlags]::GetProperty,
        $null, $record, @($position))
    }}
    function Read-MsiInt($record, [int]$position) {{
      return [int]$record.GetType().InvokeMember(
        'IntegerData', [System.Reflection.BindingFlags]::GetProperty,
        $null, $record, @($position))
    }}

    try {{
      $installer = New-Object -ComObject WindowsInstaller.Installer -ErrorAction Stop
      $db = $installer.OpenDatabase('{safe}', 0)

      # _Tables contains only tables that actually exist. Absence of optional
      # ServiceInstall/ServiceControl/Environment/Shortcut is not a query error.
      $tableSet = @{{}}
      $tableView = $db.OpenView('SELECT * FROM `_Tables`')
      try {{
        [void]$tableView.Execute()
        while ($null -ne ($tableRecord = $tableView.Fetch())) {{
          $tableSet[(Read-MsiString $tableRecord 1)] = $true
        }}
      }} finally {{
        [void]$tableView.Close()
      }}
      if ($tableSet.Count -eq 0) {{ throw 'MSI _Tables returned no table names' }}

      # _Columns provides the actual field positions AND types; relying on
      # Record.FieldCount silently produced blank CustomAction/Registry reports.
      $columnMap = @{{}}
      $columnView = $db.OpenView('SELECT * FROM `_Columns`')
      try {{
        [void]$columnView.Execute()
        while ($null -ne ($columnRecord = $columnView.Fetch())) {{
          $table = Read-MsiString $columnRecord 1
          $number = Read-MsiInt $columnRecord 2
          $name = Read-MsiString $columnRecord 3
          $type = Read-MsiInt $columnRecord 4
          if ([string]::IsNullOrWhiteSpace($table) -or
              [string]::IsNullOrWhiteSpace($name) -or $number -lt 1) {{
            throw 'Invalid _Columns metadata returned by Windows Installer'
          }}
          if (-not $columnMap.ContainsKey($table)) {{ $columnMap[$table] = @() }}
          $columnMap[$table] += [PSCustomObject]@{{
            Number = $number; Name = $name; IsString = (($type -band 2048) -ne 0)
          }}
        }}
      }} finally {{
        [void]$columnView.Close()
      }}

      foreach ($table in $tableNames) {{
        if (-not $tableSet.ContainsKey($table)) {{
          $all[$table] = $null
          $absent += $table
          continue
        }}
        $view = $null
        try {{
          if (-not $columnMap.ContainsKey($table)) {{
            throw "Present table $table has no _Columns metadata"
          }}
          $columns = @($columnMap[$table] | Sort-Object Number)
          $view = $db.OpenView("SELECT * FROM ``$table``")
          [void]$view.Execute()
          $rows = New-Object 'System.Collections.Generic.List[object]'
          while ($null -ne ($record = $view.Fetch())) {{
            $row = [ordered]@{{}}
            foreach ($column in $columns) {{
              $index = [int]$column.Number
              $name = [string]$column.Name
              if ($table -eq 'Binary' -and $name -eq 'Data') {{
                $value = '<binary stream; content not exported>'
              }} elseif ($column.IsString) {{
                $value = Read-MsiString $record $index
              }} else {{
                $number = Read-MsiInt $record $index
                $value = if ($number -eq [int]::MinValue) {{ '' }} else {{ [string]$number }}
              }}
              $row[$name] = $value
            }}
            [void]$rows.Add([PSCustomObject]$row)
          }}
          $all[$table] = @($rows.ToArray())
        }} catch {{
          $errors[$table] = $_.Exception.Message
          $all[$table] = @()
        }} finally {{
          if ($null -ne $view) {{ [void]$view.Close() }}
        }}
      }}
    }} catch {{
      $errors['Database'] = $_.Exception.Message
      foreach ($table in $tableNames) {{
        if (-not $all.Contains($table)) {{ $all[$table] = @() }}
      }}
    }}

    # The only pipeline output must be this one JSON-serializable object.
    [PSCustomObject]@{{
      Tables = [PSCustomObject]$all
      Errors = [PSCustomObject]$errors
      Absent = @($absent)
    }}
    """


def _query_tables(msi: Path):
    data, result = run_powershell_json(_powershell_query(msi), timeout=240)
    output = {name: [] for name in TABLES}
    if not isinstance(data, dict):
        message = result.get("stderr") or result.get("stdout") or "No parseable MSI data returned."
        return output, {"PowerShell": message}

    tables = data.get("Tables", {})
    errors = data.get("Errors", {})
    absent = data.get("Absent", [])
    if not isinstance(tables, dict):
        tables = {}
        errors = {"Collection": "Windows Installer did not return table data."}
    if not isinstance(errors, dict):
        errors = {"Collection": str(errors)}
    if isinstance(absent, str):
        absent = [absent]
    if not isinstance(absent, list):
        errors["Collection"] = "Invalid absent-table metadata received."
        absent = []
    absent = set(absent)

    for table in TABLES:
        if table in absent:
            output[table] = None  # An absent optional table is different from zero rows.
            if table in CORE_TABLES:
                errors[table] = "Required MSI table is absent."
            continue
        rows = tables.get(table)
        if rows is None:
            if table not in errors:
                errors[table] = "Present table did not return usable rows."
            continue
        if isinstance(rows, dict):
            rows = [rows]  # ConvertTo-Json can flatten a one-row collection.
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            errors[table] = "Invalid MSI row data returned."
            continue
        output[table] = rows
    return output, errors


def _named_row(table, row):
    if not isinstance(row, dict):
        return {}
    if any(not re.fullmatch(r"Field\d+", key) for key in row):
        # p3: _Columns supplies authoritative column names (not guessed positions).
        return row
    schema = SCHEMAS.get(table, [])
    result = {}
    for key, value in sorted(row.items(), key=lambda pair: int(pair[0][5:])):
        index = int(key[5:]) - 1
        result[schema[index] if index < len(schema) else key] = value
    return result


def _valid_rows(collected):
    errors = {}
    for table, rows in collected.items():
        if rows is None or not rows:
            continue
        primary = ROW_IDENTIFIERS.get(table)
        for index, raw in enumerate(rows, 1):
            row = _named_row(table, raw)
            if not row or not any(str(value or "").strip() for value in row.values()):
                errors[table] = f"Row {index} contained no decoded field values."
                break
            required = MANDATORY_ROW_VALUES.get(table, (primary,) if primary else ())
            missing = [name for name in required if not str(row.get(name) or "").strip()]
            if missing:
                errors[table] = f"Row {index} is missing its required {', '.join(missing)} value."
                break
    return errors


def _display_value(value):
    """Keep untrusted MSI text to one terminal/report line."""
    value = str(value if value is not None else "")
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in value)


def _render_table(lines, table, rows, width=104, max_rows=500):
    if rows is None:
        lines += section(table, width)
        lines.append("NOT PRESENT in this MSI (not a collection failure).")
        return
    lines += section(table, width, len(rows))
    if not rows:
        lines.append("Present, but no rows.")
        return
    for idx, row in enumerate(rows[:max_rows], 1):
        named = _named_row(table, row)
        lines.append(f"[{table.upper()}-{idx:03d}]")
        for key, value in named.items():
            if key == "Data" and table == "Binary":
                value = "<binary stream; content not exported>"
            elif key in {"FileSize", "Size", "Length"} and value not in (None, ""):
                value = format_bytes(value)
            lines.append(kv(key, _display_value(value), 24, "  "))
        lines.append("")
    if len(rows) > max_rows:
        lines.append(f"... {len(rows) - max_rows} additional row(s) omitted from text output ...")


def _render_custom_action_correlation(lines, collected, width):
    custom_actions = collected.get("CustomAction") or []
    if not custom_actions:
        return
    sequence = {
        row.get("Action"): row
        for raw in (collected.get("InstallExecuteSequence") or [])
        if (row := _named_row("InstallExecuteSequence", raw)).get("Action")
    }
    lines += section("Custom Action Execution Correlation", width, len(custom_actions))
    lines.append("Action, execution type, payload source/target and execute-sequence placement (if scheduled).")
    for raw in custom_actions[:500]:
        row = _named_row("CustomAction", raw)
        action = str(row.get("Action", ""))
        scheduled = sequence.get(action, {})
        lines.append("")
        for key in ("Action", "Type", "Source", "Target"):
            lines.append(kv(key, _display_value(row.get(key, "")), 24, "  "))
        if scheduled:
            lines.append(kv("Sequence", _display_value(scheduled.get("Sequence", "")), 24, "  "))
            lines.append(kv("Condition", _display_value(scheduled.get("Condition", "")), 24, "  "))
        else:
            lines.append("  Execution sequence      : Not in InstallExecuteSequence (may be UI-only or indirect)")


def run_msi_analysis(installer: Path, assessment_dir: Path):
    width = 104
    collected, errors = _query_tables(installer)
    errors = dict(errors)
    errors.update({key: value for key, value in _valid_rows(collected).items() if key not in errors})
    empty_core = sorted(table for table in CORE_TABLES if not collected.get(table))
    collection_valid = not errors and not empty_core
    absent_optional = [table for table in TABLES if table not in CORE_TABLES and collected.get(table) is None]

    lines = header(
        "Windows Client Assessment - MSI Analysis",
        [
            "Parses Windows Installer database tables and presents security-relevant tables first.",
            "Custom actions, service installation, registry writes, and execution sequencing should receive priority review.",
            "Absent optional tables are normal; failures reading a present table are not.",
        ], width,
    )
    lines += ["TABLE SUMMARY", "-" * width, f"{'Table':30} {'Rows':>8} {'Priority':>12}", "-" * width]
    for table in TABLES:
        rows = collected.get(table)
        priority = "REVIEW" if table in PRIORITY_TABLES and rows else ""
        count = "ABSENT" if rows is None else str(len(rows))
        lines.append(f"{table:30} {count:>8} {priority:>12}")
    if absent_optional:
        lines += section("Optional Tables Not Present", width)
        lines.append(", ".join(absent_optional))
        lines.append("These tables are not part of this installer; their absence is not a collector error.")
    if errors or empty_core:
        lines += section("Collection Diagnostics", width)
        for source, message in sorted(errors.items()):
            lines.append(kv(source, _display_value(message), 24))
        if empty_core:
            lines.append(kv("Empty/missing core tables", ", ".join(empty_core), 24))
            lines.append(kv("Empty required tables", ", ".join(empty_core), 24))
        lines.append("MSI analysis is incomplete and must not be treated as a successful table review.")

    lines += section("Recommended Review Workflow", width)
    lines += [
        "1. Review CustomAction for executable, DLL, script, command-line, or deferred actions.",
        "2. Correlate CustomAction entries with InstallExecuteSequence to determine execution timing.",
        "3. Review ServiceInstall/ServiceControl when present; services may also be created by custom actions.",
        "4. Review Registry and Environment for user-controllable values consumed by privileged components.",
        "5. Use lessmsi/extracted_installer when a table references embedded binaries or scripts.",
    ]
    _render_custom_action_correlation(lines, collected, width)
    lines += section("Priority Tables", width)
    for table in PRIORITY_TABLES:
        _render_table(lines, table, collected.get(table), width)
    lines += section("Supporting MSI Tables", width)
    for table in TABLES:
        if table not in PRIORITY_TABLES:
            _render_table(lines, table, collected.get(table), width)

    report = sanitize_report_text("\n".join(lines).rstrip() + "\n", installer)
    (artifact_path(assessment_dir, "msi_analysis.txt")).write_text(report, encoding="utf-8")

    custom_count = len(collected.get("CustomAction") or [])
    findings = []
    if custom_count:
        findings.append({
            "title": "MSI Custom Actions Identified",
            "severity": "Informational",
            "description": "The MSI defines custom actions that may execute with installer privileges and should be reviewed.",
            "evidence": f"{custom_count} CustomAction row(s) identified.",
            "recommendation": "Review CustomAction and InstallExecuteSequence entries for privilege context, unsafe paths, arguments, and writable dependencies.",
        })
    if not collection_valid:
        return {
            "status": "ERROR",
            "details": "MSI database query failed or required table/row fields were missing",
            "findings": findings,
        }
    return {
        "status": "PASS",
        "details": "MSI tables reviewed" + (f"; {len(absent_optional)} optional table(s) absent" if absent_optional else ""),
        "findings": findings,
    }
