from __future__ import annotations

import re

from utils.powershell import run_powershell_json

BROAD_PRINCIPALS = (
    "everyone",
    "authenticated users",
    "builtin\\users",
    "\\users",
    "interactive",
)
WRITE_RIGHTS = ("fullcontrol", "modify", "write", "writeandexecute", "createfiles", "appenddata")
READ_RIGHTS = ("fullcontrol", "read", "readandexecute", "readdata", "readattributes")


def get_acl_summary(path: str):
    safe = str(path).replace("'", "''")
    ps = rf"""
    if (Test-Path -LiteralPath '{safe}') {{
      $a = Get-Acl -LiteralPath '{safe}'
      $aces = @($a.Access | ForEach-Object {{
        [PSCustomObject]@{{
          Identity = [string]$_.IdentityReference
          Rights = [string]$_.FileSystemRights
          Type = [string]$_.AccessControlType
          Inherited = [bool]$_.IsInherited
        }}
      }})
      [PSCustomObject]@{{
        Path = '{safe}'
        Exists = $true
        Owner = $a.Owner
        Access = $aces
      }}
    }} else {{
      [PSCustomObject]@{{Path='{safe}';Exists=$false;Owner=$null;Access=@()}}
    }}
    """
    data, result = run_powershell_json(ps, timeout=60)
    if isinstance(data, dict):
        return data
    return {
        "Path": path,
        "Exists": False,
        "Owner": None,
        "Access": [],
        "Error": result.get("stderr", ""),
    }


def broad_write_aces(acl):
    access = acl.get("Access", []) if isinstance(acl, dict) else []
    if isinstance(access, dict):
        access = [access]
    hits = []
    for ace in access or []:
        if str(ace.get("Type", "")).lower() != "allow":
            continue
        identity = str(ace.get("Identity", "")).lower()
        rights = str(ace.get("Rights", "")).replace(" ", "").lower()
        if any(principal in identity for principal in BROAD_PRINCIPALS) and any(
            right in rights for right in WRITE_RIGHTS
        ):
            hits.append(ace)
    return hits



def broad_create_file_aces(acl):
    """Return broad-principal ACEs that can create a file in a directory.

    This is intentionally narrower than broad_write_aces(). Directory
    AppendData/CreateDirectories does not establish the ability to create an
    executable such as C:\\Program.exe, so it must not promote an unquoted
    service-path candidate to writable/HIGH confidence.
    """
    access = acl.get("Access", []) if isinstance(acl, dict) else []
    if isinstance(access, dict):
        access = [access]
    create_file_rights = {
        "fullcontrol", "modify", "write", "writeandexecute",
        "createfiles", "writedata",
    }
    hits = []
    for ace in access or []:
        if str(ace.get("Type", "")).lower() != "allow":
            continue
        identity = str(ace.get("Identity", "")).lower()
        if not any(principal in identity for principal in BROAD_PRINCIPALS):
            continue
        raw = str(ace.get("Rights", ""))
        rights = {re.sub(r"[^a-z0-9]", "", part.lower()) for part in raw.split(",") if part.strip()}
        if rights & create_file_rights:
            hits.append(ace)
    return hits



def broad_read_aces(acl):
    """Return broad-principal allow ACEs that grant meaningful read access."""
    access = acl.get("Access", []) if isinstance(acl, dict) else []
    if isinstance(access, dict):
        access = [access]
    hits = []
    for ace in access or []:
        if str(ace.get("Type", "")).lower() != "allow":
            continue
        identity = str(ace.get("Identity", "")).lower()
        rights = str(ace.get("Rights", "")).replace(" ", "").lower()
        if any(principal in identity for principal in BROAD_PRINCIPALS) and any(
            right in rights for right in READ_RIGHTS
        ):
            hits.append(ace)
    return hits


def get_acl_summaries(paths, batch_size: int = 75):
    """
    Query ACLs for multiple filesystem paths using batched PowerShell calls.

    This avoids starting a separate PowerShell process for every installed file
    or directory when reviewing a large system-state differential.
    """
    unique = []
    seen = set()
    for raw in paths or []:
        path = str(raw or "").strip()
        if not path:
            continue
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)

    output = {}
    for start in range(0, len(unique), batch_size):
        batch = unique[start:start + batch_size]
        quoted = ",".join("'" + p.replace("'", "''") + "'" for p in batch)
        ps = rf"""
        $paths = @({quoted})
        $results = foreach ($p in $paths) {{
          if (Test-Path -LiteralPath $p) {{
            try {{
              $a = Get-Acl -LiteralPath $p
              $aces = @($a.Access | ForEach-Object {{
                [PSCustomObject]@{{
                  Identity = [string]$_.IdentityReference
                  Rights = [string]$_.FileSystemRights
                  Type = [string]$_.AccessControlType
                  Inherited = [bool]$_.IsInherited
                }}
              }})
              [PSCustomObject]@{{
                Path = $p
                Exists = $true
                Owner = $a.Owner
                Access = $aces
                Error = $null
              }}
            }} catch {{
              [PSCustomObject]@{{
                Path = $p
                Exists = $true
                Owner = $null
                Access = @()
                Error = $_.Exception.Message
              }}
            }}
          }} else {{
            [PSCustomObject]@{{
              Path = $p
              Exists = $false
              Owner = $null
              Access = @()
              Error = $null
            }}
          }}
        }}
        $results
        """
        data, result = run_powershell_json(ps, timeout=180)
        if isinstance(data, dict):
            rows = [data]
        elif isinstance(data, list):
            rows = data
        else:
            rows = []

        returned = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            path = str(row.get("Path", ""))
            output[path.lower()] = row
            returned.add(path.lower())

        for path in batch:
            key = path.lower()
            if key not in returned:
                output[key] = {
                    "Path": path,
                    "Exists": False,
                    "Owner": None,
                    "Access": [],
                    "Error": result.get("stderr", "") or "ACL query returned no result.",
                }

    return output


class AclCache:
    """Run-scoped cache that batches new ACL paths and reuses prior results."""

    def __init__(self):
        self._cache = {}

    def seed(self, mapping=None):
        for key, value in (mapping or {}).items():
            if isinstance(value, dict):
                self._cache[str(key).lower()] = value
        return self

    def get_many(self, paths, batch_size: int = 75):
        unique = []
        seen = set()
        for raw in paths or []:
            path = str(raw or "").strip()
            if not path:
                continue
            key = path.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)

        missing = [path for path in unique if path.lower() not in self._cache]
        if missing:
            self._cache.update(get_acl_summaries(missing, batch_size=batch_size))
        return {path.lower(): self._cache.get(path.lower(), {}) for path in unique}

    def get(self, path):
        path = str(path or "").strip()
        if not path:
            return {"Path": path, "Exists": False, "Owner": None, "Access": [], "Error": "Empty path"}
        return self.get_many([path]).get(path.lower(), {})

    def snapshot(self):
        return dict(self._cache)
