# Read-only target-specific COM registry inspection. Does not instantiate COM objects.
param([Parameter(Mandatory=$true)][ValidatePattern('^\{[a-fA-F0-9-]{36}\}$')][string]$Clsid)
$ErrorActionPreference = 'Stop'
foreach ($root in @('Registry::HKEY_CURRENT_USER\Software\Classes\CLSID',
                     'Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID',
                     'Registry::HKEY_LOCAL_MACHINE\Software\Classes\WOW6432Node\CLSID')) {
    foreach ($subkey in @('InprocServer32', 'LocalServer32')) {
        $path = "$root\$Clsid\$subkey"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $key = Get-Item -LiteralPath $path
        $acl = Get-Acl -LiteralPath $path
        [pscustomobject]@{
            Registration = $path
            Server = [string]$key.GetValue('')
            Owner = $acl.Owner
            Access = ($acl.Access | ForEach-Object { "$($_.IdentityReference): $($_.RegistryRights) [$($_.AccessControlType)]" }) -join '; '
        } | Format-List
    }
}
Write-Warning 'A writable COM key is not a hijack until a target consumer actually activates the controlled registration across a trust boundary.'
