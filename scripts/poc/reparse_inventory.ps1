# Read-only. Do not create or follow links for this check.
param([Parameter(Mandatory=$true)][string]$LiteralPath)
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $LiteralPath -Force
$isReparse = [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
[pscustomobject]@{
    Path = $item.FullName
    ReparsePoint = $isReparse
    LinkType = if ($isReparse) { $item.LinkType } else { '(none)' }
    Target = if ($isReparse) { $item.Target } else { '(none)' }
    Owner = (Get-Acl -LiteralPath $LiteralPath).Owner
} | Format-List
if ($isReparse) {
    Write-Warning 'Inventory only. Inspect parent ACL and approved installer-time tracing separately; a link alone does not prove a vulnerability.'
}
