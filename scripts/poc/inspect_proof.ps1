# Read-only inspection of a marker created by marker_dll.c or marker_exe.c.
# The marker lands in the launched process's TEMP directory, which can differ
# from the current user (for SYSTEM often C:\Windows\TEMP).
param([Parameter(Mandatory=$true)][string]$LiteralPath)
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
if ($item.PSIsContainer -or $item.Length -gt 16384) { throw 'Expected a small proof text file.' }
$content = Get-Content -LiteralPath $item.FullName -Raw
if ($content -notmatch 'WCA_(?:DLL_LOADED|EXE_EXECUTED) PID=\d+ USER=') {
    throw 'Proof marker syntax not found. Do not infer code execution from an unrelated text file.'
}
[pscustomobject]@{
    Marker = $item.Name
    SHA256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
    Lines = ($content -split "`r?`n" | Where-Object { $_ }).Count
    Content = $content
    Limitations = 'Marker is evidence of execution only; independently correlate PID and integrity level to the target.'
} | Format-List
