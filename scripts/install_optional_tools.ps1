# WCA optional tool preparation. Nothing is downloaded or installed by default.
[CmdletBinding(DefaultParameterSetName='Check')]
param(
    [Parameter(ParameterSetName='Check')][switch]$CheckOnly,
    [Parameter(ParameterSetName='Download')][switch]$DownloadOnly,
    [Parameter(ParameterSetName='Install')][switch]$Install,
    [ValidateSet('Sysinternals','ILSpyCmd','PESecurity','lessmsi','DUMPBIN','WinDbg','Ghidra','Frida')]
    [string[]]$Tools = @('Sysinternals'),
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'WCA\OptionalTools')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$source = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$official = @{
    Sysinternals='https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite'
    ILSpyCmd='https://www.nuget.org/packages/ilspycmd'
    PESecurity='https://www.powershellgallery.com/packages/PESecurity'
    lessmsi='https://github.com/activescott/lessmsi/releases'
    DUMPBIN='https://visualstudio.microsoft.com/downloads/'
    WinDbg='https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/'
    Ghidra='https://github.com/NationalSecurityAgency/ghidra/releases'
    Frida='https://frida.re/docs/installation/'
}
function Show-Detected {
    $names = @('accesschk64.exe','procmon64.exe','handle64.exe','listdlls64.exe','autorunsc64.exe','tcpvcon64.exe','pipelist.exe','ilspycmd.exe','dumpbin.exe','frida.exe')
    foreach ($name in $names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        $local = Join-Path $Destination "Sysinternals\$name"
        $found = if ($command) { $command.Source } elseif (Test-Path -LiteralPath $local -PathType Leaf) { $local } else { 'NOT FOUND' }
        Write-Host ("{0,-20} {1}" -f $name,$found)
    }
}
if (-not $DownloadOnly -and -not $Install) {
    Show-Detected
    Write-Host 'No downloads or changes were made. Use -DownloadOnly or -Install with explicit selection.'
    exit 0
}
if (-not $PSBoundParameters.ContainsKey('Tools')) {
    Write-Host 'Default selection is Sysinternals only; other vendors require deliberate selection.'
}
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
foreach ($tool in $Tools) {
    if ($tool -ne 'Sysinternals') {
        Write-Host "[$tool] Official vendor setup: $($official[$tool])"
        if ($Install -and $tool -eq 'ILSpyCmd') {
            $answer = Read-Host 'Install ilspycmd as a per-user dotnet tool using official NuGet? (yes/no)'
            if ($answer -eq 'yes') { dotnet tool install --global ilspycmd }
        } elseif ($Install -and $tool -eq 'PESecurity') {
            $answer = Read-Host 'Install PESecurity via the configured PowerShell Gallery repository? (yes/no)'
            if ($answer -eq 'yes') { Install-Module -Name PESecurity -Scope CurrentUser -Force }
        }
        continue
    }
    $archive = Join-Path $Destination 'SysinternalsSuite.zip'
    Write-Host "Downloading official Microsoft Sysinternals Suite: $source"
    Invoke-WebRequest -Uri $source -OutFile $archive -MaximumRedirection 4 -UseBasicParsing
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    Write-Host "Downloaded SHA-256: $hash (record this for provenance; Microsoft does not publish a pinned hash here)."
    if (-not $Install) { continue }
    $answer = Read-Host 'Extract downloaded Microsoft tools after validating the signed executables? (yes/no)'
    if ($answer -ne 'yes') { continue }
    $folder = Join-Path $Destination 'Sysinternals'
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    Expand-Archive -LiteralPath $archive -DestinationPath $folder -Force
    $exes = @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -File)
    $untrusted = @($exes | Where-Object { $sig = Get-AuthenticodeSignature -LiteralPath $_.FullName; $sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft' })
    if ($untrusted.Count -gt 0) {
        Write-Warning 'One or more extracted executables did not pass Microsoft Authenticode validation. Do not execute them.'
        foreach ($bad in $untrusted) { Write-Warning $bad.FullName }
        throw 'Sysinternals executable signature verification failed.'
    }
    Write-Host "Verified $($exes.Count) Microsoft-signed executable(s). Configure paths in WCA Tool Readiness if detection is needed."
}
Write-Host 'No tools were executed and no system PATH entries were changed.'
