param(
    [switch]$Recreate,
    [switch]$TestDependencies
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed (exit code $LASTEXITCODE)." }
}

if ($Recreate -and (Test-Path ".venv")) {
    Write-Host "[+] Removing existing .venv..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force ".venv"
}

if (-not (Test-Path ".venv")) {
    Write-Host "[+] Creating Python virtual environment..." -ForegroundColor Cyan
    $PyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($PyLauncher) {
        & $PyLauncher.Source -m venv .venv
        Assert-NativeSuccess 'Virtual environment creation'
    } else {
        $Python = Get-Command python.exe -ErrorAction Stop
        & $Python.Source -m venv .venv
        Assert-NativeSuccess 'Virtual environment creation'
    }
}

Write-Host "[+] Activating virtual environment..." -ForegroundColor Cyan
& .\.venv\Scripts\Activate.ps1

Write-Host "[+] Upgrading pip..." -ForegroundColor Cyan
python -m pip install --upgrade pip
Assert-NativeSuccess "pip upgrade"

Write-Host "[+] Installing WCA Python requirements..." -ForegroundColor Cyan
python -m pip install -r requirements.txt
Assert-NativeSuccess "WCA Python requirements installation"
if ($TestDependencies) {
    Write-Host "[+] Installing optional WCA regression-test requirements..." -ForegroundColor Cyan
    python -m pip install -r requirements-dev.txt
    Assert-NativeSuccess "WCA test requirements installation"
}

Write-Host "[+] Verifying Python imports..." -ForegroundColor Cyan
python -c "import rich, pefile, psutil; print('Python dependencies: OK')"
Assert-NativeSuccess 'Core import verification'

$SevenZip = Get-Command 7z.exe -ErrorAction SilentlyContinue
if (-not $SevenZip) {
    $Default7z = "C:\Program Files\7-Zip\7z.exe"
    if (Test-Path $Default7z) {
        $SevenZipPath = $Default7z
    }
} else {
    $SevenZipPath = $SevenZip.Source
}

if ($SevenZipPath) {
    Write-Host "[+] 7-Zip detected: $SevenZipPath" -ForegroundColor Green
} else {
    Write-Host "[!] 7-Zip was not detected. Install it before assessments that require extraction." -ForegroundColor Yellow
}

Write-Host "[+] Core Python setup complete." -ForegroundColor Green
Write-Host "[i] For every supported external tool, see docs\optional-tools.md" -ForegroundColor Cyan

if ($TestDependencies) { Write-Host "[+] Development/test requirements are available." -ForegroundColor Green }
