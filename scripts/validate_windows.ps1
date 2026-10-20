$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-CheckedPython {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    & python @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Python validation command failed (exit code $exitCode): python $($Arguments -join ' ')"
    }
}

Write-Host 'WCA v2.2.1 Windows validation' -ForegroundColor Cyan
if (-not (Test-Path '.\requirements-dev.txt')) { throw 'requirements-dev.txt missing' }
# install_dependencies.ps1 -TestDependencies or python -m pip install -r requirements-dev.txt
Invoke-CheckedPython -Arguments @('-W','error','-m','compileall','-q','.')
Invoke-CheckedPython -Arguments @('-m','pytest','-q')
Invoke-CheckedPython -Arguments @('.\scripts\package_release.py','--audit-only')

$version = (Invoke-CheckedPython -Arguments @('.\wca.py','--version') | Out-String).Trim()
Write-Host $version
if ($version -notmatch 'WCA 2\.2\.1') { throw 'WCA 2.2.1 version string not detected' }
if ($version -notmatch 'Windows Client Assessment') { throw 'Full product name missing' }
if ($version -notmatch 'Author: Matthew B\.') { throw 'Author metadata missing' }
if ($version -notmatch 'methodology 1\.9') { throw 'Methodology 1.9 not detected' }
if ($version -notmatch 'artifact catalog 2\.0') { throw 'Artifact catalog 1.9 not detected' }
$null = Invoke-CheckedPython -Arguments @('.\wca.py','--help')
$rawCapabilities = Invoke-CheckedPython -Arguments @('.\wca.py','--backend-action','capabilities')
$backend = ($rawCapabilities | Out-String | ConvertFrom-Json)
if (-not $backend.ok -or $backend.schema -ne '1.0' -or -not $backend.data.interface.gui -or -not $backend.data.interface.http_server) { throw 'Backend capability contract failed' }
$readableCapabilities = (Invoke-CheckedPython -Arguments @('.\wca.py','--backend-action','capabilities','--backend-format','text') | Out-String)
if ($readableCapabilities -notmatch 'WCA' -or $readableCapabilities -notmatch 'installable') {
    throw 'Readable backend capability output missing expected content'
}

$required = @(
  '.\modules\target_info.py',
  '.\modules\application_profile.py',
  '.\modules\local_storage_review.py',
  '.\modules\attack_surface_correlations.py',
  '.\docs\attack-surface-coverage.md',
  '.\docs\backend-service.md',
  '.\docs\gui-guide.md',
  '.\docs\getting-started.md',
  '.\utils\gui_catalog.py',
  '.\utils\tool_versions.py',
  '.\tests\test_gui_203.py',
  '.\utils\gui_server.py',
  '.\utils\web_worker.py',
  '.\tests\test_gui_worker_202.py',
  '.\gui\index.html',
  '.\gui\app.js',
  '.\gui\app.css',
  '.\tests\test_gui_200.py',
  '.\METHODOLOGY.md',
  '.\utils\backend_service.py',
  '.\utils\backend_format.py',
  '.\utils\operation_lock.py',
  '.\tests\test_backend_193.py',
  '.\tests\test_stabilization_194.py',
  '.\tests\test_backend_format_195.py',
  '.\requirements-dev.txt',
  '.\docs\windows-environment-setup.md',
  '.\docs\windows-validation.md',
  '.\tests\test_portable_target_support.py',
  '.\scripts\validate_windows.ps1',
  '.\scripts\poc\marker_dll.c',
  '.\scripts\poc\marker_exe.c'
)
foreach ($path in $required) {
  if (-not (Test-Path $path)) { throw "Required v2.2.1 artifact missing: $path" }
}

$forbidden = @('.\wca.egg-info', '.\build', '.\dist', '.\examples', '.\winclientassess.py')
foreach ($path in $forbidden) {
  if (Test-Path $path) { throw "Unexpected packaged artifact: $path" }
}
if (Get-ChildItem .\scripts -File -Filter 'validate_windows_*.ps1' -ErrorAction SilentlyContinue) {
  throw 'Historical version-specific validation scripts are still packaged'
}
Write-Host 'Portable/package checks passed.' -ForegroundColor Green
Write-Host 'Next: Windows GUI acceptance — localhost access, in-browser checkpoints, live Guided Runtime stop, review/export, and legacy compatibility.' -ForegroundColor Yellow
