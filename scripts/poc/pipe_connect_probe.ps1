# Read-only connection probe. Does not send application protocol messages.
# A successful connection alone is NOT proof of unauthorized operation.
param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_.-]{1,128}$')][string]$PipeName)
$pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
try {
    $pipe.Connect(2000)
    Write-Output "PIPE_CONNECT_SUCCESS: $PipeName"
    Write-Output "CURRENT_IDENTITY: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
} catch {
    Write-Output "PIPE_CONNECT_REJECTED: $($_.Exception.GetType().Name)"
} finally { $pipe.Dispose() }
