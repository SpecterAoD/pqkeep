# DE: Nur eigene kurzlebige öffentliche Testprozesse; keine Geheimnisse oder Hoständerung.
# EN: Owned short-lived public test processes only; no secrets or host settings.
$ErrorActionPreference = 'Stop'

function New-Probe([string[]]$Arguments) {
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Resolve-Path 'target/debug/examples/process_access_probe.exe').Path
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Probe did not start' }
    return $process
}

function Stop-OwnedProbe($Process) {
    if ($null -ne $Process) {
        if (-not $Process.HasExited) {
            $Process.Kill()
            if (-not $Process.WaitForExit(5000)) { throw 'Owned probe did not terminate' }
        }
        $Process.Dispose()
    }
}

$target = $null
$inspector = $null
try {
    $target = New-Probe -Arguments @('target')
    $ready = $target.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(10000)) { throw 'Own target readiness timeout' }
    if ($ready.Result -cne "READY $($target.Id)") { throw 'Own target identity mismatch' }
    $inspector = New-Probe -Arguments @('inspect-restricted', [string]$target.Id)
    $inspector.StandardInput.Close()
    if (-not $inspector.WaitForExit(10000)) { throw 'Own inspector timeout' }
    $result = $inspector.StandardOutput.ReadToEnd()
    # DE/EN: Ausschließlich öffentliche Probenkontrolle / public probe control only.
    Write-Output ($inspector.StandardError.ReadToEnd().Trim())
    if ($inspector.ExitCode -ne 0 -or -not $result.StartsWith('PASS:')) {
        throw 'Own inspector rejected process access policy'
    }
    $target.StandardInput.Close()
    if (-not $target.WaitForExit(10000)) { throw 'Own target exit timeout' }
    if ($target.ExitCode -ne 0) { throw 'Own target rejected policy readback' }
    Write-Output ($result.Trim())
    Write-Output 'PASS: only own target DACL changed; both owned children exited'
} finally {
    try {
        Stop-OwnedProbe $inspector
    } finally {
        Stop-OwnedProbe $target
    }
}
