#requires -Version 7.4
# DE: Backup-Monitoring; Aufruf und Voraussetzungen: docs/SERVER.md.
# EN: Backup monitoring; usage and prerequisites: docs/SERVER.md.
param(
    [string] $Pqkeep = 'pqkeep',
    [string] $KeyFile,
    [string] $PassphraseFile,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Sources = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# DE: Nicht-null muss bis zur JSON-Auswertung gelangen; nur im Skript gültig.
# EN: Non-zero must reach JSON evaluation; scoped to this script only.
$PSNativeCommandUseErrorActionPreference = $false
$PSNativeCommandArgumentPassing = 'Standard'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Stop-Monitor([string] $Message, [int] $Code = 1) {
    [Console]::Error.WriteLine($Message)
    exit $Code
}

function Assert-Valid([bool] $Condition) {
    if (-not $Condition) { throw 'invalid' }
}

function Test-Integer($Value) {
    return ($Value -is [long] -or $Value -is [int] -or $Value -is [double]) -and
        $Value -ge 0 -and $Value -le 2147483647 -and [math]::Floor($Value) -eq $Value
}

function Test-Object($Value) {
    return $Value -is [System.Collections.IDictionary]
}

function Assert-Error($Value) {
    Assert-Valid (Test-Object $Value)
    Assert-Valid ((Test-Integer $Value.code) -and $Value.code -ge 1 -and $Value.code -le 7)
    $kinds = @('ok', 'error', 'usage', 'decrypt_failed', 'weak_passphrase',
        'target_exists', 'no_windows', 'invalid_signature')
    Assert-Valid ($Value.kind -is [string] -and $Value.kind -ceq $kinds[$Value.code])
}

function Get-StatusLines($Report, [int] $Status) {
    Assert-Valid (Test-Object $Report)
    Assert-Valid ($Report.schema -is [string] -and $Report.schema -ceq 'pqkeep-json/1' -and
        $Report.command -is [string] -and $Report.command -ceq 'check')
    Assert-Valid ($Report.ok -is [bool] -and (Test-Integer $Report.exit_code))
    Assert-Valid ($Report.exit_code -le 7 -and $Report.exit_code -eq $Status)
    Assert-Valid ($Report.ok -eq ($Status -eq 0))
    if ($Report.Contains('error')) {
        Assert-Error $Report.error
        Assert-Valid (-not $Report.ok -and $Report.error.code -eq $Status)
        Assert-Valid (-not $Report.Contains('results') -and -not $Report.Contains('summary'))
        $selection = ConvertTo-Json -InputObject @($Sources) -Compress
        return "FEHLER / ERROR: Aufruf gescheitert / command failed ($($Report.error.kind)); " +
            "Quellen nicht bestätigt / sources unverified: $selection"
    }
    Assert-Valid ($Report.results -is [array] -and (Test-Object $Report.summary))
    Assert-Valid ($Report.results.Count -eq $Sources.Count)
    $failed = 0
    $firstError = 0
    $lines = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $Sources.Count; $i++) {
        $item = $Report.results[$i]
        Assert-Valid (Test-Object $item)
        Assert-Valid ($item.source -is [string] -and $item.source -ceq $Sources[$i])
        Assert-Valid ($item.ok -is [bool])
        if ($item.ok) { Assert-Valid (-not $item.Contains('error')); continue }
        Assert-Error $item.error
        if ($failed -eq 0) { $firstError = $item.error.code }
        $failed++
        $source = ConvertTo-Json -InputObject $item.source -Compress
        $lines.Add("FEHLER / ERROR: $source ($($item.error.kind))")
    }
    Assert-Summary $Report $failed $firstError
    $label = if ($Report.ok) { 'OK' } else { 'FEHLER / ERROR' }
    $lines.Add("${label}: gesamt / total=$($Sources.Count), OK=$($Sources.Count - $failed), Fehler / failed=$failed")
    return $lines.ToArray()
}

function Assert-Summary($Report, [int] $Failed, [int] $FirstError) {
    $summary = $Report.summary
    Assert-Valid ((Test-Integer $summary.total) -and (Test-Integer $summary.ok) -and
        (Test-Integer $summary.failed))
    Assert-Valid ($summary.total -eq $Sources.Count -and $summary.failed -eq $Failed -and
        $summary.ok -eq ($Sources.Count - $Failed))
    Assert-Valid ($Report.ok -eq ($Failed -eq 0) -and $Report.exit_code -eq $FirstError)
}

if (-not $KeyFile -or -not $PassphraseFile -or $Sources.Count -eq 0 -or $Sources.Count -gt 1000) {
    Stop-Monitor 'FEHLER / ERROR: Schlüssel, Passphrase-Datei und 1–1000 Quellen erforderlich / key, passphrase file and sources required' 2
}
try {
    # DE: Explizite Pfade wörtlich behandeln, Namen nur als Programme auflösen.
    # EN: Treat explicit paths literally, resolve names only as applications.
    $executable = if (Test-Path -LiteralPath $Pqkeep -PathType Leaf) {
        (Get-Item -LiteralPath $Pqkeep).FullName
    } else {
        (Get-Command -Name $Pqkeep -CommandType Application -ErrorAction Stop).Source
    }
    $arguments = @('--batch', 'check', '--json', '--key', $KeyFile,
        '--passphrase-file', $PassphraseFile, '--') + $Sources
    $raw = & $executable @arguments 2>$null
    $status = $LASTEXITCODE
} catch {
    Stop-Monitor 'FEHLER / ERROR: pqkeep konnte nicht gestartet werden / could not start pqkeep'
}
$failure = if ($status -eq 0) { 1 } else { $status }
try {
    # DE: -NoEnumerate verhindert, dass ein Array als Einzelobjekt akzeptiert wird.
    # EN: -NoEnumerate prevents accepting an array as a single object.
    $text = $raw -join "`n"
    # DE: Auch Kommentare/Schlusskommas ablehnen, die ConvertFrom-Json sonst erlaubt.
    # EN: Also reject comments/trailing commas otherwise accepted by ConvertFrom-Json.
    $syntax = [System.Text.Json.JsonDocument]::Parse($text)
    $syntax.Dispose()
    $report = ConvertFrom-Json -InputObject $text -AsHashtable -NoEnumerate -ErrorAction Stop
    $lines = @(Get-StatusLines $report $status)
} catch {
    Stop-Monitor "FEHLER / ERROR: JSON fehlt oder ist inkonsistent / missing or inconsistent JSON (pqkeep=$status)" $failure
}
$lines | ForEach-Object { [Console]::WriteLine($_) }
exit $status
