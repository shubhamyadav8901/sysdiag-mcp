<#
.SYNOPSIS
    Answers the open questions about driving Process Monitor unattended, before any tool code is written.

.DESCRIPTION
    Everything about Procmon's batch interface in the plan was inferred from strings inside the binary.
    Procmon has never actually been run by this project, and it cannot be: it needs elevation, and it is
    a GUI application whose error dialogs are invisible when launched with CreateNoWindow. So this script
    exists to turn inference into evidence.

    It answers, in order:

      (a) Does  /BackingFile ... /Runtime n  self-terminate and leave a valid .pml?
      (b) Does  /OpenLog ... /SaveAs ....csv  produce a parseable CSV, and with which columns?
      (c) Does a capture overwrite the operator's own saved Procmon configuration in HKCU?
      (d) Does /Terminate flush the .pml synchronously, or does it return before the file is complete?
      (e) What volume does a short capture actually produce on this machine?

    It also demonstrates the filter hazard directly, and leaves behind a golden CSV fixture that the
    parser's tests will assert against.

.PARAMETER Seconds
    Capture duration for each leg. Procmon's own limit is 1..3600; keep this small.

.PARAMETER OutputDirectory
    Where captures and the fixture are written. Created if absent.

.PARAMETER ProcmonPath
    Full path to Procmon.exe. Only needed when Sysinternals is not installed and not on PATH — for
    example on a freshly imaged lab VM where you have just unzipped ProcessMonitor.zip.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File procmon-spike.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File procmon-spike.ps1 -ProcmonPath C:\tools\Procmon.exe -Seconds 30

.NOTES
    WHAT THIS CHANGES ON THIS MACHINE:
      - Loads the Process Monitor kernel minifilter (PROCMON24). It stays registered afterwards; that
        is normal Procmon behaviour, not something this script does extra.
      - May overwrite your saved Procmon column/filter configuration under
        HKCU\Software\Sysinternals\Process Monitor. Question (c) exists to find out. The script backs
        that key up first and tells you where.
      - Writes capture files, which can be large. Check free space before raising -Seconds.

    Exit codes: 0 all legs ran, 1 not elevated, 2 Procmon not found, 3 a leg failed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(5, 120)]
    [int] $Seconds = 20,

    [string] $OutputDirectory = (Join-Path $env:TEMP 'procmon-spike'),

    [string] $ProcmonPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Head($text) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Answer($question, $answer) {
    Write-Host ("  {0,-12} {1}" -f $question, $answer) -ForegroundColor Green
}

# ---------------------------------------------------------------- prerequisites

# Resolution happens BEFORE the elevation check on purpose: an unelevated run then still validates that
# the files are where they should be, and reports what it found, which is a useful dry check.
$procmon = $ProcmonPath

# Next to this script first. Unzipping ProcessMonitor.zip beside the script is the obvious thing to do,
# so it should just work without anyone passing a path.
if (-not $procmon -and $PSScriptRoot) {
    foreach ($candidate in 'Procmon.exe', 'Procmon64.exe', 'Procmon64a.exe') {
        $local = Join-Path $PSScriptRoot $candidate
        if (Test-Path $local) { $procmon = $local; break }
    }
}

if (-not $procmon) {
    $procmon = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\Procmon.exe' `
        -ErrorAction SilentlyContinue).'(default)'
}
if (-not $procmon -or -not (Test-Path $procmon)) {
    $procmon = (Get-Command Procmon.exe -ErrorAction SilentlyContinue).Source
}
if (-not $procmon -or -not (Test-Path $procmon)) {
    Write-Host 'Procmon.exe not found.' -ForegroundColor Red
    Write-Host 'Download ProcessMonitor.zip from'
    Write-Host '  https://learn.microsoft.com/sysinternals/downloads/procmon'
    Write-Host "and unzip it next to this script ($PSScriptRoot), or pass -ProcmonPath C:\path\to\Procmon.exe"
    exit 2
}

# The Store package ships ONE x64 Procmon.exe. The downloadable ProcessMonitor.zip is different: its
# Procmon.exe is a 32-bit launcher that extracts and starts Procmon64.exe (or Procmon64a.exe on ARM64).
# That matters because the server waits for the process it started — if the launcher exits after
# spawning the real one, "capture finished" would fire immediately and the trace would be empty.
# Prefer the native binary when it is present, and report which shape this machine has.
$procmonDir = Split-Path -Parent $procmon

# Is64BitOperatingSystem, NOT PROCESSOR_ARCHITECTURE. The environment variable reports the bitness of
# the *current process*, so a 32-bit PowerShell on 64-bit Windows reports x86 and would send us down
# this branch wrongly. Only the OS bitness decides which Procmon can run.
$is64BitOs = [Environment]::Is64BitOperatingSystem

$layout = 'single binary (Store package)'

if ($is64BitOs) {
    $native = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
        Join-Path $procmonDir 'Procmon64a.exe'
    }
    else {
        Join-Path $procmonDir 'Procmon64.exe'
    }

    if (Test-Path $native) {
        $layout = "launcher + native pair (downloaded zip); using $(Split-Path -Leaf $native)"
        $procmon = $native
    }
}
else {
    # A 32-bit OS. Procmon64.exe simply cannot load here, and the 32-bit build is not a fallback but the
    # correct choice: "Capture requires 64-bit mode" is emitted when the 32-bit build runs on *x64*
    # Windows, not on a genuinely 32-bit one, where it captures normally.
    $layout = '32-bit OS; using the 32-bit Procmon.exe, which is the only one that can run here'

    $candidate = Join-Path $procmonDir 'Procmon.exe'
    if (Test-Path $candidate) { $procmon = $candidate }
}

function Get-PeMachine([string] $path) {
    try {
        $fs = [IO.File]::OpenRead($path)
        try {
            $br = New-Object IO.BinaryReader($fs)
            $fs.Position = 0x3C
            $fs.Position = $br.ReadInt32() + 4
            switch ($br.ReadUInt16()) {
                0x8664 { 'x64' }
                0x014c { 'x86' }
                0xAA64 { 'ARM64' }
                default { 'unknown' }
            }
        }
        finally { $fs.Dispose() }
    }
    catch { 'unreadable' }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

# Capture everything to a file. This script exists to produce evidence for someone who is not at this
# keyboard, so the console output has to survive the session.
$transcript = Join-Path $OutputDirectory 'spike-transcript.txt'
try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
Start-Transcript -Path $transcript -Force | Out-Null

$procmonMachine = Get-PeMachine $procmon

Write-Head 'Environment'
Write-Host "  Procmon : $procmon"
Write-Host "  Version : $((Get-Item $procmon).VersionInfo.FileVersion)"
Write-Host "  PE arch : $procmonMachine"
Write-Host "  Layout  : $layout"
Write-Host "  OS      : $(if ($is64BitOs) { '64-bit' } else { '32-bit' }) (process reports $env:PROCESSOR_ARCHITECTURE)"
Write-Host "  Output  : $OutputDirectory"
Write-Host "  Duration: $Seconds s per leg"

# Fail here with an explanation rather than letting Start-Process throw
# "not a valid application for this OS platform" from inside a capture leg.
if (-not $is64BitOs -and $procmonMachine -ne 'x86') {
    Write-Host ''
    Write-Host "  This is a 32-bit OS but the selected binary is $procmonMachine, which cannot run." -ForegroundColor Red
    Write-Host '  Point -ProcmonPath at the 32-bit Procmon.exe from the zip.' -ForegroundColor Red
    exit 2
}

if ($is64BitOs -and $procmonMachine -eq 'x86') {
    Write-Host ''
    Write-Host '  WARNING: this is the 32-bit Procmon on a 64-bit OS. It cannot capture ("Capture' -ForegroundColor Yellow
    Write-Host '  requires 64-bit mode"); it extracts and launches the 64-bit build as a CHILD process.' -ForegroundColor Yellow
    Write-Host '  Watch whether the exit timings below match the requested duration - if a leg "exits"' -ForegroundColor Yellow
    Write-Host '  almost instantly, the launcher is not waiting for its child, and the server will need' -ForegroundColor Yellow
    Write-Host '  to invoke the native binary directly rather than through it.' -ForegroundColor Yellow
}

# Everything above is inspection. Everything below loads a driver and captures, so this is the line.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host '  Setup looks fine, but this session is NOT elevated.' -ForegroundColor Red
    Write-Host '  Procmon loads a kernel minifilter, so the capture legs need an elevated prompt.'
    Write-Host '  Right-click Windows Terminal or cmd, "Run as administrator", then re-run this script.'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 1
}

# ------------------------------------------------- (c) back up the operator's config

$configKey = 'HKCU:\Software\Sysinternals\Process Monitor'
$backup = Join-Path $OutputDirectory 'procmon-hkcu-before.reg'
$configBefore = $null

if (Test-Path $configKey) {
    & reg.exe export 'HKCU\Software\Sysinternals\Process Monitor' $backup /y | Out-Null
    $configBefore = Get-ItemProperty -Path $configKey
    Write-Host "  HKCU config backed up to $backup" -ForegroundColor Yellow
    Write-Host ("  Columns before: ColumnCount={0}" -f $configBefore.ColumnCount)
    if ($configBefore.PSObject.Properties.Name -contains 'FilterRules') {
        Write-Host ("  FilterRules before: {0} bytes" -f $configBefore.FilterRules.Length)
    }
}
else {
    Write-Host '  No HKCU Procmon config exists yet (clean profile).' -ForegroundColor Yellow
}

# --------------------------------------------------------------- marker activity

# A uniquely named file touched during the capture. Any capture that works must contain it, which makes
# every later assertion self-verifying rather than a judgement call about whether the trace "looks right".
$marker = "windiag-spike-$([guid]::NewGuid().ToString('N'))"
$markerPath = Join-Path $OutputDirectory "$marker.txt"

function Start-MarkerActivity {
    Start-Job -ScriptBlock {
        param($path, $seconds)
        $deadline = (Get-Date).AddSeconds($seconds)
        while ((Get-Date) -lt $deadline) {
            Set-Content -Path $path -Value "spike $(Get-Date -Format o)" -ErrorAction SilentlyContinue
            Get-Content -Path $path -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Milliseconds 200
        }
    } -ArgumentList $markerPath, ($Seconds + 2)
}

# ============================================================ LEG 1: inherited filter
# Runs with whatever filter this profile has saved. If a user-added INCLUDE rule is present, the capture
# records almost nothing -- the hazard the plan warns about, demonstrated rather than asserted.

Write-Head "LEG 1  capture with the profile's existing filter (no /NoFilter, no /LoadConfig)"

$pml1 = Join-Path $OutputDirectory 'leg1-inherited.pml'
Remove-Item $pml1 -ErrorAction SilentlyContinue

$job = Start-MarkerActivity
$sw = [Diagnostics.Stopwatch]::StartNew()

$p = Start-Process -FilePath $procmon -PassThru -ArgumentList @(
    '/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', $pml1, '/Runtime', $Seconds)

$exited = $p.WaitForExit(($Seconds + 60) * 1000)
$sw.Stop()
Receive-Job $job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue | Out-Null

Write-Answer '(a) exits?' $(if ($exited) { "YES after $([int]$sw.Elapsed.TotalSeconds)s (asked for $Seconds)" } else { 'NO - still running, killed' })
if (-not $exited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }

if (Test-Path $pml1) {
    Write-Answer '(e) size' ("{0:N0} bytes" -f (Get-Item $pml1).Length)
}
else {
    Write-Host '  LEG 1 produced no .pml at all.' -ForegroundColor Red
}

# ============================================================ LEG 2: cleared filter

Write-Head "LEG 2  capture with /NoFilter (stock exclusions cleared too - expect high volume)"

$pml2 = Join-Path $OutputDirectory 'leg2-nofilter.pml'
Remove-Item $pml2 -ErrorAction SilentlyContinue

$job = Start-MarkerActivity
$sw = [Diagnostics.Stopwatch]::StartNew()

$p = Start-Process -FilePath $procmon -PassThru -ArgumentList @(
    '/AcceptEula', '/Quiet', '/Minimized', '/NoFilter', '/BackingFile', $pml2, '/Runtime', $Seconds)

$exited = $p.WaitForExit(($Seconds + 60) * 1000)
$sw.Stop()
Receive-Job $job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue | Out-Null

Write-Answer '(a) exits?' $(if ($exited) { "YES after $([int]$sw.Elapsed.TotalSeconds)s" } else { 'NO - killed' })
if (-not $exited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
if (Test-Path $pml2) { Write-Answer '(e) size' ("{0:N0} bytes" -f (Get-Item $pml2).Length) }

# ============================================================ (b) export to CSV

Write-Head '(b) export the LEG 2 capture to CSV'

$csv = Join-Path $OutputDirectory 'leg2-nofilter.csv'
Remove-Item $csv -ErrorAction SilentlyContinue

if (Test-Path $pml2) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $procmon -PassThru -ArgumentList @(
        '/AcceptEula', '/Quiet', '/Minimized', '/OpenLog', $pml2, '/SaveAs', $csv)
    $exported = $p.WaitForExit(600 * 1000)
    $sw.Stop()

    if (-not $exported) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }

    if (Test-Path $csv) {
        $info = Get-Item $csv
        Write-Answer '(b) exported' ("{0:N0} bytes in {1:N0}s" -f $info.Length, $sw.Elapsed.TotalSeconds)
        Write-Host ''
        Write-Host '  CSV HEADER (this is what the parser must expect):' -ForegroundColor Yellow
        Write-Host ('  ' + (Get-Content $csv -TotalCount 1))
        Write-Host ''
        Write-Host '  First 3 data rows:' -ForegroundColor Yellow
        Get-Content $csv -TotalCount 4 | Select-Object -Skip 1 | ForEach-Object { Write-Host "  $_" }

        $markerHits = @(Select-String -Path $csv -SimpleMatch $marker -ErrorAction SilentlyContinue)
        Write-Answer 'marker rows' "$($markerHits.Count) rows mention $marker"
        if ($markerHits.Count -eq 0) {
            Write-Host '  WARNING: the file this script wrote during the capture is absent from the trace.' -ForegroundColor Red
            Write-Host '  That means the capture is not recording what it should.' -ForegroundColor Red
        }

        # Golden fixture: the header plus the marker rows and some context. Small, and every row in it is
        # one this script caused, so the parser test asserts against known-true data.
        $fixture = Join-Path $OutputDirectory 'procmon-golden.csv'
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add((Get-Content $csv -TotalCount 1))
        $markerHits | Select-Object -First 40 | ForEach-Object { $lines.Add($_.Line) }
        Set-Content -Path $fixture -Value $lines -Encoding UTF8
        Write-Answer 'fixture' "$fixture ($($lines.Count) lines)"
    }
    else {
        Write-Host '  Export produced no CSV. /SaveAs may have been rejected.' -ForegroundColor Red
    }
}

# ============================================================ (d) /Terminate semantics

Write-Head '(d) does /Terminate flush the .pml before it returns?'

$pml3 = Join-Path $OutputDirectory 'leg3-terminate.pml'
Remove-Item $pml3 -ErrorAction SilentlyContinue

$job = Start-MarkerActivity
# Deliberately a long /Runtime so /Terminate is what actually stops it.
$p = Start-Process -FilePath $procmon -PassThru -ArgumentList @(
    '/AcceptEula', '/Quiet', '/Minimized', '/NoFilter', '/BackingFile', $pml3, '/Runtime', 600)

Start-Sleep -Seconds ([Math]::Min($Seconds, 15))
$sizeBeforeStop = if (Test-Path $pml3) { (Get-Item $pml3).Length } else { 0 }

# Start-Process -PassThru + WaitForExit, NOT the call operator. Procmon is a GUI-subsystem binary, and
# PowerShell's `&` does not wait for one — it would return instantly and this stopwatch, which is the
# entire point of question (d), would report a meaningless ~0s.
$sw = [Diagnostics.Stopwatch]::StartNew()
$stopper = Start-Process -FilePath $procmon -PassThru -ArgumentList @('/AcceptEula', '/Terminate')
$stopperExited = $stopper.WaitForExit(60 * 1000)
$sw.Stop()
if (-not $stopperExited) {
    Write-Host '  /Terminate itself did not exit within 60s.' -ForegroundColor Red
    Stop-Process -Id $stopper.Id -Force -ErrorAction SilentlyContinue
}

$sizeAtReturn = if (Test-Path $pml3) { (Get-Item $pml3).Length } else { 0 }
$captureExited = $p.WaitForExit(30 * 1000)
Start-Sleep -Seconds 2
$sizeAfterExit = if (Test-Path $pml3) { (Get-Item $pml3).Length } else { 0 }

Receive-Job $job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue | Out-Null
if (-not $captureExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }

Write-Answer '(d) returns in' ("{0:N1}s" -f $sw.Elapsed.TotalSeconds)
Write-Answer '(d) target exit' $(if ($captureExited) { 'YES' } else { 'NO' })
Write-Host ("  size before stop : {0,15:N0}" -f $sizeBeforeStop)
Write-Host ("  size at return   : {0,15:N0}" -f $sizeAtReturn)
Write-Host ("  size after exit  : {0,15:N0}" -f $sizeAfterExit)
if ($sizeAfterExit -ne $sizeAtReturn) {
    Write-Host '  => /Terminate returns BEFORE the file is complete. Poll for PID exit and size stability.' -ForegroundColor Yellow
}
else {
    Write-Host '  => file size was already stable when /Terminate returned.' -ForegroundColor Green
}

# ============================================================ (c) config side effect

Write-Head '(c) did any of this overwrite the saved Procmon configuration?'

if (Test-Path $configKey) {
    $configAfter = Get-ItemProperty -Path $configKey
    $changed = @()

    foreach ($name in 'ColumnCount', 'Columns', 'ColumnMap', 'FilterRules') {
        # Indexing PSObject.Properties with a name that is absent returns $null, so .Value on it throws.
        # A value that did not exist before and exists now is itself a change worth reporting.
        $beforeProp = if ($configBefore) { $configBefore.PSObject.Properties[$name] } else { $null }
        $afterProp = $configAfter.PSObject.Properties[$name]

        $before = if ($beforeProp) { $beforeProp.Value } else { $null }
        $after = if ($afterProp) { $afterProp.Value } else { $null }

        $b = if ($before -is [byte[]]) { [Convert]::ToBase64String($before) } else { "$before" }
        $a = if ($after -is [byte[]]) { [Convert]::ToBase64String($after) } else { "$after" }
        if ($b -ne $a) { $changed += $name }
    }

    if ($changed.Count -gt 0) {
        Write-Host "  CHANGED: $($changed -join ', ')" -ForegroundColor Yellow
        Write-Host "  Restore with:  reg import `"$backup`"" -ForegroundColor Yellow
    }
    else {
        Write-Answer '(c) config' 'unchanged'
    }
}

Write-Head 'Summary'
Write-Host "  Working files are in $OutputDirectory"
Write-Host '  Compare LEG 1 and LEG 2 sizes: a large gap means this profile had a restrictive filter,'
Write-Host '  which is exactly why the server must pin the filter rather than inherit it.'

# ------------------------------------------------------------------ results bundle

# The .pml and full .csv are far too big to move around, and nobody needs them elsewhere. Bundle only
# what someone reading the results actually has to see.
Write-Head 'Results bundle'

$bundleDir = Join-Path $OutputDirectory 'bundle'
Remove-Item $bundleDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $bundleDir | Out-Null

$sizes = [ordered]@{}
foreach ($f in 'leg1-inherited.pml', 'leg2-nofilter.pml', 'leg2-nofilter.csv', 'leg3-terminate.pml') {
    $p = Join-Path $OutputDirectory $f
    $sizes[$f] = if (Test-Path $p) { (Get-Item $p).Length } else { $null }
}

[pscustomobject]@{
    Machine        = $env:COMPUTERNAME
    WindowsVersion = (Get-CimInstance Win32_OperatingSystem).Version
    ProcmonPath    = $procmon
    ProcmonVersion = (Get-Item $procmon).VersionInfo.FileVersion
    ProcmonArch    = $procmonMachine
    ProcmonLayout  = $layout
    Is64BitOs      = $is64BitOs
    OsArchitecture = $env:PROCESSOR_ARCHITECTURE
    Elevated       = $true
    CaptureSeconds = $Seconds
    Marker         = $marker
    FileSizes      = $sizes
    RunAtUtc       = (Get-Date).ToUniversalTime().ToString('o')
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $bundleDir 'spike-facts.json') -Encoding UTF8

foreach ($f in 'spike-transcript.txt', 'procmon-golden.csv') {
    $p = Join-Path $OutputDirectory $f
    if (Test-Path $p) { Copy-Item $p $bundleDir -Force }
}

# The CSV header on its own, since it is the single most important output: it defines what the parser
# must expect, and it is one line.
$csvPath = Join-Path $OutputDirectory 'leg2-nofilter.csv'
if (Test-Path $csvPath) {
    Get-Content $csvPath -TotalCount 1 |
        Set-Content -Path (Join-Path $bundleDir 'csv-header.txt') -Encoding UTF8
}

$zip = Join-Path $OutputDirectory 'procmon-spike-results.zip'
Remove-Item $zip -Force -ErrorAction SilentlyContinue

try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
Copy-Item $transcript $bundleDir -Force -ErrorAction SilentlyContinue

Compress-Archive -Path (Join-Path $bundleDir '*') -DestinationPath $zip -Force

Write-Host ''
Write-Host '  BRING THIS BACK:' -ForegroundColor Green
Write-Host "    $zip" -ForegroundColor Green
Write-Host ("    ({0:N0} bytes - transcript, CSV header, golden fixture, environment facts)" -f (Get-Item $zip).Length)
Write-Host ''
Write-Host '  The .pml captures stay here; they are large and nothing downstream needs them.'
Write-Host ''
Write-Host '  STILL TO DO BY HAND (the part no script can do):' -ForegroundColor Cyan
Write-Host '    1. Open Procmon, set the columns you want, keep the stock exclusion filters,'
Write-Host '       and remove any personal include rules.'
Write-Host '    2. File > Export Configuration...  ->  save as windiag.pmc'
Write-Host '    3. Re-run one capture adding  /LoadConfig <path>\windiag.pmc  and confirm the CSV header'
Write-Host '       matches the columns you chose.'
Write-Host '    4. Bring windiag.pmc back along with the zip - it gets committed to the repo, and it is'
Write-Host '       the only thing that makes the export schema deterministic.'

exit 0
