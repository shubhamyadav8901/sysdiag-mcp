<#
.SYNOPSIS
    Verifies the two windiag capabilities that have never actually run, against a real elevated machine.

.DESCRIPTION
    Everything else in this project is covered by `dotnet test`. Two paths are not, because they need
    administrator rights and a kernel driver:

      - capture_activity / query_activity  (drives Process Monitor)
      - path_handle_search                 (drives handle.exe)

    Their unit tests run against a stubbed process runner, so they prove the arguments are composed
    correctly and nothing else. This script proves the tools actually work.

    It drives the PUBLISHED server over stdio, exactly as Claude Code does, so it needs no .NET SDK on
    the machine under test — just the single self-contained exe.

    Each check is self-verifying: the script creates the thing it then goes looking for, so a pass
    cannot be a coincidence.

.PARAMETER ServerPath
    Path to the published WinDiag.Mcp.exe. Defaults to one sitting next to this script.

.PARAMETER CaptureSeconds
    Duration for the activity capture. Traces grow ~5 MB/s, so keep it small.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File verify-on-target.ps1 -ServerPath .\WinDiag.Mcp.exe

.NOTES
    Must run elevated. Loads the Process Monitor kernel driver and writes capture files.
    Exit codes: 0 all checks passed, 1 not elevated, 2 server not found, 3 one or more checks failed.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string] $ServerPath,

    [ValidateRange(5, 60)]
    [int] $CaptureSeconds = 15
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:Failures = 0
$script:Checks = 0

function Write-Head($text) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Assert-That($name, $condition, $detail) {
    $script:Checks++
    if ($condition) {
        Write-Host ("  PASS  {0}" -f $name) -ForegroundColor Green
    }
    else {
        $script:Failures++
        Write-Host ("  FAIL  {0}" -f $name) -ForegroundColor Red
        if ($detail) { Write-Host ("        {0}" -f $detail) -ForegroundColor Red }
    }
}

# ------------------------------------------------------------------ prerequisites

if (-not $ServerPath) {
    $ServerPath = Join-Path $PSScriptRoot 'WinDiag.Mcp.exe'
}

if (-not (Test-Path $ServerPath)) {
    Write-Host "windiag server not found at '$ServerPath'." -ForegroundColor Red
    Write-Host 'Publish it and copy it next to this script:'
    Write-Host '  dotnet publish src\WinDiag.Mcp\WinDiag.Mcp.csproj -c Release -r win-x64 --self-contained ^'
    Write-Host '    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts\win-x64'
    Write-Host 'Use -r win-x86 instead on a 32-bit machine.'
    exit 2
}

$ServerPath = (Resolve-Path $ServerPath).Path

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Not elevated.' -ForegroundColor Red
    Write-Host 'These are precisely the checks that need administrator rights; run from an elevated prompt.'
    exit 1
}

$work = Join-Path $env:TEMP ("windiag-verify-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$transcript = Join-Path $work 'verify-transcript.txt'
try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
Start-Transcript -Path $transcript -Force | Out-Null

Write-Head 'Environment'
Write-Host "  Server  : $ServerPath"
Write-Host "  OS      : $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' })"
Write-Host "  Work dir: $work"

# ------------------------------------------------------------------ MCP over stdio

$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $ServerPath
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$psi.EnvironmentVariables['WINDIAG_ARTIFACT_DIR'] = $work

$server = [Diagnostics.Process]::Start($psi)
$script:NextId = 0

function Invoke-Mcp($method, $params, $timeoutSeconds = 60) {
    $script:NextId++
    $id = $script:NextId

    $request = @{ jsonrpc = '2.0'; id = $id; method = $method }
    if ($params) { $request.params = $params }

    $server.StandardInput.WriteLine(($request | ConvertTo-Json -Depth 8 -Compress))
    $server.StandardInput.Flush()

    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $task = $server.StandardOutput.ReadLineAsync()
        if (-not $task.Wait(1000)) { continue }

        $line = $task.Result
        if (-not $line) { continue }

        $message = $line | ConvertFrom-Json
        if ($message.id -eq $id) { return $message }
    }

    throw "no reply to '$method' within ${timeoutSeconds}s"
}

function Send-Notification($method) {
    $server.StandardInput.WriteLine((@{ jsonrpc = '2.0'; method = $method } | ConvertTo-Json -Compress))
    $server.StandardInput.Flush()
}

function Get-ToolResult($response) {
    # Tool results carry both prose and structured content; the structured form is what to assert on.
    if ($response.error) { throw "tool call failed: $($response.error.message)" }
    if ($response.result.isError) { throw "tool reported an error: $($response.result.content[0].text)" }
    return $response.result.structuredContent
}

try {
    Write-Head 'Handshake'

    $init = Invoke-Mcp 'initialize' @{
        protocolVersion = '2024-11-05'
        capabilities    = @{}
        clientInfo      = @{ name = 'windiag-verify'; version = '1.0' }
    }
    Assert-That 'server initializes' ($null -ne $init.result.serverInfo) $init.error.message
    Send-Notification 'notifications/initialized'

    $tools = (Invoke-Mcp 'tools/list').result.tools.name
    Write-Host "  tools: $($tools -join ', ')"
    Assert-That 'capture_activity is registered' ($tools -contains 'capture_activity')
    Assert-That 'path_handle_search is registered' ($tools -contains 'path_handle_search')

    Write-Head 'Capabilities as this machine sees them'

    $caps = Get-ToolResult (Invoke-Mcp 'tools/call' @{ name = 'capabilities'; arguments = @{} })
    Assert-That 'server reports itself elevated' ($caps.elevated -eq $true) 'expected elevated'
    foreach ($tool in $caps.tools) {
        $colour = if ($tool.status -eq 'Available') { 'Gray' } else { 'Yellow' }
        Write-Host ("    {0,-22} {1}" -f $tool.tool, $tool.status) -ForegroundColor $colour
    }

    # ============================================================ path_handle_search

    Write-Head 'path_handle_search (handle.exe, needs elevation)'

    $held = Join-Path $work ("held-" + [guid]::NewGuid().ToString('N') + '.bin')
    $stream = [IO.File]::Open($held, 'CreateNew', 'ReadWrite', 'None')
    try {
        $fragment = [IO.Path]::GetFileName($held)
        $search = Get-ToolResult (Invoke-Mcp 'tools/call' @{
                name      = 'path_handle_search'
                arguments = @{ nameFragment = $fragment }
            } 180)

        Write-Host "  matched $($search.totalMatched) handle(s); elevated=$($search.elevated)"
        Assert-That 'reports running elevated' ($search.elevated -eq $true)

        # This process holds the file open, so an exhaustive handle search must find this PID.
        $mine = @($search.handles | Where-Object { $_.processId -eq $PID })
        Assert-That 'finds the handle this script is holding' ($mine.Count -gt 0) `
            "no handle for PID $PID among $($search.totalMatched) matches"
    }
    finally {
        $stream.Dispose()
    }

    # ============================================================ capture_activity

    Write-Head "capture_activity + query_activity (Procmon, $CaptureSeconds s)"

    $marker = "windiag-verify-" + [guid]::NewGuid().ToString('N')
    $markerPath = Join-Path $work "$marker.txt"

    # Generate known activity for the whole capture window, so a working capture MUST contain it.
    $job = Start-Job -ScriptBlock {
        param($path, $seconds)
        $deadline = (Get-Date).AddSeconds($seconds)
        while ((Get-Date) -lt $deadline) {
            Set-Content -Path $path -Value (Get-Date -Format o) -ErrorAction SilentlyContinue
            Get-Content -Path $path -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep -Milliseconds 150
        }
    } -ArgumentList $markerPath, ($CaptureSeconds + 15)

    try {
        $capture = Get-ToolResult (Invoke-Mcp 'tools/call' @{
                name      = 'capture_activity'
                arguments = @{ durationSeconds = $CaptureSeconds }
            } (($CaptureSeconds + 240)))
    }
    finally {
        Receive-Job $job -Wait -AutoRemoveJob -ErrorAction SilentlyContinue | Out-Null
    }

    Write-Host "  trace : $($capture.capture.pmlPath)"
    Write-Host "  export: $($capture.capture.csvPath)"
    Write-Host "  events: $($capture.capture.totalEvents)"

    Assert-That 'capture produced a trace file' (Test-Path $capture.capture.pmlPath)
    Assert-That 'capture produced a CSV export' (Test-Path $capture.capture.csvPath)
    Assert-That 'capture recorded events' ($capture.capture.totalEvents -gt 0) `
        'zero events - the driver may not have loaded'

    $query = Get-ToolResult (Invoke-Mcp 'tools/call' @{
            name      = 'query_activity'
            arguments = @{ capturePath = $capture.capture.csvPath; pathContains = $marker; maxEvents = 5 }
        } 300)

    Write-Host "  marker events: $($query.query.matched) of $($query.query.scanned) scanned"

    # The decisive check. This script caused those operations during the window, so a capture that
    # works cannot miss them, and one that misses them is not working.
    Assert-That 'query finds the activity this script generated' ($query.query.matched -gt 0) `
        "no events mention $marker"

    Assert-That 'aggregate counts cover all matches, not just returned events' `
        ($query.query.scanned -ge $query.query.matched)
}
catch {
    $script:Failures++
    Write-Host ''
    Write-Host "ERROR: $_" -ForegroundColor Red
    Write-Host ($_.ScriptStackTrace) -ForegroundColor DarkGray
}
finally {
    try {
        if (-not $server.HasExited) {
            $server.StandardInput.Close()
            if (-not $server.WaitForExit(5000)) { $server.Kill() }
        }
    }
    catch { }

    $stderr = $server.StandardError.ReadToEnd()
    if ($stderr) {
        Write-Head 'Server stderr'
        Write-Host $stderr
    }
}

Write-Head 'Result'
Write-Host ("  {0} of {1} checks passed" -f ($script:Checks - $script:Failures), $script:Checks)

try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }

$zip = Join-Path $work 'windiag-verify-results.zip'
Compress-Archive -Path $transcript -DestinationPath $zip -Force -ErrorAction SilentlyContinue

if (Test-Path $zip) {
    Write-Host ''
    Write-Host '  BRING THIS BACK:' -ForegroundColor Green
    Write-Host "    $zip" -ForegroundColor Green
}

if ($script:Failures -gt 0) {
    Write-Host '  Captures are left in place for inspection.' -ForegroundColor Yellow
    exit 3
}

exit 0
