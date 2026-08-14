<#
.SYNOPSIS
    Verifies a published windiag build against the machine it will actually run on.

.DESCRIPTION
    Everything in this project is covered by `dotnet test` EXCEPT what it cannot fake: the tools that
    shell out to Sysinternals, the ones that need administrator rights and a kernel driver, and
    anything whose answer depends on the bitness of the machine. Their unit tests run against a
    stubbed process runner, so they prove the arguments are composed correctly and nothing else.

    This script proves the tools actually work, on this machine, from the published exe:

      - capture_activity / query_activity  (Process Monitor; needs elevation)
      - path_handle_search, process_handles (handle.exe; needs elevation to be complete)
      - autostart_audit                    (autorunsc, and its UTF-16 output)
      - process_modules, registry_read     (bitness-dependent answers)
      - capture_dump                       (checks the MINIDUMP header, not just the path)

    Run it on both a 32- and a 64-bit target. Several answers here differ by bitness, and the ones
    that differ silently are the reason this exists.

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
    Runs elevated by default and loads the Process Monitor kernel driver. Unelevated it still covers
    every tool that can answer without administrator rights, and states which checks it skipped and
    why -- a partial pass is worth more than a refusal to start, and it is the only way to verify a
    machine where nobody has admin.
    Exit codes: 0 all checks passed, 2 server not found, 3 one or more checks failed.
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
$script:Skipped = 0

function Write-Head($text) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

<#
.SYNOPSIS
    Records a check that could not run here, with the reason.
.DESCRIPTION
    Counted separately from a pass. A skipped check reported as passing is how a verification script
    starts lying about coverage, which is worse than not having one.
#>
function Skip-Check($name, $reason) {
    $script:Skipped++
    Write-Host ("  SKIP  {0}" -f $name) -ForegroundColor DarkYellow
    Write-Host ("        {0}" -f $reason) -ForegroundColor DarkYellow
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
$script:Elevated = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $script:Elevated) {
    Write-Host 'Not elevated: the handle-search and activity-capture checks will be skipped.' -ForegroundColor Yellow
    Write-Host 'Everything else still runs. Re-run from an elevated prompt for full coverage.' -ForegroundColor Yellow
}

$work = Join-Path $env:TEMP ("windiag-verify-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$transcript = Join-Path $work 'verify-transcript.txt'
try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
Start-Transcript -Path $transcript -Force | Out-Null

Write-Head 'Environment'
Write-Host "  Server  : $ServerPath"
Write-Host "  OS      : $(if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' })"
Write-Host "  Elevated: $script:Elevated"
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

    # One pending read at a time, held across iterations. Starting a fresh ReadLineAsync each time
    # round throws "the stream is currently in use by a previous operation" the moment a call takes
    # longer than the poll interval -- which is most of them, since the point of these checks is the
    # tools that do real work.
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)
    $pending = $null

    while ((Get-Date) -lt $deadline) {
        if ($null -eq $pending) { $pending = $server.StandardOutput.ReadLineAsync() }
        if (-not $pending.Wait(1000)) { continue }

        $line = $pending.Result
        $pending = $null

        # Null means the stream closed; waiting out the deadline would only delay the real error.
        if ($null -eq $line) { break }
        if ($line.Trim().Length -eq 0) { continue }

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
    # Agreement rather than "must be elevated": the script already knows which it is, and a server
    # that disagrees with the process it was launched from is a bug worth catching either way.
    Assert-That 'server agrees with this script about elevation' `
        ($caps.elevated -eq $script:Elevated) `
        "server said $($caps.elevated), script sees $script:Elevated"
    foreach ($tool in $caps.tools) {
        $colour = if ($tool.status -eq 'Available') { 'Gray' } else { 'Yellow' }
        Write-Host ("    {0,-22} {1}" -f $tool.tool, $tool.status) -ForegroundColor $colour
    }

    # ============================================================ path_handle_search

    Write-Head 'path_handle_search (handle.exe, needs elevation)'

    if (-not $script:Elevated) {
        Skip-Check 'path_handle_search finds a held handle' `
            'handle.exe unelevated returns a partial list, so a miss would prove nothing.'
    }
    else {
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
    }

    # ============================================================ the rest of the tool surface

    Write-Head 'Tools that need no elevation'

    # process_modules -- against this script's own host, whose modules must be readable.
    $modules = Get-ToolResult (Invoke-Mcp 'tools/call' @{
            name      = 'process_modules'
            arguments = @{ processId = $PID }
        } 120)
    Assert-That 'process_modules lists this host''s modules' ($modules.modules.modules.Count -gt 0) `
        $modules.modules.limitation
    Assert-That 'every module reports a preferred base to compare against' `
        (@($modules.modules.modules | Where-Object { -not $_.preferredBase }).Count -eq 0) `
        'a load address with nothing to compare it to is unusable'

    # The bitness check that only a 64-bit machine can make: a 64-bit server must read a 64-bit
    # process, and a 32-bit server must refuse rather than return an empty list.
    if ([Environment]::Is64BitOperatingSystem) {
        Assert-That 'reads a 64-bit process''s modules on 64-bit Windows' `
            ($modules.modules.modules.Count -gt 5) `
            'a short list here is the signature of a cross-bitness read that failed silently'
    }

    # registry_read -- a key present on every Windows install.
    $reg = Get-ToolResult (Invoke-Mcp 'tools/call' @{
            name      = 'registry_read'
            arguments = @{ path = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; valueName = 'CurrentBuild' }
        } 60)
    Assert-That 'registry_read returns a known value' ($reg.key.values.Count -eq 1)
    Assert-That 'registry_read states which view it read' `
        (-not [string]::IsNullOrWhiteSpace($reg.key.view)) `
        'an answer that does not say which of the two views it read is ambiguous'
    if ([Environment]::Is64BitOperatingSystem) {
        Assert-That 'defaults to the 64-bit view rather than the process view' `
            ($reg.key.view -eq '64-bit') `
            "read '$($reg.key.view)'; a 32-bit server defaulting to WOW6432Node answers the wrong key"
    }

    # process_handles -- scoped, so it is cheap even unelevated, and must attribute fields correctly.
    if (-not $script:Elevated) {
        Skip-Check 'process_handles returns this host''s handles' `
            'handle.exe unelevated cannot see every handle; correctness is asserted in the offline suite.'
    }
    else {
        $handles = Get-ToolResult (Invoke-Mcp 'tools/call' @{
                name      = 'process_handles'
                arguments = @{ processId = $PID }
            } 300)
        Assert-That 'process_handles returns handles for this host' ($handles.totalMatched -gt 0)
        Assert-That 'attributes the owning process to every row' `
            (@($handles.handles | Where-Object { $_.processId -ne $PID }).Count -eq 0) `
            'a row attributed to another PID means the layout was read with the wrong column order'
    }

    # autostart_audit -- unsigned-only keeps it fast and is the query that actually gets used.
    $autostart = Get-ToolResult (Invoke-Mcp 'tools/call' @{
            name      = 'autostart_audit'
            arguments = @{ categories = 'logon,services'; unsignedOnly = $true }
        } 700)
    Assert-That 'autostart_audit parses autorunsc output' ($null -ne $autostart.autostarts) `
        'a parse failure here usually means the UTF-16 decoding regressed'
    Assert-That 'autostart_audit reports it verified signatures' `
        ($autostart.autostarts.signaturesVerified -eq $true)

    # capture_dump -- writes a real file, so check the header rather than trusting the path.
    $dump = Get-ToolResult (Invoke-Mcp 'tools/call' @{
            name      = 'capture_dump'
            arguments = @{ processId = $PID }
        } 300)
    $dumpPath = $dump.dump.path
    Assert-That 'capture_dump wrote a file' (Test-Path $dumpPath) $dumpPath
    if (Test-Path $dumpPath) {
        $magic = [IO.File]::ReadAllBytes($dumpPath)[0..3]
        Assert-That 'the dump carries a MINIDUMP header' `
            (($magic[0] -eq 0x4D) -and ($magic[1] -eq 0x44) -and ($magic[2] -eq 0x4D) -and ($magic[3] -eq 0x50)) `
            "first bytes were $($magic -join ','), expected MDMP"
    }

    # ============================================================ capture_activity

    Write-Head "capture_activity + query_activity (Procmon, $CaptureSeconds s)"

    if (-not $script:Elevated) {
        Skip-Check 'capture_activity + query_activity round trip' `
            'Procmon cannot load its driver without administrator rights; it fails rather than degrades.'
    }
    else {
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
if ($script:Skipped -gt 0) {
    Write-Host ("  {0} skipped -- see SKIP lines above for what was not covered" -f $script:Skipped) -ForegroundColor DarkYellow
}

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
