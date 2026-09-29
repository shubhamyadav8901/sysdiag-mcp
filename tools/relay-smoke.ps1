<#
.SYNOPSIS
    Drives a published relay over stdio: initialize, list tools, call one forwarded tool.

.DESCRIPTION
    Proves a relay build works end to end before any MCP registration is pointed at it. The relay
    pre-connects ~/.windiag-targets.json, so the forwarded tool named by -Tool must appear in tools/list
    and answer. A registration swapped to an untested binary is only discovered broken after a session
    restart, with the old relay already gone.

.EXAMPLE
    .\tools\relay-smoke.ps1 -Relay artifacts\diagrelay\DiagRelay.Mcp.exe -Tool runner1__capabilities
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Relay,
    [string] $Tool = 'runner1__capabilities',
    [int] $TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'

$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = (Resolve-Path $Relay).Path
$start.UseShellExecute = $false
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true

# Windows PowerShell's Process builds the child's stdin writer from [Console]::InputEncoding and flushes
# it inside Start(), so on a UTF-8 console a byte-order mark reaches the relay before anything this
# script sends -- measured as EF BB BF ahead of the first brace. Wrapping the stream afterwards is too
# late for that reason. The .NET relay tolerates the mark; a stricter JSON-RPC peer rejects the first
# line outright, so the smoke test would fail a relay that is fine. The encoding is swapped only for
# the Start() call and put back, so an interactive console is left as it was.
$previousInputEncoding = [Console]::InputEncoding
try {
    [Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
    $process = [System.Diagnostics.Process]::Start($start)
}
finally {
    [Console]::InputEncoding = $previousInputEncoding
}

# stderr drained asynchronously, or a chatty relay blocks on a full pipe and the smoke test hangs.
$null = $process.StandardError.ReadToEndAsync()

function Send([hashtable] $message) {
    $process.StandardInput.WriteLine(($message | ConvertTo-Json -Compress -Depth 10))
    $process.StandardInput.Flush()
}

# One read in flight at a time. Calling ReadLineAsync again while an earlier call is still pending
# throws "The stream is currently in use by a previous operation" -- and a pending read is exactly
# what a slow pre-connect or a slow forwarded call leaves behind, so a loop that started a fresh read
# on every timeout would fail precisely when a target is slow.
$script:pending = $null

function Receive([int] $id, [string] $what) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($null -eq $script:pending) { $script:pending = $process.StandardOutput.ReadLineAsync() }
        if (-not $script:pending.Wait([TimeSpan]::FromSeconds(1))) { continue }

        $line = $script:pending.Result
        $script:pending = $null
        if ($null -eq $line) { throw "The relay closed stdout before answering $what." }

        # Notifications carry no id and are skipped; so is any reply to an earlier request.
        $reply = $line | ConvertFrom-Json
        if ($reply.id -ne $id) { continue }

        # A protocol-level refusal is a JSON-RPC error object with no result at all. Unchecked, the next
        # line to touch .result threw "Cannot index into a null array" and the relay's own reason for
        # refusing was thrown away -- exactly the sentence the person running this needed.
        if ($null -ne $reply.error) {
            throw "The relay refused $what`: $($reply.error.message) (JSON-RPC code $($reply.error.code))"
        }
        return $reply
    }
    throw "No reply to $what within ${TimeoutSeconds}s."
}

try {
    Send @{ jsonrpc = '2.0'; id = 1; method = 'initialize'; params = @{
        protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'relay-smoke'; version = '1' } } }
    $null = Receive 1 'initialize'
    Send @{ jsonrpc = '2.0'; method = 'notifications/initialized' }

    Send @{ jsonrpc = '2.0'; id = 2; method = 'tools/list' }
    $names = (Receive 2 'tools/list').result.tools.name
    if ($names -notcontains $Tool) {
        throw "tools/list has no '$Tool'. It lists: $($names -join ', ')"
    }
    Write-Host "tools/list: $($names.Count) tools, including $Tool"

    Send @{ jsonrpc = '2.0'; id = 3; method = 'tools/call'; params = @{ name = $Tool; arguments = @{} } }
    $call = Receive 3 "tools/call $Tool"
    if ($call.result.isError) { throw "$Tool returned an error: $($call.result.content[0].text)" }

    # Every windiag tool carries a rendered summary, but a forwarded result arrives with the whole
    # structured object serialised into one line of text; printing that line put a page of JSON where
    # one sentence was meant. Prefer the summary, from structured content or from that serialised text.
    $text = $call.result.content[0].text
    $summary = $call.result.structuredContent.summary
    if (-not $summary) { try { $summary = ($text | ConvertFrom-Json).summary } catch { $summary = $null } }
    if (-not $summary) { $summary = $text }
    Write-Host ($summary -split "`r?`n")[0]
}
finally {
    $process.StandardInput.Close()
    if (-not $process.WaitForExit(5000)) { $process.Kill() }
}
