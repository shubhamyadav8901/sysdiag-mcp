<#
.SYNOPSIS
    Calls a tool on a windiag server over HTTP and prints the result.

.DESCRIPTION
    A minimal MCP client for driving a windiag server running on another machine, the way cdb drives
    dbgsrv. Handles the initialize handshake, the session header and the server-sent-event framing, so
    a caller can just name a tool and pass arguments.

    Exists because the interesting machine is usually not this one. Once someone has started the server
    elevated on a target, everything else - capture, query, dump, verification - is done from here.

.PARAMETER Address
    Base URL of the target server, e.g. http://10.0.0.5:7777

.PARAMETER Token
    Bearer token. Printed by the server at startup when WINDIAG_TOKEN is not set.

.PARAMETER Tool
    Tool name. Omit to list the available tools.

.PARAMETER Arguments
    Hashtable of tool arguments.

.PARAMETER Raw
    Emit the structured content as JSON instead of the human-readable summary.

.EXAMPLE
    .\mcp-call.ps1 -Address http://10.0.0.5:7777 -Token abc123

.EXAMPLE
    .\mcp-call.ps1 -Address http://10.0.0.5:7777 -Token abc123 -Tool system_overview

.EXAMPLE
    .\mcp-call.ps1 -Address http://10.0.0.5:7777 -Token abc123 -Tool capture_activity -Arguments @{ durationSeconds = 15 } -TimeoutSeconds 300
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Address,
    [Parameter(Mandatory)] [string] $Token,
    [string] $Tool,

    # Object, not hashtable: this is driven from a non-PowerShell shell as often as from PowerShell,
    # where a hashtable literal arrives as a string. Accept either rather than fail on the useful case.
    [object] $Arguments = @{},
    [int] $TimeoutSeconds = 120,
    [switch] $Raw
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ($Arguments -is [string]) {
    $text = $Arguments.Trim()
    if (-not $text) {
        $Arguments = @{}
    }
    else {
        try {
            $parsed = $text | ConvertFrom-Json
        }
        catch {
            $example = '{"name":"Spooler"}'
            throw "-Arguments must be a hashtable or a JSON object, for example $example. Got: $text"
        }

        $table = @{}
        foreach ($property in $parsed.PSObject.Properties) { $table[$property.Name] = $property.Value }
        $Arguments = $table
    }
}

$base = $Address.TrimEnd('/') + '/'
$script:Session = $null
$script:Id = 0

function Invoke-Rpc($method, $params, $timeout) {
    $script:Id++
    $body = @{ jsonrpc = '2.0'; id = $script:Id; method = $method }
    if ($params) { $body.params = $params }

    $headers = @{
        Authorization = "Bearer $Token"
        Accept        = 'application/json, text/event-stream'
    }
    if ($script:Session) { $headers['Mcp-Session-Id'] = $script:Session }

    $response = Invoke-WebRequest -Uri $base -Method Post -Headers $headers `
        -ContentType 'application/json' -TimeoutSec $timeout `
        -Body ($body | ConvertTo-Json -Depth 10 -Compress) -UseBasicParsing

    if (-not $script:Session -and $response.Headers['Mcp-Session-Id']) {
        $script:Session = $response.Headers['Mcp-Session-Id']
    }

    # Streamable HTTP replies as server-sent events; the payload is on the data: line.
    $payload = $response.Content
    foreach ($line in $payload -split "`n") {
        if ($line.Trim().StartsWith('data:')) {
            $payload = $line.Trim().Substring(5).Trim()
            break
        }
    }

    $message = $payload | ConvertFrom-Json
    if ($message.error) { throw "$method failed: $($message.error.message)" }
    return $message.result
}

function Send-Notification($method) {
    $headers = @{ Authorization = "Bearer $Token"; Accept = 'application/json, text/event-stream' }
    if ($script:Session) { $headers['Mcp-Session-Id'] = $script:Session }

    Invoke-WebRequest -Uri $base -Method Post -Headers $headers -ContentType 'application/json' `
        -Body (@{ jsonrpc = '2.0'; method = $method } | ConvertTo-Json -Compress) `
        -UseBasicParsing -TimeoutSec 30 | Out-Null
}

$init = Invoke-Rpc 'initialize' @{
    protocolVersion = '2024-11-05'
    capabilities    = @{}
    clientInfo      = @{ name = 'mcp-call'; version = '1.0' }
} 30

Write-Host "connected to $($init.serverInfo.name) $($init.serverInfo.version) at $Address" -ForegroundColor DarkGray
Send-Notification 'notifications/initialized'

if (-not $Tool) {
    $tools = (Invoke-Rpc 'tools/list' $null 30).tools
    Write-Host "$($tools.Count) tools:" -ForegroundColor Cyan
    foreach ($t in $tools | Sort-Object name) {
        Write-Host ("  {0,-22} {1}" -f $t.name, $t.title)
    }
    exit 0
}

$result = Invoke-Rpc 'tools/call' @{ name = $Tool; arguments = $Arguments } $TimeoutSeconds

if ($result.isError) {
    Write-Host $result.content[0].text -ForegroundColor Red
    exit 1
}

# Results go to the SUCCESS stream, not to the host. Write-Host cannot be captured by redirection, so
# emitting there makes the script unusable in a pipeline - which is most of the point of having it.
# Only the connection banner above is host chrome.
if ($Raw) {
    Write-Output ($result.structuredContent | ConvertTo-Json -Depth 12)
}
else {
    # Every windiag tool returns a rendered summary alongside its structured content.
    $summary = $result.structuredContent.summary
    if ($summary) { Write-Output $summary }
    else { Write-Output ($result.structuredContent | ConvertTo-Json -Depth 12) }
}

exit 0
