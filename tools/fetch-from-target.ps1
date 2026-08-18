<#
.SYNOPSIS
    Pulls a file off a target machine over the windiag server's own channel, with no SMB share.

.DESCRIPTION
    The mirror of deploy-target.ps1's staging: that script sends a file with put_file, this one
    retrieves it with get_file. It exists because everything the server PRODUCES -- the minidump
    capture_dump writes, the .pml and .csv capture_activity write -- was previously reachable only as a
    UNC path on the admin share, so collecting it dragged back the whole "System error 5" token-filtering
    dependency that put_file had already removed from deployment.

    The file arrives in slices. Each slice carries its own SHA-256, checked here before it is appended,
    so corruption on a lossy link is caught at the slice rather than as an opaque whole-file mismatch
    minutes later; the whole file's hash is taken on the first call and the reassembled copy is verified
    against it at the end.

    Slices are streamed straight to disk and never held in memory as one buffer, which is what makes a
    multi-hundred-megabyte dump practical -- and, when this runs from an agent's session rather than a
    shell, is what keeps those bytes out of the conversation.

.PARAMETER Target
    Target host name or IP running the windiag server.

.PARAMETER Token
    The target server's WINDIAG_TOKEN bearer token.

.PARAMETER RemotePath
    The file to fetch, as the TARGET sees it -- pass the path a capture returned, verbatim.

.PARAMETER OutFile
    Where to write it locally. Defaults to the remote file's name in the current directory.

.PARAMETER Port
    Port the server listens on. Defaults to 4024.

.PARAMETER ChunkBytes
    Bytes per slice. Defaults to 4 MB, matching the server's cap and the send side's chunk size.

.PARAMETER Force
    Overwrite an existing local file instead of refusing.

.EXAMPLE
    .\fetch-from-target.ps1 -Target 192.168.32.93 -Token $token `
        -RemotePath 'C:\Users\admin\AppData\Local\Temp\windiag\explorer_1904.dmp'

.EXAMPLE
    .\fetch-from-target.ps1 -Target 192.168.32.76 -Token $token `
        -RemotePath 'C:\...\activity.csv' -OutFile .\activity.csv -Force
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Target,
    [Parameter(Mandatory)] [string] $Token,
    [Parameter(Mandatory)] [string] $RemotePath,
    [string] $OutFile,
    [int] $Port = 4024,

    # 4 MB raw is ~5.6 MB of base64, which is the server's own per-call cap and what a 32-bit target
    # can encode in one piece.
    [int] $ChunkBytes = 4 * 1024 * 1024,

    [switch] $Force
)

$ErrorActionPreference = 'Stop'

function Write-Step([string] $Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Note([string] $Message) { Write-Host "    $Message" }

$address = "http://${Target}:${Port}"

if (-not $OutFile) { $OutFile = Join-Path (Get-Location) (Split-Path -Leaf $RemotePath) }
$OutFile = [IO.Path]::GetFullPath($OutFile)

if ((Test-Path $OutFile) -and -not $Force) {
    throw "$OutFile already exists. Pass -Force to overwrite it, or choose another -OutFile."
}

function Invoke-GetFile([long] $Offset, [int] $Length, [bool] $WithWholeHash) {
    $callArgs = @{
        path                 = $RemotePath
        offset               = $Offset
        length               = $Length
        includeWholeFileHash = $WithWholeHash
    }

    # 300s base plus size, matching the send side: a slice is small, but a slow lab link is slow in
    # both directions.
    $timeoutSec = [int]([Math]::Min(1800, 300 + $Length / 100000))

    # -Raw emits the structured content as a JSON *string*, so it has to be parsed back -- the same
    # idiom deploy-target.ps1 uses for every structured call.
    $result = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token -Tool get_file `
        -Arguments $callArgs -TimeoutSeconds $timeoutSec -Raw | ConvertFrom-Json

    if ($LASTEXITCODE -ne 0) {
        throw "get_file failed for $RemotePath (the server reported the reason above)."
    }

    return $result.file
}

function Get-Sha256Hex([byte[]] $Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes)) -replace '-', '') }
    finally { $sha.Dispose() }
}

Write-Step "Fetching $RemotePath from $address"

# The first slice also brings back the whole file's size and hash, so the loop knows how far it has to
# walk and what the finished copy must match -- one hash of the file, not one per slice.
$first = Invoke-GetFile -Offset 0 -Length $ChunkBytes -WithWholeHash $true

$total = [int64] $first.totalBytes
$expectedSha = "$($first.sha256)".ToUpperInvariant()
$slices = [Math]::Max(1, [Math]::Ceiling($total / $ChunkBytes))

Write-Note ("{0:N1} MB in {1} slice(s), SHA-256 {2}" -f ($total / 1MB), $slices, $expectedSha)

$directory = Split-Path -Parent $OutFile
if ($directory -and -not (Test-Path $directory)) { New-Item -ItemType Directory -Force $directory | Out-Null }

$stream = [IO.File]::Open($OutFile, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $slice = $first
    $index = 0

    while ($true) {
        $index++
        $bytes = [Convert]::FromBase64String($slice.content)

        # Verified before it is appended, so a corrupted slice never reaches the file and re-requesting
        # the same offset is unambiguous.
        $actual = Get-Sha256Hex $bytes
        $claimed = "$($slice.chunkSha256)".ToUpperInvariant()
        if ($actual -ne $claimed) {
            throw "Slice $index at offset $($slice.offset) arrived corrupted (SHA-256 $actual, expected $claimed). Nothing was appended; re-run."
        }

        $stream.Write($bytes, 0, $bytes.Length)
        Write-Note ("  slice {0}/{1} ({2:N0} bytes at {3:N0})" -f $index, $slices, $bytes.Length, $slice.offset)

        if ($slice.endOfFile) { break }

        $next = [int64] $slice.offset + [int64] $slice.length
        $slice = Invoke-GetFile -Offset $next -Length $ChunkBytes -WithWholeHash $false
    }
}
finally {
    $stream.Dispose()
}

# The same end-to-end check the send side does, in reverse: the reassembled copy is compared against the
# hash the target reported for the original.
$landedSha = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash.ToUpperInvariant()
if ($landedSha -ne $expectedSha) {
    throw "$OutFile assembled to SHA-256 $landedSha, not the expected $expectedSha. The copy is not trustworthy; delete it and re-run."
}

$landedSize = (Get-Item $OutFile).Length
Write-Step "Wrote $OutFile"
Write-Note ("{0:N0} bytes, SHA-256 verified against the target's copy" -f $landedSize)
