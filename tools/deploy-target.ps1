<#
.SYNOPSIS
    Builds windiag, stages it and its Sysinternals dependencies on a target machine, and restarts it.

.DESCRIPTION
    One command from the base machine that leaves a target fully set up and running the build in this
    working tree. It publishes the right architecture, downloads the pinned Sysinternals binaries,
    verifies every file by SHA-256 both before and after the copy, records what it staged, and then
    asks the running server to replace itself.

    Every step is hash-checked because the failure this exists to prevent is silent. An 89 MB SMB copy
    to a lab VM was observed truncating at exactly the right file size, twice; and the 32-bit build of
    handle.exe on 64-bit Windows answers "No matching handles found." to every query rather than
    failing. Both look like success from the outside.

    The manifest written to the target (windiag-staged.json) is compared on the next run, so a machine
    someone has since touched by hand shows up as drift instead of being quietly overwritten.

.PARAMETER Target
    Target host name or IP. Reachable over SMB (admin share) and, if already running, over HTTP.

.PARAMETER Token
    Bearer token of the running server, needed only to trigger update_self. Never written to disk and
    never passed to the target as an argument; if omitted, the script stages everything and prints the
    command to start the server by hand.

.PARAMETER Architecture
    x86 or x64. Defaults to asking the running server; required when nothing is running yet, because
    guessing it wrong produces a server that starts and then answers wrongly.

.PARAMETER RemotePath
    Directory on the target, as the target sees it. Its admin share equivalent is derived from it.

.PARAMETER AcceptUpstreamChange
    Rewrite tools/sysinternals.json when Sysinternals has shipped a new build. Without this the script
    stops on a hash change rather than deploying something nobody pinned.

.EXAMPLE
    .\deploy-target.ps1 -Target 192.168.32.76 -Token $token

.EXAMPLE
    .\deploy-target.ps1 -Target 192.168.32.76 -Architecture x64 -SkipServer
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Target,
    [string] $Token,
    [ValidateSet('x86', 'x64')] [string] $Architecture,
    [string] $RemotePath = 'C:\Users\admin\Desktop\WinDiag',
    [int] $Port = 4024,

    # Sysinternals only; leaves the server binary alone. Useful when the target is already running the
    # build you want and only its tools are missing.
    [switch] $SkipServer,
    [switch] $SkipSysinternals,

    # Reuse whatever is already in artifacts/ rather than publishing again.
    [switch] $SkipBuild,
    [switch] $AcceptUpstreamChange
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $PSScriptRoot 'sysinternals.json'
$cacheDir = Join-Path $repo 'artifacts\sysinternals'
$address = "http://${Target}:${Port}"

# The admin share is derived rather than asked for, so the two paths cannot disagree.
if ($RemotePath -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "-RemotePath must be a local path on the target, e.g. C:\WinDiag. Got: $RemotePath"
}
$remoteShare = "\\$Target\$($Matches[1])`$\$($Matches[2])"

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Note($text) { Write-Host "    $text" -ForegroundColor DarkGray }

function Get-Sha256($path) { (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToUpperInvariant() }

<#
.SYNOPSIS
    Copies one file and proves it arrived intact, retrying a corrupt transfer.
.DESCRIPTION
    Not defensive programming: an SMB copy of a 89 MB build to a lab VM completed "successfully" with
    the right byte count and the wrong contents, twice in a row. Without the read-back the next step
    would have been update_self refusing a hash it could not explain.
#>
function Copy-Verified {
    param([string] $Source, [string] $Destination, [int] $Attempts = 3)

    $expected = Get-Sha256 $Source

    for ($i = 1; $i -le $Attempts; $i++) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
        $actual = Get-Sha256 $Destination

        if ($actual -eq $expected) {
            return $expected
        }

        Write-Warning "$(Split-Path -Leaf $Source): attempt $i landed as $actual, expected $expected. Retrying."
    }

    throw "$(Split-Path -Leaf $Source) could not be copied to $Destination intact after $Attempts attempts."
}

# ---------------------------------------------------------------------------------------------------
# 1. Which architecture
# ---------------------------------------------------------------------------------------------------

function Resolve-Architecture {
    if ($Architecture) { return $Architecture }

    if (-not $Token) {
        throw "-Architecture is required when -Token is not supplied: with no running server to ask, " +
              "the only alternative is guessing, and a win-x86 server on 64-bit Windows cannot read a " +
              "64-bit process's modules or search its handles."
    }

    Write-Step "Asking $address which architecture it is"

    try {
        $overview = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token `
            -Tool system_overview -Raw | ConvertFrom-Json
    }
    catch {
        throw "Could not reach a running server at $address to determine the architecture ($($_.Exception.Message)). " +
              "Pass -Architecture x86 or -Architecture x64 explicitly."
    }

    # The OS, not the server answering: a win-x86 server reporting for itself is exactly the mismatch
    # this deploy is most likely being run to fix, so its own bitness is the wrong thing to copy.
    if ($null -eq $overview.system.is64BitOperatingSystem) {
        throw "system_overview did not report is64BitOperatingSystem. Pass -Architecture explicitly."
    }

    $resolved = if ($overview.system.is64BitOperatingSystem) { 'x64' } else { 'x86' }
    Write-Note "$resolved ($($overview.system.operatingSystem), $($overview.system.architecture))"
    return $resolved
}

$Architecture = Resolve-Architecture
$rid = "win-$Architecture"

# ---------------------------------------------------------------------------------------------------
# 2. Sysinternals, pinned
# ---------------------------------------------------------------------------------------------------

function Get-PinnedSysinternals {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    New-Item -ItemType Directory -Force $cacheDir | Out-Null

    $changed = @()
    $resolved = @()

    foreach ($package in $manifest.packages) {
        $needsDownload = $false

        foreach ($file in $package.files) {
            $local = Join-Path $cacheDir $file.name
            if (-not (Test-Path $local) -or (Get-Sha256 $local) -ne $file.sha256.ToUpperInvariant()) {
                $needsDownload = $true
            }
        }

        if ($needsDownload) {
            $zip = Join-Path $cacheDir $package.package
            Write-Note "downloading $($package.package)"
            Invoke-WebRequest -Uri "$($manifest.baseUrl)$($package.package)" -OutFile $zip `
                -UseBasicParsing -TimeoutSec 300

            # Expand-Archive refuses to overwrite in PS 5.1 without -Force, and extracts the whole zip;
            # only the files named in the manifest are used from it.
            Expand-Archive -Path $zip -DestinationPath $cacheDir -Force
            Remove-Item $zip -Force
        }

        foreach ($file in $package.files) {
            $local = Join-Path $cacheDir $file.name
            if (-not (Test-Path $local)) {
                throw "$($package.package) did not contain $($file.name). The package layout has changed."
            }

            $actual = Get-Sha256 $local

            if ($actual -ne $file.sha256.ToUpperInvariant()) {
                # Upstream always serves latest, so this is expected eventually -- but it must be a
                # decision someone makes and commits, not something a deploy absorbs quietly.
                $version = (Get-Item $local).VersionInfo.FileVersion
                $changed += [pscustomobject]@{
                    Name = $file.name; Pinned = $file.sha256; Actual = $actual
                    PinnedVersion = $file.version; ActualVersion = $version
                }
                $file.sha256 = $actual
                $file.version = "$version"
                $file.sizeBytes = (Get-Item $local).Length
            }

            # Refusing an unsigned Sysinternals binary matters more than the hash: the hash only says
            # it matches what someone pinned, which could itself have been swapped in transit.
            $signature = Get-AuthenticodeSignature -LiteralPath $local
            if ($signature.Status -ne 'Valid') {
                throw "$($file.name) is not validly signed ($($signature.Status)). Refusing to stage it."
            }
            if ($signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
                throw "$($file.name) is signed by $($signature.SignerCertificate.Subject), not Microsoft. Refusing to stage it."
            }

            $resolved += [pscustomobject]@{ Name = $file.name; Path = $local; Sha256 = $actual; Version = "$($file.version)" }
        }
    }

    if ($changed.Count -gt 0) {
        $summary = ($changed | ForEach-Object { "  $($_.Name): $($_.PinnedVersion) -> $($_.ActualVersion)" }) -join "`n"

        if (-not $AcceptUpstreamChange) {
            throw "Sysinternals has shipped new builds since these were pinned:`n$summary`n" +
                  "Nothing has been staged. Re-run with -AcceptUpstreamChange to update " +
                  "tools/sysinternals.json, then commit that change as a deliberate version bump."
        }

        $manifest.pinnedOn = (Get-Date).ToString('yyyy-MM-dd')
        $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
        Write-Warning "Re-pinned tools/sysinternals.json:`n$summary`nCommit that change."
    }

    return $resolved
}

$sysinternals = @()
if (-not $SkipSysinternals) {
    Write-Step "Verifying pinned Sysinternals binaries"
    $sysinternals = Get-PinnedSysinternals
    Write-Note (($sysinternals | ForEach-Object { "$($_.Name) v$($_.Version)" }) -join ', ')
}

# ---------------------------------------------------------------------------------------------------
# 3. The server build
# ---------------------------------------------------------------------------------------------------

$publishDir = Join-Path $repo "artifacts\$rid-deploy"
$serverExe = Join-Path $publishDir 'WinDiag.Mcp.exe'

if (-not $SkipServer) {
    if (-not $SkipBuild) {
        Write-Step "Publishing $rid"
        & dotnet publish (Join-Path $repo 'src\WinDiag.Mcp') -c Release -r $rid --self-contained `
            -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o $publishDir | Out-Null

        if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }
    }

    if (-not (Test-Path $serverExe)) {
        throw "$serverExe does not exist. Drop -SkipBuild, or publish it first."
    }

    Write-Note "$([math]::Round((Get-Item $serverExe).Length / 1MB, 1)) MB, SHA-256 $(Get-Sha256 $serverExe)"
}

# ---------------------------------------------------------------------------------------------------
# 4. What is on the target now
# ---------------------------------------------------------------------------------------------------

$stagedManifest = Join-Path $remoteShare 'windiag-staged.json'

Write-Step "Checking $remoteShare"

if (-not (Test-Path $remoteShare)) {
    New-Item -ItemType Directory -Force $remoteShare | Out-Null
    Write-Note 'created'
}

$previous = $null

if (Test-Path $stagedManifest) {
    $previous = Get-Content -LiteralPath $stagedManifest -Raw | ConvertFrom-Json
    Write-Note "last deployed $($previous.deployedOn) from $($previous.deployedFrom) ($($previous.commit))"

    foreach ($entry in $previous.files) {
        $onDisk = Join-Path $remoteShare $entry.name
        if (-not (Test-Path $onDisk)) {
            Write-Warning "$($entry.name) is recorded as deployed but is missing from the target."
        }
        elseif ((Get-Sha256 $onDisk) -ne $entry.sha256.ToUpperInvariant()) {
            # The point of writing the manifest: a file changed by hand since the last deploy is
            # reported rather than silently replaced, because knowing it happened is the useful part.
            Write-Warning "$($entry.name) on the target no longer matches what this script staged; replacing it."
        }
    }
}
else {
    Write-Note 'no previous deployment recorded'
}

# ---------------------------------------------------------------------------------------------------
# 5. Stage
# ---------------------------------------------------------------------------------------------------

$staged = @()

if (-not $SkipSysinternals) {
    Write-Step "Staging $($sysinternals.Count) Sysinternals binaries"

    foreach ($tool in $sysinternals) {
        $destination = Join-Path $remoteShare $tool.Name

        if ((Test-Path $destination) -and (Get-Sha256 $destination) -eq $tool.Sha256) {
            Write-Note "$($tool.Name) already current"
        }
        else {
            $hash = Copy-Verified -Source $tool.Path -Destination $destination
            Write-Note "$($tool.Name) staged and verified"
            $null = $hash
        }

        $staged += [pscustomobject]@{ name = $tool.Name; sha256 = $tool.Sha256; version = $tool.Version }
    }
}

$serverHash = $null

if (-not $SkipServer) {
    # Staged under a different name, never written over the running exe: the live binary is locked, and
    # an earlier attempt to work around that by renaming it took the server down.
    Write-Step 'Staging the server build as WinDiag.Mcp.new.exe'
    $serverHash = Copy-Verified -Source $serverExe -Destination (Join-Path $remoteShare 'WinDiag.Mcp.new.exe')
    Write-Note "verified $serverHash"

    $staged += [pscustomobject]@{ name = 'WinDiag.Mcp.exe'; sha256 = $serverHash; version = 'this build' }
}

# A skipped category keeps whatever the last full deploy recorded. Dropping it would turn the manifest
# from a record of what is on the target into a record of the last command that happened to be typed,
# and the next run would then report no drift because it had nothing to compare against.
if ($previous) {
    $recorded = $staged | ForEach-Object { $_.name }

    foreach ($entry in $previous.files) {
        if ($entry.name -notin $recorded) {
            $staged += [pscustomobject]@{ name = $entry.name; sha256 = $entry.sha256; version = $entry.version }
            Write-Note "carrying forward $($entry.name) from the previous deployment"
        }
    }
}

# The commit describes the SERVER, so a Sysinternals-only deploy must not restamp it -- that would
# claim the target is running code it has never been given.
$commit = if ($SkipServer) {
    if ($previous) { $previous.commit } else { 'unknown' }
}
else {
    try { (& git -C $repo rev-parse --short HEAD).Trim() } catch { 'unknown' }
}

[pscustomobject]@{
    deployedOn   = (Get-Date).ToString('s')
    deployedFrom = $env:COMPUTERNAME
    commit       = $commit
    architecture = $Architecture
    files        = $staged
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $stagedManifest -Encoding utf8

Write-Note "recorded in windiag-staged.json"

# ---------------------------------------------------------------------------------------------------
# 6. Swap the running server
# ---------------------------------------------------------------------------------------------------

if ($SkipServer) {
    Write-Step 'Done. The server binary was left alone.'
    if ($Token) {
        Write-Note "Sysinternals changes take effect immediately; re-run capabilities to confirm."
    }
    return
}

if (-not $Token) {
    Write-Step 'Staged, but not installed: no -Token was supplied.'
    Write-Host ""
    Write-Host "  On $Target, from an ELEVATED terminal:" -ForegroundColor Yellow
    Write-Host "    cd `"$RemotePath`""
    Write-Host "    move /y WinDiag.Mcp.new.exe WinDiag.Mcp.exe"
    Write-Host "    set WINDIAG_TOKEN=<choose one>"
    Write-Host "    WinDiag.Mcp.exe --http http://${Target}:${Port}"
    Write-Host ""
    return
}

Write-Step "Installing via update_self"

& (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token -Tool update_self `
    -Arguments @{ expectedSha256 = $serverHash } | Out-Null

Write-Note 'server is restarting; waiting for it to come back'

$deadline = (Get-Date).AddSeconds(90)
$tools = $null

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5

    try {
        $tools = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token -Tool capabilities -Raw |
            ConvertFrom-Json
        break
    }
    catch {
        continue
    }
}

if (-not $tools) {
    throw "The server did not come back on $address within 90s. Read the helper log named in the " +
          "update_self result on the target, at %TEMP%\windiag\self-update.log."
}

Write-Step "$Target is running commit $commit"

foreach ($capability in $tools.tools | Where-Object { $_.status -ne 'Available' }) {
    Write-Warning "$($capability.tool) [$($capability.status)] $($capability.detail)"
}

Write-Note "$(($tools.tools | Where-Object { $_.status -eq 'Available' }).Count) of $($tools.tools.Count) tools fully available"
