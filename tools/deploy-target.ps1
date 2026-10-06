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
    Directory on the target, as the target sees it; its admin share equivalent is derived from it.
    Defaults to wherever the running server already lives, which is asked for rather than assumed --
    a wrong default here does not fail, it stages a complete install into a directory nobody is using.

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
    [string] $RemotePath,
    [int] $Port = 4024,

    # Sysinternals only; leaves the server binary alone. Useful when the target is already running the
    # build you want and only its tools are missing.
    [switch] $SkipServer,
    [switch] $SkipSysinternals,

    # Reuse whatever is already in artifacts/ rather than publishing again.
    [switch] $SkipBuild,
    [switch] $AcceptUpstreamChange,

    # Force staging over the SMB admin share even when a server is running. The staging default is the
    # server's own HTTP channel; this is the escape hatch for the one case HTTP cannot cover -- landing
    # a build whose put_file protocol the RUNNING server does not yet speak (the chunk/append support
    # had to arrive this way once) -- and a fallback if the HTTP transfer will not go through.
    [switch] $Smb
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

. "$PSScriptRoot\windiag-acl.ps1"

$repo = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $PSScriptRoot 'sysinternals.json'
$cacheDir = Join-Path $repo 'artifacts\sysinternals'
$address = "http://${Target}:${Port}"

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
    $name = Split-Path -Leaf $Source

    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            # -ErrorAction Stop explicitly: catch [type] only fires on a terminating error, and relying
            # on $ErrorActionPreference for that would make this depend on a setting far away.
            Copy-Item -LiteralPath $Source -Destination $Destination -Force -ErrorAction Stop
            $actual = Get-Sha256 $Destination
        }
        catch [System.IO.IOException] {
            # Two very different IOExceptions land here. A dropped share session ("network name is no
            # longer available") is transient on a slow link and usually recovers on the next access --
            # Windows re-establishes the connection -- so it is worth retrying. A genuine lock (a running
            # binary) will not recover by retrying, but telling the two apart up front is unreliable, so
            # retry either way and let the exhausted-attempts message name both causes.
            if ($i -lt $Attempts) {
                Write-Warning "${name}: $($_.Exception.Message.Trim()) -- retrying (attempt $i/$Attempts)"
                Start-Sleep -Seconds 3
                continue
            }
            throw "$name could not be copied to $Destination after $Attempts attempts: " +
                  "$($_.Exception.Message.Trim()) Either the link kept dropping the share session, or a " +
                  "running binary holds it locked (wait for a capture or handle scan to finish)."
        }

        if ($actual -eq $expected) {
            return $expected
        }

        Write-Warning "${name}: attempt $i landed as $actual, expected $expected. Retrying."
    }

    throw "$name could not be copied to $Destination intact after $Attempts attempts. This is a " +
          "corrupt transfer, not a lock: the copy succeeded each time and the contents were wrong."
}

# ---------------------------------------------------------------------------------------------------
# Staging channel: over the server's own HTTP once one is running, over SMB only for the first hop.
# ---------------------------------------------------------------------------------------------------

# A running server we can push to means we can stage over put_file and never touch the admin share.
# The first deploy has no server to receive anything, so it falls back to SMB -- the one hop no tool
# on the target can remove -- and -Smb forces that same fallback for a running server when needed.
$script:UseHttp = [bool]$Token -and -not $Smb

<#
.SYNOPSIS
    The SHA-256 of a file already on the target, or $null if it is not there.
.DESCRIPTION
    Over HTTP this is file_signatures reading the target's own disk; over SMB it is a hash of the file
    through the share. Either way it drives the "already current" skip and the "differs from this
    build" notice, so a re-deploy moves only what actually changed.
#>
function Get-RemoteHash([string] $Name) {
    if ($script:UseHttp) {
        $target = Join-Path $RemotePath $Name
        try {
            $sig = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token `
                -Tool file_signatures -Arguments @{ paths = @($target) } -Raw | ConvertFrom-Json
        }
        catch { return $null }

        $file = @($sig.files) | Where-Object { $_ } | Select-Object -First 1
        if ($file -and $file.sha256) { return "$($file.sha256)".ToUpperInvariant() }
        return $null
    }

    $share = Join-Path $remoteShare $Name
    if (Test-Path $share) { return Get-Sha256 $share }
    return $null
}

<#
.SYNOPSIS
    Places a local file on the target under the given name, verified.
.DESCRIPTION
    Over HTTP, put_file carries the bytes and verifies the SHA-256 server-side, rolling back on
    mismatch -- so a non-zero exit from mcp-call means it did not verify. Over SMB, Copy-Verified does
    the copy-and-read-back. The server binary and every Sysinternals binary sit under the 128 MB
    put_file cap.
#>
# 4 MB raw per chunk (~5.6 MB base64). Proven to decode without memory pressure on the 32-bit server,
# where a single ~57 MB base64 argument for the whole binary threw an out-of-memory error inside the
# JSON pipeline. Small enough for that, large enough that a 43 MB binary is ~11 chunks, not hundreds.
$script:ChunkBytes = 4 * 1024 * 1024

# Attempts for a single chunk before the whole transfer is restarted. A transient refusal -- an
# on-access virus scanner holding the file it just saw grow -- is far cheaper to ride out here than by
# resending tens of megabytes over a slow link.
$script:ChunkAttempts = 5

function Get-Sha256Bytes([byte[]] $Bytes) {
    return ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($Bytes)) -replace '-', '')
}

function Invoke-PutFile([string] $Target, [byte[]] $Bytes, [string] $ExpectedSha, [bool] $Append) {
    $b64 = [Convert]::ToBase64String($Bytes)
    $callArgs = @{ path = $Target; contentBase64 = $b64; append = $Append; chunkSha256 = (Get-Sha256Bytes $Bytes) }
    if ($ExpectedSha) { $callArgs.expectedSha256 = $ExpectedSha }

    # 300s base plus size; a single chunk is small, but the same formula covers a small file sent whole.
    $timeoutSec = [int]([Math]::Min(1800, 300 + $b64.Length / 100000))

    & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token -Tool put_file `
        -Arguments $callArgs -TimeoutSeconds $timeoutSec | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "put_file failed for $Target (the server reported the reason above)."
    }
}

<#
.SYNOPSIS
    Sends a whole file over put_file, chunked and retried, verified end to end.
.DESCRIPTION
    Each chunk carries its own hash so a corruption on a lossy link fails at that chunk, not as an
    opaque whole-file mismatch minutes later; the last chunk also carries the finished file's hash,
    which the server checks against the assembled file. On any failure the whole send restarts from
    chunk 0 -- which truncates, so a half-written attempt is wiped and the retry is unambiguous. The
    lab link drops chunks often enough that this retry is not theoretical.
#>
function Send-OverHttp([string] $Target, [byte[]] $Bytes, [string] $ExpectedSha, [int] $Attempts = 3) {
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            if ($Bytes.Length -le $script:ChunkBytes) {
                Invoke-PutFile -Target $Target -Bytes $Bytes -ExpectedSha $ExpectedSha -Append $false
                return
            }

            $total = [Math]::Ceiling($Bytes.Length / $script:ChunkBytes)
            if ($attempt -eq 1) {
                Write-Note ("sending {0:N1} MB in {1} chunks (the link to a lab VM is slow; this takes a few minutes)" -f ($Bytes.Length / 1MB), $total)
            }
            else {
                Write-Warning "transfer of $(Split-Path -Leaf $Target) failed; restarting from the first chunk (attempt $attempt/$Attempts)"
            }

            for ($i = 0; $i -lt $total; $i++) {
                $offset = $i * $script:ChunkBytes
                $len = [Math]::Min($script:ChunkBytes, $Bytes.Length - $offset)
                $chunk = New-Object byte[] $len
                [Array]::Copy($Bytes, $offset, $chunk, 0, $len)

                $shaForChunk = if ($i -eq $total - 1) { $ExpectedSha } else { '' }

                # Retry THIS chunk before giving up on the whole transfer. An on-access scanner
                # (CrowdStrike Falcon on one of the lab VMs) opens the staged .exe each time it grows, so
                # the next append hits a sharing violation -- observed failing at chunk 10, then 9, then 1
                # on three consecutive whole-file restarts, each costing minutes and re-triggering the
                # same scan. The open failing means nothing was written, so re-sending in place is safe;
                # and if a chunk ever did land twice, the whole-file hash on the last chunk still catches
                # it and the outer loop restarts cleanly.
                for ($try = 1; ; $try++) {
                    try {
                        Invoke-PutFile -Target $Target -Bytes $chunk -ExpectedSha $shaForChunk -Append ($i -gt 0)
                        break
                    }
                    catch {
                        if ($try -ge $script:ChunkAttempts) { throw }
                        Write-Note ("  chunk {0}/{1} was refused; retrying in {2:N1}s ({3}/{4})" -f `
                            ($i + 1), $total, (0.75 * $try), $try, $script:ChunkAttempts)
                        Start-Sleep -Milliseconds (750 * $try)
                    }
                }

                Write-Note ("  chunk {0}/{1}" -f ($i + 1), $total)
            }
            return
        }
        catch {
            if ($attempt -eq $Attempts) { throw }
        }
    }
}

function Send-Staged([string] $Source, [string] $Name, [string] $ExpectedSha) {
    if (-not $script:UseHttp) {
        Copy-Verified -Source $Source -Destination (Join-Path $remoteShare $Name) | Out-Null
        return
    }

    Send-OverHttp -Target (Join-Path $RemotePath $Name) -Bytes ([IO.File]::ReadAllBytes($Source)) -ExpectedSha $ExpectedSha
}

<#
.SYNOPSIS
    Writes the staging manifest onto the target.
.DESCRIPTION
    Over HTTP it goes through put_file like everything else; over SMB it is written to the share. The
    manifest lands in a windiag-owned directory, so put_file needs no arbitrary-write grant for it.
#>
function Write-StagedManifest([string] $Json) {
    if ($script:UseHttp) {
        $temp = Join-Path ([IO.Path]::GetTempPath()) ("windiag-staged-" + [guid]::NewGuid().ToString('N') + '.json')
        Set-Content -LiteralPath $temp -Value $Json -Encoding utf8
        try {
            Send-Staged -Source $temp -Name 'windiag-staged.json' -ExpectedSha (Get-Sha256 $temp)
        }
        finally {
            Remove-Item $temp -ErrorAction SilentlyContinue
        }
        return
    }

    Set-Content -LiteralPath (Join-Path $remoteShare 'windiag-staged.json') -Value $Json -Encoding utf8
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

<#
.SYNOPSIS
    Finds where the server already lives on the target, rather than assuming a layout.
.DESCRIPTION
    A wrong directory is the one mistake here that does not announce itself: the script would create it,
    stage a complete and correct install into it, and then fail to find anything to update -- or worse,
    succeed while the machine carries on running the copy in the real directory. Asking the server for
    its own path removes the guess entirely, and the answer is exactly what update_self will replace.
#>
function Resolve-RemotePath {
    if ($RemotePath) { return $RemotePath }

    if (-not $Token) {
        throw "-RemotePath is required when -Token is not supplied. With nothing running to ask, the " +
              "alternative is a guessed directory, which would stage a complete install somewhere " +
              "nobody is looking. Pass the folder the server will live in, e.g. C:\WinDiag."
    }

    $processes = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token `
        -Tool process_list -Arguments @{ nameFilter = 'WinDiag' } -Raw | ConvertFrom-Json
    $server = $processes.processes | Where-Object { $_.name -match 'WinDiag\.Mcp' } | Select-Object -First 1

    # First try the command line. It carries a full path only when the server was launched by one --
    # `cd <dir>; WinDiag.Mcp.exe --http ...` records just the bare exe name, which is exactly how the
    # enable-a-flag restart tends to be run, so this misses more often than it looks.
    if ($server.commandLine -match '^"?([A-Za-z]:\\[^"]*WinDiag\.Mcp\.exe)"?') {
        $resolved = Split-Path -Parent $Matches[1]
        Write-Note "server lives in $resolved (from command line)"
        return $resolved
    }

    # Fall back to the module path, which is absolute however the process was started. The server's own
    # image is a loaded module of its own process, so process_modules on its PID always yields the full
    # path -- the robust source the command line only sometimes is.
    if ($server.processId) {
        $modules = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token `
            -Tool process_modules -Arguments @{ processId = $server.processId } -Raw | ConvertFrom-Json
        $exe = $modules.modules.modules | Where-Object { $_.name -match 'WinDiag\.Mcp\.exe' } | Select-Object -First 1
        if ($exe.path) {
            $resolved = Split-Path -Parent $exe.path
            Write-Note "server lives in $resolved (from module path)"
            return $resolved
        }
    }

    throw "Could not read the server's own path from process_list or process_modules " +
          "(command line: '$($server.commandLine)'). Pass -RemotePath explicitly."
}

Write-Step 'Locating the server on the target'
$RemotePath = Resolve-RemotePath

# Derived rather than asked for, so the local path and the share path cannot disagree.
if ($RemotePath -notmatch '^([A-Za-z]):\\(.*)$') {
    throw "-RemotePath must be a local path on the target, e.g. C:\WinDiag. Got: $RemotePath"
}
$remoteShare = "\\$Target\$($Matches[1])`$\$($Matches[2])"

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

$previous = $null

if ($script:UseHttp) {
    # Over HTTP there is no share to read the previous manifest from -- and it is not needed. The
    # per-file hash check in the staging loop below (file_signatures on the target's own copy) is a
    # stronger drift signal than the manifest anyway: it compares the file that is actually there
    # against the one about to be sent, rather than a record of what was sent last time.
    Write-Step "Staging to $RemotePath on $Target over the server's own channel (no SMB)"
}
else {
    $stagedManifest = Join-Path $remoteShare 'windiag-staged.json'

    Write-Step "Checking $remoteShare"

    if (-not (Test-Path $remoteShare)) {
        # Made restricted to SYSTEM and Administrators, not left to inherit from C:\: there a new folder
        # gets "Authenticated Users: Modify", and the SYSTEM service will run what it finds in it.
        Protect-WinDiagDirectory $remoteShare
        Write-Note 'created, writable by SYSTEM and Administrators only'
    }

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
}

# ---------------------------------------------------------------------------------------------------
# 5. Stage
# ---------------------------------------------------------------------------------------------------

$staged = @()

if (-not $SkipSysinternals) {
    Write-Step "Staging $($sysinternals.Count) Sysinternals binaries"

    foreach ($tool in $sysinternals) {
        if ((Get-RemoteHash $tool.Name) -eq $tool.Sha256) {
            Write-Note "$($tool.Name) already current"
        }
        else {
            Send-Staged -Source $tool.Path -Name $tool.Name -ExpectedSha $tool.Sha256
            Write-Note "$($tool.Name) staged and verified"
        }

        $staged += [pscustomobject]@{ name = $tool.Name; sha256 = $tool.Sha256; version = $tool.Version }
    }
}

$serverHash = $null

if (-not $SkipServer) {
    # Staged under a different name, never written over the running exe: the live binary is locked, and
    # an earlier attempt to work around that by renaming it took the server down.
    Write-Step 'Staging the server build as WinDiag.Mcp.new.exe'
    $serverHash = Get-Sha256 $serverExe
    Send-Staged -Source $serverExe -Name 'WinDiag.Mcp.new.exe' -ExpectedSha $serverHash
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

$manifestJson = [pscustomobject]@{
    deployedOn   = (Get-Date).ToString('s')
    deployedFrom = $env:COMPUTERNAME
    commit       = $commit
    architecture = $Architecture
    files        = $staged
} | ConvertTo-Json -Depth 6

Write-StagedManifest $manifestJson
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

# A server started without WINDIAG_ALLOW_SELF_UPDATE has no update_self to call. The binary is staged
# and verified; the swap just has to happen at the console once -- and that restart is the moment to
# enable the flag so it never has to happen again. Detected rather than surfaced as a bare
# "Unknown tool", which says nothing about what to do.
$hasUpdateSelf = ($null -ne ($tools_now = & (Join-Path $PSScriptRoot 'mcp-call.ps1') `
        -Address $address -Token $Token -Tool capabilities -Raw | ConvertFrom-Json) ) -and
    ($tools_now.tools.tool -contains 'update_self')

if (-not $hasUpdateSelf) {
    Write-Step 'Staged and verified, but this server cannot swap itself: update_self is not enabled.'
    Write-Host ""
    Write-Host "  On $Target, from the ELEVATED terminal running the server:" -ForegroundColor Yellow
    Write-Host "    (stop the server)"
    Write-Host "    cd `"$RemotePath`""
    Write-Host "    move /y WinDiag.Mcp.new.exe WinDiag.Mcp.exe"
    Write-Host "    set WINDIAG_TOKEN=<the token you passed as -Token>"
    Write-Host "    set WINDIAG_ALLOW_SELF_UPDATE=1    (so future updates need no console step)"
    Write-Host "    WinDiag.Mcp.exe --http http://${Target}:${Port}"
    Write-Host ""
    Write-Note "the staged build is verified as $serverHash"
    return
}

Write-Step "Installing via update_self"

# Deliberately NOT forced. The target may be serving someone else -- a capture running from another
# session is exactly the work that used to be truncated by a deploy -- so this waits for it. The
# result tells us how long it is prepared to wait.
$updateRaw = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token -Tool update_self `
    -Arguments @{ expectedSha256 = $serverHash } -Raw

# A refused update produces no stdout: mcp-call.ps1 reports the refusal to the host and exits 1, which
# does NOT throw here. Without this check a hash mismatch or a signature refusal fell straight through
# to the poll below, which then got a perfectly good answer from the OLD server that was never asked to
# stop, and the script announced a successful deploy of a build it had not installed.
if (-not $updateRaw) {
    throw "update_self was refused (its reason is printed above). $Target is unchanged and still " +
          'running the previous build.'
}

$update = ($updateRaw | ConvertFrom-Json).update
$drain = if ($update.drainTimeoutSeconds) { [int]$update.drainTimeoutSeconds } else { 0 }

if ($update.otherCallsInFlight -gt 0) {
    $budget = if ($drain -lt 60) { "$drain s" } else { "$([math]::Floor($drain / 60)) min" }
    Write-Note ("$($update.otherCallsInFlight) other call(s) are running on the target; it will finish " +
                "them before restarting (up to $budget)")
}

Write-Note 'server is restarting; waiting for it to come back'

# The budget has to cover the drain, or a deploy onto a busy target reports failure while the update
# is proceeding perfectly. 90s on top is the restart itself.
$deadline = (Get-Date).AddSeconds($drain + 90)
$tools = $null

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 5

    try {
        $answer = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token -Tool capabilities -Raw |
            ConvertFrom-Json

        # Only a real answer ends the wait. mcp-call.ps1 signals a tool-level refusal by writing to the
        # host and exiting 1, which does NOT throw here -- so without this check the break below ran
        # unconditionally, $tools stayed null, and every drain longer than one sleep looked like a
        # server that never came back.
        #
        # And because the gate refuses every tool but update_self while an update is pending, a
        # capabilities reply can only have come from the NEW process. That is what makes this poll
        # conclusive rather than a guess about whether the old one is still answering.
        if ($null -ne $answer -and $null -ne $answer.tools) {
            $tools = $answer
            break
        }
    }
    catch {
        continue
    }
}

if (-not $tools) {
    throw "The server did not come back on $address within $($drain + 90)s. It may still be draining " +
          "in-flight calls; read the helper log named in the update_self result on the target, at " +
          "%TEMP%\windiag\self-update.log."
}

# The server answering proves a server is up, NOT that it is the one we just staged. The helper aborts
# and restarts the EXISTING build whenever the swap cannot happen -- most often because another process
# holds the executable open, which is exactly what a second windiag on the same machine does. That path
# leaves the old binary running and everything else looking like a clean deploy, so the claim below has
# to be checked against the file rather than inferred from a reply.
if (-not $SkipServer) {
    $live = & (Join-Path $PSScriptRoot 'mcp-call.ps1') -Address $address -Token $Token `
        -Tool file_signatures -Arguments @{ paths = @((Join-Path $RemotePath 'WinDiag.Mcp.exe')) } -Raw |
        ConvertFrom-Json

    $installed = $live.files[0].sha256
    if ($installed -ne $serverHash) {
        throw "The server came back, but it is NOT the build that was just staged: expected " +
              "$serverHash, found $installed. The swap was aborted -- read the helper log on the " +
              "target at %TEMP%\windiag\self-update.log. The usual cause is another process holding " +
              "WinDiag.Mcp.exe open, such as a second windiag running as a service from the same folder."
    }

    Write-Note "verified the running build is $($installed.Substring(0, 16))"
}

Write-Step "$Target is running commit $commit"

foreach ($capability in $tools.tools | Where-Object { $_.status -ne 'Available' }) {
    Write-Warning "$($capability.tool) [$($capability.status)] $($capability.detail)"
}

Write-Note "$(($tools.tools | Where-Object { $_.status -eq 'Available' }).Count) of $($tools.tools.Count) tools fully available"
