<#
.SYNOPSIS
    Installs linuxdiag on a Linux host that has never run it, over SSH.

.DESCRIPTION
    Copies the published binary into the SSH user's home directory, checks its hash there, then runs
    --install-service with sudo. The home directory, not /tmp: a file in the shared /tmp could be swapped
    by another local account between the copy and the root execution.

    From then on update_self handles every later build and this script is not needed again for that
    host.

.PARAMETER Target
    Host name or address. Needs SSH reachable, and the bind port free.

.PARAMETER User
    The SSH user. Must be able to sudo, or be root.

.PARAMETER IdentityFile
    SSH private key to use instead of ssh's default identity.

.PARAMETER Token
    Bearer token to pin. Must match what the relay's ~/.windiag-targets.json holds for this host. Generated
    if omitted, and printed once -- at which point you must put it in that file yourself.

.PARAMETER Grants
    None = --read-only; Standard = self-update and command execution; All = those plus arbitrary read
    and write. The same presets as bootstrap-target.ps1.

.EXAMPLE
    .\tools\bootstrap-linux.ps1 -Target build-01 -User ops -Token $t -Grants Standard
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Target,
    [string] $User = $env:USERNAME,
    [int] $SshPort = 22,
    [string] $IdentityFile,
    [string] $Token,
    [ValidateSet('None', 'Standard', 'All')] [string] $Grants = 'Standard',
    [string] $Bind = 'http://0.0.0.0:4024',
    [string] $Binary = 'artifacts/linux-x64/LinuxDiag.Mcp'
)

$ErrorActionPreference = 'Stop'

# ssh and scp write progress and warnings to stderr; under 'Stop' in Windows PowerShell each such line
# becomes a terminating error even on success. Lowered inside the block only; exit codes are checked.
function Invoke-Native([scriptblock] $Command) {
    & { $ErrorActionPreference = 'Continue'; & $Command 2>&1 }
    if ($LASTEXITCODE -ne 0) { throw "command failed with exit $LASTEXITCODE" }
}

$local = (Resolve-Path $Binary).Path
$sha = (Get-FileHash -Algorithm SHA256 $local).Hash.ToLowerInvariant()
$remote = "$User@$Target"
$identity = if ($IdentityFile) { @('-i', (Resolve-Path $IdentityFile).Path) } else { @() }

# Every argument is single-quoted for the remote shell below, so none may contain a quote.
if ($Bind.Contains("'")) { throw "-Bind may not contain a single quote." }
$installArgs = @('--install-service', '--http', $Bind)
if ($Token) { $installArgs += '--token-stdin' }
switch ($Grants) {
    'Standard' { $installArgs += @('--allow-self-update', '--allow-command-execution') }
    'All'      { $installArgs += @('--allow-self-update', '--allow-command-execution', '--allow-arbitrary-write', '--allow-arbitrary-read') }
    'None'     { $installArgs += '--read-only' }
}

Write-Host "==> copying $local to $remote"
Invoke-Native { scp @identity -P $SshPort $local "${remote}:LinuxDiag.Mcp" }

# A pinned token travels over SSH's stdin into an owner-only file, never on a command line: sudo logs
# its command line and ps shows it. A separate session because the install session's terminal belongs
# to sudo's password prompt.
if ($Token) {
    Write-Host "==> sending the token"
    Invoke-Native { $Token | ssh @identity -p $SshPort $remote "umask 077 && cat > ~/.linuxdiag-token" }
}

# One remote command: verify, then install, then remove the copy -- which runs whatever the install
# returned, so a failed install still leaves nothing behind. sudo is skipped when already root.
$sudo = if ($User -eq 'root') { '' } else { 'sudo ' }
$quoted = ($installArgs | ForEach-Object { "'$_'" }) -join ' '
$tokenInput = if ($Token) { ' < ~/.linuxdiag-token' } else { '' }
$command = "echo '$sha  LinuxDiag.Mcp' | sha256sum -c - && chmod 0755 ~/LinuxDiag.Mcp && ${sudo}~/LinuxDiag.Mcp $quoted$tokenInput ; rc=`$?; rm -f ~/LinuxDiag.Mcp ~/.linuxdiag-token; exit `$rc"
Write-Host "==> installing on $Target ($Grants grants)"
Invoke-Native { ssh @identity -t -p $SshPort $remote $command }

Write-Host "==> done. If a token was generated it was printed above, once: put it in ~/.windiag-targets.json."
