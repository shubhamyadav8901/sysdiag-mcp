<#
.SYNOPSIS
    Installs macdiag on a Mac that has never run it, over SSH (Remote Login).

.DESCRIPTION
    Copies the published binary into the SSH user's home directory, checks its hash there, clears the
    quarantine flag, signs it ad hoc if it carries no valid signature (an Apple Silicon Mac kills an
    unsigned binary at launch, and a build published off a Mac is unsigned), then runs --install-service
    with sudo. The home directory, not /tmp: a file in the shared /tmp could be swapped
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
    .\tools\bootstrap-macos.ps1 -Target mac-01 -User admin -Token $t -Grants Standard
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
    [string] $Bind = 'http://0.0.0.0:4025',
    [string] $Binary = 'artifacts/macdiag-osx-arm64/MacDiag.Mcp'
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
Invoke-Native { scp @identity -P $SshPort $local "${remote}:MacDiag.Mcp" }

# Best effort, from a fresh session: when a step below fails, the remote side may never have reached
# its own cleanup -- the connection dropped, or the token session died mid-write -- and the token must
# not be left sitting in the home directory.
function Remove-Leftovers {
    try { Invoke-Native { ssh @identity -p $SshPort $remote 'rm -f ~/MacDiag.Mcp ~/.macdiag-token' } }
    catch { Write-Warning "Could not remove ~/MacDiag.Mcp and ~/.macdiag-token on ${Target}: $_. Remove them by hand." }
}

# A pinned token travels over SSH's stdin into an owner-only file, never on a command line: sudo logs
# its command line and ps shows it. A separate session because the install session's terminal belongs
# to sudo's password prompt. Removed first, because umask only sets the mode of a file it creates: a
# token file left behind with a looser mode would otherwise keep it.
if ($Token) {
    Write-Host "==> sending the token"
    try { Invoke-Native { $Token | ssh @identity -p $SshPort $remote 'rm -f ~/.macdiag-token && umask 077 && cat > ~/.macdiag-token' } }
    catch { Remove-Leftovers; throw }
}

# One remote command: verify, then install. The trap removes the copy and the token however the session
# ends -- the install's own exit, a failed check, or a dropped connection or Ctrl-C. The signals exit
# rather than run the cleanup themselves: a trapped signal otherwise lets the shell carry on to the next
# command, and dash, unlike bash, does not run an EXIT trap for a signal it leaves at its default.
# sudo is skipped when already root.
$sudo = if ($User -eq 'root') { '' } else { 'sudo ' }
$quoted = ($installArgs | ForEach-Object { "'$_'" }) -join ' '
$tokenInput = if ($Token) { ' < ~/.macdiag-token' } else { '' }
$command = "trap 'rm -f ~/MacDiag.Mcp ~/.macdiag-token' EXIT; trap 'exit 1' HUP INT TERM; echo '$sha  MacDiag.Mcp' | shasum -a 256 -c - && chmod 0755 ~/MacDiag.Mcp && { xattr -d com.apple.quarantine ~/MacDiag.Mcp 2>/dev/null || true; } && { codesign -v ~/MacDiag.Mcp 2>/dev/null || codesign --force --sign - ~/MacDiag.Mcp; } && ${sudo}~/MacDiag.Mcp $quoted$tokenInput"
Write-Host "==> installing on $Target ($Grants grants)"
try { Invoke-Native { ssh @identity -t -p $SshPort $remote $command } }
catch { Remove-Leftovers; throw }

Write-Host "==> done. If a token was generated it was printed above, once: put it in ~/.windiag-targets.json."
