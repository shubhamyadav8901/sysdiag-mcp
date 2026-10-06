<#
.SYNOPSIS
    Brings a machine that has never run windiag all the way to a registered, running service.

.DESCRIPTION
    The one step deploy-target.ps1 cannot do. That script stages a build over the admin share and then
    asks the running server to replace itself -- which needs a server to already be running. On a fresh
    machine there is nothing to ask, so the first start has always been a console visit.

    This closes that gap wherever the target answers on SMB (445) and RPC (135), which is all it takes:
    stage with deploy-target.ps1, promote the staged build, run --install-service on the target through
    PsExec, then verify over HTTP that the service actually answers. From there update_self handles
    every later build and this script is never needed again for that machine.

    It deliberately does NOT use PowerShell remoting. WinRM addressed by IP requires the caller's
    machine to have the target in TrustedHosts, which is an elevated change to the *operator's* box --
    a strange thing to need for a tool whose whole point is that you have rights on the target rather
    than on your own workstation. PsExec needs nothing configured locally.

    Credentials are used once, in this process, to open an authenticated IPC$ session through
    WNetAddConnection2 -- not `net use`, whose command line would carry the password into process
    auditing and EDR on this machine. PsExec then rides that session and runs the installer as SYSTEM
    (-s), so the password never reaches any command line.

    The token does not reach one either. It travels to the target as a file in the install directory,
    which is first restricted to SYSTEM and Administrators, is fed to the installer's --token-stdin by a
    small .cmd beside it, and both are deleted as soon as the installer returns. Passed as --token, it
    would sit in the target's process-creation log, PSEXESVC's command line and windiag's own
    process_list.

.PARAMETER Target
    Target IP or host name. Needs 445 and 135 reachable, and 4024 free.

.PARAMETER Credential
    An administrator ON THE TARGET. Prompted for if omitted. Never written to disk.

.PARAMETER Token
    Bearer token to pin. Must match what the relay's ~/.sysdiag-targets.json holds for this machine,
    or the alias connects and then fails every call with a 401. Generated if omitted, and printed
    once -- at which point you must put it in that file yourself.

.PARAMETER Grants
    Which grants to register. A service registered without them comes back with fewer tools than the
    server it replaced, and nothing reports that except a capabilities call nobody makes.

.EXAMPLE
    .\bootstrap-target.ps1 -Target 192.168.36.49 -Token $token -Grants All

.EXAMPLE
    # Every runner in the relay's targets file, one prompt for credentials.
    $c = Get-Credential
    '192.168.36.49','192.168.36.17','192.168.36.41' | ForEach-Object {
        .\bootstrap-target.ps1 -Target $_ -Credential $c -Token $token -Grants All
    }
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Target,
    [System.Management.Automation.PSCredential] $Credential,
    [string] $Token,
    [ValidateSet('None', 'Standard', 'All')] [string] $Grants = 'Standard',
    [string] $RemotePath = 'C:\WinDiag',
    [string] $ArtifactPath = 'C:\WinDiagArtifacts',
    [string] $ServiceName = 'windiag',
    [int] $Port = 4024,

    # Where the firewall rule lets connections in from. Defaults to this machine, because a rule
    # scoped to one address is the difference between a lab tool and an open elevated listener.
    [string] $FirewallFrom,

    [switch] $SkipStaging
)

$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\windiag-acl.ps1"

function Step { param($m) Write-Host "==> $m" -ForegroundColor Cyan }
function Warn { param($m) Write-Host "    $m" -ForegroundColor Yellow }

# Native commands write status to stderr as a matter of course -- PsExec puts *all* of its output
# there, including its success line. Under $ErrorActionPreference='Stop', PowerShell 5.1 turns each
# such line into a terminating NativeCommandError, so the plain form throws on success: verified as
# "cmd exited with error code 0". Left unguarded that killed this script *after* the service was
# created and started, losing a generated token that is printed exactly once. The preference is
# lowered inside the scriptblock only; $LASTEXITCODE crosses the boundary intact.
function Invoke-Native {
    param([scriptblock] $Command)
    & { $ErrorActionPreference = 'Continue'; & $Command 2>&1 }
}

if (-not $Credential) {
    $Credential = Get-Credential -Message "Administrator on $Target"
}

$user = $Credential.UserName

# WNetAddConnection2 is what `net use` calls; calling it here keeps the password inside this process.
# Guarded because Add-Type refuses to redefine a type, and the fleet example runs this script in a loop.
if (-not ('WinDiagBootstrap.Net' -as [type])) {
    Add-Type -Namespace WinDiagBootstrap -Name Net -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public class NetResource
{
    public int Scope; public int Type; public int DisplayType; public int Usage;
    public string LocalName; public string RemoteName; public string Comment; public string Provider;
}

[DllImport("mpr.dll", CharSet = CharSet.Unicode)]
public static extern int WNetAddConnection2(NetResource resource, string password, string user, int flags);

[DllImport("mpr.dll", CharSet = CharSet.Unicode)]
public static extern int WNetCancelConnection2(string name, int flags, bool force);
'@
}

# Forced, which is what `net use /delete /y` did: the cancel otherwise fails while handles are open.
function Close-IpcSession { param([string] $Server) [void][WinDiagBootstrap.Net]::WNetCancelConnection2("\\$Server\IPC$", 0, $true) }

# Resolved once, and everything downstream uses the address rather than the name. Find-NetRoute takes
# only an IP literal, and binding the listener to a name that resolves differently on the target than
# it does here produces a server nobody can reach.
$targetIp = ([System.Net.Dns]::GetHostAddresses($Target) |
    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
    Select-Object -First 1).IPAddressToString
if (-not $targetIp) { throw "Could not resolve $Target to an IPv4 address." }

if (-not $FirewallFrom) {
    # Asked of the routing table rather than taken as "the first IPv4 that is not loopback". This box
    # has Hyper-V and WSL adapters that sort ahead of the real one, and picking 172.23.240.1 would
    # write a firewall rule scoped to an address that can never reach the target -- locking out the
    # very machine the rule exists to admit, with the install otherwise reporting success.
    $FirewallFrom = (Find-NetRoute -RemoteIPAddress $targetIp |
        Select-Object -First 1 -ExpandProperty IPAddress)
    Warn "firewall scoped to this machine ($FirewallFrom); pass -FirewallFrom to change it"
}

# --- reachability, before anything is copied -------------------------------------------------------
# Checked up front because the two failures look identical from inside a half-finished install: a
# machine that was never reachable, and one that stopped being reachable partway through.
Step "checking $Target ($targetIp)"
foreach ($p in 445, 135) {
    if (-not (Test-NetConnection -ComputerName $targetIp -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue)) {
        throw "$Target is not reachable on port $p. SMB (445) and RPC (135) are both required."
    }
}

if (Test-NetConnection -ComputerName $targetIp -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue) {
    throw ("Something is already listening on ${targetIp}:${Port}. If a previous run of this script " +
           "got as far as registering the service, it is already installed -- check with " +
           "'WinDiag.Mcp.exe --service-status' on the target and remove it with --uninstall-service " +
           "before bootstrapping again, rather than assuming this is a stale by-hand server.")
}

$share = "\\$targetIp\" + ($RemotePath -replace '^([A-Za-z]):', '$1$')

Step "authenticating to $targetIp"

# Dropped first because Windows allows only one set of credentials per server: a session left over
# from earlier work fails the new one with error 1219 rather than replacing it.
Close-IpcSession $targetIp

$ipc = New-Object 'WinDiagBootstrap.Net+NetResource'
$ipc.RemoteName = "\\$targetIp\IPC$"
$result = [WinDiagBootstrap.Net]::WNetAddConnection2($ipc, $Credential.GetNetworkCredential().Password, $user, 0)
if ($result -ne 0) {
    throw ("Could not authenticate to $targetIp as ${user}: " +
           "$((New-Object System.ComponentModel.Win32Exception $result).Message) (error $result).")
}

try {
    # --- architecture ------------------------------------------------------------------------------
    # ADMIN$ rather than C$\Windows: it maps to %SystemRoot% wherever that is, so a system drive that
    # is not C: does not read as 32-bit. The positive control matters more than the test -- Test-Path
    # answers false for "denied" exactly as it does for "32-bit", and a local admin account under
    # remote UAC token filtering gets IPC$ but not the admin share unless LocalAccountTokenFilterPolicy
    # is set on the target. Without this check that denial silently selects the x86 build, which runs
    # happily on 64-bit Windows and then answers wrongly -- no 64-bit dumps, no activity capture.
    if (-not (Test-Path "\\$targetIp\ADMIN$")) {
        throw ("The admin share on $targetIp is not readable as $user, so the architecture cannot be " +
               "determined. With a local (non-domain) admin account this needs " +
               "LocalAccountTokenFilterPolicy=1 on the target.")
    }

    $arch = if (Test-Path "\\$targetIp\ADMIN$\SysWOW64") { 'x64' } else { 'x86' }
    Step "target is $arch"

    if (-not $SkipStaging) {
        # Delegated rather than reimplemented: deploy-target.ps1 already verifies every file by SHA-256
        # on both sides, stages the Sysinternals binaries, and records a manifest so a machine someone
        # has since touched by hand shows up as drift. Without those, four tools report Unavailable and
        # the reason is a missing file nobody looks for.
        #
        # Its success is not checked by exit code: PowerShell does not set $LASTEXITCODE for a .ps1
        # invocation, so reading it here returns whatever native command ran last *inside* the callee
        # -- a failed `git rev-parse` that it deliberately tolerates would abort a perfectly good
        # stage. It signals failure by throwing, which $ErrorActionPreference already propagates.
        Step "staging build and Sysinternals (hash-verified)"
        & "$PSScriptRoot\deploy-target.ps1" -Target $targetIp -Architecture $arch -RemotePath $RemotePath
    }

    # deploy-target.ps1 stages the server as WinDiag.Mcp.new.exe, because on every other target the
    # live binary is locked and only update_self may replace it. Here nothing is running, so this is
    # the promotion update_self would otherwise do. It is also what the manifest already claims: that
    # file is recorded as WinDiag.Mcp.exe, so skipping the move makes the next deploy report drift.
    $stagedNew = "$share\WinDiag.Mcp.new.exe"
    if (Test-Path $stagedNew) {
        Step "promoting staged build to WinDiag.Mcp.exe"
        Move-Item -LiteralPath $stagedNew -Destination "$share\WinDiag.Mcp.exe" -Force
    }

    if (-not (Test-Path "$share\WinDiag.Mcp.exe")) {
        throw "$RemotePath\WinDiag.Mcp.exe is not on the target. Staging did not leave a build behind."
    }

    # Before the token file is written into it, and before the installer runs from it. The installer
    # restricts both directories too; doing it here first closes the window in between.
    Step "restricting $RemotePath and $ArtifactPath to SYSTEM and Administrators"
    Protect-WinDiagDirectory $share
    Protect-WinDiagDirectory ("\\$targetIp\" + ($ArtifactPath -replace '^([A-Za-z]):', '$1$'))

    # --- register ----------------------------------------------------------------------------------
    $installArgs = @(
        '--install-service'
        '--service-name'; $ServiceName
        '--http'; "http://${targetIp}:${Port}"
        '--artifacts'; $ArtifactPath
        '--firewall-from'; $FirewallFrom
    )
    if ($Token) { $installArgs += '--token-stdin' }
    switch ($Grants) {
        'Standard' { $installArgs += @('--allow-self-update', '--allow-command-execution') }
        'All'      { $installArgs += @('--allow-self-update', '--allow-command-execution',
                                       '--allow-arbitrary-write', '--allow-arbitrary-read') }
        'None'     { $installArgs += '--read-only' }
    }

    # The installer is started by a .cmd rather than by PsExec directly, because cmd can feed it the
    # token file on stdin: PsExec documents forwarding typed console input, not a pipe, and the token
    # must not be an argument. Every argument is quoted for cmd, with % doubled so none is expanded.
    $line = (@("$RemotePath\WinDiag.Mcp.exe") + $installArgs | ForEach-Object {
        if ("$_" -match '"') { throw "An install argument contains a double quote, which cmd cannot carry: $_" }
        '"' + ("$_" -replace '%', '%%') + '"'
    }) -join ' '
    if ($Token) { $line += " < `"$RemotePath\install-token.tmp`"" }

    Step "registering '$ServiceName' on $targetIp"

    $utf8 = New-Object System.Text.UTF8Encoding $false
    try {
        if ($Token) { [System.IO.File]::WriteAllText("$share\install-token.tmp", $Token, $utf8) }
        [System.IO.File]::WriteAllText("$share\install-windiag.cmd",
            "@echo off`r`n$line`r`nexit /b %errorlevel%`r`n", $utf8)

        # -s runs the installer as SYSTEM, riding the IPC$ session opened above. SYSTEM is also
        # unconditionally elevated, which matters for more than tidiness: with a filtered admin token
        # the installer would call its own UAC relaunch and then block on WaitForExit for a prompt in
        # session 0 that nobody can answer.
        $output = Invoke-Native {
            psexec "\\$targetIp" -s -accepteula -nobanner cmd.exe /c "$RemotePath\install-windiag.cmd"
        }
        $installExit = $LASTEXITCODE
    }
    finally {
        # As soon as the installer is done with it, success or not: from here the token lives only in
        # the service's own restricted registry key.
        Remove-Item -LiteralPath "$share\install-token.tmp", "$share\install-windiag.cmd" -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath "$share\install-token.tmp") {
            Warn "could not delete $RemotePath\install-token.tmp on the target; delete it by hand."
        }
    }

    $output | ForEach-Object { Write-Host "    $_" }

    # PsExec returns the remote process's exit code, so these are usually the installer's own: 2
    # configuration or already-exists, 3 elevation refused, 4 something unexpected that it named for
    # you. PsExec's own connection failures land in the same space, so a 5 or 53 is more likely to be
    # "access denied" or "network path not found" than anything the installer decided.
    if ($installExit -ne 0) {
        throw "--install-service exited $installExit on $targetIp. Nothing else was changed here."
    }

    # --- verify ------------------------------------------------------------------------------------
    # The install reporting success and the service actually answering are different claims. A service
    # that starts and immediately exits leaves the SCM saying Running for a moment either way.
    Step "waiting for $targetIp to answer on $Port"
    $deadline = (Get-Date).AddSeconds(45)
    $up = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-NetConnection -ComputerName $targetIp -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue) {
            $up = $true; break
        }
        Start-Sleep -Seconds 3
    }

    if (-not $up) {
        throw ("The service registered but nothing is listening on ${targetIp}:${Port} after 45s. " +
               "Check the Application event log on the target under source 'windiag'.")
    }

    if ($Token) {
        Step "calling capabilities"

        # -Raw and an emptiness check, not an exit code: mcp-call.ps1 reports a refusal to the host and
        # exits 1, which does not throw here. A token that disagrees with ~/.sysdiag-targets.json is
        # the single most likely mistake this step exists to catch, and without the check it printed
        # its 401 and fell straight through to the success banner below.
        $raw = & "$PSScriptRoot\mcp-call.ps1" -Address "http://${targetIp}:${Port}" -Token $Token `
            -Tool capabilities -Raw
        if (-not $raw) {
            throw ("$targetIp is listening but refused the token (its reason is printed above). The " +
                   "service is installed; correct the token and re-register, or fix " +
                   "~/.sysdiag-targets.json to match what was registered.")
        }

        Write-Host "    $(($raw | ConvertFrom-Json).summary)"
    } else {
        Warn "no -Token given, so the installer generated one and printed it above."
        Warn "put it in ~/.sysdiag-targets.json for this machine, or the relay alias will 401."
    }

    Write-Host ""
    Write-Host "$targetIp is registered as '$ServiceName' and answering on $Port." -ForegroundColor Green
    Write-Host "Later builds go through update_self; this script is not needed for it again."
}
finally {
    # Its result is ignored, and it cannot throw: anything raised in a finally block REPLACES the
    # exception on its way out, so a real install failure would be reported as a cleanup error instead.
    Close-IpcSession $targetIp
}
