<#
.SYNOPSIS
    Registers windiag as a service on a machine reachable only over WinRM.

.DESCRIPTION
    The companion to bootstrap-target.ps1, for targets where the SMB route cannot work. That script
    stages over the admin share and runs the installer through PsExec -- and PsExec needs ADMIN$ too,
    so a machine with administrative shares switched off (AutoShareServer=0, which answers
    "The server is not configured for remote administration", NET HELPMSG 3743) is unreachable by both
    halves of it at once, no matter how privileged the caller is.

    WinRM needs no shares: it carries the file copy and the elevated execution over the same session.

    Address the target BY NAME, not by IP. Negotiate against an IP requires the caller's own machine to
    list it in TrustedHosts, which is an elevated change to the operator's workstation; a name resolves
    to an SPN and authenticates with Kerberos, needing nothing configured locally. Where reverse DNS is
    missing, the machine's own RDP certificate carries its hostname -- that is how these three were
    identified in the first place:
        $c = New-Object Net.Sockets.TcpClient($ip, 3389)
        $s = New-Object Net.Security.SslStream($c.GetStream(), $false, {$true})
        $s.AuthenticateAsClient($ip); $s.RemoteCertificate.Subject

.PARAMETER Target
    Target host name, resolvable and domain-joined. An IP will usually fail authentication; the error
    says so rather than leaving you to guess.

.PARAMETER Credential
    Omit to use the current logon, which is the point of the Kerberos route. Supply one only to
    install as somebody else.

.PARAMETER Token
    Bearer token to pin. Must match what the relay's ~/.windiag-targets.json holds for this machine, or
    the alias connects and then 401s every call.

.EXAMPLE
    .\bootstrap-winrm.ps1 -Target runner1.example.com -Token $token -Grants All
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

    # Full bind URL, when the target's own address is the wrong thing to bind to. On DHCP a literal
    # address is a time bomb: the lease changes, the auto-start service cannot bind, restart-on-failure
    # spends its three retries and the machine goes quiet -- which is exactly the console visit that
    # registering a service was meant to abolish. http://0.0.0.0:4024 survives that, at the cost of
    # listening on every interface, which leaves the scoped firewall rule as the only thing gating an
    # elevated server. Defaults to the resolved address, so the narrow choice stays the default.
    [string] $Bind,

    [string] $FirewallFrom,
    [switch] $SkipSysinternals
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Step { param($m) Write-Host "==> $m" -ForegroundColor Cyan }
function Warn { param($m) Write-Host "    $m" -ForegroundColor Yellow }
function Note { param($m) Write-Host "    $m" }

# --- where the target is ---------------------------------------------------------------------------
$targetIp = ([System.Net.Dns]::GetHostAddresses($Target) |
    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
    Select-Object -First 1).IPAddressToString
if (-not $targetIp) { throw "Could not resolve $Target to an IPv4 address." }

if (-not $FirewallFrom) {
    # From the routing table, not "first non-loopback IPv4": Hyper-V and WSL adapters sort ahead of the
    # real one, and a rule scoped to 172.23.240.1 admits an address that can never reach the target.
    $FirewallFrom = (Find-NetRoute -RemoteIPAddress $targetIp | Select-Object -First 1 -ExpandProperty IPAddress)
    Warn "firewall scoped to this machine ($FirewallFrom); pass -FirewallFrom to change it"
}

Step "connecting to $Target ($targetIp)"

$sessionArgs = @{ ComputerName = $Target }
if ($Credential) { $sessionArgs.Credential = $Credential }
$session = New-PSSession @sessionArgs

try {
    $facts = Invoke-Command -Session $session -ScriptBlock {
        [pscustomobject]@{
            Name     = $env:COMPUTERNAME
            Arch     = $env:PROCESSOR_ARCHITECTURE
            Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
            Existing = (Get-Service -Name $using:ServiceName -ErrorAction SilentlyContinue).Status
        }
    }

    Note "$($facts.Name), $($facts.Arch), elevated=$($facts.Elevated)"

    # Checked rather than assumed: the SCM refuses an unelevated caller, and the installer's answer to
    # that is a UAC relaunch that would block forever on a prompt nobody can see.
    if (-not $facts.Elevated) {
        throw "The WinRM session on $Target is not elevated, so the SCM will refuse to register a service."
    }

    if ($facts.Existing) {
        throw ("'$ServiceName' already exists on $Target (currently $($facts.Existing)). Remove it with " +
               "--uninstall-service before bootstrapping again, rather than installing a second one.")
    }

    $arch = if ($facts.Arch -eq 'AMD64') { 'x64' } else { 'x86' }

    # --- what to send ------------------------------------------------------------------------------
    $files = @(
        [pscustomobject]@{ Local = Join-Path $repo "artifacts\win-$arch\WinDiag.Mcp.exe"; Name = 'WinDiag.Mcp.exe' }
    )

    if (-not $SkipSysinternals) {
        # Without these four tools report Unavailable, and the reason is a missing file nobody thinks to
        # look for. The 64-bit names matter: the 32-bit handle.exe on 64-bit Windows answers
        # "No matching handles found." to every query rather than failing.
        $suffix = if ($arch -eq 'x64') { '64' } else { '' }
        foreach ($tool in "Procmon$suffix.exe", "handle$suffix.exe", "autorunsc$suffix.exe") {
            $files += [pscustomobject]@{ Local = Join-Path $repo "artifacts\sysinternals\$tool"; Name = $tool }
        }
    }

    foreach ($f in $files) {
        if (-not (Test-Path $f.Local)) { throw "Missing locally: $($f.Local)" }
    }

    Invoke-Command -Session $session -ScriptBlock {
        $null = New-Item -ItemType Directory -Path $using:RemotePath -Force
    }

    # --- send, and verify every byte ---------------------------------------------------------------
    # Hash-checked on both sides because the failure this prevents is silent: an 89 MB copy to a lab VM
    # was seen truncating at exactly the right file size, twice.
    foreach ($f in $files) {
        $expected = (Get-FileHash $f.Local -Algorithm SHA256).Hash
        $size = [Math]::Round((Get-Item $f.Local).Length / 1MB, 1)
        Step "sending $($f.Name) ($size MB)"

        Copy-Item -Path $f.Local -Destination (Join-Path $RemotePath $f.Name) -ToSession $session -Force

        $actual = Invoke-Command -Session $session -ScriptBlock {
            (Get-FileHash (Join-Path $using:RemotePath $using:f.Name) -Algorithm SHA256).Hash
        }

        if ($actual -ne $expected) {
            throw "$($f.Name) arrived corrupted on $Target (expected $expected, got $actual)."
        }
        Note "verified $expected"
    }

    # --- register ----------------------------------------------------------------------------------
    $installArgs = @(
        '--install-service'
        '--service-name'; $ServiceName
        '--http'; $(if ($Bind) { $Bind } else { "http://${targetIp}:${Port}" })
        '--artifacts'; $ArtifactPath
        '--firewall-from'; $FirewallFrom
    )
    if ($Token) { $installArgs += @('--token', $Token) }
    switch ($Grants) {
        'Standard' { $installArgs += @('--allow-self-update', '--allow-command-execution') }
        'All'      { $installArgs += @('--allow-self-update', '--allow-command-execution',
                                       '--allow-arbitrary-write', '--allow-arbitrary-read') }
        'None'     { $installArgs += '--read-only' }
    }

    Step "registering '$ServiceName'"

    # The installer writes everything to stderr -- it has no other channel once it is a service -- so
    # the remote side merges the streams itself and hands back plain strings. Left to PowerShell's
    # remoting error stream instead, a successful install arrives as a pile of RemoteExceptions.
    $install = Invoke-Command -Session $session -ScriptBlock {
        $out = & "$using:RemotePath\WinDiag.Mcp.exe" @using:installArgs 2>&1 | ForEach-Object { "$_" }
        [pscustomobject]@{ Output = $out; ExitCode = $LASTEXITCODE }
    }

    $install.Output | ForEach-Object { Note $_ }

    # 2 configuration or already-exists, 3 elevation refused, 4 something unexpected that it named.
    if ($install.ExitCode -ne 0) {
        throw "--install-service exited $($install.ExitCode) on $Target."
    }

    # --- verify ------------------------------------------------------------------------------------
    # Installing successfully and actually answering are different claims; a service that starts and
    # immediately exits looks Running for a moment either way.
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
               "Check the Application event log on $Target under source 'windiag'.")
    }

    if ($Token) {
        Step 'calling capabilities'

        # -Raw and an emptiness check, not an exit code: mcp-call.ps1 reports a refusal to the host and
        # exits 1, which does not throw here. A token disagreeing with ~/.windiag-targets.json is the
        # likeliest mistake this step exists to catch, and unchecked it prints its 401 and falls
        # through to the success banner.
        $raw = & "$PSScriptRoot\mcp-call.ps1" -Address "http://${targetIp}:${Port}" -Token $Token -Tool capabilities -Raw
        if (-not $raw) {
            throw ("$Target is listening but refused the token. The service is installed; correct the " +
                   "token and re-register, or fix ~/.windiag-targets.json to match it.")
        }
        Note ($raw | ConvertFrom-Json).summary
    }

    Write-Host ""
    Write-Host "$Target is registered as '$ServiceName' and answering on ${targetIp}:${Port}." -ForegroundColor Green
}
finally {
    if ($session) { Remove-PSSession $session }
}
