---
name: sysdiag-target
description: Use when standing up, updating, or recovering a sysdiag target machine (WinDiag, LinuxDiag or MacDiag) — "set up windiag on <host>", "add this VM to windiag", "deploy the latest build to <host>", "the target is down / not answering / refusing the token", "register windiag as a service", "give me read-only access to that box", "runner1 is unreachable". Covers choosing a transport from what the target actually answers on, choosing grants, first install, later updates via update_self, and the failures that look like something else. Do NOT read src/ to answer a configuration question — `--help` and the README are authoritative.
---

# Setting up and recovering a sysdiag target

## First, never skip this

`WinDiag.Mcp.exe --help` is the authoritative CLI reference and the README documents every
`WINDIAG_*` variable, both bootstrap routes, and the `-Grants` presets. **Reading `src/` to find out
what a flag is called is a bug in the docs — fix the doc rather than working around it.**

Adding an entry to `~/.sysdiag-targets.json` deploys nothing. It only tells the relay where to
connect to a server that is *already listening*. A new machine always needs a bootstrap first.

## 1. Ask the target what it answers on

Do this before choosing anything. The route is a property of the machine, not a preference.

```powershell
foreach ($p in 4024, 445, 135, 5985, 3389) {
  '{0,-6} {1}' -f $p, (Test-NetConnection -ComputerName $t -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue)
}
```

| What you see | What it means |
|---|---|
| 4024 open | Something already serves. Do **not** bootstrap — go to step 4 (update) |
| 445 + 135, admin share mountable | `tools/bootstrap-target.ps1` (SMB + PsExec) |
| 5985 open | `tools/bootstrap-winrm.ps1` — preferred where it works, no credentials needed if your logon is admin there |
| nothing but 3389 | Console/RDP only. Say so rather than burning attempts |

**Check the admin share before trusting 445.** An open port only means TCP connects:

```powershell
net use "\\$t\ADMIN$"      # 3743 "not configured for remote administration" => shares DISABLED
```

`NET HELPMSG 3743`, or system error 67 on `IPC$`, means administrative shares are switched off. **No
privilege level fixes that** — a share that is not published cannot be mounted — and it rules out
`bootstrap-target.ps1`, `deploy-target.ps1` and PsExec together, since PsExec needs `ADMIN$` to
install its own service. Use WinRM.

## 2. WinRM: address it by name

Negotiate against an *IP* needs the target in the **caller's** `TrustedHosts`, an elevated change to
your own workstation. A **name** resolves to an SPN and uses Kerberos, needing nothing local. When
reverse DNS and NetBIOS are both dead, the machine's own RDP certificate carries its hostname:

```powershell
$c = New-Object Net.Sockets.TcpClient($ip, 3389)
$s = New-Object Net.Security.SslStream($c.GetStream(), $false, {$true})
$s.AuthenticateAsClient($ip); $s.RemoteCertificate.Subject   # CN=host.example.com
```

Confirm before staging anything — this also tells you the architecture and whether you get an
elevated token:

```powershell
Invoke-Command -ComputerName $name { $env:PROCESSOR_ARCHITECTURE,
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators') }
```

## 3. Choose grants deliberately, then install

**Read the preset before using it.** `-Grants None` passes `--read-only` *alone* — services and
processes only, and it cannot read a single configuration file. If someone asks for read-only access
to inspect files, that is `--read-only --allow-arbitrary-read`, which no preset spells:

```powershell
.\tools\bootstrap-winrm.ps1 -Target host.example.com -Token $token -Grants All -Bind 'http://0.0.0.0:4024'
```

- **Bind `0.0.0.0` if the target is on DHCP** (`Get-NetIPAddress … PrefixOrigin`). A literal address
  stops resolving when the lease moves; the service then fails to bind on boot and the machine goes
  quiet weeks later, looking like anything but DHCP. Prefer hostnames in the targets file too.
- **The token must match the targets file**, or the alias connects and then 401s every call.
- Sysinternals binaries go across with the build. Without them `autostart_audit`,
  `capture_activity`, `path_handle_search` and `process_handles` report Unavailable, and the reason is
  a missing file nobody thinks to look for.

## 4. Updating a target that already serves

`update_self`, not another bootstrap. Push the build with the relay's `push_file` (bytes never enter
the conversation), then call `update_self` with the staged hash — or use `tools/deploy-target.ps1`,
which stages and updates in one step.

It **waits for in-flight calls by default** and refuses new ones while draining, so on a busy target
this takes minutes; `force` cuts that work off instead. **A dropped connection is success.** If it
does not come back, read the helper log named in the result.

## 5. Verify — installing and answering are different claims

```powershell
.\tools\mcp-call.ps1 -Address "http://$name:4024" -Token $token -Tool capabilities
```

Expect *N tools; N fully available. Server is elevated.* Anything Unavailable names its own cause.

**`mcp-call.ps1` exits 1 on a refusal without throwing.** In a script, capture `-Raw` and treat empty
output as failure, or you will report success for work that never happened.

## Failures that look like something else

| Symptom | Actual cause |
|---|---|
| Relay alias 401s after a target restarted | The relay's cached connection, not a changed token. Reconnect the alias; check with `mcp-call.ps1` directly first |
| `runner1__*` tools not callable after editing the targets file | The relay only enumerates at startup. Start a fresh session; until then `mcp-call.ps1` reaches the target directly |
| Tools Unavailable on a working server | Missing Sysinternals binary, or the server is not elevated. `capabilities` says which |
| `update_self` succeeds but the build is unchanged | The helper aborted and restored the old build — a server answers either way. Compare `file_signatures` against the staged hash |
| Host reachable, 4024 closed, nothing can update it | Nothing is running. If it served before an `update_self`, first read the target's Application event log (source `windiag`): a service that refuses to start says why there. `… can be renamed or removed …` means a directory above windiag's lets others replace it — remove the rights it names, or hand it to Administrators (`icacls <dir> /setowner *S-1-5-32-544`) when it says an account `owns it`, or move windiag — then start the service again. Otherwise this is a bootstrap, not an update |
| Bootstrap refuses an existing `C:\WinDiag` with `… cannot be used as it is` | The scripts never take over a directory that already exists and is not restricted. Rename it aside and bootstrap again; if windiag still serves from it, `update_self` instead — the new server restricts it on its next start |
| A capture appears then vanishes | As SYSTEM `%TEMP%` is `C:\Windows\SystemTemp`. Pin `--artifacts` |

## Never

- Put the token on a serving command line — `process_list` exposes command lines to every local user.
  Installing, use `--install-service --token-stdin`; `--token <value>` is visible in the installer's own
  command line (and process-creation auditing) while it runs.
- Stand a target up across a network the operator does not trust. The channel is plaintext HTTP with
  no TLS, so the token — and every dump, file and command output — is readable by anyone on the path,
  and `--firewall-from` scopes who can connect, not who can watch. Trusted segment, or a tunnel.
- Scope a firewall rule to a subnet, or to whatever `Get-NetIPAddress` returns first — on a box with
  Hyper-V or WSL adapters that is a virtual address that can never reach the target. Ask the routing
  table: `Find-NetRoute -RemoteIPAddress $ip`.
