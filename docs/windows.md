# WinDiag on Windows targets

## Running it


```
dotnet run --project src/WinDiag.Mcp                      # stdio
dotnet run --project src/WinDiag.Mcp -- --http http://127.0.0.1:7777
dotnet run --project src/DiagRelay.Mcp                   # local relay to any target (see relay.md)
WinDiag.Mcp --help
```

Locally over stdio:

```json
{
  "mcpServers": {
    "windiag": {
      "type": "stdio",
      "command": "D:/Tools/sysdiag-mcp/artifacts/win-x64/WinDiag.Mcp.exe"
    }
  }
}
```


## Deploying to a target machine

This is the intended shape: the debugging target is a different machine, where you have admin and we
do not. Rather than remoting into it, the server runs *there* and Claude Code connects to it — the
same pattern as `dbgsrv`, but with no remoting layer, no stored credentials, and nothing that
resembles a lateral-movement primitive.

### One command

`tools/deploy-target.ps1` does the whole thing from the base machine:

```
.\tools\deploy-target.ps1 -Target 192.168.32.76 -Token $token
```

It asks the target which architecture it is, publishes that build, downloads the Sysinternals binaries
pinned in `tools/sysinternals.json`, verifies each one's SHA-256 *and* its Microsoft signature, stages
everything **over the running server's own `put_file` channel** — no SMB share — records what it staged
in `windiag-staged.json` on the target, and then calls `update_self` and waits for the server to come
back. It finishes by printing any tool that is not fully available.

Without `-Token` (the first-ever deploy, when nothing is running to receive a `put_file`) it stages
over the SMB admin share instead and prints the command to start the server by hand. That first hop is
the one no tool on the target can remove; everything after it rides HTTP.

Three behaviours are deliberate and worth knowing:

- **A Sysinternals version change stops the deploy.** `download.sysinternals.com` always serves the
  latest build, so a pinned hash is how a version change gets *noticed* rather than absorbed. Re-run
  with `-AcceptUpstreamChange` to re-pin, and commit that as a deliberate bump.
- **`windiag-staged.json` is compared before it is rewritten.** A file someone replaced on the target
  by hand is reported as drift, not silently overwritten. That report is the point of the file.
- **`-Smb` forces the share even with a server running.** Needed once to land a build whose `put_file`
  protocol the *running* server does not yet speak (chunked/append support arrived this way), and as a
  fallback if an HTTP transfer will not go through. The large server binary is sent in hash-verified
  4&#160;MB chunks over HTTP — a single ~57&#160;MB base64 body is more than a 32-bit server can decode
  at once, and a per-chunk hash catches a corrupt chunk on a lossy link at the chunk, not minutes later.
- **A deploy waits for whatever the target is already doing.** `update_self` finishes the calls in
  flight before it restarts, refusing new ones meanwhile, so a deploy no longer cuts short a capture
  someone else started — it used to, silently, leaving them a truncated trace and a transport error.
  The script therefore extends its own patience to match (`WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS`
  plus 90&#160;s for the restart) and says so when it is waiting on someone. Pass `force` to
  `update_self` by hand if you would rather take the target down now and orphan that work.

The rest of this section is what the script automates, and what to do when it cannot be used.

### Getting artifacts back off a target

`capture_dump` and `capture_activity` return a UNC path on the admin share, but that is no longer the
only way to collect what they wrote — and the share brings back the whole token-filtering prerequisite
below. `get_file` reads a file back over the same authenticated HTTP the tools already use, sliced and
hash-verified exactly as `put_file` is in the other direction:

```
.\tools\fetch-from-target.ps1 -Target 192.168.32.93 -Token $token `
  -RemotePath 'C:\Users\admin\AppData\Local\Temp\windiag\explorer_1904.dmp'
```

The script walks the slices, checks each one's SHA-256 before appending, and verifies the reassembled
copy against the whole-file hash the target reported. It streams to disk rather than buffering, so a
large dump is practical — and when this is driven from an agent session, the bytes never enter the
conversation. Calling `get_file` directly is for small files (a config, a log tail); the response
carries the bytes, so a multi-megabyte dump fetched that way lands in the caller's context.

From a session with the relay connected, [`pull_file`](relay.md#moving-files-without-spending-context) does the
same thing as one tool call and needs no token argument, since the relay already holds it. The script
remains the right tool from a plain shell, or when no relay is running.

No flag is needed for anything a capture wrote: the artifact directory is one of windiag's own. Reading
elsewhere needs `WINDIAG_ALLOW_ARBITRARY_READ`. Multi-gigabyte `full` dumps still belong on the UNC
path — the same caveat `put_file` carries in the other direction.


## Reaching the admin share

Both the first-deploy hop and `-Smb` write to `\\<target>\C$`, which only opens to an administrator whose
token is *not* filtered. Two different failures turn up here, and they mean different things:

- **`The password is invalid`** — authentication was rejected. A wrong password, or the wrong account
  *scope*: `/user:<host>\name` names a **local** account, but a domain-joined target wants `DOMAIN\name`.
  Repeated misses can lock the account, which then surfaces as the next error instead.
- **`System error 5 … Access is denied`** — the credential authenticated but is not authorised for `C$`.
  For a **local** admin this is UAC remote token filtering: over the network a local admin is handed a
  filtered standard-user token and `C$`/`ADMIN$` are denied even with the right password. Set this **on
  the target** once, at the console or over RDP — it cannot be set over the channel it is blocking — and
  new sessions get through with no reboot:
  ```
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^
    /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
  ```
  This is the same prerequisite the lab VMs needed. The built-in `Administrator` (RID 500) is exempt from
  filtering, so `net use \\<target>\C$ /user:<target>\Administrator` connects without the policy where
  that account is enabled.

Confirm the share opens before deploying over it:
```
net use \\<target>\C$ /user:<target>\admin
```

**1. Publish one file.** Self-contained, so the target needs no .NET runtime:

```
dotnet publish src/WinDiag.Mcp/WinDiag.Mcp.csproj -c Release -r win-x64 --self-contained ^
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts/win-x64
```

Produces `artifacts/win-x64/WinDiag.Mcp.exe`, ~96 MB. Drop `--self-contained` for a ~2 MB build if
the target already has the .NET 10 runtime. Trimming is *not* used: the MCP SDK discovers tools by
reflection and WMI binds late, so a trimmed build fails at runtime rather than at publish.

**Targets are both 32- and 64-bit VMs, so publish both** and copy the matching one to each machine —
an x64 build cannot load at all on 32-bit Windows:

```
dotnet publish src/WinDiag.Mcp/WinDiag.Mcp.csproj -c Release -r win-x64 --self-contained ^
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts/win-x64
dotnet publish src/WinDiag.Mcp/WinDiag.Mcp.csproj -c Release -r win-x86 --self-contained ^
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o artifacts/win-x86
```

Roughly 96 MB and 89 MB respectively.

The hand-written interop is 32-bit clean — every struct containing a pointer is sized with
`Marshal.SizeOf` rather than a constant, and the fixed offsets (`FILE_DIRECTORY_INFORMATION`, the
`MIB_*` row strides) are pointer-free and identical on both. Verified by running the x86 build under
WOW64 and confirming named-pipe instance counts and socket ports still come back correct.

**Getting the pairing wrong is the failure worth guarding.** The x86 build on 64-bit Windows cannot dump
a 64-bit process and cannot capture activity at all (the 32-bit Procmon refuses to capture on x64) — and
both failures surface much later, looking like tool bugs rather than a wrong download. The server
therefore warns about it at startup and in `system_overview`.

**The same trap applies to the Sysinternals binaries, and there it is worse.** Each download ships two
builds whose names differ by one character, and on 64-bit Windows the 32-bit one does not fail — it
answers wrongly. Measured on an x64 workstation, both unelevated, same filter:

```
handle.exe   -u -v System32  ->  "No matching handles found."
handle64.exe -u -v System32  ->  526 rows
```

An empty handle search reads as *"nothing holds this file"*, which is the answer that ends an
investigation. Procmon fails as quietly by a different route: its 32-bit build is a launcher that
starts the 64-bit one and exits, so a capture appears to finish in a second over a trace that is still
being written.

So the server does not resolve `handle.exe`; it resolves *handle*, prefers `handle64.exe` on a 64-bit
OS, and if only the unsuffixed build is present it reads that file's PE machine type and **refuses**
rather than running it. `capabilities` makes the same decision ahead of time and reports the path it
would use, because two copies of a Sysinternals tool on one machine is the normal case:

```
- path_handle_search [Available] Sysinternals handle.exe - Ready, using C:\WinDiag\handle64.exe.
```

`deploy-target.ps1` stages both builds of every tool, so the refusal only fires on a machine someone
set up by hand.

A tool found in the server's own folder, which is searched first, is also run only if its Authenticode
signature is valid and Microsoft's: whatever sits there runs as the service's account. An unsigned or
foreign-signed copy is refused by name, in the tool's result and in `capabilities`.


## Verifying on a target

Two capabilities cannot be covered by `dotnet test`, because they need administrator rights and a kernel
driver: `capture_activity`/`query_activity` and `path_handle_search`. Their unit tests run against a
stubbed process runner, so they prove the arguments are composed correctly and nothing more.

`tools/verify-on-target.ps1` proves they actually work. It drives the **published** server over stdio
exactly as Claude Code does, so the machine under test needs no .NET SDK — just the one exe.

**Verified on both.** A 32-bit Windows 10 VM and a 64-bit Windows 11 VM, both elevated, both running
the build from this tree:

| Check | 32-bit target | 64-bit target |
|---|---|---|
| Sysinternals build chosen | `handle.exe`, `Procmon.exe`, `autorunsc.exe` | `handle64.exe`, `Procmon64.exe`, `autorunsc64.exe` |
| `path_handle_search` | 106 handles | 217 handles, including ones held by `NT AUTHORITY\SYSTEM` |
| `process_handles` | attributed correctly | 506 handles, 17 object types, 0 rows misattributed |
| `capture_activity` + `query_activity` | 84,764 events | 419,767 events; 16,651 against a file `capture_dump` wrote *during* the window |
| `capture_dump` | verified | 3.4 MB mini dump of a 64-bit process |
| `registry_read` views | one view, labelled as such | 64-bit: 37 subkeys, WOW6432Node: 25 |

The handle counts are the point. Before the architecture-aware resolution, the 64-bit target would
have run the 32-bit `handle.exe` and answered *"No matching handles found."* to all 217.

**Run it on both a 32- and a 64-bit target.** Several answers here differ by bitness, and the ones
that differ *silently* are why the script exists: three of its checks only mean anything on 64-bit
Windows. Unelevated it still runs everything that can answer without administrator rights and reports
the rest as `SKIP` with the reason, so a machine where nobody has admin can still be verified.

```
powershell -ExecutionPolicy Bypass -File verify-on-target.ps1 -ServerPath .\WinDiag.Mcp.exe
```

Run it elevated. Each check is self-verifying: the script holds a file open and requires the handle
search to find its own PID, and generates known file activity during the capture window and requires
the query to find it. A pass cannot be a coincidence.

**2. Sign it.** An unsigned, elevated network listener is exactly what endpoint security on a managed
machine should object to. Sign with the release certificate before copying.

**Verify the copy by hash, not by size.** Copying the ~90 MB build to a lab VM produced a file of
*exactly* the right size that was corrupt — twice, once with an explicit "unexpected network error".
Only the hash caught it, and a swap script that checked size alone would have installed a broken
executable.

Two things make this manageable:

- `-p:EnableCompressionInSingleFile=true` roughly halves the payload (90 MB → 45 MB), at the cost of a
  little startup time while it decompresses. Worth it on any slow link.
- Use **BITS** rather than a plain copy. It is restartable and checksummed, and it succeeded on the
  same link where `Copy-Item` and `robocopy` both failed:
  ```powershell
  Start-BitsTransfer -Source .\WinDiag.Mcp.exe -Destination \\target\C$\...\WinDiag.Mcp.new.exe
  ```

Verify the landed file with the server already running on the target — `file_signatures` hashes it
*there*, so nothing crosses the link a second time:

```powershell
mcp-call.ps1 -Address http://target:7777 -Token ... -Tool file_signatures `
  -Arguments '{"paths":["C:/path/WinDiag.Mcp.new.exe"]}'
```

Stage under a different filename. The live exe is locked while it runs, so making it the copy target
fails — and a rename-then-copy dance risks renaming the running binary instead.

**3. Copy it across and start it elevated:**

```
set WINDIAG_TOKEN=<paste a long random value>
WinDiag.Mcp.exe --http http://10.0.0.5:7777
```

Omit `WINDIAG_TOKEN` and the server generates one and prints it to stderr; it changes on restart.

### Running it as a service instead

Everything above starts the server by hand, which is how the fleet has always run and still works
unchanged. The same executable can also run under the Service Control Manager, which buys one thing
worth having: **`service_control` can then restart a target remotely**, so a server that dies, or one
you deliberately stop, no longer needs somebody at that machine's console. That was the single
recurring cost of the by-hand model.

The executable installs itself, so a target needs nothing copied to it but the one file it already
has. Run it from any shell — it asks Windows for elevation if it does not have it:

```
WinDiag.Mcp.exe --install-service --http http://10.0.0.5:7777 ^
  --start auto --allow-self-update --firewall-from 10.0.0.9 ^
  --artifacts C:\WinDiagArtifacts
```

That registers the service, configures the SCM to restart it if the process dies, generates a
256-bit token and stores it where only SYSTEM, Administrators and the service's account can read it,
opens the port to one address, and starts it. The token is printed once, because it exists nowhere
else a human can read. It goes into `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters`, a key
created with that ACL already on it, and not into the service key's own `Environment` value: `sc
create` makes that key readable by every local user, and a handle someone opened on it before it was
restricted would go on reading whatever was written there afterwards. A target installed by an older
build, whose token is still in `Environment`, keeps starting with it after `update_self`, and logs a
warning until it is reinstalled with a new token. The reverse does not hold: an older build sent by
`update_self` to a target this build installed finds no token in `Environment`, generates one nobody
has, and cannot be reached again until it is reinstalled at the console. Do not downgrade such a target
through `update_self`.

The executable's directory and the `--artifacts` directory must be ones only SYSTEM and
Administrators can change, and everything in them too. That is not tidiness: the service runs the
Sysinternals binaries it finds beside itself and `self-update.cmd` from the artifact directory as
SYSTEM, and a folder made under `C:\` inherits *Authenticated Users: Modify*. An `--artifacts`
directory that does not exist yet is created with the right ACL from the start. **One that exists and
that anyone but an administrator can change is refused, not taken over** — either directory (files an
administrator copied in, owned by their own account, are simply handed to Administrators): restricting it would not
shut out a handle opened on it, or on a file in it, beforehand, and whoever made it can hold one open
to put their own access back afterwards. So install from a directory that was restricted when it was
made: one created from an elevated prompt under `C:\Program Files` (`md "%ProgramFiles%\WinDiag"`),
whose inherited ACL lets only administrators write, or the `C:\WinDiag` the bootstrap scripts create.
If the refusal names a directory an earlier windiag left, rename it aside and install again; one that
the service restricted on its last start is used as it is. A service repeats the check on every start,
writes what it changed to the Application event log, and refuses to start from a directory it cannot
restrict; the default artifact directory, `%TEMP%\windiag`, it moves aside and makes afresh if someone
else made it first. Either directory being a link — a junction, a symbolic link, a mounted folder — or being reached
through one is refused: whoever made the link could point it somewhere else after the check. So is
either directory sitting below one that someone else could rename or empty, such as a folder any user
made under `C:\` — they could put a directory of their own in its place. Above the two directories, a
direct member of the local Administrators group counts as an administrator, so a folder the built-in
Administrator made and owns is fine; an owner outside the group, or in it only through a domain group,
is not, even when the ACL is restricted. Links only administrators can change, in a directory only
they can write, are left alone. **Install from a directory of its own**: a Downloads folder or a drive
root is refused, and the refusal names the files in it that are not windiag's.

A target installed by an older build has these directories restricted by its next `update_self`, but
restricting them does not undo what happened while they were open: a file a local user planted is
still there, and a handle they opened then keeps its access until it is closed. On such a target,
check the files against `windiag-staged.json` and restart the machine, which closes every such handle.

```
WinDiag.Mcp.exe --service-status      # by hand, or as a service? and configured how?
WinDiag.Mcp.exe --uninstall-service   # removes the service, its token key and its firewall rule
```

`--service-status` answers a question the machine cannot otherwise be asked in one step: a server
started by hand and one running as a service look identical from outside and behave differently on
every restart.

**Carry the grants across.** A by-hand server running with `--allow-self-update` re-registered
without it comes back with fewer tools than it went away with, and nothing announces that except a
`capabilities` call nobody makes. `--service-status` lists what was configured.

#### Every option `--install-service` takes

`WinDiag.Mcp.exe --help` prints this list too, and is the authority if the two ever disagree.

| Option | Meaning |
|---|---|
| `--http <url>` | Required. What to bind. **On DHCP, bind `http://0.0.0.0:<port>`** — a literal address stops resolving when the lease moves, the service then fails to bind on boot, and the machine goes quiet |
| `--service-name <name>` | Default `windiag`. More than one instance per machine is fine |
| `--display-name <text>` | What `services.msc` shows. Default: the service name |
| `--start auto\|delayed\|demand` | Default `auto` |
| `--account <spec>` | `LocalSystem` (default), `NetworkService`, `LocalService`, or `DOMAIN\user` with `--password` |
| `--password <value>` | Required for an account that is not built in |
| `--token-stdin` | Reads the token from standard input, so it never appears on the target's command line. Needs an already-elevated shell: stdin cannot cross the UAC prompt. The bootstrap scripts use this |
| `--token <value>` | Default: a new 256-bit token, printed once. Must match what the relay's targets file holds for this machine, or the alias connects and then 401s every call. Prefer `--token-stdin`: a value here is in the installer's command line, which process auditing records |
| `--artifacts <dir>` | Pins `WINDIAG_ARTIFACT_DIR`. As SYSTEM `%TEMP%` is `C:\Windows\SystemTemp`, so captures and dumps move somewhere surprising without it. Give windiag a directory of its own: one that does not exist yet is created restricted to SYSTEM and Administrators, as are directories above it that do not exist yet, and one that exists and others can change is refused rather than taken over. A service refuses it when it is reached through any link, or sits below a directory others could rename — a folder made under a drive root, say — and, run by hand, `get_file` and `put_file` refuse one reached through a folder a volume is mounted at, a junction to a device, or a relative symbolic link: see Troubleshooting |
| `--allow-self-update` | Registers `update_self`, and lets `put_file` stage into the server's own directory |
| `--allow-command-execution` | Registers `run_command` |
| `--allow-arbitrary-write` | Lets `put_file` write anywhere, the server's own directory included |
| `--allow-arbitrary-read` | Lets the read tools open files outside them |
| `--read-only` | Drops every state-changing tool |
| `--firewall-from <address>` | Opens the bind port inbound from one address, removed on uninstall. An address, never a subnet |
| `--no-restart-on-failure` | Default is to let the SCM restart it if the process dies |

An option not in this table is refused and nothing is installed, so a misspelt `--readonly` cannot
quietly register a writable service. So is an option whose value is missing, empty or another option:
Windows PowerShell 5.1 drops an empty `$tok` from `--token $tok`, and the grant after it would otherwise
have become the token and still been granted. A server started by hand likewise takes only `--http`:
its grants are the `WINDIAG_*` variables, and `--read-only` on that command line is refused rather than
ignored.

**Flags and environment variables are two spellings of one setting.** Each grant flag becomes its
`WINDIAG_*` variable (see [Configuration](configuration.md#configuration)) in the service key's `Environment` value —
`--allow-arbitrary-read` writes `WINDIAG_ALLOW_ARBITRARY_READ=1`. So anything the environment can
express, an install can too, and the semantics documented there apply unchanged to the flags here.

The combination worth calling out, because no example above uses it:

```
WinDiag.Mcp.exe --install-service --http http://0.0.0.0:4024 ^
  --read-only --allow-arbitrary-read --firewall-from 10.0.0.9
```

That is a **look-but-do-not-touch** target: no `run_command`, no writes, no `update_self`, but the
read tools can still open any file the service account can reach. `--read-only` deliberately does
*not* override the read grant — reading is what a read-only server is for. Reach for this when
somebody will grant you diagnostics on a machine but not a shell on it.

### Bringing up a machine that has never run windiag

`--install-service` assumes the executable is already on the target. Getting it there is the one step
that needs a route in, and the two scripts under `tools/` cover the two shapes that exist. Both leave
a registered, verified, auto-start service; after that every update goes through `update_self` and
neither script is needed for that machine again.

| Script | Route | Use it when |
|---|---|---|
| `tools/bootstrap-target.ps1` | Admin share (SMB 445) + PsExec (RPC 135) | The admin share is reachable. Takes `-Credential`; needs no WinRM |
| `tools/bootstrap-winrm.ps1` | WinRM (5985), addressed **by name** | The admin share is off, or you would rather use Kerberos. Needs no credentials at all where your own logon is admin on the target |

Which one applies is a property of the target, not a preference:

- **`ADMIN$` answering *"The server is not configured for remote administration"* (`NET HELPMSG 3743`),
  or `IPC$` answering system error 67, means the administrative shares are disabled.** No account,
  however privileged, can mount a share that is not published — so `bootstrap-target.ps1` and
  `deploy-target.ps1` both fail, PsExec included, since it needs `ADMIN$` to install its own service.
  Use the WinRM script.
- **Address WinRM by name, never by IP.** Negotiate against an IP requires the *caller's* machine to
  list it in `TrustedHosts`, which is an elevated change to your own workstation. A name resolves to
  an SPN and authenticates with Kerberos, needing nothing configured locally. Where reverse DNS is
  missing, the machine's own RDP certificate carries its hostname:
  ```powershell
  $c = New-Object Net.Sockets.TcpClient($ip, 3389)
  $s = New-Object Net.Security.SslStream($c.GetStream(), $false, {$true})
  $s.AuthenticateAsClient($ip); $s.RemoteCertificate.Subject   # CN=host.example.com
  ```

Both take `-Grants`, and **the preset names are not a security policy — check what they pass**:

| `-Grants` | Passes | Result |
|---|---|---|
| `None` | `--read-only` alone | Services, processes and the registry outside HKLM\SAM, HKLM\SECURITY and other users' hives. **Cannot read a single config file**, and no tool opens a network share — if you want read-only-but-readable, do not use this; pass `--read-only --allow-arbitrary-read` yourself |
| `Standard` | `--allow-self-update --allow-command-execution` | The usual fleet target |
| `All` | those two plus `--allow-arbitrary-write --allow-arbitrary-read` | Full diagnostics |

```powershell
# a fleet, one credential prompt
$c = Get-Credential
'10.0.0.5','10.0.0.6' | ForEach-Object {
    .\tools\bootstrap-target.ps1 -Target $_ -Credential $c -Token $token -Grants Standard
}

# admin shares off, domain-joined, no password needed
.\tools\bootstrap-winrm.ps1 -Target host.example.com -Token $token -Grants All -Bind 'http://0.0.0.0:4024'
```

Neither script puts a secret on a command line. The token reaches the installer on `--token-stdin` —
piped through the WinRM session, or, for PsExec, from a file in the install directory, named afresh
for each run, created readable only by SYSTEM and Administrators, and deleted as soon as the installer
returns — and `bootstrap-target.ps1` opens its `IPC$` session in-process rather than through `net use`,
whose command line would carry the password. Both create `-RemotePath` and `-ArtifactPath` (default
`C:\WinDiag` and `C:\WinDiagArtifacts`) restricted to SYSTEM and Administrators before anything is
copied into them, since a folder made under `C:\` is writable by every user. A directory that already
exists is used only if it is already restricted that way, and is otherwise refused with nothing
changed: taking over what someone else could still change needs handles opened without following
links, which the installer and the service have and a script sent bare to a target does not. Rename
such a directory aside and run again — or, if windiag already runs from it, let `update_self` bring it
to this release, whose next start restricts it. A directory that is, or is reached through, a link, or
sits below one others could rename, is refused too. Who counts as an administrator above the two
directories depends on where they are judged. `bootstrap-winrm.ps1` judges them on the target, by the
target's own rule, the installer's: a direct member of its Administrators group counts. `bootstrap-target.ps1`
and `deploy-target.ps1` judge them from your workstation over the admin share (`\\host\C$\…`), where
your machine's Administrators group says nothing about the target's, so there only SYSTEM, the
Administrators group itself and TrustedInstaller count: a folder above that the target's built-in
Administrator owns is refused over the share although the installer would accept it. Hand it to the group
(`icacls <dir> /setowner *S-1-5-32-544`) or use `bootstrap-winrm.ps1`.

Adding a target to the relay's `~/.sysdiag-targets.json` does **not** deploy or start anything; it
only tells the relay where to connect to a server that is already listening. **Prefer hostnames over
addresses in that file** for the same reason as the bind: a DHCP lease that moves breaks every entry
pinned to an address.

Doing it by hand instead is a few more commands, and three details are easy to lose — the token's
location, the artifact directory, and the grants:

```
sc create windiagsvc binPath= "\"C:\WinDiag\WinDiag.Mcp.exe\" --http http://10.0.0.5:7777" ^
   start= auto obj= LocalSystem DisplayName= "windiag"
```

**Put the token in a key created restricted, not a machine-wide variable and not the service key
itself.** A service has no console to inherit `WINDIAG_TOKEN` from, and the obvious fix is the wrong
one: machine environment variables are readable by *every local user*, and with `run_command` or
`update_self` enabled that token is code execution as SYSTEM. **`sc create` does not protect the
per-service key either** — it inherits the Services key's ACL, under which every local user can read
its values — and restricting it afterwards does not help a secret written there: Windows checks access
when a handle is opened, so one opened before the change goes on reading. The server reads its token
from the `Parameters` subkey, created with its ACL in the same call, and finds that key through
`WINDIAG_SERVICE_NAME`; the service key itself is restricted for its grants. This is what
`--install-service` does (Windows PowerShell 5.1, elevated):

```powershell
$acl = New-Object System.Security.AccessControl.RegistrySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544')
'S-1-5-18', 'S-1-5-32-544' | ForEach-Object {   # SYSTEM, Administrators
  $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule (
    [Security.Principal.SecurityIdentifier]$_), 'FullControl', 'ContainerInherit', 'None', 'Allow')) }
Set-Acl -Path HKLM:\SYSTEM\CurrentControlSet\Services\windiagsvc -AclObject $acl

# Created with the ACL, never given it afterwards. CreateSubKey opens an existing key as it is, so
# check first that there is none.
$service = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\windiagsvc', $true)
if ($service.OpenSubKey('Parameters')) { throw 'Parameters already exists' }
$parameters = $service.CreateSubKey('Parameters', 'ReadWriteSubTree', 'None', $acl)
$parameters.SetValue('WINDIAG_TOKEN', '<paste a long random value>')

New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\windiagsvc `
  -Name Environment -PropertyType MultiString -Force -Value @(
    'WINDIAG_SERVICE_NAME=windiagsvc',
    'WINDIAG_ARTIFACT_DIR=C:\WinDiagArtifacts')
```

A service running as NetworkService or another account also needs a `ReadKey` ACE for that account on
`Parameters`, since it reads the key itself.

Two things change when it runs as a service, both measured rather than assumed:

- **Session 0 is fine.** Procmon captures normally with no interactive desktop — verified on a 32-bit
  and a 64-bit VM and again from a real service (67,423 events). `handle.exe` and the rest are
  unaffected. If you had assumed `capture_activity` needs a desktop, it does not.
- **`%TEMP%` moves** to `C:\Windows\SystemTemp` for SYSTEM, so dumps and traces land somewhere else
  with different ACLs. Pin `WINDIAG_ARTIFACT_DIR` as above rather than discovering that later.

Note `obj= LocalSystem` means the server presents as the **machine account** on the network
(`DOMAIN\HOST$`), which on a domain may carry permissions the interactive account does not. Use a
dedicated account if that matters.

Nothing about the console path changes: `AddWindowsService()` is inert unless the SCM started the
process, and a test asserts it installs no service lifetime when running interactively.

**4. Scope the firewall to your machine** — not to the subnet:

```
netsh advfirewall firewall add rule name="windiag" dir=in action=allow ^
  protocol=TCP localport=7777 remoteip=<your base machine IP>
```

**5. Point Claude Code at it:**

```json
{
  "mcpServers": {
    "windiag-target": {
      "type": "http",
      "url": "http://10.0.0.5:7777/",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```
