# windiag — Windows diagnostics MCP server

Answers live-machine debugging questions that a debugger structurally cannot: who has this file
locked, what is the machine actually doing, why is this access denied, what is set to autostart.

It complements `mcp-windbg`, which owns post-mortem dump analysis. A debugger sees inside one
process; this server sees the machine.

**[Changelog](CHANGELOG.md)** · **[Contributing](CONTRIBUTING.md)** · **[Security](SECURITY.md)** ·
**[Code of conduct](CODE_OF_CONDUCT.md)**

> **Licence:** not yet declared. Until a `LICENSE` file lands, treat this as
> © 2026 Shubham Yadav, all rights reserved — no permission to use, copy or redistribute is granted by its
> presence here.

## Status

**Current release: `v1.3.0`.** Versions before `v1.0.0` were tagged retroactively at the commits
that shipped something; `v1.0.0` is the first release in which every tool could actually be called
from an MCP client. See the [changelog](CHANGELOG.md) for what each one changed.

**The build order is complete.** Twenty tools plus an opt-in twenty-first (`update_self`), both
transports (stdio locally, authenticated Streamable HTTP for running on a target), dump capture,
Procmon-backed activity tracing, the Sysinternals shell-outs, and the process/service control write
tools.

Most are backed by native Windows APIs. Four shell out to Sysinternals — `path_handle_search` and
`process_handles` to `handle`, `capture_activity` to `Procmon`, `autostart_audit` to `autorunsc` —
and `tools/deploy-target.ps1` stages all of them from a pinned manifest.

| Tool | Backing | Answers |
|---|---|---|
| `who_locks_path` | Restart Manager | Who is holding this file or folder open |
| `path_handle_search` | Sysinternals `handle` | Handle search across every process (files by default; all object types on request) |
| `process_handles` | Sysinternals `handle -p` | Everything one process holds open — files, keys, sections, mutants, tokens |
| `autostart_audit` | Sysinternals `autorunsc` | What runs without anybody starting it, and who signed it |
| `system_overview` | Win32 / runtime | What is this machine, and can the server see everything |
| `capabilities` | — | Which tools work here, and why any do not |
| `process_list` | WMI `Win32_Process` | What is running, with parent PID and full command line |
| `process_modules` | `Process.Modules` + PE headers + `WinVerifyTrust` | Which DLL version actually loaded, from where, whether anything unsigned got in, and which modules lost a base-address collision |
| `named_pipes` | `NtQueryDirectoryFile` | IPC pipes, and whether any is at its instance limit |
| `network_owners` | IP Helper | Which process owns which socket |
| `service_config` | SCM + services registry | Configured start type vs actual state, account, dependencies |
| `event_log_tail` | `EventLogReader` | What the machine complained about, filtered |
| `file_signatures` | `WinVerifyTrust` | Is this the binary we shipped |
| `effective_access` | Security descriptors + a real access attempt | Why is this denied |
| `registry_read` | Managed registry API, native view | What a setting is actually set to, in the view you meant |
| `capture_dump` *(writes)* | `MiniDumpWriteDump` | Snapshot a process → hand the path to mcp-windbg |
| `capture_activity` *(writes)* | Sysinternals `Procmon` | Record file and registry activity for a few seconds |
| `query_activity` | streaming read of a capture | Filter that trace down to the operations that failed |
| `process_control` *(writes)* | Win32 process control | Terminate, suspend or resume a process — PID plus expected name, verified before acting |
| `service_control` *(writes)* | SCM | Start, stop or restart a service; refuses a small set of critical ones |
| `update_self` *(writes, opt-in)* | hash-verified binary replacement | Replace this server's own executable and restart it, without touching the target by hand. Finishes the calls already running before it restarts, refusing new ones meanwhile; `force` skips that and cuts them off. It is also the one tool a draining server still accepts, so calling it again with `force` stops the wait |
| `run_command` *(writes, opt-in)* | arbitrary shell (cmd / powershell / direct) | Run any command as the server's account — for git, builds, Klocwork, anything the other tools do not cover |
| `put_file` *(writes)* | hash-verified file write over HTTP | Stage a file on the target without an SMB share — server updates, Sysinternals binaries, inputs; scoped to windiag's own dirs unless arbitrary write is enabled |
| `get_file` | hash-verified sliced file read over HTTP | Pull a file *back* without an SMB share — the dump or trace a capture wrote; same scoping. For anything large, drive it with the relay's [`pull_file`](#moving-files-without-spending-context) or `tools/fetch-from-target.ps1` rather than calling it directly, so the bytes stay out of the caller's context |

## Requirements

| Component | Runs on |
|---|---|
| `WinDiag.Mcp` — the diagnostics server | **Windows only**, x64 or x86. Its tools are Windows primitives: the registry, the SCM, the event log, Authenticode, Sysinternals. |
| `DiagRelay.Mcp` — the local relay | **Windows** and **Linux**: verified end to end against live Windows targets — pre-connect, forwarded calls, and a byte-identical `push_file`/`pull_file` round trip — and the full test suite passes on a real Linux runtime (`tools/test-linux.sh`). **macOS**: built for, **untested** until the CI job has run on a pushed branch. |

The relay is what lets a Mac or Linux machine drive Windows targets. Build it for the machine you are on:

    dotnet publish src/DiagRelay.Mcp -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o artifacts/diagrelay

## Build and test

```
dotnet build -warnaserror
dotnet test tests/WinDiag.Mcp.Tests          # offline; never touches the live machine
dotnet test tests/Diag.Mcp.Server.Tests      # the shared server kit; also runs on Linux
dotnet test tests/DiagRelay.Mcp.Tests        # the relay
dotnet test tests/WinDiag.Mcp.OnTarget       # creates real locks on this machine
```

`WinDiag.Mcp.OnTarget` skips its elevated cases with a stated reason when run unelevated or without
Sysinternals installed, rather than failing or silently passing.

## Run

```
dotnet run --project src/WinDiag.Mcp                      # stdio
dotnet run --project src/WinDiag.Mcp -- --http http://127.0.0.1:7777
dotnet run --project src/DiagRelay.Mcp                   # local relay to any target (see below)
WinDiag.Mcp --help
```

Locally over stdio:

```json
{
  "mcpServers": {
    "windiag": {
      "type": "stdio",
      "command": "D:/Tools/sysinternals_mcp/artifacts/win-x64/WinDiag.Mcp.exe"
    }
  }
}
```

### One stable MCP entry for a fleet of targets — the relay

The targets are lab VMs whose IP changes every time, so a fixed `--http <url>` registration goes stale
on every reboot. The relay solves that. `DiagRelay.Mcp` is its own executable that runs a **local stdio** MCP server on the base machine — no
address of its own, so the registration never changes — that forwards to whichever target you point it
at *at runtime*.

Register it once:

```json
{ "mcpServers": { "windiag": { "type": "stdio",
    "command": "…/artifacts/diagrelay/DiagRelay.Mcp.exe", "args": [] } } }
```

Keep the entry named `windiag`: forwarded tools are named after the registration — `windiag__runner1__capabilities` — not after the executable, so the name is what keeps them stable.

On Linux or macOS the command is the `DiagRelay.Mcp` binary — no `.exe` — from a `-r linux-x64` or `-r osx-arm64` publish. A binary downloaded from a release artifact arrives without its execute bit, so `chmod +x DiagRelay.Mcp` before registering it.

It exposes five control tools — `connect`, `disconnect`, `status`, and the two transfer tools
[`push_file` / `pull_file`](#moving-files-without-spending-context) below. Call `connect` with the target's
current address and token, and that target's full tool set appears here (via a `tools/list_changed`
notification) and every call forwards to it. `connect` again with a different address to repoint — no
config edit, no restart. One registration, any target, IP as runtime data:

```
connect { target: "192.168.32.93", token: "…" }   → 23 tools from that target appear
process_list { … }                                → forwarded to .93
connect { target: "192.168.32.76", token: "…" }    → repointed; now forwards to .76
```

Connect several targets under different aliases (`connect { target, token, as: "w11" }`) to drive a
whole fleet at once — each target's tools are then listed as `w11__process_list`, `w10__system_overview`
and so on, and calls route by that prefix.

**Pre-connecting at launch.** Some MCP clients (Claude Code among them) fix the callable tool set when
they first enumerate the server, so a target you `connect` mid-session isn't picked up until a reload —
and a reload restarts the relay and drops the connection. To make a target's tools available from the
start, list it in `%USERPROFILE%\.windiag-targets.json` and the relay connects it *before* it answers,
putting its `alias__tool` tools in the very first `tools/list`:

```json
{ "targets": [
  { "as": "w11", "target": "192.168.32.93", "token": "…" },
  { "as": "w10", "target": "192.168.32.76", "token": "…" }
] }
```

`as` and `port` are optional (`as` defaults to the host, `port` to 4024). Changing the fleet is an edit
to this file plus a fresh session — the addresses still live in data, never in the MCP registration. A
missing or malformed file just means "pre-connect nothing"; an unreachable target is skipped (within a
5-second total budget so a powered-off VM never stalls startup) with the `connect` line to retry it
logged to stderr.

The file holds bearer tokens in plaintext, so the relay **restricts it to your account** on every write —
inheritance off, SYSTEM and local administrators removed. Because every session runs its own relay
against this one file, reads and writes take a named cross-process lock and each write lands atomically
through a temporary file, keeping the previous contents as `.windiag-targets.json.bak`. That backup is
what a corrupted file is recovered from; an empty one (what a relay killed mid-write leaves behind) is
treated as "no targets" rather than an error, so persistence heals itself instead of wedging.

You rarely edit it by hand: a successful `connect` **writes the target (with its token) into this file**
by default, so the naive fix — reconnect `windiag` or start a fresh session — actually works, because
the relaunch pre-connects what the last `connect` saved. (A plain reconnect *without* that would drop a
runtime connection and surface only the control tools — which is the trap to avoid.) Pass
`persist: false` for a one-off connection you do not want written to disk; `disconnect` is session-only
and never edits the file, so this file stays the durable set.

The relay is a client of the real servers, not a diagnostics server itself — it holds no privileges and
runs unelevated on the base machine.

### Moving files without spending context

`put_file` and `get_file` carry the bytes as tool arguments and results. Driven from an agent session
that is the expensive part: every byte is a token the model has to emit or read, so a 46&#160;MB build is
~63&#160;MB of base64. It does not fit a context window, and chunking only changes how it is split. This
is why `deploy-target.ps1` and `fetch-from-target.ps1` exist — not because MCP could not carry the
transfer, but because the caller could not afford to be on the path.

The relay already runs locally and already holds each target's connection and token, so it can be on
that path instead:

```
push_file { alias: "w11", localPath: "artifacts/win-x64/WinDiag.Mcp.exe",
            remotePath: "C:\\WinDiag\\WinDiag.Mcp.new.exe" }
  → Sent 46,700,000 bytes to w11 in 12 chunk(s). SHA-256 …, verified by the target.

pull_file { alias: "w11", remotePath: "…\\explorer_1904.dmp", localPath: "./dumps/explorer.dmp" }
  → Wrote 777,101 bytes in 1 slice(s). SHA-256 …, verified against the target's hash.
```

The caller sends a path and gets back a summary line; the bytes never enter the conversation. Moving
10&#160;MB in both directions against a lab VM costs about a kilobyte of tool call.

Both verify in flight and end to end, because the failure they guard against is silent. `push_file`
slices into 4&#160;MB chunks, each carrying its own SHA-256, the last carrying the whole-file hash so the
target checks the assembled file and rolls it back on a mismatch; a refused chunk is re-sent on its own
rather than restarting the transfer, and the summary says how many had to be. `pull_file` checks each
slice before appending, writes to a `.partial` name and moves it into place only once the reassembled
copy matches the whole-file hash the target reported — so an interrupted pull cannot leave a short file
under the name you are about to use. It says so explicitly when the target reported no whole-file hash,
because an unverified copy is a different artifact from a verified one.

**These are the first thing the relay does that touches local disk**, so the local side is confined the
way the target side already confines `put_file` and `get_file` — reusing `FileScope`, not a second copy
of it. `WINDIAG_RELAY_FILE_ROOT` is a semicolon-separated list of roots that replaces the default of the
build tree the relay sits in plus the local artifact directory; a `..` is judged by where it lands.

That first default is the directory *above* the relay executable's own, which is what makes
`push_file` work out of the box: the relay ships in `artifacts/diagrelay` and the builds it exists to send
sit beside it in `artifacts/win-x64`. The climb is one level and stops short of a drive root, so a relay
unpacked somewhere odd cannot quietly default to an entire disk. Both defaults resolve against the
running executable, so under `dotnet run` they point into dotnet's install directory — set the variable
when developing.

Use these instead of calling a target's `put_file`/`get_file` yourself for anything but a small file.
`fetch-from-target.ps1` still works and needs no relay, which is what makes it the right tool from a
plain shell; `deploy-target.ps1` still owns publishing, the pinned Sysinternals manifest and the drift
check, so a full deploy is still a script.

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

From a session with the relay connected, [`pull_file`](#moving-files-without-spending-context) does the
same thing as one tool call and needs no token argument, since the relay already holds it. The script
remains the right tool from a plain shell, or when no relay is running.

No flag is needed for anything a capture wrote: the artifact directory is one of windiag's own. Reading
elsewhere needs `WINDIAG_ALLOW_ARBITRARY_READ`. Multi-gigabyte `full` dumps still belong on the UNC
path — the same caveat `put_file` carries in the other direction.

### Reaching the admin share

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
the target already has the .NET 9 runtime. Trimming is *not* used: the MCP SDK discovers tools by
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
256-bit token and stores it where only SYSTEM and Administrators can read it, opens the port to one
address, and starts it. The token is printed once, because it exists nowhere else a human can read.

```
WinDiag.Mcp.exe --service-status      # by hand, or as a service? and configured how?
WinDiag.Mcp.exe --uninstall-service   # removes the service, its token and its firewall rule
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
| `--token <value>` | Default: a new 256-bit token, printed once. Must match what the relay's targets file holds for this machine, or the alias connects and then 401s every call |
| `--artifacts <dir>` | Pins `WINDIAG_ARTIFACT_DIR`. As SYSTEM `%TEMP%` is `C:\Windows\SystemTemp`, so captures and dumps move somewhere surprising without it |
| `--allow-self-update` | Registers `update_self` |
| `--allow-command-execution` | Registers `run_command` |
| `--allow-arbitrary-write` | Lets `put_file` write outside the server's own directories |
| `--allow-arbitrary-read` | Lets the read tools open files outside them |
| `--read-only` | Drops every state-changing tool |
| `--firewall-from <address>` | Opens the bind port inbound from one address, removed on uninstall. An address, never a subnet |
| `--no-restart-on-failure` | Default is to let the SCM restart it if the process dies |

**Flags and environment variables are two spellings of one setting.** Each grant flag becomes its
`WINDIAG_*` variable (see [Configuration](#configuration)) in the service's own registry key —
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
| `None` | `--read-only` alone | Services and processes only. **Cannot read a single config file** — if you want read-only-but-readable, do not use this; pass `--read-only --allow-arbitrary-read` yourself |
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

Adding a target to the relay's `~/.windiag-targets.json` does **not** deploy or start anything; it
only tells the relay where to connect to a server that is already listening. **Prefer hostnames over
addresses in that file** for the same reason as the bind: a DHCP lease that moves breaks every entry
pinned to an address.

Doing it by hand instead is a few more commands, and three details are easy to lose — the token's
location, the artifact directory, and the grants:

```
sc create windiagsvc binPath= "\"C:\WinDiag\WinDiag.Mcp.exe\" --http http://10.0.0.5:7777" ^
   start= auto obj= LocalSystem DisplayName= "windiag"
```

**Put the token in the service's own environment, not a machine-wide variable.** A service has no
console to inherit `WINDIAG_TOKEN` from, and the obvious fix is the wrong one: machine environment
variables are readable by *every local user*, and with `run_command` or `update_self` enabled that
token is code execution as SYSTEM. The per-service key is ACL'd to SYSTEM and Administrators:

```powershell
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\windiagsvc `
  -Name Environment -PropertyType MultiString -Force -Value @(
    'WINDIAG_TOKEN=<paste a long random value>',
    'WINDIAG_ARTIFACT_DIR=C:\WinDiagArtifacts')
```

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

## Security

The threat model is **not only the network**. The server runs elevated, so any local unprivileged user
on the target can reach the port; with the token they get command execution at the server's privilege
level through an ordinary tool call. The token is the whole boundary.

- **A bearer token is always required in HTTP mode.** There is no unauthenticated path — if none is
  configured, one is generated rather than the check being skipped. Comparison is fixed-time.
- **The channel is not encrypted, so the boundary travels in cleartext.** windiag serves plaintext
  HTTP; there is no TLS support. Every request carries the bearer token in an `Authorization` header,
  and every response carries whatever the tool returned — file contents, memory dumps, registry
  values, `run_command` output. Anyone able to observe traffic on the segment captures the token, and
  the token is the whole boundary. SHA-256 chunk hashing on file transfers is **integrity, not
  confidentiality**: it catches a truncated copy, and an active on-path attacker simply recomputes it.
  The firewall rule scopes who can *reach* the port, not who can *watch* it. So deploy this on a
  management segment you already trust, and do not route it across one you do not. If you need
  confidentiality on the wire today, tunnel it — WireGuard, SSH, an mTLS proxy — rather than assuming
  the port being scoped is enough.
- **The token is never accepted as a command-line argument.** This server's own `process_list` shows
  command lines to every local user, so a `--token` switch would publish the credential to precisely
  the audience it excludes. Environment variable only.
- **There is no default bind address.** `--http` with no address and no `WINDIAG_HTTP_BIND` is a
  startup failure, not a guess.
- **A hostname is a wildcard bind, and is warned about as one.** Kestrel's binder falls back to
  "any IP" for any host that is not an IP literal and is not `localhost` — so
  `--http http://target-vm:7777` listens on `0.0.0.0` while looking specific. Verified: that address
  produces `Now listening on: http://[::]:47901`. Use an IP literal to bind one interface.
- **A configured token is never echoed.** Only a *generated* token is printed, because that one is
  ephemeral and you need to read it once. A `WINDIAG_TOKEN` value is long-lived, and running an
  elevated listener under a service wrapper with `2> windiag.log` is the normal deployment — so that
  log would otherwise hold a standing credential. `WinDiagOptions` is a record whose `ToString` is
  overridden for the same reason: the generated one would print every property, token included.
- `WINDIAG_READ_ONLY=1` drops state-changing tools from registration entirely, so they are never
  advertised.
- **Tool *results* are untrusted input to whatever agent is driving.** `run_command` output, process
  command lines, registry values, event-log messages and any file content the tools surface are data
  the target controls — a compromised or hostile target can return text crafted to steer the model into
  further calls. The server's own tool *descriptions* are injection-free, but the boundary it cannot
  enforce is on the reading side: treat returned content as data, never as instructions, and keep the
  destructive grants (`WINDIAG_ALLOW_COMMAND_EXECUTION`, `update_self`) off unless a run needs them.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WINDIAG_READ_ONLY` | `false` | `1`/`true` drops all state-changing tools from registration |
| `WINDIAG_ALLOW_SELF_UPDATE` | `false` | `1`/`true` registers `update_self`. Gated separately because it lets the bearer token replace an elevated binary; `WINDIAG_READ_ONLY` still overrides it |
| `WINDIAG_ALLOW_COMMAND_EXECUTION` | `false` | `1`/`true` registers `run_command`, turning the bearer token into an arbitrary shell as the server's account. The heaviest grant here; `WINDIAG_READ_ONLY` overrides it. Off unless a deployment deliberately needs it |
| `WINDIAG_ALLOW_ARBITRARY_WRITE` | `false` | `1`/`true` lets `put_file` write outside the server's own directories. `put_file` itself is always available on a writable server, scoped to those dirs; this widens it to anywhere as the server's account. `WINDIAG_READ_ONLY` overrides it |
| `WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS` | `120` | Budget per external tool call (1–3600) |
| `WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS` | `1800` | How long `update_self` waits for running tool calls to finish before restarting anyway (1–86400). A backstop, not a schedule: on an idle target the wait is milliseconds. 30 minutes clears `capture_activity`'s ~21-minute worst case, which is the call most likely to be running when you update. A full-length `run_command` can exceed it — raise this, or pass `force` |
| `WINDIAG_ALLOW_ARBITRARY_READ` | `false` | `1`/`true` lets `get_file` read *outside* windiag's own directories. It always reads inside them — which includes the artifact directory, so retrieving a dump or a trace needs no flag. This widens it to anything the elevated account can open, i.e. exfiltration, so it is off by default. Unlike the write grant, `WINDIAG_READ_ONLY` does **not** override it — reading is what a read-only server is for |
| `WINDIAG_MAX_RESULTS` | `50000` | Row cap per tool call (1–10000000). High so handle-heavy tools aren't truncated; lower it if one call's output is too large for your client. |
| `WINDIAG_HTTP_BIND` | — | Address to serve on; equivalent to `--http` |
| `WINDIAG_TOKEN` | generated | Bearer token for HTTP mode |
| `WINDIAG_ARTIFACT_DIR` | `%TEMP%\windiag` | Where dumps and traces are written |
| `WINDIAG_RELAY_FILE_ROOT` | the directory *above* the relay executable's, plus a per-user `windiag` folder: `%TEMP%\windiag` on Windows, `$XDG_CACHE_HOME/windiag` or `~/.cache/windiag` elsewhere — never the shared `/tmp` | **Relay only.** Semicolon-separated local directories `push_file` may read from and `pull_file` may write to, *replacing* the defaults rather than adding to them. This is the boundary that stops one tool call copying an arbitrary local file onto a target, so widen it deliberately. The first default is one level up because the relay ships in `artifacts/diagrelay` while the builds it sends sit beside it in `artifacts/win-x64`; the climb stops short of handing out a whole drive. Both resolve against the running executable, so under `dotnet run` they point into dotnet's install directory — set this when developing |

Booleans are strict: `1/true/yes/on` or `0/false/no/off`. A misspelling fails startup rather than
silently defaulting, because the flag removes capability.

Diagnostics go to **stderr only**. stdout carries the MCP protocol and nothing else; a test asserts it.

## Behaviour worth knowing

**`who_locks_path` is fast and unelevated, but not exhaustive.** Restart Manager was built so
installers could avoid reboots, and reports only processes it could restart. It misses many services,
kernel-held references and memory-mapped sections. An empty result therefore renders as *"this is NOT
proof that nothing holds it"* and points at `path_handle_search`. Do not "simplify" that wording — a
bare "no holders found" ends investigations that should continue.

**`path_handle_search` needs administrator rights.** Unelevated, `handle.exe` returns a *shorter list*
rather than an error, which is indistinguishable from a complete list. The tool leads with an explicit
partial-results warning when it is not elevated.

**`handle.exe`'s CSV header does not describe its own rows.** Verified against Sysinternals Suite
2026.6.0.0:

```
header: Process,PID,User,Handle,Type,Share Flags,Name,Access      (8 columns)
row   : explorer.exe,3628,File,CONTOSO\user,0x0000068C,C:\Windows\Fonts\StaticCache.dat   (6 fields)
```

Real row order is `Process, PID, Type, User, Handle, Name`; share flags and access are never emitted.
The parser therefore reads **by position**, and `HandleCsvParserTests` asserts that. Mapping by header
name — the obvious defensive choice — silently attributes every field to the wrong column.

Worse, the row layout depends on *how handle.exe was invoked*, not just on its flags: process-scoped
(`-p`) invocation emits a 7-column header and 7-field rows that **do** follow header order. Those rows
have enough fields to satisfy positional parsing, so they would be accepted and mis-attributed. The
parser therefore validates the header shape and throws on anything it was not written for. If you add
a new invocation mode, add its layout explicitly — do not relax that check.

**`path_handle_search` searches file references only unless you ask for more.** handle.exe without
`-a` "will dump all file references" and nothing else — no registry keys, no mutants, no events.
"File references" is broader than `File` handles though, and the row counts say so: measured on a
single process, 380 rows and **2 object types** without `-a`, those two being `File` and `Section`.
A section backing a file *is* a reference to it, so a holder that only memory-mapped the file is
already covered by the default — which matters, because a mapped section is exactly the holder
`who_locks_path` cannot see. With `-a`: 12007 rows and 25 types, including 3218 registry `Key` rows.

`-a` is nonetheless **opt-in**, via `includeAllObjectTypes`, because it is drastically more expensive:
a machine-wide `-a` search on an ordinary workstation had emitted 223 rows — every one of them still
a `File` — after **6m40s**, against a 120s budget. Always-on would mean the tool reliably times out
instead of reliably answering. So:

- file-lock follow-up from `who_locks_path` → leave it off (fast, and files are what you want)
- "who is touching this registry key" → set it, and keep the search term narrow

An empty file-only result says so explicitly and points at the flag, so "no handles matched" can never
send you away from a registry key that was simply never examined.
`Exhaustive_search_covers_registry_keys_not_just_files` (on-target, elevated) is the only test that
catches the flag being dropped.

**Child output is decoded as ANSI, not OEM.** Measured by hex-dumping handle.exe's raw pipe bytes for
a path containing `é`/`ï`: they arrive as `0xE9`/`0xEF`, which is CP1252. Decoding as the OEM code page
(CP437) would render those as `Θ`/`∩` — a path that does not exist on disk, which the model would then
report and act on.

**`file_signatures` uses `WinVerifyTrust`, not the embedded certificate.** Most of `System32` is signed
by *catalog* and carries no certificate inside the file, so the obvious
`X509Certificate.CreateFromSignedFile` approach reports half of Windows as unsigned. Catalog-signed
files are labelled as such in the output.

**`effective_access` attempts the access as well as reading the ACL.** Share modes, integrity levels,
filter drivers and privileges all change the outcome without appearing in any ACE, so an ACL-only
answer and reality routinely disagree. The empirical result leads; the ACL explains it. The tool also
states plainly that it does not resolve group-granted rights, rather than implying a full
effective-rights calculation it does not perform.

**`event_log_tail` cannot clear a log.** `psloglist -c` wipes the event log and is one character from
the harmless `-s`; using `EventLogReader` means that verb does not exist here at all. Caller-supplied
provider names are validated before reaching the XPath filter, for the same reason argv values are
validated before reaching a command line.

**`capture_dump` returns a UNC path so nobody copies gigabytes.** The dump is written on the target, and
the result includes the same file addressed through the machine's administrative share. `cdb` opens a UNC
path directly, so it feeds straight into mcp-windbg's `open_windbg_dump` from the base machine. Measured
on this box: a mini dump of a .NET test host was 1.7 MB, a full dump of the same process 166 MB — hence
`mini` being the default, and hence this tool being excluded under `WINDIAG_READ_ONLY`.

**Activity tracing wraps Procmon, and every constant in it was measured, not read.** A spike on a 32-bit
Windows 10 VM with Procmon 4.05 settled five things the documentation does not:

- **`/Runtime` self-terminates**, but a 20s capture takes 25–26s wall — driver load and flush. The
  timeout budget is duration + 90s; a tight margin kills healthy captures.
- **`/SaveAs` requires `/OpenLog`**, so capture and export are two separate processes. And `/Terminate`
  is standalone ("terminate all instances and exit"), *not* "stop after `/Runtime`" — putting it on the
  capture command line captures nothing.
- **Procmon preallocates the trace file.** It sat at exactly 134,217,728 bytes mid-capture and *shrank*
  to 106,525,338 on close. So the health check asks whether the file **appears**, never whether it
  grows — a growth check reports every healthy capture as stalled.
- **`FAST IO DISALLOWED` is routine, not a failure** (6 of 40 rows in the committed fixture), as are
  `END OF FILE` and `FILE LOCKED WITH WRITERS`. `problemsOnly` matches an explicit set — `ACCESS
  DENIED`, `NAME NOT FOUND`, `PATH NOT FOUND`, `SHARING VIOLATION` and friends — rather than "anything
  that isn't SUCCESS", which would bury the results that explain a bug.
- **The CSV carries a UTF-8 BOM**, and its columns follow the machine's Procmon configuration. The
  parser reads **by header name** — the opposite of the `handle.exe` rule, because Procmon's header
  genuinely describes its own rows — so an unexpected column set loses a field rather than
  mis-attributing every field.

Two consequences worth knowing before you run it. Procmon's downloadable zip ships `Procmon.exe` as a
**32-bit launcher** that starts `Procmon64.exe` and exits immediately; driving that on x64 would look
like an instant capture over a trace still being written, so the PE header is checked and the launcher
refused. And a capture **writes** `Columns`, `ColumnMap` and `FilterRules` into `HKCU` for the account
the server runs as, even where none existed — harmless on a target, but a real change to that profile.

`capture_activity` returns paths and a summary, never events; a 20-second unfiltered trace measured
110 MB of `.pml` and 65 MB of `.csv`. `query_activity` streams that file, and its aggregate counts cover
**every** match while only the returned event list is capped — otherwise "busiest paths" would quietly
mean "busiest paths among the first hundred". The `.pml` opens unchanged in the Procmon GUI, which is
where a human continues.

**`file_signatures` checks catalogs, not just embedded signatures — and that needs two things.**
`WTD_CHOICE_FILE` only ever examines a signature inside the file. Most of Windows is signed by
*catalog*: on this machine, 38 of 60 sampled System32 binaries have no embedded signature at all. A
file-only check reports every one of them as unsigned — the worst possible failure for a tool whose
job is "is this the binary we shipped".

So the tool falls back to `CryptCATAdminEnumCatalogFromHash` plus a catalog-mode verify. The trap
there: **`WINTRUST_CATALOG_INFO.hCatAdmin` must carry the catalog admin context.** Measured against a
SHA-256 catalog context:

```
hCatAdmin = 0            -> 0x800B0100 TRUST_E_NOSIGNATURE
hCatAdmin = adminContext -> 0x00000000 S_OK
```

A SHA-1 context succeeds without it, which is precisely why the omission survives casual testing.
`Reports_catalog_signing_consistently_across_a_sample_of_system_binaries` asserts that a System32
sample yields both attribution paths and *no* unsigned files, so either half breaking fails the suite.

Relatedly, reading the signer certificate uses `X509Certificate2Collection.Import`, not
`X509CertificateLoader` — the latter rejects Authenticode content and throws for every signed binary —
and picks the leaf out of the returned chain rather than `collection[0]`, which is an intermediate CA.

**Caller values are never allowed to look like switches.** Arguments are passed as a vector, and any
caller-supplied value beginning with `-` or `/` is refused before the process starts. Passing a vector
alone is not enough: the target binary's own parser would read `-c` as handle.exe's destructive
close-handle switch. See `ExternalToolRunnerGuardTests`.

## Layout

```
src/WinDiag.Mcp/
  Program.cs            entry: argv dispatch, logging pinned to stderr
  ServerBuilder.cs      DI wiring and tool registration (shared with tests)
  Configuration/        WINDIAG_* parsing, fail-fast validation
  Diagnostics/          all real work, each domain behind an interface
    Locks/              Restart Manager interop
    Handles/            handle.exe shell-out and its parser
    External/           runner, tool locator, the flag-injection guard
  Tools/                MCP tool definitions: schema and rendering only
```

`Tools/` contains no logic — it binds parameters, calls a `Diagnostics/` interface and renders. That
split is what lets the tool layer be tested with fakes and no live machine.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `'handle.exe' was not found on this machine` | Sysinternals Suite is not installed. Native-backed tools still work. |
| `path_handle_search` warns about partial results | Not elevated. Restart the server from an elevated terminal. |
| `who_locks_path` finds nothing on a file you know is locked | Expected: Restart Manager is not exhaustive. Run `path_handle_search`. |
| `handle.exe did not finish within 120s` | Search term too broad. Narrow it, or raise `WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS`. |
| `handle.exe produced a CSV layout this parser was not written for` | An invocation change altered the row shape. See the layout note below — do not "fix" it by loosening the parser. |
| `configuration error` on startup | A `WINDIAG_*` value is malformed; the message names the variable. |
