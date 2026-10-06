# sysdiag — live-machine diagnostics MCP servers for Windows, Linux and macOS

Answers live-machine debugging questions that a debugger structurally cannot: who has this file
locked, what is the machine actually doing, why is this access denied, what is set to autostart.

It complements `mcp-windbg`, which owns post-mortem dump analysis. A debugger sees inside one
process; this server sees the machine.

sysdiag is a set of servers: **WinDiag** (`WinDiag.Mcp`, Windows), **LinuxDiag** and **MacDiag**,
which serve much the same tool set on Linux and macOS (each one's section lists its tools), and **DiagRelay**, a local relay that puts any number
of them behind one MCP registration. Most of this README is about WinDiag, the Windows server; see
[Linux targets](#linux-targets) and [macOS targets](#macos-targets) for the others.

**[Changelog](CHANGELOG.md)** · **[Contributing](CONTRIBUTING.md)** · **[Security](SECURITY.md)** ·
**[Code of conduct](CODE_OF_CONDUCT.md)**

> **Licence:** [MIT](LICENSE).

## Quick start

Download the zip for each machine from the [latest release](https://github.com/shubhamyadav8901/sysdiag-mcp/releases/latest):
`windiag-win-x64` or `windiag-win-x86`, `linuxdiag-linux-x64`, `macdiag-osx-arm64` or `macdiag-osx-x64`, and `diagrelay-<platform>` for the
relay. Each carries a `SHA256.txt`. Every binary is self-contained, so no .NET install is needed.

To diagnose the machine you are on, register its server with Claude Code over stdio:

```
claude mcp add windiag -- C:/Tools/sysdiag/WinDiag.Mcp.exe      # Windows
claude mcp add linuxdiag -- /opt/sysdiag/LinuxDiag.Mcp          # Linux, x86-64
claude mcp add macdiag -- /usr/local/sysdiag/MacDiag.Mcp        # macOS
```

On a Mac, if Gatekeeper blocks a binary downloaded in a browser, clear its quarantine flag:
`xattr -d com.apple.quarantine MacDiag.Mcp`. Run
unelevated, the servers answer for what the current account can see, and `capabilities` names what is
missing.

To drive other machines, install the server on each one as a service, with HTTP and a bearer token, and
register the relay locally. See [Deploying to a target machine](#deploying-to-a-target-machine) and
[the relay](#one-stable-mcp-entry-for-a-fleet-of-targets--the-relay). That channel is plaintext HTTP: keep
it on a network you trust, or tunnel it.

## Status

**Current release: `v3.0.0`.** Versions before `v1.0.0` were tagged retroactively at the commits
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
| `named_pipes` | `NtQueryDirectoryFile` + `WaitNamedPipe` | IPC pipes, and whether any has every instance taken and none listening for a client |
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
| `DiagRelay.Mcp` — the local relay | **Windows** and **Linux**: verified end to end against live Windows targets — pre-connect, forwarded calls, and a byte-identical `push_file`/`pull_file` round trip — and the full test suite passes on a real Linux runtime (`tools/test-linux.sh`). **macOS**: its test suite runs on Apple Silicon in CI's `macos-latest` job. |

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
      "command": "D:/Tools/sysdiag-mcp/artifacts/win-x64/WinDiag.Mcp.exe"
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
{ "mcpServers": { "sysdiag": { "type": "stdio",
    "command": "…/artifacts/diagrelay/DiagRelay.Mcp.exe", "args": [] } } }
```

Keep the entry named `sysdiag`: forwarded tools are named after the registration — `sysdiag__runner1__capabilities` — not after the executable, so the name is what keeps them stable.

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
start, list it in `%USERPROFILE%\.sysdiag-targets.json` and the relay connects it *before* it answers,
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
through a temporary file, keeping the previous contents as `.sysdiag-targets.json.bak`. That backup is
what a corrupted file is recovered from; an empty one (what a relay killed mid-write leaves behind) is
treated as "no targets" rather than an error, so persistence heals itself instead of wedging.

You rarely edit it by hand: a successful `connect` **writes the target (with its token) into this file**
by default, so the naive fix — reconnect `sysdiag` or start a fresh session — actually works, because
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
of it. `SYSDIAG_RELAY_FILE_ROOT` is a semicolon-separated list of roots that replaces the default of the
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

### Linux targets

`LinuxDiag.Mcp` is the Linux server: Ubuntu and Debian, **x86-64 only**. It is reached through the same
relay, with the same bearer token model and the same plaintext-HTTP caveat as windiag. It serves
`capabilities`, `put_file`, `get_file`, `system_overview`, `run_command` (`sh`, `bash`, `none`),
`update_self`, and the process, open-file and container tools below; the systemd and host-configuration
tools follow.

#### Processes, open files and containers

| Tool | Answers from | Notes |
|---|---|---|
| `process_list` | `/proc/<pid>/{stat,status,cmdline,cgroup}` | Each process's container (runtime, id, name, image) and its PID inside it |
| `container_list` | Docker Engine API on `/var/run/docker.sock`; containerd task state in `/run/containerd` | Main PID as the host numbers it; Kubernetes pod and namespace from CRI annotations |
| `process_modules` | `/proc/<pid>/maps` | Flags a library deleted or replaced on disk since it was mapped - a stale library after an upgrade |
| `process_handles` | `/proc/<pid>/fd`, `fdinfo`, `maps` | Files, sockets, pipes and anonymous inodes, each with its access mode |
| `path_handle_search` | every `/proc/<pid>/fd` and `maps` | A full path also matches the same file by device and inode: a hard link, a rename, a container's own path |
| `who_locks_path` | `statx` identity, `fdinfo` `lock:` lines, `/proc/locks` | flock, POSIX, OFD locks and leases, waiters included; `Exhaustive` only as root |
| `network_owners` | `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` per network namespace | Every owner of a shared socket; container sockets included |
| `named_pipes` | `/proc/<pid>/net/unix` per network namespace, FIFOs among open files | Named and abstract (`@`) unix sockets, listening state, holders |
| `process_control` | `pidfd_open` + `pidfd_send_signal` | Writable servers only. `terminate` is SIGTERM plus a 10 s wait; `kill` is SIGKILL. The name you pass must match exactly (case-sensitive; a path compared whole). PID 1, kernel threads, zombies, this server, and the daemons a machine needs (journald, logind, udevd, dbus, networking, resolver, polkit, sshd, VPN daemons) are refused for everything but `resume` |

Every tool here reads another user's processes only as root; run unprivileged, each says its answer is
partial instead of presenting it as complete. The Docker socket is asked one fixed read-only question,
`GET /containers/json`, within 5 seconds - a hung daemon never hangs a tool. `process_control` needs Linux
5.3 or later for its pidfd; on an older kernel (RHEL 8 ships 4.18) it refuses with that explanation rather
than risk signalling a reused PID. `process_handles`, `path_handle_search`, `who_locks_path` and `named_pipes` need glibc 2.28
or later, which every distribution .NET 9 supports has.

#### Services, logs and host configuration

| Tool | Answers from | Notes |
|---|---|---|
| `service_config` | `systemctl show` | Unit file, drop-ins, main PID, restart count, result, dependencies both ways; a close name is offered when the unit does not exist |
| `service_control` | `systemctl start/stop/restart` | Writable server only. Services only, never a pattern. Stopping or restarting a unit the machine needs (journald, logind, udevd, networking, resolver, dbus, polkit, SSH, VPN tunnels such as `tailscaled` and `wg-quick@`), this server's own unit (use `update_self`), or a unit whose stop would take one of those down is refused; starting them is allowed. A service that powers off, reboots or suspends the machine is refused for every action. Waits at most 75 s, then reports "still running" |
| `event_log_tail` | `journalctl -o json` | `unit`, `minutes`, `levels`, `provider` (the syslog identifier), `match` (`FIELD=value`), `maxEvents` |
| `file_signatures` | SHA-256; dpkg's lists, md5sums, status and diversions | Valid, Modified, ConfigurationChanged, Unpackaged or Unknown against the dpkg database - integrity, not provenance |
| `autostart_audit` | enabled units, users' units, systemd generators, cron, rc.local, profile.d, ld.so.preload | `unpackagedOnly` checks the unit, its drop-ins, the program and an interpreter's script against their packages |
| `effective_access` | statx, ACL and capability xattrs, mountinfo, `faccessat` | For an `account` or a `processId`: each right with the rule that decides, and the first directory it cannot search |

These tools run `systemctl` and `journalctl` from the system directories only, with a fixed `PATH`, `LC_ALL=C.UTF-8` and no pager, and never pass a caller's value where it could be read as an option. A host without dpkg (a non-Debian distribution) still gets SHA-256 from `file_signatures`, and `capabilities` reports it Degraded, naming the missing database.

Publish it, then install it over SSH:

```
dotnet publish src/LinuxDiag.Mcp -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o artifacts/linux-x64
.\tools\bootstrap-linux.ps1 -Target build-01 -User ops -Grants Standard
```

(`tools/bootstrap-linux.sh` is the same for a Linux or macOS operator; it is the one verified against a
live host so far -- the `.ps1` has not yet been run end to end.) A token given with `-Token` is sent
over the SSH connection's standard input into a `0600` file that the install reads with `--token-stdin`
and then removes, so it never appears on a command line. The removal, of the token and the copied
binary alike, is a trap on the install session, so it also runs when the install fails, the hash check
fails, or the session is cut off; if the connection itself fails the script tries once more from a
fresh session and warns when it cannot. (That cleanup has been exercised against a local `dash`, not yet
a live host.) Leave `-Token` out and the installer generates
one and prints it once. The script copies the binary into
the SSH user's home directory -- not the shared `/tmp`, where another account could swap it -- checks its
hash there, and runs `sudo LinuxDiag.Mcp --install-service`. `-Grants` takes the same presets as
`bootstrap-target.ps1`. That installs:

| Path | What |
|---|---|
| `/opt/linuxdiag/LinuxDiag.Mcp` | the binary |
| `/etc/linuxdiag/linuxdiag.env` | root-owned `0600`: the token, bind address and grants |
| `/var/lib/linuxdiag` | `0700`: the artifact directory |
| `/etc/systemd/system/linuxdiag.service` | `Type=notify`, `Restart=on-failure` |

The unit is deliberately **not** sandboxed (no `ProtectSystem` and similar): a diagnostics server has to
see every process's `/proc`, and a sandbox would silently hide exactly what it is asked about.
`--uninstall-service` and `--service-status` do what they say; `LinuxDiag.Mcp --help` lists every switch.

Add it to the relay's `~/.sysdiag-targets.json` like any target:

```json
{ "as": "build-01", "target": "build-01", "token": "…" }
```

Later builds go through `push_file` to `/opt/linuxdiag/LinuxDiag.Mcp.new` and `update_self`, so both
need the self-update grant (`--allow-self-update`, `LINUXDIAG_ALLOW_SELF_UPDATE=1`). Unlike windiag,
`put_file` does not write into the server's own directory without it: that directory holds a root
service's binary, and staging a build is the only reason to write there. The artifact directory stays
writable either way -- unless it is placed inside the server's own directory, which gets no exemption:
everything under `/opt/linuxdiag`, the `netcoredeps` folder the binary loads libraries from included,
needs the grant. Arbitrary write lifts the restriction too. A path is judged where the write
really lands: links among its parent directories are followed, but a link as the final name is replaced
where it sits rather than written through, so `put_file /tmp/x` is a write to `/tmp` even when
`/tmp/x` links into `/var/lib/linuxdiag`. A path through any link on procfs -- `/proc/<pid>/root`,
`cwd`, `fd/N`, and `/proc/self` or `/dev/fd` on the way there -- is never owned and needs the
arbitrary grant: the kernel does not follow those links by the name `readlink` prints, so where the
bytes land cannot be judged. The staged
file must be an x86-64 Linux executable. The swap runs from a helper started with `systemd-run`, because
a child of the service would be killed along with it before it could swap anything.

### macOS targets

`MacDiag.Mcp` is the macOS server: macOS 13 or later, Apple Silicon (`osx-arm64`) and Intel (`osx-x64`).
It is reached through the same relay, with the same bearer token model and the same plaintext-HTTP caveat.

It is built and unit-tested on Windows and Linux. CI's `macos-latest` job runs its Mac-only tests,
captures real command output for its parsers, and smoke-installs it: install, a `put_file`/`get_file`
round trip, `service_control`, `update_self` and uninstall. It has also run on an interactive Mac (macOS
26.6.2, Apple Silicon): the full test suite, every read-only tool over stdio, and the launchd install
over HTTP, with `put_file`/`get_file` and `update_self`. The parsers are tested against output written from Apple's documentation
(`tests/MacDiag.Mcp.Tests/Fixtures/macos-unverified`) until `tools/capture-macos-fixtures.sh` has run on a Mac.

It serves:

| Tool | Answers from | Notes |
|---|---|---|
| `system_overview` | `sw_vers`, `sysctl -n hw.model hw.memsize kern.osrelease kern.boottime`, `vm_stat`, `mount`, each volume's size | Each APFS container once, by its writable volume, because its volumes share free space; the sealed system volume is never flagged full. Anything that could not be read, or that came back in a shape it does not recognise, is listed as a warning, so a 0 is never mistaken for a real value. The page size is never guessed |
| `run_command` | `/bin/zsh -c` (default), `/bin/sh -c`, `/bin/bash -c` (bash 3.2), or a direct exec | Only with `--allow-command-execution`, never on a read-only server |
| `capabilities`, `put_file`, `get_file` | the shared kit | As on every server |
| `process_list` | `ps -axww` (pid, ppid, uid, rss, stat, lstart, args) joined by PID with `ps -axww -o pid,comm` | Command lines are decoded from ps's vis escaping; a process that exits between the two calls keeps no path rather than another's. Containers run in a VM, so their processes are not listed |
| `process_handles`, `process_modules` | `lsof -p` (field output, NUL-terminated, so a name cannot forge a record) | Files, sockets, pipes and kqueues with their access mode. System libraries live in the dyld shared cache and are not listed one by one |
| `path_handle_search` | a full `lsof -b` listing, matched under every spelling of each name; for a full path, also `lsof -f --` by device and inode | Finds `/tmp/...` though lsof says `/private/tmp/...`, and `/Users/...` though it says `/System/Volumes/Data/Users/...`; a directory finds what is open beneath it; a hard link is found by identity |
| `who_locks_path` | `lsof -f -- <path>` | Darwin's lsof does not report lock state, so it lists who has the path open (reading, writing, running it, mapping it, or as a working directory), never who locks it. A mount point is answered as that directory |
| `network_owners` | `lsof -i -Ts`, joined by each socket's kernel address | Every owner of a shared listener; an IPv4 and an IPv6 listener on one port stay separate |
| `named_pipes` | unix sockets and FIFOs from a full lsof listing | Darwin's lsof does not report whether a unix socket is listening, so `listening` is always null |
| `update_self` | a Mach-O check (thin or universal, the slice this Mac runs, `codesign --verify` for arm64), then a detached helper that swaps the binary and runs `launchctl kickstart -k` | Only with `--allow-self-update`. Any failure before the swap starts the old build again; a new build that does not come up within 30 s (new PID, matching hash, port answering) is rolled back. It has run on a Mac, in CI's macOS smoke and on an interactive one |
| `service_config` | the job's plist (`plutil -convert xml1 -o -`) for configuration; `launchctl print` for runtime state, top-level keys only | Takes the label (`com.openssh.sshd` is Remote Login). A plist named otherwise than its label is found by the `Label` inside it. A LaunchAgent is read in the console user's `gui/<uid>` domain |
| `service_control` | `launchctl kickstart`/`bootstrap` (start), `bootout` (stop), `kickstart -k` (restart), system domain only | Writable server only. stop unloads the job until it is started again or the Mac restarts. Refused for stop and restart: Apple's jobs (`com.apple.*`, Remote Login among them), remote-access and VPN agents (Tailscale, WireGuard, OpenVPN, ZeroTier, Cisco, GlobalProtect, Fortinet, TeamViewer, Jamf), `MACDIAG_PROTECTED_LABELS`, and this server's own job. A disabled job is not started; the refusal says how to enable it |
| `process_control` | `/bin/kill` after a `ps` name and start-time check, checked again just before the signal | Writable server only. macOS has no pidfd: a window of milliseconds remains between the last check and the signal, and every result says so. Refused for everything but resume: PID 1, the kernel, loginwindow, WindowServer, logd, opendirectoryd, sshd and screen sharing, this server, zombies, and the main process of any job `service_control` protects, including a user's own remote-access or VPN agent, found in that user's launchd domain (`launchctl asuser <uid> sudo -n -u #<uid> launchctl list`) and refused fail-closed if that list cannot be read, is empty, or is the system list again. **That lookup has not yet run on a Mac**; CI's capture checks it. Suspending a direct child of this server is refused: macOS reports a stopped child to .NET's exit watcher, which then spins and hangs the whole server. Apple's per-user agents (Finder, Dock) may be restarted |
| `event_log_tail` | `log show --style ndjson`, walked backwards in time windows | Defaults to critical (fault) and error: macOS's `default` type, which `warning` maps to, is most of all logging. Looks back at most 7 days. A window too large to read in full is reported as not reached, never as the newest events. `<private>` redaction is the system's |
| `container_list` | Docker Engine API (`GET /containers/json?all=1`, nothing else) on `/var/run/docker.sock` and each user's Docker Desktop, Colima, OrbStack or Rancher Desktop socket | A socket is asked only when it is a socket, owned by its home directory's owner (root for the system socket), in directories no other account can change; anything else is refused and named. A link into a home is asked under its target's path. Containers run in a VM, so there are no host PIDs. Each engine gets 5 s and at most 8 MiB of answer |
| `file_signatures` | SHA-256 from `shasum` (a child process, so a file swapped for a FIFO cannot hang the server); `codesign --verify --strict`, `-R 'anchor apple'` and `-dvvv`; `spctl --assess -v` for a file inside an `.app`; `pkgutil --file-info` | At most 200 paths and 120 s per call. "Signed by Apple" means codesign's `anchor apple` requirement holds, which only Apple's own signing satisfies; it is never inferred from a certificate's name, which any signer can choose. Developer ID and App Store chains also end in Apple Root CA, and are reported by their leaf. A valid signature is provenance, not a verdict on the signer |
| `autostart_audit` | launchd plists (`/Library` and `/System` daemons and agents, every user's agents) via `plutil`, `/etc/crontab` and users' crontabs, `/etc/periodic` and `/usr/local/etc/periodic`, loginwindow hooks, SecurityAgent plugins, `systemextensionsctl list`, `kmutil showloaded`, `sfltool dumpbtm` | Each file that decides what runs, the program, the script an interpreter runs, and every directory above them are statted; one another account could change is flagged with the reason. `hideApple` (default on) hides what is on the sealed `/System` volume, never a `com.apple.` label in `/Library` or a job because Apple signed its program (`curl`, `sh -c` run what a planted plist says). An interpreter running code from its arguments counts as unsigned. A plist that is not a regular file is shown and never read. ACL-granted write is not checked. Users' crontabs, root's login hooks and Background Task Management need root |
| `effective_access` | the kernel's own `access(2)`: `/bin/test -r/-w/-x` as the subject, through `sudo -n -u #<uid>` when the server is root; `stat`, `ls -le` and `mount` to explain it | The answer is the kernel's, so ACLs, nested groups and flags are as macOS applies them. Asking for another account needs root; without it the answer is "not evaluated", never the server's own. Names a deny ACL entry that applies, uchg/schg/restricted flags, a read-only or noexec mount (firmlinks resolved, so `/Users` is on the data volume) and the first directory the subject cannot search. SIP and TCC are named, not evaluated |

MacDiag serves the same tool list as LinuxDiag. Programs
are run from `/usr/sbin`, `/usr/bin`, `/sbin` and `/bin` only (never `/usr/local` or `/opt/homebrew`, which
an admin user can own), with `LC_ALL=C` and no pager -- except `ps`, which gets `LANG=C LC_CTYPE=en_US.UTF-8`
so that a non-ASCII command line comes back as itself; under C, macOS ps prints it as `M-` escapes that cannot be
told apart from text.

Publish it, then install it over SSH. Remote Login must be on, and the SSH user an administrator:

```
dotnet publish src/MacDiag.Mcp -c Release -r osx-arm64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o artifacts/macdiag-osx-arm64
.\tools\bootstrap-macos.ps1 -Target mac-01 -User admin -Grants Standard
```

Use `-r osx-x64` and `-Binary artifacts/macdiag-osx-x64/MacDiag.Mcp` for an Intel Mac. `tools/bootstrap-macos.sh`
is the same for a Linux or macOS operator. Both do what the Linux scripts do, plus two Mac-specific steps:

- After checking the hash, they clear the quarantine flag.
- They sign the binary ad hoc (`codesign --force --sign -`) if it carries no valid signature. An Apple
  Silicon Mac kills an unsigned binary at launch, and a build published on Windows or Linux is unsigned;
  one published on a Mac is already signed ad hoc by the SDK.

That installs:

| Path | What |
|---|---|
| `/Library/PrivilegedHelperTools/com.sysdiag.macdiag/MacDiag.Mcp` | the binary |
| `/etc/macdiag/<label>.env` | root-owned `0600`: the token, bind address and grants, read with `--env-file`; one file per label |
| `/var/db/macdiag` | `0700`: the artifact directory. An existing `--artifacts` directory is never re-chmodded. It is refused unless root alone controls it, so `/tmp` is refused |
| `/var/log/macdiag` | `0700`: `macdiag.log` (rolled at 10 MiB) and `crash.log` (what the runtime writes before logging starts) |
| `/Library/LaunchDaemons/<label>.plist` | `KeepAlive` on a failed exit only, `AbandonProcessGroup`, `ProcessType Standard`, `ExitTimeOut` 20 s |

The plist is world-readable, so it never holds the token. It passes `--env-file` instead.

**The server refuses to start if another account could have written its settings.** It checks:

- the env file, which must be a root-owned `0600` regular file and not a link;
- the binary;
- every directory above either one, both as spelled and with links resolved (so `/etc` is checked as
  `/private/etc`).

Any of these that is owned by someone other than root, or writable by a group or by everyone, is named in
the refusal. The installer runs the same check before loading the job.

launchd retries a refused start every 10 seconds, writing the reason to `crash.log` each time, so the
daemon recovers by itself once the file is fixed.

The installer waits until the new job is running and is itself the process listening on the port, not a leftover by-hand server or the previous process, and reports the Application Firewall's state, which
can block the port without an error anywhere. If the daemon never listens, the installer prints the last
lines of both logs and exits 4. `--uninstall-service [--purge]` and `--service-status` do what they say;
`MacDiag.Mcp --help` lists every switch.

Full Disk Access is needed to read other users' protected files and the TCC database. Grant it under
System Settings → Privacy & Security → Full Disk Access by adding the binary. macOS ties that grant to the
code signature, so an ad-hoc build loses it whenever the binary changes. A Developer ID signature, or an
MDM privacy profile, keeps it across updates.

Add it to the relay's `~/.sysdiag-targets.json` like any target:

```json
{ "as": "mac-01", "target": "mac-01.local", "token": "…" }
```

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

The Linux server reads the same settings as `LINUXDIAG_*` -- `LINUXDIAG_READ_ONLY`, `LINUXDIAG_TOKEN` and so on -- with the same meanings and defaults, except that its artifact directory defaults to `/var/lib/linuxdiag`
and `put_file` writes into the server's own directory only with `LINUXDIAG_ALLOW_SELF_UPDATE`. `LinuxDiag.Mcp --help` lists them.

The macOS server reads them as `MACDIAG_*`, from its `--env-file` laid over the environment. They have the
same meanings, except:

- its artifact directory defaults to `/var/db/macdiag`;
- `MACDIAG_SERVICE_LABEL` names its launchd job;
- `MACDIAG_PROTECTED_LABELS` adds launchd labels, comma-separated, that `service_control` refuses to stop or restart and whose main process `process_control` refuses to signal. An entry is an exact label, or a prefix ending in `.` (`com.corp.`); a pattern such as `com.corp.*` stops the server at startup rather than protecting nothing. Add the labels of any remote-access tool the Mac is reached through that the built-in list misses - AnyDesk, RealVNC, Splashtop, ScreenConnect, Zscaler, Cloudflare WARP.

`MacDiag.Mcp --help` lists them.

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
| `SYSDIAG_RELAY_FILE_ROOT` | the directory *above* the relay executable's, plus a per-user `sysdiag` folder: `%TEMP%\sysdiag` on Windows, `$XDG_CACHE_HOME/sysdiag` or `~/.cache/sysdiag` elsewhere — never the shared `/tmp` | **Relay only.** Semicolon-separated local directories `push_file` may read from and `pull_file` may write to, *replacing* the defaults rather than adding to them. This is the boundary that stops one tool call copying an arbitrary local file onto a target, so widen it deliberately. The first default is one level up because the relay ships in `artifacts/diagrelay` while the builds it sends sit beside it in `artifacts/win-x64`; the climb stops short of handing out a whole drive. Both resolve against the running executable, so under `dotnet run` they point into dotnet's install directory — set this when developing |

Booleans are strict: `1/true/yes/on` or `0/false/no/off`. A misspelling fails startup rather than
silently defaulting, because the flag removes capability.

Diagnostics go to **stderr only**. stdout carries the MCP protocol and nothing else; a test asserts it.

## Behaviour worth knowing

**A LinuxDiag walk of /proc can wait behind a process stuck in the kernel.** Reading a process's command line or memory map takes a lock that a process blocked on a dead NFS server or a hung FUSE mount holds, and the read waits for it; there is no per-process timeout. If a `process_list` or `path_handle_search` call hangs on such a host, that is the cause - the tool call's own timeout still ends it.

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
