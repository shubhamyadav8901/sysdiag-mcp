# Changelog

All notable changes to windiag are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions before `v1.0.0` were tagged
retroactively, at the commits that actually shipped something, so the history reads as releases
rather than as a commit dump.

For a server whose whole job is answering questions about a live machine, "changed" means the answer
changed. Entries therefore say what a caller now sees, not only what moved in the code — and where a
release fixed something that had been silently wrong, it says what the wrong answer looked like.

## [Unreleased]

## [2.0.0] - 2026-10-01

### Removed

- **BREAKING: `WinDiag.Mcp.exe --relay`.** The relay is now its own executable, `DiagRelay.Mcp`,
  published to `artifacts/diagrelay/`. Running the server with `--relay` now exits 2 with a message
  naming the new executable, rather than falling through to stdio mode and silently serving this
  machine's own tools in the fleet's place. To move over, point your MCP registration at
  `DiagRelay.Mcp` and keep its name — every forwarded tool name stays the same. Because this removes a
  documented interface, this release is **2.0.0**, not a minor bump.

### Added

- **LinuxDiag.Mcp, a Linux diagnostics server** for Ubuntu and Debian (x86-64), reached through the same
  relay. It serves `capabilities`, `put_file`, `get_file`, `system_overview`, `run_command`
  (`sh`/`bash`/`none`) and `update_self`, installs as a systemd service with `--install-service`, and is
  brought up over SSH by `tools/bootstrap-linux.sh` (verified live) or `tools/bootstrap-linux.ps1` (not
  yet run against a live host). The systemd and host-configuration tools follow. **Not yet for
  production hosts:** findings from its security review are still open; keep it to test machines until
  they are resolved.
- **LinuxDiag's process, open-file and container tools:** `process_list`, `process_modules`,
  `process_handles`, `path_handle_search`, `who_locks_path`, `network_owners`, `named_pipes`,
  `process_control` and the new `container_list`. Every process is tagged with its container - Docker's
  or containerd's, Kubernetes pods included - and its PID inside it. Open files are matched by device
  and inode, so a hard link, a rename or a container's own path still finds the holder. Lock holders
  come from each open file's own lock list, so a lock inherited by a forked child names the child, not
  the process that took it and exited. `network_owners` names every process sharing a socket.
  `process_control` signals through a pidfd, so a PID reused since `process_list` cannot be hit; its
  `terminate` is SIGTERM with a 10-second wait, and `kill` is SIGKILL.
- **LinuxDiag host configuration.** `service_config`, `service_control` (writable servers only),
  `event_log_tail`, `file_signatures`, `autostart_audit` and `effective_access`. `file_signatures` and
  `autostart_audit` judge files against the dpkg database - including the drop-ins that can override a
  packaged unit - and say "matches the database", never "signed". `effective_access` names the rule that
  decides, down to an ACL mask or a parent directory, and shows the kernel's own answer beside it.

- **`RenderLimits` is shared by both servers**, and the kit's capability table can say a tool is
  Degraded when none of the sockets or directories it reads exists.
- **The relay runs on Linux**, and is built for macOS (untested until CI has run on it). A Linux machine
  can now drive Windows targets: verified end to end from a native Linux build — pre-connect,
  forwarded calls, and a byte-identical `push_file`/`pull_file` round trip against a live target. Off Windows the relay's token file is created owner-only
  (`0600`), concurrent relays serialise on a kernel-held file lock, local paths are compared
  case-sensitively — including on macOS, since APFS can be formatted case-sensitive and the check that
  confines `push_file` fails closed — and pulled dumps and traces land owner-only in a per-user
  directory rather than the shared `/tmp`, where another local user could read them or plant a file
  for the next `push_file` to send to a target.
- **`--install-service --token-stdin`** reads the bearer token to pin from standard input, keeping it
  out of `sudo`'s log and `ps`. `tools/bootstrap-linux.sh` and `bootstrap-linux.ps1` now send a token
  given with `-k`/`-Token` that way: over the SSH connection's standard input into an owner-only file
  that the install reads, and that a trap removes -- with the copied binary -- however the install
  session ends, including a failed hash check or a dropped connection.
- **LinuxDiag's `put_file` refuses its own directory without the self-update grant.** That directory
  holds a root service's binary and the `netcoredeps` folder it loads libraries from, and staging a
  build is the only reason to write there, so a write under it needs `LINUXDIAG_ALLOW_SELF_UPDATE=1`
  (`--allow-self-update`) or arbitrary write, and the refusal names both. An artifact directory placed
  inside the server's folder gets no exemption. windiag's own folder stays writable as before.

### Fixed

- **LinuxDiag summaries can no longer be forged by the text they report.** A command line, process or
  socket name, unit description, journal message or cron command containing a newline used to start a line
  of its own in the summary an agent reads, and an ESC or direction override reached it raw; every such
  value is now shown escaped (`\n`, `\u001b`), while the structured content keeps the original.
- **LinuxDiag says more of what it could not see.** `process_list` names a `/proc` mounted with
  `hidepid`, `named_pipes` names network namespaces it could not read, `service_config` shows why a unit
  file failed to load, units written by systemd generators are no longer reported as unpackaged - each generator is audited instead - and the
  systemd tools report Degraded where systemd is not running. One unreadable process, odd lock line,
  socket name or unit no longer loses the whole answer, and `container_list` and `file_signatures` are capped.
- **LinuxDiag's control tools refuse more of what would cut a machine off.** `process_control` refuses to
  stop or freeze journald, logind, udevd, dbus, networking, the resolver, polkit, sshd and VPN daemons, and
  matches the expected name exactly (case-sensitive, a path compared whole). `service_control` refuses a
  stop that would take a critical unit down with it, and treats `tailscaled`, `wg-quick@` and `openvpn@`
  as critical.

- **A link loop is refused instead of crashing the process** (windiag too). A symlink or junction whose
  target ran back through one of its own parent components sent path resolution into unbounded
  recursion, and the stack overflow took the whole server down with every call in flight; `put_file`
  and `get_file` now answer that the path could not be resolved.
- **LinuxDiag loads the C library by its soname, `libc.so.6`.** A plain `libc` import is probed in the
  application directory before the system loader is asked, so a `libc.so` dropped beside the server
  could have been mapped into a root process.
- **`put_file` and `get_file` judge a path by where it really resolves.** A symlink (Linux) or junction
  (Windows) inside a server-owned directory no longer carries a write or a read outside it without
  the arbitrary grant: containment was checked on the path as spelled, so a link planted in an owned
  folder looked owned wherever it pointed.
  Links are followed one component at a time, the way the kernel walks them, so a target like
  `hop/..` climbs from where `hop` points rather than from its spelling. And a write off Windows, which
  replaces a link at the destination rather than writing through it, is judged at the link itself:
  `put_file /tmp/x` with `/tmp/x` linking into the artifact directory used to pass as owned while it
  created `/tmp/x`, and now needs the arbitrary grant. Reads, appends and Windows writes follow the
  link and are judged at its target.
  On Linux a path through any link on procfs is never owned and needs the arbitrary grant. That is the
  magic links -- `/proc/<pid>/root`, `cwd`, `fd/N` -- and the ordinary ones with them: `/proc/self`,
  `/proc/thread-self`, and `/dev/fd/*` and `/dev/stdin`, which lead there. What `readlink` prints for
  a magic link is not where the kernel goes: through a container's `root`,
  `put_file /proc/<pid>/root/var/lib/linuxdiag/x` was judged owned while a link inside the container
  could carry the write anywhere on the host. With the grant it works as before. An artifact directory
  configured through such a link is refused on every call, since what it owns cannot be judged.
- **`push_file` of an empty file now works.** The relay sends a zero-byte file as one call with no
  content, which the server refused as "contentBase64 is empty", so an empty file could not be pushed
  at all. Empty content is now an empty file; *missing* content (`null`) is still refused, since with
  `overwrite` on by default accepting it would empty whatever was at the path.
- **`put_file` no longer follows a symbolic link off Windows, and writes owner-only there.** The write
  path is now shared with the coming Linux server, which runs as root: a file is replaced rather than
  written through a link at its path, and new files and directories — including a file an append
  creates — are created `0600` and `0700`. An append to a path that has become a link is refused; on
  x86-64 Linux the refusal comes from `open(2)` with `O_NOFOLLOW` itself, so a link swapped in at the
  file's own name between the check and the open is still refused (this covers the last path component
  only). Windows behaviour is unchanged.

### Changed

- **The `capabilities` description, the `get_file` path hint and three put_file/get_file messages no
  longer name Windows-only tools**, because the Linux server serves them too. `update_self`'s forced-
  restart message now says it allows time "to stop the tools it started" rather than naming Procmon.
- **`put_file` and `get_file` describe themselves without Windows-only wording** — no `C:\WinDiag`,
  SMB or UNC examples — because every server in the family now serves the same two tools. Their
  parameters and answers are unchanged. The refusal for a file over the single-call limit now says to
  send it in chunks, rather than pointing at a UNC path.
- **`put_file`'s description gains one sentence**, shared by every server: a server may reserve its
  own folder for staging an update, in which case writing there also needs its self-update grant and
  the refusal names it. windiag does not reserve its folder, so nothing it does has changed.

### Documentation

- **Said plainly that the channel is not encrypted.** The security notes covered the bearer token
  thoroughly -- fixed-time comparison, never on a command line, never echoed -- and never mentioned
  that it crosses the wire in cleartext on every call, along with every dump, file and command output
  the tools return. The chunk hashing on file transfers is integrity, not confidentiality. Nothing
  about the software changed; what changed is that an operator deciding whether to route a target
  across a network they do not control can now find that out before doing it.
- The full `--install-service` option list, and the fact that each grant flag becomes its `WINDIAG_*`
  variable in the service's own registry key, are now documented rather than living only in the
  parser. `--help` had also been missing three variables it does honour.
- Both bootstrap scripts are documented, including what each `-Grants` preset actually passes --
  `None` is `--read-only` alone and cannot read a file, which is a trap for anyone asked for
  "read-only access".
- Adds a `CLAUDE.md` the repo never had, and a `windiag-target` skill for the setup procedure.

### Added

- **The executable installs itself as a service.** `--install-service`, `--uninstall-service` and
  `--service-status`, asking Windows for elevation when it does not already have it. It configures
  what is easy to lose by hand: the token generated and written to the service's own registry key
  rather than anywhere a local user can read, SCM restart-on-failure, the artifact directory pinned
  so captures do not silently move to `C:\Windows\SystemTemp`, the grants carried across so a
  re-registered server does not come back with fewer tools, and a firewall rule scoped to one
  address and removed again on uninstall.
- `--service-status` reports whether this machine runs windiag by hand or as a service, and how it
  is configured. The two look identical from outside and behave differently on every restart.

### Fixed

- **`update_self` works on a server running as a service.** It failed with
  `AggregateException: An error occurred while writing to logger(s)`, and the cause was not in the
  update path at all: running under the SCM there is no stderr, so logging goes to the Windows event
  log, and writing there needs `System.Threading.AccessControl` -- which `EventLog` reaches only
  through a named-mutex path no compiler records, so the published build did not carry it. What made
  it look like an `update_self` bug is that the event log provider only logs at Warning and above, so
  every Information line was filtered out and never attempted a write. The server started, served
  every tool, and then died on the first Warning of its life -- the one noting that the staged build
  is unsigned, emitted halfway through an update. The assembly is now referenced outright and CI
  asserts it survives to the published set. A service-registered target updates like any other.
- Registering the event log source cannot take the installer down with it. `--install-service`
  caught the failures it predicted rather than all of them, so the missing assembly above surfaced as
  an unhandled stack trace and no service at all. Service management now names the failure and points
  at `--service-status`, instead of printing a trace. When it had to ask for elevation first, it also
  says that the elevated run failed and took its console window with it -- previously that path
  printed nothing but an exit code, because everything the elevated child wrote vanished with its
  window.

### Changed

- A service whose event log source cannot be registered now starts with **no event log output at
  all**, rather than with a logger that throws the first time something writes to it. Under the SCM
  there is no stderr, so this means no server output at any level; `--install-service` says so when it
  happens. Every tool still works, which is the point -- a diagnostic channel must not be able to
  break the thing it is reporting on.
- `--uninstall-service` deliberately leaves the `windiag` event log source registered. It is
  machine-global and shared by every windiag on the box regardless of `--service-name`, so removing it
  with one service would silence any other still running.


- **`update_self` on a service-registered target no longer desynchronises the SCM.** The restart
  helper relaunched the executable, which starts a process the Service Control Manager knows nothing
  about: the service reads as Stopped while something holds its port, and `service_control start`
  then fails because the port is taken. It now issues `sc start` when the server is running as a
  service, and still launches the executable when it was started by hand.

### Added

- Project metadata: changelog, contributing guide, security policy, code of conduct, editor
  settings, CI workflow, and issue/PR templates.

## [1.3.0] - 2026-08-21

### Added

- **The same executable can run as a Windows service.** `AddWindowsService()` on the existing
  generic host, so `sc create` works and — the point of it — `service_control` can restart a target
  **remotely**. Until now a server that died, or one you stopped, needed somebody at that machine's
  console.

### Verified

- **Session 0 imposes no limits.** Procmon captures with no interactive desktop, measured as a
  SYSTEM scheduled task on a 32-bit and a 64-bit VM (68,849 and 202,908 events) and again from a
  real service (67,423). A note claiming `capture_activity` needed a desktop was wrong.

### Notes

- Running by hand is unchanged and tested: `AddWindowsService()` is inert unless the SCM started the
  process, and a test fails if a service lifetime ever appears interactively.
- As a service, `%TEMP%` becomes `C:\Windows\SystemTemp` — pin `WINDIAG_ARTIFACT_DIR`.
- Put the token in the service's own registry `Environment` value, which is ACL'd to SYSTEM and
  Administrators. A machine-wide variable is readable by every local user.

## [1.2.1] - 2026-08-21

### Fixed

- `path_handle_search` and `process_handles` no longer offer mapped sections as a reason to re-run
  with `includeAllObjectTypes=true`. Without `-a`, handle.exe returns *file references* — file
  handles **and** the sections backing them — so that advice sent callers into a measured 6m40s
  sweep for rows they already had, and implied the fast search could not see a memory-mapped holder,
  which is precisely the holder `who_locks_path` misses.

## [1.2.0] - 2026-08-21

### Changed

- **`update_self` finishes what the server is doing before it restarts.** It waits for in-flight
  tool calls, refusing new ones so the server is guaranteed to reach idle, bounded by
  `WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS` (default 1800). Previously it cut work off after an
  inherited 30-second framework default: a 90-second capture died at ~56s, the caller got a raw
  transport error rather than a result, and a 256 MB partial trace was orphaned.

### Added

- `force` on `update_self` for the old behaviour, now an explicit choice. `update_self` is also the
  one tool a draining server still accepts, so a wait can be escalated rather than stranding you.
- `WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS` (1–86400, default 1800), sized to `capture_activity`'s
  ~21-minute worst case.

### Fixed

- A failed helper launch no longer bricks every later update by leaving the commit claim set.
- `deploy-target.ps1` no longer reports a successful deploy of a build it never installed: a refused
  `update_self` writes nothing to stdout and does not throw, so it used to fall through to a poll
  answered by the old server.

## [1.1.0] - 2026-08-20

### Added

- **`push_file` and `pull_file` on the relay**, moving whole files without their bytes entering the
  conversation. `put_file`/`get_file` carry bytes as tool arguments and results, so an agent-driven
  transfer of a 46 MB build is ~63 MB of base64. The relay reads from local disk and streams instead:
  101 MB moved for a single tool call.
- `WINDIAG_RELAY_FILE_ROOT`, confining what the relay may read and write locally. This is the first
  thing the relay does that touches local disk, so it reuses `FileScope` rather than a second copy.

### Fixed

- The relay's default build root pointed one level too deep and therefore at a directory that does
  not exist, so pushing a build required setting the variable — exactly the inert-by-default state
  the design argued against.

## [1.0.0] - 2026-08-19

First release in which **every tool can actually be called from an MCP client.**

### Fixed

- **Seven tools were unusable and returned correct answers the client threw away.** The output
  schema marks every constructor parameter without a default as required, while the SDK's serializer
  omits nulls — so any response with a null in it failed validation against the schema the server
  itself advertised. `system_overview` (an unlabelled volume), `file_signatures` (an unsigned file),
  `network_owners` (a listening socket), `process_list`, `process_modules`, `autostart_audit` (on
  its *default* arguments) and `effective_access` were all affected. `process_list` mattered most:
  nearly every other tool's description tells the caller to get a PID from it.

### Added

- A test that walks from every `[McpServerTool]` method to the records it can return and asserts
  each one serializes completely — the check that would have caught all seven, and which nothing
  did.

## [0.8.0] - 2026-08-19

### Added

- `get_file`: retrieve a capture or dump over the server's own channel, so collecting an artifact
  needs no SMB share either. `tools/fetch-from-target.ps1` drives it and streams straight to disk.
- `query_activity` filters on the `Detail` column server-side.

### Fixed

- `who_locks_path` failed outright whenever it actually found a holder — the one case anybody calls
  it for. It had survived a full sweep because every earlier call pointed at a path with no holders.
- A refused `put_file` chunk is retried on its own rather than restarting the whole transfer.
- A capture with no `Detail` values no longer reads as "nothing matched".

## [0.7.0] - 2026-08-18

### Added

- **`--relay`**: one local stdio MCP server that forwards to any target at runtime, so a fleet of lab
  VMs on changing addresses needs one client registration instead of one per machine. Several
  targets connect at once, each prefixed by an alias.
- Targets pre-connect at launch from `%USERPROFILE%\.windiag-targets.json`, so their tools are in the
  very first `tools/list` — which is what clients that read the tool list only at startup require.

## [0.6.0] - 2026-08-17

### Added

- `put_file`, staging files over the server's own authenticated channel instead of the SMB admin
  share, in hash-verified 4 MB chunks. A single ~57 MB base64 body is more than a 32-bit server can
  decode at once, and a per-chunk hash catches a corrupt chunk at the chunk.
- `deploy-target.ps1`: one command that publishes, stages, verifies by hash on both sides, records
  what it staged, and asks the server to replace itself.

## [0.5.0] - 2026-08-16

### Added

- `run_command`, an opt-in arbitrary-command tool behind its own flag — the escape hatch for git,
  build tools and anything the diagnostics do not cover.

## [0.4.0] - 2026-08-15

The full tool surface, verified on both bitnesses.

### Added

- `autostart_audit`, `process_handles`, `process_modules`, `registry_read`, `process_control`,
  `service_control`, and readable tool errors.

### Fixed

- A broken autostart hook no longer renders as a healthy one.
- 32-bit Windows is no longer told it is reading `WOW6432Node`, which it does not have.

## [0.3.0] - 2026-08-14

### Added

- `update_self`: replace the server's own executable and restart, for a target reachable by file copy
  but not by remote execution. Hash-checked, signature-ratcheted, and handed to a detached helper so
  a failure restarts the existing build rather than leaving nothing running.

## [0.2.0] - 2026-08-13

### Added

- Architecture-aware Sysinternals resolution, and `tools/verify-on-target.ps1` to prove the tools
  that cannot be faked actually work on the machine under test.
- `tools/mcp-call.ps1`, a minimal HTTP MCP client for driving a target from the base machine.

### Fixed

- The 32-bit `handle.exe` on 64-bit Windows answers "No matching handles found." to every query
  rather than failing — so the wrong build looked like a clean result. It is now chosen by the
  target's architecture.

## [0.1.0] - 2026-08-12

### Added

- windiag: a Windows diagnostics MCP server answering live-machine questions a debugger structurally
  cannot — who holds this file, what is the machine doing, why is this access denied, what runs
  without being started. Both transports, stdio locally and authenticated Streamable HTTP on a
  target.

[Unreleased]: https://example.internal/windiag/compare/v2.0.0...HEAD
[2.0.0]: https://example.internal/windiag/compare/v1.3.0...v2.0.0
[1.3.0]: https://example.internal/windiag/compare/v1.2.1...v1.3.0
[1.2.1]: https://example.internal/windiag/compare/v1.2.0...v1.2.1
[1.2.0]: https://example.internal/windiag/compare/v1.1.0...v1.2.0
[1.1.0]: https://example.internal/windiag/compare/v1.0.0...v1.1.0
[1.0.0]: https://example.internal/windiag/compare/v0.8.0...v1.0.0
[0.8.0]: https://example.internal/windiag/compare/v0.7.0...v0.8.0
[0.7.0]: https://example.internal/windiag/compare/v0.6.0...v0.7.0
[0.6.0]: https://example.internal/windiag/compare/v0.5.0...v0.6.0
[0.5.0]: https://example.internal/windiag/compare/v0.4.0...v0.5.0
[0.4.0]: https://example.internal/windiag/compare/v0.3.0...v0.4.0
[0.3.0]: https://example.internal/windiag/compare/v0.2.0...v0.3.0
[0.2.0]: https://example.internal/windiag/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.internal/windiag/releases/tag/v0.1.0
