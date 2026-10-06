# Changelog

All notable changes to sysdiag are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions before `v1.0.0` were tagged
retroactively, at the commits that actually shipped something, so the history reads as releases
rather than as a commit dump.

For a server whose whole job is answering questions about a live machine, "changed" means the answer
changed. Entries therefore say what a caller now sees, not only what moved in the code — and where a
release fixed something that had been silently wrong, it says what the wrong answer looked like.

## [Unreleased]

## [3.0.0] - 2026-10-06

### Breaking

- WinDiag, LinuxDiag and MacDiag refuse a command-line argument or install option they do not know, naming
  it and suggesting the right spelling (`--readonly` -> `--read-only`), and exit 2. Before, an unknown
  option was ignored, so `--install-service ... --readonly` installed a fully writable service and a
  trailing `--token` installed a generated token. A server started by hand takes only `--http [address]`:
  set its other options through their `WINDIAG_*`, `LINUXDIAG_*` or `MACDIAG_*` variables.
- The project is now **sysdiag**: WinDiag, LinuxDiag and MacDiag servers and the DiagRelay relay. The
  Windows server keeps its WinDiag names, `WINDIAG_*` variables and paths.
- The relay's targets file is `~/.sysdiag-targets.json` (was `~/.windiag-targets.json`). Rename the file;
  the old name is not read.
- The relay's file-root variable is `SYSDIAG_RELAY_FILE_ROOT` (was `WINDIAG_RELAY_FILE_ROOT`), and its
  per-user folder is `sysdiag` (was `windiag`). The old variable is not read.
- The relay reports itself as `sysdiag-relay`, and the suggested Claude Code registration name is
  `sysdiag`, so forwarded tools appear as `mcp__sysdiag__<alias>__<tool>`. Re-key the `mcpServers`
  entry in your client config.
- MacDiag's default launchd label and install folder are `com.sysdiag.macdiag` (was `com.windiag.macdiag`).
- `put_file` and `get_file` report `scope` `"Owned"` (was `"WinDiag"`) for a path inside the server's
  own directories, on every server.

### Security

- Before, any local user on a Windows target could read the service's bearer token from its registry key
  (`HKLM\SYSTEM\CurrentControlSet\Services\<name>`, value `Environment`). `sc create` gives the key the
  Services key's ACL and nothing restricted it, even though the docs said only SYSTEM and Administrators
  could read it. With the Standard grants that token allows run_command as SYSTEM. Now `--install-service`
  restricts the key to SYSTEM and Administrators before writing the token, `--service-status` reports
  anyone else who can read it, and a service restricts its own key on its first start on this build and
  logs a warning. Change the token on any target installed before this release.
- Before, `C:\WinDiag` and `C:\WinDiagArtifacts`, the bootstrap defaults, inherited *Authenticated Users:
  Modify* from `C:\`. Any local user could plant `handle64.exe` and similar binaries, a replacement
  server, or a changed `self-update.cmd`, all of which the SYSTEM service runs, and could read memory
  dumps. Now the installer, `deploy-target.ps1` and both bootstrap scripts give the server and artifact
  directories a protected ACL: SYSTEM and Administrators only, owned by Administrators. The bootstrap
  scripts do this before copying anything, and hand anything already in an existing directory to
  Administrators. A service checks again on every start, restricts what it can (with an event-log
  warning), and refuses to start, writing the reason to the event log, only when it cannot. The installer
  refuses a drive root, and a server directory that holds files other than windiag's, rather than locking
  it down; the scripts refuse a directory that is or contains a link.
- Before, the Windows bootstrap scripts passed `--token <value>` on the target's command line, so it
  showed up in process-creation auditing, PSEXESVC and `process_list`, and `deploy-target.ps1` printed the
  real token in its by-hand instructions. Now `WinDiag.Mcp.exe --install-service` accepts `--token-stdin`,
  both bootstrap scripts deliver the token that way, and `deploy-target.ps1` prints a placeholder.
- Before, `bootstrap-target.ps1` put the target administrator's password on `net use`'s command line on
  the operator's machine, despite promising it never reached one. Now it opens the IPC$ session in-process
  through WNetAddConnection2.
- WinDiag's `put_file` no longer writes into the server's own folder unless the self-update grant
  (`WINDIAG_ALLOW_SELF_UPDATE` / `--allow-self-update`) or arbitrary write is on. Before, any writable
  server's token could put `handle64.exe` or a DLL there, and the server ran it as SYSTEM with
  `run_command` and `update_self` both off. A put there now gets a refusal that names
  `WINDIAG_ALLOW_SELF_UPDATE=1`, and `deploy-target.ps1` says so before staging.
- WinDiag loads `dbghelp.dll`, `wintrust.dll`, `rstrtmgr.dll`, `iphlpapi.dll` and its other imports, plus
  the event log package's `wevtapi.dll`, only from System32 by absolute path. Before, a copy in the
  server's folder was loaded first, inside the SYSTEM process. The .NET runtime's own imports are not
  covered; for those, the server folder's ACL and the self-update grant remain the boundary.
- A Sysinternals tool found beside WinDiag runs only if its Authenticode signature is valid and
  Microsoft's. An unsigned or foreign-signed copy is refused by path in the tool result and in
  `capabilities`. Before, it was run as long as it had the right bitness.
- A junction or symbolic link inside an owned directory whose target .NET reports without a root now
  counts as leaving that directory, so `get_file` and `put_file` through it need the arbitrary grant. That
  covers a mounted folder (`\\?\Volume{guid}\`), a `GLOBALROOT` path, a junction to
  `\Device\HarddiskVolumeN\` or a shadow copy, and a relative symbolic link. A link to a share now stops
  the scope check before the check itself connects to the share. Before, such a target was judged a child
  of the link's folder, so another volume or a shadow copy read as owned. An artifact or server directory
  reached through such a link is refused with a message saying to move it to a directory on a drive
  letter.
- On Windows, `who_locks_path`, `file_signatures`, `effective_access`, `query_activity` and `get_file`
  refuse network share and device paths (`\\host\share`, `\\?\UNC\`, `\\.\`, `\\?\GLOBALROOT`, and mapped
  network drives however the letter is spelled, `\\?\Z:\` included) unless `WINDIAG_ALLOW_ARBITRARY_READ`
  is set, and they refuse before touching the path. `put_file` reaches one only with
  `WINDIAG_ALLOW_ARBITRARY_WRITE`. Before, even a read-only token could make the SYSTEM service open SMB
  to any host and sign in as the machine account.
- `query_activity` reads only captures inside the server's own directories, the same rule as `get_file`,
  unless `WINDIAG_ALLOW_ARBITRARY_READ` is set. A path outside gets the same refusal whether or not it
  exists, and a file that is not a capture is rejected by naming the missing column. Before, it read any
  file as SYSTEM on a read-only server, and its error echoed the file's first line.
- WinDiag summaries now escape newlines, control characters and bidirectional overrides in text other
  accounts control: command lines, process, service, module and handle names, registry names and data,
  event messages, paths, signer names and trace entries. Before, a process started with a newline in its
  command line, or an HKCU REG_SZ holding one, could write a line into process_list's or registry_read's
  summary that read as the server's own. The structured content keeps the original text.
- process_control now refuses to terminate or suspend a process Windows marks critical, or one hosting a
  service that service_control refuses to stop (RpcSs, DcomLaunch, Winmgmt, EventLog and the rest).
  Before, ending the right svchost by PID could bugcheck the machine or take RPC and WMI down. It also
  refuses when it cannot read those facts. Resume is never refused.
- service_control also checks the service's resolved short name. Before, naming a core service by its
  display name got past the check.
- capture_dump refuses lsass, lsaiso and csrss, identified by their image in System32. Before, a writable
  server's token with no grants could dump them and fetch the file with get_file.
- registry_read needs WINDIAG_ALLOW_ARBITRARY_READ for HKLM\SAM, HKLM\SECURITY and other users' hives
  under HKU, and the refusal names the grant. Before, any token, read-only included, could read them.
- registry_read now redacts values named like a credential under every grant, including NAME=value entries
  such as WINDIAG_TOKEN in a service's Environment, and keeps their size. Before, a read-only instance's
  token could read another instance's bearer token from its service key.
- `autostart_audit`: autorunsc's output used to be split on line breaks before quotes were handled. A Run
  value name containing a line break plus a complete fake row (which any user can create) dropped the
  real, unsigned entry as if it were a section header and listed the fake one as a Verified Microsoft
  entry, so the summary called every entry validly signed. Records are now read quote-aware. A row that
  cannot be read as a whole entry is counted in `malformedRowCount`, and a non-zero count opens the
  summary with a warning instead of a clean signature verdict.
- `path_handle_search` and `process_handles`: a comma in a process image name shifted handle.exe's
  columns. `a,b.exe` holding a file was dropped, and an elevated search answered 'No open file references
  matched'; `x,668,File,SYSTEM,0x4,svc.exe` blamed the lock on PID 668. Columns are now located by what
  they look like (anchored on the requested PID under `-p`). A row that is ambiguous or cannot be read is
  counted in the new `unparsedRows` field and flagged, and an empty result is never described as nothing
  matching.
- `process_modules` read version, PE header and signature from whatever file sits at a module's path now.
  A DLL renamed away while loaded and replaced by a signed copy was reported as signed. Each module's
  loaded PE header is now compared with its file. A mismatch is flagged `replacedOnDisk` / [REPLACED ON
  DISK], its signature is not checked, and no relocation verdict is taken from the other file. The
  description no longer promises tamper detection.
- `update_self` on Windows accepted any validly signed replacement from any publisher, and turned its
  signature check off entirely when the running build's own signature no longer verified (for example,
  expired without a timestamp). The staged file's signature verdict and its hash also came from two
  separate file opens, so a `put_file` landing between them could get an unsigned build installed. A
  signed server now accepts only a validly signed replacement whose verified signer matches its own,
  refuses everything if its own signer cannot be read, and verifies and hashes the staged file through one
  handle that blocks writers. `file_signatures` gains `signerSubject`.
- LinuxDiag `service_control` refuses a stop or restart when `systemctl list-dependencies` fails. Before,
  a D-Bus timeout or a partial walk read as "nothing depends on this", so the stop ran and could take
  `ssh.service` or the diagnostics server down with it. It now answers "could not list the services that
  depend on it ... Nothing has been done."
- LinuxDiag `autostart_audit` reads users' systemd units the way a user's manager does: by name along the
  user search path, with every drop-in, keeping only the commands after the last empty `ExecStart=`.
  Before, an enabled packaged user unit with `~/.config/systemd/user/x.service.d/o.conf` replacing
  ExecStart was reported with the packaged program, called packaged, and hidden by `unpackagedOnly`. Now
  the user's program is reported and the drop-in is checked. User timers, sockets and paths now name the
  program of the unit they start; before, they showed none. Units enabled for every user, including vendor
  units under `/usr/lib/systemd/user` such as `pipewire.socket`, are listed. They are listed again for any
  user whose own files change what they run, including the service a socket or timer starts.
- The LinuxDiag installer makes `/opt/linuxdiag`, `/etc/linuxdiag` and the default `/var/lib/linuxdiag`
  root-owned with their documented modes even when they already exist, and makes a binary installed from
  its own path root's. An existing `--artifacts` directory is refused unless root alone controls it and
  every directory above it, and it is never re-chmodded. A missing one is made only where root alone
  controls the directories above it, and nothing is made when it is refused. `update_self` also refuses to
  write its helper script into an artifact directory another account controls. Before, a pre-existing
  operator-owned or world-writable directory was used as-is, and a local user could get root code
  execution at the next update.
- The relay's default `push_file`/`pull_file` root no longer reaches the home directory. It used to be the
  folder above the relay's executable wherever that was: `~/bin/DiagRelay.Mcp` allowed all of `$HOME`,
  `~/DiagRelay.Mcp` allowed every user's home, and an unpacked release zip allowed `~/Downloads`. That put
  `~/.ssh` and `~/.sysdiag-targets.json` one tool call away from a target. Now the default is the per-user
  `sysdiag` folder (`%TEMP%\sysdiag`, or `$XDG_CACHE_HOME/sysdiag` / `~/.cache/sysdiag`), plus the
  `artifacts` directory only when the relay runs from `artifacts/diagrelay` or
  `artifacts/diagrelay-<rid>`. That tree is refused if it holds the user profile. To push builds from
  anywhere else, copy them into the per-user folder or set `SYSDIAG_RELAY_FILE_ROOT`.
- The relay's `push_file` and `pull_file` now refuse a local path that leads through a symlink or junction
  out of the permitted roots. Before, the check went only by the path as written, so `root/keys ->
  ~/.ssh/id_ed25519`, or a linked directory a pull wrote into, passed. Paths and roots are both resolved
  with the same realpath-style walk the server's `put_file`/`get_file` use, so a roots folder that is
  itself a link still works. A link loop or an unreadable link is refused.
- All servers over HTTP: every request without a valid bearer token used to be logged twice at Information
  by ASP.NET Core, with no peer address, so any peer could roll MacDiag's 10 MB log or exhaust journald's
  rate limit without a token. ASP.NET Core's own categories are now logged at Warning and above. The
  bearer gate writes one Warning per peer address per minute, naming the address, for at most 10 addresses
  a minute, and then a single summary of what it only counted.

### Added

- **MacDiag.Mcp, a macOS diagnostics server**, for macOS 13 or later on Apple Silicon and Intel,
  reached through the same relay.
  - It serves the kit tools, `run_command` (`zsh`, `sh`, `bash`, `none`), `system_overview`, `process_list`,
    `process_handles`, `process_modules`, `path_handle_search`, `who_locks_path`, `network_owners`,
    `named_pipes`, `update_self` (a launchd swap that restarts the old build on any abort and rolls back a
    build that does not come up), `service_config`, `service_control` and `process_control` (which refuse what
    keeps the Mac reachable, including the main process of a protected launchd job, in the system domain or a
    user's own - the latter not yet verified on a Mac), `event_log_tail`
    (the unified log, walked backwards in time windows), `container_list` (Docker Desktop, Colima, OrbStack
    and Rancher Desktop sockets, each checked for owner and type first), `file_signatures` (codesign,
    Gatekeeper for app bundles, package receipts, SHA-256), `autostart_audit` (launchd, cron, periodic,
    login hooks, authorization plugins, system and kernel extensions and Background Task Management,
    flagging what another account could change) and `effective_access` (the kernel's own answer, run as
    the subject) - the same tool list as LinuxDiag.
  - `--install-service` installs it as a launchd daemon from root-only paths.
  - It refuses to start if its settings file, its binary, or any directory above them could have been
    written by an account other than root.
  - `tools/bootstrap-macos.sh` and `.ps1` install it over SSH.
  - CI builds, tests and smoke-installs it on `macos-latest`, and the release workflow publishes both
    architectures.
- The shared server kit now:
  - loads libSystem on macOS;
  - refuses a planted link when appending a chunk there, through `open(2)` with `O_NOFOLLOW`;
  - treats a case or Unicode-normalisation variant of the server's directory as needing the self-update
    grant, on APFS's case-insensitive volumes.
- The system-program runner moved from LinuxDiag into the kit, with a streaming mode for output that has
  no natural end.

### Fixed

- `autostart_audit` scanned only the profile of the account it ran as. As a LocalSystem service (the
  normal deployment) it listed SYSTEM's HKCU Run keys and Startup folder and no real user's, while calling
  the list complete. It now asks autorunsc for every user profile, and a per-user entry shows the profile
  it belongs to.
- `run_command` with the default Cmd shell broke every command containing a double quote: `"C:\Program
  Files\App\app.exe" --version` failed with 'is not recognized', and `echo "a b"` printed `\"a b\"`.
  Commands now reach cmd.exe exactly as typed, through `cmd /d /s /c "…"`. Because of `/d`, a target's cmd
  AutoRun registry commands no longer run first.
- `named_pipes` flagged every pipe whose instances were all created as 'AT LIMIT' and said a client would
  block or fail, including single-instance pipes waiting for their first client, which would have accepted
  one. It now checks such pipes with `WaitNamedPipe` (connecting nothing) and marks BUSY only those with
  no instance listening. Structured output changed: `activeInstances` is now `instancesCreated`,
  `exhausted` is now `allInstancesCreated`, and `listening` and `busy` are added.
- The release workflow no longer publishes Windows builds when the WinDiag test suite fails. Its
  multi-line build-and-test steps ran under pwsh on Windows, which counts only the last command's exit
  code. Each dotnet build and test is now its own step, and CI's publish-then-inspect steps check
  `$LASTEXITCODE`.
- Release zips now include `LICENSE` and a new `THIRD-PARTY-NOTICES.md`. Before, they shipped only the
  binary and `SHA256.txt`, although every self-contained binary redistributes the .NET runtime (MIT),
  ASP.NET Core (servers only, MIT) and the MCP C# SDK (Apache-2.0). The notices file also states that
  Sysinternals is not redistributed and that WinDiag accepts its EULA on the target when it runs those
  tools.
- The LinuxDiag release job now builds the kit's test project before running it with `--no-build`, which
  otherwise found nothing to run.
- LinuxDiag's `system_overview` could report a healthy mount as not answering when another mount's size
  probe was stuck and the thread pool was busy. Each probe now has a thread of its own.
- LinuxDiag's `process_control`, given a thread's ID, said only "could not open" on newer kernels, where
  `pidfd_open` refuses it with ENOENT (measured on 7.0). It now says it is a thread, as on older kernels.

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

[Unreleased]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v1.3.0...v2.0.0
[1.3.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.8.0...v1.0.0
[0.8.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/shubhamyadav8901/sysdiag-mcp/releases/tag/v0.1.0
