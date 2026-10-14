# MacDiag on macOS targets

## macOS targets

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
| `file_signatures` | SHA-256 from `shasum` (a child process, so a file swapped for a FIFO cannot hang the server); `codesign --verify --strict`, `-R 'anchor apple'`, `-R 'anchor apple generic'` and `-dvvv`; `spctl --assess -v` for a file inside an `.app`; `pkgutil --file-info` | At most 200 paths and 120 s per call. "Signed by Apple" means codesign's `anchor apple` requirement holds, which only Apple's own signing satisfies; it is never inferred from a certificate's name, which any signer can choose. Developer ID and App Store chains also end in Apple Root CA, and are reported by their leaf once `anchor apple generic` confirms Apple issued them; a chain it does not (self-signed or a private CA) is `Untrusted`, however its certificate and team are named, and `autostart_audit` counts it as unsigned. A valid signature is provenance, not a verdict on the signer |
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
| `/var/db/macdiag` | `0700`: the artifact directory. An existing `--artifacts` directory is never re-chmodded. It is refused, at install before anything is written and when a root server starts, unless root alone controls it and every directory above it, so `/tmp` and anything under a home directory are refused |
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
