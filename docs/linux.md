# LinuxDiag on Linux targets

`LinuxDiag.Mcp` is the Linux server: Ubuntu and Debian, **x86-64 only**. It is reached through the same
relay, with the same bearer token model and the same plaintext-HTTP caveat as windiag. It serves
`capabilities`, `put_file`, `get_file`, `system_overview`, `run_command` (`sh`, `bash`, `none`),
`update_self`, and the process, open-file and container tools below; the systemd and host-configuration
tools follow.

### Processes, open files and containers

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
or later, which every distribution .NET 10 supports has.

### Services, logs and host configuration

| Tool | Answers from | Notes |
|---|---|---|
| `service_config` | `systemctl show` | Unit file, drop-ins, main PID, restart count, result, dependencies both ways; a close name is offered when the unit does not exist |
| `service_control` | `systemctl start/stop/restart` | Writable server only. Services only, never a pattern. Stopping or restarting a unit the machine needs (journald, logind, udevd, networking, resolver, dbus, polkit, SSH, VPN tunnels such as `tailscaled` and `wg-quick@`), this server's own unit (use `update_self`), or a unit whose stop would take one of those down is refused; starting them is allowed. A service that powers off, reboots or suspends the machine is refused for every action. Waits at most 75 s, then reports "still running" |
| `event_log_tail` | `journalctl -o json` | `unit`, `minutes`, `levels`, `provider` (the syslog identifier), `match` (`FIELD=value`), `maxEvents` |
| `file_signatures` | SHA-256; dpkg's lists, md5sums, status and diversions | Valid, Modified, ConfigurationChanged, Unpackaged or Unknown against the dpkg database - integrity, not provenance |
| `autostart_audit` | enabled units, users' units (with the drop-ins of every name a link gives a unit file) and the `environment.d` and `user.conf` files in their homes (variable names only; one another account owns is named, never read), systemd generators, cron, rc.local, profile.d, ld.so.preload | `unpackagedOnly` checks the unit, its drop-ins, the program and an interpreter's script against their packages |
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
`bootstrap-target.ps1` ([the presets table](windows.md#bringing-up-a-machine-that-has-never-run-windiag)). That installs:

| Path | What |
|---|---|
| `/opt/linuxdiag/LinuxDiag.Mcp` | the binary. `/opt/linuxdiag`, `/etc/linuxdiag` and the default `/var/lib/linuxdiag` are made root's, with these modes, even when they already exist, and so is everything already in them, with group and other write removed. A symbolic link, a hard-linked file, a FIFO or a device inside one is refused instead: remove it and install again |
| `/etc/linuxdiag/linuxdiag.env` | root-owned `0600`: the token, bind address and grants |
| `/var/lib/linuxdiag` | `0700`: the artifact directory. `--artifacts` must be an absolute path with no `.` or `..` component. An existing `--artifacts` directory is never re-chmodded. It is refused unless root alone controls it, every directory above it and every link on the way to it — a link another account owns in `/tmp` is refused wherever it leads — so `/tmp` is refused. A missing one is made `0700` only where root alone controls the directories above it, and nothing is made when it is refused |
| `/etc/systemd/system/linuxdiag.service` | `Type=notify`, `Restart=on-failure` |

The unit is deliberately **not** sandboxed (no `ProtectSystem` and similar): a diagnostics server has to
see every process's `/proc`, and a sandbox would silently hide exactly what it is asked about.
`--uninstall-service` and `--service-status` do what they say; `LinuxDiag.Mcp --help` lists every switch.

Add it to the relay's `~/.sysdiag-targets.json` like any target:

```json
{ "as": "build-01", "target": "build-01", "token": "…" }
```

Later builds go through `push_file` to `/opt/linuxdiag/LinuxDiag.Mcp.new` and `update_self`, so both
need the self-update grant (`--allow-self-update`, `LINUXDIAG_ALLOW_SELF_UPDATE=1`). As on windiag,
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
