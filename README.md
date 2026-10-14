# sysdiag — live-machine diagnostics MCP servers for Windows, Linux and macOS

Answers live-machine debugging questions that a debugger structurally cannot: who has this file
locked, what is the machine actually doing, why is this access denied, what is set to autostart.

It complements `mcp-windbg`, which owns post-mortem dump analysis. A debugger sees inside one
process; this server sees the machine.

sysdiag is a set of servers: **WinDiag** (`WinDiag.Mcp`, Windows), **LinuxDiag** and **MacDiag**,
which serve much the same tool set on Linux and macOS ([Linux](docs/linux.md) and [macOS](docs/macos.md) list theirs), and **DiagRelay**, a local relay that puts any number
of them behind one MCP registration. This page gets you started; the [documentation](#documentation) has
the rest.

**[Changelog](CHANGELOG.md)** · **[Contributing](CONTRIBUTING.md)** · **[Security](SECURITY.md)** ·
**[Code of conduct](CODE_OF_CONDUCT.md)**

> **Licence:** [MIT](LICENSE).

## Quick start

Download the zip for each machine from the [latest release](https://github.com/shubhamyadav8901/sysdiag-mcp/releases/latest):
`windiag-win-x64` or `windiag-win-x86`, `linuxdiag-linux-x64`, `macdiag-osx-arm64` or `macdiag-osx-x64`, and `diagrelay-<platform>` for the
relay. Each carries a `SHA256.txt`, the licence and `THIRD-PARTY-NOTICES.md`. Every binary is self-contained, so no .NET install is needed.

In releases after v3.0.0, every zip and every executable in one has a build-provenance attestation: a signed record of the
commit and workflow run that built it. Check a download, or a binary already on a target, with the GitHub CLI:

```
gh attestation verify windiag-win-x64-v3.1.0.zip -R shubhamyadav8901/sysdiag-mcp
gh attestation verify C:/Tools/sysdiag/WinDiag.Mcp.exe -R shubhamyadav8901/sysdiag-mcp
```

This proves where a file came from. It is not OS code signing: the binaries are not Authenticode- or
Developer ID-signed, so SmartScreen and Gatekeeper still treat them as unsigned.

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
register the relay locally. See the [Windows](docs/windows.md#deploying-to-a-target-machine), [Linux](docs/linux.md) and [macOS](docs/macos.md) guides, and
[the relay](docs/relay.md). That channel is plaintext HTTP: keep
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
| `process_modules` | `Process.Modules` + PE headers + `WinVerifyTrust` | Which DLLs loaded, from where, whether anything unsigned got in, and which modules lost a base-address collision. Version and signature are read from the file the kernel names as behind each mapping, held open while it is read - not from the listed path, which may since hold another file (flagged replaced on disk). The kernel's name is the name the file was opened under and does not follow a rename of a directory above it, so it is trusted only where SYSTEM, Administrators and TrustedInstaller alone can change every directory on the path - a policy judgement, not a proof: a directory moved into place earlier, while permissions were looser, is not caught, and holders of the restore or take-ownership privilege can change any directory. A module whose file cannot be identified that way - under a user profile or temp directory, or on a share - is flagged, names the first directory anyone else can change, and is not verified. The verdict is on that file, not on the code in memory |
| `named_pipes` | `NtQueryDirectoryFile` + `WaitNamedPipe` | IPC pipes, and whether any has every instance taken and none listening for a client |
| `network_owners` | IP Helper | Which process owns which socket |
| `service_config` | SCM + services registry | Configured start type vs actual state, account, dependencies |
| `event_log_tail` | `EventLogReader` | What the machine complained about, filtered |
| `file_signatures` | `WinVerifyTrust` | Is this the binary we shipped |
| `effective_access` | Security descriptors + a real access attempt | Why is this denied |
| `registry_read` | Managed registry API, native view | What a setting is actually set to, in the view you meant. Available under every grant; HKLM\SAM, HKLM\SECURITY and other users' HKU hives need `--allow-arbitrary-read`, and values named like a credential are always redacted |
| `capture_dump` *(writes)* | `MiniDumpWriteDump` | Snapshot a process → hand the path to mcp-windbg. Never lsass, lsaiso or csrss (judged by the image in System32): they hold the machine's credentials |
| `capture_activity` *(writes)* | Sysinternals `Procmon` | Record file and registry activity for a few seconds |
| `query_activity` | streaming read of a capture | Filter that trace down to the operations that failed |
| `process_control` *(writes)* | Win32 process control | Terminate, suspend or resume a process — PID plus expected name, verified before acting. Terminate and suspend are refused for core processes (lsass, csrss, winlogon…), for any process Windows marks critical, and for the host of any service `service_control` refuses to stop; resume never is |
| `service_control` *(writes)* | SCM | Start, stop or restart a service; refuses to stop or restart a small set of critical ones, by short or display name |
| `update_self` *(writes, opt-in)* | hash-verified binary replacement | Replace this server's own executable and restart it, without touching the target by hand. Finishes the calls already running before it restarts, refusing new ones meanwhile; `force` skips that and cuts them off. It is also the one tool a draining server still accepts, so calling it again with `force` stops the wait |
| `run_command` *(writes, opt-in)* | arbitrary shell (cmd / powershell / direct) | Run any command as the server's account — for git, builds, Klocwork, anything the other tools do not cover |
| `put_file` *(writes)* | hash-verified file write over HTTP | Stage a file on the target without an SMB share — server updates, Sysinternals binaries, inputs; scoped to the artifact directory unless arbitrary write is enabled, and to the server's own folder only with the self-update grant |
| `get_file` | hash-verified sliced file read over HTTP | Pull a file *back* without an SMB share — the dump or trace a capture wrote; same scoping. For anything large, drive it with the relay's [`pull_file`](docs/relay.md#moving-files-without-spending-context) or `tools/fetch-from-target.ps1` rather than calling it directly, so the bytes stay out of the caller's context |

## Requirements

| Component | Runs on |
|---|---|
| `WinDiag.Mcp` — the diagnostics server | **Windows only**, x64 or x86. Its tools are Windows primitives: the registry, the SCM, the event log, Authenticode, Sysinternals. |
| `DiagRelay.Mcp` — the local relay | **Windows** and **Linux**: verified end to end against live Windows targets — pre-connect, forwarded calls, and a byte-identical `push_file`/`pull_file` round trip — and the full test suite passes on a real Linux runtime (`tools/test-linux.sh`). **macOS**: its test suite runs on Apple Silicon in CI's `macos-latest` job. |

The relay is what lets a Mac or Linux machine drive Windows targets. Build it for the machine you are on:

    dotnet publish src/DiagRelay.Mcp -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -o artifacts/diagrelay

## Security, in short

Read [docs/security.md](docs/security.md) before putting a server on a network. The essentials:

- **The bearer token is the whole boundary.** A server runs elevated, and with the token a caller gets
  whatever its grants allow — with command execution, that is the server's own privilege level.
- **The channel is plaintext HTTP; there is no TLS.** The token and every tool result cross the wire in
  the clear. Keep targets on a network you trust, or tunnel the port (WireGuard, SSH, an mTLS proxy).
- **Grant only what a run needs.** Command execution, self-update and reads or writes outside the
  server's own directories are each off until their own flag turns them on, and `--read-only` removes
  every state-changing tool.
- **Tool results are untrusted input** to the agent reading them: a hostile target controls the text it
  returns.

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.

## Documentation

| Page | What it covers |
|---|---|
| [Windows targets](docs/windows.md) | Running WinDiag, deploying it, the admin share, verifying on a target, installing it as a service with every `--install-service` option, and bringing up a machine that has never run it |
| [Linux targets](docs/linux.md) | LinuxDiag: install, grants and what each tool reads |
| [macOS targets](docs/macos.md) | MacDiag: install, Full Disk Access, signing and what each tool reads |
| [The relay](docs/relay.md) | One MCP registration for a fleet, `~/.sysdiag-targets.json`, and moving files without spending context |
| [Configuration](docs/configuration.md) | Every `WINDIAG_*`, `LINUXDIAG_*`, `MACDIAG_*` and relay variable, and its default |
| [Security](docs/security.md) | The threat model and what each defence is for |
| [Design notes and troubleshooting](docs/design-notes.md) | Behaviour worth knowing, and what each error means |
| [Contributing](CONTRIBUTING.md) | Building, testing, the source layout and releases |
