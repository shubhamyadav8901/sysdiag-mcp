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

## What it answers

**Current release: `v3.0.0`.** See the [changelog](CHANGELOG.md) for what each version changed.

The three servers answer the same questions with each platform's own primitives, under the same tool
names, so an agent asks a Linux box and a Windows box alike.

| Question | Tool | Windows | Linux | macOS |
|---|---|:-:|:-:|:-:|
| Who holds this file open or locked | `who_locks_path`, `path_handle_search` | ✓ | ✓ | ✓ |
| What one process holds and has loaded | `process_handles`, `process_modules` | ✓ | ✓ | ✓ |
| What is running, from what command line | `process_list` | ✓ | ✓ | ✓ |
| Which process owns this socket or pipe | `network_owners`, `named_pipes` | ✓ | ✓ | ✓ |
| How a service is configured, and its state | `service_config` | ✓ | ✓ | ✓ |
| What the machine logged | `event_log_tail` | ✓ | ✓ | ✓ |
| What runs without anyone starting it | `autostart_audit` | ✓ | ✓ | ✓ |
| Is this the binary we shipped | `file_signatures` | ✓ | ✓ | ✓ |
| Why is this access denied | `effective_access` | ✓ | ✓ | ✓ |
| What is this machine, and what can the server see | `system_overview`, `capabilities` | ✓ | ✓ | ✓ |
| Which containers are running | `container_list` | | ✓ | ✓ |
| What a registry setting really is | `registry_read` | ✓ | | |
| Snapshot a process for a debugger | `capture_dump` *(writes)* | ✓ | | |
| Record and filter file and registry activity | `capture_activity`, `query_activity` | ✓ | | |
| Start, stop or restart a service; signal a process | `service_control`, `process_control` *(writes)* | ✓ | ✓ | ✓ |
| Move files to and from the target | `put_file` *(writes)*, `get_file` | ✓ | ✓ | ✓ |
| Run a command; replace the server itself | `run_command`, `update_self` *(writes, opt-in)* | ✓ | ✓ | ✓ |

Write tools disappear under `--read-only`, and the opt-in ones need their own grant. Each server's page
lists its tools with what backs each one: [Windows](docs/windows.md#tools), [Linux](docs/linux.md),
[macOS](docs/macos.md).

## Requirements

| Component | Runs on | For complete answers |
|---|---|---|
| `WinDiag.Mcp` | Windows, x64 or x86 | Run elevated; four tools also need Sysinternals, which `tools/deploy-target.ps1` stages |
| `LinuxDiag.Mcp` | Ubuntu and Debian, x86-64 only | Run as root |
| `MacDiag.Mcp` | macOS 13 or later, Apple Silicon or Intel | Run as root, with Full Disk Access |
| `DiagRelay.Mcp` | Windows x64, Linux x64, macOS on Apple Silicon | Nothing: it only forwards calls |

Every binary is self-contained. Run with less, a server still answers, says its answer is partial, and
`capabilities` names what is missing.

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
