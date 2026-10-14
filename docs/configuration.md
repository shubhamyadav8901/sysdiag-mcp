# Configuration

## Configuration

The Linux server reads the same settings as `LINUXDIAG_*` -- `LINUXDIAG_READ_ONLY`, `LINUXDIAG_TOKEN` and so on -- with the same meanings and defaults, except that its artifact directory defaults to `/var/lib/linuxdiag`.
`LinuxDiag.Mcp --help` lists them.

The macOS server reads them as `MACDIAG_*`, from its `--env-file` laid over the environment. They have the
same meanings, except:

- its artifact directory defaults to `/var/db/macdiag`;
- `MACDIAG_SERVICE_LABEL` names its launchd job;
- `MACDIAG_PROTECTED_LABELS` adds launchd labels, comma-separated, that `service_control` refuses to stop or restart and whose main process `process_control` refuses to signal. An entry is an exact label, or a prefix ending in `.` (`com.corp.`); a pattern such as `com.corp.*` stops the server at startup rather than protecting nothing. Add the labels of any remote-access tool the Mac is reached through that the built-in list misses - AnyDesk, RealVNC, Splashtop, ScreenConnect, Zscaler, Cloudflare WARP.

`MacDiag.Mcp --help` lists them.

| Variable | Default | Meaning |
|---|---|---|
| `WINDIAG_READ_ONLY` | `false` | `1`/`true` drops all state-changing tools from registration |
| `WINDIAG_ALLOW_SELF_UPDATE` | `false` | `1`/`true` registers `update_self`, and lets `put_file` write into the server's own directory to stage a build. Gated separately because it lets the bearer token replace an elevated binary -- or plant a Sysinternals tool or DLL beside it, which the server would run; `WINDIAG_READ_ONLY` still overrides it |
| `WINDIAG_ALLOW_COMMAND_EXECUTION` | `false` | `1`/`true` registers `run_command`, turning the bearer token into an arbitrary shell as the server's account. The heaviest grant here; `WINDIAG_READ_ONLY` overrides it. Off unless a deployment deliberately needs it |
| `WINDIAG_ALLOW_ARBITRARY_WRITE` | `false` | `1`/`true` lets `put_file` write anywhere, the server's own directory included. `put_file` itself is always available on a writable server, scoped to the artifact directory; this widens it to anywhere as the server's account. `WINDIAG_READ_ONLY` overrides it |
| `WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS` | `120` | Budget per external tool call (1–3600) |
| `WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS` | `1800` | How long `update_self` waits for running tool calls to finish before restarting anyway (1–86400). A backstop, not a schedule: on an idle target the wait is milliseconds. 30 minutes clears `capture_activity`'s ~21-minute worst case, which is the call most likely to be running when you update. A full-length `run_command` can exceed it — raise this, or pass `force` |
| `WINDIAG_ALLOW_ARBITRARY_READ` | `false` | `1`/`true` lets `get_file` and `query_activity` read *outside* windiag's own directories. It always reads inside them — which includes the artifact directory, so retrieving a dump or a trace needs no flag. This widens it to anything the elevated account can open, i.e. exfiltration, so it is off by default. Without it, every read tool that opens a path it is given (`get_file`, `who_locks_path`, `file_signatures`, `effective_access`, `query_activity`) also refuses a network share or device path — `\\host\share`, `\\?\UNC\`, `\\.\`, a mapped network drive — because opening one makes the server sign in to that host as its machine account. `put_file` reaches one only with `WINDIAG_ALLOW_ARBITRARY_WRITE`, which already lets it write anywhere. Unlike the write grant, `WINDIAG_READ_ONLY` does **not** override it — reading is what a read-only server is for |
| `WINDIAG_MAX_RESULTS` | `50000` | Row cap per tool call (1–10000000). High so handle-heavy tools aren't truncated; lower it if one call's output is too large for your client. |
| `WINDIAG_HTTP_BIND` | — | Address to serve on; equivalent to `--http` |
| `WINDIAG_TOKEN` | generated | Bearer token for HTTP mode. A service `--install-service` registered reads it from `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters` instead, and falls back to this variable only when that key has none |
| `WINDIAG_ARTIFACT_DIR` | `%TEMP%\windiag` | Where dumps and traces are written. Neither it nor the server's own folder may be reached through a mounted folder, a junction to a device, or a relative symbolic link: `get_file` and `put_file` cannot tell where such a link lands, so they refuse every transfer. Run as a service, windiag goes further and refuses to start when either is, or is reached through, any link, or sits below a directory someone other than SYSTEM and Administrators could rename (see the service section) |
| `SYSDIAG_RELAY_FILE_ROOT` | a per-user `sysdiag` folder: `%TEMP%\sysdiag` on Windows, `$XDG_CACHE_HOME/sysdiag` or `~/.cache/sysdiag` elsewhere — never the shared `/tmp`; plus the `artifacts` directory when the relay runs from `artifacts/diagrelay` | **Relay only.** Semicolon-separated local directories `push_file` may read from and `pull_file` may write to, *replacing* the defaults rather than adding to them. This is the boundary that stops one tool call copying an arbitrary local file onto a target, so widen it deliberately. The `artifacts` default exists because a relay published to `artifacts/diagrelay` sends the builds beside it in `artifacts/win-x64`; anywhere else — `~/bin`, an unpacked release zip, `dotnet run` — it does not apply, so set this to push builds from another folder |

Booleans are strict: `1/true/yes/on` or `0/false/no/off`. A misspelling fails startup rather than
silently defaulting, because the flag removes capability.

Diagnostics go to **stderr only**. stdout carries the MCP protocol and nothing else; a test asserts it.
