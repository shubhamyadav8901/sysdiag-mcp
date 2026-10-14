# The relay

## One stable MCP entry for a fleet of targets — the relay

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


## Moving files without spending context

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
per-user artifact folder plus, in a build tree, the tree the relay sits in; a `..` is judged by where it lands,
and a link by where it leads.

The per-user folder is `%TEMP%\sysdiag` on Windows and `$XDG_CACHE_HOME/sysdiag` or `~/.cache/sysdiag`
elsewhere. The build tree is added only when the relay runs from `artifacts/diagrelay` (or
`artifacts/diagrelay-<rid>`): there the root is `artifacts`, so `push_file` can send the builds that sit
beside it in `artifacts/win-x64` out of the box. Anywhere else — `~/bin`, an unpacked release zip, under
`dotnet run` — the per-user folder is the only default, because the folder above an ordinary install is
the home directory or `Downloads`, and one `push_file` from there could send `~/.ssh` or the targets file
to a target. So with a release zip, copy what you push into the per-user folder, or set the variable to
a folder that holds only builds.

Use these instead of calling a target's `put_file`/`get_file` yourself for anything but a small file.
`fetch-from-target.ps1` still works and needs no relay, which is what makes it the right tool from a
plain shell; `deploy-target.ps1` still owns publishing, the pinned Sysinternals manifest and the drift
check, so a full deploy is still a script.
