# windiag — Windows diagnostics MCP server

Answers live-machine debugging questions that a debugger structurally cannot: who has this file
locked, what is the machine actually doing, why is this access denied, what is set to autostart.

It complements `mcp-windbg`, which owns post-mortem dump analysis. A debugger sees inside one
process; this server sees the machine.

## Status

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
| `update_self` *(writes, opt-in)* | hash-verified binary replacement | Replace this server's own executable and restart it, without touching the target by hand |
| `run_command` *(writes, opt-in)* | arbitrary shell (cmd / powershell / direct) | Run any command as the server's account — for git, builds, Klocwork, anything the other tools do not cover |
| `put_file` *(writes)* | hash-verified file write over HTTP | Stage a file on the target without an SMB share — server updates, Sysinternals binaries, inputs; scoped to windiag's own dirs unless arbitrary write is enabled |

## Build and test

```
dotnet build -warnaserror
dotnet test tests/WinDiag.Mcp.Tests          # offline; never touches the live machine
dotnet test tests/WinDiag.Mcp.OnTarget       # creates real locks on this machine
```

`WinDiag.Mcp.OnTarget` skips its elevated cases with a stated reason when run unelevated or without
Sysinternals installed, rather than failing or silently passing.

## Run

```
dotnet run --project src/WinDiag.Mcp                      # stdio
dotnet run --project src/WinDiag.Mcp -- --http http://127.0.0.1:7777
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
pinned in `tools/sysinternals.json`, verifies each one's SHA-256 *and* its Microsoft signature, copies
everything over the admin share re-checking the hash after each copy, records what it staged in
`windiag-staged.json` on the target, and then calls `update_self` and waits for the server to come
back. It finishes by printing any tool that is not fully available.

Without `-Token` it stages everything and prints the command to start the server by hand — which is
the first-run case, since there is nothing running yet to swap.

Two behaviours are deliberate and worth knowing:

- **A Sysinternals version change stops the deploy.** `download.sysinternals.com` always serves the
  latest build, so a pinned hash is how a version change gets *noticed* rather than absorbed. Re-run
  with `-AcceptUpstreamChange` to re-pin, and commit that as a deliberate bump.
- **`windiag-staged.json` is compared before it is rewritten.** A file someone replaced on the target
  by hand is reported as drift, not silently overwritten. That report is the point of the file.

The rest of this section is what the script automates, and what to do when it cannot be used.

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

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WINDIAG_READ_ONLY` | `false` | `1`/`true` drops all state-changing tools from registration |
| `WINDIAG_ALLOW_SELF_UPDATE` | `false` | `1`/`true` registers `update_self`. Gated separately because it lets the bearer token replace an elevated binary; `WINDIAG_READ_ONLY` still overrides it |
| `WINDIAG_ALLOW_COMMAND_EXECUTION` | `false` | `1`/`true` registers `run_command`, turning the bearer token into an arbitrary shell as the server's account. The heaviest grant here; `WINDIAG_READ_ONLY` overrides it. Off unless a deployment deliberately needs it |
| `WINDIAG_ALLOW_ARBITRARY_WRITE` | `false` | `1`/`true` lets `put_file` write outside the server's own directories. `put_file` itself is always available on a writable server, scoped to those dirs; this widens it to anywhere as the server's account. `WINDIAG_READ_ONLY` overrides it |
| `WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS` | `120` | Budget per external tool call (1–3600) |
| `WINDIAG_MAX_RESULTS` | `200` | Row cap per tool call (1–10000) |
| `WINDIAG_HTTP_BIND` | — | Address to serve on; equivalent to `--http` |
| `WINDIAG_TOKEN` | generated | Bearer token for HTTP mode |
| `WINDIAG_ARTIFACT_DIR` | `%TEMP%\windiag` | Where dumps and traces are written |

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

**`path_handle_search` searches files only unless you ask for more.** handle.exe without `-a` "will
dump all file references" and nothing else — no registry keys, no sections, no mutants. Measured on a
single process: 380 rows and 2 object types without `-a`; 12007 rows and 25 types with it, including
3218 registry `Key` rows.

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
