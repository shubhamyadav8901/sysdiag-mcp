# windiag — working notes for agents

A Windows diagnostics MCP server. One self-contained executable that serves MCP over stdio locally
or authenticated HTTP on a target machine, plus a separate cross-platform relay, DiagRelay.Mcp, that
forwards to a fleet of targets.

## Do not read source to answer a configuration question

Every operator-facing knob is documented, and the source is the slowest place to find it:

| Question | Answer lives in |
|---|---|
| What CLI options exist, including every `--install-service` flag | `WinDiag.Mcp.exe --help` — authoritative; `ServerBuilder.HelpText` is the same string — for the server. The relay's options are in `DiagRelay.Mcp --help`. |
| What `WINDIAG_*` variables exist and what each defaults to | README **Configuration** table, and each executable's `--help` |
| Which flag sets which variable | Two spellings of one setting: `--allow-arbitrary-read` → `WINDIAG_ALLOW_ARBITRARY_READ=1`, written into the service's own registry key |
| How to reach a machine that has never run windiag | README **Bringing up a machine that has never run windiag** |
| What each `-Grants` preset actually passes | Same section. `None` is `--read-only` alone and **cannot read files** |
| The `~/.windiag-targets.json` shape | README, under the relay |
| What a tool can and cannot do on a given machine | Call `capabilities` on it — it names the missing binary or the lost privilege |

If any of those is wrong or missing, **fix the doc in the same change**. A fact that exists only in a
parser is a fact the next person greps for; that has already cost one session an afternoon.

## Build, test, verify

```
dotnet build -warnaserror                 # 0 warnings is the gate, not just 0 errors
dotnet test tests/WinDiag.Mcp.Tests       # the offline suite; must be green before any commit
dotnet test tests/DiagRelay.Mcp.Tests     # the relay's suite; Unix-only tests report Skipped here
```

- **Gate on the exit code, never on grepping the output.** `dotnet build | grep "Error(s)"` *succeeds*
  when it finds `5 Error(s)`. That mistake put a red build into this history.
- `tests/WinDiag.Mcp.OnTarget` needs a real machine, administrator rights and a kernel driver. It does
  not run in CI — see `tools/verify-on-target.ps1`.
- Publishing is `-r win-x64` or `win-x86`, `--self-contained -p:PublishSingleFile=true`, into
  `artifacts/win-<arch>/`. The relay is its own net9.0 project, `src/DiagRelay.Mcp`, published to
  `artifacts/diagrelay/`. Test it on real Linux with `tools/test-linux.sh` through WSL — mode, lock and
  case-sensitivity tests only run there. **Invoke it from PowerShell or cmd, never Git Bash**: MSYS
  rewrites the `/mnt/d/...` argument into `C:/Program Files/Git/mnt/d/...` and the script is not found.
- **`dotnet test --filter Name~X` matches nothing under xUnit and still exits 0.** Filter by
  `FullyQualifiedName~X`, and read the summary for a non-zero `Total` before trusting a green run —
  otherwise a mutation check's "restored" run can pass without having run anything.
- **A dependency reached only by reflection must be an explicit `PackageReference`.** It will not
  otherwise survive to the published set, while the test host — which is not published — always has
  it, so the suite stays green and only the shipped build breaks. CI asserts the known cases.

## Things that are true and non-obvious

- **A diagnostic channel must never be able to break the thing it reports on.** Under the SCM there is
  no stderr, so logging goes to the event log; a sink that can throw took down `update_self` mid-run.
  Sinks are made safe or removed, never left to throw.
- **`update_self` waits for in-flight calls by default** and refuses new ones while draining, so a
  deploy can take minutes on a busy target. `force` cuts work off instead. A dropped connection is
  success, not failure.
- **Bind to `0.0.0.0` on a DHCP target.** A literal address stops resolving when the lease moves; the
  auto-start service then fails to bind, spends its restart retries, and the machine goes quiet weeks
  later looking unrelated. Prefer hostnames in the relay's targets file for the same reason.
- **The channel is plaintext HTTP and there is no TLS support.** The bearer token rides an
  `Authorization` header on every call, and tool results cross the wire in the clear. The chunk
  hashing on file transfers is integrity, not confidentiality. Never suggest this is encrypted, and
  never route a target across a network the operator does not trust; recommend a tunnel instead.
- **A relay-forwarded 401 after a target restarts means reconnect the alias, not a changed token.**
  Check with `tools/mcp-call.ps1` against the target directly before concluding anything.
- **`tools/mcp-call.ps1` exits 1 on a refusal without throwing.** Callers must check `-Raw` output for
  emptiness; a bare call falls through and reports success for work that never happened.
- **Native commands write status to stderr, PsExec entirely so.** Under
  `$ErrorActionPreference = 'Stop'`, `cmd 2>&1` turns a *successful* run into a terminating error, and
  one raised inside a `finally` replaces the real exception on its way out.

## House style

Read a few neighbouring files before writing. Briefly: comments say *why*, and specifically why the
obvious alternative is wrong — usually because it was tried and failed on a real machine. Tests have
long descriptive names and hand-written fakes, no mocking library. A test that cannot fail when the
fix is reverted is not a test: mutate the fix and watch it go red before trusting it.

`CONTRIBUTING.md` covers the dev loop, commit and release conventions.
