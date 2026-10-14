# Contributing to sysdiag

sysdiag answers questions about a live machine, usually an elevated one, often somebody else's. That
shapes the rules below more than any style preference does: a wrong answer here is worse than no
answer, because the caller acts on it.

## The one rule that matters

**A tool must never answer confidently when it could not actually see.** Several of this project's
worst bugs were silent successes, not failures:

- the 32-bit `handle.exe` on 64-bit Windows answers *"No matching handles found."* to every query,
- an 89 MB copy to a lab VM arrived at exactly the right size and was corrupt, twice,
- seven tools returned correct answers that the client discarded, because a null was omitted from
  JSON the server's own schema said was required.

None of these looked like errors. If a result can be incomplete, say so in the result — that is what
`capabilities`, the `Degraded` status and the coverage caveats in the summaries exist for.

## Getting set up

```
dotnet build -warnaserror
dotnet test tests/WinDiag.Mcp.Tests          # offline; never touches the live machine
dotnet test tests/Diag.Mcp.Server.Tests      # the shared server kit; also runs on Linux
dotnet test tests/DiagRelay.Mcp.Tests        # the relay
dotnet test tests/LinuxDiag.Mcp.Tests        # the Linux server; its [LinuxFact] tests run through tools/test-linux.sh
dotnet test tests/MacDiag.Mcp.Tests          # the macOS server; its [MacFact] tests run only on a Mac (CI's macos-latest)
dotnet test tests/WinDiag.Mcp.OnTarget       # creates real locks on this machine
```

All but the last must be clean before you push; the shared kit and the relay also run on Linux through
`tools/test-linux.sh`. `tests/WinDiag.Mcp.OnTarget` needs a real Windows target and is not part of the
normal loop. It skips its elevated cases with a stated reason when run unelevated or without
Sysinternals installed, rather than failing or silently passing.

Run it locally over stdio:

```
dotnet run --project src/WinDiag.Mcp
```

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

## Testing

Unit tests cover what can be faked. Two things cannot: the tools that shell out to Sysinternals, and
anything whose answer depends on the machine's bitness. For those, `tools/verify-on-target.ps1`
drives the **published** server over stdio on a real target, and every check is self-verifying — the
script creates the thing it then goes looking for, so a pass cannot be a coincidence.

Follow that pattern when you add a test. Asserting that a tool returned *something* is close to
worthless here; assert that it returned the thing you deliberately created.

Prefer a test that fails for the right reason over a test that passes. If you fix a bug, first make
the suite fail, then fix it — and say in the test comment what the failure looked like from the
caller's side. Several tests in this repo exist because a previous fix could be deleted with the
suite still green; that is the failure mode worth guarding against.

## Style

`.editorconfig` carries the formatting rules; the build treats warnings as errors. Beyond that:

- **Comments explain why, not what.** The code says what. A comment earns its place by recording the
  thing the next reader cannot see: the failure that motivated the design, the option that was
  rejected, the measurement behind a constant.
- **Error messages are the product.** Say what happened, what was *not* changed, and what to do
  next. `"An error occurred"` is a bug report from the future.
- **Numbers in comments should be measured, not guessed.** If you write a timeout, say what you
  timed.

## Commits

One change per commit, present tense, describing the effect rather than the edit:

> `Stop a Detail-less capture reading as "nothing matched"`

The body is where the reasoning goes — what was wrong, what the caller saw, why this fix and not the
obvious one. Long bodies are welcome; the history is documentation.

## Pull requests

- Say how you verified it, with the command and its output. "Tests pass" is not evidence; the last
  line of `dotnet test` is.
- If it changes what a tool returns, update the tool's `[Description]`. Those strings are the API.
- If it changes behaviour a caller could notice, add a `CHANGELOG.md` entry under `Unreleased`.

## Releases

Tags are `vMAJOR.MINOR.PATCH`, annotated, on the commit that shipped the change. Bump `<Version>` in
`Directory.Build.props` — the one number the server and the relay both take their version from; file
and assembly versions are derived from it — move the `Unreleased` entries into a dated section, then
tag. Every section opens with a short summary, before its first `###`: two to four sentences on what the
release means for someone upgrading, then any upgrade steps and known issues, linked. That summary is the
release page:

```
git tag -a v1.4.0 -m "sysdiag v1.4.0" -m "<the changelog section>"
```

Pushing the tag runs the Release workflow. It builds and tests every server on its own OS, then
publishes a GitHub Release with one zip per binary, `SHA256SUMS.txt`, and notes made of the section's
summary, a link to the full section, and GitHub's list of the pull requests merged since the last release.
`tools/release-notes.sh <version>` prints the first two parts. Run the workflow by hand first: it does
everything except publish, and fails if `<Version>` has no changelog section or the section no summary.

MAJOR is for a change that breaks a caller — a tool removed, a result field's meaning changed, a
default that alters what an existing call returns.

## Security

Do not open an issue for a vulnerability. See [SECURITY.md](SECURITY.md).
