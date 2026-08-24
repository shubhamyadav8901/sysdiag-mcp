## What this changes

<!-- The effect on a caller, not the edit. If a tool's answer changes, say what it used to say. -->

## Why

<!-- What was wrong, or what could not be done before. Link the issue if there is one. -->

## How it was verified

<!-- Commands and their output. "Tests pass" is not evidence; the last line of dotnet test is.
     If it touches a tool that needs a real machine, say which target and what you saw there. -->

```
dotnet build -warnaserror
dotnet test tests/WinDiag.Mcp.Tests
```

## Checklist

- [ ] Build is clean with `-warnaserror`
- [ ] `dotnet test tests/WinDiag.Mcp.Tests` passes, and the output is pasted above
- [ ] If a tool's result or arguments changed, its `[Description]` is updated — those strings are the API
- [ ] If a caller could notice the change, `CHANGELOG.md` has an `Unreleased` entry
- [ ] If this fixes a bug, a test fails without the fix (say how you confirmed that)
- [ ] No secret, token or signing material is in the diff
