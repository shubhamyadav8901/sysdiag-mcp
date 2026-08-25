# Changelog

All notable changes to windiag are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Versions before `v1.0.0` were tagged
retroactively, at the commits that actually shipped something, so the history reads as releases
rather than as a commit dump.

For a server whose whole job is answering questions about a live machine, "changed" means the answer
changed. Entries therefore say what a caller now sees, not only what moved in the code — and where a
release fixed something that had been silently wrong, it says what the wrong answer looked like.

## [Unreleased]

### Added

- **The executable installs itself as a service.** `--install-service`, `--uninstall-service` and
  `--service-status`, asking Windows for elevation when it does not already have it. It configures
  what is easy to lose by hand: the token generated and written to the service's own registry key
  rather than anywhere a local user can read, SCM restart-on-failure, the artifact directory pinned
  so captures do not silently move to `C:\Windows\SystemTemp`, the grants carried across so a
  re-registered server does not come back with fewer tools, and a firewall rule scoped to one
  address and removed again on uninstall.
- `--service-status` reports whether this machine runs windiag by hand or as a service, and how it
  is configured. The two look identical from outside and behave differently on every restart.

### Known limitations

- **`update_self` has not been proven to work on a server running as a service.** Install, uninstall,
  status, and every tool through a service are verified on a target; `update_self` against one fails
  with an exception that has not yet been identified, and the helper never reaches the point of
  writing its script. It is safe rather than destructive -- the commit claim is released, the binary
  is untouched and the service stays running -- but it means a service-registered target must be
  updated with `sc stop`, replace the file, `sc start` until this is resolved.

### Fixed

- **`update_self` on a service-registered target no longer desynchronises the SCM.** The restart
  helper relaunched the executable, which starts a process the Service Control Manager knows nothing
  about: the service reads as Stopped while something holds its port, and `service_control start`
  then fails because the port is taken. It now issues `sc start` when the server is running as a
  service, and still launches the executable when it was started by hand.

### Added

- Project metadata: changelog, contributing guide, security policy, code of conduct, editor
  settings, CI workflow, and issue/PR templates.

## [1.3.0] - 2026-08-21

### Added

- **The same executable can run as a Windows service.** `AddWindowsService()` on the existing
  generic host, so `sc create` works and — the point of it — `service_control` can restart a target
  **remotely**. Until now a server that died, or one you stopped, needed somebody at that machine's
  console.

### Verified

- **Session 0 imposes no limits.** Procmon captures with no interactive desktop, measured as a
  SYSTEM scheduled task on a 32-bit and a 64-bit VM (68,849 and 202,908 events) and again from a
  real service (67,423). A note claiming `capture_activity` needed a desktop was wrong.

### Notes

- Running by hand is unchanged and tested: `AddWindowsService()` is inert unless the SCM started the
  process, and a test fails if a service lifetime ever appears interactively.
- As a service, `%TEMP%` becomes `C:\Windows\SystemTemp` — pin `WINDIAG_ARTIFACT_DIR`.
- Put the token in the service's own registry `Environment` value, which is ACL'd to SYSTEM and
  Administrators. A machine-wide variable is readable by every local user.

## [1.2.1] - 2026-08-21

### Fixed

- `path_handle_search` and `process_handles` no longer offer mapped sections as a reason to re-run
  with `includeAllObjectTypes=true`. Without `-a`, handle.exe returns *file references* — file
  handles **and** the sections backing them — so that advice sent callers into a measured 6m40s
  sweep for rows they already had, and implied the fast search could not see a memory-mapped holder,
  which is precisely the holder `who_locks_path` misses.

## [1.2.0] - 2026-08-21

### Changed

- **`update_self` finishes what the server is doing before it restarts.** It waits for in-flight
  tool calls, refusing new ones so the server is guaranteed to reach idle, bounded by
  `WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS` (default 1800). Previously it cut work off after an
  inherited 30-second framework default: a 90-second capture died at ~56s, the caller got a raw
  transport error rather than a result, and a 256 MB partial trace was orphaned.

### Added

- `force` on `update_self` for the old behaviour, now an explicit choice. `update_self` is also the
  one tool a draining server still accepts, so a wait can be escalated rather than stranding you.
- `WINDIAG_UPDATE_DRAIN_TIMEOUT_SECONDS` (1–86400, default 1800), sized to `capture_activity`'s
  ~21-minute worst case.

### Fixed

- A failed helper launch no longer bricks every later update by leaving the commit claim set.
- `deploy-target.ps1` no longer reports a successful deploy of a build it never installed: a refused
  `update_self` writes nothing to stdout and does not throw, so it used to fall through to a poll
  answered by the old server.

## [1.1.0] - 2026-08-20

### Added

- **`push_file` and `pull_file` on the relay**, moving whole files without their bytes entering the
  conversation. `put_file`/`get_file` carry bytes as tool arguments and results, so an agent-driven
  transfer of a 46 MB build is ~63 MB of base64. The relay reads from local disk and streams instead:
  101 MB moved for a single tool call.
- `WINDIAG_RELAY_FILE_ROOT`, confining what the relay may read and write locally. This is the first
  thing the relay does that touches local disk, so it reuses `FileScope` rather than a second copy.

### Fixed

- The relay's default build root pointed one level too deep and therefore at a directory that does
  not exist, so pushing a build required setting the variable — exactly the inert-by-default state
  the design argued against.

## [1.0.0] - 2026-08-19

First release in which **every tool can actually be called from an MCP client.**

### Fixed

- **Seven tools were unusable and returned correct answers the client threw away.** The output
  schema marks every constructor parameter without a default as required, while the SDK's serializer
  omits nulls — so any response with a null in it failed validation against the schema the server
  itself advertised. `system_overview` (an unlabelled volume), `file_signatures` (an unsigned file),
  `network_owners` (a listening socket), `process_list`, `process_modules`, `autostart_audit` (on
  its *default* arguments) and `effective_access` were all affected. `process_list` mattered most:
  nearly every other tool's description tells the caller to get a PID from it.

### Added

- A test that walks from every `[McpServerTool]` method to the records it can return and asserts
  each one serializes completely — the check that would have caught all seven, and which nothing
  did.

## [0.8.0] - 2026-08-19

### Added

- `get_file`: retrieve a capture or dump over the server's own channel, so collecting an artifact
  needs no SMB share either. `tools/fetch-from-target.ps1` drives it and streams straight to disk.
- `query_activity` filters on the `Detail` column server-side.

### Fixed

- `who_locks_path` failed outright whenever it actually found a holder — the one case anybody calls
  it for. It had survived a full sweep because every earlier call pointed at a path with no holders.
- A refused `put_file` chunk is retried on its own rather than restarting the whole transfer.
- A capture with no `Detail` values no longer reads as "nothing matched".

## [0.7.0] - 2026-08-18

### Added

- **`--relay`**: one local stdio MCP server that forwards to any target at runtime, so a fleet of lab
  VMs on changing addresses needs one client registration instead of one per machine. Several
  targets connect at once, each prefixed by an alias.
- Targets pre-connect at launch from `%USERPROFILE%\.windiag-targets.json`, so their tools are in the
  very first `tools/list` — which is what clients that read the tool list only at startup require.

## [0.6.0] - 2026-08-17

### Added

- `put_file`, staging files over the server's own authenticated channel instead of the SMB admin
  share, in hash-verified 4 MB chunks. A single ~57 MB base64 body is more than a 32-bit server can
  decode at once, and a per-chunk hash catches a corrupt chunk at the chunk.
- `deploy-target.ps1`: one command that publishes, stages, verifies by hash on both sides, records
  what it staged, and asks the server to replace itself.

## [0.5.0] - 2026-08-16

### Added

- `run_command`, an opt-in arbitrary-command tool behind its own flag — the escape hatch for git,
  build tools and anything the diagnostics do not cover.

## [0.4.0] - 2026-08-15

The full tool surface, verified on both bitnesses.

### Added

- `autostart_audit`, `process_handles`, `process_modules`, `registry_read`, `process_control`,
  `service_control`, and readable tool errors.

### Fixed

- A broken autostart hook no longer renders as a healthy one.
- 32-bit Windows is no longer told it is reading `WOW6432Node`, which it does not have.

## [0.3.0] - 2026-08-14

### Added

- `update_self`: replace the server's own executable and restart, for a target reachable by file copy
  but not by remote execution. Hash-checked, signature-ratcheted, and handed to a detached helper so
  a failure restarts the existing build rather than leaving nothing running.

## [0.2.0] - 2026-08-13

### Added

- Architecture-aware Sysinternals resolution, and `tools/verify-on-target.ps1` to prove the tools
  that cannot be faked actually work on the machine under test.
- `tools/mcp-call.ps1`, a minimal HTTP MCP client for driving a target from the base machine.

### Fixed

- The 32-bit `handle.exe` on 64-bit Windows answers "No matching handles found." to every query
  rather than failing — so the wrong build looked like a clean result. It is now chosen by the
  target's architecture.

## [0.1.0] - 2026-08-12

### Added

- windiag: a Windows diagnostics MCP server answering live-machine questions a debugger structurally
  cannot — who holds this file, what is the machine doing, why is this access denied, what runs
  without being started. Both transports, stdio locally and authenticated Streamable HTTP on a
  target.

[Unreleased]: https://example.internal/windiag/compare/v1.3.0...HEAD
[1.3.0]: https://example.internal/windiag/compare/v1.2.1...v1.3.0
[1.2.1]: https://example.internal/windiag/compare/v1.2.0...v1.2.1
[1.2.0]: https://example.internal/windiag/compare/v1.1.0...v1.2.0
[1.1.0]: https://example.internal/windiag/compare/v1.0.0...v1.1.0
[1.0.0]: https://example.internal/windiag/compare/v0.8.0...v1.0.0
[0.8.0]: https://example.internal/windiag/compare/v0.7.0...v0.8.0
[0.7.0]: https://example.internal/windiag/compare/v0.6.0...v0.7.0
[0.6.0]: https://example.internal/windiag/compare/v0.5.0...v0.6.0
[0.5.0]: https://example.internal/windiag/compare/v0.4.0...v0.5.0
[0.4.0]: https://example.internal/windiag/compare/v0.3.0...v0.4.0
[0.3.0]: https://example.internal/windiag/compare/v0.2.0...v0.3.0
[0.2.0]: https://example.internal/windiag/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.internal/windiag/releases/tag/v0.1.0
