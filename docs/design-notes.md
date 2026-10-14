# Design notes and troubleshooting

## Behaviour worth knowing

**A LinuxDiag walk of /proc can wait behind a process stuck in the kernel.** Reading a process's command line or memory map takes a lock that a process blocked on a dead NFS server or a hung FUSE mount holds, and the read waits for it; there is no per-process timeout. If a `process_list` or `path_handle_search` call hangs on such a host, that is the cause - the tool call's own timeout still ends it.

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

**`path_handle_search` searches file references only unless you ask for more.** handle.exe without
`-a` "will dump all file references" and nothing else — no registry keys, no mutants, no events.
"File references" is broader than `File` handles though, and the row counts say so: measured on a
single process, 380 rows and **2 object types** without `-a`, those two being `File` and `Section`.
A section backing a file *is* a reference to it, so a holder that only memory-mapped the file is
already covered by the default — which matters, because a mapped section is exactly the holder
`who_locks_path` cannot see. With `-a`: 12007 rows and 25 types, including 3218 registry `Key` rows.

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


## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `'handle.exe' was not found on this machine` | Sysinternals Suite is not installed. Native-backed tools still work. |
| `'…\handle64.exe' is beside the server but is not signed by Microsoft` | The copy in the server's folder is damaged or was not Microsoft's. Replace it from `download.sysinternals.com` (or re-run `deploy-target.ps1`), or delete it to use an installed copy. |
| `--install-service`: `The server directory … can be changed by accounts other than SYSTEM and Administrators … Nothing was installed` (or `The artifact directory …`) | The directory exists and someone other than an administrator can change it or something in it — a folder made by hand under `C:\`, or one a user made before you did. The installer no longer takes such a directory over, because a handle opened on it beforehand would outlast that. For `--artifacts`, rename it aside or name one that does not exist yet: the installer creates it restricted. For the server, copy `WinDiag.Mcp.exe` into a directory created restricted — `md "%ProgramFiles%\WinDiag"` from an elevated prompt, or the bootstrap scripts' `C:\WinDiag` — and install from there. |
| A service refuses to start: `… can be renamed or removed, or what it holds removed, by accounts other than SYSTEM and Administrators` | The server's or the artifact directory sits below a directory someone else could rename and replace — typically a folder made under `C:\` or `D:\`, which every user inherits *Modify* on, or one whose owner is an account outside the local Administrators group (an owner can grant itself any right, whatever the ACL says). The event log names the directory and who can change it. Remove the rights it names; if it says an account `owns it`, hand the directory to the group with `icacls <dir> /setowner *S-1-5-32-544`. Or move windiag to `C:\WinDiag` and `--artifacts C:\WinDiagArtifacts`. Then start the service again (`sc.exe \\<host> start <service>`): once its restart retries are spent it stays stopped, and nothing over port 4024 can reach it. |
| `The owned directory '…' cannot be judged` on every `get_file` / `put_file` | The artifact directory or the server's folder sits under a folder a volume is mounted at (a data disk mounted at `C:\Data`), a junction to a device, or a relative symbolic link. .NET does not report where such a link really lands, so nothing under it can be judged owned. Move the directory: give the disk a drive letter and set `--artifacts` to a directory on that letter. |
| `path_handle_search` warns about partial results | Not elevated. Restart the server from an elevated terminal. |
| `who_locks_path` finds nothing on a file you know is locked | Expected: Restart Manager is not exhaustive. Run `path_handle_search`. |
| `handle.exe did not finish within 120s` | Search term too broad. Narrow it, or raise `WINDIAG_EXTERNAL_TOOL_TIMEOUT_SECONDS`. |
| `handle.exe produced a CSV layout this parser was not written for` | An invocation change altered the row shape. See the layout note above — do not "fix" it by loosening the parser. |
| `configuration error` on startup | A `WINDIAG_*` value is malformed; the message names the variable. |
