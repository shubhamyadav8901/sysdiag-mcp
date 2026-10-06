# Security Policy

## Reporting a vulnerability

**Do not open an issue or a pull request for a security problem.**

Report it privately through [GitHub's private vulnerability reporting](https://github.com/shubhamyadav8901/sysdiag-mcp/security/advisories/new), with:

- what an attacker can do, and what they need to start (network position, a token, local access),
- the smallest reproduction you have,
- the version or commit you saw it on.

You will get an acknowledgement within `<n>` working days.

## Supported versions

The newest tagged release is the supported one. Because targets are updated with `update_self`,
"upgrade" is usually a `deploy-target.ps1` run, so there is little reason to keep older versions
alive.

## What this software is

Read this before deciding whether something is a vulnerability, because sysdiag's normal behaviour
looks alarming out of context.

sysdiag is a set of diagnostics servers that **run elevated by design** and expose tools that read process
memory, handles, the registry, ACLs and file contents. Two tools are gated behind their own flags
because they are far more than diagnostics. Settings are named here with the Windows server's
`WINDIAG_` prefix; LinuxDiag and MacDiag use the same settings with `LINUXDIAG_` and `MACDIAG_`.

| Grant | Default | What it really is |
|---|---|---|
| `WINDIAG_ALLOW_COMMAND_EXECUTION` | off | Arbitrary code execution as the server's account |
| `WINDIAG_ALLOW_SELF_UPDATE` | off | Replacing the server's own elevated binary, and running it; `put_file` into the server's own folder, whose binaries and DLLs it runs |

With either enabled, **the bearer token is equivalent to code execution on that host.** That is
intended, documented, and the reason both are off unless a deployment explicitly turns them on.

## The threat model is not only the network

The server runs elevated, so a local unprivileged user is inside the threat model too. Things that
follow from that, and which are deliberate rather than oversights:

- **A running server reads the token from the environment only, never a command-line argument.** Each
  server's own `process_list` shows command lines to every local user on the machine; a token passed as
  an argument would be readable by the people it is meant to exclude. The installers accept `--token`
  for convenience, which is visible while the installer runs; `--token-stdin` is not, and is what every
  bootstrap script uses.
- **As a Windows service, the token belongs in the service's own registry `Environment` value**, which
  `--install-service` restricts to SYSTEM and Administrators before writing it — `sc create` alone
  leaves the key readable by every local user, and a service restricts its own key on start if it
  finds it that way. A machine-wide environment variable is readable by every local user and is *not*
  an acceptable substitute. LinuxDiag and MacDiag keep it in a root-owned `0600` env file instead
  (`/etc/linuxdiag/linuxdiag.env`, `/etc/macdiag/<label>.env`).
- **The directories a Windows service runs code from are writable only by SYSTEM and Administrators.**
  The server runs Sysinternals binaries from beside itself and `self-update.cmd` from its artifact
  directory, and a folder made under `C:\` inherits *Authenticated Users: Modify*. The installer and the
  bootstrap scripts give both directories a protected ACL, and a service checks again on every start and
  refuses to run from one it cannot restrict.
- **There is no default bind address.** `--http` with nothing to bind to is refused rather than
  quietly listening on `0.0.0.0`.
- **File access is confined** to directories the server owns, on both the read and write sides, through
  one shared check rather than two copies. Widening it is opt-in
  (`WINDIAG_ALLOW_ARBITRARY_WRITE`, `WINDIAG_ALLOW_ARBITRARY_READ`) because reading anywhere the
  elevated account can reach is exfiltration.
- **`registry_read` is available under every grant, read-only included,** and reads whatever the
  server's account can. HKLM\SAM, HKLM\SECURITY and other users' hives under HKU need
  `WINDIAG_ALLOW_ARBITRARY_READ`, and a value named like a credential -- a windiag instance's own
  `WINDIAG_TOKEN` in its service key's `Environment` among them -- is returned redacted under every grant.
- **A dump is a read of a process's memory.** `capture_dump` writes into the artifact directory, which
  `get_file` reads without `WINDIAG_ALLOW_ARBITRARY_READ`, so a writable server's token can read the
  memory of any process the server can open -- SYSTEM services included. The processes that hold the
  machine's credentials (`lsass`, `lsaiso`) are refused outright, with no grant to turn it back on;
  `WINDIAG_READ_ONLY` removes the tool entirely.
- **A signed server refuses an unsigned replacement, or one from another publisher.** On Windows the
  self-update signature check is a ratchet, not a setting: unsigned development builds keep working,
  but a target already running a signed build accepts only a validly signed replacement whose signer
  matches its own, and cannot be downgraded to an unsigned one through that path. It narrows what
  `update_self` installs, not what the grant allows: the same grant opens the server's folder to
  `put_file`, and a DLL placed there loads at the next start whatever the ratchet accepted.

## Traffic is not encrypted

Stated plainly because everything else in this file is about protecting the token, and this is the
one place that protection stops.

sysdiag serves **plaintext HTTP. There is no TLS support.** Consequences, all of them intended in a
trusted-segment deployment and all of them dangerous outside one:

- The bearer token is sent in an `Authorization` header on every single call. A passive observer on
  the path captures it, and where either grant above is enabled, **the token is equivalent to code
  execution on that host** as an elevated account.
- Tool results are equally exposed: file contents, memory dumps, registry values, event-log text and
  `run_command` output all cross the wire in the clear.
- The SHA-256 hashing on `put_file`, `get_file` and the relay's chunked transfers gives **integrity,
  not confidentiality.** It reliably catches a truncated or corrupted copy — which is why it exists —
  but an attacker who can modify traffic can recompute the hashes.
- `--firewall-from` restricts which address may *connect*. It does nothing about observation of
  traffic in flight, and nothing about an attacker already on the path.

**What that requires of a deployment.** Run it on a management network you already trust, scoped to
one address, and do not route it across an untrusted one. Where confidentiality on the wire is
needed, put sysdiag behind a tunnel — WireGuard, an SSH forward, an mTLS reverse proxy — rather than
treating the scoped port as sufficient.

Two adjacent paths *are* encrypted, which is easy to confuse with the above: WinRM on 5985 looks like
plaintext HTTP but Negotiate/Kerberos encrypts the payload at the message level, so
`tools/bootstrap-winrm.ps1` transfers are protected; SMB staging is authenticated and signed, with
encryption depending on the target's SMB configuration. Neither changes the sysdiag channel itself.

## What we would consider a vulnerability

- Reaching any tool without a valid bearer token, or a token comparison that leaks its length or
  content through timing.
- Escaping the file-scope confinement without the arbitrary-read/write grant.
- Getting `update_self` to install a binary whose hash the caller did not supply, or to bypass the
  signature ratchet.
- Any path by which a **local unprivileged** user obtains the token, or gets the elevated server to
  act on their behalf.
- Command or argument injection into a shelled-out Sysinternals tool.

## What we would not

- That an authenticated caller can run commands when `WINDIAG_ALLOW_COMMAND_EXECUTION` is on. That
  is the feature.
- That an elevated server can read privileged data. That is the point of it.
- Anything requiring administrator rights on the host to set up — an attacker who is already
  administrator does not need sysdiag.
- That the channel is unencrypted, on its own. It is documented above and it is a real limitation, not
  an oversight — so it needs no report, and a report of it will be closed as known. What we *do* want
  is anything that makes it worse than stated: a token reaching a log, a crash dump, an error
  response, or any channel the section above does not already say it travels on.
