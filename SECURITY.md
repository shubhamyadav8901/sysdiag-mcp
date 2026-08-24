# Security Policy

## Reporting a vulnerability

**Do not open an issue or a pull request for a security problem.**

Report it to `<security contact — fill in>` with:

- what an attacker can do, and what they need to start (network position, a token, local access),
- the smallest reproduction you have,
- the version or commit you saw it on.

You will get an acknowledgement within `<n>` working days.

## Supported versions

The newest tagged release is the supported one. Because targets are updated with `update_self`,
"upgrade" is usually a `deploy-target.ps1` run, so there is little reason to keep older versions
alive.

## What this software is

Read this before deciding whether something is a vulnerability, because windiag's normal behaviour
looks alarming out of context.

windiag is a diagnostics server that **runs elevated by design** and exposes tools that read process
memory, handles, the registry, ACLs and file contents. Two tools are gated behind their own flags
because they are far more than diagnostics:

| Grant | Default | What it really is |
|---|---|---|
| `WINDIAG_ALLOW_COMMAND_EXECUTION` | off | Arbitrary code execution as the server's account |
| `WINDIAG_ALLOW_SELF_UPDATE` | off | Replacing the server's own elevated binary, and running it |

With either enabled, **the bearer token is equivalent to code execution on that host.** That is
intended, documented, and the reason both are off unless a deployment explicitly turns them on.

## The threat model is not only the network

The server runs elevated, so a local unprivileged user is inside the threat model too. Things that
follow from that, and which are deliberate rather than oversights:

- **The token is read from the environment only, never a command-line argument.** windiag's own
  `process_list` shows command lines to every local user on the machine; a token passed as an
  argument would be readable by the people it is meant to exclude.
- **As a service, the token belongs in the service's own registry `Environment` value**, which is
  ACL'd to SYSTEM and Administrators. A machine-wide environment variable is readable by every local
  user and is *not* an acceptable substitute.
- **There is no default bind address.** `--http` with nothing to bind to is refused rather than
  quietly listening on `0.0.0.0`.
- **File access is confined** to directories windiag owns, on both the read and write sides, through
  one shared check rather than two copies. Widening it is opt-in
  (`WINDIAG_ALLOW_ARBITRARY_WRITE`, `WINDIAG_ALLOW_ARBITRARY_READ`) because reading anywhere the
  elevated account can reach is exfiltration.
- **A signed server refuses an unsigned replacement.** The self-update signature check is a ratchet,
  not a setting: unsigned development builds keep working, but a target already running a signed
  build cannot be downgraded to an unsigned one through that path.

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
  administrator does not need windiag.
