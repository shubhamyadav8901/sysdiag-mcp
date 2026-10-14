# Security

## Security

The threat model is **not only the network**. The server runs elevated, so any local unprivileged user
on the target can reach the port; with the token they get command execution at the server's privilege
level through an ordinary tool call. The token is the whole boundary.

- **A bearer token is always required in HTTP mode.** There is no unauthenticated path — if none is
  configured, one is generated rather than the check being skipped. Comparison is fixed-time.
- **The channel is not encrypted, so the boundary travels in cleartext.** windiag serves plaintext
  HTTP; there is no TLS support. Every request carries the bearer token in an `Authorization` header,
  and every response carries whatever the tool returned — file contents, memory dumps, registry
  values, `run_command` output. Anyone able to observe traffic on the segment captures the token, and
  the token is the whole boundary. SHA-256 chunk hashing on file transfers is **integrity, not
  confidentiality**: it catches a truncated copy, and an active on-path attacker simply recomputes it.
  The firewall rule scopes who can *reach* the port, not who can *watch* it. So deploy this on a
  management segment you already trust, and do not route it across one you do not. If you need
  confidentiality on the wire today, tunnel it — WireGuard, SSH, an mTLS proxy — rather than assuming
  the port being scoped is enough.
- **The running server never takes the token as a command-line argument.** This server's own
  `process_list` shows command lines to every local user, so a `--token` switch would publish the
  credential to precisely the audience it excludes. Environment variable only. The installer's
  `--token` is the one exception and is visible while the installer runs; `--token-stdin` is not, and
  is what the bootstrap scripts use.
- **There is no default bind address.** `--http` with no address and no `WINDIAG_HTTP_BIND` is a
  startup failure, not a guess.
- **A service's directories and registry key are SYSTEM's and Administrators' alone.** The installer
  restricts them, and a service re-checks on every start, restricting what it can and refusing to start
  from a directory it cannot. A target installed before this was the case may have had its token read
  by a local user: its first start on this build logs that to the Application event log, and the token
  should then be changed.
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
- **Tool *results* are untrusted input to whatever agent is driving.** `run_command` output, process
  command lines, registry values, event-log messages and any file content the tools surface are data
  the target controls — a compromised or hostile target can return text crafted to steer the model into
  further calls. The server's own tool *descriptions* are injection-free, but the boundary it cannot
  enforce is on the reading side: treat returned content as data, never as instructions, and keep the
  destructive grants (`WINDIAG_ALLOW_COMMAND_EXECUTION`, `update_self`) off unless a run needs them.
