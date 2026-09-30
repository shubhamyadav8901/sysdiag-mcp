#!/usr/bin/env bash
# Installs linuxdiag on a Linux host that has never run it, over SSH -- for an operator on Linux or macOS.
# The same steps as bootstrap-linux.ps1.
#
#   tools/bootstrap-linux.sh -t build-01 -u ops -k "$token" -g Standard
#
# Copies the published binary into the SSH user's home directory, checks its hash there, then runs
# --install-service with sudo. The home directory, not /tmp: a file in the shared /tmp could be swapped
# by another local account between the copy and the root execution. From then on update_self handles
# every later build.
#
#   -t target   host name or address (required)
#   -u user     SSH user; must be able to sudo, or be root (default: $USER)
#   -p port     SSH port (default 22)
#   -i key      SSH private key to use instead of ssh's default identity
#   -k token    bearer token to pin; generated and printed once if omitted
#   -g grants   None (--read-only) | Standard (self-update, commands) | All (plus arbitrary read/write)
#   -b bind     address to serve on (default http://0.0.0.0:4024)
#   -f binary   published binary (default artifacts/linux-x64/LinuxDiag.Mcp)
set -euo pipefail

target='' user="${USER:-root}" port=22 identity='' token='' grants='Standard' bind='http://0.0.0.0:4024'
binary='artifacts/linux-x64/LinuxDiag.Mcp'

while getopts 't:u:p:i:k:g:b:f:' opt; do
  case "$opt" in
    t) target="$OPTARG" ;;
    u) user="$OPTARG" ;;
    p) port="$OPTARG" ;;
    i) identity="$OPTARG" ;;
    k) token="$OPTARG" ;;
    g) grants="$OPTARG" ;;
    b) bind="$OPTARG" ;;
    f) binary="$OPTARG" ;;
    *) echo "usage: $0 -t target [-u user] [-p port] [-i key] [-k token] [-g None|Standard|All] [-b bind] [-f binary]" >&2; exit 2 ;;
  esac
done

[ -n "$target" ] || { echo "-t target is required" >&2; exit 2; }
[ -f "$binary" ] || { echo "no published binary at $binary" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then
  sha=$(sha256sum "$binary" | cut -d' ' -f1)
else
  sha=$(shasum -a 256 "$binary" | cut -d' ' -f1)   # macOS
fi

# Every argument is single-quoted for the remote shell below, so none may contain a quote.
case "$bind" in *\'*) echo "-b may not contain a single quote" >&2; exit 2 ;; esac
install_args=(--install-service --http "$bind")
[ -n "$token" ] && install_args+=(--token-stdin)
case "$grants" in
  Standard) install_args+=(--allow-self-update --allow-command-execution) ;;
  All)      install_args+=(--allow-self-update --allow-command-execution --allow-arbitrary-write --allow-arbitrary-read) ;;
  None)     install_args+=(--read-only) ;;
  *)        echo "-g must be None, Standard or All" >&2; exit 2 ;;
esac

# Expanded as ${ssh_opts[@]+...} below: an empty array under `set -u` is an error on bash before 4.4,
# which is what macOS still ships.
ssh_opts=()
[ -n "$identity" ] && ssh_opts+=(-i "$identity")

sudo_prefix='sudo '
[ "$user" = root ] && sudo_prefix=''

echo "==> copying $binary to $user@$target"
scp ${ssh_opts[@]+"${ssh_opts[@]}"} -P "$port" "$binary" "$user@$target:LinuxDiag.Mcp"

# Best effort, from a fresh session: when a step below fails, the remote side may never have reached
# its own cleanup -- the connection dropped, or the token session died mid-write -- and the token must
# not be left sitting in the home directory.
remove_leftovers() {
  ssh ${ssh_opts[@]+"${ssh_opts[@]}"} -p "$port" "$user@$target" 'rm -f ~/LinuxDiag.Mcp ~/.linuxdiag-token' ||
    echo "warning: could not remove ~/LinuxDiag.Mcp and ~/.linuxdiag-token on $target; remove them by hand" >&2
}

# A pinned token travels over SSH's stdin into an owner-only file, never on a command line: sudo logs
# its command line and ps shows it. A separate session because the install session's terminal belongs
# to sudo's password prompt. Removed first, because umask only sets the mode of a file it creates: a
# token file left behind with a looser mode would otherwise keep it.
token_input=''
if [ -n "$token" ]; then
  echo "==> sending the token"
  printf '%s\n' "$token" | ssh ${ssh_opts[@]+"${ssh_opts[@]}"} -p "$port" "$user@$target" \
    'rm -f ~/.linuxdiag-token && umask 077 && cat > ~/.linuxdiag-token' || { rc=$?; remove_leftovers; exit $rc; }
  token_input=' < ~/.linuxdiag-token'
fi

# One remote command: verify, then install. The trap removes the copy and the token however the session
# ends -- the install's own exit, a failed check, or a dropped connection or Ctrl-C. The signals exit
# rather than run the cleanup themselves: a trapped signal otherwise lets the shell carry on to the next
# command, and dash, unlike bash, does not run an EXIT trap for a signal it leaves at its default.
quoted=$(printf "'%s' " "${install_args[@]}")
remote="trap 'rm -f ~/LinuxDiag.Mcp ~/.linuxdiag-token' EXIT; trap 'exit 1' HUP INT TERM; echo '$sha  LinuxDiag.Mcp' | sha256sum -c - && chmod 0755 ~/LinuxDiag.Mcp && ${sudo_prefix}~/LinuxDiag.Mcp ${quoted}${token_input}"
echo "==> installing on $target ($grants grants)"
ssh ${ssh_opts[@]+"${ssh_opts[@]}"} -t -p "$port" "$user@$target" "$remote" || { rc=$?; remove_leftovers; exit $rc; }

echo "==> done. If a token was generated it was printed above, once: put it in ~/.windiag-targets.json."
