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
#   -k token    bearer token to pin; generated and printed once if omitted
#   -g grants   None (--read-only) | Standard (self-update, commands) | All (plus arbitrary read/write)
#   -b bind     address to serve on (default http://0.0.0.0:4024)
#   -f binary   published binary (default artifacts/linux-x64/LinuxDiag.Mcp)
set -euo pipefail

target='' user="${USER:-root}" port=22 token='' grants='Standard' bind='http://0.0.0.0:4024'
binary='artifacts/linux-x64/LinuxDiag.Mcp'

while getopts 't:u:p:k:g:b:f:' opt; do
  case "$opt" in
    t) target="$OPTARG" ;;
    u) user="$OPTARG" ;;
    p) port="$OPTARG" ;;
    k) token="$OPTARG" ;;
    g) grants="$OPTARG" ;;
    b) bind="$OPTARG" ;;
    f) binary="$OPTARG" ;;
    *) echo "usage: $0 -t target [-u user] [-p port] [-k token] [-g None|Standard|All] [-b bind] [-f binary]" >&2; exit 2 ;;
  esac
done

[ -n "$target" ] || { echo "-t target is required" >&2; exit 2; }
[ -f "$binary" ] || { echo "no published binary at $binary" >&2; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then
  sha=$(sha256sum "$binary" | cut -d' ' -f1)
else
  sha=$(shasum -a 256 "$binary" | cut -d' ' -f1)   # macOS
fi

install_args=(--install-service --http "$bind")
[ -n "$token" ] && install_args+=(--token "$token")
case "$grants" in
  Standard) install_args+=(--allow-self-update --allow-command-execution) ;;
  All)      install_args+=(--allow-self-update --allow-command-execution --allow-arbitrary-write --allow-arbitrary-read) ;;
  None)     install_args+=(--read-only) ;;
  *)        echo "-g must be None, Standard or All" >&2; exit 2 ;;
esac

sudo_prefix='sudo '
[ "$user" = root ] && sudo_prefix=''

echo "==> copying $binary to $user@$target"
scp -P "$port" "$binary" "$user@$target:LinuxDiag.Mcp"

# One remote command: verify, install, then remove the copy whatever the install returned.
remote="echo '$sha  LinuxDiag.Mcp' | sha256sum -c - && chmod 0755 ~/LinuxDiag.Mcp && ${sudo_prefix}~/LinuxDiag.Mcp ${install_args[*]} ; rc=\$?; rm -f ~/LinuxDiag.Mcp; exit \$rc"
echo "==> installing on $target ($grants grants)"
ssh -t -p "$port" "$user@$target" "$remote"

echo "==> done. If a token was generated it was printed above, once: put it in ~/.windiag-targets.json."
