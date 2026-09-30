#!/usr/bin/env bash
# Captures every /proc format LinuxDiag parses, from the distro it runs in, into
# tests/LinuxDiag.Mcp.Tests/Fixtures/<ID from os-release>/. Run once per distro, from PowerShell:
#
#   wsl -d Ubuntu -- bash "/mnt/d/Tools/sysinternals_mcp/tools/capture-linux-fixtures.sh"
#   wsl -d Debian -- bash "/mnt/d/Tools/sysinternals_mcp/tools/capture-linux-fixtures.sh"
#
# Captured rather than written by hand: a parser tested against the format as someone remembered it
# passes on text the kernel never prints. The docker-* files are written only where the docker CLI can
# reach a daemon; a busybox container is started for the capture and removed afterwards.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. /etc/os-release
out="$repo/tests/LinuxDiag.Mcp.Tests/Fixtures/$ID"
mkdir -p "$out"

cat /proc/self/stat > "$out/pid-stat"
cat /proc/self/status > "$out/pid-status"
cat /proc/self/maps > "$out/pid-maps"
cat /proc/self/cgroup > "$out/pid-cgroup"
cat /proc/stat > "$out/kernel-stat"
for table in tcp tcp6 udp udp6 unix; do cat "/proc/net/$table" > "$out/net-$table"; done

# A lock held by a process that is still running while both files are read. /proc/locks leaves out a flock
# whose creator has exited -- flock(1) on an inherited descriptor exits at once -- so the lock is taken by
# flock(1) running the reader, and its own descriptor's fdinfo is the one captured.
lockfile="$(mktemp)"
flock -x "$lockfile" sh -c '
  cat /proc/locks > "$1/locks"
  for fd in /proc/$PPID/fd/*; do
    if [ "$(readlink "$fd")" = "$2" ]; then cat "/proc/$PPID/fdinfo/${fd##*/}" > "$1/pid-fdinfo-locked"; fi
  done' _ "$out" "$lockfile"
rm -f "$lockfile"

if docker info >/dev/null 2>&1; then
  cid="$(docker run -d busybox sleep 60)"
  pid="$(docker inspect -f '{{.State.Pid}}' "$cid")"
  cat "/proc/$pid/cgroup" > "$out/container-cgroup"
  cat "/proc/$pid/status" > "$out/container-status"
  # Only the container started here: the host's other containers are its owner's business, not a fixture.
  curl -s -G --unix-socket /var/run/docker.sock --data-urlencode "filters={\"id\":[\"$cid\"]}" \
    "http://localhost/containers/json" > "$out/docker-containers.json"
  docker rm -f "$cid" >/dev/null
fi

ls "$out"
