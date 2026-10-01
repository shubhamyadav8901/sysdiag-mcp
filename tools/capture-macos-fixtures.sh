#!/usr/bin/env bash
# Captures the real output of every command MacDiag parses into tests/MacDiag.Mcp.Tests/Fixtures/macos/,
# where the parser tests check its shape (the values they pin come from Fixtures/macos-unverified, written
# from Apple's documentation). Run on a Mac, or by CI's macos-latest job:
#
#   sudo tools/capture-macos-fixtures.sh
#
# Captured under the environment the server's runner gives a program -- LC_ALL=C and only the system
# directories on PATH -- so the fixtures are what the parsers will really be handed.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$repo/tests/MacDiag.Mcp.Tests/Fixtures/macos"
mkdir -p "$out"
export LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin

sw_vers > "$out/sw_vers"
sysctl -n hw.model hw.memsize kern.osrelease kern.boottime > "$out/sysctl"
vm_stat > "$out/vm_stat"
mount > "$out/mount"

ps -axww -o pid=,ppid=,uid=,rss=,stat=,lstart=,args= > "$out/ps-args"
ps -axww -o pid=,lstart=,comm= > "$out/ps-comm"

# lsof exits 1 when it finds nothing, which set -e would read as failure.
lsof -n -P -w -F0pcuRfatdDsinPT -p $$ > "$out/lsof-p" || [ $? -eq 1 ]
lsof -n -P -w -F0pcuRfatdDsinPT -i -Ts > "$out/lsof-i" || [ $? -eq 1 ]

plutil -convert xml1 -o - /System/Library/LaunchDaemons/ssh.plist > "$out/plist-sshd.xml" || true

launchctl print system/com.openssh.sshd > "$out/launchctl-print-sshd" || true
launchctl list > "$out/launchctl-list" || true
launchctl print-disabled system > "$out/launchctl-print-disabled" || true

# A line of our own first, so the capture is never empty; then how much a busy runner logs in five minutes.
logger -t macdiag-capture "capture $(date +%s)"
sleep 2
log show --style ndjson --last 1m --predicate 'process == "logger"' > "$out/log-ndjson" || true
log show --style ndjson --last 5m | wc -c > "$out/log-size" || true

# Readable by the user who runs the tests next, though captured as root.
chmod a+r "$out"/*
ls -l "$out"
