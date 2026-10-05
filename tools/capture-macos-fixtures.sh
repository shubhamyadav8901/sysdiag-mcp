#!/usr/bin/env bash
# Captures the real output of every command MacDiag parses into tests/MacDiag.Mcp.Tests/Fixtures/macos/,
# where the parser tests check its shape (the values they pin come from Fixtures/macos-unverified, written
# from Apple's documentation). Run on a Mac, or by CI's macos-latest job:
#
#   sudo tools/capture-macos-fixtures.sh
#
# Captured under the environment the server's runner gives a program -- LC_ALL=C (ps excepted) and only the system
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

# ps alone gets a UTF-8 LC_CTYPE from the runner (MacSystemCommand), so it does here. env -i, not -u LC_ALL: sudo
# keeps the caller's LC_TIME, which LC_ALL=C was masking, and a localized lstart is not what the server sees.
env -i PATH="$PATH" LANG=C LC_CTYPE=en_US.UTF-8 ps -axww -o pid=,ppid=,uid=,rss=,stat=,lstart=,args= > "$out/ps-args"
env -i PATH="$PATH" LANG=C LC_CTYPE=en_US.UTF-8 ps -axww -o pid=,lstart=,comm= > "$out/ps-comm"

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

# codesign writes what it displays to standard error.
codesign -dvvv /bin/ls 2> "$out/codesign-dvvv-apple" || true
pkgutil --file-info /bin/ls > "$out/pkgutil-file-info" || true
# A home directory, which carries an ACL (group:everyone deny delete); /Library usually has none.
user="${SUDO_USER:-$(id -un)}"
home="$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
ls -lde "${home:-/Users/$user}" > "$out/ls-lde" || true
# process_control's view of a user's own launchd domain, exactly as the server asks for it.
uid="$(id -u "$user")"
launchctl asuser "$uid" sudo -n -u "#$uid" launchctl list > "$out/launchctl-list-user" || true
# The server's own stat format; printf turns %% into % and \t into a TAB.
stat -f "$(printf '%%u\t%%g\t%%Mp%%Lp\t%%Sf\t%%z\t%%m\t%%HT\t%%N')" -- / /bin/ls /dev/null > "$out/stat-lines" || true
systemextensionsctl list > "$out/systemextensionsctl-list" || true
kmutil showloaded > "$out/kmutil-showloaded" || true
sfltool dumpbtm > "$out/sfltool-dumpbtm" || true

# Readable by the user who runs the tests next, though captured as root.
chmod a+r "$out"/*
ls -l "$out"
