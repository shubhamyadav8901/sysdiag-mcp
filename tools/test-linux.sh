#!/usr/bin/env bash
# Runs the cross-platform relay tests on a real Linux runtime. Invoked from Windows through WSL:
#
#   wsl -d Ubuntu -- bash "/mnt/d/Tools/sysinternals_mcp/tools/test-linux.sh"
#
# Extra arguments pass through to `dotnet test` (for example --filter "FullyQualifiedName~PathScope").
#
# The tree is copied into the Linux filesystem rather than built in place under /mnt, for two reasons.
# A Linux restore rewrites obj/project.assets.json, and the next Windows build then fails on paths
# that do not exist -- the two builds must never share obj/. And /mnt is DrvFs, which ignores chmod
# unless remounted with metadata, so a file-mode test run there would pass or fail for reasons that
# have nothing to do with the code.
#
# One-time setup, no root needed:
#   curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
#   bash /tmp/dotnet-install.sh --channel 9.0 --install-dir "$HOME/.dotnet"
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="${DIAG_VERIFY_DIR:-$HOME/diag-verify}"

export PATH="$HOME/.dotnet:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1

if ! command -v dotnet >/dev/null 2>&1; then
  echo "dotnet is not installed in this distro; see the one-time setup at the top of $0" >&2
  exit 2
fi

mkdir -p "$work"

# --delete-excluded wipes the copy's bin/ and obj/ on every run, so each run is a clean build. Keeping
# them looked like free speed and gave false results: rsync -a preserves source timestamps, so a file
# restored to its older content AND its older mtime -- Copy-Item, cp -p, unzip all do this -- reaches
# the copy looking older than the binary already built from the mutated version. MSBuild then skips
# the compile and the tests run against code that no longer exists. That happened here, during a
# mutation check, and a harness whose job is to catch regressions cannot be allowed to report on
# stale code.
rsync -a --delete --delete-excluded \
  --exclude 'bin/' --exclude 'obj/' --exclude 'artifacts/' --exclude '.git/' \
  "$repo/" "$work/"

cd "$work"

# Every cross-platform suite. A filter that matches nothing in one project reports "No test matches"
# and exits 0 there, so a filtered run is read for a non-zero Total, never for the exit code alone.
status=0
for project in tests/DiagRelay.Mcp.Tests tests/Diag.Mcp.Server.Tests tests/LinuxDiag.Mcp.Tests tests/MacDiag.Mcp.Tests; do
  dotnet test "$project" -warnaserror "$@" || status=1
done
exit $status
