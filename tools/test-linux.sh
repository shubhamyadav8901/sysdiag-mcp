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
rsync -a --delete --exclude 'bin/' --exclude 'obj/' --exclude 'artifacts/' --exclude '.git/' \
  "$repo/" "$work/"

cd "$work"
dotnet test tests/DiagRelay.Mcp.Tests -warnaserror "$@"
