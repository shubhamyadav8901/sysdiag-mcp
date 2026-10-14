#!/usr/bin/env bash
# Prints a GitHub Release's notes for one version: the summary written under its CHANGELOG.md heading,
# then a link to the whole section. The release page is a summary; CHANGELOG.md stays the full record.
# Copying the whole section made a 300-line page nobody reads. The Release workflow appends GitHub's
# generated list of merged pull requests (--generate-notes), so no PR is listed here by hand.
#
#   tools/release-notes.sh <version> [owner/repo]     e.g. tools/release-notes.sh 3.1.0
#   CHANGELOG_REF=main tools/release-notes.sh 1.0.0    link main's changelog instead of the tag's
#
# Fails, printing nothing to stdout, when the version has no section or the section has no summary.
set -euo pipefail

version=${1:?usage: release-notes.sh <version> [owner/repo]}
repo=${2:-${GITHUB_REPOSITORY:-shubhamyadav8901/sysdiag-mcp}}
changelog=${CHANGELOG:-CHANGELOG.md}
# The link points at the changelog as tagged, so it keeps working after later sections are added.
ref=${CHANGELOG_REF:-v$version}

heading=$(awk -v v="$version" 'index($0, "## [" v "]") == 1 { print; exit }' "$changelog")
if [ -z "$heading" ]; then
  echo "release-notes: $changelog has no section for $version" >&2
  exit 1
fi

# The summary is everything between the heading and the first subsection, without its outer blank lines.
summary=$(awk -v h="$heading" '
  $0 == h { found = 1; next }
  found && (/^## / || /^### /) { exit }
  found { print }' "$changelog" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')
if [ -z "$summary" ]; then
  echo "release-notes: the $version section has no summary. Write a few sentences under '$heading'," >&2
  echo "before its first ### subsection, saying what the release means for someone upgrading." >&2
  exit 1
fi

# GitHub's anchor for a heading: lower-cased, punctuation other than '-' and '_' dropped, spaces to '-'.
anchor=$(printf '%s' "${heading#\#\# }" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9 _-' | tr ' ' '-')

printf '%s\n\n' "$summary"
printf '**Changelog:** [the full %s section](https://github.com/%s/blob/%s/CHANGELOG.md#%s)\n' "$version" "$repo" "$ref" "$anchor"
