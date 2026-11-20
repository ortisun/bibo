#!/usr/bin/env bash
# Syntax-check the Mermaid blocks in Markdown files without installing anything into the repository.
#
#   docs/architecture/tools/check-mermaid.sh docs/architecture/overview.md docs/architecture/state-machine.md
#
# It copies package.json, package-lock.json and check-mermaid.mjs into a temporary directory,
# runs `npm ci --ignore-scripts` there, checks the given files, and removes the directory.
# Needs node and npm. Exit status is non-zero if any block fails to parse or the install fails.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
if [ "$#" -lt 1 ]; then echo "usage: $0 <file.md> [<file.md> ...]" >&2; exit 2; fi
work="$(mktemp -d "${TMPDIR:-/tmp}/mermaid-check.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cp "$here/package.json" "$here/package-lock.json" "$here/check-mermaid.mjs" "$work/"
files=()
for f in "$@"; do files+=("$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"); done
(cd "$work" && npm ci --ignore-scripts --no-audit --no-fund --silent && node check-mermaid.mjs "${files[@]}")
