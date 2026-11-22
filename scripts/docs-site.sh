#!/usr/bin/env bash
# scripts/docs-site.sh - build or preview the documentation site that GitHub Pages serves.
#
# OBJECTIVE   docs/ becomes a static site with MkDocs and the Material theme, at the versions pinned
#             by hash in .github/tools/mkdocs/requirements.txt. The same command runs on a laptop,
#             in scripts/ci.sh and in the Pages workflow, so the three cannot drift.
# DONE WHEN   "build" prints "READY: site written to DIR" and exits with code 0. MkDocs runs with
#             --strict, so a broken link, a missing page in the navigation or any other warning
#             fails the build.
#
# USAGE
#   scripts/docs-site.sh build [--site-dir DIR]   Build the site into DIR (default: .tools/docs-site/site).
#   scripts/docs-site.sh serve                    Preview on http://127.0.0.1:8000 with live reload.
#   scripts/docs-site.sh --help                   Show this text.
#
# The tools are installed into .tools/docs-site/venv (in .gitignore) with "uv pip sync
# --require-hashes", so a package whose hash differs from the pinned one is refused. Python is
# 3.12, the version the requirements were compiled for; uv fetches it when it is missing.
#
# EXIT CODES
#   0  The site was built (or the preview stopped normally).
#   1  The build failed: MkDocs reported an error or a warning.
#   2  The script was used wrongly.
#   3  BLOCKED: uv is missing, or the pinned tools could not be installed (no network and no cache).
#      There is no evidence either way, and BLOCKED is never counted as a pass.

set -euo pipefail

export NO_MKDOCS_2_WARNING=1  # Material prints a notice about MkDocs 2 on every build; the pins above decide the version.
SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SELF_DIR/.." && pwd -P)
REQUIREMENTS="$ROOT/.github/tools/mkdocs/requirements.txt"
PYTHON_VERSION=3.12
WORK="$ROOT/.tools/docs-site"
VENV="$WORK/venv"

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

usage_error() {
  printf 'docs-site.sh: %s\n' "$1" >&2
  printf 'Run scripts/docs-site.sh --help for the usage.\n' >&2
  exit 2
}

blocked() {
  printf 'BLOCKED: %s\n' "$1" >&2
  exit 3
}

install_tools() {
  type -P uv >/dev/null 2>&1 || blocked "uv is not installed, so the pinned MkDocs cannot be installed"
  [ -f "$REQUIREMENTS" ] || usage_error "$REQUIREMENTS is missing"
  mkdir -p "$WORK"
  if [ ! -x "$VENV/bin/python" ]; then
    uv venv --quiet --python "$PYTHON_VERSION" "$VENV" \
      || blocked "uv could not create a Python $PYTHON_VERSION environment (is the network reachable?)"
  fi
  uv pip sync --quiet --require-hashes --python "$VENV/bin/python" "$REQUIREMENTS" \
    || blocked "the pinned MkDocs packages could not be installed (is the network reachable, or are they cached?)"
}

[ $# -ge 1 ] || usage_error "name a command: build or serve"
command=$1
shift

case $command in
  --help | -h)
    usage
    exit 0
    ;;
  build)
    site_dir="$WORK/site"
    while [ $# -gt 0 ]; do
      case $1 in
        --site-dir)
          [ $# -ge 2 ] || usage_error "--site-dir needs a directory"
          site_dir=$2
          shift 2
          ;;
        *) usage_error "unknown option for build: $1" ;;
      esac
    done
    install_tools
    cd "$ROOT"
    if ! "$VENV/bin/mkdocs" build --strict --clean --config-file mkdocs.yml --site-dir "$site_dir"; then
      printf 'FAILED: MkDocs reported an error or a warning (see above)\n' >&2
      exit 1
    fi
    printf 'READY: site written to %s\n' "$site_dir"
    ;;
  serve)
    [ $# -eq 0 ] || usage_error "serve takes no option"
    install_tools
    cd "$ROOT"
    exec "$VENV/bin/mkdocs" serve --strict --config-file mkdocs.yml --dev-addr 127.0.0.1:8000
    ;;
  *) usage_error "unknown command: $command" ;;
esac
