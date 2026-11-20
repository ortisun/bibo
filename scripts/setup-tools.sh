#!/usr/bin/env bash
# scripts/setup-tools.sh - bring the factory's own tools to the versions it pins, on the machine that runs the factory.
#
# OBJECTIVE   The tools that scripts/ci.sh and the factory's checks run (cargo-nextest, cargo-deny, cargo-audit, gitleaks,
#             actionlint, pyright, shellcheck) are installed at the versions in scripts/lib/tool-pins.sh, and the
#             programs they need are there. scripts/install.sh runs this script as its host-tools step.
# DONE WHEN   Every line it prints is PRESENT or ADDED, it prints "READY", and it exits with code 0.
#
#   scripts/setup-tools.sh --check           Show what is missing or at another version. Change nothing.
#   scripts/setup-tools.sh                   Install every missing tool at its pinned version.
#   --prefix DIR                             Install into DIR/bin. The default is .tools/ in this repository (it is in
#                                            .gitignore), or FACTORY_TOOLS_PREFIX when that is set. scripts/ci.sh puts
#                                            that bin/ folder first on its PATH by itself.
#   --help                                   Show this text.
#
# How each tool is installed
#   cargo-nextest, cargo-deny, cargo-audit   cargo install --locked --root PREFIX NAME --version PIN. Needs Rust.
#   gitleaks, actionlint                     The release archive from the project's GitHub releases page, for darwin or
#                                            linux on arm64 or amd64. Its SHA-256 must equal the one written in
#                                            scripts/lib/tool-pins.sh. All archives are downloaded and checked before
#                                            anything is installed. One wrong hash stops the run, installs nothing, and
#                                            exits with code 1. Nothing downloaded is ever run as a script.
#   pyright                                  npm ci from .github/tools/pyright/package-lock.json (the same lockfile CI
#                                            uses, which npm checks by hash), with install scripts switched off,
#                                            into PREFIX/pyright. Needs Node.js and npm.
#   ShellCheck                               brew install shellcheck when Homebrew is present. A package manager cannot
#                                            pick an exact version, so another version is a NOTE and is kept. Without
#                                            Homebrew this is NEEDS: apt needs sudo, which this script does not run.
#
# Checked and reported, but left to a person
#   git, python3   Needed by every script.
#   cargo          Rust, through rustup (https://rustup.rs). rust-toolchain.toml selects the version. This script does
#                  not run the rustup installer, because that is a script fetched from the network and run by a shell.
#   node, npm      Node.js, for pyright and the Mermaid check.
#   uv             For the policy and schema checks.
#   docker         Docker with the Compose plugin, for the local stack and the Compose check.
#   gh             The GitHub CLI, for scripts/install.sh --repo.
#
# A tool counts as PRESENT when the copy found first on the PATH (with PREFIX/bin in front) reports the pinned version.
# A copy at another version is not touched: the pinned version is installed into PREFIX/bin, and a NOTE says when the
# other copy comes first on your own PATH.
#
# Output: one line per step, "  STATE  step  detail". STATE is PRESENT, ADDED, WOULD_ADD, DRIFT, NEEDS, NOTE or
# BLOCKED. The end lists "Done for you", "Needs you" and "Remember".
#
# Exit codes: 0 ready, 1 a step failed (a wrong hash, a failed install), 2 wrong arguments, 3 not finished: something
# NEEDS a person, is BLOCKED, or (with --check) would be installed.
#
# This script works with the bash that ships with macOS (3.2) and with bash 4 and 5.

set -uo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SELF_DIR/.." && pwd -P)
PINS_FILE="$SELF_DIR/lib/tool-pins.sh"
PYRIGHT_LOCK_DIR="$ROOT/.github/tools/pyright"

usage_error() {
  printf 'setup-tools.sh: %s (try --help)\n' "$1" >&2
  exit 2
}

[ -f "$PINS_FILE" ] || usage_error "$PINS_FILE is missing; it names the versions to install"
# shellcheck source=lib/tool-pins.sh
. "$PINS_FILE"

check_only=0
prefix="${FACTORY_TOOLS_PREFIX:-$ROOT/.tools}"

while [ $# -gt 0 ]; do
  case "$1" in
    --check) check_only=1 ;;
    --prefix)
      [ $# -ge 2 ] || usage_error "--prefix needs a directory"
      prefix=$2
      shift
      ;;
    -h | --help)
      sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done

[ -n "$prefix" ] || usage_error "--prefix must not be empty"
case "$prefix" in
  /*) ;;
  *) prefix="$PWD/$prefix" ;;
esac
BIN_DIR="$prefix/bin"
ORIGINAL_PATH=$PATH
PATH="$BIN_DIR:$PATH"
export PATH

WORK_DIR=$(mktemp -d) || usage_error "cannot create a temporary directory"
trap 'rm -rf "$WORK_DIR"' EXIT

# ---------------------------------------------------------------------------------------------------------------
# Reporting, in the same form as scripts/install.sh
# ---------------------------------------------------------------------------------------------------------------
DONE_LINES=""
NEED_LINES=""
NOTE_LINES=""
FAILED=0
PENDING=0

clean() { printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177'; }
report() { # STATE STEP DETAIL
  printf '  %-9s %-15s %s\n' "$1" "$2" "$(clean "$3")"
  case "$1" in WOULD_ADD | DRIFT) PENDING=1 ;; esac
}
done_for_you() { DONE_LINES="${DONE_LINES}  - $(clean "$1")"$'\n'; }
needs_you() { # the same advice is listed once, however many tools need it
  local line
  line="  - $(clean "$1")"$'\n'
  case "$NEED_LINES" in *"$line"*) return 0 ;; esac
  NEED_LINES="$NEED_LINES$line"
}
remember() { NOTE_LINES="${NOTE_LINES}  - $(clean "$1")"$'\n'; }
show_log_tail() { tail -n 15 "$1" | while IFS= read -r line; do printf '              %s\n' "$(clean "$line")"; done; }

have() { command -v "$1" >/dev/null 2>&1; }

RUST_ADVICE="Install Rust with rustup (https://rustup.rs), then run this script again: it installs the cargo tools. This script does not run the rustup installer itself, because that installer is a script fetched from the network and run by a shell."
NODE_ADVICE="Install Node.js with npm (https://nodejs.org), then run this script again. pyright and the Mermaid check need it."

# The first X.Y.Z that the tool prints about its version, or nothing.
version_of() { # PROGRAM-PATH TOOL-NAME
  local out
  case "$2" in
    cargo-nextest) out=$("$1" nextest --version 2>/dev/null </dev/null) ;;
    gitleaks) out=$("$1" version 2>/dev/null </dev/null) ;;
    actionlint) out=$("$1" -version 2>/dev/null </dev/null) ;;
    *) out=$("$1" --version 2>/dev/null </dev/null) ;;
  esac
  printf '%s\n' "$out" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1
  return 0
}

pin_of() {
  case "$1" in
    cargo-nextest) printf '%s' "$PIN_NEXTEST" ;;
    cargo-deny) printf '%s' "$PIN_DENY" ;;
    cargo-audit) printf '%s' "$PIN_AUDIT" ;;
    gitleaks) printf '%s' "$PIN_GITLEAKS" ;;
    actionlint) printf '%s' "$PIN_ACTIONLINT" ;;
    pyright) printf '%s' "$PIN_PYRIGHT" ;;
    shellcheck) printf '%s' "$PIN_SHELLCHECK" ;;
  esac
}

file_sha256() {
  if have shasum; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif have sha256sum; then
    sha256sum "$1" | cut -d' ' -f1
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Programs that a person installs
# ---------------------------------------------------------------------------------------------------------------
step_prerequisites() {
  local tool
  for tool in git python3; do
    if have "$tool"; then
      report PRESENT "$tool" "$(command -v "$tool")"
    else
      report NEEDS "$tool" "not installed"
      needs_you "Install $tool and run this script again."
    fi
  done
  if have cargo; then
    report PRESENT cargo "$("cargo" --version 2>/dev/null | head -n 1) (rust-toolchain.toml selects the toolchain)"
  else
    report NEEDS cargo "Rust is not installed"
    needs_you "$RUST_ADVICE"
  fi
  local node_missing=0
  for tool in node npm; do
    if have "$tool"; then
      report PRESENT "$tool" "$("$tool" --version 2>/dev/null | head -n 1)"
    else
      report NEEDS "$tool" "not installed"
      node_missing=1
    fi
  done
  if [ "$node_missing" -eq 1 ]; then needs_you "$NODE_ADVICE"; fi
  if have uv; then
    report PRESENT uv "$(uv --version 2>/dev/null | head -n 1)"
  else
    report NEEDS uv "not installed"
    needs_you "Install uv (https://docs.astral.sh/uv/). The policy and schema checks run Python through it."
  fi
  if ! have docker; then
    report NEEDS docker "not installed"
    needs_you "Install Docker with the Compose plugin (https://docs.docker.com/get-docker/). The local stack and the Compose check need it."
  elif ! docker compose version >/dev/null 2>&1; then
    report NEEDS docker "the Compose plugin does not answer 'docker compose version'"
    needs_you "Install the Docker Compose plugin (https://docs.docker.com/compose/install/)."
  else
    report PRESENT docker "$(docker compose version 2>/dev/null | head -n 1)"
  fi
  if have gh; then
    report PRESENT gh "$(gh --version 2>/dev/null | head -n 1)"
  else
    report NEEDS gh "not installed"
    needs_you "Install the GitHub CLI (https://cli.github.com). scripts/install.sh --repo uses it."
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# The pinned tools: first look at all of them, then download and check the archives, then install.
# ---------------------------------------------------------------------------------------------------------------
TOOLS="cargo-nextest cargo-deny cargo-audit gitleaks actionlint pyright shellcheck"
# The tools this run installs, separated by spaces.
TO_INSTALL=" "

# Platform names as the two release pages spell them, or empty when this machine is not supported.
PLATFORM_KEY=""
GITLEAKS_PLATFORM=""
ACTIONLINT_PLATFORM=""
detect_platform() {
  local system machine
  system=$(uname -s 2>/dev/null)
  machine=$(uname -m 2>/dev/null)
  case "$system" in
    Darwin) system=darwin ;;
    Linux) system=linux ;;
    *) return 1 ;;
  esac
  case "$machine" in
    arm64 | aarch64) machine=arm64 ;;
    x86_64 | amd64) machine=amd64 ;;
    *) return 1 ;;
  esac
  PLATFORM_KEY=$(printf '%s_%s' "$system" "$machine" | LC_ALL=C tr '[:lower:]' '[:upper:]')
  ACTIONLINT_PLATFORM="${system}_${machine}"
  if [ "$machine" = amd64 ]; then GITLEAKS_PLATFORM="${system}_x64"; else GITLEAKS_PLATFORM="${system}_${machine}"; fi
  return 0
}

# What a missing tool needs before it can be installed. Prints the missing program, or nothing when all is there.
missing_requirement() {
  case "$1" in
    cargo-nextest | cargo-deny | cargo-audit) have cargo || printf 'cargo' ;;
    pyright) { have npm && have node; } || printf 'node and npm' ;;
    gitleaks | actionlint)
      if [ -z "$PLATFORM_KEY" ]; then
        printf 'a supported platform (darwin or linux, arm64 or amd64; this is %s %s)' "$(uname -s)" "$(uname -m)"
      elif ! have curl; then
        printf 'curl'
      elif ! have tar; then
        printf 'tar'
      elif ! have shasum && ! have sha256sum; then
        printf 'shasum or sha256sum'
      fi
      ;;
    shellcheck) have brew || printf 'Homebrew' ;;
  esac
}

manual_hint() {
  case "$1" in
    cargo-nextest | cargo-deny | cargo-audit) printf '%s' "$RUST_ADVICE" ;;
    pyright) printf '%s' "$NODE_ADVICE" ;;
    gitleaks) printf 'Install gitleaks %s from https://github.com/gitleaks/gitleaks/releases and check its SHA-256 against the release checksum file.' "$PIN_GITLEAKS" ;;
    actionlint) printf 'Install actionlint %s from https://github.com/rhysd/actionlint/releases and check its SHA-256 against the release checksum file.' "$PIN_ACTIONLINT" ;;
    shellcheck) printf 'Install shellcheck %s with your package manager (for example: sudo apt install shellcheck), then run this script again.' "$PIN_SHELLCHECK" ;;
  esac
}

look_at_tool() {
  local tool=$1 pin found version requirement
  pin=$(pin_of "$tool")
  found=$(command -v "$tool" 2>/dev/null || true)
  if [ -n "$found" ]; then
    version=$(version_of "$found" "$tool")
    if [ "$version" = "$pin" ]; then
      report PRESENT "$tool" "$version at $found"
      return
    fi
    if [ "$tool" = shellcheck ]; then
      report NOTE shellcheck "${version:-an unknown version} at $found; CI uses $pin"
      remember "shellcheck at $found is ${version:-of unknown version}, and CI uses $pin. A package manager cannot install an exact version, so it was kept; its findings can differ from CI's."
      return
    fi
  fi
  requirement=$(missing_requirement "$tool")
  if [ -n "$requirement" ]; then
    report NEEDS "$tool" "${found:+${version:-an unknown version} at $found, the pin is $pin; }cannot install: needs $requirement"
    needs_you "$(manual_hint "$tool")"
    return
  fi
  if [ "$check_only" -eq 1 ]; then
    if [ -n "$found" ]; then
      report DRIFT "$tool" "${version:-an unknown version} at $found, the pin is $pin; would install $pin into $BIN_DIR"
    elif [ "$tool" = shellcheck ]; then
      report WOULD_ADD shellcheck "would run: brew install shellcheck"
    else
      report WOULD_ADD "$tool" "would install $pin into $BIN_DIR"
    fi
    return
  fi
  TO_INSTALL="$TO_INSTALL$tool "
  if [ -n "$found" ]; then remember "$tool at $found is ${version:-of unknown version}; $pin was installed into $BIN_DIR."; fi
}

wants_install() { case "$TO_INSTALL" in *" $1 "*) return 0 ;; esac; return 1; }

archive_url() {
  case "$1" in
    gitleaks) printf 'https://github.com/gitleaks/gitleaks/releases/download/v%s/gitleaks_%s_%s.tar.gz' "$PIN_GITLEAKS" "$PIN_GITLEAKS" "$GITLEAKS_PLATFORM" ;;
    actionlint) printf 'https://github.com/rhysd/actionlint/releases/download/v%s/actionlint_%s_%s.tar.gz' "$PIN_ACTIONLINT" "$PIN_ACTIONLINT" "$ACTIONLINT_PLATFORM" ;;
  esac
}

# Download the archive of tool $1 into WORK_DIR and check its hash. 0 good, 1 wrong hash, 3 could not download.
fetch_archive() {
  local tool=$1 url expected actual name archive
  url=$(archive_url "$tool")
  name=$(printf 'SHA256_%s_%s' "$tool" "$PLATFORM_KEY" | LC_ALL=C tr '[:lower:]' '[:upper:]')
  expected=${!name:-}
  archive="$WORK_DIR/$tool.tar.gz"
  case "$expected" in
    "" | *[!0-9a-f]*)
      report BLOCKED "$tool" "scripts/lib/tool-pins.sh records no SHA-256 for $PLATFORM_KEY; nothing was installed"
      return 1
      ;;
  esac
  if [ "${#expected}" -ne 64 ]; then
    report BLOCKED "$tool" "the SHA-256 for $PLATFORM_KEY in scripts/lib/tool-pins.sh is not 64 hex digits; nothing was installed"
    return 1
  fi
  if ! curl --fail --silent --show-error --location --retry 3 --proto '=https' --output "$archive" "$url" >"$WORK_DIR/$tool.download.log" 2>&1; then
    report BLOCKED "$tool" "could not download $url"
    show_log_tail "$WORK_DIR/$tool.download.log"
    needs_you "Check that github.com can be reached and run this script again."
    return 3
  fi
  actual=$(file_sha256 "$archive")
  if [ "$actual" != "$expected" ]; then
    report BLOCKED "$tool" "the archive's SHA-256 is $actual, but scripts/lib/tool-pins.sh records $expected; nothing was installed"
    return 1
  fi
  return 0
}

install_from_archive() {
  local tool=$1 pin unpack version
  pin=$(pin_of "$tool")
  unpack="$WORK_DIR/$tool.unpacked"
  mkdir -p "$unpack"
  if ! tar -xzf "$WORK_DIR/$tool.tar.gz" -C "$unpack" "$tool" >"$WORK_DIR/$tool.tar.log" 2>&1 \
    || [ -L "$unpack/$tool" ] || [ ! -f "$unpack/$tool" ]; then
    report BLOCKED "$tool" "the archive holds no regular file named $tool"
    show_log_tail "$WORK_DIR/$tool.tar.log"
    FAILED=1
    return
  fi
  mkdir -p "$BIN_DIR"
  cp "$unpack/$tool" "$BIN_DIR/.$tool.new" && chmod 0755 "$BIN_DIR/.$tool.new" && mv -f "$BIN_DIR/.$tool.new" "$BIN_DIR/$tool"
  finish_install "$tool" "$pin" "from $(archive_url "$tool"), SHA-256 checked"
}

install_with_cargo() {
  local tool=$1 pin
  pin=$(pin_of "$tool")
  printf '  ...       %-15s cargo install --locked --root %s %s --version %s (this can take minutes)\n' "$tool" "$prefix" "$tool" "$pin"
  if ! cargo install --locked --root "$prefix" "$tool" --version "$pin" >"$WORK_DIR/$tool.log" 2>&1; then
    report BLOCKED "$tool" "cargo install failed"
    show_log_tail "$WORK_DIR/$tool.log"
    FAILED=1
    return
  fi
  finish_install "$tool" "$pin" "with cargo install --locked"
}

install_pyright() {
  local staging="$prefix/.pyright.new"
  rm -rf "$staging"
  mkdir -p "$staging" "$BIN_DIR"
  cp "$PYRIGHT_LOCK_DIR/package.json" "$PYRIGHT_LOCK_DIR/package-lock.json" "$staging/"
  if ! (cd "$staging" && npm ci --ignore-scripts --no-audit --no-fund) >"$WORK_DIR/pyright.log" 2>&1; then
    rm -rf "$staging"
    report BLOCKED pyright "npm ci failed"
    show_log_tail "$WORK_DIR/pyright.log"
    FAILED=1
    return
  fi
  rm -rf "$prefix/pyright"
  mv "$staging" "$prefix/pyright"
  ln -sf ../pyright/node_modules/.bin/pyright "$BIN_DIR/pyright"
  finish_install pyright "$PIN_PYRIGHT" "with npm ci from .github/tools/pyright/package-lock.json"
}

install_shellcheck() {
  local found version
  if ! brew install shellcheck >"$WORK_DIR/shellcheck.log" 2>&1; then
    report BLOCKED shellcheck "brew install shellcheck failed"
    show_log_tail "$WORK_DIR/shellcheck.log"
    FAILED=1
    return
  fi
  found=$(command -v shellcheck 2>/dev/null || true)
  if [ -z "$found" ]; then
    report BLOCKED shellcheck "brew install shellcheck finished, but shellcheck is not on the PATH"
    FAILED=1
    return
  fi
  version=$(version_of "$found" shellcheck)
  report ADDED shellcheck "${version:-an unknown version} at $found, with Homebrew"
  done_for_you "Installed shellcheck with Homebrew."
  if [ "$version" != "$PIN_SHELLCHECK" ]; then
    remember "Homebrew installed shellcheck ${version:-of unknown version}, and CI uses $PIN_SHELLCHECK. Its findings can differ from CI's."
  fi
}

# Run the new copy and make sure it reports the pinned version.
finish_install() { # TOOL PIN HOW
  local version
  version=$(version_of "$BIN_DIR/$1" "$1")
  if [ "$version" != "$2" ]; then
    report BLOCKED "$1" "installed into $BIN_DIR, but it reports ${version:-no version} instead of $2"
    FAILED=1
    return
  fi
  report ADDED "$1" "$2 into $BIN_DIR, $3"
  done_for_you "Installed $1 $2 into $BIN_DIR."
}

step_pinned_tools() {
  local tool code
  detect_platform || true
  for tool in $TOOLS; do look_at_tool "$tool"; done
  [ "$check_only" -eq 0 ] || return 0

  # Every archive is downloaded and checked before anything is installed, so a wrong hash leaves the machine as it was.
  for tool in gitleaks actionlint; do
    wants_install "$tool" || continue
    fetch_archive "$tool"
    code=$?
    if [ "$code" -eq 1 ]; then
      FAILED=1
      report BLOCKED all-tools "no tool was installed in this run, because one archive did not match its recorded SHA-256"
      needs_you "Do not install $tool from this archive. The file served for $(archive_url "$tool") is not the one whose SHA-256 is recorded in scripts/lib/tool-pins.sh. Compare with the release's checksum file and find out why before you change the recorded hash."
      return 0
    fi
    if [ "$code" -ne 0 ]; then TO_INSTALL=${TO_INSTALL/ $tool / }; fi
  done

  for tool in $TOOLS; do
    wants_install "$tool" || continue
    case "$tool" in
      cargo-nextest | cargo-deny | cargo-audit) install_with_cargo "$tool" ;;
      gitleaks | actionlint) install_from_archive "$tool" ;;
      pyright) install_pyright ;;
      shellcheck) install_shellcheck ;;
    esac
  done
}

# Whether a person who types the tool's name gets the installed copy.
step_path() {
  [ -d "$BIN_DIR" ] || return 0
  local tool other
  case ":$ORIGINAL_PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
      report NOTE path "$BIN_DIR is not on your PATH"
      if [ "$prefix" = "$ROOT/.tools" ]; then
        remember "$BIN_DIR is not on your PATH. scripts/ci.sh adds it by itself. To use these tools in a shell, add: export PATH=\"$BIN_DIR:\$PATH\""
      else
        remember "$BIN_DIR is not on your PATH. scripts/ci.sh adds it only when FACTORY_TOOLS_PREFIX=$prefix is set. To use these tools in a shell, add: export PATH=\"$BIN_DIR:\$PATH\""
      fi
      ;;
  esac
  for tool in $TOOLS; do
    [ -x "$BIN_DIR/$tool" ] || continue
    other=$(PATH=$ORIGINAL_PATH command -v "$tool" 2>/dev/null || true)
    if [ -n "$other" ] && [ "$other" != "$BIN_DIR/$tool" ]; then
      remember "On your own PATH, $tool is $other, which comes before $BIN_DIR/$tool."
    fi
  done
}

# ---------------------------------------------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------------------------------------------
if [ "$check_only" -eq 1 ]; then printf 'Checking only. Nothing will be changed.\n'; fi
printf 'Tools folder: %s\n' "$BIN_DIR"
step_prerequisites
step_pinned_tools
step_path

printf '\n'
if [ -n "$DONE_LINES" ]; then printf 'Done for you\n%s\n' "$DONE_LINES"; fi
if [ -n "$NEED_LINES" ]; then printf 'Needs you\n%s\n' "$NEED_LINES"; fi
if [ -n "$NOTE_LINES" ]; then printf 'Remember\n%s\n' "$NOTE_LINES"; fi
if [ "$FAILED" -ne 0 ]; then
  printf 'FAILED: a tool could not be installed. Read the BLOCKED lines above.\n'
  exit 1
fi
if [ -n "$NEED_LINES" ]; then
  printf 'NOT READY\n'
  exit 3
fi
if [ "$PENDING" -ne 0 ]; then
  printf 'NOT READY: the WOULD_ADD and DRIFT lines above are changes that --check did not make. Run again without --check.\n'
  exit 3
fi
printf 'READY\n'
