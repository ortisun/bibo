#!/usr/bin/env bash
# check-pins.sh - compare every pin in pins.env with what the upstream projects publish now.
#
#   infra/sandbox-images/check-pins.sh
#
# Needs the network, gpg, curl and python3 (3.11 or newer), and a Docker client for the image
# digests. It builds nothing and downloads only small metadata files, never a binary.
#
#   Claude Code   fetches manifest.json and its signature, checks the signature against the
#                 release key whose fingerprint is in pins.env, and compares the linux checksums.
#   Rust          the same for the signed channel manifest: clippy and rustfmt archive hashes.
#   Codex         compares the SHA-256 that GitHub lists for the npm platform packages.
#   Base images   compares the index digest that the registry reports for each tag with the pin.
#
# Exit codes: 0 every pin matches, 1 a pin differs or a signature is bad, 2 misuse, 3 BLOCKED
# (no network, or a tool is missing). BLOCKED proves nothing.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=tools/common.sh
. "$here/tools/common.sh"
sbx_load_pins

[ "$#" -eq 0 ] || sbx_usage_error "this script takes no arguments"
for tool in curl gpg python3; do
  type -P "$tool" >/dev/null 2>&1 || sbx_blocked "$tool is not installed"
done
python3 -c 'import tomllib' 2>/dev/null || sbx_blocked "python3 has no tomllib (needs Python 3.11 or newer)"

work=$(mktemp -d "${TMPDIR:-/tmp}/sbx-pins.XXXXXX")
trap 'rm -rf "$work"' EXIT
bad=0

fetch() {
  curl --fail --silent --show-error --location --max-time 120 --retry 2 --output "$2" "$1" ||
    sbx_blocked "could not download $1"
}

report() {
  # report NAME PINNED UPSTREAM
  if [ "$2" = "$3" ]; then
    printf 'OK    %-34s %s\n' "$1" "$2"
  else
    printf 'DIFF  %-34s pinned %s, upstream %s\n' "$1" "$2" "${3:-nothing}"
    bad=1
  fi
}

# verify_signature NAME KEY_URL FINGERPRINT SIGNATURE FILE
verify_signature() {
  local name=$1 key_url=$2 fingerprint=$3 signature=$4 file=$5 home="$work/gpg-$1"
  mkdir -m 700 "$home"
  fetch "$key_url" "$work/$name.key"
  gpg --homedir "$home" --batch --quiet --import "$work/$name.key" 2>/dev/null || sbx_blocked "gpg could not import the $name key"
  if ! gpg --homedir "$home" --batch --with-colons --fingerprint 2>/dev/null | grep -q "^fpr:::::::::$fingerprint:"; then
    printf 'DIFF  %-34s the downloaded key does not have fingerprint %s\n' "$name key" "$fingerprint"
    bad=1
    return
  fi
  if gpg --homedir "$home" --batch --verify "$signature" "$file" >/dev/null 2>&1; then
    printf 'OK    %-34s signature verified, key %s\n' "$name manifest" "$fingerprint"
  else
    printf 'DIFF  %-34s BAD SIGNATURE\n' "$name manifest"
    bad=1
  fi
}

# --- Claude Code -----------------------------------------------------------------------------------
base="$CLAUDE_URL_BASE/$CLAUDE_VERSION"
fetch "$base/manifest.json" "$work/claude-manifest.json"
fetch "$base/manifest.json.sig" "$work/claude-manifest.json.sig"
verify_signature claude "https://downloads.claude.ai/keys/claude-code.asc" "$CLAUDE_SIGNING_FINGERPRINT" \
  "$work/claude-manifest.json.sig" "$work/claude-manifest.json"
for arch in arm64 amd64; do
  report "claude $CLAUDE_VERSION $arch" "$(sbx_pin CLAUDE_SHA256 "$arch")" \
    "$($SBX_PY "$here/tools/pincheck.py" claude-hash "$work/claude-manifest.json" "$(sbx_claude_platform_of "$arch")")"
done

# --- Rust ------------------------------------------------------------------------------------------
fetch "https://static.rust-lang.org/dist/channel-rust-$TOOLCHAIN_VERSION.toml" "$work/channel.toml"
fetch "https://static.rust-lang.org/dist/channel-rust-$TOOLCHAIN_VERSION.toml.asc" "$work/channel.toml.asc"
verify_signature rust "https://static.rust-lang.org/rust-key.gpg.ascii" "$RUST_RELEASE_SIGNING_FINGERPRINT" \
  "$work/channel.toml.asc" "$work/channel.toml"
for arch in arm64 amd64; do
  triple=$(sbx_triple_of "$arch")
  report "clippy $TOOLCHAIN_VERSION $arch" "$(sbx_pin CLIPPY_SHA256 "$arch")" \
    "$($SBX_PY "$here/tools/pincheck.py" rust-hash "$work/channel.toml" clippy-preview "$triple")"
  report "rustfmt $TOOLCHAIN_VERSION $arch" "$(sbx_pin RUSTFMT_SHA256 "$arch")" \
    "$($SBX_PY "$here/tools/pincheck.py" rust-hash "$work/channel.toml" rustfmt-preview "$triple")"
done

# --- Codex -----------------------------------------------------------------------------------------
fetch "https://api.github.com/repos/openai/codex/releases/tags/rust-v$CODEX_VERSION" "$work/codex-release.json"
for arch in arm64 amd64; do
  report "codex npm package $CODEX_VERSION $arch" "$(sbx_pin CODEX_SHA256 "$arch")" \
    "$($SBX_PY "$here/tools/pincheck.py" github-digest "$work/codex-release.json" "codex-npm-linux-$(sbx_npm_arch_of "$arch")-$CODEX_VERSION.tgz")"
done

# --- Base images -----------------------------------------------------------------------------------
if type -P docker >/dev/null 2>&1 && sbx_timeout 60 docker info >/dev/null 2>&1; then
  for entry in "RUST_BASE:$RUST_BASE" "DISTROLESS_BASE:$DISTROLESS_BASE"; do
    name=${entry%%:*}
    reference=${entry#*:}
    pinned=${reference##*@}
    upstream=$(docker buildx imagetools inspect "${reference%@*}" 2>/dev/null | sed -n 's/^Digest: *//p' | head -n 1)
    report "$name index digest" "$pinned" "$upstream"
  done
else
  echo "SKIP  base image digests: no Docker daemon to ask"
fi

if [ "$bad" -ne 0 ]; then
  echo "RESULT: FAILED (a pin differs from upstream; see README.md, Update a pin)"
  exit "$EXIT_FAILED"
fi
echo "RESULT: PASSED"
