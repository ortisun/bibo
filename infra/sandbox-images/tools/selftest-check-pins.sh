#!/usr/bin/env bash
# selftest-check-pins.sh - prove that check-pins.sh fails when it should, with no network.
#
#   infra/sandbox-images/tools/selftest-check-pins.sh
#
# check-pins.sh compares pins.env with what the upstream projects publish. A check that has never
# been seen to fail proves nothing, and this one reads the network, so the cases are made here:
#
#   * the base image section, with a stand-in `docker` that answers like a registry: the pins as
#     committed pass; a reference with no digest, a floating tag whose digest is not the pin, a
#     wrong digest and an empty pin each fail;
#   * the same section with no Docker daemon at all is BLOCKED, not a pass;
#   * a pin with no value does not match an upstream lookup that found nothing;
#   * a signature made by another key that sits in the downloaded key file is refused, and one
#     made by the pinned key is accepted. The keys are made here, at run time, and thrown away.
#
# Exit codes: 0 every case behaved, 1 one did not, 3 BLOCKED (gpg or python3 is missing).
set -uo pipefail

here=$(cd "$(dirname "$0")/.." && pwd -P)
# shellcheck source=/dev/null
. "$here/tools/common.sh"
for tool in gpg python3 awk; do
  type -P "$tool" >/dev/null 2>&1 || sbx_blocked "$tool is not installed"
done

# gpg keeps a socket in its home, and a socket path is short. Use a short directory.
work=$(mktemp -d /tmp/sbx-selftest.XXXXXX)
cleanup() {
  for home in "$work"/gnupg-*; do
    [ -d "$home" ] && gpgconf --homedir "$home" --kill gpg-agent >/dev/null 2>&1
  done
  rm -rf "$work"
}
trap cleanup EXIT
failed=0
expect() {
  # expect LABEL CONDITION-RESULT(0|1)
  if [ "$2" -eq 0 ]; then
    printf 'ok    %s\n' "$1"
  else
    printf 'FAIL  %s\n' "$1"
    failed=1
  fi
}

# --- the base image section, on a copy with a stand-in docker -------------------------------------
cp -R "$here" "$work/si"
mkdir "$work/bin"
cat >"$work/bin/docker" <<'EOF'
#!/bin/sh
case "$1" in
  info) [ -n "$SBX_SELFTEST_NO_DAEMON" ] && exit 1; exit 0 ;;
  buildx)
    case "$4" in
      rust:*) echo "Digest: sha256:$SBX_SELFTEST_RUST_DIGEST" ;;
      gcr.io/*) echo "Digest: sha256:$SBX_SELFTEST_DISTROLESS_DIGEST" ;;
      *) exit 1 ;;
    esac ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$work/bin/docker"
# Keep the functions at the top of the script and the base image section; drop the network parts.
awk '/^# --- Claude Code/{skip=1} /^# --- Base images/{skip=0} !skip{print}' "$here/check-pins.sh" >"$work/si/check-pins-base.sh"
chmod +x "$work/si/check-pins-base.sh"

pinned_rust=$(sed -n 's/^RUST_BASE=.*@sha256://p' "$here/pins.env")
pinned_distroless=$(sed -n 's/^DISTROLESS_BASE=.*@sha256://p' "$here/pins.env")
run_base() {
  # run_base 'RUST_BASE=...'   (empty argument: the pins as committed)
  cp "$here/pins.env" "$work/si/pins.env"
  if [ -n "$1" ]; then
    sed "s|^RUST_BASE=.*|$1|" "$here/pins.env" >"$work/si/pins.env"
  fi
  OUT=$(PATH="$work/bin:$PATH" SBX_SELFTEST_RUST_DIGEST="$pinned_rust" SBX_SELFTEST_DISTROLESS_DIGEST="$pinned_distroless" \
    "$work/si/check-pins-base.sh" 2>&1)
  RC=$?
}

run_base ""
expect "base pins as committed pass" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)"
run_base "RUST_BASE=rust:1.98.0-slim-trixie"
expect "a base with no digest fails" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
run_base "RUST_BASE=rust:latest@sha256:2222222222222222222222222222222222222222222222222222222222222222"
expect "a floating tag with a digest that is not the pin fails" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
run_base "RUST_BASE=rust:1.98.0-slim-trixie@sha256:3333333333333333333333333333333333333333333333333333333333333333"
expect "a base with a wrong digest fails" "$([ "$RC" -eq 1 ] && echo 0 || echo 1)"
run_base "RUST_BASE="
expect "an empty base pin fails" "$([ "$RC" -eq 1 ] && printf '%s' "$OUT" | grep -q 'the pin has no value' && echo 0 || echo 1)"
cp "$here/pins.env" "$work/si/pins.env"
OUT=$(PATH="$work/bin:$PATH" SBX_SELFTEST_NO_DAEMON=1 "$work/si/check-pins-base.sh" 2>&1)
RC=$?
expect "no Docker daemon is BLOCKED, not a pass" "$([ "$RC" -eq 3 ] && echo 0 || echo 1)"

# --- report(): an empty pin against an empty lookup -----------------------------------------------
awk '/^report\(\) \{/,/^}/' "$here/check-pins.sh" >"$work/report_fn.sh"
OUT=$(
  bad=0
  # shellcheck source=/dev/null
  . "$work/report_fn.sh"
  report "claude arm64" "" ""
  echo "bad=$bad"
)
expect "an empty pin does not match an empty lookup" "$(printf '%s' "$OUT" | grep -q 'bad=1' && echo 0 || echo 1)"

# --- verify_signature(): the pinned key, not any key in the downloaded file ------------------------
export GNUPGHOME="$work/gnupg-src"
mkdir -m 700 "$GNUPGHOME"
for who in pinned other; do
  gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "$who <$who@example.test>" ed25519 sign never 2>/dev/null
done
fingerprint=$(gpg --batch --with-colons --list-keys pinned@example.test 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
gpg --batch --armor --export pinned@example.test other@example.test >"$work/ring.asc" 2>/dev/null
printf '{"platforms":{}}\n' >"$work/manifest.json"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user other@example.test --detach-sign --output "$work/by-other.sig" "$work/manifest.json" 2>/dev/null
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user pinned@example.test --detach-sign --output "$work/by-pinned.sig" "$work/manifest.json" 2>/dev/null
gpgconf --homedir "$GNUPGHOME" --kill gpg-agent >/dev/null 2>&1
unset GNUPGHOME
awk '/^verify_signature\(\) \{/,/^}/' "$here/check-pins.sh" >"$work/verify_fn.sh"
verify_with() {
  # verify_with SIGNATURE-FILE -> prints bad=0|1
  (
    bad=0
    work="$work/verify-$RANDOM"
    mkdir -p "$work"
    sbx_blocked() { echo "BLOCKED: $*"; }
    fetch() { cp "$work/../ring.asc" "$2"; }
    # shellcheck source=/dev/null
    . "$work/../verify_fn.sh"
    verify_signature probe "unused" "$fingerprint" "$1" "$work/../manifest.json" >/dev/null 2>&1
    echo "bad=$bad"
  )
}
expect "a signature by another key in the downloaded file is refused" "$(verify_with "$work/by-other.sig" | grep -q 'bad=1' && echo 0 || echo 1)"
expect "a signature by the pinned key is accepted" "$(verify_with "$work/by-pinned.sig" | grep -q 'bad=0' && echo 0 || echo 1)"
for home in "$work"/verify-*/gpg-*; do
  [ -d "$home" ] && gpgconf --homedir "$home" --kill gpg-agent >/dev/null 2>&1
done

if [ "$failed" -ne 0 ]; then
  echo "RESULT: FAILED"
  exit "$EXIT_FAILED"
fi
echo "RESULT: PASSED (check-pins.sh failed every case it should)"
