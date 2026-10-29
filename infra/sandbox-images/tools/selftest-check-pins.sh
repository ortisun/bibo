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
#     made by the pinned key is accepted. The keys are made here, at run time, and thrown away;
#   * a signature made by the pinned key before the key was REVOKED is refused (finding RR-15: gpg
#     prints VALIDSIG for it, next to REVKEYSIG and KEYREVOKED), and so is one made by a key that
#     has EXPIRED since; the same expiring key, checked while it is still good, is accepted;
#   * the judgement of the status lines on its own: a revoked, expired or bad status, a status
#     line nobody has read, a missing GOODSIG and a VALIDSIG of another key each refuse.
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
for who in pinned other revoked; do
  gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "$who <$who@example.test>" ed25519 sign never 2>/dev/null
done
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "expiring <expiring@example.test>" ed25519 sign 1d 2>/dev/null
fingerprint=$(gpg --batch --with-colons --list-keys pinned@example.test 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
gpg --batch --armor --export pinned@example.test other@example.test >"$work/ring.asc" 2>/dev/null
printf '{"platforms":{}}\n' >"$work/manifest.json"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user other@example.test --detach-sign --output "$work/by-other.sig" "$work/manifest.json" 2>/dev/null
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user pinned@example.test --detach-sign --output "$work/by-pinned.sig" "$work/manifest.json" 2>/dev/null
# The key that signs and is revoked afterwards, and the key that signs and expires afterwards.
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user revoked@example.test --detach-sign --output "$work/by-revoked.sig" "$work/manifest.json" 2>/dev/null
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --local-user expiring@example.test --detach-sign --output "$work/by-expiring.sig" "$work/manifest.json" 2>/dev/null
fp_revoked=$(gpg --batch --with-colons --list-keys revoked@example.test 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
fp_expiring=$(gpg --batch --with-colons --list-keys expiring@example.test 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')
gpg --batch --armor --export expiring@example.test >"$work/ring-expiring.asc" 2>/dev/null
# A revocation certificate needs a terminal prompt in some gpg versions; --no-tty with the answers on
# standard input works for gpg 2.5. Whether the key really is revoked is checked, so that a failure
# to revoke is a failure of this test and not a pass (the first reproduction of RR-15 never revoked
# its key).
printf 'y\n0\n\ny\n' | gpg --no-tty --yes --pinentry-mode loopback --passphrase '' --command-fd 0 \
  --output "$work/revoked.rev.asc" --gen-revoke "$fp_revoked" >/dev/null 2>&1
gpg --batch --import "$work/revoked.rev.asc" >/dev/null 2>&1
revoked_for_real=1
gpg --batch --with-colons --list-keys "$fp_revoked" 2>/dev/null | grep -q '^pub:r:' && revoked_for_real=0
gpg --batch --armor --export revoked@example.test >"$work/ring-revoked.asc" 2>/dev/null
gpgconf --homedir "$GNUPGHOME" --kill gpg-agent >/dev/null 2>&1
unset GNUPGHOME
{
  awk '/^signature_status_accepts\(\) \{/,/^}/' "$here/check-pins.sh"
  awk '/^verify_signature\(\) \{/,/^}/' "$here/check-pins.sh"
} >"$work/verify_fn.sh"
verify_with() {
  # verify_with SIGNATURE-FILE RING-FILE FINGERPRINT [FAKED-EPOCH-SECONDS] -> prints bad=0|1
  (
    bad=0
    ring=$2
    want=$3
    faked=${4:-}
    work="$work/verify-$RANDOM"
    mkdir -p "$work"
    sbx_blocked() { echo "BLOCKED: $*"; }
    fetch() { cp "$ring" "$2"; }
    if [ -n "$faked" ]; then
      # Judge the signature as of a later day, as gpg would when the key has expired by then.
      gpg() { command gpg --faked-system-time "$faked!" "$@"; }
    fi
    # shellcheck source=/dev/null
    . "$work/../verify_fn.sh"
    verify_signature probe "unused" "$want" "$1" "$work/../manifest.json" >/dev/null 2>&1
    echo "bad=$bad"
  )
}
expect "a signature by another key in the downloaded file is refused" "$(verify_with "$work/by-other.sig" "$work/ring.asc" "$fingerprint" | grep -q 'bad=1' && echo 0 || echo 1)"
expect "a signature by the pinned key is accepted" "$(verify_with "$work/by-pinned.sig" "$work/ring.asc" "$fingerprint" | grep -q 'bad=0' && echo 0 || echo 1)"
expect "the test revoked its key for real (gpg lists it as revoked)" "$revoked_for_real"
expect "a signature by the pinned key that has been REVOKED since is refused" "$(verify_with "$work/by-revoked.sig" "$work/ring-revoked.asc" "$fp_revoked" | grep -q 'bad=1' && echo 0 || echo 1)"
expect "a signature by the pinned key that has EXPIRED since is refused" "$(verify_with "$work/by-expiring.sig" "$work/ring-expiring.asc" "$fp_expiring" "$(($(date +%s) + 864000))" | grep -q 'bad=1' && echo 0 || echo 1)"
expect "the same expiring key is accepted while it is still good" "$(verify_with "$work/by-expiring.sig" "$work/ring-expiring.asc" "$fp_expiring" | grep -q 'bad=0' && echo 0 || echo 1)"

# --- signature_status_accepts(): the judgement of the status lines on its own ---------------------
# shellcheck source=/dev/null
. "$work/verify_fn.sh"
status_case() {
  # status_case EXPECTED(0|1) FINGERPRINT LINES... -> 0 when the verdict was as expected
  local want=$1 fp=$2 verdict
  shift 2
  printf '%s\n' "$@" | signature_status_accepts "$fp" >/dev/null
  verdict=$?
  [ "$verdict" -eq "$want" ] && echo 0 || echo 1
}
# The fingerprints are those of the throwaway keys made above, not literals.
KEY=$fingerprint
KEYID=${KEY: -16}
OTHER=$fp_revoked
GOOD=("[GNUPG:] NEWSIG" "[GNUPG:] KEY_CONSIDERED $KEY 0" "[GNUPG:] SIG_ID x 2026-01-01 1" "[GNUPG:] GOODSIG $KEYID a <a@b>" "[GNUPG:] VALIDSIG $KEY 2026-01-01 1 0 4 0 22 10 00 $KEY" "[GNUPG:] TRUST_ULTIMATE 0 pgp")
expect "the status of a good signature by the pinned key is accepted" "$(status_case 0 "$KEY" "${GOOD[@]}")"
expect "a status with REVKEYSIG and KEYREVOKED next to VALIDSIG is refused" "$(status_case 1 "$KEY" "${GOOD[@]/GOODSIG/REVKEYSIG}" "[GNUPG:] KEYREVOKED")"
expect "a status with KEYREVOKED added to a good one is refused" "$(status_case 1 "$KEY" "${GOOD[@]}" "[GNUPG:] KEYREVOKED")"
expect "a status with EXPKEYSIG is refused" "$(status_case 1 "$KEY" "${GOOD[@]}" "[GNUPG:] EXPKEYSIG $KEYID a <a@b>")"
expect "a status with EXPSIG is refused" "$(status_case 1 "$KEY" "${GOOD[@]}" "[GNUPG:] EXPSIG $KEYID a <a@b>")"
expect "a status with BADSIG is refused" "$(status_case 1 "$KEY" "${GOOD[@]}" "[GNUPG:] BADSIG $KEYID a <a@b>")"
expect "a status line nobody has read is refused" "$(status_case 1 "$KEY" "${GOOD[@]}" "[GNUPG:] SOMETHING_NEW 1 2")"
expect "a status with no GOODSIG is refused" "$(status_case 1 "$KEY" "${GOOD[@]/GOODSIG/NOTHING}")"
expect "a status with a VALIDSIG of another key is refused" "$(status_case 1 "$OTHER" "${GOOD[@]}")"
expect "an empty status is refused" "$(status_case 1 "$KEY")"
for home in "$work"/verify-*/gpg-*; do
  [ -d "$home" ] && gpgconf --homedir "$home" --kill gpg-agent >/dev/null 2>&1
done

if [ "$failed" -ne 0 ]; then
  echo "RESULT: FAILED"
  exit "$EXIT_FAILED"
fi
echo "RESULT: PASSED (check-pins.sh failed every case it should)"
