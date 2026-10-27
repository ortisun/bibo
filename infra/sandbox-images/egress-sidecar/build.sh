#!/usr/bin/env bash
# Build the egress sidecar image and record it in images.json.
#
#   infra/sandbox-images/egress-sidecar/build.sh [--platform P] [--binary PATH --sha256 HEX]
#
# Without --binary the result is a skeleton: the right user and entrypoint, and no program.
# images.json marks it "awaiting-binary" and the adapter must refuse to use it. The program
# factory-egress-sidecar is written by work package s1-egress-and-broker and does not exist yet;
# this script never creates a stand-in for it.
#
# With --binary the file must be a Linux executable for the platform, and its SHA-256 must equal
# --sha256, so the person who supplies it states exactly which build they mean. The hash is
# recorded in images.json as binary_sha256.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=../tools/common.sh
. "$here/../tools/common.sh"

platform=""
binary=""
expected=""
while [ "$#" -gt 0 ]; do
  case $1 in
    --platform)
      [ "$#" -ge 2 ] || sbx_usage_error "--platform needs a value"
      platform=$2
      shift 2
      ;;
    --binary)
      [ "$#" -ge 2 ] || sbx_usage_error "--binary needs a path"
      binary=$2
      shift 2
      ;;
    --sha256)
      [ "$#" -ge 2 ] || sbx_usage_error "--sha256 needs a value"
      expected=$2
      shift 2
      ;;
    -h | --help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *) sbx_usage_error "unknown argument '$1'" ;;
  esac
done
if [ -n "$binary" ] && [ -z "$expected" ]; then
  sbx_usage_error "--binary needs --sha256"
fi
if [ -z "$binary" ] && [ -n "$expected" ]; then
  sbx_usage_error "--sha256 needs --binary"
fi

sbx_require_docker
sbx_load_pins
[ -n "$platform" ] || platform=$(sbx_daemon_platform)
arch=$(sbx_arch_of "$platform")

context=$(mktemp -d "${TMPDIR:-/tmp}/sbx-sidecar.XXXXXX")
trap 'rm -rf "$context"' EXIT
mkdir "$context/payload"

status="awaiting-binary"
actual=""
if [ -n "$binary" ]; then
  [ -f "$binary" ] && [ ! -L "$binary" ] || sbx_die "$binary is not a regular file"
  actual=$($SBX_PY -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$binary")
  [ "$actual" = "$expected" ] || sbx_die "the SHA-256 of $binary is $actual, not the $expected that was given"
  # An ELF header: the four magic bytes, then e_machine at offset 18 (little endian).
  magic=$(od -An -tx1 -N4 "$binary" | tr -d ' \n')
  [ "$magic" = "7f454c46" ] || sbx_die "$binary is not an ELF executable"
  machine=$(od -An -tx1 -j18 -N2 "$binary" | tr -d ' \n')
  case $arch:$machine in
    arm64:b700 | amd64:3e00) ;;
    *) sbx_die "$binary is built for machine code $machine, which is not $platform" ;;
  esac
  cp "$binary" "$context/payload/factory-egress-sidecar"
  status="ready"
fi

# The tag says what is inside: a skeleton, or the first twelve characters of the program's hash.
if [ -n "$actual" ]; then
  SBX_TAG=${SBX_TAG:-bin-${actual:0:12}}
else
  SBX_TAG=${SBX_TAG:-skeleton}
fi
export SBX_TAG

sbx_build_image egress-sidecar "$here/Dockerfile" "$context" "$platform" \
  "status=$status" \
  "profile=egress_sidecar" \
  "binary_path=/usr/local/bin/factory-egress-sidecar" \
  "binary_sha256=$actual" \
  "base=$DISTROLESS_BASE" \
  -- \
  "DISTROLESS_BASE=$DISTROLESS_BASE" \
  "SIDECAR_UID=$SIDECAR_UID" \
  "SIDECAR_GID=$SIDECAR_GID"
