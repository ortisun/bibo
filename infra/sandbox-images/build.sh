#!/usr/bin/env bash
# build.sh - build the three sandbox images and write their digests to images.json.
#
#   infra/sandbox-images/build.sh [--platform linux/arm64|linux/amd64] [--only IMAGE]...
#                                 [--sidecar-binary PATH --sidecar-sha256 HEX]
#                                 [--check-reproducible]
#
# Images, built in this order: verify, agent, egress-sidecar. Each has its own build.sh that can be
# run alone. The platform defaults to the one the Docker daemon runs. Every version and checksum
# comes from pins.env. Nothing is pulled at run time and no host credential is read or mounted:
# the build downloads public files only, and each one must match its pinned checksum.
#
# --check-reproducible builds each selected image a second time with --no-cache into a scratch
# file and fails if a digest differs from the first build.
#
# Exit codes: 0 built, 1 a build or the check failed, 2 misuse, 3 BLOCKED (no Docker daemon).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=tools/common.sh
. "$here/tools/common.sh"

platform=""
only=""
sidecar_args=()
check=""
while [ "$#" -gt 0 ]; do
  case $1 in
    --platform)
      [ "$#" -ge 2 ] || sbx_usage_error "--platform needs a value"
      platform=$2
      shift 2
      ;;
    --only)
      [ "$#" -ge 2 ] || sbx_usage_error "--only needs an image name"
      only="$only $2"
      shift 2
      ;;
    --sidecar-binary)
      [ "$#" -ge 2 ] || sbx_usage_error "--sidecar-binary needs a path"
      sidecar_args+=(--binary "$2")
      shift 2
      ;;
    --sidecar-sha256)
      [ "$#" -ge 2 ] || sbx_usage_error "--sidecar-sha256 needs a value"
      sidecar_args+=(--sha256 "$2")
      shift 2
      ;;
    --check-reproducible)
      check=1
      shift
      ;;
    -h | --help)
      sed -n '2,19p' "$0"
      exit 0
      ;;
    *) sbx_usage_error "unknown argument '$1'" ;;
  esac
done

for role in $only; do
  case " $ROLES " in
    *" $role "*) ;;
    *) sbx_usage_error "unknown image '$role' (use one of: $ROLES)" ;;
  esac
done
selected=${only:-verify agent egress-sidecar}

sbx_require_docker
[ -n "$platform" ] || platform=$(sbx_daemon_platform)

build_one() {
  local role=$1
  shift
  case $role in
    egress-sidecar) "$here/$role/build.sh" --platform "$platform" ${sidecar_args[@]+"${sidecar_args[@]}"} "$@" ;;
    *) "$here/$role/build.sh" --platform "$platform" "$@" ;;
  esac
}

for role in $selected; do
  build_one "$role"
done

if [ -n "$check" ]; then
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/sbx-repro.XXXXXX")
  trap 'rm -rf "$scratch"' EXIT
  mismatch=""
  for role in $selected; do
    first=$(sbx_json_get "$(sbx_images_json)" "$platform" "$role" digest)
    SBX_NO_CACHE=1 FACTORY_IMAGES_JSON="$scratch/images.json" build_one "$role"
    second=$(sbx_json_get "$scratch/images.json" "$platform" "$role" digest)
    if [ "$first" = "$second" ]; then
      echo "reproducible: $role $first"
    else
      echo "NOT reproducible: $role built $first, then $second with --no-cache"
      mismatch=1
    fi
  done
  [ -z "$mismatch" ] || exit "$EXIT_FAILED"
fi

echo
echo "wrote $(sbx_images_json)"
