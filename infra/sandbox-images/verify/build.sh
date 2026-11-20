#!/usr/bin/env bash
# Build the verify image and record it in images.json.
#
#   infra/sandbox-images/verify/build.sh [--platform linux/arm64|linux/amd64]
#
# The platform defaults to the one the Docker daemon runs. Exit 3 (BLOCKED) when there is no
# Docker daemon. All versions and checksums come from pins.env.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=../tools/common.sh
. "$here/../tools/common.sh"

platform=""
while [ "$#" -gt 0 ]; do
  case $1 in
    --platform)
      [ "$#" -ge 2 ] || sbx_usage_error "--platform needs a value"
      platform=$2
      shift 2
      ;;
    -h | --help)
      sed -n '2,8p' "$0"
      exit 0
      ;;
    *) sbx_usage_error "unknown argument '$1'" ;;
  esac
done

sbx_require_docker
sbx_load_pins
sbx_check_toolchain_pin
[ -n "$platform" ] || platform=$(sbx_daemon_platform)
arch=$(sbx_arch_of "$platform")
sbx_require_pins "$arch"

build_args=()
while IFS= read -r line; do
  build_args+=("$line")
done < <(sbx_toolchain_args "$arch")

sbx_build_image verify "$here/Dockerfile" "$SBX_DIR" "$platform" \
  "status=ready" \
  "profile=verify" \
  "home=/home/agent" \
  "mount_points=/workspace,/out,/cache,/home/agent" \
  "base=$RUST_BASE" \
  "tools.rustc=$TOOLCHAIN_VERSION" \
  -- \
  "${build_args[@]}"
