#!/usr/bin/env bash
# build.sh - build the API image and the worker image from the repository root.
#
#   infra/service-images/build.sh [--platform linux/arm64|linux/amd64] [--only api|worker]...
#                                 [--builder NAME] [--jobs N] [--check-reproducible]
#
# Images, built in this order: api, worker. They share one compile of the workspace. The tags are
# the ones infra/compose/local.yml expects: factory-api:local and factory-worker:local. The platform
# defaults to the one the Docker daemon runs. The two base images and the compiler version come
# from infra/sandbox-images/pins.env (the same pins as the sandbox images); the user is fixed below.
# Nothing is pulled at run time except the two pinned base images and the public crates that
# Cargo.lock names, and no host credential is read or mounted. The build context is the repository
# root, cut down to an allow list by the .dockerignore there.
#
# --builder NAME  use this buildx builder. A throwaway builder (docker buildx create --name NAME
#                 --driver docker-container) keeps the whole build cache in one place that
#                 `docker buildx rm --force NAME` removes.
# --jobs N        parallel rustc jobs inside the build. Default 4: a release build of this
#                 workspace on more jobs can need more memory than a laptop's Docker VM has.
# --check-reproducible  builds each selected image a second time with --no-cache and fails if a
#                 digest differs from the first build. It compiles the workspace again.
#
# Exit codes: 0 built, 1 a build or the check failed, 2 misuse, 3 BLOCKED (no Docker daemon).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=../sandbox-images/tools/common.sh
. "$here/../sandbox-images/tools/common.sh"

# The user of both images: numeric, not root, and the one infra/compose/local.yml runs the
# services as (FACTORY_UID and FACTORY_GID default to 10010). 10001 to 10003 belong to the sandbox
# images. test.sh --static checks that the compose file and this file agree.
SERVICE_UID=10010
SERVICE_GID=10010

platform=""
only=""
builder=""
jobs=4
check=""
while [ "$#" -gt 0 ]; do
  case $1 in
    --platform)
      [ "$#" -ge 2 ] || sbx_usage_error "--platform needs a value"
      platform=$2
      shift 2
      ;;
    --only)
      [ "$#" -ge 2 ] || sbx_usage_error "--only needs api or worker"
      only="$only $2"
      shift 2
      ;;
    --builder)
      [ "$#" -ge 2 ] || sbx_usage_error "--builder needs a name"
      builder=$2
      shift 2
      ;;
    --jobs)
      [ "$#" -ge 2 ] || sbx_usage_error "--jobs needs a number"
      jobs=$2
      shift 2
      ;;
    --check-reproducible)
      check=1
      shift
      ;;
    -h | --help)
      sed -n '2,24p' "$0"
      exit 0
      ;;
    *) sbx_usage_error "unknown argument '$1'" ;;
  esac
done

for role in $only; do
  case $role in
    api | worker) ;;
    *) sbx_usage_error "unknown image '$role' (use api or worker)" ;;
  esac
done
case $jobs in
  '' | *[!0-9]* | 0) sbx_usage_error "--jobs must be a whole number above zero" ;;
esac
selected=${only:-api worker}

sbx_require_docker
sbx_load_pins
sbx_check_toolchain_pin
[ -n "$platform" ] || platform=$(sbx_daemon_platform)
sbx_arch_of "$platform" >/dev/null
for name in RUST_BASE DISTROLESS_BASE SOURCE_DATE_EPOCH TOOLCHAIN_VERSION; do
  [ -n "${!name:-}" ] || sbx_die "pins.env has no value for $name"
done
case $RUST_BASE$DISTROLESS_BASE in
  *@sha256:*@sha256:*) ;;
  *) sbx_die "RUST_BASE and DISTROLESS_BASE in pins.env must both be pinned by digest" ;;
esac

# The commit the programs are built from: the full object id of HEAD, or nothing when the tree holds
# a change that is not committed (a tracked file changed, or a file Git does not ignore is new). Such
# a build is not the build of any commit, so its API states none and answers 503 on the process
# snapshot (ADR 0029) instead of naming a commit that did not make it.
build_commit=$(git -C "$SBX_REPO" rev-parse --verify --quiet 'HEAD^{commit}' 2>/dev/null) || build_commit=""
if [ -n "$build_commit" ] && [ -n "$(git -C "$SBX_REPO" status --porcelain 2>/dev/null)" ]; then
  build_commit=""
fi
case $build_commit in
  '') echo "note: the tree is not a clean commit, so the images state no build commit" ;;
  *[!0-9a-f]*) sbx_die "git gave a commit id that is not lowercase hexadecimal: $build_commit" ;;
esac

tag_of() { printf 'factory-%s:local' "$1"; }

# build_one ROLE [--no-cache]: build the target ROLE and load it into the local store under its tag.
build_one() {
  local role=$1 ref
  shift
  ref=$(tag_of "$role")
  local -a builder_args=()
  [ -z "$builder" ] || builder_args=(--builder "$builder")
  echo "building $ref for $platform"
  docker buildx build \
    ${builder_args[@]+"${builder_args[@]}"} \
    --platform "$platform" \
    --provenance=false --sbom=false \
    "$@" \
    --target "$role" \
    --build-arg "RUST_BASE=$RUST_BASE" \
    --build-arg "DISTROLESS_BASE=$DISTROLESS_BASE" \
    --build-arg "TOOLCHAIN_VERSION=$TOOLCHAIN_VERSION" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --build-arg "BUILD_JOBS=$jobs" \
    --build-arg "FACTORY_BUILD_COMMIT=$build_commit" \
    --build-arg "SERVICE_UID=$SERVICE_UID" \
    --build-arg "SERVICE_GID=$SERVICE_GID" \
    --output "type=docker,name=$ref,rewrite-timestamp=true" \
    -f "$here/Dockerfile" \
    "$SBX_REPO" || sbx_die "docker build of $role failed"
}

digest_of() { docker image inspect "$(tag_of "$1")" --format '{{.Id}}'; }

first=""
for role in $selected; do
  build_one "$role"
  id=$(digest_of "$role")
  first="$first $role=$id"
  echo "built $(tag_of "$role") $id"
done

if [ -n "$check" ]; then
  mismatch=""
  for role in $selected; do
    before=${first#* "$role="}
    before=${before%% *}
    build_one "$role" --no-cache
    after=$(digest_of "$role")
    if [ "$before" = "$after" ]; then
      echo "reproducible: $role $after"
    else
      echo "NOT reproducible: $role built $before, then $after with --no-cache"
      mismatch=1
    fi
  done
  [ -z "$mismatch" ] || exit "$EXIT_FAILED"
fi
