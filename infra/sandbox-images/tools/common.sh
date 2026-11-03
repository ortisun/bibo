#!/usr/bin/env bash
# common.sh - helpers shared by the build, test, smoke, audit and pin-check scripts.
# Source it; do not run it. It works with the bash 3.2 that ships with macOS.
#
# Exit codes used by every script in this directory (the same as scripts/ci.sh):
#   0  everything passed
#   1  a check failed
#   2  the script was used wrongly
#   3  BLOCKED: the check could not run (no Docker, a missing image), so there is no evidence
#      either way. BLOCKED is never a pass.

# shellcheck shell=bash

SBX_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
SBX_REPO=$(cd "$SBX_DIR/../.." && pwd -P)
SBX_PINS="$SBX_DIR/pins.env"
SBX_IMAGES_JSON_DEFAULT="$SBX_DIR/images.json"
SBX_PY="python3 -I"

EXIT_FAILED=1
EXIT_USAGE=2
EXIT_BLOCKED=3

# Every image, container and network this directory creates carries one of these labels, so
# clean-up can find exactly its own leftovers and nothing else on the machine.
SBX_LABEL="factory.sandbox-images=1"
SBX_TEST_LABEL="factory.sandbox-images.test=1"

IMAGE_PREFIX="${SBX_IMAGE_PREFIX:-factory-sandbox}"
# shellcheck disable=SC2034  # read by the scripts that source this file
ROLES="agent verify egress-sidecar"

sbx_usage_error() {
  printf '%s: %s\n' "$(basename "$0")" "$*" >&2
  exit "$EXIT_USAGE"
}

# BLOCKED goes to standard output so a log that only captured stdout still shows it.
sbx_blocked() {
  printf 'BLOCKED: %s\n' "$*"
  exit "$EXIT_BLOCKED"
}

sbx_die() {
  printf 'error: %s\n' "$*" >&2
  exit "$EXIT_FAILED"
}

# Run a command with a time limit when this machine has a tool for it, and plainly otherwise.
sbx_timeout() {
  local seconds=$1
  shift
  if type -P timeout >/dev/null 2>&1; then
    timeout "$seconds" "$@"
  elif type -P gtimeout >/dev/null 2>&1; then
    gtimeout "$seconds" "$@"
  else
    "$@"
  fi
}

# BLOCKED unless the Docker client exists and the daemon answers.
sbx_require_docker() {
  type -P docker >/dev/null 2>&1 || sbx_blocked "the docker command is not installed, so no image can be built or tested"
  sbx_timeout 60 docker info >/dev/null 2>&1 ||
    sbx_blocked "the Docker daemon is not reachable (DOCKER_HOST=${DOCKER_HOST:-unset}), so no image can be built or tested"
  local os
  os=$(docker version --format '{{.Server.Os}}' 2>/dev/null || true)
  [ "$os" = "linux" ] || sbx_blocked "the Docker daemon reports operating system '${os:-unknown}', not linux"
}

# Read pins.env. Each line must be NAME=VALUE with only safe characters, so sourcing it cannot
# run anything.
sbx_load_pins() {
  [ -f "$SBX_PINS" ] || sbx_die "missing $SBX_PINS"
  local bad
  bad=$(grep -v -E -e '^[[:space:]]*(#.*)?$' -e '^[A-Za-z0-9_]+=[A-Za-z0-9._:/@+-]*$' "$SBX_PINS" || true)
  [ -z "$bad" ] || sbx_die "pins.env has a line that is not NAME=VALUE with safe characters: $bad"
  set -a
  # shellcheck source=/dev/null
  . "$SBX_PINS"
  set +a
}

# Every per-architecture pin must have a value before anything is built.
sbx_require_pins() {
  local arch=$1 name
  for name in CLIPPY_SHA256 RUSTFMT_SHA256 CLAUDE_SHA256 CODEX_SHA256 CODEX_BINARY_SHA256 RUST_BASE_MANIFEST; do
    local full="${name}_${arch}"
    [ -n "${!full:-}" ] || sbx_die "pins.env has no value for $full"
  done
}

# The value of a per-architecture pin, for example: sbx_pin CLIPPY_SHA256 arm64
sbx_pin() {
  local name="$1_$2"
  printf '%s' "${!name:-}"
}

# The platform the daemon runs, as linux/arm64 or linux/amd64.
sbx_daemon_platform() {
  local arch
  arch=$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)
  case $arch in
    arm64 | aarch64) printf 'linux/arm64' ;;
    amd64 | x86_64) printf 'linux/amd64' ;;
    *) sbx_blocked "the Docker daemon reports architecture '${arch:-unknown}', which has no pins" ;;
  esac
}

sbx_arch_of() {
  case $1 in
    linux/arm64) printf 'arm64' ;;
    linux/amd64) printf 'amd64' ;;
    *) sbx_usage_error "unsupported platform '$1' (use linux/arm64 or linux/amd64)" ;;
  esac
}

# The Rust triple, and the name Anthropic uses, for an architecture.
sbx_triple_of() {
  case $1 in
    arm64) printf 'aarch64-unknown-linux-gnu' ;;
    amd64) printf 'x86_64-unknown-linux-gnu' ;;
  esac
}
sbx_musl_triple_of() {
  case $1 in
    arm64) printf 'aarch64-unknown-linux-musl' ;;
    amd64) printf 'x86_64-unknown-linux-musl' ;;
  esac
}
sbx_npm_arch_of() {
  case $1 in
    arm64) printf 'arm64' ;;
    amd64) printf 'x64' ;;
  esac
}
sbx_claude_platform_of() {
  case $1 in
    arm64) printf 'linux-arm64' ;;
    amd64) printf 'linux-x64' ;;
  esac
}

# The Rust channel written in rust-toolchain.toml at the repository root.
sbx_toolchain_channel() {
  sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$SBX_REPO/rust-toolchain.toml" | head -n 1
}

# Fail if pins.env and rust-toolchain.toml name different compilers.
sbx_check_toolchain_pin() {
  local channel
  channel=$(sbx_toolchain_channel)
  [ -n "$channel" ] || sbx_die "no channel found in rust-toolchain.toml"
  [ "$channel" = "$TOOLCHAIN_VERSION" ] ||
    sbx_die "rust-toolchain.toml says $channel but pins.env says TOOLCHAIN_VERSION=$TOOLCHAIN_VERSION"
}

# Build arguments (NAME=VALUE lines) that the agent and verify builds share, for one architecture.
sbx_toolchain_args() {
  local arch=$1 triple
  triple=$(sbx_triple_of "$arch")
  printf '%s\n' \
    "RUST_BASE=$RUST_BASE" \
    "TOOLCHAIN_VERSION=$TOOLCHAIN_VERSION" \
    "CLIPPY_URL=$RUST_DIST_BASE/clippy-$TOOLCHAIN_VERSION-$triple.tar.gz" \
    "CLIPPY_SHA256=$(sbx_pin CLIPPY_SHA256 "$arch")" \
    "RUSTFMT_URL=$RUST_DIST_BASE/rustfmt-$TOOLCHAIN_VERSION-$triple.tar.gz" \
    "RUSTFMT_SHA256=$(sbx_pin RUSTFMT_SHA256 "$arch")" \
    "SANDBOX_UID=$SANDBOX_UID" \
    "SANDBOX_GID=$SANDBOX_GID"
}

sbx_images_json() {
  printf '%s' "${FACTORY_IMAGES_JSON:-$SBX_IMAGES_JSON_DEFAULT}"
}

sbx_json_get() {
  # sbx_json_get FILE PLATFORM ROLE FIELD
  $SBX_PY "$SBX_DIR/tools/images_json.py" get --file "$1" --platform "$2" --role "$3" --field "$4"
}

# A short tag for an image, built from what is inside it.
sbx_tag_for() {
  case $1 in
    agent) printf 'rust%s-claude%s-codex%s' "$TOOLCHAIN_VERSION" "$CLAUDE_VERSION" "$CODEX_VERSION" ;;
    verify) printf 'rust%s' "$TOOLCHAIN_VERSION" ;;
    egress-sidecar) printf 'sidecar' ;;
  esac
}

# Build one image deterministically and record it in images.json.
#   sbx_build_image ROLE DOCKERFILE CONTEXT PLATFORM EXTRA_FIELD... -- BUILD_ARG...
# The build uses the fixed clock from pins.env, no provenance or SBOM attestation (they carry
# timestamps and would change the digest) and rewrites file times to the fixed clock.
sbx_build_image() {
  local role=$1 dockerfile=$2 context=$3 platform=$4
  shift 4
  local -a fields=() build_args=() cache_args=()
  if [ -n "${SBX_NO_CACHE:-}" ]; then
    cache_args=(--no-cache)
  fi
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    fields+=(--field "$1")
    shift
  done
  [ "$#" -gt 0 ] && shift
  while [ "$#" -gt 0 ]; do
    build_args+=(--build-arg "$1")
    shift
  done

  local name="$IMAGE_PREFIX/$role" tag extra_label=()
  tag=${SBX_TAG:-$(sbx_tag_for "$role")}
  if [ -n "${SBX_EXTRA_LABEL:-}" ]; then
    extra_label=(--label "$SBX_EXTRA_LABEL")
  fi
  local ref="$name:$tag"

  echo "building $ref for $platform"
  docker buildx build \
    --platform "$platform" \
    --provenance=false --sbom=false \
    ${cache_args[@]+"${cache_args[@]}"} \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    ${build_args[@]+"${build_args[@]}"} \
    --label "$SBX_LABEL" \
    ${extra_label[@]+"${extra_label[@]}"} \
    --output "type=docker,name=$ref,rewrite-timestamp=true" \
    -f "$dockerfile" \
    "$context" || sbx_die "docker build of $role failed"

  local work inspect
  work=$(mktemp -d "${TMPDIR:-/tmp}/sbx-record.XXXXXX")
  inspect="$work/inspect.json"
  docker image inspect "$ref" >"$inspect" || sbx_die "cannot inspect $ref after the build"
  $SBX_PY "$SBX_DIR/tools/images_json.py" record \
    --file "$(sbx_images_json)" --platform "$platform" --role "$role" \
    --name "$name" --tag "$tag" --pins "$SBX_PINS" --inspect "$inspect" \
    ${fields[@]+"${fields[@]}"}
  rm -rf "$work"
}

# --- test reporting --------------------------------------------------------------------------------
T_PASS=0
T_FAIL=0

t_pass() {
  T_PASS=$((T_PASS + 1))
  printf 'PASS  %-24s %s\n' "$1" "$2"
}

t_fail() {
  T_FAIL=$((T_FAIL + 1))
  printf 'FAIL  %-24s %s\n' "$1" "$2"
}

t_info() {
  printf 'INFO  %-24s %s\n' "$1" "$2"
}

# The full hardened profile of docs/security/sandbox-policy.md section 3.2, as docker run options.
# The caller appends the image reference and the command. Resource limits are the agent profile's.
#   sbx_hardened_args UID:GID
sbx_hardened_args() {
  printf '%s\n' \
    --pull=never \
    --user "$1" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --init \
    --ipc none \
    --pids-limit 256 \
    --memory 4g --memory-swap 4g \
    --cpus 2 \
    --ulimit nofile=4096:4096 --ulimit core=0 --ulimit fsize=536870912 \
    --network none \
    --log-driver none \
    --stop-timeout 10 \
    --workdir /workspace \
    --env HOME=/home/agent \
    --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777" \
    --tmpfs "/home/agent:rw,noexec,nosuid,nodev,size=64m,uid=${1%%:*},gid=${1##*:},mode=0700" \
    --label "$SBX_TEST_LABEL"
}

# Fill the array HARDENED with the options above.
sbx_set_hardened() {
  local line
  HARDENED=()
  while IFS= read -r line; do
    HARDENED+=("$line")
  done < <(sbx_hardened_args "$1")
}

# The paths of lib/execute-only.txt, one per line (comments and blank lines left out).
#   sbx_execute_only_paths LIST_FILE
sbx_execute_only_paths() {
  local line
  while IFS= read -r line; do
    case $line in
      '' | '#'*) continue ;;
    esac
    printf '%s\n' "$line"
  done <"$1"
}

# Judges what `stat -c '%n|%a|%u:%g|%F'` printed for the paths of lib/execute-only.txt. Each path
# must be a regular file of mode 711 owned by root, so that a process started from it is not
# dumpable (finding RR-14: a readable program anywhere in the command chain of an adapter lets a
# hostile process that already runs open the exec's output pipe). One problem per line on standard
# output, nothing when the image is right. A path that stat did not print is reported missing.
#   sbx_execute_only_problems LIST_FILE < stat-lines
sbx_execute_only_problems() {
  local list=$1 seen path mode owner kind wanted
  seen=$(cat)
  while IFS='|' read -r path mode owner kind; do
    [ -n "$path" ] || continue
    if [ "$kind" != "regular file" ]; then
      printf '%s is a %s, not a regular file\n' "$path" "$kind"
    elif [ "$mode" != 711 ]; then
      case $mode in
        ???) mode="0$mode" ;;
      esac
      printf '%s mode %s\n' "$path" "$mode"
    elif [ "$owner" != "0:0" ]; then
      printf '%s owner %s\n' "$path" "$owner"
    fi
  done <<<"$seen"
  while IFS= read -r wanted; do
    grep -q -F -e "$wanted|" <<<"$seen" || printf '%s missing\n' "$wanted"
  done < <(sbx_execute_only_paths "$list")
}
