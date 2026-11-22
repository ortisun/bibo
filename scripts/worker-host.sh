#!/usr/bin/env bash
# scripts/worker-host.sh - run the factory worker on the host, beside the local stack (ADR 0036).
#
#   scripts/worker-host.sh            Prepare everything below, build the worker and run it in the foreground.
#   scripts/worker-host.sh --check    Prepare and check everything, build the worker, start nothing.
#   scripts/worker-host.sh --setcap   Linux only: also give the built program cap_chown with sudo (ADR 0035). Without
#                                     this flag the script never runs sudo; it prints the command and stops BLOCKED.
#   scripts/worker-host.sh --no-build Use the program that is already built.
#   scripts/worker-host.sh --help     Show this text.
#
# Start the database and the API first: scripts/local-up.sh --api, with FACTORY_COMPOSE_OVERRIDE set to
# infra/compose/host-worker.yml so the API reads this worker's artifacts (and, on Linux, FACTORY_UID=$(id -u)
# FACTORY_GID=$(id -g), so the API can read the files this user writes).
#
# What it prepares, under FACTORY_HOST_DIR (default .local/host-worker in the repository, when the sandbox policy
# allows that path as a mount source; a Linux checkout under /home is refused and needs a folder such as /srv/factory):
#   protected/       a copy of what the worker reads: policies, agents, profiles, schemas, the allowlist
#                    (FACTORY_ALLOWLIST_DIR, default infra/compose/allowlist) and the sandbox image catalog
#   secrets/         the database URL files of the worker's two logins, for 127.0.0.1:FACTORY_PG_PORT (mode 0600)
#   workspaces/, artifacts/, docker-config/ (empty: the worker follows no docker context or credential helper)
#   tokens/          the job token root, unless $XDG_RUNTIME_DIR exists on Linux (a tmpfs): then
#                    $XDG_RUNTIME_DIR/factory-tokens
#   worker.yaml      infra/compose/config/worker.host.example.yaml filled in, with credentials.yaml merged over it
#   credentials.yaml yours, never written by this script: broker.upstreams, github and worker.tenants
#                    (infra/compose/config/worker.local.example.yaml shows their shape)
#
# Settings (environment): FACTORY_HOST_DIR, FACTORY_SECRETS_DIR (default infra/compose/secrets, made by
# scripts/local-up.sh), FACTORY_PG_PORT (55432), FACTORY_BROKER_PORT (8731), FACTORY_ALLOWLIST_DIR, FACTORY_LOG,
# CARGO_TARGET_DIR. The broker listens on the bridge gateway address on Linux and on 127.0.0.1 on Docker Desktop; the
# sidecar reaches it at the host-gateway address a container on the bridge resolves.
#
# Exit codes: 0 ready (--check) or a clean stop, 1 failed, 2 wrong arguments, 3 BLOCKED (one line for each missing
# item; nothing was started). A secret value is never printed.
set -euo pipefail
OPS_TOOL=worker-host
# shellcheck source=lib/ops.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/lib/ops.sh"

check=0
setcap=0
build=1
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    --setcap) setcap=1 ;;
    --no-build) build=0 ;;
    -h | --help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ops_usage_error "unknown argument '$1' (try --help)" ;;
  esac
  shift
done

# OPS_PLATFORM stands in for `uname -s` in the tests, as in scripts/lib/ops.sh.
platform=${OPS_PLATFORM:-$(uname -s)}
secrets_dir=${FACTORY_SECRETS_DIR:-$OPS_ROOT/infra/compose/secrets}
pg_port=${FACTORY_PG_PORT:-55432}
broker_port=${FACTORY_BROKER_PORT:-8731}
allowlist_dir=${FACTORY_ALLOWLIST_DIR:-$OPS_ROOT/infra/compose/allowlist}
target_dir=${CARGO_TARGET_DIR:-$OPS_ROOT/target}
worker_bin=$target_dir/release/factory-worker
blocked=()
block() { blocked+=("$1"); }
report_blocked() {
  local line
  for line in "${blocked[@]}"; do printf '%s: BLOCKED: %s\n' "$OPS_TOOL" "$line" >&2; done
}

ops_require_python
command -v uv >/dev/null 2>&1 || ops_blocked "uv is not on PATH (scripts/setup-tools.sh installs it); it runs the configuration helper"
helper() { uv run --quiet --no-project --with pyyaml==6.0.3 python -I "$OPS_LIB_DIR/worker_host.py" "$@"; }
command -v docker >/dev/null 2>&1 || ops_blocked "docker is not installed or not on PATH"
docker info >/dev/null 2>&1 || ops_blocked "the Docker daemon does not answer (docker info failed)"

# ---- Where the files go, and whether the policy lets the daemon mount them ------------------------------------
host_dir=${FACTORY_HOST_DIR:-$OPS_ROOT/.local/host-worker}
case "$host_dir" in /*) ;; *) ops_usage_error "FACTORY_HOST_DIR must be an absolute path, not '$host_dir'" ;; esac
token_root=$host_dir/tokens
if [ "$platform" = Linux ] && [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "${XDG_RUNTIME_DIR:-}" ]; then
  token_root=$XDG_RUNTIME_DIR/factory-tokens
fi
refused=$(helper forbidden "$OPS_ROOT/policies/security.yaml" "$host_dir" "$token_root")
if [ -n "$refused" ]; then
  while IFS= read -r line; do
    block "paths: $line is a forbidden mount source of policies/security.yaml (sandbox.forbidden_mount_sources); set FACTORY_HOST_DIR to a folder outside them, such as /srv/factory"
  done <<<"$refused"
  report_blocked
  exit 3
fi

# ---- The local stack: the secret files and the database ------------------------------------------------------
for name in pg_password_worker pg_password_engine decision_signing_key; do
  [ -f "$secrets_dir/$name" ] || block "secrets: $secrets_dir/$name is missing; start the stack first with scripts/local-up.sh --api"
done
if ! python3 -I -c 'import socket,sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 2).close()' "$pg_port" 2>/dev/null; then
  block "database: nothing answers on 127.0.0.1:$pg_port; start it with scripts/local-up.sh --api (or set FACTORY_PG_PORT)"
fi

# ---- Docker: the daemon's endpoint, its platform and the address of the host as a container sees it ------------
docker_host=$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)
[ -n "$docker_host" ] || block "docker: the endpoint of the current docker context could not be read"
daemon_platform=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || true)
catalog=$OPS_ROOT/infra/sandbox-images/images.json
verify=$(helper image "$catalog" "$daemon_platform" verify 2>/dev/null || true)
upstream_ip=""
if [ -z "$verify" ]; then
  block "images: infra/sandbox-images/images.json has no image for the daemon's platform '$daemon_platform'"
elif ! docker image inspect "$verify" >/dev/null 2>&1; then
  block "images: $verify is not on this host; build the sandbox images with infra/sandbox-images/build.sh"
else
  upstream_ip=$(docker run --rm --pull=never --network bridge --add-host=host.docker.internal:host-gateway \
    --label factory.owner=worker-host --entrypoint getent "$verify" ahostsv4 host.docker.internal 2>/dev/null \
    | awk 'NR == 1 { print $1 }' || true)
  [ -n "$upstream_ip" ] || block "network: a container on the default bridge could not resolve host.docker.internal (host-gateway)"
fi
if [ "$platform" = Linux ]; then
  listen_ip=$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)
  [ -n "$listen_ip" ] || block "network: the gateway address of the default bridge could not be read"
else
  # Docker Desktop forwards the host-gateway address to the host's loopback.
  listen_ip=127.0.0.1
fi

# ---- The program, and on Linux its one capability ------------------------------------------------------------
if [ "$build" = 1 ]; then
  command -v cargo >/dev/null 2>&1 || ops_blocked "cargo is not on PATH; it builds the worker"
  ops_say "worker-host: building the worker (cargo build --release --locked -p factory-worker)"
  (cd "$OPS_ROOT" && cargo build --release --locked -p factory-worker) || ops_die "the worker did not build"
fi
if [ ! -x "$worker_bin" ]; then
  block "program: $worker_bin is not built; run without --no-build"
elif [ "$platform" = Linux ]; then
  has_chown() { getcap "$worker_bin" 2>/dev/null | grep -q 'cap_chown'; }
  if ! has_chown && [ "$setcap" = 1 ]; then
    ops_say "worker-host: giving $worker_bin cap_chown (sudo setcap cap_chown+ep, ADR 0035)"
    sudo setcap cap_chown+ep "$worker_bin" || ops_die "sudo setcap failed"
  fi
  has_chown || block "capability: $worker_bin lacks cap_chown, so no agent sandbox could read its job token (ADR 0035); run: sudo setcap cap_chown+ep $worker_bin (or this script with --setcap). A rebuild drops it."
fi

credentials=$host_dir/credentials.yaml
[ -f "$credentials" ] || block "credentials: $credentials is missing: the model provider (broker.upstreams), the GitHub App (github) and the tenants (worker.tenants) are yours to supply (their shape is in infra/compose/config/worker.local.example.yaml)"

if [ ${#blocked[@]} -gt 0 ]; then
  report_blocked
  exit 3
fi

# ---- Write the folders, the URL files, the protected copy and the configuration --------------------------------
umask 077
mkdir -p "$host_dir" "$host_dir/secrets" "$host_dir/workspaces" "$host_dir/artifacts" "$host_dir/docker-config" "$token_root"
chmod 0700 "$host_dir/secrets" "$host_dir/docker-config" "$token_root"
for pair in worker:factory_worker engine:factory_engine; do
  (printf 'postgres://%s:%s@127.0.0.1:%s/factory' "${pair#*:}" "$(tr -d '\n' <"$secrets_dir/pg_password_${pair%%:*}")" "$pg_port" \
    >"$host_dir/secrets/db_${pair%%:*}")
  chmod 0600 "$host_dir/secrets/db_${pair%%:*}"
done
protected=$host_dir/protected
rm -rf "$protected"
mkdir -p "$protected/infra/sandbox-images"
for folder in policies agents profiles schemas; do cp -R "$OPS_ROOT/$folder" "$protected/$folder"; done
cp -R "$allowlist_dir" "$protected/allowlist"
cp "$catalog" "$protected/infra/sandbox-images/images.json"
chmod -R go-rwx "$protected"

helper render "$OPS_ROOT/infra/compose/config/worker.host.example.yaml" "$host_dir/worker.yaml" --credentials "$credentials" \
  "PROTECTED=$protected" "SECRETS=$host_dir/secrets" "KEY_FILE=$secrets_dir/decision_signing_key" \
  "ARTIFACTS=$host_dir/artifacts" "TOKEN_ROOT=$token_root" "WORKSPACES=$host_dir/workspaces" \
  "DOCKER_HOST=$docker_host" "DOCKER_CONFIG=$host_dir/docker-config" \
  "BROKER_LISTEN=$listen_ip:$broker_port" "UPSTREAM=$upstream_ip:$broker_port" \
  || ops_die "the configuration could not be written (the reason is above)"

ops_say "worker-host: configuration $host_dir/worker.yaml"
ops_say "  broker listens on $listen_ip:$broker_port; sidecars reach it at $upstream_ip:$broker_port"
ops_say "  job tokens in $token_root; workspaces and artifacts in $host_dir"
if [ "$check" = 1 ]; then
  ops_say "READY"
  exit 0
fi
ops_say "worker-host: starting $worker_bin (Ctrl-C stops it)"
exec env FACTORY_CONFIG="$host_dir/worker.yaml" FACTORY_PROFILE=local FACTORY_LOG="${FACTORY_LOG:-info}" "$worker_bin"
