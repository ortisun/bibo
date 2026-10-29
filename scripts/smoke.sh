#!/usr/bin/env bash
# scripts/smoke.sh - start a throwaway copy of the local stack and check that it is what the design says.
#
#   scripts/smoke.sh                  The whole smoke test. Needs Docker, psql, diesel and the sandbox images.
#   scripts/smoke.sh --static         Only the checks that read the rendered Compose file. Needs the docker CLI and its
#                                     Compose plugin, and no running Docker daemon. Cheap and deterministic: this is the
#                                     part that scripts/ci.sh runs.
#   scripts/smoke.sh --report FILE    Write the machine-readable report (JSON, mode 0600) to FILE.
#
# The static checks (scripts/lib/factory_ops.py check-topology), on infra/compose/local.yml with every profile on:
#   PostgreSQL is on the data network and nothing else; the sandbox probe is on an internal network that PostgreSQL is
#   not on; the broker network is internal; every published port is bound to 127.0.0.1; every image is pinned by digest
#   or is never pulled; every service drops all capabilities, has a read-only root, no-new-privileges, memory and
#   process limits and a profile, and mounts no Docker socket; no secret-looking variable holds a value; the factory
#   services run as one non-root user (10010:10010, or FACTORY_UID:FACTORY_GID) that owns the artifact volume; the
#   decision signing key is mounted in the api and the worker at one path and in no other service, and that path is
#   the one both configuration files name.
#
# The dynamic checks, on a project named factory-smoke-<run> (profile test, one data network and one internal network,
# both labelled factory.test=true, removed at the end, the machine-wide Docker lock held meanwhile):
#   1. every container is healthy (PostgreSQL) or running (the probe), and the artifact volume belongs to the factory user (10010 unless FACTORY_UID is set) with 0700;
#   2. the migrations apply and each of the three logins passes the start-up role check;
#   3. nothing is published except on 127.0.0.1, and a connection to this machine's own LAN address on the
#      database port is refused;
#   4. the sandbox probe (the real agent image under the sandbox policy flags) cannot resolve "postgres", cannot connect
#      to PostgreSQL's address, cannot connect to this machine's published port through host.docker.internal and cannot
#      reach the internet; the same attempt from a container on the data network DOES connect (a control, so a
#      failure above means "no route" and not "the test cannot connect").
#
# Exit codes: 0 every check passed, 1 a check failed, 2 wrong arguments, 3 BLOCKED (Docker, psql, diesel, python3 or the
# sandbox image is missing, or the lock was not free in time). BLOCKED is never a pass.

# The OPS_* variables set below are read by scripts/lib/ops.sh, which this script sources.
# shellcheck disable=SC2034
set -euo pipefail
OPS_TOOL=smoke
# shellcheck source=lib/ops.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/lib/ops.sh"

static=0
report=""
while [ $# -gt 0 ]; do
  case "$1" in
    --static) static=1 ;;
    --report) report=${2:?--report needs a file}; shift ;;
    -h | --help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ops_usage_error "unknown argument '$1' (try --help)" ;;
  esac
  shift
done

ops_require_python
ops_install_traps
ops_new_run
started=$SECONDS
OPS_TEST=true
OPS_PROFILE="test"
OPS_PROJECT="factory-smoke-$OPS_RUN_ID"
OPS_SECRETS_DIR="$OPS_RUN_DIR/secrets"

# ---- static: the rendered Compose file ------------------------------------------------------------------------------

smoke_static() {
  command -v docker >/dev/null 2>&1 || ops_blocked "docker is not installed or not on PATH"
  docker compose version --short >/dev/null 2>&1 || ops_blocked "the 'docker compose' plugin is not available"
  # The file needs FACTORY_SECRETS_DIR to render. The folder is never read here, so a path that does not exist will do.
  local -a files=(-f "$OPS_COMPOSE_FILE")
  [ -z "${FACTORY_COMPOSE_OVERRIDE:-}" ] || files+=(-f "$FACTORY_COMPOSE_OVERRIDE")
  FACTORY_SECRETS_DIR="$OPS_RUN_DIR/no-secrets" COMPOSE_PROFILES=local,test,factory \
    docker compose "${files[@]}" config --format json >"$OPS_RUN_DIR/config.json" 2>"$OPS_RUN_DIR/config.err" \
    || { head -n 5 "$OPS_RUN_DIR/config.err" >&2; ops_die "docker compose cannot render $OPS_COMPOSE_FILE"; }
  ops_py_checks check-topology --config "$OPS_RUN_DIR/config.json"
}

# ---- dynamic ----------------------------------------------------------------------------------------------------------

# The agent sandbox image, by digest, from the catalog of the sandbox images work package.
sandbox_image() {
  local platform
  platform=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
  python3 -I -c 'import json, sys
catalog = json.load(open(sys.argv[1]))
image = catalog.get("platforms", {}).get(sys.argv[2], {}).get("images", {}).get("agent", {})
print(image.get("reference", "") if image.get("status") == "ready" else "")' "$OPS_ROOT/infra/sandbox-images/images.json" "$platform"
}

probe_connects() { # host port -> exit status 0 when the TCP connection was made
  docker exec "$PROBE" timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1
}

smoke_dynamic() {
  ops_require_docker
  ops_require_psql
  ops_require_diesel
  local image
  image=$(sandbox_image)
  [ -n "$image" ] || ops_blocked "no ready agent sandbox image for this platform in infra/sandbox-images/images.json. Build it: infra/sandbox-images/build.sh"
  docker image inspect "$image" >/dev/null 2>&1 || ops_blocked "the sandbox image $image is not on this machine. Build it: infra/sandbox-images/build.sh"
  ops_make_secrets "$OPS_SECRETS_DIR"
  export FACTORY_SECRETS_DIR=$OPS_SECRETS_DIR FACTORY_TEST=true FACTORY_RUN_ID=$OPS_RUN_ID FACTORY_RESTART=no
  export FACTORY_SANDBOX_PROBE_IMAGE=$image
  FACTORY_PG_PORT=$(ops_free_port)
  export FACTORY_PG_PORT
  OPS_PG_IMAGE_REF=$(ops_compose config --images 2>/dev/null | grep '^postgres:' | head -n1) || true

  smoke_cleanup() {
    ops_stack_down
    ops_lock_release
    if ! ops_leftovers; then OPS_EXIT_CODE=1; ops_warn "objects of this run are still there (label factory.run=$OPS_RUN_ID)"; fi
  }
  ops_on_exit smoke_cleanup
  ops_lock_acquire
  ops_say "smoke: project $OPS_PROJECT, PostgreSQL on 127.0.0.1:$FACTORY_PG_PORT, probe image ${image##*@}"
  ops_stack_up postgres sandbox-probe
  ops_find_postgres
  ops_write_pgpass
  PROBE=$(docker ps -q --filter "label=com.docker.compose.project=$OPS_PROJECT" --filter "label=com.docker.compose.service=sandbox-probe" | head -n1)

  # 1. Health.
  local id name health bad=""
  for id in $(docker ps -q --filter "label=com.docker.compose.project=$OPS_PROJECT"); do
    name=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$id")
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$id")
    case "$name:$health" in postgres:healthy | sandbox-probe:running) ;; *) bad="$bad $name=$health" ;; esac
  done
  if [ -z "$bad" ]; then ops_check containers-healthy PASS "postgres healthy, sandbox-probe running"; else ops_check containers-healthy FAIL "$bad"; fi
  local owner
  owner=$(ops_volume_run "$OPS_ARTIFACT_VOLUME" ro 'stat -c "%u:%g %a" /v')
  if [ "$owner" = "$OPS_FACTORY_UID:$OPS_FACTORY_GID 700" ]; then ops_check artifact-volume-owner-and-mode PASS "$owner"; else ops_check artifact-volume-owner-and-mode FAIL "got '$owner', expected '$OPS_FACTORY_UID:$OPS_FACTORY_GID 700'"; fi

  # 2. The database is ready for the factory services.
  ops_migrate
  ops_ensure_logins
  local applied expected login want got
  applied=$(ops_sql -c 'SELECT count(*) FROM __diesel_schema_migrations')
  expected=$(find "$OPS_ROOT/migrations" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
  if [ "$applied" = "$expected" ]; then ops_check schema-version PASS "$applied migrations applied"; else ops_check schema-version FAIL "$applied of $expected migrations applied"; fi
  for pair in "factory_worker:f|f|f|t|f|f|f" "factory_api:f|f|f|t|f|t|f" "factory_engine:f|f|f|f|t|f|f"; do
    login=${pair%%:*}; want=${pair#*:}
    if got=$(ops_role_readiness "$login" 2>&1) && [ "$got" = "$want" ]; then ops_check "readiness-$login" PASS "logs in over 127.0.0.1:$OPS_PG_PORT; role check $got"
    else ops_check "readiness-$login" FAIL "got '$got', expected '$want'"; fi
  done

  # 3. Exposure.
  # The container ids are hexadecimal words, so splitting them is what is wanted.
  # shellcheck disable=SC2046
  docker inspect $(docker ps -aq --filter "label=com.docker.compose.project=$OPS_PROJECT") >"$OPS_RUN_DIR/inspect.json"
  got=$(python3 -I -c 'import json, sys
bad = []
for c in json.load(open(sys.argv[1])):
    if c["HostConfig"]["NetworkMode"] == "host": bad.append(c["Name"] + " uses the host network")
    for port, bindings in (c["NetworkSettings"]["Ports"] or {}).items():
        for b in bindings or []:
            if b["HostIp"] != "127.0.0.1": bad.append("%s publishes %s on %s" % (c["Name"], port, b["HostIp"]))
print("; ".join(bad) or "ok")' "$OPS_RUN_DIR/inspect.json")
  if [ "$got" = ok ]; then ops_check ports-loopback-only PASS "every published port is on 127.0.0.1 (docker inspect of every container)"; else ops_check ports-loopback-only FAIL "$got"; fi
  got=$(python3 -I -c 'import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(("192.0.2.1", 9)); lan = s.getsockname()[0]
except OSError:
    lan = ""
if not lan or lan.startswith("127."):
    print("skip:no LAN address on this machine"); sys.exit()
try:
    socket.create_connection((lan, int(sys.argv[1])), timeout=3).close()
    print("open:%s accepted a connection on the database port" % lan)
except OSError as e:
    print("refused:%s refused the connection (%s)" % (lan, type(e).__name__))' "$OPS_PG_PORT")
  case "$got" in
    refused:*) ops_check lan-address-refused PASS "${got#refused:}" ;;
    skip:*) ops_check lan-address-refused SKIP "${got#skip:}" ;;
    *) ops_check lan-address-refused FAIL "${got#open:}" ;;
  esac

  # 4. The sandbox has no route to PostgreSQL.
  local pg_ip nets
  pg_ip=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}' "$OPS_PG")
  nets=$(docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$PROBE")
  if [ "$nets" = "${OPS_PROJECT}_probe_net " ] && [ "$(docker network inspect "${OPS_PROJECT}_probe_net" --format '{{.Internal}}')" = true ]; then
    ops_check sandbox-network-is-internal PASS "the probe is on $nets only, and it is --internal"
  else ops_check sandbox-network-is-internal FAIL "probe networks: $nets"; fi
  got=$(docker inspect --format '{{.Config.User}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.CapDrop}}|{{.HostConfig.SecurityOpt}}' "$PROBE")
  if [ "$got" = "10001:10001|true|[ALL]|[no-new-privileges:true]" ]; then ops_check sandbox-posture PASS "$got"; else ops_check sandbox-posture FAIL "$got"; fi

  # The control: the same attempt from the data network succeeds, so the failures below mean "no route".
  if docker run --rm --pull never --network "${OPS_PROJECT}_data" --user 10001:10001 --cap-drop ALL \
       --security-opt no-new-privileges:true --read-only --memory 128m --pids-limit 32 \
       --label factory.managed=true --label factory.test=true --label "factory.run=$OPS_RUN_ID" \
       --entrypoint /bin/bash "$image" -c 'timeout 4 bash -c "exec 3<>/dev/tcp/postgres/5432"' >/dev/null 2>&1; then
    ops_check control-data-network-reaches-postgres PASS "a container on the data network connects to postgres:5432, so the method can connect"
  else ops_check control-data-network-reaches-postgres FAIL "the control connection failed; the negative results below prove nothing"; fi
  if docker exec "$PROBE" getent hosts postgres >/dev/null 2>&1; then ops_check sandbox-cannot-resolve-postgres FAIL "the probe resolved the name 'postgres'"
  else ops_check sandbox-cannot-resolve-postgres PASS "the name 'postgres' does not resolve in the sandbox network"; fi
  if probe_connects "$pg_ip" 5432; then ops_check sandbox-cannot-reach-postgres-address FAIL "the probe connected to $pg_ip:5432"
  else ops_check sandbox-cannot-reach-postgres-address PASS "no connection from the sandbox to $pg_ip:5432"; fi
  if probe_connects host.docker.internal "$OPS_PG_PORT"; then ops_check sandbox-cannot-reach-published-port FAIL "the probe reached the published database port through the host"
  else ops_check sandbox-cannot-reach-published-port PASS "no connection from the sandbox to host.docker.internal:$OPS_PG_PORT"; fi
  if probe_connects 1.1.1.1 443; then ops_check sandbox-has-no-internet FAIL "the probe connected to 1.1.1.1:443"
  else ops_check sandbox-has-no-internet PASS "no connection from the sandbox to 1.1.1.1:443"; fi
}

if [ "$static" = 1 ]; then
  ops_say "smoke: static checks of $OPS_COMPOSE_FILE"
  smoke_static
else
  smoke_static
  smoke_dynamic
fi

ops_say "smoke: finished in $((SECONDS - started))s"
rc=0
ops_finish "$report" --meta "mode=$([ "$static" = 1 ] && echo static || echo full)" --meta "seconds=$((SECONDS - started))" || rc=$?
if [ "$rc" = 0 ]; then ops_say "smoke: PASS"; else ops_say "smoke: FAIL"; fi
exit "$rc"
