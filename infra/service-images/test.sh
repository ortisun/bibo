#!/usr/bin/env bash
# test.sh - tests for the API image and the worker image.
#
#   infra/service-images/test.sh                  every rule on both images (needs Docker and the images)
#   infra/service-images/test.sh --only api       one image (repeatable)
#   infra/service-images/test.sh --static         the rules that need only the files, no Docker daemon
#   infra/service-images/test.sh --self-test      damage the files one rule at a time; every damage must be caught
#   infra/service-images/test.sh --list           list the rules and exit
#   infra/service-images/test.sh --platform linux/arm64
#
# The images under test are factory-api:local and factory-worker:local in the local Docker store,
# which build.sh makes. A rule never builds or pulls anything.
#
# Exit codes:
#   0  every selected rule passed
#   1  at least one rule failed
#   2  the script was used wrongly
#   3  BLOCKED. There is no Docker daemon or an image is missing, so nothing was tested. This is
#      never a pass.
#
# Every container this script makes carries the label factory.service-images.test=1 and is removed
# when the script ends, whatever the outcome. The file system audit is the one of the sandbox
# images (infra/sandbox-images/tools/fsaudit.py), which reads its secret patterns from
# policies/security.yaml.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=../sandbox-images/tools/common.sh
. "$here/../sandbox-images/tools/common.sh"

SVC_TEST_LABEL="factory.service-images.test=1"
ROLES_SVC="api worker"
PLATFORM=""
ONLY=""
STATIC=""
SELF=""
LIST=""
while [ "$#" -gt 0 ]; do
  case $1 in
    --only)
      [ "$#" -ge 2 ] || sbx_usage_error "--only needs api or worker"
      ONLY="$ONLY $2"
      shift 2
      ;;
    --platform)
      [ "$#" -ge 2 ] || sbx_usage_error "--platform needs a value"
      PLATFORM=$2
      shift 2
      ;;
    --static) STATIC=1; shift ;;
    --self-test) SELF=1; shift ;;
    --list) LIST=1; shift ;;
    -h | --help)
      sed -n '2,22p' "$0"
      exit 0
      ;;
    *) sbx_usage_error "unknown argument '$1'" ;;
  esac
done
for role in $ONLY; do
  case " $ROLES_SVC " in
    *" $role "*) ;;
    *) sbx_usage_error "unknown image '$role' (use api or worker)" ;;
  esac
done
SELECTED=${ONLY:-$ROLES_SVC}

if [ -n "$LIST" ]; then
  cat <<'EOF'
STATIC               [--static]  Dockerfile, build.sh, .dockerignore, pins.env and local.yml keep the promises (check_static.py; 7 rules)
IMAGE-USER           the image user is a numeric, non-root uid:gid of 10000 or higher
IMAGE-CONFIG         environment, labels, entry point and history hold no secret, no unexpected variable, no volume, no health check
ONLY-THE-PROGRAM     the program is the one file the image adds: root-owned, mode 0555, an ELF for the platform
NO-SHELL             no shell anywhere, and the image cannot start one
NO-SETID             no setuid or setgid file
NO-WORLD-WRITABLE    no file or directory that any user may write, other than the sticky temporary directories
NO-FORBIDDEN         no git, GitHub CLI, package manager, network client or unneeded interpreter
NO-CREDENTIAL        no credential file name and no content that policies/security.yaml blocks
STARTS               under the hardened profile (read-only root, no capabilities, no network, the image user) the program starts,
                     and with no configuration it says so and exits with code 2; with a configuration whose protected checkout
                     is missing it stops at its start-up check with code 1
SIZE                 report the size of each image
EOF
  exit 0
fi

if [ -n "$SELF" ]; then
  exec python3 -I "$here/check_static.py" --self-test
fi
if [ -n "$STATIC" ]; then
  type -P python3 >/dev/null 2>&1 || sbx_blocked "python3 is not installed, and the static rules need it"
  python3 -I "$here/check_static.py"
  exit $?
fi

# --- the image tests ---------------------------------------------------------------------------
sbx_require_docker
sbx_load_pins
[ -n "$PLATFORM" ] || PLATFORM=$(sbx_daemon_platform)
ARCH=$(sbx_arch_of "$PLATFORM")
POLICY="$SBX_REPO/policies/security.yaml"
[ -f "$POLICY" ] || sbx_blocked "$POLICY is missing, so the secret patterns cannot be read"
type -P python3 >/dev/null 2>&1 || sbx_blocked "python3 is not installed, and the file system audit needs it"
LIB="$here/../sandbox-images/lib"
FSAUDIT="$here/../sandbox-images/tools/fsaudit.py"

ref_of() { printf 'factory-%s:local' "$1"; }
for role in $SELECTED; do
  docker image inspect "$(ref_of "$role")" >/dev/null 2>&1 ||
    sbx_blocked "image $(ref_of "$role") is not in the local Docker store, so nothing was tested. Run infra/service-images/build.sh first."
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/svc-test.XXXXXX")
CONTAINERS=""
cleanup() {
  local c
  for c in $CONTAINERS; do docker rm -f "$c" >/dev/null 2>&1; done
  rm -rf "$WORK"
}
trap cleanup EXIT

first_lines() { printf '%s\n' "$1" | head -n "${2:-3}" | tr '\n' ';' | cut -c1-300; }

# The user the images must run as: the one build.sh fixes.
SERVICE_UID=$(sed -n 's/^SERVICE_UID=\([0-9]*\)$/\1/p' "$here/build.sh")
SERVICE_GID=$(sed -n 's/^SERVICE_GID=\([0-9]*\)$/\1/p' "$here/build.sh")

# Export the file system of an image once and audit it. Result: $WORK/fs-ROLE/*.txt
fs_audit() {
  local role=$1 dir="$WORK/fs-$1" name
  [ -f "$dir/summary.txt" ] && return 0
  mkdir -p "$dir"
  name="svc-test-$$-$role"
  docker create --pull=never --name "$name" --label "$SVC_TEST_LABEL" "$(ref_of "$role")" >/dev/null || return 1
  CONTAINERS="$CONTAINERS $name"
  docker export "$name" | python3 -I "$FSAUDIT" fs --out-dir "$dir" \
    --forbidden "$LIB/forbidden-binaries.txt" --shells "$LIB/shells.txt" --policy "$POLICY"
  local rc=("${PIPESTATUS[@]}")
  docker export "$name" >"$WORK/fs-$role.tar" 2>/dev/null
  docker rm -f "$name" >/dev/null 2>&1
  [ "${rc[0]}" -eq 0 ] && [ "${rc[1]}" -eq 0 ] && [ -f "$dir/summary.txt" ]
}

expect_empty() {
  local id=$1 role=$2 file=$3 text=$4
  fs_audit "$role" || { t_fail "$id" "$role: could not read the image file system"; return; }
  if [ -s "$WORK/fs-$role/$file" ]; then
    t_fail "$id" "$role: $text: $(first_lines "$(cat "$WORK/fs-$role/$file")" 4)"
  else
    t_pass "$id" "$role: none"
  fi
}

# run_in ROLE [docker run options] -- [ARGUMENT...]   sets OUT (stdout and stderr) and RC. The
# hardened profile of the services: read-only root, no capabilities, no new privileges, no network,
# the user of the image, memory and process limits, a temporary directory in memory.
OUT=""
RC=0
run_in() {
  local role=$1
  shift
  local -a extra=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    extra+=("$1")
    shift
  done
  [ "$#" -gt 0 ] && shift
  OUT=$(sbx_timeout 120 docker run --rm --pull=never --label "$SVC_TEST_LABEL" \
    --user "$SERVICE_UID:$SERVICE_GID" --read-only --cap-drop ALL --security-opt no-new-privileges \
    --network none --memory 256m --pids-limit 128 --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    ${extra[@]+"${extra[@]}"} "$(ref_of "$role")" "$@" 2>&1)
  RC=$?
}

rule_image_user() {
  local role user
  for role in $SELECTED; do
    user=$(docker image inspect "$(ref_of "$role")" --format '{{.Config.User}}')
    case $user in
      [0-9]*:[0-9]*) ;;
      *) t_fail IMAGE-USER "$role: Config.User is '${user:-empty}', not a numeric uid:gid"; continue ;;
    esac
    if [ "${user%%:*}" -lt 10000 ] || [ "${user##*:}" -lt 10000 ]; then
      t_fail IMAGE-USER "$role: Config.User '$user' is below 10000 (root or a system user)"
    elif [ "$user" != "$SERVICE_UID:$SERVICE_GID" ]; then
      t_fail IMAGE-USER "$role: Config.User '$user' differs from $SERVICE_UID:$SERVICE_GID in build.sh"
    else
      t_pass IMAGE-USER "$role: $user"
    fi
  done
}

rule_image_config() {
  local role findings labels entry
  for role in $SELECTED; do
    mkdir -p "$WORK/config-$role"
    docker image inspect "$(ref_of "$role")" >"$WORK/config-$role/inspect.json" 2>/dev/null
    docker history --no-trunc "$(ref_of "$role")" >"$WORK/config-$role/history.txt" 2>/dev/null
    findings=$(python3 -I "$FSAUDIT" config --inspect "$WORK/config-$role/inspect.json" \
      --history "$WORK/config-$role/history.txt" --policy "$POLICY" --allowed-env PATH --allowed-env SSL_CERT_FILE 2>&1)
    entry=$(docker image inspect "$(ref_of "$role")" --format '{{json .Config.Entrypoint}}{{json .Config.Cmd}}')
    labels=$(docker image inspect "$(ref_of "$role")" --format '{{index .Config.Labels "factory.service-images"}}/{{index .Config.Labels "factory.service.role"}}')
    if [ -n "$findings" ]; then
      t_fail IMAGE-CONFIG "$role: $(first_lines "$findings" 4)"
    elif [ "$entry" != "[\"/usr/local/bin/factory-$role\"]null" ]; then
      t_fail IMAGE-CONFIG "$role: the entry point and command are $entry, not the program alone"
    elif [ "$labels" != "1/$role" ]; then
      t_fail IMAGE-CONFIG "$role: the labels say '$labels', not '1/$role'"
    else
      t_pass IMAGE-CONFIG "$role: environment limited to PATH and SSL_CERT_FILE; entry point is the program; no secret in config or history"
    fi
  done
}

rule_only_the_program() {
  local role found machine
  for role in $SELECTED; do
    fs_audit "$role" || { t_fail ONLY-THE-PROGRAM "$role: could not read the image file system"; continue; }
    # mode, owner and the ELF header of the program, read from the exported file system without running it.
    found=$(python3 -I - "$WORK/fs-$role.tar" "usr/local/bin/factory-$role" <<'EOF'
import sys, tarfile
tar = tarfile.open(sys.argv[1])
try:
    member = tar.getmember(sys.argv[2])
except KeyError:
    print("missing"); raise SystemExit
head = tar.extractfile(member).read(20)
print(f"{member.mode:04o} {member.uid}:{member.gid} {head[:4].hex()} {head[18:20].hex()} {member.size}")
others = [m.name for m in tar if m.name.startswith("usr/local/") and m.isfile() and m.name != sys.argv[2]]
if others:
    print("also " + ",".join(others))
EOF
)
    case $ARCH in arm64) machine=b700 ;; amd64) machine=3e00 ;; esac
    case $found in
      "0555 0:0 7f454c46 $machine "*) t_pass ONLY-THE-PROGRAM "$role: factory-$role is root-owned, mode 0555, an ELF for $PLATFORM" ;;
      *) t_fail ONLY-THE-PROGRAM "$role: $(first_lines "$found" 3)" ;;
    esac
  done
}

rule_no_shell() {
  local role
  for role in $SELECTED; do
    expect_empty NO-SHELL "$role" shells.txt "a shell exists"
    # The image cannot start one either: a shell as the entry point does not exist.
    run_in "$role" --entrypoint /bin/sh -- -c true
    if [ "$RC" -eq 0 ]; then
      t_fail NO-SHELL "$role: /bin/sh started"
    else
      t_pass NO-SHELL "$role: /bin/sh cannot be started (exit $RC)"
    fi
  done
}

rule_simple() { # RULE FILE TEXT
  local role
  for role in $SELECTED; do expect_empty "$1" "$role" "$2" "$3"; done
}

rule_no_credential() {
  local role
  for role in $SELECTED; do
    expect_empty NO-CREDENTIAL "$role" credential-names.txt "a credential file"
    expect_empty NO-CREDENTIAL "$role" secrets.txt "content that the security policy blocks"
  done
}

rule_starts() {
  local role config
  for role in $SELECTED; do
    # 1. No configuration: the program says which variable is missing and exits with code 2.
    run_in "$role" --
    if [ "$RC" -eq 2 ] && printf '%s' "$OUT" | grep -q "factory-$role: FACTORY_CONFIG: is not set"; then
      t_pass STARTS "$role: with no configuration it starts, says FACTORY_CONFIG is not set and exits with code 2"
    else
      t_fail STARTS "$role: with no configuration: exit $RC: $(first_lines "$OUT" 3)"
    fi
    # 2. A configuration file that is not there.
    run_in "$role" --env FACTORY_CONFIG=/nonexistent/factory.yaml --
    if [ "$RC" -eq 2 ] && printf '%s' "$OUT" | grep -q "cannot be read"; then
      t_pass STARTS "$role: a missing configuration file is named and refused (exit 2)"
    else
      t_fail STARTS "$role: a missing configuration file: exit $RC: $(first_lines "$OUT" 3)"
    fi
    # 3. The example configuration of the local stack, with no protected checkout behind it: the
    #    program reads the file, begins its start-up checks and stops at the first (exit 1).
    config="$SBX_REPO/infra/compose/config/$role.local.example.yaml"
    run_in "$role" --env FACTORY_CONFIG=/etc/factory/factory.yaml --env FACTORY_PROFILE=local \
      --mount "type=bind,src=$config,dst=/etc/factory/factory.yaml,readonly" --
    if [ "$RC" -eq 1 ] && printf '%s' "$OUT" | grep -q "factory-$role: start-up check failed"; then
      t_pass STARTS "$role: with the example configuration and no checkout it stops at its start-up check (exit 1)"
    else
      t_fail STARTS "$role: with the example configuration: exit $RC: $(first_lines "$OUT" 3)"
    fi
  done
}

rule_size() {
  local role
  for role in $SELECTED; do
    t_info SIZE "$role: $(docker image inspect "$(ref_of "$role")" --format '{{.Size}}' | awk '{printf "%.1f MB", $1 / 1048576}')"
  done
}

rule_image_user
rule_image_config
rule_only_the_program
rule_no_shell
rule_simple NO-SETID setid.txt "a setuid or setgid file"
rule_simple NO-WORLD-WRITABLE world-writable.txt "a world-writable path"
rule_simple NO-FORBIDDEN forbidden.txt "a forbidden program"
rule_no_credential
rule_starts
rule_size

echo
printf 'PASSED %s   FAILED %s\n' "$T_PASS" "$T_FAIL"
[ "$T_FAIL" -eq 0 ] || exit "$EXIT_FAILED"
exit 0
