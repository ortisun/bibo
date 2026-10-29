#!/usr/bin/env bash
# test.sh - posture tests for the three sandbox images.
#
#   infra/sandbox-images/test.sh                     run every rule on every image
#   infra/sandbox-images/test.sh --only agent        limit to one image (repeatable)
#   infra/sandbox-images/test.sh --rule NO-SETID     run one rule (repeatable)
#   infra/sandbox-images/test.sh --group audit       run a group of rules: posture, smoke, audit
#   infra/sandbox-images/test.sh --list              list the rules and exit
#   infra/sandbox-images/test.sh --images-json FILE  test the images that FILE names
#   infra/sandbox-images/test.sh --platform linux/arm64
#
# The images under test are the ones images.json names for the platform, found in the local
# Docker image store by digest. Build them first with build.sh.
#
# Exit codes:
#   0  every selected rule passed
#   1  at least one rule failed
#   2  the script was used wrongly
#   3  BLOCKED. There is no Docker daemon, or images.json or an image is missing. Nothing was
#      tested, so this is never a pass.
#
# A rule that does not apply to any selected image prints SKIP. SKIP is not a pass.
#
# Every container and image this script creates carries the label factory.sandbox-images.test=1
# and is removed when the script ends, whatever the outcome.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=tools/common.sh
. "$here/tools/common.sh"

# --- arguments -----------------------------------------------------------------------------------
IMAGES_JSON=$(sbx_images_json)
PLATFORM=""
ONLY=""
RULE_FILTER=""
GROUP_FILTER=""
LIST_ONLY=""

while [ "$#" -gt 0 ]; do
  case $1 in
    --images-json)
      [ "$#" -ge 2 ] || sbx_usage_error "--images-json needs a path"
      IMAGES_JSON=$2
      shift 2
      ;;
    --platform)
      [ "$#" -ge 2 ] || sbx_usage_error "--platform needs a value"
      PLATFORM=$2
      shift 2
      ;;
    --only)
      [ "$#" -ge 2 ] || sbx_usage_error "--only needs an image name"
      ONLY="$ONLY $2"
      shift 2
      ;;
    --rule)
      [ "$#" -ge 2 ] || sbx_usage_error "--rule needs a rule id"
      RULE_FILTER="$RULE_FILTER $2"
      shift 2
      ;;
    --group)
      [ "$#" -ge 2 ] || sbx_usage_error "--group needs a name"
      GROUP_FILTER="$GROUP_FILTER $2"
      shift 2
      ;;
    --list) LIST_ONLY=1; shift ;;
    -h | --help)
      sed -n '2,24p' "$0"
      exit 0
      ;;
    *) sbx_usage_error "unknown argument '$1'" ;;
  esac
done

for role in $ONLY; do
  case " $ROLES " in
    *" $role "*) ;;
    *) sbx_usage_error "unknown image '$role' (use one of: $ROLES)" ;;
  esac
done
SELECTED=${ONLY:-$ROLES}

# --- rule registry -------------------------------------------------------------------------------
RULE_IDS=()
RULE_FUNCS=()
RULE_GROUPS=()
RULE_TEXT=()

register() {
  RULE_IDS+=("$1")
  RULE_FUNCS+=("$2")
  RULE_GROUPS+=("$3")
  RULE_TEXT+=("$4")
}

register PINS               rule_pins               "posture"               "pins.env agrees with rust-toolchain.toml and images.json was built from the current pins"
register IMAGES-JSON        rule_images_json        "posture"               "images.json names a digest-pinned reference per image and the local store holds the same digest"
register IMAGE-USER         rule_image_user         "posture"               "the image user is a numeric, non-root uid:gid of 10000 or higher"
register IMAGE-CONFIG       rule_image_config       "posture audit"         "image environment, labels, command and history hold no secret, no unexpected variable, no volume"
register NO-SETID           rule_no_setid           "posture"               "no setuid or setgid file"
register NO-WORLD-WRITABLE  rule_no_world_writable  "posture audit"         "no file or directory that any user may write, other than the sticky temporary directories"
register NO-FORBIDDEN       rule_no_forbidden       "posture audit"         "no git, GitHub CLI, package manager, network client, account tool or unneeded interpreter"
register SHELLS             rule_shells             "posture"               "agent keeps only bash, sh and dash; verify and the sidecar have no shell"
register TOOLS-ONLY-IN-AGENT rule_tools_only_agent  "posture audit"         "claude and codex exist only in the agent image, at the pinned checksums"
register TOOLS-EXECUTE-ONLY rule_tools_execute_only "posture audit"         "in the agent image every program of the adapters' command chain (env, timeout, the tools) is execute-only (0711), so their processes are not dumpable"
register NO-CREDENTIAL-FILES rule_no_credential_files "posture audit"       "no credential file or credential directory in any image"
register NO-SECRET-CONTENT  rule_no_secret_content  "posture audit"         "a scan of every file finds no secret that policies/security.yaml blocks"
register RUNTIME-PROFILE    rule_runtime_profile    "posture"               "under the hardened profile: non-root, no capabilities, no-new-privileges, seccomp, no network interface"
register READONLY-ROOT      rule_readonly_root      "posture"               "the root file system is read-only; the documented tmpfs paths are writable"
register NO-TOOLS-RUN       rule_no_tools_run       "posture audit"         "git, gh, apt-get, dpkg, rustup, curl, wget, ssh and python3 cannot be started"
register TOOLCHAIN          rule_toolchain          "posture smoke"         "rustc, cargo, clippy, rustfmt and cc run and rustc equals rust-toolchain.toml"
register OFFLINE-BUILD      rule_offline_build      "smoke"                 "build, test, fmt and clippy of a sample crate run offline, read-only source, in the verify image"
register AGENT-TOOLS-RUN    rule_agent_tools_run    "posture"               "claude --version and codex --version start under the full hardened profile"
register SIDECAR-STATE      rule_sidecar_state      "posture"               "the sidecar image holds no program (skeleton) or exactly the pinned one, and a skeleton fails to start"
register SIDECAR-CONTRACT   rule_sidecar_contract   "posture"               "the sidecar Dockerfile accepts a program and runs it non-root on a read-only root (uses a labelled probe, not a sidecar)"
register SIZE               rule_size               "posture"               "report the size of each image"

if [ -n "$LIST_ONLY" ]; then
  i=0
  while [ "$i" -lt "${#RULE_IDS[@]}" ]; do
    printf '%-22s [%s] %s\n' "${RULE_IDS[$i]}" "${RULE_GROUPS[$i]}" "${RULE_TEXT[$i]}"
    i=$((i + 1))
  done
  exit 0
fi

rule_selected() {
  local id=$1 groups=$2 g
  if [ -n "$RULE_FILTER" ]; then
    case " $RULE_FILTER " in *" $id "*) return 0 ;; *) return 1 ;; esac
  fi
  if [ -n "$GROUP_FILTER" ]; then
    for g in $GROUP_FILTER; do
      case " $groups " in *" $g "*) return 0 ;; esac
    done
    return 1
  fi
  return 0
}

if [ -n "$RULE_FILTER" ]; then
  for wanted in $RULE_FILTER; do
    known=""
    for id in "${RULE_IDS[@]}"; do [ "$id" = "$wanted" ] && known=1; done
    [ -n "$known" ] || sbx_usage_error "unknown rule '$wanted' (see --list)"
  done
fi

# --- environment ---------------------------------------------------------------------------------
sbx_require_docker
sbx_load_pins
[ -n "$PLATFORM" ] || PLATFORM=$(sbx_daemon_platform)
ARCH=$(sbx_arch_of "$PLATFORM")
POLICY="$SBX_REPO/policies/security.yaml"

[ -f "$IMAGES_JSON" ] || sbx_blocked "$IMAGES_JSON does not exist. Run infra/sandbox-images/build.sh first."
[ -f "$POLICY" ] || sbx_blocked "$POLICY is missing, so the secret patterns cannot be read"
type -P python3 >/dev/null 2>&1 || sbx_blocked "python3 is not installed, and the file system audit needs it"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/sbx-test.XXXXXX")
CONTAINERS=""
TEST_IMAGES=""

cleanup() {
  local c i
  for c in $CONTAINERS; do docker rm -f "$c" >/dev/null 2>&1; done
  for i in $TEST_IMAGES; do docker image rm -f "$i" >/dev/null 2>&1; done
  # Files that a container user created may belong to a uid the host user cannot delete from.
  # Remove them with a throwaway container that runs as root, then the rest from the host.
  if [ -d "$WORK/sample" ] && [ -n "${SAMPLE_CLEANUP_REF:-}" ]; then
    docker run --rm --pull=never --user 0:0 --label "$SBX_TEST_LABEL" \
      --mount "type=bind,src=$WORK/sample,dst=/w" "$SAMPLE_CLEANUP_REF" rm -rf /w/out /w/crate >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# Per-image facts, read once from images.json and the local store.
ref_of() { local v="REF_${1//-/_}"; printf '%s' "${!v}"; }
uid_of() { local v="UID_${1//-/_}"; printf '%s' "${!v}"; }
gid_of() { local v="GID_${1//-/_}"; printf '%s' "${!v}"; }
status_of() { local v="STATUS_${1//-/_}"; printf '%s' "${!v}"; }

for role in $SELECTED; do
  key=${role//-/_}
  ref=$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" "$role" reference 2>/dev/null) ||
    sbx_blocked "$IMAGES_JSON has no '$role' image for $PLATFORM. Run infra/sandbox-images/build.sh first."
  docker image inspect "$ref" >/dev/null 2>&1 ||
    sbx_blocked "image $ref is not in the local Docker store. Run infra/sandbox-images/build.sh first."
  printf -v "REF_$key" '%s' "$ref"
  printf -v "UID_$key" '%s' "$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" "$role" user.uid)"
  printf -v "GID_$key" '%s' "$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" "$role" user.gid)"
  printf -v "STATUS_$key" '%s' "$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" "$role" status)"
done

has_role() { case " $SELECTED " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# --- helpers -------------------------------------------------------------------------------------
# run_in ROLE [docker run options] -- COMMAND...   sets OUT (stdout and stderr) and RC.
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
  sbx_set_hardened "$(uid_of "$role"):$(gid_of "$role")"
  OUT=$(sbx_timeout 900 docker run --rm "${HARDENED[@]}" ${extra[@]+"${extra[@]}"} "$(ref_of "$role")" "$@" 2>&1)
  RC=$?
}

first_lines() { printf '%s\n' "$1" | head -n "${2:-3}" | tr '\n' ';' | cut -c1-300; }

# Export the file system of an image once and audit it. Result: $WORK/fs-ROLE/*.txt
fs_audit() {
  local role=$1 dir="$WORK/fs-$1" name known=""
  [ -f "$dir/summary.txt" ] && return 0
  mkdir -p "$dir"
  name="sbx-test-$$-$role"
  docker create --pull=never --name "$name" --label "$SBX_TEST_LABEL" "$(ref_of "$role")" /nonexistent >/dev/null || return 1
  CONTAINERS="$CONTAINERS $name"
  if [ "$role" = agent ]; then
    known="--known-sha256 $(sbx_pin CLAUDE_SHA256 "$ARCH") --known-sha256 $(sbx_pin CODEX_BINARY_SHA256 "$ARCH")"
  fi
  # shellcheck disable=SC2086  # $known is two options with values that contain no spaces
  docker export "$name" | $SBX_PY "$here/tools/fsaudit.py" fs --out-dir "$dir" \
    --forbidden "$here/lib/forbidden-binaries.txt" --shells "$here/lib/shells.txt" --policy "$POLICY" $known
  local rc=("${PIPESTATUS[@]}")
  docker rm -f "$name" >/dev/null 2>&1
  [ "${rc[0]}" -eq 0 ] && [ "${rc[1]}" -eq 0 ] && [ -f "$dir/summary.txt" ]
}

# Judge one finding file: empty means pass.
expect_empty() {
  local id=$1 role=$2 file=$3 text=$4
  fs_audit "$role" || { t_fail "$id" "$role: could not read the image file system"; return; }
  if [ -s "$WORK/fs-$role/$file" ]; then
    t_fail "$id" "$role: $text: $(first_lines "$(cat "$WORK/fs-$role/$file")" 4)"
  else
    t_pass "$id" "$role: none"
  fi
}

skip_rule() { printf 'SKIP  %-24s %s\n' "$1" "$2"; }

# --- rules ---------------------------------------------------------------------------------------
rule_pins() {
  local channel
  channel=$(sbx_toolchain_channel)
  if [ "$channel" = "$TOOLCHAIN_VERSION" ]; then
    t_pass PINS "pins.env TOOLCHAIN_VERSION $TOOLCHAIN_VERSION equals the channel in rust-toolchain.toml"
  else
    t_fail PINS "rust-toolchain.toml says $channel, pins.env says $TOOLCHAIN_VERSION"
  fi
  local recorded current
  recorded=$($SBX_PY -c 'import json,sys;print(json.load(open(sys.argv[1]))["platforms"][sys.argv[2]]["pins_sha256"])' "$IMAGES_JSON" "$PLATFORM")
  current=$($SBX_PY -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$SBX_PINS")
  if [ "$recorded" = "$current" ]; then
    t_pass PINS "images.json was built from the current pins.env"
  else
    t_fail PINS "images.json was built from a different pins.env; rebuild with build.sh"
  fi
}

rule_images_json() {
  local role ref digest local_digest name
  for role in $SELECTED; do
    ref=$(ref_of "$role")
    digest=$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" "$role" digest)
    name=$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" "$role" name)
    local_digest=$(docker image inspect "$ref" --format '{{.Descriptor.digest}}' 2>/dev/null || true)
    case $ref in
      "$name@sha256:"*) ;;
      *) t_fail IMAGES-JSON "$role: reference '$ref' is not name@sha256:digest"; continue ;;
    esac
    if [ "$local_digest" = "$digest" ]; then
      t_pass IMAGES-JSON "$role: $digest"
    else
      t_fail IMAGES-JSON "$role: images.json says $digest, the local store says '${local_digest:-nothing}'"
    fi
  done
}

rule_image_user() {
  local role user uid gid
  for role in $SELECTED; do
    user=$(docker image inspect "$(ref_of "$role")" --format '{{.Config.User}}' 2>/dev/null || true)
    case $user in
      [0-9]*:[0-9]*) ;;
      *) t_fail IMAGE-USER "$role: Config.User is '${user:-empty}', not a numeric uid:gid"; continue ;;
    esac
    uid=${user%%:*}
    gid=${user##*:}
    case $uid$gid in *[!0-9]*) t_fail IMAGE-USER "$role: Config.User '$user' is not numeric"; continue ;; esac
    if [ "$uid" -lt 10000 ] || [ "$gid" -lt 10000 ]; then
      t_fail IMAGE-USER "$role: Config.User '$user' is below 10000 (root or a system user)"
    elif [ "$uid:$gid" != "$(uid_of "$role"):$(gid_of "$role")" ]; then
      t_fail IMAGE-USER "$role: Config.User '$user' differs from images.json"
    else
      t_pass IMAGE-USER "$role: $user"
    fi
  done
}

rule_image_config() {
  local role allowed args findings
  for role in $SELECTED; do
    mkdir -p "$WORK/config-$role"
    docker image inspect "$(ref_of "$role")" >"$WORK/config-$role/inspect.json" 2>/dev/null
    docker history --no-trunc "$(ref_of "$role")" >"$WORK/config-$role/history.txt" 2>/dev/null
    allowed="PATH"
    [ "$role" = egress-sidecar ] && allowed="PATH SSL_CERT_FILE"
    args=()
    for n in $allowed; do args+=(--allowed-env "$n"); done
    findings=$($SBX_PY "$here/tools/fsaudit.py" config --inspect "$WORK/config-$role/inspect.json" \
      --history "$WORK/config-$role/history.txt" --policy "$POLICY" "${args[@]}" 2>&1)
    if [ -n "$findings" ]; then
      t_fail IMAGE-CONFIG "$role: $(first_lines "$findings" 4)"
    else
      t_pass IMAGE-CONFIG "$role: environment limited to $allowed; no secret in config or history"
    fi
  done
}

rule_no_setid() {
  local role
  for role in $SELECTED; do expect_empty NO-SETID "$role" setid.txt "setuid or setgid files"; done
}

rule_no_world_writable() {
  local role
  for role in $SELECTED; do expect_empty NO-WORLD-WRITABLE "$role" world-writable.txt "world-writable files or directories"; done
}

rule_no_forbidden() {
  local role
  for role in $SELECTED; do expect_empty NO-FORBIDDEN "$role" forbidden.txt "forbidden programs"; done
}

rule_shells() {
  local role line path base bad have_bash have_sh
  for role in $SELECTED; do
    fs_audit "$role" || { t_fail SHELLS "$role: could not read the image file system"; continue; }
    if [ "$role" = agent ]; then
      bad=""
      have_bash=""
      have_sh=""
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        path=${line%% *}
        base=${path##*/}
        case $base in
          bash) have_bash=1 ;;
          sh) have_sh=1 ;;
          dash) ;;
          *) bad="$bad $path" ;;
        esac
      done <"$WORK/fs-$role/shells.txt"
      if [ -n "$bad" ]; then
        t_fail SHELLS "agent: shells beyond bash, sh and dash:$bad"
      elif [ -z "$have_bash" ] || [ -z "$have_sh" ]; then
        t_fail SHELLS "agent: bash or sh is missing, so the agent tools cannot run commands"
      else
        t_pass SHELLS "agent: only bash, sh and dash"
      fi
    else
      expect_empty SHELLS "$role" shells.txt "shells"
    fi
  done
}

rule_tools_only_agent() {
  local role
  for role in $SELECTED; do
    fs_audit "$role" || { t_fail TOOLS-ONLY-IN-AGENT "$role: could not read the image file system"; continue; }
    if [ "$role" != agent ]; then
      expect_empty TOOLS-ONLY-IN-AGENT "$role" agent-tools.txt "agent tools"
      continue
    fi
    local claude codex
    claude=$(grep -c "^/usr/local/bin/claude sha256 $(sbx_pin CLAUDE_SHA256 "$ARCH")\$" "$WORK/fs-agent/agent-tools.txt" || true)
    codex=$(grep -c "^/opt/codex/bin/codex sha256 $(sbx_pin CODEX_BINARY_SHA256 "$ARCH")\$" "$WORK/fs-agent/agent-tools.txt" || true)
    local others
    others=$(grep -v -e '^/usr/local/bin/claude' -e '^/opt/codex/bin/codex' "$WORK/fs-agent/agent-tools.txt" || true)
    if [ "$claude" -eq 1 ] && [ "$codex" -eq 1 ] && [ -z "$others" ]; then
      t_pass TOOLS-ONLY-IN-AGENT "agent: claude $CLAUDE_VERSION and codex $CODEX_VERSION at the pinned checksums, no other copy"
    else
      t_fail TOOLS-ONLY-IN-AGENT "agent: expected one claude and one codex at the pinned checksums; got: $(first_lines "$(cat "$WORK/fs-agent/agent-tools.txt")" 6)"
    fi
  done
}

# A process started from a file that nobody can read is not dumpable (the kernel clears the flag at
# exec). Its /proc/<pid>/fd, /proc/<pid>/mem and /proc/<pid>/environ then belong to root, so a
# process of the sandbox user, such as a command the model asked the tool to run, can neither write
# the standard output pipe of the tool through /proc/<pid>/fd/1 nor attach to it (finding SBX-4).
# The adapters start `env -i ... timeout ... <tool>`, and every one of those programs holds the same
# pipe in turn, so a hostile process that already runs when the exec starts wins the pipe of the
# first READABLE program of the chain and keeps it across the exec calls that follow (finding RR-14).
# Every program of lib/execute-only.txt must therefore be exactly 0711: execute for everyone, read
# for nobody but root, no write, a regular file owned by root. The modes are read with `stat`, run
# under the hardened profile as the sandbox user, so the rule needs nothing the image does not have.
rule_tools_execute_only() {
  local role list paths problems
  list="$here/lib/execute-only.txt"
  for role in $SELECTED; do
    if [ "$role" != agent ]; then
      t_pass TOOLS-EXECUTE-ONLY "$role: not applicable, the image holds no agent tool"
      continue
    fi
    paths=$(sbx_execute_only_paths "$list")
    if [ -z "$paths" ]; then
      t_fail TOOLS-EXECUTE-ONLY "agent: $list names no program"
      continue
    fi
    # shellcheck disable=SC2086  # the paths are absolute and contain no space
    run_in agent -- stat -c '%n|%a|%u:%g|%F' $paths
    if [ "$RC" -ne 0 ] && ! printf '%s' "$OUT" | grep -q -F 'No such file'; then
      t_fail TOOLS-EXECUTE-ONLY "agent: stat could not run: $(first_lines "$OUT" 2)"
      continue
    fi
    problems=$(printf '%s\n' "$OUT" | grep -v -e '^stat: ' | sbx_execute_only_problems "$list")
    if [ -z "$problems" ]; then
      t_pass TOOLS-EXECUTE-ONLY "agent: $(printf '%s\n' "$paths" | wc -l | tr -d ' ') programs of the command chain are mode 0711, owner root: $(printf '%s' "$paths" | tr '\n' ' ')"
    else
      t_fail TOOLS-EXECUTE-ONLY "agent: not execute-only: $(first_lines "$problems" 6)"
    fi
  done
}

rule_no_credential_files() {
  local role
  for role in $SELECTED; do expect_empty NO-CREDENTIAL-FILES "$role" credential-names.txt "credential files"; done
}

rule_no_secret_content() {
  local role
  for role in $SELECTED; do
    expect_empty NO-SECRET-CONTENT "$role" secrets.txt "secret-shaped content"
    if [ -s "$WORK/fs-$role/skipped.txt" ]; then
      t_info NO-SECRET-CONTENT "$role: $(first_lines "$(cat "$WORK/fs-$role/skipped.txt")" 3)"
    fi
  done
}

rule_runtime_profile() {
  local role status routes
  for role in agent verify; do
    has_role "$role" || continue
    run_in "$role" -- cat /proc/self/status
    if [ "$RC" -ne 0 ]; then
      t_fail RUNTIME-PROFILE "$role: could not read /proc/self/status under the hardened profile: $(first_lines "$OUT")"
      continue
    fi
    status=$OUT
    local want_uid problems=""
    want_uid=$(uid_of "$role")
    printf '%s\n' "$status" | grep -q -E "^Uid:[[:space:]]+${want_uid}[[:space:]]+${want_uid}[[:space:]]+${want_uid}[[:space:]]+${want_uid}\$" || problems="$problems uid-is-not-$want_uid"
    printf '%s\n' "$status" | grep -q -E '^CapEff:[[:space:]]+0000000000000000$' || problems="$problems CapEff-not-zero"
    printf '%s\n' "$status" | grep -q -E '^CapPrm:[[:space:]]+0000000000000000$' || problems="$problems CapPrm-not-zero"
    printf '%s\n' "$status" | grep -q -E '^CapBnd:[[:space:]]+0000000000000000$' || problems="$problems CapBnd-not-zero"
    printf '%s\n' "$status" | grep -q -E '^NoNewPrivs:[[:space:]]+1$' || problems="$problems NoNewPrivs-not-1"
    printf '%s\n' "$status" | grep -q -E '^Seccomp:[[:space:]]+2$' || problems="$problems Seccomp-not-2"
    # --network none leaves loopback and a few unconfigured tunnel devices (sandbox-policy.md E1).
    # What matters is that the routing table is empty, so nothing outside the container is reachable.
    run_in "$role" -- cat /proc/net/route
    routes=$(printf '%s\n' "$OUT" | wc -l | tr -d ' ')
    [ "$RC" -eq 0 ] && [ "$routes" -le 1 ] || problems="$problems network-has-routes($routes-lines)"
    run_in "$role" -- id -u
    [ "$RC" -eq 0 ] && [ "$OUT" = "$want_uid" ] || problems="$problems id-u-says-$OUT"
    if [ -z "$problems" ]; then
      t_pass RUNTIME-PROFILE "$role: uid $want_uid, CapEff/CapPrm/CapBnd 0, NoNewPrivs 1, Seccomp 2, empty routing table"
    else
      t_fail RUNTIME-PROFILE "$role:$problems"
    fi
  done
  has_role agent || has_role verify || skip_rule RUNTIME-PROFILE "neither the agent nor the verify image is selected"
}

rule_readonly_root() {
  local role problems path
  for role in agent verify; do
    has_role "$role" || continue
    problems=""
    for path in /probe /usr/bin/probe /etc/probe /opt/rust/probe; do
      run_in "$role" -- touch "$path"
      [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q 'Read-only file system' || problems="$problems $path-was-writable"
    done
    for path in /tmp/probe /home/agent/probe; do
      run_in "$role" -- touch "$path"
      [ "$RC" -eq 0 ] || problems="$problems $path-not-writable($(first_lines "$OUT" 1))"
    done
    if [ "$role" = agent ]; then
      # The documented /tmp is noexec. A copied program must not start from there.
      run_in "$role" -- sh -c 'cp /usr/bin/true /tmp/t && /tmp/t'
      [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q -i 'permission denied' || problems="$problems tmp-allowed-execution"
    fi
    if [ -z "$problems" ]; then
      t_pass READONLY-ROOT "$role: writes to /, /usr, /etc and /opt fail; /tmp and /home/agent accept writes"
    else
      t_fail READONLY-ROOT "$role:$problems"
    fi
  done
  has_role agent || has_role verify || skip_rule READONLY-ROOT "neither the agent nor the verify image is selected"
}

rule_no_tools_run() {
  local role name problems
  for role in agent verify; do
    has_role "$role" || continue
    problems=""
    for name in git gh apt-get dpkg rustup curl wget ssh python3 perl; do
      run_in "$role" -- "$name" --version
      if [ "$RC" -eq 0 ]; then
        problems="$problems $name-started"
      elif ! printf '%s' "$OUT" | grep -q -i -E 'not found|no such file|executable file'; then
        problems="$problems $name-failed-for-another-reason($(first_lines "$OUT" 1))"
      fi
    done
    if [ -z "$problems" ]; then
      t_pass NO-TOOLS-RUN "$role: none of git, gh, apt-get, dpkg, rustup, curl, wget, ssh, python3, perl can be started"
    else
      t_fail NO-TOOLS-RUN "$role:$problems"
    fi
  done
  has_role agent || has_role verify || skip_rule NO-TOOLS-RUN "neither the agent nor the verify image is selected"
}

rule_toolchain() {
  local role channel problems out
  channel=$(sbx_toolchain_channel)
  for role in agent verify; do
    has_role "$role" || continue
    problems=""
    run_in "$role" -- rustc --version
    out=$OUT
    [ "$RC" -eq 0 ] && printf '%s' "$out" | grep -q "^rustc $channel " || problems="$problems rustc:'$(first_lines "$out" 1)'"
    run_in "$role" -- cargo --version
    [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q "^cargo $channel " || problems="$problems cargo:'$(first_lines "$OUT" 1)'"
    run_in "$role" -- cargo clippy --version
    [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q '^clippy ' || problems="$problems clippy:'$(first_lines "$OUT" 1)'"
    run_in "$role" -- rustfmt --version
    [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -q '^rustfmt ' || problems="$problems rustfmt:'$(first_lines "$OUT" 1)'"
    run_in "$role" -- cc --version
    [ "$RC" -eq 0 ] && printf '%s' "$OUT" | head -n 1 | grep -q -E '^(cc|gcc) \(' || problems="$problems cc:'$(first_lines "$OUT" 1)'"
    if [ -z "$problems" ]; then
      t_pass TOOLCHAIN "$role: $out; cargo, clippy, rustfmt and cc run"
    else
      t_fail TOOLCHAIN "$role:$problems"
    fi
  done
  has_role agent || has_role verify || skip_rule TOOLCHAIN "neither the agent nor the verify image is selected"
}

write_sample_crate() {
  local crate=$1
  mkdir -p "$crate/src"
  cat >"$crate/Cargo.toml" <<'EOF'
[package]
name = "smoke-tool"
version = "0.1.0"
edition = "2021"

[dependencies]
EOF
  cat >"$crate/src/lib.rs" <<'EOF'
//! A tiny library that the sandbox image smoke test builds.

/// Adds two numbers.
///
/// ```
/// assert_eq!(smoke_tool::add(2, 3), 5);
/// ```
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_two_numbers() {
        assert_eq!(add(2, 2), 4);
    }
}
EOF
  cat >"$crate/src/main.rs" <<'EOF'
fn main() {
    println!("smoke-tool {}", smoke_tool::add(20, 22));
}
EOF
}

rule_offline_build() {
  has_role verify || { skip_rule OFFLINE-BUILD "the verify image is not selected"; return; }
  local crate="$WORK/sample/crate" out="$WORK/sample/out" step
  mkdir -p "$crate" "$out"
  chmod 0777 "$WORK/sample" "$crate" "$out"
  SAMPLE_CLEANUP_REF=$(ref_of verify)
  write_sample_crate "$crate"
  chmod -R a+rwX "$crate"

  # The lock file is part of a real repository. Make it with a writable source tree, offline.
  run_in verify --mount "type=bind,src=$crate,dst=/workspace" -- cargo generate-lockfile --offline
  if [ "$RC" -ne 0 ]; then
    t_fail OFFLINE-BUILD "verify: cargo generate-lockfile --offline failed: $(first_lines "$OUT")"
    return
  fi

  # The verify profile: source read-only, one writable exec-capable output directory, no network.
  # TMPDIR points at the output directory because /tmp is noexec and rustdoc runs the programs it
  # builds from its temporary directory.
  mkdir -p "$out/tmp"
  chmod 0777 "$out/tmp"
  local -a mounts=(
    --mount "type=bind,src=$crate,dst=/workspace,readonly"
    --mount "type=bind,src=$out,dst=/out"
    --env CARGO_TARGET_DIR=/out/target
    --env CARGO_HOME=/home/agent/.cargo
    --env CARGO_NET_OFFLINE=true
    --env CARGO_INCREMENTAL=0
    --env CARGO_TERM_COLOR=never
    --env TMPDIR=/out/tmp
  )
  local failed=""
  for step in \
    "cargo build --locked --offline" \
    "cargo test --locked --offline" \
    "cargo fmt --check" \
    "cargo clippy --locked --offline --all-targets -- -D warnings" \
    "/out/target/debug/smoke-tool"; do
    # shellcheck disable=SC2086  # the step is a plain command line, split into words on purpose
    run_in verify "${mounts[@]}" -- $step
    if [ "$RC" -ne 0 ]; then
      failed="$failed [$step exit $RC: $(first_lines "$OUT" 4)]"
    elif [ "$step" = "/out/target/debug/smoke-tool" ] && [ "$OUT" != "smoke-tool 42" ]; then
      failed="$failed [the built program printed '$OUT']"
    fi
  done
  if [ -z "$failed" ]; then
    t_pass OFFLINE-BUILD "verify: build, test (unit and doc), fmt --check, clippy -D warnings and the built program, offline, source read-only, non-root"
  else
    t_fail OFFLINE-BUILD "verify:$failed"
  fi
}

rule_agent_tools_run() {
  has_role agent || { skip_rule AGENT-TOOLS-RUN "the agent image is not selected"; return; }
  local problems="" claude codex
  run_in agent -- claude --version
  claude=$OUT
  [ "$RC" -eq 0 ] && printf '%s' "$claude" | grep -q "^$CLAUDE_VERSION (Claude Code)" || problems="$problems claude:'$(first_lines "$claude" 2)'"
  run_in agent -- codex --version
  codex=$OUT
  [ "$RC" -eq 0 ] && printf '%s' "$codex" | grep -q "^codex-cli $CODEX_VERSION\$" || problems="$problems codex:'$(first_lines "$codex" 2)'"
  if [ -z "$problems" ]; then
    t_pass AGENT-TOOLS-RUN "agent: $claude; $codex (full hardened profile, --network none)"
  else
    t_fail AGENT-TOOLS-RUN "agent:$problems"
  fi
}

rule_sidecar_state() {
  has_role egress-sidecar || { skip_rule SIDECAR-STATE "the sidecar image is not selected"; return; }
  fs_audit egress-sidecar || { t_fail SIDECAR-STATE "egress-sidecar: could not read the image file system"; return; }
  local status ref recorded found
  status=$(status_of egress-sidecar)
  ref=$(ref_of egress-sidecar)
  recorded=$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" egress-sidecar binary_sha256 2>/dev/null || true)
  found=$(cat "$WORK/fs-egress-sidecar/sidecar-binary.txt")
  case $status in
    awaiting-binary)
      if [ -n "$found" ]; then
        t_fail SIDECAR-STATE "egress-sidecar: images.json says awaiting-binary but the image holds: $found"
        return
      fi
      run_in egress-sidecar --
      if [ "$RC" -ne 0 ] && printf '%s' "$OUT" | grep -q -i -E 'no such file|not found'; then
        t_pass SIDECAR-STATE "egress-sidecar: skeleton with no program; starting it fails closed (exit $RC)"
      else
        t_fail SIDECAR-STATE "egress-sidecar: a skeleton must fail to start; got exit $RC: $(first_lines "$OUT" 2)"
      fi
      ;;
    ready)
      if [ -n "$recorded" ] && [ "$found" = "/usr/local/bin/factory-egress-sidecar sha256 $recorded" ]; then
        t_pass SIDECAR-STATE "egress-sidecar: holds the program with the SHA-256 that images.json records"
      else
        t_fail SIDECAR-STATE "egress-sidecar: images.json says ready ($recorded) but the image holds: ${found:-nothing}"
      fi
      ;;
    *) t_fail SIDECAR-STATE "egress-sidecar: unknown status '$status' for $ref" ;;
  esac
}

rule_sidecar_contract() {
  has_role egress-sidecar && has_role verify || { skip_rule SIDECAR-CONTRACT "needs the verify image (to compile the probe) and the sidecar image"; return; }
  local dir="$WORK/probe" out="$WORK/probe/out" probe_sha tag="factory-sandbox-test/egress-sidecar:probe-$$"
  mkdir -p "$dir/src" "$out"
  chmod 0777 "$dir" "$out"
  cat >"$dir/src/probe.rs" <<'EOF'
// A test probe. It is NOT the egress sidecar. It prints the facts that the image must guarantee
// and tries one forbidden write, so test.sh can see how a program behaves in the sidecar image.
use std::fs;

fn main() {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if ["Uid:", "Gid:", "CapEff:", "NoNewPrivs:", "Seccomp:"].iter().any(|k| line.starts_with(k)) {
            println!("{}", line.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    match fs::write("/usr/local/bin/probe-write", b"x") {
        Ok(()) => println!("root-write: allowed"),
        Err(error) => println!("root-write: refused ({error})"),
    }
}
EOF
  run_in verify --mount "type=bind,src=$dir,dst=/workspace,readonly" --mount "type=bind,src=$out,dst=/out" -- \
    rustc --edition 2021 -C opt-level=1 /workspace/src/probe.rs -o /out/probe
  if [ "$RC" -ne 0 ]; then
    t_fail SIDECAR-CONTRACT "could not compile the probe in the verify image: $(first_lines "$OUT")"
    return
  fi
  probe_sha=$($SBX_PY -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$out/probe")
  TEST_IMAGES="$TEST_IMAGES $tag"
  local build_out
  build_out=$(FACTORY_IMAGES_JSON="$WORK/probe/images.json" SBX_IMAGE_PREFIX=factory-sandbox-test SBX_TAG="probe-$$" \
    SBX_EXTRA_LABEL="$SBX_TEST_LABEL" "$here/egress-sidecar/build.sh" --platform "$PLATFORM" --binary "$out/probe" --sha256 "$probe_sha" 2>&1)
  if [ $? -ne 0 ]; then
    t_fail SIDECAR-CONTRACT "the sidecar Dockerfile did not build with a program: $(first_lines "$(printf '%s' "$build_out" | tail -n 5)" 5)"
    return
  fi
  sbx_set_hardened "$SIDECAR_UID:$SIDECAR_GID"
  OUT=$(docker run --rm "${HARDENED[@]}" "$tag" 2>&1)
  RC=$?
  local problems=""
  printf '%s\n' "$OUT" | grep -q "^Uid: $SIDECAR_UID $SIDECAR_UID $SIDECAR_UID $SIDECAR_UID\$" || problems="$problems uid"
  printf '%s\n' "$OUT" | grep -q '^CapEff: 0000000000000000$' || problems="$problems CapEff"
  printf '%s\n' "$OUT" | grep -q '^NoNewPrivs: 1$' || problems="$problems NoNewPrivs"
  printf '%s\n' "$OUT" | grep -q '^Seccomp: 2$' || problems="$problems Seccomp"
  printf '%s\n' "$OUT" | grep -q '^root-write: refused' || problems="$problems read-only-root"
  if [ "$RC" -eq 0 ] && [ -z "$problems" ]; then
    t_pass SIDECAR-CONTRACT "a dynamically linked program in the sidecar image runs as $SIDECAR_UID, with no capabilities, on a read-only root"
  else
    t_fail SIDECAR-CONTRACT "probe run exit $RC, problems:${problems:- none}: $(first_lines "$OUT" 6)"
  fi
  docker image rm -f "$tag" >/dev/null 2>&1
}

rule_size() {
  local role bytes
  for role in $SELECTED; do
    bytes=$(sbx_json_get "$IMAGES_JSON" "$PLATFORM" "$role" size_bytes)
    t_info SIZE "$role: $((bytes / 1024 / 1024)) MiB ($bytes bytes) on disk, $PLATFORM"
  done
}

# --- run -----------------------------------------------------------------------------------------
echo "images: $IMAGES_JSON ($PLATFORM); selected: $SELECTED"
i=0
RAN=0
while [ "$i" -lt "${#RULE_IDS[@]}" ]; do
  if rule_selected "${RULE_IDS[$i]}" "${RULE_GROUPS[$i]}"; then
    RAN=$((RAN + 1))
    "${RULE_FUNCS[$i]}"
  fi
  i=$((i + 1))
done

echo
echo "rules run: $RAN, checks passed: $T_PASS, checks failed: $T_FAIL"
if [ "$RAN" -eq 0 ]; then
  sbx_usage_error "no rule matched the selection"
fi
if [ "$T_FAIL" -gt 0 ]; then
  echo "RESULT: FAILED"
  exit "$EXIT_FAILED"
fi
echo "RESULT: PASSED"
exit 0
