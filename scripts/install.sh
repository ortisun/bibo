#!/usr/bin/env bash
# scripts/install.sh - prepare an existing project to work with the factory, for Claude Code and for Codex (ADRs 0016, 0018, 0019).
#
# OBJECTIVE   Put the design tools and the issue workflow in place, so that a project can be mapped and then
#             receive tickets. It installs; it never starts a job and it never commits or pushes anything.
# DONE WHEN   Every line it prints is PRESENT or ADDED, it prints "READY", and it exits with code 0.
#
#   scripts/install.sh --check                         Show what would change. Change nothing: no file in the project,
#                                                      nothing on GitHub, no plugin. Safe to run any time.
#   scripts/install.sh                                 Install the EGM plugin if it is missing, for Claude Code, for
#                                                      Codex, or for both: every one of them that is installed.
#   --agent auto|claude|codex|both                     Which coding agent to prepare. The default, auto, takes each of
#                                                      claude and codex that is on the PATH and stops if there is none.
#                                                      claude or codex insists on that one. both insists on both.
#   scripts/install.sh --checkout PATH                 Also prepare the project at PATH: the GitHub MCP server entry
#                                                      (.mcp.json), the issue workflow files (.github/), and a check
#                                                      that the project has been mapped by EGM's bootstrap.
#   scripts/install.sh --checkout PATH --repo O/N      Also create the issue-workflow labels in the GitHub repository
#                                                      O/N with `gh`. This and --create-project are the steps that
#                                                      change GitHub.
#   --project OWNER/NUMBER                             Use this GitHub Projects board. Without it the installer uses
#                                                      the one board linked to the repository, if there is exactly one.
#   --board-field NAME                                 The single-select field that holds the stages (default Status).
#   --create-project OWNER                             Create a board for the repository when it has none. OWNER is an
#                                                      organization, a user, or @me. It adds a new field called Stage
#                                                      and links the board to the repository. This changes GitHub.
#   --no-board                                         Do not set up a board.
#   --update                                           Replace a project file that differs from the factory's copy.
#                                                      Without it a differing file is reported as DRIFT and kept.
#   --no-mcp                                           Skip the GitHub MCP server entry.
#   --help                                             Show this text.
#
# What each step does
#   tools          git and python3.
#   claude, codex  The coding agents. Claude Code must be 2.1.271 or later, for EGM's reviewer isolation. Codex must
#                  have the `plugin` command; the script checks the command, not a version number.
#   egm-plugin     The EGM plugin (egm@egm, from github.com/google/elephant-goldfish-model) in the user scope of each
#                  agent. Installed only when missing. Claude Code can enable a disabled plugin; Codex has no command
#                  for it, so a disabled plugin there is left to a person. Start a new session afterwards.
#   github-mcp     An entry for GitHub's MCP server: in the project's .mcp.json for Claude Code and in its
#                  .codex/config.toml for Codex. The entry holds the name of an environment variable,
#                  FACTORY_GITHUB_MCP_TOKEN, and never a token. This script does not read that variable, only whether
#                  it is set. The server is a tool for the person in the design session. The factory's engine never
#                  uses it and never honors a project's .mcp.json or .codex/config.toml. Codex reads its file only
#                  for a project that the person trusts.
#   workflow-files The issue forms, the Action that keeps labels consistent, and its two helper files, copied into
#                  the project's .github/. They are files in the working tree. A person commits them by pull request.
#   labels         The labels of policies/issue-workflow.yaml, created or corrected with `gh label create --force`.
#   project-board  A GitHub Projects board that mirrors the labels (ADR 0018). A board that already exists is ADAPTED
#                  TO: the stages are mapped onto its existing options and written to .github/project-board.json for
#                  a person to review. No option of an existing field is ever created, renamed or deleted. A mapping
#                  file that is already there is only checked against the board. The credential for the board is
#                  checked by name only.
#   project-map    Whether every directory that holds code has a README.md or EGM.md contract. EGM's bootstrap writes
#                  them, and it needs a person (it asks before it maps a large tree), so this script only checks.
#
# Output: one line per step, "  STATE  step  detail". STATE is PRESENT, ADDED, UPDATED, WOULD_ADD, DRIFT, NEEDS,
# NOTE, BLOCKED or SKIPPED. The end lists "Done for you" and "Needs you".
#
# Exit codes: 0 ready, 1 a step failed, 2 wrong arguments, 3 not finished: something is BLOCKED or NEEDS a person.
# (3 is the same code the other scripts use for BLOCKED. An unmapped project is not an error, but it is not ready.)
#
# This script works with the bash that ships with macOS (3.2) and with bash 4 and 5.

set -euo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SELF_DIR/.." && pwd -P)

# What this script was written against. A newer EGM is reported as DRIFT, not refused: EGM is a tool of the person
# in the design session and it is not part of the factory's trusted engine.
EGM_MARKETPLACE_SOURCE="google/elephant-goldfish-model"
EGM_MARKETPLACE_NAME="egm"
EGM_PLUGIN="egm@egm"
EGM_EXPECTED_VERSION="0.1.0"
CLAUDE_MIN_VERSION="2.1.271"
MCP_TOKEN_VAR="FACTORY_GITHUB_MCP_TOKEN"

# This script and the programs it starts never need the token. Tracing is switched off first, so that `bash -x` cannot
# print it; the test below expands to "x" and not to the value; and the variable is dropped, so that claude, codex, gh,
# git and python3 do not inherit it (a plugin install runs third-party code).
{ set +x; } 2>/dev/null
TOKEN_IS_SET=0
if [ -n "${!MCP_TOKEN_VAR:+x}" ]; then TOKEN_IS_SET=1; fi
unset "$MCP_TOKEN_VAR"

WORKFLOW_TOOL="$SELF_DIR/lib/issue_workflow.py"
CODEX_CONFIG_TOOL="$SELF_DIR/lib/codex_config.py"
BOARD_TOOL="$SELF_DIR/lib/project_board.py"
BOARD_POLICY="$ROOT/onboarding/github/project-board-policy.json"
BOARD_CONFIG_REL=".github/project-board.json"
MAP_TOOL="$SELF_DIR/lib/project_map.py"
RENDERED="$ROOT/onboarding/github/issue-workflow.json"

check_only=0
update=0
agent="auto"
want_mcp=1
want_board=1
checkout=""
repo=""
project=""
create_project=""
board_field="Status"

usage_error() {
  printf 'install.sh: %s (try --help)\n' "$1" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check) check_only=1 ;;
    --update) update=1 ;;
    --no-mcp) want_mcp=0 ;;
    --agent)
      [ $# -ge 2 ] || usage_error "--agent needs auto, claude, codex or both"
      agent=$2
      shift
      ;;
    --no-board) want_board=0 ;;
    --project)
      [ $# -ge 2 ] || usage_error "--project needs OWNER/NUMBER"
      project=$2
      shift
      ;;
    --create-project)
      [ $# -ge 2 ] || usage_error "--create-project needs an owner"
      create_project=$2
      shift
      ;;
    --board-field)
      [ $# -ge 2 ] || usage_error "--board-field needs a field name"
      board_field=$2
      shift
      ;;
    --checkout)
      [ $# -ge 2 ] || usage_error "--checkout needs a path"
      checkout=$2
      shift
      ;;
    --repo)
      [ $# -ge 2 ] || usage_error "--repo needs OWNER/NAME"
      repo=$2
      shift
      ;;
    -h | --help)
      sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done

case "$agent" in auto | claude | codex | both) ;; *) usage_error "--agent must be auto, claude, codex or both" ;; esac
if [ -n "$repo" ]; then
  case "$repo" in
    */*/* | */ | /* | . | .. | ./* | ../* | */. | */.. | *[!A-Za-z0-9_./-]*) usage_error "--repo must look like OWNER/NAME" ;;
  esac
  case "$repo" in */*) ;; *) usage_error "--repo must look like OWNER/NAME" ;; esac
  [ -n "$checkout" ] || usage_error "--repo goes with --checkout, so the labels and the files come from one install"
fi
if [ -n "$project" ] || [ -n "$create_project" ]; then
  [ -n "$repo" ] || usage_error "--project and --create-project go with --repo"
  [ -n "$project" ] && [ -n "$create_project" ] && usage_error "use --project or --create-project, not both"
  [ "$want_board" -eq 1 ] || usage_error "--no-board cannot be combined with --project or --create-project"
fi
if [ -n "$project" ]; then
  case "$project" in
    */*[!0-9]* | */ | /* | */*/* | *[!A-Za-z0-9/-]* | -*) usage_error "--project must look like OWNER/NUMBER" ;;
  esac
  case "$project" in [A-Za-z0-9]*/[0-9]*) ;; *) usage_error "--project must look like OWNER/NUMBER" ;; esac
fi
if [ -n "$create_project" ]; then
  case "$create_project" in
    @me) ;;
    *[!A-Za-z0-9-]* | -* | "") usage_error "--create-project needs a GitHub login or @me" ;;
  esac
fi
case "$board_field" in
  "" | *[!A-Za-z0-9\ _.-]*) usage_error "--board-field must be a plain field name" ;;
esac
if [ -n "$checkout" ]; then
  [ -d "$checkout" ] || usage_error "--checkout: '$checkout' is not a directory"
  checkout=$(cd "$checkout" && pwd -P)
fi

# ---------------------------------------------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------------------------------------------
# One scratch folder for the whole run, removed when the script ends however it ends.
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

DONE_LINES=""
NEED_LINES=""
NOTE_LINES=""
FAILED=0
PENDING=0

# Text that came from a checkout, a plugin or a board is data. Control characters (escape sequences, a bell, a carriage
# return) are removed before it reaches the terminal.
clean() { printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177'; }

report() { # STATE STEP DETAIL
  printf '  %-9s %-15s %s\n' "$1" "$2" "$(clean "$3")"
  if [ "$1" = WOULD_ADD ]; then PENDING=1; fi
}
done_for_you() { DONE_LINES="${DONE_LINES}  - $(clean "$1")"$'\n'; }
# Something only a person can do. The install is not ready until it is done.
needs_you() { NEED_LINES="${NEED_LINES}  - $(clean "$1")"$'\n'; }
# Something to know. It does not stop the install from being ready.
remember() { NOTE_LINES="${NOTE_LINES}  - $(clean "$1")"$'\n'; }

# Lines of untrusted text, indented under the line above them, with control characters removed.
indent_clean() {
  local line
  while IFS= read -r line; do printf '              %s\n' "$(clean "$line")"; done
}

lower() { printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]'; }

# ---- writing into a checkout we do not trust (PL-4, PL-15) ---------------------------------------------------------
# True when the path (relative to the checkout) is, or goes through, a symbolic link. A link that points nowhere counts.
# The installer will not write through one: the target could be a file of the person's that lives somewhere else.
path_has_link() {
  local rel=$1 current="$checkout" part
  local IFS=/
  for part in $rel; do
    [ -n "$part" ] || continue
    current="$current/$part"
    if [ -L "$current" ]; then return 0; fi
    [ -e "$current" ] || return 1
  done
  return 1
}

# Reports BLOCKED and returns 1 when the path may not be written. $1 is the step, $2 the relative path.
refuse_link() {
  if path_has_link "$2"; then
    report BLOCKED "$1" "$2 is, or goes through, a symbolic link; it was not written"
    needs_you "Replace the symbolic link at $2 with a real file or folder, or remove it, and run this script again. The installer does not write through a link, because its target may be a file of yours that lives somewhere else."
    return 0
  fi
  return 1
}

# Copy a file so that a failure cannot leave half a file, keeping the mode of a file that is replaced.
atomic_copy() { # SOURCE DESTINATION
  python3 -I -c '
import os, shutil, sys, tempfile
src, dst = sys.argv[1], sys.argv[2]
folder = os.path.dirname(dst)
os.makedirs(folder, exist_ok=True)
descriptor, temporary = tempfile.mkstemp(dir=folder, prefix=".install.")
try:
    with os.fdopen(descriptor, "wb") as out, open(src, "rb") as source:
        shutil.copyfileobj(source, out)
    if os.path.exists(dst):
        shutil.copymode(dst, temporary)
    else:
        os.chmod(temporary, 0o644)
    os.replace(temporary, dst)
finally:
    if os.path.exists(temporary):
        os.remove(temporary)' "$1" "$2"
}

# ---------------------------------------------------------------------------------------------------------------
# Step 1: tools and coding agents
# ---------------------------------------------------------------------------------------------------------------
HAVE_CLAUDE=0
HAVE_CODEX=0
FOUND_CLAUDE=0
FOUND_CODEX=0
HAVE_GH=0

version_at_least() { # have want
  python3 -I -c '
import sys
def parts(v):
    return tuple(int(p) for p in v.split(".")[:3])
sys.exit(0 if parts(sys.argv[1]) >= parts(sys.argv[2]) else 1)' "$1" "$2" 2>/dev/null
}

wants() { # claude | codex: does --agent ask for it?
  case "$agent" in
    both | auto | "$1") return 0 ;;
  esac
  return 1
}

# "Claude Code", "Codex" or "Claude Code or Codex": the agents this run prepares, for the sentences that name them.
agents_label() {
  if [ "$HAVE_CLAUDE" -eq 1 ] && [ "$HAVE_CODEX" -eq 1 ]; then
    printf 'Claude Code or Codex'
  elif [ "$HAVE_CODEX" -eq 1 ]; then
    printf 'Codex'
  else
    printf 'Claude Code'
  fi
}

step_agent_claude() {
  wants claude || return 0
  if ! command -v claude >/dev/null 2>&1; then
    if [ "$agent" = auto ]; then
      report SKIPPED claude "not installed"
    else
      report BLOCKED claude "Claude Code is not installed"
      needs_you "Install Claude Code (https://claude.com/claude-code) $CLAUDE_MIN_VERSION or later, then run this script again."
    fi
    return
  fi
  FOUND_CLAUDE=1
  local have
  have=$(claude --version 2>/dev/null | awk '{print $1; exit}')
  if [ -z "$have" ] || ! version_at_least "$have" "$CLAUDE_MIN_VERSION"; then
    report BLOCKED claude "Claude Code ${have:-of unknown version} is older than $CLAUDE_MIN_VERSION"
    needs_you "Update Claude Code to $CLAUDE_MIN_VERSION or later. Older versions do not isolate EGM's reviewers."
    return
  fi
  HAVE_CLAUDE=1
  report PRESENT claude "Claude Code $have"
}

step_agent_codex() {
  wants codex || return 0
  if ! command -v codex >/dev/null 2>&1; then
    if [ "$agent" = auto ]; then
      report SKIPPED codex "not installed"
    else
      report BLOCKED codex "Codex is not installed"
      needs_you "Install Codex (https://developers.openai.com/codex) and run this script again."
    fi
    return
  fi
  FOUND_CODEX=1
  # Codex is probed for the command this script uses, not for a version number (ADR 0005 does the same for the engine).
  if ! codex plugin add --help >/dev/null 2>&1; then
    report BLOCKED codex "this Codex has no 'plugin add' command"
    needs_you "Update Codex to a version that has 'codex plugin add'."
    return
  fi
  HAVE_CODEX=1
  report PRESENT codex "Codex $(codex --version 2>/dev/null | awk '{print $NF; exit}')"
}

step_tools() {
  local missing=""
  for tool in git python3; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
  done
  if [ -n "$missing" ]; then
    report BLOCKED tools "not installed:$missing"
    needs_you "Install$missing and run this script again."
    return
  fi
  report PRESENT tools "git, python3"
  if command -v gh >/dev/null 2>&1; then HAVE_GH=1; fi
  step_agent_claude
  step_agent_codex
  if [ "$agent" = auto ] && [ "$FOUND_CLAUDE" -eq 0 ] && [ "$FOUND_CODEX" -eq 0 ]; then
    report BLOCKED agents "no coding agent is installed: neither claude nor codex is on the PATH"
    needs_you "Install Claude Code (https://claude.com/claude-code) or Codex (https://developers.openai.com/codex), then run this script again."
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Step 2: the EGM plugin
# ---------------------------------------------------------------------------------------------------------------
plugin_status() { # prints "enabled VERSION", "disabled VERSION" or "absent -"
  claude plugin list --json 2>/dev/null | python3 -I -c '
import json, sys
try:
    plugins = json.load(sys.stdin)
except ValueError:
    plugins = []
for plugin in plugins:
    if plugin.get("id") == sys.argv[1]:
        print("enabled" if plugin.get("enabled") else "disabled", plugin.get("version", "?"))
        break
else:
    print("absent -")' "$EGM_PLUGIN"
}

marketplace_present() {
  claude plugin marketplace list --json 2>/dev/null | python3 -I -c '
import json, sys
try:
    items = json.load(sys.stdin)
except ValueError:
    items = []
sys.exit(0 if any(i.get("name") == sys.argv[1] for i in items) else 1)' "$EGM_MARKETPLACE_NAME"
}

step_egm_claude() {
  if [ "$HAVE_CLAUDE" -ne 1 ]; then
    if [ "$FOUND_CLAUDE" -eq 1 ] || [ "$agent" = claude ] || [ "$agent" = both ]; then
      report SKIPPED egm-plugin "claude: needs Claude Code"
    fi
    return
  fi
  local state version
  read -r state version <<EOF
$(plugin_status)
EOF
  case "$state" in
    enabled)
      if [ "$version" = "$EGM_EXPECTED_VERSION" ]; then
        report PRESENT egm-plugin "claude: $EGM_PLUGIN $version"
      else
        report DRIFT egm-plugin "claude: $EGM_PLUGIN $version is installed; this script was written against $EGM_EXPECTED_VERSION"
        remember "Read the EGM release notes for $version before you rely on it in Claude Code. Nothing was changed."
      fi
      ;;
    disabled)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD egm-plugin "claude: $EGM_PLUGIN $version is installed but disabled; it would be enabled"
        return
      fi
      if claude plugin enable "$EGM_PLUGIN" >/dev/null 2>&1; then
        report UPDATED egm-plugin "claude: $EGM_PLUGIN $version enabled"
        done_for_you "Enabled the EGM plugin in Claude Code."
        remember "Start a new Claude Code session so the /egm skills load."
      else
        report BLOCKED egm-plugin "claude: 'claude plugin enable $EGM_PLUGIN' failed"
        FAILED=1
      fi
      ;;
    *)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD egm-plugin "claude: $EGM_PLUGIN would be installed from $EGM_MARKETPLACE_SOURCE"
        return
      fi
      if ! marketplace_present; then
        if ! claude plugin marketplace add "$EGM_MARKETPLACE_SOURCE" >/dev/null 2>&1; then
          report BLOCKED egm-plugin "claude: could not add the marketplace $EGM_MARKETPLACE_SOURCE (is the network reachable?)"
          FAILED=1
          return
        fi
      fi
      if ! claude plugin install "$EGM_PLUGIN" >/dev/null 2>&1; then
        report BLOCKED egm-plugin "claude: 'claude plugin install $EGM_PLUGIN' failed"
        FAILED=1
        return
      fi
      read -r state version <<EOF
$(plugin_status)
EOF
      if [ "$state" = enabled ] && [ "$version" = "$EGM_EXPECTED_VERSION" ]; then
        report ADDED egm-plugin "claude: $EGM_PLUGIN $version"
        done_for_you "Installed the EGM plugin in Claude Code ($EGM_PLUGIN $version)."
        remember "Start a new Claude Code session so the /egm skills load."
      elif [ "$state" = enabled ]; then
        report DRIFT egm-plugin "claude: installed $EGM_PLUGIN $version, but this script was written against $EGM_EXPECTED_VERSION"
        done_for_you "Installed the EGM plugin in Claude Code ($EGM_PLUGIN $version)."
        remember "The marketplace gave EGM $version and not $EGM_EXPECTED_VERSION. Read its release notes before you rely on it in Claude Code, and start a new session."
      else
        report BLOCKED egm-plugin "claude: the plugin was installed but is not enabled"
        FAILED=1
      fi
      ;;
  esac
}

# Codex lists installed plugins as {"installed": [{"pluginId": "egm@egm", "enabled": true, "version": "0.1.0"}, ...]}.
codex_plugin_status() { # prints "enabled VERSION", "disabled VERSION" or "absent -"
  codex plugin list --json 2>/dev/null | python3 -I -c '
import json, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    data = {}
installed = data.get("installed") if isinstance(data, dict) else None
for plugin in installed or []:
    if plugin.get("pluginId") == sys.argv[1]:
        print("enabled" if plugin.get("enabled") else "disabled", plugin.get("version", "?"))
        break
else:
    print("absent -")' "$EGM_PLUGIN"
}

codex_marketplace_present() {
  codex plugin marketplace list --json 2>/dev/null | python3 -I -c '
import json, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    data = {}
items = data.get("marketplaces") if isinstance(data, dict) else None
sys.exit(0 if any(i.get("name") == sys.argv[1] for i in items or []) else 1)' "$EGM_MARKETPLACE_NAME"
}

step_egm_codex() {
  if [ "$HAVE_CODEX" -ne 1 ]; then
    if [ "$FOUND_CODEX" -eq 1 ] || [ "$agent" = codex ] || [ "$agent" = both ]; then
      report SKIPPED egm-plugin "codex: needs Codex"
    fi
    return
  fi
  local state version
  read -r state version <<EOF
$(codex_plugin_status)
EOF
  case "$state" in
    enabled)
      if [ "$version" = "$EGM_EXPECTED_VERSION" ]; then
        report PRESENT egm-plugin "codex: $EGM_PLUGIN $version"
      else
        report DRIFT egm-plugin "codex: $EGM_PLUGIN $version is installed; this script was written against $EGM_EXPECTED_VERSION"
        remember "Read the EGM release notes for $version before you rely on it in Codex. Nothing was changed."
      fi
      ;;
    disabled)
      # Codex has plugin add, list, remove and marketplace, and no enable. A person turns it on.
      report NEEDS egm-plugin "codex: $EGM_PLUGIN $version is installed but disabled"
      needs_you "Turn the EGM plugin on in Codex's plugin settings. The Codex command line has no command that enables a plugin."
      ;;
    *)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD egm-plugin "codex: $EGM_PLUGIN would be installed from $EGM_MARKETPLACE_SOURCE"
        return
      fi
      if ! codex_marketplace_present; then
        if ! codex plugin marketplace add "$EGM_MARKETPLACE_SOURCE" >/dev/null 2>&1; then
          report BLOCKED egm-plugin "codex: could not add the marketplace $EGM_MARKETPLACE_SOURCE (is the network reachable?)"
          FAILED=1
          return
        fi
      fi
      if ! codex plugin add "$EGM_PLUGIN" >/dev/null 2>&1; then
        report BLOCKED egm-plugin "codex: 'codex plugin add $EGM_PLUGIN' failed"
        FAILED=1
        return
      fi
      read -r state version <<EOF
$(codex_plugin_status)
EOF
      if [ "$state" = enabled ] && [ "$version" = "$EGM_EXPECTED_VERSION" ]; then
        report ADDED egm-plugin "codex: $EGM_PLUGIN $version"
        done_for_you "Installed the EGM plugin in Codex ($EGM_PLUGIN $version)."
        remember "Start a new Codex session so the EGM skills load."
      elif [ "$state" = enabled ]; then
        report DRIFT egm-plugin "codex: installed $EGM_PLUGIN $version, but this script was written against $EGM_EXPECTED_VERSION"
        done_for_you "Installed the EGM plugin in Codex ($EGM_PLUGIN $version)."
        remember "The marketplace gave EGM $version and not $EGM_EXPECTED_VERSION. Read its release notes before you rely on it in Codex, and start a new session."
      else
        report BLOCKED egm-plugin "codex: the plugin was installed but is not enabled"
        FAILED=1
      fi
      ;;
  esac
}

step_egm() {
  step_egm_claude
  step_egm_codex
}

# ---------------------------------------------------------------------------------------------------------------
# Step 3: GitHub's MCP server entry in the project's .mcp.json
# ---------------------------------------------------------------------------------------------------------------
# prints one of: absent | same | different | redirected | credential | invalid, and with "write" as the second argument
# it merges the entry in. The token is never read: the entry names a variable.
#   credential  an authorization-like header with no ${...} in it, or a value anywhere in the entry shaped like a GitHub token
#   redirected  the entry names the token variable but its address is not GitHub's, so the token would go elsewhere
#   invalid     the file is not strict JSON (a comment, for example); nothing is changed
# The write keeps the order and the characters of the rest of the file, keeps its mode, and replaces it in one step.
# The single quotes hold Python. The "${" inside is literal text for .mcp.json, which Claude Code expands later,
# so the shell must not expand it (SC2016 is expected here).
# shellcheck disable=SC2016
mcp_entry() { # PATH MODE(inspect|write)
  python3 -I -c '
import json, os, re, shutil, sys, tempfile
path, mode, var = sys.argv[1], sys.argv[2], sys.argv[3]
entry = {
    "type": "http",
    "url": "https://api.githubcopilot.com/mcp/",
    "headers": {
        "Authorization": "Bearer ${%s}" % var,
        "X-MCP-Toolsets": "repos,issues,pull_requests,labels",
        "X-MCP-Lockdown": "true",
    },
}
token_shape = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")
try:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
except FileNotFoundError:
    document = {}
except (ValueError, OSError):
    document = None
servers = document.get("mcpServers", {}) if isinstance(document, dict) else None
if not isinstance(servers, dict):
    print("invalid")
    sys.exit(0 if mode == "inspect" else 3)
current = servers.get("github")
if mode == "inspect":
    if current is None:
        print("absent")
    elif current == entry:
        print("same")
    else:
        text = json.dumps(current)
        headers = current.get("headers") if isinstance(current, dict) else None
        # Only a header that carries a secret by its name counts. X-MCP-Toolsets is not a credential.
        secret_name = re.compile(r"auth|token|key|secret|password|cookie", re.IGNORECASE)
        literal = isinstance(headers, dict) and any(secret_name.search(str(k)) and "${" not in str(v) for k, v in headers.items())
        if token_shape.search(text) or literal:
            print("credential")
        elif var in text and (not isinstance(current, dict) or current.get("url") != entry["url"]):
            print("redirected")
        else:
            print("different")
    sys.exit(0)
if os.path.islink(path) or os.path.islink(os.path.dirname(os.path.abspath(path))):
    sys.exit(4)
document = document if isinstance(document, dict) else {}
document.setdefault("mcpServers", {})["github"] = entry
folder = os.path.dirname(os.path.abspath(path))
descriptor, temporary = tempfile.mkstemp(dir=folder, prefix=".mcp.json.")
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    if os.path.exists(path):
        shutil.copymode(path, temporary)
    else:
        os.chmod(temporary, 0o644)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.remove(temporary)' "$1" "$2" "$MCP_TOKEN_VAR"
}

write_claude_entry() { # the state it replaces, for the words of the report
  if mcp_entry "$checkout/.mcp.json" write; then return 0; fi
  report BLOCKED github-mcp "claude: .mcp.json could not be written"
  FAILED=1
  return 1
}

step_mcp_claude() {
  local file="$checkout/.mcp.json" state
  if refuse_link github-mcp ".mcp.json"; then return; fi
  state=$(mcp_entry "$file" inspect) || state=invalid
  case "$state" in
    same) report PRESENT github-mcp "claude: .mcp.json names \${$MCP_TOKEN_VAR}" ;;
    invalid)
      report BLOCKED github-mcp "claude: .mcp.json is not plain JSON (a comment, perhaps); it was not changed"
      needs_you "Make .mcp.json plain JSON by hand, then run this script again."
      ;;
    credential)
      report DRIFT github-mcp "claude: the github entry in .mcp.json holds what may be a token (value not shown)"
      needs_you "Remove the token from .mcp.json and rotate it. A token in a committed file is public to everyone with access. Then run this script with --update."
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ] && write_claude_entry; then
        report UPDATED github-mcp "claude: replaced by an entry that names \${$MCP_TOKEN_VAR}"
      fi
      ;;
    redirected)
      report DRIFT github-mcp "claude: the github entry in .mcp.json names \${$MCP_TOKEN_VAR} but its address is not GitHub's; kept"
      needs_you "Read the github entry in .mcp.json. It would send your token to an address that is not GitHub's. If you did not write it, remove it. Then run this script with --update."
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ] && write_claude_entry; then
        report UPDATED github-mcp "claude: replaced by the factory's entry"
      fi
      ;;
    different)
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ]; then
        if write_claude_entry; then
          report UPDATED github-mcp "claude: the github entry in .mcp.json was replaced"
          done_for_you "Updated the github entry in .mcp.json."
        fi
      else
        report DRIFT github-mcp "claude: the github entry in .mcp.json differs from the factory's; kept (use --update to replace)"
        needs_you "Compare the github entry in .mcp.json with the factory's, then run with --update if you want it replaced. Until you do, the install is not ready."
      fi
      ;;
    *)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD github-mcp "claude: a github entry would be added to .mcp.json"
      elif write_claude_entry; then
        report ADDED github-mcp "claude: added a github entry to .mcp.json"
        done_for_you "Added GitHub's MCP server to .mcp.json."
      fi
      ;;
  esac
}

# The same entry for Codex, in .codex/config.toml. scripts/lib/codex_config.py edits the one table and refuses forms
# it does not understand. Codex loads the file only for a project that the person trusts.
write_codex_entry() { # [--replace]
  if python3 -I "$CODEX_CONFIG_TOOL" write "$checkout/.codex/config.toml" "$MCP_TOKEN_VAR" "$@"; then return 0; fi
  report BLOCKED github-mcp "codex: .codex/config.toml could not be written safely"
  FAILED=1
  return 1
}

step_mcp_codex() {
  local file="$checkout/.codex/config.toml" state
  if refuse_link github-mcp ".codex/config.toml"; then return; fi
  state=$(python3 -I "$CODEX_CONFIG_TOOL" inspect "$file" "$MCP_TOKEN_VAR")
  case "$state" in
    same) report PRESENT github-mcp "codex: .codex/config.toml names \${$MCP_TOKEN_VAR}" ;;
    credential)
      report DRIFT github-mcp "codex: the github entry in .codex/config.toml holds what may be a token (value not shown)"
      needs_you "Remove the token from .codex/config.toml and rotate it. A token in a committed file is public to everyone with access. Then run this script with --update."
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ] && write_codex_entry --replace; then
        report UPDATED github-mcp "codex: replaced by an entry that names \${$MCP_TOKEN_VAR}"
      fi
      ;;
    redirected)
      report DRIFT github-mcp "codex: the github entry in .codex/config.toml names \${$MCP_TOKEN_VAR} but its address is not GitHub's; kept"
      needs_you "Read the github entry in .codex/config.toml. It would send your token to an address that is not GitHub's. If you did not write it, remove it. Then run this script with --update."
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ] && write_codex_entry --replace; then
        report UPDATED github-mcp "codex: replaced by the factory's entry"
      fi
      ;;
    unsafe)
      report DRIFT github-mcp "codex: .codex/config.toml has a github entry that this script will not edit (it runs a command, or is written in a form it does not understand)"
      needs_you "Edit the github entry in .codex/config.toml by hand so that it is the table [mcp_servers.github] with url, bearer_token_env_var and http_headers only. If it holds a token, rotate it. See docs/guides/claude-and-codex.md."
      ;;
    different)
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ]; then
        if write_codex_entry --replace; then
          report UPDATED github-mcp "codex: the github entry in .codex/config.toml was replaced"
          done_for_you "Updated the github entry in .codex/config.toml."
        fi
      else
        report DRIFT github-mcp "codex: the github entry in .codex/config.toml differs from the factory's; kept (use --update to replace)"
        needs_you "Compare the github entry in .codex/config.toml with the factory's, then run with --update if you want it replaced. Until you do, the install is not ready."
      fi
      ;;
    *)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD github-mcp "codex: a github entry would be added to .codex/config.toml"
      elif write_codex_entry; then
        report ADDED github-mcp "codex: added a github entry to .codex/config.toml"
        done_for_you "Added GitHub's MCP server to .codex/config.toml."
      fi
      ;;
  esac
  remember "Codex reads .codex/config.toml only for a project that you trust. When Codex asks, trust this project, or the GitHub server will not appear."
}

step_mcp() {
  if [ -z "$checkout" ] || [ "$want_mcp" -eq 0 ]; then
    return
  fi
  if [ "$HAVE_CLAUDE" -eq 0 ] && [ "$HAVE_CODEX" -eq 0 ]; then
    report SKIPPED github-mcp "needs a coding agent"
    return
  fi
  if [ "$HAVE_CLAUDE" -eq 1 ]; then step_mcp_claude; fi
  if [ "$HAVE_CODEX" -eq 1 ]; then step_mcp_codex; fi
  if [ "$TOKEN_IS_SET" -eq 0 ]; then
    report NEEDS github-token "$MCP_TOKEN_VAR is not set (it was not read, only checked)"
    needs_you "Create a fine-grained GitHub token for this one repository (Issues and Pull requests: read and write; Contents and Metadata: read) and export it as $MCP_TOKEN_VAR before you start $(agents_label). Never paste it in a chat or a file."
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Step 4: the issue workflow files
# ---------------------------------------------------------------------------------------------------------------
copy_one() { # SOURCE DESTINATION(relative to the checkout)
  local src=$1 rel=$2 dst
  dst="$checkout/$rel"
  if path_has_link "$rel"; then
    report BLOCKED workflow-files "$rel is, or goes through, a symbolic link; it was not written"
    LINKED=$((LINKED + 1))
  elif [ ! -e "$dst" ]; then
    if [ "$check_only" -eq 1 ]; then
      WOULD=$((WOULD + 1))
    else
      atomic_copy "$src" "$dst"
      ADDED=$((ADDED + 1))
    fi
  elif cmp -s "$src" "$dst"; then
    SAME=$((SAME + 1))
  elif [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ]; then
    atomic_copy "$src" "$dst"
    UPDATED=$((UPDATED + 1))
  else
    report DRIFT workflow-files "$rel differs from the factory's copy; kept (use --update to replace)"
    DRIFTED=$((DRIFTED + 1))
  fi
}

step_files() {
  [ -n "$checkout" ] || return 0
  # A link at .github would send every file somewhere else. Say it once and stop.
  if refuse_link workflow-files ".github"; then return 0; fi
  ADDED=0 SAME=0 UPDATED=0 WOULD=0 DRIFTED=0 LINKED=0
  copy_one "$RENDERED" ".github/issue-workflow.json"
  copy_one "$WORKFLOW_TOOL" ".github/scripts/issue_workflow.py"
  copy_one "$BOARD_TOOL" ".github/scripts/project_board.py"
  copy_one "$BOARD_POLICY" ".github/project-board-policy.json"
  copy_one "$ROOT/onboarding/github/workflows/issue-workflow.yml" ".github/workflows/issue-workflow.yml"
  local template
  for template in "$ROOT"/onboarding/github/ISSUE_TEMPLATE/*.yml; do
    copy_one "$template" ".github/ISSUE_TEMPLATE/$(basename "$template")"
  done
  local detail="$ADDED added, $UPDATED updated, $SAME already the same"
  if [ "$check_only" -eq 1 ] && [ "$WOULD" -gt 0 ]; then
    report WOULD_ADD workflow-files "$WOULD file(s) would be copied into .github/"
  elif [ "$ADDED" -gt 0 ]; then
    report ADDED workflow-files "$detail"
    done_for_you "Copied the issue workflow files into .github/ ($ADDED added)."
  elif [ "$UPDATED" -gt 0 ]; then
    report UPDATED workflow-files "$detail"
    done_for_you "Updated the issue workflow files in .github/ ($UPDATED updated)."
  elif [ "$DRIFTED" -eq 0 ] && [ "$LINKED" -eq 0 ]; then
    report PRESENT workflow-files "$detail"
  fi
  if [ "$DRIFTED" -gt 0 ]; then
    needs_you "Compare the DRIFT files above with the factory's copies, then run with --update if you want them replaced."
  fi
  if [ "$LINKED" -gt 0 ]; then
    needs_you "Replace the symbolic links named above with real files or folders, or remove them, and run this script again. The installer does not write through a link."
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Step 5: the labels in the GitHub repository
# ---------------------------------------------------------------------------------------------------------------
# Prints "name<TAB>color<TAB>description" for every label that is missing or different on GitHub.
labels_to_fix() { # reads `gh label list --json` on stdin
  python3 -I -c '
import json, subprocess, sys
wanted = [line.split("\t") for line in subprocess.run(
    [sys.executable, "-I", sys.argv[1], "labels", "--config", sys.argv[2]], capture_output=True, text=True, check=True
).stdout.splitlines()]
have = {l["name"].lower(): l for l in json.load(sys.stdin)}
for name, color, description in wanted:
    current = have.get(name.lower())
    if current is None or current.get("color", "").lower() != color or (current.get("description") or "") != description:
        print("\t".join((name, color, description)))' "$WORKFLOW_TOOL" "$RENDERED"
}

step_labels() {
  [ -n "$repo" ] || return 0
  if [ "$HAVE_GH" -ne 1 ]; then
    report BLOCKED labels "the GitHub command line (gh) is not installed"
    needs_you "Install gh (https://cli.github.com) and run 'gh auth login', then run this script again with --repo $repo."
    return
  fi
  local listing todo
  if ! listing=$(gh label list --repo "$repo" --limit 200 --json name,color,description 2>/dev/null); then
    report BLOCKED labels "could not list the labels of $repo (not signed in to gh, or no access)"
    needs_you "Run 'gh auth status'. The account needs permission to manage labels on $repo."
    return
  fi
  todo=$(printf '%s' "$listing" | labels_to_fix)
  if [ -z "$todo" ]; then
    report PRESENT labels "all workflow labels exist on $repo"
    return
  fi
  local count
  count=$(printf '%s\n' "$todo" | wc -l | tr -d ' ')
  if [ "$check_only" -eq 1 ]; then
    report WOULD_ADD labels "$count label(s) would be created or corrected on $repo"
    return
  fi
  local name color description
  while IFS=$'\t' read -r name color description; do
    if ! gh label create "$name" --color "$color" --description "$description" --repo "$repo" --force >/dev/null 2>&1; then
      report BLOCKED labels "could not create the label '$name' on $repo"
      FAILED=1
      return
    fi
  done <<EOF
$todo
EOF
  report ADDED labels "$count label(s) created or corrected on $repo"
  done_for_you "Created or corrected $count label(s) on $repo."
}

# ---------------------------------------------------------------------------------------------------------------
# Step 5b: the GitHub Projects board
# ---------------------------------------------------------------------------------------------------------------
# The single quotes below hold GraphQL. The "$o" and "$n" are GraphQL variables, not shell variables (SC2016).
# shellcheck disable=SC2016
owner_type_of() { # LOGIN -> organization | user | (nothing)
  local reply
  reply=$(gh api graphql -f query='query($o:String!){repositoryOwner(login:$o){__typename}}' -f o="$1" 2>/dev/null) || return 1
  printf '%s' "$reply" | python3 -I -c '
import json, sys
kind = ((json.load(sys.stdin).get("data") or {}).get("repositoryOwner") or {}).get("__typename", "")
print({"Organization": "organization", "User": "user"}.get(kind, ""))'
}

# shellcheck disable=SC2016
linked_projects() { # OWNER NAME -> "login<TAB>number<TAB>title" for each open board linked to the repository
  local reply
  reply=$(gh api graphql -f query='query($o:String!,$n:String!){repository(owner:$o,name:$n){projectsV2(first:20){nodes{number title closed owner{__typename ... on Organization{login} ... on User{login}}}}}}' -f o="$1" -f n="$2" 2>/dev/null) || return 1
  printf '%s' "$reply" | python3 -I -c '
import json, sys
nodes = ((((json.load(sys.stdin).get("data") or {}).get("repository") or {}).get("projectsV2") or {}).get("nodes")) or []
for node in nodes:
    if node and not node.get("closed"):
        print("%s\t%s\t%s" % ((node.get("owner") or {}).get("login", ""), node.get("number", ""), str(node.get("title", "")).replace("\t", " ")))'
}

board_config_field() { # FILE KEY -> a value of project-board.json
  python3 -I -c '
import json, sys
board = json.load(open(sys.argv[1], encoding="utf-8"))
print({"owner": board["project"]["owner"], "number": board["project"]["number"], "field": board["status_field"]}[sys.argv[2]])' "$1" "$2"
}

# Says whether the repository has a credential for the board, by NAME only. Values are never read.
# The Action reverts a `factory:` label unless the App named in FACTORY_BOT_LOGIN set it (PL-21). Without the variable it
# would revert the factory's own status labels, and say so in a comment each time. Names only; a value is never read.
step_bot_variable() {
  [ -n "$repo" ] && [ "$HAVE_GH" -eq 1 ] || return 0
  local listing
  listing=$(gh variable list --repo "$repo" --json name 2>/dev/null) || return 0
  if ! printf '%s' "$listing" | python3 -I -c '
import json, sys
try:
    names = {item.get("name") for item in json.load(sys.stdin)}
except ValueError:
    names = set()
sys.exit(0 if "FACTORY_BOT_LOGIN" in names else 1)'; then
    remember "The repository variable FACTORY_BOT_LOGIN is not set on $repo. Set it to the login of the factory's GitHub App (for example my-factory[bot]) before the factory runs there, or the Action will remove the factory's own status labels."
  fi
}

step_board_credential() {
  local secrets variables
  if ! secrets=$(gh secret list --repo "$repo" --json name 2>/dev/null) || ! variables=$(gh variable list --repo "$repo" --json name 2>/dev/null); then
    remember "Could not list the secrets of $repo, so the board credential was not checked. The Action warns in its log if it is missing."
    return
  fi
  if printf '%s\n%s' "$secrets" "$variables" | python3 -I -c '
import json, sys
secrets, variables = [json.loads(part) for part in sys.stdin.read().split("\n", 1)]
secret = {item["name"] for item in secrets}
variable = {item["name"] for item in variables}
sys.exit(0 if "FACTORY_BOARD_TOKEN" in secret or ("FACTORY_BOARD_APP_PRIVATE_KEY" in secret and "FACTORY_BOARD_CLIENT_ID" in variable) else 1)'; then
    report PRESENT board-credential "a credential for the board is set on $repo (checked by name)"
  else
    report NOTE board-credential "no credential for the board is set on $repo"
    remember "The board will not move until it has a credential. For an organization board, create a GitHub App with Projects (organization) read and write and Issues read, install it, then set the variable FACTORY_BOARD_CLIENT_ID and the secret FACTORY_BOARD_APP_PRIVATE_KEY. For a personal board, set the secret FACTORY_BOARD_TOKEN to a personal access token with the project scope. Use 'gh secret set' so the value never goes through a chat or a file. An organization-level secret is not listed here."
  fi
}

step_board() {
  [ -n "$repo" ] || return 0
  if [ "$want_board" -eq 0 ]; then
    report SKIPPED project-board "--no-board"
    return
  fi
  if [ "$HAVE_GH" -ne 1 ]; then
    report SKIPPED project-board "needs the GitHub command line (gh)"
    return
  fi
  local config="$checkout/$BOARD_CONFIG_REL" tmp="$WORK_DIR" owner number
  if refuse_link project-board "$BOARD_CONFIG_REL"; then return; fi

  # 1. A mapping file is already there: a person may have edited it. Check it against the board. Never rewrite it.
  # Its values go to `gh` and to the terminal, so they are validated first; a file from a hostile checkout is data.
  if [ -f "$config" ]; then
    local shape
    if ! shape=$(python3 -I "$BOARD_TOOL" validate --policy-json "$BOARD_POLICY" --board-config "$config" 2>&1); then
      report NEEDS project-board "$BOARD_CONFIG_REL is not valid"
      printf '%s\n' "$shape" | head -n 6 | indent_clean
      needs_you "Fix $BOARD_CONFIG_REL, or delete it and run this script again to make a new one."
      return
    fi
    owner=$(board_config_field "$config" owner)
    number=$(board_config_field "$config" number)
    note_board_owner "$owner"
    local field
    field=$(board_config_field "$config" field)
    if ! gh project field-list "$number" --owner "$owner" --format json --limit 50 >"$tmp/fields.json" 2>/dev/null; then
      report BLOCKED project-board "could not read the fields of the board $owner/$number"
      needs_you "Run 'gh auth refresh -s project' and check that $owner/$number exists. Then run this script again."
      return
    fi
    local problems
    if problems=$(python3 -I "$BOARD_TOOL" validate --policy-json "$BOARD_POLICY" --board-config "$config" --fields "$tmp/fields.json"); then
      report PRESENT project-board "$BOARD_CONFIG_REL matches the board $owner/$number, field '$field'"
    else
      report NEEDS project-board "$BOARD_CONFIG_REL no longer matches the board $owner/$number"
      printf '%s\n' "$problems" | indent_clean
      needs_you "The board changed, or the mapping file is wrong. Edit $BOARD_CONFIG_REL so that each stage names an option that exists, or delete it to map again."
    fi
    step_board_credential
    return
  fi

  # 2. Find the board: given, linked to the repository, or to be created.
  local created=0 field_name="$board_field"
  if [ -n "$project" ]; then
    owner=${project%/*}
    number=${project#*/}
  elif [ -n "$create_project" ]; then
    if [ "$check_only" -eq 1 ]; then
      report WOULD_ADD project-board "a board would be created for $create_project, linked to $repo, with a new field called Stage"
      return
    fi
    owner=$create_project
    created=1
  else
    local linked count
    if ! linked=$(linked_projects "${repo%/*}" "${repo#*/}"); then
      report BLOCKED project-board "could not list the boards linked to $repo"
      needs_you "Run 'gh auth refresh -s project', then run this script again. Or pass --project OWNER/NUMBER, or --no-board."
      return
    fi
    count=$(printf '%s' "$linked" | grep -c . || true)
    if [ "$count" -eq 0 ]; then
      report NEEDS project-board "no board is linked to $repo"
      needs_you "Decide about the board: pass --project OWNER/NUMBER to use one you have, --create-project OWNER to make one, or --no-board to go without."
      return
    fi
    if [ "$count" -gt 1 ]; then
      report NEEDS project-board "$count boards are linked to $repo, and the installer will not guess"
      printf '%s\n' "$linked" | awk -F'\t' '{printf "%s/%s  %s\n", $1, $2, $3}' | indent_clean
      needs_you "Pick one with --project OWNER/NUMBER."
      return
    fi
    owner=$(printf '%s' "$linked" | cut -f1)
    number=$(printf '%s' "$linked" | cut -f2)
  fi

  # 3. Create the board when asked. Only additive things: a project, a link and a NEW field.
  if [ "$created" -eq 1 ]; then
    if [ "$owner" = "@me" ]; then
      owner=$(gh api user 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("login",""))') || owner=""
      if [ -z "$owner" ]; then
        report BLOCKED project-board "could not tell who you are on GitHub (gh api user failed)"
        needs_you "Run 'gh auth status', or give the owner by name instead of @me."
        return
      fi
    fi
    local titles made
    titles=$(python3 -I "$BOARD_TOOL" titles --policy-json "$BOARD_POLICY")
    if ! made=$(gh project create --owner "$owner" --title "${repo#*/} factory board" --format json 2>/dev/null); then
      report BLOCKED project-board "could not create a board for $owner"
      needs_you "Run 'gh auth refresh -s project' and check that you may create projects for $owner."
      return
    fi
    number=$(printf '%s' "$made" | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("number",""))')
    field_name=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["created_field"])' "$BOARD_POLICY")
    if [ -z "$number" ] ||
      ! gh project link "$number" --owner "$owner" --repo "$repo" >/dev/null 2>&1 ||
      ! gh project field-create "$number" --owner "$owner" --name "$field_name" --data-type SINGLE_SELECT --single-select-options "$titles" --format json >/dev/null 2>&1; then
      report BLOCKED project-board "the board $owner/${number:-?} was created but it could not be linked or given its field"
      needs_you "A board was created. Do NOT run --create-project again, or you will get a second one. Finish with: gh project link ${number:-NUMBER} --owner $owner --repo $repo ; gh project field-create ${number:-NUMBER} --owner $owner --name '$field_name' --data-type SINGLE_SELECT --single-select-options '$titles' . Then run this script with --project $owner/${number:-NUMBER}."
      FAILED=1
      return
    fi
    done_for_you "Created the board $owner/$number and linked it to $repo."
  fi

  # 4. Read the board's field and map the stages onto the options that are there.
  local kind
  kind=$(owner_type_of "$owner") || kind=""
  if [ -z "$kind" ]; then
    report BLOCKED project-board "could not tell whether $owner is an organization or a user"
    needs_you "Run 'gh auth status' and check that $owner exists."
    return
  fi
  if ! gh project field-list "$number" --owner "$owner" --format json --limit 50 >"$tmp/fields.json" 2>/dev/null; then
    report BLOCKED project-board "could not read the fields of the board $owner/$number"
    needs_you "Run 'gh auth refresh -s project' and check that $owner/$number exists. Then run this script again."
    return
  fi
  local mapped_ok=0
  if [ "$created" -eq 1 ]; then
    python3 -I "$BOARD_TOOL" map --policy-json "$BOARD_POLICY" --owner "$owner" --owner-type "$kind" --number "$number" --created \
      >"$tmp/board.json" 2>"$tmp/notes.txt" && mapped_ok=1
  else
    python3 -I "$BOARD_TOOL" map --policy-json "$BOARD_POLICY" --owner "$owner" --owner-type "$kind" --number "$number" \
      --fields "$tmp/fields.json" --status-field "$field_name" >"$tmp/board.json" 2>"$tmp/notes.txt" && mapped_ok=1
  fi
  if [ "$mapped_ok" -ne 1 ]; then
    report NEEDS project-board "the board $owner/$number has no single-select field named '$field_name'"
    sed 's/^FAIL //' "$tmp/notes.txt" | indent_clean
    needs_you "Pass --board-field with the name of the field that holds your columns (it must be a single-select field), or use --create-project to make a board with its own field."
    return
  fi
  note_board_owner "$owner"
  if [ "$check_only" -eq 1 ]; then
    report WOULD_ADD project-board "$BOARD_CONFIG_REL would be written for the board $owner/$number, field '$field_name'"
  else
    atomic_copy "$tmp/board.json" "$config"
    report ADDED project-board "wrote $BOARD_CONFIG_REL for the board $owner/$number, field '$field_name'. No option of the board was changed."
    done_for_you "Mapped the stages onto the board $owner/$number in $BOARD_CONFIG_REL."
  fi
  while IFS= read -r note; do
    [ -n "$note" ] && remember "Board: ${note#NOTE }"
  done <"$tmp/notes.txt"
  remember "Review $BOARD_CONFIG_REL in the pull request. A board view is made in the GitHub web page: group a Board layout by '$field_name'."
  step_board_credential
}

# The Action moves cards only on a board that belongs to the repository's owner, or to an owner the repository lists in
# the variable FACTORY_BOARD_OWNERS (PL-11). Say so when the board belongs to somebody else.
note_board_owner() { # OWNER
  if [ "$(lower "$1")" != "$(lower "${repo%/*}")" ]; then
    remember "The board belongs to $1, who is not the owner of $repo. Set the repository variable FACTORY_BOARD_OWNERS to $1, or the Action will refuse to move cards. It moves cards only on a board of the repository's owner or of an owner listed there."
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Step 6: has the project been mapped?
# ---------------------------------------------------------------------------------------------------------------
# What to type to map the project, for the agents this run prepared. With none prepared, both are named.
bootstrap_hint() {
  local claude_hint="In Claude Code, started in $checkout, run /egm:egm-bootstrap with the path ."
  local codex_hint="In Codex, started in $checkout, choose the egm-bootstrap skill from the skill list (EGM's Codex guide describes it this way) and give it the path ."
  if [ "$HAVE_CLAUDE" -eq 1 ] && [ "$HAVE_CODEX" -eq 1 ]; then
    printf '%s Or %s' "$claude_hint" "$codex_hint"
  elif [ "$HAVE_CODEX" -eq 1 ]; then
    printf '%s' "$codex_hint"
  elif [ "$HAVE_CLAUDE" -eq 1 ]; then
    printf '%s' "$claude_hint"
  else
    printf '%s Or %s' "$claude_hint" "$codex_hint"
  fi
}

step_map() {
  [ -n "$checkout" ] || return 0
  local out rc=0
  out=$(python3 -I "$MAP_TOOL" check "$checkout" 2>&1) || rc=$?
  case "$rc" in
    0) report PRESENT project-map "$(printf '%s' "$out" | tail -n 1)" ;;
    1)
      report NEEDS project-map "$(printf '%s' "$out" | tail -n 1)"
      printf '%s\n' "$out" | grep '^MISSING' | head -n 8 | indent_clean
      needs_you "Map the project. $(bootstrap_hint) It asks before it maps a large tree. Read what it wrote, then merge it by pull request. If people already maintain READMEs there, give it the file name EGM.md so that it does not touch them."
      ;;
    *)
      report BLOCKED project-map "$out"
      FAILED=1
      ;;
  esac
}

step_uncommitted() {
  [ -n "$checkout" ] || return 0
  git -C "$checkout" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
  local changed
  # Only the paths that this script and EGM's bootstrap write. Other work in progress is the person's business.
  # The checkout is not trusted: its .git/config could name a command (core.fsmonitor) that git would run.
  changed=$(GIT_OPTIONAL_LOCKS=0 git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "$checkout" status --porcelain -- .github .mcp.json .codex '*README.md' '*EGM.md' 2>/dev/null | wc -l | tr -d ' ')
  if [ "$changed" -gt 0 ]; then
    report NEEDS uncommitted "$changed installed or generated path(s) are not committed"
    needs_you "Review the changes in $checkout and merge them by pull request, so that the map is on the default branch before a person attests it. The engine cannot see your repository: it records the commit that you attest and does not check that the commit exists. A second person enables the repository after the one who attested the map; if you are the only maintainer, register the repository with 'factory-cli repository register --single-maintainer' (see the onboarding guide, 'A single-maintainer repository'). Registering, confirming and enabling are requests that the worker applies: each command waits up to 60 seconds for it (exit code 3 means the worker had not applied it yet; look again with 'factory-cli repository change REQUEST', do not send it again)."
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------------------------------------------
if [ "$check_only" -eq 1 ]; then printf 'Checking only. Nothing will be changed.\n'; fi
step_tools
step_egm
step_mcp
step_files
step_labels
step_board
step_bot_variable
step_map
step_uncommitted

printf '\n'
if [ -n "$DONE_LINES" ]; then printf 'Done for you\n%s\n' "$DONE_LINES"; fi
if [ -n "$NEED_LINES" ]; then printf 'Needs you\n%s\n' "$NEED_LINES"; fi
if [ -n "$NOTE_LINES" ]; then printf 'Remember\n%s\n' "$NOTE_LINES"; fi
if [ "$FAILED" -ne 0 ]; then
  printf 'FAILED: a step could not finish. Read the BLOCKED lines above.\n'
  exit 1
fi
if [ -n "$NEED_LINES" ]; then
  printf 'NOT READY\n'
  exit 3
fi
if [ "$PENDING" -ne 0 ]; then
  printf 'NOT READY: the WOULD_ADD lines above are changes that --check did not make. Run again without --check.\n'
  exit 3
fi
printf 'READY\n'
