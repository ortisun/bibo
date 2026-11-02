#!/usr/bin/env bash
# scripts/install.sh - prepare an existing project to work with the factory (ADR 0016).
#
# OBJECTIVE   Put the design tools and the issue workflow in place, so that a project can be mapped and then
#             receive tickets. It installs; it never starts a job and it never commits or pushes anything.
# DONE WHEN   Every line it prints is PRESENT or ADDED, it prints "READY", and it exits with code 0.
#
#   scripts/install.sh --check                         Show what would change. Change nothing. Safe to run any time.
#   scripts/install.sh                                 Install the EGM plugin for Claude Code if it is missing.
#   scripts/install.sh --checkout PATH                 Also prepare the project at PATH: the GitHub MCP server entry
#                                                      (.mcp.json), the issue workflow files (.github/), and a check
#                                                      that the project has been mapped by EGM's bootstrap.
#   scripts/install.sh --checkout PATH --repo O/N      Also create the issue-workflow labels in the GitHub repository
#                                                      O/N with `gh`. This is the one step that changes GitHub.
#   --update                                           Replace a project file that differs from the factory's copy.
#                                                      Without it a differing file is reported as DRIFT and kept.
#   --no-mcp                                           Skip the GitHub MCP server entry.
#   --help                                             Show this text.
#
# What each step does
#   tools          git, python3 and Claude Code (version 2.1.271 or later, for EGM's reviewer isolation).
#   egm-plugin     The EGM plugin (egm@egm, from github.com/google/elephant-goldfish-model) in Claude Code's user
#                  scope. Installed only when missing; enabled when it is installed but disabled. Start a new
#                  Claude Code session afterwards.
#   github-mcp     An entry for GitHub's MCP server in the project's .mcp.json. The entry holds the name of an
#                  environment variable, FACTORY_GITHUB_MCP_TOKEN, and never a token. This script does not read
#                  that variable, only whether it is set. The server is a tool for the person in the design
#                  session. The factory's engine never uses it and never honors a project's .mcp.json.
#   workflow-files The issue forms, the Action that keeps labels consistent, and its two helper files, copied into
#                  the project's .github/. They are files in the working tree. A person commits them by pull request.
#   labels         The labels of policies/issue-workflow.yaml, created or corrected with `gh label create --force`.
#   project-map    Whether every directory that holds code has a README.md or EGM.md contract. EGM's bootstrap writes
#                  them, and it needs a person (it asks before it maps a large tree), so this script only checks.
#
# Output: one line per step, "  STATE  step  detail". STATE is PRESENT, ADDED, UPDATED, WOULD_ADD, DRIFT, NEEDS,
# BLOCKED or SKIPPED. The end lists "Done for you" and "Needs you".
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

WORKFLOW_TOOL="$SELF_DIR/lib/issue_workflow.py"
MAP_TOOL="$SELF_DIR/lib/project_map.py"
RENDERED="$ROOT/onboarding/github/issue-workflow.json"

check_only=0
update=0
want_mcp=1
checkout=""
repo=""

usage_error() {
  printf 'install.sh: %s (try --help)\n' "$1" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --check) check_only=1 ;;
    --update) update=1 ;;
    --no-mcp) want_mcp=0 ;;
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

if [ -n "$repo" ]; then
  case "$repo" in
    */*/* | */ | /* | . | .. | ./* | ../* | */. | */.. | *[!A-Za-z0-9_./-]*) usage_error "--repo must look like OWNER/NAME" ;;
  esac
  case "$repo" in */*) ;; *) usage_error "--repo must look like OWNER/NAME" ;; esac
  [ -n "$checkout" ] || usage_error "--repo goes with --checkout, so the labels and the files come from one install"
fi
if [ -n "$checkout" ]; then
  [ -d "$checkout" ] || usage_error "--checkout: '$checkout' is not a directory"
  checkout=$(cd "$checkout" && pwd -P)
fi

# ---------------------------------------------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------------------------------------------
DONE_LINES=""
NEED_LINES=""
NOTE_LINES=""
FAILED=0
PENDING=0

report() { # STATE STEP DETAIL
  printf '  %-9s %-15s %s\n' "$1" "$2" "$3"
  if [ "$1" = WOULD_ADD ]; then PENDING=1; fi
}
done_for_you() { DONE_LINES="${DONE_LINES}  - $1"$'\n'; }
# Something only a person can do. The install is not ready until it is done.
needs_you() { NEED_LINES="${NEED_LINES}  - $1"$'\n'; }
# Something to know. It does not stop the install from being ready.
remember() { NOTE_LINES="${NOTE_LINES}  - $1"$'\n'; }

# ---------------------------------------------------------------------------------------------------------------
# Step 1: tools
# ---------------------------------------------------------------------------------------------------------------
HAVE_CLAUDE=0
HAVE_GH=0

version_at_least() { # have want
  python3 -I -c '
import sys
def parts(v):
    return tuple(int(p) for p in v.split(".")[:3])
sys.exit(0 if parts(sys.argv[1]) >= parts(sys.argv[2]) else 1)' "$1" "$2" 2>/dev/null
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
  if ! command -v claude >/dev/null 2>&1; then
    report BLOCKED tools "Claude Code is not installed"
    needs_you "Install Claude Code (https://claude.com/claude-code) $CLAUDE_MIN_VERSION or later, then run this script again."
    return
  fi
  local have
  have=$(claude --version 2>/dev/null | awk '{print $1; exit}')
  if [ -z "$have" ] || ! version_at_least "$have" "$CLAUDE_MIN_VERSION"; then
    report BLOCKED tools "Claude Code ${have:-of unknown version} is older than $CLAUDE_MIN_VERSION"
    needs_you "Update Claude Code to $CLAUDE_MIN_VERSION or later. Older versions do not isolate EGM's reviewers."
    return
  fi
  HAVE_CLAUDE=1
  report PRESENT tools "git, python3, claude $have"
  if command -v gh >/dev/null 2>&1; then HAVE_GH=1; fi
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

step_egm() {
  if [ "$HAVE_CLAUDE" -ne 1 ]; then
    report SKIPPED egm-plugin "needs Claude Code"
    return
  fi
  local state version
  read -r state version <<EOF
$(plugin_status)
EOF
  case "$state" in
    enabled)
      if [ "$version" = "$EGM_EXPECTED_VERSION" ]; then
        report PRESENT egm-plugin "$EGM_PLUGIN $version"
      else
        report DRIFT egm-plugin "$EGM_PLUGIN $version is installed; this script was written against $EGM_EXPECTED_VERSION"
        remember "Read the EGM release notes for $version before you rely on it. Nothing was changed."
      fi
      ;;
    disabled)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD egm-plugin "$EGM_PLUGIN $version is installed but disabled; it would be enabled"
        return
      fi
      if claude plugin enable "$EGM_PLUGIN" >/dev/null 2>&1; then
        report UPDATED egm-plugin "$EGM_PLUGIN $version enabled"
        done_for_you "Enabled the EGM plugin."
        remember "Start a new Claude Code session so the /egm skills load."
      else
        report BLOCKED egm-plugin "'claude plugin enable $EGM_PLUGIN' failed"
        FAILED=1
      fi
      ;;
    *)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD egm-plugin "$EGM_PLUGIN would be installed from $EGM_MARKETPLACE_SOURCE"
        return
      fi
      if ! marketplace_present; then
        if ! claude plugin marketplace add "$EGM_MARKETPLACE_SOURCE" >/dev/null 2>&1; then
          report BLOCKED egm-plugin "could not add the marketplace $EGM_MARKETPLACE_SOURCE (is the network reachable?)"
          FAILED=1
          return
        fi
      fi
      if ! claude plugin install "$EGM_PLUGIN" >/dev/null 2>&1; then
        report BLOCKED egm-plugin "'claude plugin install $EGM_PLUGIN' failed"
        FAILED=1
        return
      fi
      read -r state version <<EOF
$(plugin_status)
EOF
      if [ "$state" = enabled ]; then
        report ADDED egm-plugin "$EGM_PLUGIN $version"
        done_for_you "Installed the EGM plugin ($EGM_PLUGIN $version)."
        remember "Start a new Claude Code session so the /egm skills load."
      else
        report BLOCKED egm-plugin "the plugin was installed but is not enabled"
        FAILED=1
      fi
      ;;
  esac
}

# ---------------------------------------------------------------------------------------------------------------
# Step 3: GitHub's MCP server entry in the project's .mcp.json
# ---------------------------------------------------------------------------------------------------------------
# prints one of: absent | same | different | credential (a header that has no ${...} in it), and with "write"
# as the second argument it merges the entry in. The token is never read: the entry names a variable.
# The single quotes hold Python. The "${" inside is literal text for .mcp.json, which Claude Code expands later,
# so the shell must not expand it (SC2016 is expected here).
# shellcheck disable=SC2016
mcp_entry() { # PATH MODE(inspect|write)
  python3 -I -c '
import json, os, sys
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
try:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
except FileNotFoundError:
    document = {}
servers = document.setdefault("mcpServers", {})
current = servers.get("github")
if mode == "inspect":
    if current is None:
        print("absent")
    elif current == entry:
        print("same")
    elif any("${" not in str(v) for v in (current.get("headers") or {}).values()):
        print("credential")
    else:
        print("different")
else:
    servers["github"] = entry
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")' "$1" "$2" "$MCP_TOKEN_VAR"
}

step_mcp() {
  if [ -z "$checkout" ] || [ "$want_mcp" -eq 0 ]; then
    return
  fi
  local file="$checkout/.mcp.json" state
  state=$(mcp_entry "$file" inspect)
  case "$state" in
    same) report PRESENT github-mcp ".mcp.json names \${$MCP_TOKEN_VAR}" ;;
    credential)
      report DRIFT github-mcp "the github entry in .mcp.json has a header with no \${VARIABLE} in it, which may be a token (value not shown)"
      needs_you "Remove the token from .mcp.json and rotate it. A token in a committed file is public to everyone with access. Then run this script with --update."
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ]; then
        mcp_entry "$file" write
        report UPDATED github-mcp "replaced by an entry that names \${$MCP_TOKEN_VAR}"
      fi
      ;;
    different)
      if [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ]; then
        mcp_entry "$file" write
        report UPDATED github-mcp "the github entry in .mcp.json was replaced"
        done_for_you "Updated the github entry in .mcp.json."
      else
        report DRIFT github-mcp "the github entry in .mcp.json differs from the factory's; kept (use --update to replace)"
      fi
      ;;
    *)
      if [ "$check_only" -eq 1 ]; then
        report WOULD_ADD github-mcp "a github entry would be added to .mcp.json"
      else
        mcp_entry "$file" write
        report ADDED github-mcp "added a github entry to .mcp.json"
        done_for_you "Added GitHub's MCP server to .mcp.json."
      fi
      ;;
  esac
  if [ -z "${!MCP_TOKEN_VAR:-}" ]; then
    report NEEDS github-token "$MCP_TOKEN_VAR is not set (it was not read, only checked)"
    needs_you "Create a fine-grained GitHub token for this one repository (Issues and Pull requests: read and write; Contents and Metadata: read) and export it as $MCP_TOKEN_VAR before you start Claude Code. Never paste it in a chat or a file."
  fi
}

# ---------------------------------------------------------------------------------------------------------------
# Step 4: the issue workflow files
# ---------------------------------------------------------------------------------------------------------------
copy_one() { # SOURCE DESTINATION(relative to the checkout)
  local src=$1 rel=$2 dst
  dst="$checkout/$rel"
  if [ ! -e "$dst" ]; then
    if [ "$check_only" -eq 1 ]; then
      WOULD=$((WOULD + 1))
    else
      mkdir -p "$(dirname "$dst")"
      cp "$src" "$dst"
      ADDED=$((ADDED + 1))
    fi
  elif cmp -s "$src" "$dst"; then
    SAME=$((SAME + 1))
  elif [ "$update" -eq 1 ] && [ "$check_only" -eq 0 ]; then
    cp "$src" "$dst"
    UPDATED=$((UPDATED + 1))
  else
    report DRIFT workflow-files "$rel differs from the factory's copy; kept (use --update to replace)"
    DRIFTED=$((DRIFTED + 1))
  fi
}

step_files() {
  [ -n "$checkout" ] || return 0
  ADDED=0 SAME=0 UPDATED=0 WOULD=0 DRIFTED=0
  copy_one "$RENDERED" ".github/issue-workflow.json"
  copy_one "$WORKFLOW_TOOL" ".github/scripts/issue_workflow.py"
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
  elif [ "$DRIFTED" -eq 0 ]; then
    report PRESENT workflow-files "$detail"
  fi
  if [ "$DRIFTED" -gt 0 ]; then
    needs_you "Compare the DRIFT files above with the factory's copies, then run with --update if you want them replaced."
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
# Step 6: has the project been mapped?
# ---------------------------------------------------------------------------------------------------------------
step_map() {
  [ -n "$checkout" ] || return 0
  local out rc=0
  out=$(python3 -I "$MAP_TOOL" check "$checkout" 2>&1) || rc=$?
  case "$rc" in
    0) report PRESENT project-map "$(printf '%s' "$out" | tail -n 1)" ;;
    1)
      report NEEDS project-map "$(printf '%s' "$out" | tail -n 1)"
      printf '%s\n' "$out" | grep '^MISSING' | head -n 8 | sed 's/^/              /'
      needs_you "Map the project. In Claude Code, started in $checkout, run /egm:egm-bootstrap with the path . (use the file name EGM.md if people already maintain READMEs there). It asks before it maps a large tree. Read what it wrote, then merge it by pull request."
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
  changed=$(git -C "$checkout" status --porcelain -- .github .mcp.json '*README.md' '*EGM.md' 2>/dev/null | wc -l | tr -d ' ')
  if [ "$changed" -gt 0 ]; then
    report NEEDS uncommitted "$changed installed or generated path(s) are not committed"
    needs_you "Review the changes in $checkout and commit them by pull request. The factory does not enable a repository whose map is not on its default branch."
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
