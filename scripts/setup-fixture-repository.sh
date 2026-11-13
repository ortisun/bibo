#!/usr/bin/env bash
# scripts/setup-fixture-repository.sh - make the GitHub copy of the word-count fixture for the
# first real end-to-end run (scenario E1, docs/guides/first-real-run.md).
#
# USAGE
#   scripts/setup-fixture-repository.sh --check --app-id ID [--public|--private] [--owner @LOGIN ...] OWNER/NAME
#       Show every step and every gh call it would make, the files it would push and the ruleset
#       it would create. Calls nothing on GitHub and changes nothing.
#   scripts/setup-fixture-repository.sh --app-id ID [--public|--private] [--owner @LOGIN ...] OWNER/NAME
#       Do it. Run it once, as the owner, with gh logged in (gh auth login).
#   scripts/setup-fixture-repository.sh --help
#
#   Example, for the factory's own fixture:
#       scripts/setup-fixture-repository.sh --app-id ID ortisun/factory-fixture-word-count
#
#   --app-id ID      The id of the factory's GitHub App (scripts/github_app_manifest.py prints it).
#                    The ruleset pins the two required checks to it.
#   --public         Make the repository public. The default. GitHub Free offers rulesets only on
#                    public repositories, and the factory needs the ruleset. Everything in the
#                    repository, its issues, its pull requests and the factory's comments can then
#                    be read by anyone: put nothing private in it or in a test issue.
#   --private        Make the repository private. Needs GitHub Pro, Team or Enterprise for the
#                    ruleset; on GitHub Free step 5 is refused.
#   --owner @LOGIN   A code owner. Repeat for more. Default: the login gh is signed in as. The
#                    approval policy lets the owner approve their own low-risk request, so one real
#                    owner is enough; the placeholder handles of the template are all replaced.
#
# WHAT IT DOES, IN ORDER, AND THE gh CALLS IT MAKES
#   1. Reads who you are, when no --owner is given:      gh api user --jq .login
#   2. Builds the copy in target/e2e-fixture/OWNER/NAME (kept: the harness reads its CODEOWNERS):
#        fixtures/repos/word-count, with CODEOWNERS naming the owners;
#        the Spec Kit installation of this checkout (.specify, .claude/skills/speckit-*,
#        .agents/skills/speckit-*), which the specification stage needs in the repository;
#        the fixture's constitution, .specify/memory/constitution.md, from
#        fixtures/recordings/playbook/word-count/constitution.md (review it: you own it).
#      checks that nothing in the copy looks like a secret (a private key, a provider key or a
#      GitHub token, or a file named .env, *.pem or *.key) and stops if anything does,
#      and makes one commit on main with git (no gh call).
#   3. Creates the repository, public unless --private is given, and pushes the copy:
#        gh repo create OWNER/NAME --public --description ... --source DIR --remote origin --push
#   4. Creates the label the factory starts on:
#        gh label create factory --repo OWNER/NAME --color 5319e7 --description ...
#   5. Creates the branch ruleset the protection preflight requires (policies/security.yaml,
#      credentials.repository_requirements): a pull request with one approving review and a code
#      owner's review, stale approvals dismissed, no force push, no deletion, the checks
#      factory-validation and factory-review required and pinned to the App, nobody on the bypass
#      list:
#        gh api --method POST repos/OWNER/NAME/rulesets --input RULESET.json
#   6. Reads the rulesets back:                             gh api repos/OWNER/NAME/rulesets
#
#   Rulesets on a private repository need GitHub Pro, Team or Enterprise. On GitHub Free only a
#   public repository has them, which is why public is the default. With --private on GitHub Free
#   step 5 is refused; the script stops there and says so.
#
#   It never installs the App (you do that on the App's page, for this repository only), never
#   gives anybody access, and never deletes anything.
#
# EXIT CODES
#   0 done (or, with --check, shown), 1 a step failed (or the copy holds something that looks like
#   a secret), 2 wrong usage, 3 BLOCKED (gh or git missing, or gh not logged in).

set -euo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SELF_DIR/.." && pwd -P)
FIXTURE="$ROOT/fixtures/repos/word-count"
CONSTITUTION="$ROOT/fixtures/recordings/playbook/word-count/constitution.md"

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() {
  printf 'setup-fixture-repository.sh: %s\n' "$1" >&2
  exit "${2:-1}"
}

check=0
app_id=""
repo=""
visibility=public
visibility_given=""
owners=()
while [ "$#" -gt 0 ]; do
  case $1 in
    --help | -h)
      usage
      exit 0
      ;;
    --check) check=1 ;;
    --public | --private)
      [ -z "$visibility_given" ] || [ "$visibility_given" = "$1" ] || die "give --public or --private, not both" 2
      visibility_given=$1
      visibility=${1#--}
      ;;
    --app-id)
      [ "$#" -ge 2 ] || die "--app-id needs a value" 2
      app_id=$2
      shift
      ;;
    --owner)
      [ "$#" -ge 2 ] || die "--owner needs a value" 2
      owners+=("@${2#@}")
      shift
      ;;
    -*) die "unknown option $1 (see --help)" 2 ;;
    *)
      [ -z "$repo" ] || die "give one repository, not $repo and $1" 2
      repo=$1
      ;;
  esac
  shift
done

case $repo in
  */*/* | /* | */ | "") die "give the repository as OWNER/NAME" 2 ;;
  */*) ;;
  *) die "give the repository as OWNER/NAME" 2 ;;
esac
case $app_id in
  '' | *[!0-9]*) die "give the App's id with --app-id (a number)" 2 ;;
esac
for owner in ${owners[@]+"${owners[@]}"}; do
  case $owner in
    @example-org/* | @) die "$owner is not a real owner" 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
# Prints a gh call; runs it unless --check.
gh_call() {
  local shown
  shown=$(printf ' %q' "$@")
  say "  gh$shown"
  [ "$check" -eq 1 ] || gh "$@"
}

if [ "$check" -eq 0 ]; then
  type -P gh >/dev/null 2>&1 || die "gh is not installed (https://cli.github.com)" 3
  type -P git >/dev/null 2>&1 || die "git is not installed" 3
  gh auth status >/dev/null 2>&1 || die "gh is not logged in: run gh auth login" 3
fi

say "== 1. The code owners"
if [ "${#owners[@]}" -eq 0 ]; then
  if [ "$check" -eq 1 ]; then
    owners=("@YOUR-GH-LOGIN")
    say "  gh api user --jq .login   (not called with --check; shown as @YOUR-GH-LOGIN)"
  else
    say "  gh api user --jq .login"
    login=$(gh api user --jq .login) || die "gh could not say who you are"
    owners=("@$login")
  fi
fi
say "  owners: ${owners[*]}"

ruleset=$(
  cat <<JSON
{
  "name": "factory protection of the default branch",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "factory-validation", "integration_id": $app_id },
          { "context": "factory-review", "integration_id": $app_id }
        ]
      }
    }
  ]
}
JSON
)

say "== 2. The copy of the fixture"
if [ "$check" -eq 1 ]; then
  copy=$(mktemp -d "${TMPDIR:-/tmp}/fixture-check.XXXXXX")
  trap 'rm -rf "$copy"' EXIT
else
  copy="$ROOT/target/e2e-fixture/$repo"
  [ ! -e "$copy/.git" ] || die "$copy already holds a copy; this script makes the repository once. Remove that directory only if the repository was never made."
  mkdir -p "$copy"
fi
cp -R "$FIXTURE/." "$copy/"
rm -rf "$copy/target"
# Spec Kit: the files git tracks in this checkout, without the factory's own constitution.
while IFS= read -r path; do
  [ "$path" = ".specify/memory/constitution.md" ] && continue
  mkdir -p "$copy/$(dirname "$path")"
  cp "$ROOT/$path" "$copy/$path"
done < <(cd "$ROOT" && git ls-files .specify ':(glob).claude/skills/speckit-*/**' ':(glob).agents/skills/speckit-*/**')
mkdir -p "$copy/.specify/memory"
cp "$CONSTITUTION" "$copy/.specify/memory/constitution.md"
# CODEOWNERS: every placeholder handle becomes the owners.
{
  printf '# Who reviews what. GitHub reads the last matching line for a path.\n'
  printf '# Written by scripts/setup-fixture-repository.sh from the template in the factory repository.\n'
  while IFS= read -r line; do
    case $line in
      '#'* | '') ;;
      *)
        pattern=${line%% *}
        printf '%s %s\n' "$pattern" "${owners[*]}"
        ;;
    esac
  done <"$FIXTURE/CODEOWNERS"
} >"$copy/CODEOWNERS"
grep -q '@example-org/' "$copy/CODEOWNERS" && die "a placeholder handle is left in CODEOWNERS"
say "  $(find "$copy" -type f | wc -l | tr -d ' ') files in $copy"
# Nothing that looks like a secret goes to GitHub, least of all to a public repository. The
# patterns are a private key, an Anthropic or OpenAI key, a GitHub token, and AWS's key id.
secret_pattern='BEGIN [A-Z ]*PRIVATE KEY|sk-ant-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9]{32,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}'
suspects=$(
  {
    grep -rIlE "$secret_pattern" "$copy" || true
    find "$copy" -type f \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' \) -print
  } | sed "s|^$copy/||" | sort -u
)
if [ -n "$suspects" ]; then
  printf '%s\n' "$suspects" | sed 's/^/    /' >&2
  die "the copy holds files that look like secrets (listed above); nothing was pushed. Remove them from the fixture and run the script again."
fi
say "  nothing in the copy looks like a secret"
say "  CODEOWNERS:"
sed 's/^/    /' "$copy/CODEOWNERS"
if [ "$check" -eq 0 ]; then
  (
    cd "$copy"
    git init -q -b main
    git add -A
    git commit -q -m "The word-count fixture for the factory's end-to-end run"
  )
fi
say "  git init -b main; git add -A; git commit (in the copy)"

say "== 3. The $visibility repository"
if [ "$visibility" = public ]; then
  say "  Public: anyone can read its code, its issues, its pull requests and the factory's comments."
  say "  Put nothing private in it, and nothing private in a test issue."
fi
gh_call repo create "$repo" "--$visibility" \
  --description "The word-count fixture of the software factory's end-to-end run" \
  --source "$copy" --remote origin --push

say "== 4. The label"
gh_call label create factory --repo "$repo" --color 5319e7 \
  --description "Asks the software factory to work on this issue"

say "== 5. The ruleset"
ruleset_file="$copy.ruleset.json"
printf '%s\n' "$ruleset" >"$ruleset_file"
sed 's/^/    /' "$ruleset_file"
if [ "$check" -eq 1 ]; then
  say "  gh api --method POST repos/$repo/rulesets --input $ruleset_file"
  rm -f "$ruleset_file"
else
  say "  gh api --method POST repos/$repo/rulesets --input $ruleset_file"
  if ! gh api --method POST "repos/$repo/rulesets" --input "$ruleset_file" >/dev/null; then
    rm -f "$ruleset_file"
    if [ "$visibility" = private ]; then
      die "GitHub refused the ruleset. Rulesets on a private repository need GitHub Pro, Team or Enterprise; on GitHub Free make the repository public instead (the default). The repository is made and pushed, and without the ruleset the factory runs it at L0 and opens no pull request."
    fi
    die "GitHub refused the ruleset. The repository is made and pushed, and without the ruleset the factory runs it at L0 and opens no pull request. Check that your gh login may administer $repo."
  fi
  rm -f "$ruleset_file"
fi

say "== 6. The ruleset, read back"
gh_call api "repos/$repo/rulesets"

if [ "$check" -eq 1 ]; then
  say "Nothing was done (--check). Run it again without --check to make $repo."
else
  say "Done. Now install the App on $repo only (docs/guides/first-real-run.md, step 4), then"
  say "  export FACTORY_E2E_FIXTURE_REPO=$repo"
fi
