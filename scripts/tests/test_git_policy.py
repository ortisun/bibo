#!/usr/bin/env python3
"""Tests for scripts/lib/git_policy.py: Conventional Commits, gitflow, the settings file, inference and the git hooks.
Standard library only. Run it with:
    python3 -I scripts/tests/test_git_policy.py

The rules are tested as functions, then through real git: temporary repositories, the hooks installed the way the
installer installs them, a bare repository as the remote, and `gh` replaced by a fake that answers from a file.
Nothing touches the network or the person's git configuration (HOME and the git identity are set per test).
"""
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
POLICY = os.path.join(ROOT, "scripts", "lib", "git_policy.py")
HOOKS = os.path.join(ROOT, "onboarding", "github", "githooks")
_spec = importlib.util.spec_from_file_location("git_policy", POLICY)
assert _spec is not None and _spec.loader is not None
gp = importlib.util.module_from_spec(_spec)
sys.modules["git_policy"] = gp  # dataclasses look their module up by name
_spec.loader.exec_module(gp)

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
state = os.environ["FAKE_STATE"]
args = sys.argv[1:]
with open(os.path.join(state, "gh.log"), "a", encoding="utf-8") as log: log.write(" ".join(args) + "\n")
def load(name, default):
    try:
        with open(os.path.join(state, name), encoding="utf-8") as h: return json.load(h)
    except FileNotFoundError: return default
if args[:2] == ["pr", "list"]:
    print(json.dumps(load("pulls.json", [])))
elif args[:2] == ["api", "graphql"]:
    nodes = [{"number": b["number"], "title": b["title"], "closed": b.get("closed", False),
              "owner": {"__typename": "Organization", "login": b["owner"]}} for b in load("linked.json", [])]
    print(json.dumps({"data": {"repository": {"projectsV2": {"nodes": nodes}}}}))
elif args[:2] == ["repo", "view"]:
    name = load("repo_view.json", None)
    if name is None: sys.exit(1)
    print(name)
else:
    sys.exit(64)
'''


def settings(**changes):
    base = gp.Settings(owner="acme", name="widgets", board=("acme", 3), closing_mode="develop")
    for key, value in changes.items():
        setattr(base, key, value)
    return base


def document(**changes):
    doc = settings().to_json()
    for path, value in changes.items():
        target = doc
        keys = path.split("__")
        for key in keys[:-1]:
            target = target[key]
        if value is KeyError:
            del target[keys[-1]]
        else:
            target[keys[-1]] = value
    return doc


class Messages(unittest.TestCase):
    def ok(self, text, s=None, autosquash=False):
        self.assertEqual(gp.check_message(text, s or settings(), autosquash), [], text)

    def bad(self, text, words, s=None, autosquash=False):
        problems = gp.check_message(text, s or settings(), autosquash)
        self.assertTrue(problems, text)
        self.assertIn(words, " ".join(problems), text)

    def test_headers_that_follow_the_convention_pass(self):
        for text in ("feat: accept dates without a year", "fix(parser): stop at the end of input",
                     "feat(api)!: drop the v1 routes", "refactor!: rename the store",
                     "docs: say how to install\n\nThe body explains why.\n\nRefs: #12",
                     "feat: x\n\nBREAKING CHANGE: the old flag is gone", "chore: x\n\nBREAKING-CHANGE: gone"):
            self.ok(text)

    def test_each_broken_rule_is_named(self):
        cases = [
            ("add the parser", "must look like 'type(scope): description'"),
            ("feature: add the parser", "'feature' is not an allowed type"),
            ("Feat: add the parser", "write it in lower case"),
            ("feat:add the parser", "exactly one space"),
            ("feat:  add the parser", "exactly one space"),
            ("feat: ", "description after the colon is empty"),
            ("feat(): x", "scope in parentheses"),
            ("feat( api ): x", "scope in parentheses"),
            ("feat: x\nbody on the second line", "leave the second line blank"),
            ("feat: x\n\nbreaking change: gone", "'BREAKING CHANGE:' in capitals"),
            ("", "empty"),
            ("# only a comment\n", "empty"),
        ]
        for text, words in cases:
            with self.subTest(text=text):
                self.bad(text, words)

    def test_the_header_limit_is_inclusive(self):
        limit = settings().header_max_length
        at_limit = "feat: " + "a" * (limit - len("feat: "))
        self.assertEqual(len(at_limit), limit)
        self.ok(at_limit)
        self.bad(at_limit + "a", "has %d characters; the limit is %d" % (limit + 1, limit))

    def test_scopes_can_be_required_and_listed(self):
        strict = settings(require_scope=True, scopes=["api", "cli"])
        self.ok("feat(api): x", strict)
        self.bad("feat: x", "requires a scope", strict)
        self.bad("feat(web): x", "'web' is not an allowed scope", strict)

    def test_comments_and_the_scissors_part_are_not_the_message(self):
        self.ok("# Please enter the message\nfeat: x\n# a comment\n")
        self.ok("feat: x\n\n# ------------------------ >8 ------------------------\nnot a message\nat all")
        self.assertEqual(gp.message_lines("; c\nfeat: x\n", ";"), ["feat: x"])

    def test_gits_revert_message_passes(self):
        self.ok('Revert "feat: accept dates"\n\nThis reverts commit abc.')

    def test_autosquash_commits_pass_locally_and_not_in_review(self):
        self.ok("fixup! feat: x", autosquash=True)
        self.bad("fixup! feat: x", "must be squashed", autosquash=False)
        self.bad("squash! feat: x", "must be squashed", autosquash=False)


class SettingsFile(unittest.TestCase):
    def test_the_default_settings_round_trip(self):
        s = settings()
        self.assertEqual(gp.parse_settings(json.loads(gp.settings_text(s))).to_json(), s.to_json())

    def test_a_document_with_no_board_is_valid(self):
        self.assertIsNone(gp.parse_settings(document(project_board=None)).board)

    def bad(self, doc, words):
        with self.assertRaises(gp.SettingsError) as caught:
            gp.parse_settings(doc)
        self.assertIn(words, " ".join(caught.exception.problems))

    def test_every_mistake_is_refused_with_its_reason(self):
        cases = [
            (document(schema="factory-repository-settings/2"), "schema must be"),
            (document(extra=1), "unknown key 'extra'"),
            (document(gitflow__extra=1), "gitflow has an unknown key 'extra'"),
            (document(repository__owner="-acme"), "repository.owner"),
            (document(repository__name=".."), "repository.name"),
            (document(project_board__number=True), "project_board.number"),
            (document(project_board__number=0), "project_board.number"),
            (document(commits__types=[]), "commits.types must not be empty"),
            (document(commits__types=["Feat"]), "commits.types has a value that is not allowed"),
            (document(commits__types=["feat", "feat"]), "lists a value twice"),
            (document(commits__require_scope="no"), "require_scope"),
            (document(gitflow__closing_mode="main"), "closing_mode"),
            (document(gitflow__develop_branch="main"), "must differ"),
            (document(gitflow__prefixes__bugfix=["feature/"]), "listed for both feature and bugfix"),
            (document(gitflow__prefixes__hotfix=["hotfix"]), "gitflow.prefixes.hotfix has a value"),
            (document(gitflow__additional_flows=[{"head_prefix": "feature/", "into": ["develop"]}]), "already a gitflow"),
            (document(gitflow__additional_flows=[{"head_prefix": "deps/", "into": []}]), "into must not be empty"),
            (document(commits__convention=KeyError), "missing the key 'convention'"),
            ([], "the settings must be an object"),
        ]
        for doc, words in cases:
            with self.subTest(words=words):
                self.bad(doc, words)

    def test_the_header_limit_bounds_are_inclusive(self):
        for value, valid in ((19, False), (20, True), (200, True), (201, False), (True, False), (100.0, False)):
            with self.subTest(value=value):
                if valid:
                    self.assertEqual(gp.parse_settings(document(commits__header_max_length=value)).header_max_length,
                                     value)
                else:
                    self.bad(document(commits__header_max_length=value), "header_max_length")


class Inference(unittest.TestCase):
    def test_the_closing_mode_needs_three_merges_that_agree_four_in_five(self):
        cases = [
            ((0, 0), None), ((2, 0), None), ((0, 2), None),       # too few
            ((3, 0), "develop"), ((0, 3), "release"),             # the least evidence
            ((4, 1), "develop"), ((1, 4), "release"),             # exactly four in five
            ((3, 1), None), ((1, 3), None), ((2, 2), None),       # three in four is not enough
            ((8, 2), "develop"), ((7, 3), None),                  # 80 % and 70 %
        ]
        for (develop, release), expected in cases:
            with self.subTest(develop=develop, release=release):
                self.assertEqual(gp.decide_closing_mode(gp.Evidence(develop, release)), expected)

    def test_github_remote_addresses(self):
        for url in ("https://github.com/acme/widgets", "https://github.com/acme/widgets.git",
                    "https://token@github.com/acme/widgets.git", "git@github.com:acme/widgets.git",
                    "ssh://git@github.com/acme/widgets.git", "ssh://git@github.com:22/acme/widgets",
                    "https://github.com/acme/widgets/"):
            with self.subTest(url=url):
                self.assertEqual(gp.parse_github_remote(url), ("acme", "widgets"))
        for url in ("https://gitlab.com/acme/widgets.git", "git@work:acme/widgets.git", "https://github.com/acme",
                    "https://github.com/acme/widgets/tree/main", "/srv/git/widgets.git"):
            with self.subTest(url=url):
                self.assertIsNone(gp.parse_github_remote(url))

    def test_a_dotted_repository_name_keeps_its_dots(self):
        self.assertEqual(gp.parse_github_remote("git@github.com:acme/widgets.js.git"), ("acme", "widgets.js"))


class Gitflow(unittest.TestCase):
    def allowed(self, head, base, mode="develop", **changes):
        return gp.check_flow(head, base, settings(closing_mode=mode, **changes)) == []

    def test_develop_mode(self):
        for head, base, ok in (
                ("feature/login", "develop", True), ("bugfix/crash", "develop", True),
                ("factory/job-2f0c7f64", "develop", True),
                ("feature/login", "release/1.2.0", False), ("feature/login", "main", False),
                ("release/1.2.0", "main", True), ("release/1.2.0", "develop", True),
                ("release/1.2.0", "release/1.3.0", False),
                ("hotfix/1.2.1", "main", True), ("hotfix/1.2.1", "develop", True),
                ("hotfix/1.2.1", "release/1.3.0", True),
                ("main", "develop", True), ("develop", "main", False),
                ("support/1.x", "main", False)):
            with self.subTest(head=head, base=base):
                self.assertEqual(self.allowed(head, base), ok)

    def test_release_mode(self):
        for head, base, ok in (
                ("feature/login", "release/1.2.0", True), ("bugfix/crash", "release/1.2.0", True),
                ("factory/job-1", "release/1.2.0", True),
                ("feature/login", "develop", False), ("feature/login", "release/", False),
                ("release/1.2.0", "main", True), ("release/1.2.0", "develop", True),
                ("hotfix/1.2.1", "main", True)):
            with self.subTest(head=head, base=base):
                self.assertEqual(self.allowed(head, base, mode="release"), ok)

    def test_the_refusal_says_where_the_branch_may_close(self):
        problems = gp.check_flow("feature/login", "develop", settings(closing_mode="release"))
        self.assertIn("a release/... branch", problems[0])
        self.assertIn("straight into the release branch", problems[0])

    def test_branch_names(self):
        s = settings()
        for name in ("main", "develop", "feature/login", "feature/ABC-12-login", "feature/team/login",
                     "release/1.2.0", "factory/job-1"):
            with self.subTest(name=name):
                self.assertIsNone(gp.branch_problem(name, s))
        for name, words in (("wip", "not a gitflow branch name"), ("feature/", "needs a name"),
                            ("feature/-x", "needs a name"), ("feature//x", "needs a name"),
                            ("features/x", "not a gitflow branch name")):
            with self.subTest(name=name):
                self.assertIn(words, gp.branch_problem(name, s) or "")

    def test_additional_flows(self):
        s = settings(additional_flows=[gp.Flow("dependabot/", ["develop"])])
        self.assertEqual(gp.check_flow("dependabot/npm/x", "develop", s), [])
        self.assertTrue(gp.check_flow("dependabot/npm/x", "main", s))


# ---------------------------------------------------------------------------------------------------------------------
# Through real git
# ---------------------------------------------------------------------------------------------------------------------
class GitCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state = os.path.join(self.tmp, "state")
        self.bin = os.path.join(self.tmp, "bin")
        self.repo = os.path.join(self.tmp, "project")
        for folder in (self.state, self.bin, self.repo):
            os.makedirs(folder)
        gh = os.path.join(self.bin, "gh")
        with open(gh, "w", encoding="utf-8") as handle:
            handle.write(FAKE_GH)
        os.chmod(gh, 0o755)
        self.env = {"PATH": self.bin + ":/usr/bin:/bin", "HOME": self.tmp, "FAKE_STATE": self.state,
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@example.invalid",
                    "GIT_COMMITTER_NAME": "A", "GIT_COMMITTER_EMAIL": "a@example.invalid",
                    "FACTORY_GIT_POLICY_NO_PROMPT": "1"}
        self.saved_env = dict(os.environ)
        os.environ.clear()
        os.environ.update(self.env)
        self.addCleanup(self.restore_env)

    def restore_env(self):
        os.environ.clear()
        os.environ.update(self.saved_env)

    def git(self, *args, cwd=None, check=True, env=None, stdin=None):
        done = subprocess.run(["git", *args], cwd=cwd or self.repo, capture_output=True, text=True,
                              env=dict(self.env, **(env or {})), input=stdin)
        if check and done.returncode != 0:
            raise AssertionError("git %s failed: %s" % (" ".join(args), done.stdout + done.stderr))
        return done

    def init(self, remote: "str | None" = "git@github.com:acme/widgets.git"):
        self.git("init", "-q", "-b", "main")
        if remote:
            self.git("remote", "add", "origin", remote)

    def commit(self, message, verify=False, **kwargs):
        args = ["commit", "-q", "--allow-empty", "-m", message]
        if not verify:
            args.append("--no-verify")
        return self.git(*args, **kwargs)

    def merge(self, head, into, message=None):
        self.git("switch", "-q", into)
        self.git("merge", "-q", "--no-ff", "--no-verify", head, "-m", message or "Merge branch '%s' into %s" % (head, into))

    def put_state(self, name, value):
        with open(os.path.join(self.state, name), "w", encoding="utf-8") as handle:
            json.dump(value, handle)

    def write_settings(self, **changes):
        os.makedirs(os.path.join(self.repo, ".factory"), exist_ok=True)
        with open(os.path.join(self.repo, gp.SETTINGS_REL), "w", encoding="utf-8") as handle:
            handle.write(gp.settings_text(settings(**changes)))

    def install_hooks(self):
        """What the installer does: the policy and the hooks in .github/, and core.hooksPath."""
        os.makedirs(os.path.join(self.repo, ".github", "scripts"), exist_ok=True)
        shutil.copyfile(POLICY, os.path.join(self.repo, ".github", "scripts", "git_policy.py"))
        target = os.path.join(self.repo, ".github", "githooks")
        os.makedirs(target, exist_ok=True)
        for name in os.listdir(HOOKS):
            shutil.copyfile(os.path.join(HOOKS, name), os.path.join(target, name))
            os.chmod(os.path.join(target, name), 0o755)
        self.git("config", "core.hooksPath", ".github/githooks")

    def answers(self, *lines):
        path = os.path.join(self.tmp, "answers.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("".join(line + "\n" for line in lines))
        return path


class Repository(GitCase):
    def test_origin_wins_and_a_single_github_remote_is_enough(self):
        self.init()
        self.assertEqual(gp.infer_repository(self.repo, use_gh=False).value, "acme/widgets")
        self.git("remote", "rename", "origin", "github")
        found = gp.infer_repository(self.repo, use_gh=False)
        self.assertEqual((found.value, found.sure), ("acme/widgets", True))

    def test_remotes_that_disagree_are_not_guessed_between(self):
        self.init()
        self.git("remote", "add", "upstream", "https://github.com/other/widgets.git")
        found = gp.infer_repository(self.repo, use_gh=False)
        self.assertFalse(found.sure)
        self.assertEqual(found.choices, ["acme/widgets", "other/widgets"])
        self.git("remote", "remove", "origin")
        self.git("remote", "add", "fork", "https://github.com/third/widgets.git")
        found = gp.infer_repository(self.repo, use_gh=False)
        self.assertEqual((found.value, found.sure), (None, False))

    def test_an_ssh_alias_is_resolved_by_gh_and_only_when_gh_may_be_used(self):
        self.init(remote="git@work:acme/widgets.git")
        self.put_state("repo_view.json", "acme/widgets")
        self.assertEqual(gp.infer_repository(self.repo, use_gh=True).value, "acme/widgets")
        self.assertIsNone(gp.infer_repository(self.repo, use_gh=False).value)

    def test_no_remote(self):
        self.init(remote=None)
        self.assertIn("no git remote", gp.infer_repository(self.repo, use_gh=False).source)


class ClosingMode(GitCase):
    def history(self, into, count, start=0):
        for index in range(start, start + count):
            self.git("switch", "-q", "-c", "feature/f%d" % index, "main")
            self.commit("feat: f%d" % index)
            self.merge("feature/f%d" % index, into)

    def test_merge_commits_into_develop(self):
        self.init()
        self.commit("chore: start")
        self.git("branch", "develop")
        self.history("develop", 3)
        found = gp.infer_closing_mode(self.repo, None, use_gh=False)
        self.assertEqual((found.value, found.sure), ("develop", True))
        self.assertIn("3 of 3", found.source)

    def test_merge_commits_into_a_release_branch(self):
        self.init()
        self.commit("chore: start")
        self.git("branch", "release/1.0.0")
        self.history("release/1.0.0", 3)
        found = gp.infer_closing_mode(self.repo, None, use_gh=False)
        self.assertEqual((found.value, found.sure), ("release", True))

    def test_merged_pull_requests_count_and_unclear_history_is_only_a_guess(self):
        self.init()
        self.commit("chore: start")
        self.put_state("pulls.json", [{"headRefName": "feature/a", "baseRefName": "develop"},
                                      {"headRefName": "feature/b", "baseRefName": "release/2.0"},
                                      {"headRefName": "bugfix/c", "baseRefName": "develop"},
                                      {"headRefName": "dependabot/x", "baseRefName": "develop"},
                                      {"headRefName": "release/2.0", "baseRefName": "main"}])
        found = gp.infer_closing_mode(self.repo, "acme/widgets", use_gh=True)
        self.assertEqual((found.value, found.sure), ("develop", False))
        self.assertIn("2 into develop, 1 into a release branch", found.source)
        self.put_state("pulls.json", [{"headRefName": "feature/%d" % i, "baseRefName": "release/2.0"} for i in range(4)])
        found = gp.infer_closing_mode(self.repo, "acme/widgets", use_gh=True)
        self.assertEqual((found.value, found.sure), ("release", True))
        self.assertIn("merged pull requests", found.source)

    def test_a_remote_tracking_merge_counts_without_the_remote_name(self):
        self.init()
        self.commit("chore: start")
        self.git("branch", "develop")
        for index in range(3):
            self.git("switch", "-q", "-c", "feature/r%d" % index, "main")
            self.commit("feat: r%d" % index)
            self.merge("feature/r%d" % index, "develop",
                       "Merge remote-tracking branch 'origin/feature/r%d' into develop" % index)
        self.assertEqual(gp.infer_closing_mode(self.repo, None, use_gh=False).value, "develop")

    def test_a_new_project_has_only_a_guess(self):
        self.init()
        found = gp.infer_closing_mode(self.repo, None, use_gh=False)
        self.assertEqual((found.value, found.sure), ("develop", False))
        self.assertIn("new project", found.source)


class Resolve(GitCase):
    def test_without_a_terminal_what_is_missing_is_named(self):
        self.init()
        result = gp.resolve(self.repo, None, None, None, interactive=False, allow_new_board=False, use_gh=False)
        self.assertEqual(result.settings_state, "absent")
        self.assertEqual(result.repository.value, "acme/widgets")
        self.assertEqual(sorted(k for k, _ in result.needs), ["board", "closing_mode"])
        self.assertIsNone(result.closing_mode.value)

    def test_flags_complete_what_inference_cannot(self):
        self.init()
        result = gp.resolve(self.repo, None, "none", "release", interactive=False, allow_new_board=False, use_gh=False)
        self.assertEqual((result.needs, result.board.value, result.closing_mode.value), ([], "none", "release"))

    def test_the_one_linked_board_is_used_and_two_are_not_guessed_between(self):
        self.init()
        self.put_state("linked.json", [{"owner": "acme", "number": 4, "title": "Widgets"}])
        result = gp.resolve(self.repo, None, None, "develop", interactive=False, allow_new_board=False, use_gh=True)
        self.assertEqual(result.board.value, "acme/4")
        self.put_state("linked.json", [{"owner": "acme", "number": 4, "title": "A"}, {"owner": "acme", "number": 5,
                                                                                       "title": "B"}])
        result = gp.resolve(self.repo, None, None, "develop", interactive=False, allow_new_board=False, use_gh=True)
        self.assertIsNone(result.board.value)
        self.assertEqual(result.board.choices, ["acme/4  A", "acme/5  B"])

    def test_the_board_mapping_file_names_the_board(self):
        self.init()
        os.makedirs(os.path.join(self.repo, ".github"))
        with open(os.path.join(self.repo, ".github", "project-board.json"), "w", encoding="utf-8") as handle:
            json.dump({"project": {"owner": "acme", "number": 7}}, handle)
        result = gp.resolve(self.repo, None, None, "develop", interactive=False, allow_new_board=False, use_gh=False)
        self.assertEqual(result.board.value, "acme/7")

    def test_a_flag_that_disagrees_with_the_file_is_a_conflict(self):
        self.init()
        self.write_settings()
        result = gp.resolve(self.repo, "other/x", "acme/3", "release", interactive=False, allow_new_board=False,
                            use_gh=False)
        self.assertEqual(sorted(k for k, _ in result.conflicts), ["closing_mode", "repository"])
        result = gp.resolve(self.repo, "ACME/Widgets", None, None, interactive=False, allow_new_board=False,
                            use_gh=False)
        self.assertEqual(result.conflicts, [])

    def test_an_invalid_file_is_named_and_not_replaced(self):
        self.init()
        os.makedirs(os.path.join(self.repo, ".factory"))
        with open(os.path.join(self.repo, gp.SETTINGS_REL), "w", encoding="utf-8") as handle:
            handle.write("{")
        result = gp.resolve(self.repo, None, None, None, interactive=False, allow_new_board=False, use_gh=False)
        self.assertEqual(result.settings_state, "invalid")
        state, _ = gp.write(self.repo, "acme/widgets", "none", "develop", check_only=False)
        self.assertEqual(state, "NEEDS")

    def test_questions_on_the_terminal(self):
        self.init()
        os.environ["FACTORY_PROMPT_TTY"] = self.answers("", "not a board", "acme/12", "3", "2")
        terminal = gp.Terminal.open()
        assert terminal is not None
        terminal.writer = io.StringIO()
        result = gp.resolve(self.repo, None, None, None, interactive=True, allow_new_board=True, use_gh=False,
                            terminal=terminal)
        self.assertEqual(result.needs, [])
        self.assertEqual((result.repository.value, result.board.value, result.closing_mode.value),
                         ("acme/widgets", "acme/12", "release"))
        self.assertIn("confirmed", result.repository.source)
        asked = terminal.writer.getvalue()
        self.assertIn("GitHub repository (OWNER/NAME) [acme/widgets]", asked)
        self.assertIn("Write OWNER/NUMBER", asked)
        self.assertIn("Answer 1 or 2", asked)

    def test_a_new_folder_is_offered_git_init(self):
        os.environ["FACTORY_PROMPT_TTY"] = self.answers("yes", "acme/widgets", "none", "")
        result = gp.resolve(self.repo, None, None, None, interactive=True, allow_new_board=False, use_gh=False)
        self.assertTrue(result.created_repository)
        self.assertEqual(self.git("symbolic-ref", "HEAD").stdout.strip(), "refs/heads/main")
        self.assertEqual((result.repository.value, result.board.value, result.closing_mode.value),
                         ("acme/widgets", "none", "develop"))
        os.environ["FACTORY_PROMPT_TTY"] = self.answers("no")
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        self.assertEqual(gp.resolve(other, None, None, None, True, False, False).settings_state, "not-git")

    def test_running_out_of_answers_stops_without_writing(self):
        self.init()
        os.environ["FACTORY_PROMPT_TTY"] = self.answers("")
        with self.assertRaises(EOFError):
            gp.resolve(self.repo, None, None, None, interactive=True, allow_new_board=False, use_gh=False)


class Write(GitCase):
    def test_written_once_then_present_and_edits_by_hand_are_kept(self):
        self.init()
        state, detail = gp.write(self.repo, "acme/widgets", "acme/3", "develop", check_only=False)
        self.assertEqual(state, "ADDED", detail)
        self.assertEqual(gp.write(self.repo, "acme/widgets", "acme/3", "develop", check_only=False)[0], "PRESENT")
        path = os.path.join(self.repo, gp.SETTINGS_REL)
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
        doc["commits"]["types"].append("wip")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(doc, handle)
        self.assertEqual(gp.write(self.repo, "acme/widgets", "none", "release", check_only=False)[0], "UPDATED")
        kept = gp.load_settings(path)
        self.assertIn("wip", kept.types)
        self.assertEqual((kept.board, kept.closing_mode), (None, "release"))

    def test_check_writes_nothing(self):
        self.init()
        self.assertEqual(gp.write(self.repo, "acme/widgets", "none", "develop", check_only=True)[0], "WOULD_ADD")
        self.assertFalse(os.path.exists(os.path.join(self.repo, ".factory")))

    def test_a_link_is_not_written_through(self):
        self.init()
        elsewhere = os.path.join(self.tmp, "elsewhere")
        os.makedirs(elsewhere)
        os.symlink(elsewhere, os.path.join(self.repo, ".factory"))
        self.assertEqual(gp.write(self.repo, "acme/widgets", "none", "develop", check_only=False)[0], "BLOCKED")
        self.assertEqual(os.listdir(elsewhere), [])

    def test_the_main_branch_is_master_when_the_project_uses_master(self):
        self.git("init", "-q", "-b", "master")
        self.commit("chore: start")
        gp.write(self.repo, "acme/widgets", "none", "develop", check_only=False)
        self.assertEqual(gp.load_settings(os.path.join(self.repo, gp.SETTINGS_REL)).main_branch, "master")


class Hooks(GitCase):
    def setUp(self):
        super().setUp()
        self.init()
        self.install_hooks()
        self.write_settings()

    def try_commit(self, message, **kwargs):
        return self.commit(message, verify=True, check=False, **kwargs)

    def test_the_first_commit_on_main_is_allowed_and_later_ones_are_not(self):
        done = self.try_commit("chore: set up the project")
        self.assertEqual(done.returncode, 0, done.stderr)
        done = self.try_commit("fix: a direct change")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("do not commit on main directly", done.stderr)
        self.assertIn("git switch -c hotfix/NAME", done.stderr)

    def test_messages_on_a_feature_branch(self):
        self.commit("chore: start")
        self.git("switch", "-q", "-c", "develop")
        self.git("switch", "-q", "-c", "feature/login")
        done = self.try_commit("added login")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("does not follow Conventional Commits", done.stderr)
        self.assertEqual(self.try_commit("feat(auth): add the login form").returncode, 0)
        self.assertEqual(self.try_commit("fixup! feat(auth): add the login form").returncode, 0)

    def test_develop_takes_merges_and_refuses_direct_commits(self):
        self.commit("chore: start")
        self.git("switch", "-q", "-c", "develop")
        self.git("switch", "-q", "-c", "feature/login")
        self.commit("feat: add the login form")
        self.git("switch", "-q", "develop")
        self.assertIn("do not commit on develop directly", self.try_commit("feat: direct").stderr)
        done = self.git("merge", "--no-ff", "feature/login", "-m", "Merge branch 'feature/login' into develop",
                        check=False)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_branch_that_is_not_a_gitflow_name_is_refused(self):
        self.commit("chore: start")
        self.git("switch", "-q", "-c", "wip")
        done = self.try_commit("feat: x")
        self.assertIn("not a gitflow branch name", done.stderr)
        self.assertIn("git branch -m feature/NAME", done.stderr)

    def test_missing_settings_without_a_terminal_stop_the_commit_with_the_way_out(self):
        os.remove(os.path.join(self.repo, gp.SETTINGS_REL))
        done = self.try_commit("chore: start")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("python3 .github/scripts/git_policy.py configure", done.stderr)

    def test_missing_settings_are_asked_for_in_the_hook(self):
        os.remove(os.path.join(self.repo, gp.SETTINGS_REL))
        answers = self.answers("", "none", "1")
        done = self.try_commit("chore: start", env={"FACTORY_GIT_POLICY_NO_PROMPT": "", "FACTORY_PROMPT_TTY": answers})
        self.assertEqual(done.returncode, 0, done.stderr)
        written = gp.load_settings(os.path.join(self.repo, gp.SETTINGS_REL))
        self.assertEqual((written.repository, written.board, written.closing_mode), ("acme/widgets", None, "develop"))

    def test_pre_push_checks_names_and_new_commits(self):
        bare = os.path.join(self.tmp, "remote.git")
        self.git("init", "-q", "--bare", bare, cwd=self.tmp)
        self.git("remote", "set-url", "origin", bare)
        self.commit("Initial commit")  # a root commit comes before any policy
        self.assertEqual(self.git("push", "-q", "origin", "main", check=False).returncode, 0)
        self.git("switch", "-q", "-c", "feature/login")
        self.commit("feat: add the login form")
        self.commit("added a test")  # made with --no-verify
        done = self.git("push", "-q", "origin", "feature/login", check=False)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("added a test", done.stderr)
        self.assertNotIn("add the login form:", done.stderr)
        self.git("reset", "-q", "--hard", "HEAD~1")
        self.assertEqual(self.git("push", "-q", "origin", "feature/login", check=False).returncode, 0)
        self.commit("test: cover the login form")
        self.git("branch", "wip")
        done = self.git("push", "-q", "origin", "wip", check=False)
        self.assertIn("not a gitflow branch name", done.stderr)
        self.assertEqual(self.git("push", "-q", "origin", "feature/login", check=False).returncode, 0)


class PullRequests(GitCase):
    def setUp(self):
        super().setUp()
        self.init()
        self.write_settings()
        self.commit("chore: start")
        self.git("switch", "-q", "-c", "develop")
        self.base = self.sha()

    def sha(self, ref="HEAD"):
        return self.git("rev-parse", ref).stdout.strip()

    def check(self, head_ref, base_ref="develop", title="feat: add the login form", env=None):
        out = io.StringIO()
        old = dict(os.environ)
        os.environ.update(env or {})
        try:
            code = gp.check_pr(os.path.join(self.repo, gp.SETTINGS_REL), self.repo, base_ref, head_ref, self.base,
                               self.sha(), title, out)
        finally:
            os.environ.clear()
            os.environ.update(old)
        return code, out.getvalue()

    def test_a_good_pull_request_passes_with_a_merge_from_develop_inside(self):
        self.git("switch", "-q", "-c", "feature/login")
        self.commit("feat: add the login form")
        self.git("switch", "-q", "develop")
        self.commit("chore: something else")
        self.git("switch", "-q", "feature/login")
        self.git("merge", "-q", "--no-ff", "--no-verify", "develop", "-m", "Merge branch 'develop' into feature/login")
        code, out = self.check("feature/login")
        self.assertEqual(code, 0, out)
        self.assertIn("PASS feature/login -> develop", out)

    def test_each_failure_is_reported(self):
        self.git("switch", "-q", "-c", "feature/login")
        self.commit("feat: add the login form")
        self.commit("oops")
        self.commit("fixup! feat: add the login form")
        code, out = self.check("feature/login", base_ref="main", title="Login form")
        self.assertEqual(code, 1)
        self.assertIn("FAIL gitflow: 'feature/login' may close into develop, not into 'main'", out)
        self.assertIn("FAIL title: the pull request title: the first line must look like", out)
        self.assertIn("oops", out)
        self.assertIn("must be squashed", out)

    def test_annotations_on_github_and_no_title(self):
        self.git("switch", "-q", "-c", "feature/login")
        self.commit("feat: add the login form")
        code, out = self.check("feature/login", title="", env={"GITHUB_ACTIONS": "true"})
        self.assertEqual(code, 1)
        self.assertIn("::error title=git policy (title)::the pull request has no title", out)

    def test_missing_settings_fail_with_the_way_out(self):
        out = io.StringIO()
        code = gp.check_pr(os.path.join(self.tmp, "none.json"), self.repo, "develop", "feature/x", self.base, self.base,
                           "feat: x", out)
        self.assertEqual(code, 1)
        self.assertIn("does not exist on the base branch", out.getvalue())

    def test_the_command_line(self):
        self.git("switch", "-q", "-c", "feature/login")
        self.commit("feat: add the login form")
        done = subprocess.run([sys.executable, "-I", POLICY, "check-pr", "--settings",
                               os.path.join(self.repo, gp.SETTINGS_REL), "--checkout", self.repo, "--base-ref", "develop",
                               "--head-ref", "feature/login", "--base-sha", self.base, "--head-sha", self.sha()],
                              capture_output=True, text=True, env=dict(self.env, PR_TITLE="feat: add the login form"))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        done = subprocess.run([sys.executable, "-I", POLICY, "check-pr", "--settings", "x", "--checkout", self.repo,
                               "--base-ref", "develop", "--head-ref", "feature/login", "--base-sha", "HEAD",
                               "--head-sha", "HEAD", "--title", "feat: x"], capture_output=True, text=True, env=self.env)
        self.assertNotEqual(done.returncode, 0)


class CommandLine(GitCase):
    def run_policy(self, *args, stdin=None):
        done = subprocess.run([sys.executable, "-I", POLICY, *args], capture_output=True, text=True, env=self.env,
                              input=stdin, cwd=self.repo)
        return done.returncode, done.stdout + done.stderr

    def test_resolve_prints_no_empty_field(self):
        self.init()
        code, out = self.run_policy("resolve", "--checkout", self.repo, "--no-gh")
        self.assertEqual(code, 0, out)
        for line in out.splitlines():
            self.assertNotIn("\t\t", line)
            self.assertFalse(line.endswith("\t"), line)

    def test_configure_without_a_terminal_names_what_is_missing(self):
        self.init()
        code, out = self.run_policy("configure", "--non-interactive")
        self.assertEqual(code, 3, out)
        self.assertIn("--gitflow-mode", out)
        code, out = self.run_policy("configure", "--non-interactive", "--board", "none", "--closing-mode", "develop")
        self.assertEqual(code, 0, out)
        self.assertIn("ADDED", out)

    def test_check_message_and_check_settings(self):
        self.init()
        self.assertEqual(self.run_policy("check-message", stdin="feat: x\n")[0], 0)
        self.assertEqual(self.run_policy("check-message", stdin="nope\n")[0], 1)
        self.assertEqual(self.run_policy("check-settings")[0], 3)
        self.write_settings()
        self.assertEqual(self.run_policy("check-settings")[0], 0)

    def test_wrong_arguments(self):
        self.assertEqual(self.run_policy("write", "--repo", "acme", "--board", "none", "--closing-mode", "develop")[0], 2)
        self.assertEqual(self.run_policy("resolve", "--board", "new:acme")[0], 2)


class HookFiles(unittest.TestCase):
    def test_every_hook_is_executable_and_calls_the_policy(self):
        names = sorted(os.listdir(HOOKS))
        self.assertEqual(names, ["commit-msg", "pre-commit", "pre-push"])
        for name in names:
            path = os.path.join(HOOKS, name)
            self.assertTrue(os.stat(path).st_mode & stat.S_IXUSR, name)
            with open(path, encoding="utf-8") as handle:
                self.assertIn('"$policy" hook %s' % name, handle.read())


if __name__ == "__main__":
    unittest.main(verbosity=1)
