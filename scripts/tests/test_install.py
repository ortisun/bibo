#!/usr/bin/env python3
"""Tests for scripts/install.sh (ADR 0016). Standard library only. Run it with:
    python3 -I scripts/tests/test_install.py

The script runs for real, under the system bash (3.2 on macOS), but `claude` and `gh` are replaced by small fakes
that put their state in a temporary folder and log every call. Nothing touches the network, the real Claude Code
configuration or any GitHub repository. Each test builds a correct situation, shows the outcome, then changes one
thing and shows that the outcome changes.
"""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
INSTALL = os.path.join(ROOT, "scripts", "install.sh")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else "bash"
DUMMY_TOKEN = "dummy-value-that-is-not-a-secret-4242"

FAKE_CLAUDE = r'''#!/usr/bin/env python3
import json, os, sys
state = os.environ["FAKE_STATE"]
def path(name): return os.path.join(state, name)
def load(name, default):
    try:
        with open(path(name), encoding="utf-8") as h: return json.load(h)
    except FileNotFoundError: return default
def save(name, value):
    with open(path(name), "w", encoding="utf-8") as h: json.dump(value, h)
args = sys.argv[1:]
with open(path("calls.log"), "a", encoding="utf-8") as log: log.write("claude " + " ".join(args) + "\n")
fail = os.environ.get("FAKE_FAIL", "")
if args[:1] == ["--version"]:
    print(os.environ.get("FAKE_CLAUDE_VERSION", "2.1.316") + " (Claude Code)")
elif args[:2] == ["plugin", "list"]:
    print(json.dumps(load("plugins.json", [])))
elif args[:3] == ["plugin", "marketplace", "list"]:
    print(json.dumps(load("marketplaces.json", [])))
elif args[:3] == ["plugin", "marketplace", "add"]:
    if fail == "marketplace_add": sys.exit(1)
    save("marketplaces.json", load("marketplaces.json", []) + [{"name": "egm", "repo": args[3]}])
elif args[:2] == ["plugin", "install"]:
    if fail == "install": sys.exit(1)
    save("plugins.json", load("plugins.json", []) + [{"id": args[2], "version": "0.1.0", "enabled": True}])
elif args[:2] == ["plugin", "enable"]:
    if fail == "enable": sys.exit(1)
    save("plugins.json", [dict(p, enabled=True) if p["id"] == args[2] else p for p in load("plugins.json", [])])
else:
    sys.exit(64)
'''

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
state = os.environ["FAKE_STATE"]
def path(name): return os.path.join(state, name)
def load(name, default):
    try:
        with open(path(name), encoding="utf-8") as h: return json.load(h)
    except FileNotFoundError: return default
args = sys.argv[1:]
with open(path("calls.log"), "a", encoding="utf-8") as log: log.write("gh " + " ".join(args) + "\n")
if args[:2] == ["label", "list"]:
    if os.environ.get("FAKE_FAIL") == "gh_list": sys.exit(1)
    print(json.dumps(load("labels.json", [])))
elif args[:2] == ["label", "create"]:
    name = args[2]
    opts = dict(zip(args[3::2], args[4::2]))
    labels = [l for l in load("labels.json", []) if l["name"].lower() != name.lower()]
    labels.append({"name": name, "color": opts["--color"], "description": opts["--description"]})
    with open(path("labels.json"), "w", encoding="utf-8") as h: json.dump(labels, h)
else:
    sys.exit(64)
'''


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.state = os.path.join(self.tmp, "state")
        self.bin = os.path.join(self.tmp, "bin")
        self.project = os.path.join(self.tmp, "project")
        for folder in (self.state, self.bin, self.project):
            os.makedirs(folder)
        write_executable(os.path.join(self.bin, "claude"), FAKE_CLAUDE)
        write_executable(os.path.join(self.bin, "gh"), FAKE_GH)

    # -- helpers -----------------------------------------------------------------------------
    def run_install(self, *args, env=None, with_claude=True, with_gh=True, token=None):
        if not with_claude:
            os.remove(os.path.join(self.bin, "claude"))
        if not with_gh:
            os.remove(os.path.join(self.bin, "gh"))
        environment = {"PATH": self.bin + ":/usr/bin:/bin", "FAKE_STATE": self.state, "HOME": self.tmp}
        if token:
            environment["FACTORY_GITHUB_MCP_TOKEN"] = token
        environment.update(env or {})
        done = subprocess.run([BASH, INSTALL, *args], capture_output=True, text=True, env=environment)
        return done.returncode, done.stdout + done.stderr

    def has(self, out, state, step, detail=""):
        """True when a report line has this state and step (and detail), whatever the column padding."""
        return re.search(r"(?m)^\s*%s\s+%s\s+%s" % (re.escape(state), re.escape(step), re.escape(detail)), out) is not None

    def calls(self):
        try:
            with open(os.path.join(self.state, "calls.log"), encoding="utf-8") as handle:
                return handle.read().splitlines()
        except FileNotFoundError:
            return []

    def put_state(self, name, value):
        with open(os.path.join(self.state, name), "w", encoding="utf-8") as handle:
            json.dump(value, handle)

    def read(self, relative):
        with open(os.path.join(self.project, relative), encoding="utf-8") as handle:
            return handle.read()

    def exists(self, relative):
        return os.path.exists(os.path.join(self.project, relative))

    def put_project(self, files):
        for relative, text in files.items():
            path = os.path.join(self.project, relative)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)

    def egm_installed(self, version="0.1.0", enabled=True):
        self.put_state("plugins.json", [{"id": "egm@egm", "version": version, "enabled": enabled}])
        self.put_state("marketplaces.json", [{"name": "egm"}])


class EgmPlugin(Case):
    def test_a_missing_plugin_is_installed_once_and_a_second_run_changes_nothing(self):
        code, out = self.run_install()
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "ADDED", "egm-plugin"), out)
        self.assertEqual([c for c in self.calls() if "marketplace add" in c or "plugin install" in c],
                         ["claude plugin marketplace add google/elephant-goldfish-model", "claude plugin install egm@egm"])
        self.assertIn("Start a new Claude Code session", out)
        before = self.calls()
        code, out = self.run_install()
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "PRESENT", "egm-plugin"), out)
        self.assertEqual([c for c in self.calls()[len(before):] if "install" in c or "add" in c or "enable" in c], [])

    def test_a_marketplace_that_is_already_added_is_not_added_again(self):
        self.put_state("marketplaces.json", [{"name": "egm"}])
        self.run_install()
        self.assertEqual([c for c in self.calls() if "marketplace add" in c], [])
        self.assertTrue(any("plugin install egm@egm" in c for c in self.calls()))

    def test_a_disabled_plugin_is_enabled_not_reinstalled(self):
        self.egm_installed(enabled=False)
        code, out = self.run_install()
        self.assertEqual(code, 0, out)
        self.assertTrue(any(c == "claude plugin enable egm@egm" for c in self.calls()))
        self.assertFalse(any("plugin install" in c for c in self.calls()))

    def test_another_version_is_reported_and_left_alone(self):
        self.egm_installed(version="0.9.0")
        code, out = self.run_install()
        self.assertEqual(code, 0, out)
        self.assertIn("DRIFT", out)
        self.assertIn("0.9.0", out)
        self.assertFalse(any("install" in c or "enable" in c for c in self.calls() if "list" not in c))

    def test_check_changes_nothing_and_says_the_install_is_not_ready(self):
        code, out = self.run_install("--check")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "WOULD_ADD", "egm-plugin"), out)
        self.assertIn("NOT READY", out)
        self.assertFalse(any("install" in c or "add" in c or "enable" in c for c in self.calls() if "list" not in c))

    def test_check_on_a_ready_machine_is_ready(self):
        self.egm_installed()
        code, out = self.run_install("--check")
        self.assertEqual((code, out.rstrip().endswith("READY")), (0, True), out)

    def test_a_claude_older_than_the_minimum_blocks_before_any_change(self):
        code, out = self.run_install(env={"FAKE_CLAUDE_VERSION": "2.1.0"})
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "tools"), out)
        self.assertTrue(self.has(out, "SKIPPED", "egm-plugin"), out)
        self.assertEqual([c for c in self.calls() if "install" in c or "add" in c], [])

    def test_a_missing_claude_blocks(self):
        code, out = self.run_install(with_claude=False)
        self.assertEqual(code, 3, out)
        self.assertIn("Claude Code is not installed", out)

    def test_a_failing_install_is_reported_as_a_failure(self):
        for failure in ("marketplace_add", "install"):
            with self.subTest(failure=failure):
                self.setUp()
                code, out = self.run_install(env={"FAKE_FAIL": failure})
                self.assertEqual(code, 1, out)
                self.assertTrue(self.has(out, "BLOCKED", "egm-plugin"), out)


class Arguments(Case):
    def test_bad_arguments_exit_with_2_and_change_nothing(self):
        for args in (["--nonsense"], ["--repo", "acme/widgets"], ["--checkout"], ["--checkout", "/no/such/folder"],
                     ["--checkout", "{p}", "--repo", "acme"], ["--checkout", "{p}", "--repo", "../x"],
                     ["--checkout", "{p}", "--repo", "acme/widgets/extra"], ["--checkout", "{p}", "--repo", "a b/c"],
                     ["--checkout", "{p}", "--repo", "acme/widgets; touch pwned"]):
            with self.subTest(args=args):
                code, out = self.run_install(*[a.replace("{p}", self.project) for a in args])
                self.assertEqual(code, 2, out)
                self.assertEqual(self.calls(), [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "pwned")))

    def test_help_prints_the_header_and_exits_cleanly(self):
        code, out = self.run_install("--help")
        self.assertEqual(code, 0)
        self.assertIn("OBJECTIVE", out)
        self.assertIn("DONE WHEN", out)


class ProjectFiles(Case):
    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.put_project({"src/app.py": "print('hi')\n"})

    def install(self, *extra, token: "str | None" = DUMMY_TOKEN):
        return self.run_install("--checkout", self.project, *extra, token=token)

    def test_the_workflow_files_and_the_mcp_entry_are_added(self):
        code, out = self.install()
        self.assertTrue(self.has(out, "ADDED", "workflow-files"), out)
        for relative in (".github/issue-workflow.json", ".github/scripts/issue_workflow.py",
                         ".github/workflows/issue-workflow.yml", ".github/ISSUE_TEMPLATE/new-solution.yml",
                         ".github/ISSUE_TEMPLATE/change-request.yml", ".github/ISSUE_TEMPLATE/config.yml"):
            self.assertTrue(self.exists(relative), relative)
        entry = json.loads(self.read(".mcp.json"))["mcpServers"]["github"]
        self.assertEqual(entry["headers"]["Authorization"], "Bearer ${FACTORY_GITHUB_MCP_TOKEN}")
        self.assertEqual(entry["url"], "https://api.githubcopilot.com/mcp/")
        self.assertEqual(code, 3, "the project is not mapped yet, so the install is not ready")

    def test_the_token_value_is_never_printed_or_written(self):
        _, out = self.install()
        self.assertNotIn(DUMMY_TOKEN, out)
        for folder, _, files in os.walk(self.project):
            for name in files:
                with open(os.path.join(folder, name), encoding="utf-8", errors="replace") as handle:
                    self.assertNotIn(DUMMY_TOKEN, handle.read(), os.path.join(folder, name))
        self.assertNotIn(DUMMY_TOKEN, "\n".join(self.calls()))

    def test_an_unset_token_is_asked_for_and_a_set_one_is_not(self):
        _, out = self.install(token=None)
        self.assertTrue(self.has(out, "NEEDS", "github-token"), out)
        self.setUp()
        self.egm_installed()
        self.put_project({"src/app.py": "x=1\n"})
        _, out = self.install(token=DUMMY_TOKEN)
        self.assertNotIn("github-token", out)

    def test_other_servers_in_mcp_json_are_kept(self):
        self.put_project({".mcp.json": json.dumps({"mcpServers": {"docs": {"type": "http", "url": "https://example.com/mcp"}}})})
        self.install()
        servers = json.loads(self.read(".mcp.json"))["mcpServers"]
        self.assertEqual(sorted(servers), ["docs", "github"])

    def test_no_mcp_skips_the_entry(self):
        self.install("--no-mcp")
        self.assertFalse(self.exists(".mcp.json"))

    def test_a_token_written_in_mcp_json_is_flagged_without_showing_it_and_kept_until_update(self):
        leaked = "ghp_" + "A" * 36
        self.put_project({".mcp.json": json.dumps({"mcpServers": {"github": {
            "type": "http", "url": "https://api.githubcopilot.com/mcp/", "headers": {"Authorization": "Bearer " + leaked}}}})})
        _, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "github-mcp"), out)
        self.assertIn("may be a token", out)
        self.assertNotIn(leaked, out)
        self.assertIn(leaked, self.read(".mcp.json"), "without --update the file is kept")
        _, out = self.install("--update")
        self.assertNotIn(leaked, self.read(".mcp.json"))
        self.assertNotIn(leaked, out)

    def test_a_changed_file_is_kept_and_reported_until_update(self):
        self.install()
        path = os.path.join(self.project, ".github", "workflows", "issue-workflow.yml")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("# local edit\n")
        _, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "workflow-files", ".github/workflows/issue-workflow.yml"), out)
        self.assertIn("# local edit", self.read(".github/workflows/issue-workflow.yml"))
        _, out = self.install("--update")
        self.assertNotIn("# local edit", self.read(".github/workflows/issue-workflow.yml"))
        self.assertTrue(self.has(out, "UPDATED", "workflow-files"), out)

    def test_installing_twice_changes_no_file(self):
        self.install()
        snapshot = {}
        for folder, _, files in os.walk(self.project):
            for name in files:
                path = os.path.join(folder, name)
                snapshot[path] = (os.stat(path).st_mtime_ns, read_bytes(path))
        _, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "workflow-files"), out)
        for path, (mtime, content) in snapshot.items():
            self.assertEqual((os.stat(path).st_mtime_ns, read_bytes(path)), (mtime, content), path)

    def test_check_writes_no_file(self):
        code, out = self.install("--check")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "WOULD_ADD", "workflow-files"), out)
        self.assertEqual(sorted(os.listdir(self.project)), ["src"])

    def test_the_copied_helper_is_the_factorys_helper(self):
        self.install()
        self.assertEqual(read_bytes(os.path.join(self.project, ".github", "scripts", "issue_workflow.py")),
                         read_bytes(os.path.join(ROOT, "scripts", "lib", "issue_workflow.py")))


class ProjectMap(Case):
    def setUp(self):
        super().setUp()
        self.egm_installed()

    def test_an_unmapped_project_is_not_ready_and_a_mapped_one_is(self):
        self.put_project({"src/app.py": "x=1\n"})
        code, out = self.run_install("--checkout", self.project, token=DUMMY_TOKEN)
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "project-map"), out)
        self.assertIn("MISSING .", out)
        self.assertIn("/egm:egm-bootstrap", out)
        self.put_project({"README.md": "# project\n", "src/EGM.md": "# src\n"})
        code, out = self.run_install("--checkout", self.project, token=DUMMY_TOKEN)
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "PRESENT", "project-map"), out)
        self.assertTrue(out.rstrip().endswith("READY"), out)

    def test_generated_files_that_are_not_committed_keep_the_install_not_ready(self):
        self.put_project({"README.md": "# project\n", "src/app.py": "x=1\n", "src/README.md": "# src\n"})
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@example.com"}
        for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "start"]):
            subprocess.run(["git", "-C", self.project, *command], check=True, env={**os.environ, **env})
        head = subprocess.run(["git", "-C", self.project, "rev-parse", "HEAD"], capture_output=True, text=True).stdout
        code, out = self.run_install("--checkout", self.project, token=DUMMY_TOKEN)
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "uncommitted"), out)
        after = subprocess.run(["git", "-C", self.project, "rev-parse", "HEAD"], capture_output=True, text=True).stdout
        self.assertEqual(head, after, "the installer never commits")
        log = subprocess.run(["git", "-C", self.project, "log", "--oneline"], capture_output=True, text=True).stdout
        self.assertEqual(len(log.splitlines()), 1)
        subprocess.run(["git", "-C", self.project, "add", "."], check=True)
        subprocess.run(["git", "-C", self.project, "commit", "-q", "-m", "install"], check=True, env={**os.environ, **env})
        code, out = self.run_install("--checkout", self.project, token=DUMMY_TOKEN)
        self.assertEqual(code, 0, out)


class Labels(Case):
    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.put_project({"README.md": "# p\n"})

    def labels(self, *extra, **kw):
        return self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--no-mcp", *extra, **kw)

    def created(self):
        return [c for c in self.calls() if c.startswith("gh label create")]

    def test_every_workflow_label_is_created_once(self):
        code, out = self.labels()
        self.assertTrue(self.has(out, "ADDED", "labels"), out)
        created = self.created()
        self.assertEqual(len(created), 15)
        self.assertTrue(all(c.endswith("--repo acme/widgets --force") for c in created))
        names = [c.split(" --color")[0][len("gh label create "):] for c in created]
        self.assertIn("factory", names)
        self.assertIn("design: approved", names)
        self.assertIn("factory: waiting for a person", names)
        before = len(self.created())
        _, out = self.labels()
        self.assertTrue(self.has(out, "PRESENT", "labels"), out)
        self.assertEqual(len(self.created()), before)

    def test_only_the_missing_or_wrong_labels_are_touched(self):
        self.labels()
        with open(os.path.join(self.state, "labels.json"), encoding="utf-8") as handle:
            stored = json.load(handle)
        stored = [dict(l, color="000000") if l["name"] == "design: approved" else l for l in stored if l["name"] != "factory: done"]
        self.put_state("labels.json", stored)
        before = len(self.created())
        _, out = self.labels()
        fixed = [c.split(" --color")[0][len("gh label create "):] for c in self.created()[before:]]
        self.assertEqual(sorted(fixed), ["design: approved", "factory: done"])
        self.assertIn("2 label(s)", out)

    def test_check_creates_no_label(self):
        code, out = self.labels("--check")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "WOULD_ADD", "labels"), out)
        self.assertEqual(self.created(), [])

    def test_labels_need_gh_and_a_signed_in_account(self):
        code, out = self.labels(with_gh=False)
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "labels"), out)
        self.setUp()
        self.egm_installed()
        self.put_project({"README.md": "# p\n"})
        code, out = self.labels(env={"FAKE_FAIL": "gh_list"})
        self.assertEqual(code, 3, out)
        self.assertIn("could not list the labels", out)
        self.assertEqual(self.created(), [])

    def test_no_repo_means_no_github_call(self):
        self.run_install("--checkout", self.project, "--no-mcp")
        self.assertFalse(any(c.startswith("gh ") for c in self.calls()))


if __name__ == "__main__":
    unittest.main()
