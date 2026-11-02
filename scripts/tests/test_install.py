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
def save(name, value):
    with open(path(name), "w", encoding="utf-8") as h: json.dump(value, h)
args = sys.argv[1:]
with open(path("calls.log"), "a", encoding="utf-8") as log: log.write("gh " + " ".join(args) + "\n")
fail = os.environ.get("FAKE_FAIL", "")
def flag(name):
    return args[args.index(name) + 1] if name in args else ""
if args[:2] == ["label", "list"]:
    if fail == "gh_list": sys.exit(1)
    print(json.dumps(load("labels.json", [])))
elif args[:2] == ["label", "create"]:
    name = args[2]
    opts = dict(zip(args[3::2], args[4::2]))
    labels = [l for l in load("labels.json", []) if l["name"].lower() != name.lower()]
    labels.append({"name": name, "color": opts["--color"], "description": opts["--description"]})
    save("labels.json", labels)
elif args[:2] == ["api", "graphql"]:
    query = next(a for a in args if a.startswith("query="))
    if fail == "graphql": sys.exit(1)
    if "repositoryOwner" in query:
        kinds = load("owner_types.json", {})
        login = next(a[2:] for a in args if a.startswith("o="))
        print(json.dumps({"data": {"repositoryOwner": {"__typename": kinds.get(login, "Organization")}}}))
    elif "projectsV2" in query:
        nodes = [{"number": p["number"], "title": p["title"], "closed": p.get("closed", False),
                  "owner": {"__typename": "Organization", "login": p["owner"]}} for p in load("linked.json", [])]
        print(json.dumps({"data": {"repository": {"projectsV2": {"nodes": nodes}}}}))
    else:
        sys.exit(64)
elif args[:2] == ["api", "user"]:
    print(json.dumps({"login": "me-user"}))
elif args[:2] == ["project", "field-list"]:
    if fail == "project_read": sys.exit(1)
    fields = load("fields_%s_%s.json" % (flag("--owner"), args[2]), None)
    if fields is None: sys.exit(1)
    print(json.dumps(fields))
elif args[:2] == ["project", "create"]:
    if fail == "project_create": sys.exit(1)
    save("fields_%s_9.json" % flag("--owner"), {"fields": [{"name": "Title", "type": "ProjectV2Field"},
        {"name": "Status", "type": "ProjectV2SingleSelectField", "options": [{"id": "a", "name": "Todo"}, {"id": "b", "name": "In Progress"}, {"id": "c", "name": "Done"}]}], "totalCount": 2})
    print(json.dumps({"number": 9, "title": flag("--title")}))
elif args[:2] == ["project", "link"]:
    pass
elif args[:2] == ["project", "field-create"]:
    key = "fields_%s_%s.json" % (flag("--owner"), args[2])
    fields = load(key, {"fields": []})
    fields["fields"].append({"name": flag("--name"), "type": "ProjectV2SingleSelectField",
        "options": [{"id": str(i), "name": n} for i, n in enumerate(flag("--single-select-options").split(","))]})
    save(key, fields)
    print("{}")
elif args[:2] == ["secret", "list"]:
    if fail == "secret_list": sys.exit(1)
    print(json.dumps([{"name": n} for n in load("secrets.json", [])]))
elif args[:2] == ["variable", "list"]:
    print(json.dumps([{"name": n} for n in load("variables.json", [])]))
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
                         ".github/scripts/project_board.py", ".github/project-board-policy.json",
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
        return self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--no-mcp", "--no-board", *extra, **kw)

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

    def test_the_labels_step_alone_makes_no_project_call(self):
        self.labels()
        self.assertFalse(any(c.startswith("gh project") or "graphql" in c for c in self.calls()))


RICH_FIELDS = {"fields": [{"name": "Title", "type": "ProjectV2Field"},
                          {"name": "Status", "type": "ProjectV2SingleSelectField",
                           "options": [{"id": str(i), "name": n} for i, n in enumerate(
                               ["Backlog", "Design", "Design review", "Ready", "In progress", "Blocked", "In review", "Done", "Cancelled"])]}]}
DEFAULT_FIELDS = {"fields": [{"name": "Status", "type": "ProjectV2SingleSelectField",
                              "options": [{"id": "a", "name": "Todo"}, {"id": "b", "name": "In Progress"}, {"id": "c", "name": "Done"}]}]}
MUTATING = ("gh project create", "gh project link", "gh project field-create", "gh project edit", "gh project field-delete",
            "gh project delete", "gh project item")


class Board(Case):
    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.put_project({"README.md": "# p\n"})
        self.put_state("linked.json", [{"owner": "acme", "number": 7, "title": "Roadmap"}])
        self.put_state("fields_acme_7.json", RICH_FIELDS)
        self.put_state("secrets.json", [])
        self.put_state("variables.json", [])

    def board(self, *extra, **kw):
        return self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--no-mcp", *extra, **kw)

    def mutations(self):
        return [c for c in self.calls() if c.startswith(MUTATING)]

    def config(self):
        return json.loads(self.read(".github/project-board.json"))

    def test_an_existing_board_is_adapted_to_and_none_of_it_is_changed(self):
        _, out = self.board()
        self.assertTrue(self.has(out, "ADDED", "project-board"), out)
        board = self.config()
        self.assertEqual(board["project"], {"owner": "acme", "owner_type": "organization", "number": 7})
        self.assertEqual(board["status_field"], "Status")
        self.assertEqual(board["options"]["idea"], "Backlog")
        self.assertEqual(board["options"]["working"], "In progress")
        self.assertEqual(board["options"]["design_review"], "Design review")
        self.assertEqual(self.mutations(), [], "an existing board is read, never written")

    def test_the_default_three_column_board_still_gets_every_stage(self):
        self.put_state("fields_acme_7.json", DEFAULT_FIELDS)
        _, out = self.board()
        board = self.config()
        self.assertTrue(all(board["options"].values()), board)
        self.assertEqual(board["options"]["idea"], "Todo")
        self.assertEqual(board["options"]["designing"], "In Progress")
        self.assertIn("Board: Idea: no option of its own, shown as 'Todo'", out)
        self.assertEqual(self.mutations(), [])

    def test_a_mapping_that_a_person_edited_is_kept_and_only_checked(self):
        self.board()
        edited = self.config()
        edited["options"]["idea"] = "Ready"
        self.put_project({".github/project-board.json": json.dumps(edited, indent=2, sort_keys=True) + "\n"})
        before = (os.stat(os.path.join(self.project, ".github/project-board.json")).st_mtime_ns, self.read(".github/project-board.json"))
        _, out = self.board()
        self.assertTrue(self.has(out, "PRESENT", "project-board"), out)
        after = (os.stat(os.path.join(self.project, ".github/project-board.json")).st_mtime_ns, self.read(".github/project-board.json"))
        self.assertEqual(before, after)
        self.assertEqual(self.config()["options"]["idea"], "Ready")

    def test_a_board_that_changed_is_reported_and_the_mapping_is_not_rewritten(self):
        self.board()
        text = self.read(".github/project-board.json")
        fields = json.loads(json.dumps(RICH_FIELDS))
        fields["fields"][1]["options"] = [o for o in fields["fields"][1]["options"] if o["name"] != "Blocked"]
        self.put_state("fields_acme_7.json", fields)
        code, out = self.board()
        self.assertTrue(self.has(out, "NEEDS", "project-board"), out)
        self.assertIn("Blocked", out)
        self.assertEqual(code, 3)
        self.assertEqual(self.read(".github/project-board.json"), text)

    def test_no_linked_board_asks_for_a_decision_and_changes_nothing(self):
        self.put_state("linked.json", [])
        code, out = self.board()
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "project-board", "no board is linked"), out)
        self.assertIn("--create-project", out)
        self.assertFalse(self.exists(".github/project-board.json"))
        self.assertEqual(self.mutations(), [])

    def test_several_linked_boards_are_listed_and_not_guessed(self):
        self.put_state("linked.json", [{"owner": "acme", "number": 7, "title": "Roadmap"}, {"owner": "acme", "number": 8, "title": "Bugs"}])
        _, out = self.board()
        self.assertIn("2 boards are linked", out)
        self.assertIn("acme/7  Roadmap", out)
        self.assertIn("acme/8  Bugs", out)
        self.assertFalse(self.exists(".github/project-board.json"))

    def test_a_closed_board_is_not_offered(self):
        self.put_state("linked.json", [{"owner": "acme", "number": 7, "title": "Old", "closed": True}])
        _, out = self.board()
        self.assertIn("no board is linked", out)

    def test_project_names_the_board_and_no_listing_is_needed(self):
        self.put_state("linked.json", [])
        self.put_state("fields_other_3.json", RICH_FIELDS)
        self.put_state("owner_types.json", {"other": "User"})
        self.board("--project", "other/3")
        self.assertEqual(self.config()["project"], {"owner": "other", "owner_type": "user", "number": 3})

    def test_another_field_can_be_chosen_and_a_missing_one_is_refused(self):
        fields = json.loads(json.dumps(RICH_FIELDS))
        fields["fields"].append({"name": "Stage", "type": "ProjectV2SingleSelectField",
                                 "options": [{"id": "z", "name": "Idea"}, {"id": "y", "name": "Done"}]})
        self.put_state("fields_acme_7.json", fields)
        self.board("--board-field", "Stage")
        self.assertEqual(self.config()["status_field"], "Stage")
        self.assertEqual(self.config()["options"]["idea"], "Idea")
        self.setUp()
        _, out = self.board("--board-field", "Nope")
        self.assertTrue(self.has(out, "NEEDS", "project-board"), out)
        self.assertFalse(self.exists(".github/project-board.json"))

    def test_create_project_makes_a_board_with_a_new_field_and_never_touches_status(self):
        self.put_state("linked.json", [])
        code, out = self.board("--create-project", "acme")
        self.assertTrue(self.has(out, "ADDED", "project-board"), out)
        creates = [c for c in self.calls() if c.startswith("gh project field-create")]
        self.assertEqual(len(creates), 1)
        self.assertIn('--name Stage', creates[0])
        self.assertIn("Idea,Designing,Design review,Ready,Working,Needs a person,In review,Done,Stopped", creates[0])
        self.assertTrue(any(c.startswith("gh project link 9 --owner acme --repo acme/widgets") for c in self.calls()))
        board = self.config()
        self.assertEqual((board["status_field"], board["project"]["number"]), ("Stage", 9))
        self.assertEqual(board["options"]["design_review"], "Design review")
        self.assertFalse(any(c.startswith(("gh project edit", "gh project field-delete")) for c in self.calls()))

    def test_check_creates_no_board(self):
        self.put_state("linked.json", [])
        code, out = self.board("--check", "--create-project", "acme")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "WOULD_ADD", "project-board"), out)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.exists(".github/project-board.json"))

    def test_a_failed_board_creation_is_reported(self):
        self.put_state("linked.json", [])
        code, out = self.board("--create-project", "acme", env={"FAKE_FAIL": "project_create"})
        self.assertTrue(self.has(out, "BLOCKED", "project-board"), out)
        self.assertEqual(code, 3)
        self.assertFalse(self.exists(".github/project-board.json"))

    def test_no_board_skips_the_step_and_makes_no_project_call(self):
        self.board("--no-board")
        self.assertFalse(any(c.startswith("gh project") or "graphql" in c for c in self.calls()))
        _, out = self.board("--no-board")
        self.assertTrue(self.has(out, "SKIPPED", "project-board"), out)

    def test_an_unreadable_board_is_blocked_with_the_scope_to_ask_for(self):
        code, out = self.board(env={"FAKE_FAIL": "graphql"})
        self.assertEqual(code, 3, out)
        self.assertIn("gh auth refresh -s project", out)

    def test_the_credential_is_checked_by_name_and_never_read(self):
        _, out = self.board()
        self.assertTrue(self.has(out, "NOTE", "board-credential"), out)
        self.assertIn("gh secret set", out)
        self.setUp()
        self.put_state("secrets.json", ["FACTORY_BOARD_TOKEN"])
        _, out = self.board()
        self.assertTrue(self.has(out, "PRESENT", "board-credential"), out)
        self.setUp()
        self.put_state("secrets.json", ["FACTORY_BOARD_APP_PRIVATE_KEY"])
        self.put_state("variables.json", ["FACTORY_BOARD_CLIENT_ID"])
        _, out = self.board()
        self.assertTrue(self.has(out, "PRESENT", "board-credential"), out)
        self.setUp()
        self.put_state("secrets.json", ["FACTORY_BOARD_APP_PRIVATE_KEY"])
        _, out = self.board()
        self.assertTrue(self.has(out, "NOTE", "board-credential"), "the key without the client id is not a credential")
        self.assertFalse(any(c.startswith(("gh secret set", "gh secret get", "gh variable set")) for c in self.calls()))

    def test_a_missing_credential_does_not_keep_the_install_from_being_ready(self):
        self.put_project({"src/app.py": "x=1\n", "src/README.md": "# s\n"})
        code, out = self.board(token=DUMMY_TOKEN)
        self.assertEqual(code, 0, out)
        self.assertTrue(out.rstrip().endswith("READY"), out)

    def test_bad_board_arguments_exit_with_2(self):
        for args in (["--project", "acme"], ["--project", "acme/x"], ["--project", "acme/7/9"], ["--project", "/7"],
                     ["--project", "ac me/7"], ["--project", "acme/7", "--create-project", "acme"],
                     ["--project", "acme/7", "--no-board"], ["--create-project", "a;b"], ["--create-project", "-x"],
                     ["--board-field", "a;b"], ["--board-field", ""]):
            with self.subTest(args=args):
                code, out = self.run_install("--checkout", self.project, "--repo", "acme/widgets", *args)
                self.assertEqual(code, 2, out)
        code, _ = self.run_install("--checkout", self.project, "--project", "acme/7")
        self.assertEqual(code, 2, "--project goes with --repo")
        self.assertEqual(self.mutations(), [])


if __name__ == "__main__":
    unittest.main()
