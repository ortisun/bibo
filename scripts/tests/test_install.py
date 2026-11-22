#!/usr/bin/env python3
"""Tests for scripts/install.sh (ADR 0016). Standard library only. Run it with:
    python3 -I scripts/tests/test_install.py

The script runs for real, under the system bash (3.2 on macOS), but `claude` and `gh` are replaced by small fakes
that put their state in a temporary folder and log every call. Nothing touches the network, the real Claude Code
configuration or any GitHub repository. Each test builds a correct situation, shows the outcome, then changes one
thing and shows that the outcome changes.
"""
import atexit
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

# Programs that the tests replace with fakes, or remove to show what happens without them. A real copy in /usr/bin
# must not stand in for a removed fake: a GitHub runner, for one, ships a real gh there.
FAKED = {"actionlint", "brew", "cargo", "claude", "codex", "docker", "gh", "gitleaks", "node", "npm", "shellcheck",
         "specify", "uv"}


def system_bin():
    """A folder of links to every program in /usr/bin and /bin except the FAKED ones, used in place of
    "/usr/bin:/bin" on the PATH of a test. Made once per run and removed at exit."""
    folder = tempfile.mkdtemp(prefix="install-test-system-bin-")
    atexit.register(shutil.rmtree, folder, True)
    for source in ("/usr/bin", "/bin"):
        if not os.path.isdir(source):
            continue
        for name in sorted(os.listdir(source)):
            target = os.path.join(folder, name)
            if name in FAKED or os.path.lexists(target):
                continue
            os.symlink(os.path.join(source, name), target)
    return folder


SYSTEM_PATH = system_bin()

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
if os.environ.get("FACTORY_GITHUB_MCP_TOKEN"):
    with open(path("saw_token.log"), "a", encoding="utf-8") as seen: seen.write("claude\n")
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
    save("plugins.json", load("plugins.json", []) + [{"id": args[2], "version": os.environ.get("FAKE_INSTALL_VERSION", "0.1.0"), "enabled": True}])
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
if os.environ.get("FACTORY_GITHUB_MCP_TOKEN"):
    with open(path("saw_token.log"), "a", encoding="utf-8") as seen: seen.write("gh\n")
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
    if fail == "api_user": sys.exit(1)
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
    if fail == "project_link": sys.exit(1)
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
    if fail == "variable_list": sys.exit(1)
    print(json.dumps([{"name": n} for n in load("variables.json", ["FACTORY_BOT_LOGIN"])]))
elif args[:1] == ["api"] and len(args) >= 2 and args[1].startswith("repos/"):
    # The read-only questions about the default branch. review.json says what the host answers.
    review = load("review.json", {})
    path = args[1]
    if "-X" in args or "-f" in args:
        sys.exit(65)  # a write: the installer must never make one here
    if path.count("/") == 2:
        if fail == "repo_read": sys.exit(1)
        branch = review.get("default_branch", "main")
        print(branch if "--jq" in args else json.dumps({"default_branch": branch}))
    elif path.endswith("/rules/branches/main"):
        rules = review.get("rules", [])
        if rules is None:
            print(json.dumps({"message": "Resource not accessible"})); sys.exit(1)
        print(json.dumps(rules))
    elif path.endswith("/branches/main/protection"):
        body = review.get("protection", {"required_pull_request_reviews": {"required_approving_review_count": 1}})
        if body is None:
            print(json.dumps({"message": "Resource not accessible by personal access token"})); sys.exit(1)
        if body == "unprotected":
            print(json.dumps({"message": "Branch not protected"})); sys.exit(1)
        print(json.dumps(body))
    else:
        sys.exit(64)
else:
    sys.exit(64)
'''


FAKE_CODEX = r'''#!/usr/bin/env python3
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
with open(path("calls.log"), "a", encoding="utf-8") as log: log.write("codex " + " ".join(args) + "\n")
if os.environ.get("FACTORY_GITHUB_MCP_TOKEN"):
    with open(path("saw_token.log"), "a", encoding="utf-8") as seen: seen.write("codex\n")
fail = os.environ.get("FAKE_FAIL", "")
if args[:1] == ["--version"]:
    print("codex-cli " + os.environ.get("FAKE_CODEX_VERSION", "0.166.0"))
elif args == ["plugin", "add", "--help"]:
    sys.exit(1 if os.environ.get("FAKE_CODEX_NOPLUGIN") else 0)
elif args[:2] == ["plugin", "list"]:
    print(json.dumps(load("codex_plugins.json", {"installed": [], "available": []})))
elif args[:3] == ["plugin", "marketplace", "list"]:
    print(json.dumps(load("codex_marketplaces.json", {"marketplaces": []})))
elif args[:3] == ["plugin", "marketplace", "add"]:
    if fail == "codex_marketplace_add": sys.exit(1)
    data = load("codex_marketplaces.json", {"marketplaces": []})
    data["marketplaces"].append({"name": "egm", "root": "/x", "marketplaceSource": {"sourceType": "git", "source": args[3]}})
    save("codex_marketplaces.json", data)
elif args[:2] == ["plugin", "add"]:
    if fail == "codex_install": sys.exit(1)
    data = load("codex_plugins.json", {"installed": [], "available": []})
    data["installed"].append({"pluginId": args[2], "name": "egm", "marketplaceName": "egm", "version": os.environ.get("FAKE_INSTALL_VERSION", "0.1.0"), "installed": True, "enabled": True})
    save("codex_plugins.json", data)
else:
    sys.exit(64)
'''

# A fake `specify` that does what Spec Kit 1.1.2 does for `integration install KEY`, offline: it writes the files the
# release writes for KEY (here, copies of the files of this repository, which are the pinned release) and lists KEY in
# .specify/integration.json. FAKE_SPECIFY_TAMPER=1 makes it write a different skill, as another release would.
FAKE_SPECIFY = r'''#!/usr/bin/env python3
import json, os, shutil, sys
state = os.environ["FAKE_STATE"]
source = os.environ["FAKE_SPECKIT_SOURCE"]
args = sys.argv[1:]
with open(os.path.join(state, "calls.log"), "a", encoding="utf-8") as log:
    log.write("specify[%s] %s\n" % ("in project" if os.path.basename(os.getcwd()) == "project" else "elsewhere", " ".join(args)))
for name in ("GH_TOKEN", "GITHUB_TOKEN"):
    if os.environ.get(name):
        with open(os.path.join(state, "saw_token.log"), "a", encoding="utf-8") as seen: seen.write("specify " + name + "\n")
if args[:1] == ["--version"]:
    print("specify " + os.environ.get("FAKE_SPECIFY_VERSION", "1.1.2"))
elif args[:2] == ["integration", "install"] and len(args) == 3:
    if os.environ.get("FAKE_FAIL") == "specify_install":
        print("error: could not install", file=sys.stderr)
        sys.exit(1)
    key = args[2]
    with open(os.path.join(source, ".specify", "integrations", key + ".manifest.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    written = []
    for path in sorted(manifest["files"]):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copyfile(os.path.join(source, path), path)
        written.append(path)
    if os.environ.get("FAKE_SPECIFY_TAMPER"):
        with open(written[0], "a", encoding="utf-8") as handle: handle.write("\nAnother release.\n")
    os.makedirs(os.path.join(".specify", "integrations"), exist_ok=True)
    shutil.copyfile(os.path.join(source, ".specify", "integrations", key + ".manifest.json"),
                    os.path.join(".specify", "integrations", key + ".manifest.json"))
    with open(os.path.join(".specify", "integration.json"), encoding="utf-8") as handle: document = json.load(handle)
    document["installed_integrations"] = sorted(set(document.get("installed_integrations", [])) | {key})
    document.setdefault("integration_settings", {})[key] = {"script": "sh", "invoke_separator": "-"}
    with open(os.path.join(".specify", "integration.json"), "w", encoding="utf-8") as handle: json.dump(document, handle, indent=2)
    print("Integration installed successfully")
else:
    sys.exit(64)
'''


def last_line(out):
    lines = out.rstrip().splitlines()
    return lines[-1] if lines else ""


def is_ready(out):
    """True only for the line READY. "NOT READY" also ends with READY, so a suffix test would pass for it."""
    return last_line(out) == "READY"


def snapshot(root):
    """Every file, folder and link under `root`, with its content or its target: to prove that nothing was written."""
    state = {}
    for folder, directories, files in os.walk(root):
        for name in directories + files:
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, root)
            if os.path.islink(path):
                state[rel] = ("link", os.readlink(path))
            elif os.path.isdir(path):
                state[rel] = ("dir",)
            else:
                state[rel] = ("file", read_bytes(path), os.stat(path).st_mode & 0o777)
    return state


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
    def run_install(self, *args, env=None, with_claude=True, with_gh=True, token=None, shell=(), tools=False, policy=False):
        """tools=False adds --no-tools: the host-tools step has its own tests (HostTools here, test_setup_tools.py).
        policy=False adds --no-git-policy: the settings, git-hooks and gitflow steps have their own tests (GitPolicy here,
        test_git_policy.py). Standard input is never a terminal here, so the installer asks nothing unless a test passes
        --interactive with FACTORY_PROMPT_TTY."""
        if not with_claude:
            os.remove(os.path.join(self.bin, "claude"))
        if not with_gh:
            os.remove(os.path.join(self.bin, "gh"))
        if not tools:
            args = ("--no-tools", *args)
        if not policy:
            args = ("--no-git-policy", *args)
        environment = {"PATH": self.bin + ":" + SYSTEM_PATH, "FAKE_STATE": self.state, "HOME": self.tmp,
                       "FACTORY_TOOLS_PREFIX": os.path.join(self.tmp, "factory-tools")}
        if token:
            environment["FACTORY_GITHUB_MCP_TOKEN"] = token
        environment.update(env or {})
        done = subprocess.run([BASH, *shell, INSTALL, *args], capture_output=True, text=True, env=environment,
                              stdin=subprocess.DEVNULL)
        return done.returncode, done.stdout + done.stderr

    def add_codex(self):
        write_executable(os.path.join(self.bin, "codex"), FAKE_CODEX)

    def remove_claude(self):
        os.remove(os.path.join(self.bin, "claude"))

    def add_claude(self):
        write_executable(os.path.join(self.bin, "claude"), FAKE_CLAUDE)

    def remove_codex(self):
        os.remove(os.path.join(self.bin, "codex"))

    def codex_installed(self, version="0.1.0", enabled=True):
        self.put_state("codex_plugins.json", {"installed": [{"pluginId": "egm@egm", "name": "egm", "version": version,
                                                             "enabled": enabled}], "available": []})
        self.put_state("codex_marketplaces.json", {"marketplaces": [{"name": "egm"}]})

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
        self.assertEqual((code, is_ready(out)), (0, True), out)

    def test_a_claude_older_than_the_minimum_blocks_before_any_change(self):
        code, out = self.run_install(env={"FAKE_CLAUDE_VERSION": "2.1.0"})
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "claude"), out)
        self.assertTrue(self.has(out, "SKIPPED", "egm-plugin"), out)
        self.assertEqual([c for c in self.calls() if "install" in c or "add" in c], [])

    def test_a_missing_claude_blocks(self):
        code, out = self.run_install(with_claude=False)
        self.assertEqual(code, 3, out)
        self.assertIn("no coding agent is installed", out)
        self.assertTrue(self.has(out, "BLOCKED", "agents"), out)
        self.setUp()
        self.remove_claude()
        code, out = self.run_install("--agent", "claude")
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
        self.assertTrue(is_ready(out), out)

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
        self.put_state("variables.json", ["FACTORY_BOT_LOGIN"])

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
        self.put_state("variables.json", ["FACTORY_BOARD_CLIENT_ID", "FACTORY_BOT_LOGIN"])
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
        self.assertTrue(is_ready(out), out)

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


class Agents(Case):
    """Which coding agents the installer prepares: Claude Code, Codex, or both."""

    def mutating(self, agent):
        return [c for c in self.calls() if c.startswith(agent + " plugin") and any(w in c for w in (" add ", " install ", " enable "))
                and "--help" not in c and "list" not in c]

    def test_codex_alone_is_enough_and_gets_the_plugin_once(self):
        self.remove_claude()
        self.add_codex()
        code, out = self.run_install()
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "SKIPPED", "claude"), out)
        self.assertTrue(self.has(out, "ADDED", "egm-plugin", "codex: egm@egm 0.1.0"), out)
        self.assertEqual([c for c in self.calls() if c.startswith("codex plugin") and "marketplace add" in c or " plugin add egm" in c],
                         ["codex plugin marketplace add google/elephant-goldfish-model", "codex plugin add egm@egm"])
        self.assertFalse(any(c.startswith("claude ") and "plugin" in c for c in self.calls()), "Claude Code was not touched")
        self.assertIn("Start a new Codex session", out)
        before = len(self.calls())
        code, out = self.run_install()
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "PRESENT", "egm-plugin", "codex:"), out)
        self.assertEqual([c for c in self.calls()[before:] if " add " in c and "--help" not in c], [],
                         "the second run changed nothing (the --help line is the capability probe)")

    def test_with_both_installed_both_are_prepared(self):
        self.add_codex()
        code, out = self.run_install()
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "ADDED", "egm-plugin", "claude:"), out)
        self.assertTrue(self.has(out, "ADDED", "egm-plugin", "codex:"), out)
        self.assertTrue(self.mutating("claude") and self.mutating("codex"))

    def test_agent_claude_leaves_codex_alone_even_when_it_is_installed(self):
        self.add_codex()
        code, out = self.run_install("--agent", "claude")
        self.assertEqual(code, 0, out)
        self.assertFalse(any(c.startswith("codex") for c in self.calls()), self.calls())
        self.assertNotIn("codex", out.lower().replace("codex.", ""))

    def test_agent_codex_leaves_claude_alone(self):
        self.add_codex()
        code, out = self.run_install("--agent", "codex")
        self.assertEqual(code, 0, out)
        self.assertFalse(any(c.startswith("claude") for c in self.calls()), self.calls())

    def test_an_agent_that_was_asked_for_and_is_missing_blocks(self):
        code, out = self.run_install("--agent", "codex")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "codex"), out)
        self.assertEqual(self.mutating("claude"), [], "nothing was installed for the other agent")
        self.setUp()
        code, out = self.run_install("--agent", "both")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "codex"), out)

    def test_a_codex_without_the_plugin_command_is_blocked_and_not_guessed_at(self):
        self.add_codex()
        code, out = self.run_install("--agent", "codex", env={"FAKE_CODEX_NOPLUGIN": "1"})
        self.assertEqual(code, 3, out)
        self.assertIn("no 'plugin add' command", out)
        self.assertEqual(self.mutating("codex"), [])

    def test_a_disabled_codex_plugin_is_left_to_a_person_because_codex_cannot_enable_it(self):
        self.add_codex()
        self.codex_installed(enabled=False)
        code, out = self.run_install("--agent", "codex")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "egm-plugin", "codex:"), out)
        self.assertIn("no command that enables a plugin", out)
        self.assertEqual(self.mutating("codex"), [])

    def test_another_codex_plugin_version_is_reported_and_kept(self):
        self.add_codex()
        self.codex_installed(version="0.9.0")
        code, out = self.run_install("--agent", "codex")
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "DRIFT", "egm-plugin", "codex:"), out)
        self.assertEqual(self.mutating("codex"), [])

    def test_a_marketplace_that_codex_already_has_is_not_added_again(self):
        self.add_codex()
        self.put_state("codex_marketplaces.json", {"marketplaces": [{"name": "egm"}]})
        self.run_install("--agent", "codex")
        self.assertFalse(any("marketplace add" in c for c in self.calls() if c.startswith("codex")))
        self.assertTrue(any(c == "codex plugin add egm@egm" for c in self.calls()))

    def test_failures_are_reported(self):
        for failure in ("codex_marketplace_add", "codex_install"):
            with self.subTest(failure=failure):
                self.setUp()
                self.add_codex()
                code, out = self.run_install("--agent", "codex", env={"FAKE_FAIL": failure})
                self.assertEqual(code, 1, out)
                self.assertTrue(self.has(out, "BLOCKED", "egm-plugin", "codex:"), out)

    def test_check_changes_nothing_for_codex(self):
        self.add_codex()
        code, out = self.run_install("--check", "--agent", "codex")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "WOULD_ADD", "egm-plugin", "codex:"), out)
        self.assertEqual(self.mutating("codex"), [])

    def test_a_wrong_agent_name_is_a_usage_error(self):
        for value in ("gemini", "", "Claude", "both,codex"):
            with self.subTest(value=value):
                self.assertEqual(self.run_install("--agent", value)[0], 2)
        self.assertEqual(self.run_install("--agent")[0], 2)


class CodexProject(Case):
    """The project files for Codex: the GitHub MCP entry in .codex/config.toml."""

    def setUp(self):
        super().setUp()
        self.remove_claude()
        self.add_codex()
        self.codex_installed()
        self.put_project({"README.md": "# p\n"})

    def install(self, *extra, token="dummy-value-that-is-not-a-secret-4242"):
        return self.run_install("--checkout", self.project, "--no-board", *extra, token=token)

    def test_the_entry_is_added_and_names_the_variable_not_a_token(self):
        code, out = self.install()
        self.assertTrue(self.has(out, "ADDED", "github-mcp", "codex: added"), out)
        text = self.read(".codex/config.toml")
        self.assertIn('bearer_token_env_var = "FACTORY_GITHUB_MCP_TOKEN"', text)
        self.assertIn('"X-MCP-Lockdown" = "true"', text)
        self.assertFalse(self.exists(".mcp.json"), "Claude's file is not written when Claude Code is not prepared")
        self.assertNotIn("dummy-value", text + out)
        self.assertIn("only for a project that you trust", out)

    def test_it_parses_as_toml_and_keeps_what_was_there(self):
        before = '# my settings\nmodel = "o3"\n\n[mcp_servers.docs]\nurl = "https://example.com/mcp"\n'
        self.put_project({".codex/config.toml": before})
        self.install()
        text = self.read(".codex/config.toml")
        self.assertTrue(text.startswith(before))
        try:
            import tomllib
        except ImportError:
            return
        data = tomllib.loads(text)
        self.assertEqual(sorted(data["mcp_servers"]), ["docs", "github"])
        self.assertEqual(data["mcp_servers"]["github"]["bearer_token_env_var"], "FACTORY_GITHUB_MCP_TOKEN")

    def test_a_second_run_changes_nothing(self):
        self.install()
        path = os.path.join(self.project, ".codex", "config.toml")
        before = (os.stat(path).st_mtime_ns, read_bytes(path))
        _, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "github-mcp", "codex:"), out)
        self.assertEqual((os.stat(path).st_mtime_ns, read_bytes(path)), before)

    def test_a_token_in_the_file_is_flagged_without_being_shown_and_kept_until_update(self):
        leaked = "ghp_" + "C" * 36
        self.put_project({".codex/config.toml": '[mcp_servers.github]\nurl = "https://api.githubcopilot.com/mcp/"\nexperimental_bearer_token = "%s"\n' % leaked})
        _, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "github-mcp", "codex:"), out)
        self.assertNotIn(leaked, out)
        self.assertIn(leaked, self.read(".codex/config.toml"))
        _, out = self.install("--update")
        self.assertNotIn(leaked, self.read(".codex/config.toml"))
        self.assertNotIn(leaked, out)
        self.assertIn("rotate", out)

    def test_a_different_entry_is_kept_until_update(self):
        self.put_project({".codex/config.toml": '[mcp_servers.github]\nurl = "https://example.com/mcp"\n'})
        _, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "github-mcp", "codex:"), out)
        self.assertIn("example.com", self.read(".codex/config.toml"))
        self.install("--update")
        self.assertNotIn("example.com", self.read(".codex/config.toml"))

    def test_an_entry_that_runs_a_command_is_never_edited_even_with_update(self):
        text = '[mcp_servers.github]\ncommand = "npx"\nargs = ["some-server"]\n'
        self.put_project({".codex/config.toml": text})
        code, out = self.install("--update")
        self.assertTrue(self.has(out, "DRIFT", "github-mcp", "codex:"), out)
        self.assertEqual(self.read(".codex/config.toml"), text)
        self.assertEqual(code, 3)

    def test_check_and_no_mcp_write_nothing(self):
        code, out = self.install("--check")
        self.assertTrue(self.has(out, "WOULD_ADD", "github-mcp", "codex:"), out)
        self.assertFalse(self.exists(".codex/config.toml"))
        self.install("--no-mcp")
        self.assertFalse(self.exists(".codex/config.toml"))

    def test_both_agents_get_their_own_file_and_one_token_request(self):
        self.setUp()
        self.add_claude()
        self.egm_installed()
        self.put_project({"README.md": "# p\n"})
        _, out = self.run_install("--checkout", self.project, "--no-board", token=None)
        self.assertTrue(self.exists(".mcp.json") and self.exists(".codex/config.toml"))
        self.assertEqual(out.count("NEEDS     github-token"), 1)
        self.assertIn("before you start Claude Code or Codex", out)

    def test_the_mapping_hint_names_the_command_of_each_agent(self):
        self.put_project({"src/app.py": "x=1\n"})
        _, out = self.install()
        self.assertIn("choose the egm-bootstrap skill from the skill list", out)
        self.assertNotIn("/egm:egm-bootstrap", out)
        self.setUp()
        self.add_claude()
        self.remove_codex()
        self.egm_installed()
        self.put_project({"src/app.py": "x=1\n"})
        _, out = self.run_install("--checkout", self.project, "--no-board")
        self.assertIn("/egm:egm-bootstrap", out)
        self.assertNotIn("choose the egm-bootstrap skill", out)

    def test_an_uncommitted_codex_file_keeps_the_install_not_ready(self):
        self.put_project({"README.md": "# p\n", "src/app.py": "x=1\n", "src/README.md": "# s\n"})
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "start"]):
            subprocess.run(["git", "-C", self.project, *command], check=True, env={**os.environ, **env})
        code, out = self.install()
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "uncommitted"), out)
        self.assertTrue(self.exists(".codex/config.toml"))


class CheckWritesNothing(Board):
    """`--check` is promised to change nothing: no file of the project, nothing on GitHub (PL-3)."""

    def test_every_variant_leaves_the_project_exactly_as_it_was(self):
        self.add_codex()
        self.codex_installed()
        self.put_state("fields_other_3.json", RICH_FIELDS)
        self.put_state("owner_types.json", {"other": "User"})
        variants = (["--check"], ["--check", "--project", "other/3"], ["--check", "--create-project", "acme"],
                    ["--check", "--agent", "both"], ["--check", "--agent", "codex"], ["--check", "--no-board"],
                    ["--check", "--no-mcp"], ["--check", "--update"])
        for extra in variants:
            with self.subTest(extra=extra):
                before = snapshot(self.project)
                calls_before = len(self.calls())
                code, out = self.run_install("--checkout", self.project, "--repo", "acme/widgets", *extra)
                self.assertEqual(snapshot(self.project), before, out)
                self.assertEqual([c for c in self.calls()[calls_before:] if c.startswith(MUTATING)], [])
                self.assertEqual([c for c in self.calls()[calls_before:] if c.startswith("gh label create")], [])
                self.assertIn(code, (0, 3), out)

    def test_check_after_a_real_install_still_changes_nothing(self):
        self.board()
        before = snapshot(self.project)
        self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--check", "--update")
        self.assertEqual(snapshot(self.project), before)

    def test_the_board_step_says_what_it_would_write_and_does_not_write_it(self):
        _, out = self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--check", "--no-mcp")
        self.assertTrue(self.has(out, "WOULD_ADD", "project-board", ".github/project-board.json would be written"), out)
        self.assertFalse(self.exists(".github/project-board.json"))


class Links(Case):
    """The installer does not write through a symbolic link of the checkout (PL-4)."""

    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.victim = os.path.join(self.tmp, "victim")
        os.makedirs(self.victim)
        self.put_project({"README.md": "# p\n"})

    def go(self, *extra, agent="claude", token="dummy-value-that-is-not-a-secret-4242"):
        return self.run_install("--checkout", self.project, "--no-board", "--agent", agent, *extra, token=token)

    def victim_state(self):
        return snapshot(self.victim)

    def test_a_link_at_mcp_json_is_not_followed(self):
        outside = os.path.join(self.victim, "claude.json")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write('{"projects": {"/home/me": {"theme": "dark"}}}')
        os.symlink(outside, os.path.join(self.project, ".mcp.json"))
        before = self.victim_state()
        code, out = self.go()
        self.assertEqual(self.victim_state(), before, out)
        self.assertTrue(self.has(out, "BLOCKED", "github-mcp"), out)
        self.assertEqual(code, 3)
        self.assertTrue(os.path.islink(os.path.join(self.project, ".mcp.json")))

    def test_a_link_at_the_codex_folder_is_not_followed(self):
        self.remove_claude()
        self.add_codex()
        self.codex_installed()
        os.makedirs(os.path.join(self.victim, "codex"))
        outside = os.path.join(self.victim, "codex", "config.toml")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("# my settings\n[tui]\ntheme = 1\n")
        os.chmod(outside, 0o644)
        os.symlink(os.path.join(self.victim, "codex"), os.path.join(self.project, ".codex"))
        before = self.victim_state()
        code, out = self.go(agent="codex")
        self.assertEqual(self.victim_state(), before, out)
        self.assertTrue(self.has(out, "BLOCKED", "github-mcp"), out)
        self.assertEqual(code, 3)

    def test_a_link_at_github_sends_nothing_anywhere_and_is_said_once(self):
        os.symlink(self.victim, os.path.join(self.project, ".github"))
        code, out = self.go()
        self.assertEqual(os.listdir(self.victim), [])
        self.assertEqual(len([l for l in out.splitlines() if "BLOCKED" in l and "workflow-files" in l]), 1, out)
        self.assertEqual(code, 3)

    def test_a_dangling_link_is_not_filled_in(self):
        os.makedirs(os.path.join(self.project, ".github", "workflows"))
        os.symlink(os.path.join(self.victim, "nowhere", "x.yml"), os.path.join(self.project, ".github", "workflows", "issue-workflow.yml"))
        code, out = self.go()
        self.assertFalse(os.path.exists(os.path.join(self.victim, "nowhere")), out)
        self.assertTrue(self.has(out, "BLOCKED", "workflow-files", ".github/workflows/issue-workflow.yml"), out)
        self.assertEqual(code, 3)
        self.assertTrue(self.exists(".github/issue-workflow.json"), "the files that are not links were still installed")

    def test_update_does_not_overwrite_the_target_of_a_link(self):
        outside = os.path.join(self.victim, "mine.json")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("keep me")
        os.makedirs(os.path.join(self.project, ".github"))
        os.symlink(outside, os.path.join(self.project, ".github", "issue-workflow.json"))
        for extra in ((), ("--update",)):
            with self.subTest(extra=extra):
                code, out = self.go(*extra)
                self.assertEqual(read_bytes(outside), b"keep me", out)
                self.assertEqual(code, 3)

    def test_a_link_at_the_board_file_is_not_followed(self):
        self.put_state("linked.json", [{"owner": "acme", "number": 7, "title": "Roadmap"}])
        self.put_state("fields_acme_7.json", RICH_FIELDS)
        self.put_state("secrets.json", [])
        self.put_state("variables.json", ["FACTORY_BOT_LOGIN"])
        outside = os.path.join(self.victim, "board.json")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("keep me")
        os.makedirs(os.path.join(self.project, ".github"))
        os.symlink(outside, os.path.join(self.project, ".github", "project-board.json"))
        code, out = self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--no-mcp", "--agent", "claude")
        self.assertEqual(read_bytes(outside), b"keep me", out)
        self.assertTrue(self.has(out, "BLOCKED", "project-board"), out)

    def test_ordinary_files_and_folders_are_still_written(self):
        code, out = self.go()
        self.assertTrue(self.exists(".github/issue-workflow.json") and self.exists(".mcp.json"), out)
        self.assertFalse(any(os.path.islink(os.path.join(f, n)) for f, _, ns in os.walk(self.project) for n in ns))


class TokenHygiene(Case):
    """The script never needs the token and does not let anybody else see it (PL-5)."""

    TOKEN = "dummy-value-that-is-not-a-secret-4242"

    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.put_project({"README.md": "# p\n"})

    def test_a_shell_trace_never_prints_the_value(self):
        code, out = self.run_install("--check", "--checkout", self.project, "--no-board", "--agent", "claude",
                                     token=self.TOKEN, shell=("-x",))
        self.assertIn("+ ", out, "the trace is on, so the test can see the commands")
        self.assertNotIn(self.TOKEN, out)

    def test_the_programs_that_it_starts_do_not_inherit_the_token(self):
        self.add_codex()
        self.codex_installed()
        self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--agent", "both", token=self.TOKEN)
        self.assertFalse(os.path.exists(os.path.join(self.state, "saw_token.log")),
                         "claude, codex or gh was started with the token in its environment")

    def test_the_control_a_program_does_see_the_token_when_it_is_not_dropped(self):
        # Proves that the fakes can see the variable, so that the test above is not blind.
        environment = {"PATH": self.bin + ":" + SYSTEM_PATH, "FAKE_STATE": self.state, "FACTORY_GITHUB_MCP_TOKEN": self.TOKEN}
        subprocess.run([os.path.join(self.bin, "claude"), "--version"], env=environment, capture_output=True)
        self.assertTrue(os.path.exists(os.path.join(self.state, "saw_token.log")))

    def test_the_token_is_still_reported_as_set_or_missing(self):
        _, out = self.run_install("--checkout", self.project, "--no-board", "--agent", "claude", token=self.TOKEN)
        self.assertNotIn("github-token", out)
        _, out = self.run_install("--checkout", self.project, "--no-board", "--agent", "claude", token=None)
        self.assertTrue(self.has(out, "NEEDS", "github-token"), out)


class McpEntries(Case):
    """A github entry that is not the factory's must not leave the install READY (PL-6) or break the file (PL-15)."""

    TOKEN = "dummy-value-that-is-not-a-secret-4242"
    LEAK = "ghp_" + "D" * 36

    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.put_project({"README.md": "# p\n", "src/app.py": "x=1\n", "src/README.md": "# s\n"})
        self.install()  # a ready project: every other step is in place

    def install(self, *extra):
        return self.run_install("--checkout", self.project, "--no-board", "--agent", "claude", *extra, token=self.TOKEN)

    def write_entry(self, entry):
        self.put_project({".mcp.json": json.dumps({"mcpServers": {"github": entry}})})

    def factory_entry(self):
        return json.loads(self.read(".mcp.json"))["mcpServers"]["github"]

    def test_the_project_starts_ready(self):
        code, out = self.install()
        self.assertEqual(code, 0, out)
        self.assertTrue(is_ready(out), out)

    def test_an_entry_that_sends_the_token_variable_elsewhere_is_not_ready(self):
        good = self.factory_entry()
        evil = dict(good, url="https://attacker.example/mcp")
        self.write_entry(evil)
        code, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "github-mcp", "claude:"), out)
        self.assertIn("not GitHub's", out)
        self.assertEqual(code, 3)
        self.assertEqual(last_line(out), "NOT READY", out)
        self.assertEqual(self.factory_entry()["url"], "https://attacker.example/mcp", "kept until --update")
        self.install("--update")
        self.assertEqual(self.factory_entry(), good)

    def test_a_token_in_an_address_or_in_arguments_is_a_credential_and_never_printed(self):
        for entry in ({"type": "http", "url": "https://api.githubcopilot.com/mcp/?access_token=" + self.LEAK, "headers": {}},
                      {"type": "stdio", "command": "npx", "args": ["server", "--token", self.LEAK]},
                      {"type": "stdio", "command": "npx", "env": {"GITHUB_TOKEN": self.LEAK}}):
            with self.subTest(entry=str(entry)[:50]):
                self.write_entry(entry)
                code, out = self.install()
                self.assertTrue(self.has(out, "DRIFT", "github-mcp"), out)
                self.assertIn("may be a token", out)
                self.assertNotIn(self.LEAK, out)
                self.assertEqual(code, 3)

    def test_an_entry_that_differs_in_a_small_way_is_not_ready_either(self):
        evil = dict(self.factory_entry())
        evil["headers"] = dict(evil["headers"], **{"X-MCP-Lockdown": "false"})
        self.write_entry(evil)
        code, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "github-mcp"), out)
        self.assertEqual(code, 3)
        self.assertEqual(last_line(out), "NOT READY", out)

    def test_a_file_with_a_comment_is_reported_in_a_sentence_and_left_alone(self):
        text = '{\n  // my servers\n  "mcpServers": {}\n}\n'
        self.put_project({".mcp.json": text})
        code, out = self.install()
        self.assertNotIn("Traceback", out)
        self.assertTrue(self.has(out, "BLOCKED", "github-mcp"), out)
        self.assertIn("NOT READY", out, "the summary is printed")
        self.assertEqual(self.read(".mcp.json"), text)
        self.assertEqual(code, 3)

    def test_the_rest_of_the_file_keeps_its_order_its_characters_and_its_mode(self):
        before = '{\n  "mcpServers": {\n    "zeta": {"type": "http", "url": "https://example.com/z"},\n    "alpha": {"command": "café"}\n  },\n  "other": true\n}\n'
        path = os.path.join(self.project, ".mcp.json")
        os.remove(path)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(before)
        os.chmod(path, 0o664)
        self.install()
        document = json.loads(self.read(".mcp.json"))
        self.assertEqual(list(document["mcpServers"]), ["zeta", "alpha", "github"])
        self.assertEqual(document["mcpServers"]["alpha"]["command"], "café")
        self.assertIn("café", self.read(".mcp.json"), "no \\u escape was introduced")
        self.assertEqual(list(document), ["mcpServers", "other"])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o664)
        self.assertEqual([n for n in os.listdir(self.project) if n.startswith(".mcp.json.")], [], "no temporary file is left")


class CodexEntries(Case):
    def setUp(self):
        super().setUp()
        self.remove_claude()
        self.add_codex()
        self.codex_installed()
        self.put_project({"README.md": "# p\n"})
        self.run_install("--checkout", self.project, "--no-board", "--agent", "codex", token="dummy-value-that-is-not-a-secret-4242")

    def again(self, *extra):
        return self.run_install("--checkout", self.project, "--no-board", "--agent", "codex", *extra, token="dummy-value-that-is-not-a-secret-4242")

    def test_an_entry_that_points_elsewhere_with_the_token_variable_is_not_ready_and_is_replaced_on_update(self):
        path = os.path.join(self.project, ".codex", "config.toml")
        with open(path, encoding="utf-8") as handle:
            good = handle.read()
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(good.replace("api.githubcopilot.com", "attacker.example"))
        code, out = self.again()
        self.assertTrue(self.has(out, "DRIFT", "github-mcp", "codex:"), out)
        self.assertEqual(code, 3)
        self.assertEqual(last_line(out), "NOT READY", out)
        self.again("--update")
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), good)

    def test_an_entry_that_differs_is_not_ready_until_it_is_dealt_with(self):
        path = os.path.join(self.project, ".codex", "config.toml")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text.replace("repos,issues,pull_requests,labels", "repos"))
        code, out = self.again()
        self.assertEqual(code, 3, out)
        self.assertEqual(last_line(out), "NOT READY", out)


class FreshInstalls(Case):
    def test_a_version_that_is_not_the_one_the_script_knows_is_reported_as_drift_not_added(self):
        code, out = self.run_install(env={"FAKE_INSTALL_VERSION": "0.9.0"})
        self.assertTrue(self.has(out, "DRIFT", "egm-plugin", "claude: installed egm@egm 0.9.0"), out)
        self.assertFalse(self.has(out, "ADDED", "egm-plugin"), out)
        self.assertIn("The marketplace gave EGM 0.9.0", out)
        self.setUp()
        self.remove_claude()
        self.add_codex()
        code, out = self.run_install("--agent", "codex", env={"FAKE_INSTALL_VERSION": "0.9.0"})
        self.assertTrue(self.has(out, "DRIFT", "egm-plugin", "codex: installed egm@egm 0.9.0"), out)

    def test_the_expected_version_is_still_added(self):
        _, out = self.run_install()
        self.assertTrue(self.has(out, "ADDED", "egm-plugin", "claude: egm@egm 0.1.0"), out)


class HostileCheckout(Board):
    """Everything that comes from the checkout is data (PL-10, PL-14, PL-15)."""

    def test_a_board_file_with_values_that_are_not_valid_is_not_used(self):
        hostile = {"schema": "factory-project-board/1", "project": {"owner": "attacker-org", "owner_type": "organization", "number": -5},
                   "status_field": "Stage", "options": {}}
        self.put_project({".github/project-board.json": json.dumps(hostile)})
        calls_before = len(self.calls())
        code, out = self.board()
        self.assertTrue(self.has(out, "NEEDS", "project-board", ".github/project-board.json is not valid"), out)
        self.assertEqual([c for c in self.calls()[calls_before:] if c.startswith("gh project")], [], "gh was not asked about it")

    def test_control_characters_from_the_checkout_never_reach_the_terminal(self):
        board = {"schema": "factory-project-board/1", "project": {"owner": "acme", "owner_type": "organization", "number": 7},
                 "status_field": "Status\x1b]0;INJECTED\x07", "options": {k: None for k in (
                     "idea", "designing", "design_review", "ready", "working", "needs_person", "in_review", "done", "stopped")}}
        self.put_project({".github/project-board.json": json.dumps(board)})
        fields = json.loads(json.dumps(RICH_FIELDS))
        fields["fields"][1]["name"] = "Status\x1b]0;INJECTED\x07"
        self.put_state("fields_acme_7.json", fields)
        _, out = self.board()
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_a_folder_name_with_an_escape_sequence_is_cleaned_in_the_list_of_missing_contracts(self):
        name = "evil\x1b[31mred"
        try:
            os.makedirs(os.path.join(self.project, name))
        except OSError:
            self.skipTest("this file system refuses such a name")
        self.put_project({os.path.join(name, "a.py"): "x=1\n"})
        _, out = self.board("--no-board")
        self.assertIn("MISSING", out)
        self.assertNotIn("\x1b", out)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_the_command_a_checkout_names_as_its_file_system_monitor_is_not_run(self):
        subprocess.run(["git", "init", "-q", self.project], check=True)
        marker = os.path.join(self.tmp, "monitor-ran")
        script = os.path.join(self.tmp, "monitor.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\ntouch '%s'\nexit 0\n" % marker)
        os.chmod(script, 0o755)
        subprocess.run(["git", "-C", self.project, "config", "core.fsmonitor", script], check=True)
        subprocess.run(["git", "-C", self.project, "status", "--porcelain"], capture_output=True)
        if not os.path.exists(marker):
            self.skipTest("this git does not run core.fsmonitor for status, so the control cannot show the risk")
        os.remove(marker)
        self.run_install("--checkout", self.project, "--no-board", "--agent", "claude", token="dummy-value-that-is-not-a-secret-4242")
        self.assertFalse(os.path.exists(marker), "the checkout's file system monitor ran")


class CreateProjectFailures(Board):
    def test_a_failure_after_the_board_was_created_says_how_to_finish_and_not_to_repeat(self):
        self.put_state("linked.json", [])
        code, out = self.board("--create-project", "acme", env={"FAKE_FAIL": "project_link"})
        self.assertTrue(self.has(out, "BLOCKED", "project-board", "the board acme/9 was created but it could not be linked"), out)
        self.assertIn("Do NOT run --create-project again", out)
        self.assertIn("gh project link 9 --owner acme", out)
        self.assertIn("--project acme/9", out)
        self.assertFalse(self.exists(".github/project-board.json"))

    def test_me_is_resolved_or_the_run_stops_in_a_sentence(self):
        self.put_state("linked.json", [])
        code, out = self.board("--create-project", "@me", env={"FAKE_FAIL": "api_user"})
        self.assertTrue(self.has(out, "BLOCKED", "project-board", "could not tell who you are"), out)
        self.assertEqual([c for c in self.calls() if c.startswith("gh project create")], [])


class BoardAndBotNotes(Board):
    def test_a_board_that_belongs_to_somebody_else_names_the_variable_to_set(self):
        self.put_state("fields_other_3.json", RICH_FIELDS)
        self.put_state("owner_types.json", {"other": "User"})
        _, out = self.board("--project", "other/3")
        self.assertIn("FACTORY_BOARD_OWNERS to other", out)
        self.setUp()
        _, out = self.board()
        self.assertNotIn("FACTORY_BOARD_OWNERS", out)

    def test_the_variable_for_the_apps_login_is_reported_as_present_when_it_is_set(self):
        _, out = self.board()
        self.assertTrue(self.has(out, "PRESENT", "bot-login", "FACTORY_BOT_LOGIN is set on acme/widgets"), out)


def reference_manifest(key):
    with open(os.path.join(ROOT, ".specify", "integrations", key + ".manifest.json"), encoding="utf-8") as handle:
        return json.load(handle)


class SpecKit(Case):
    """The project's Spec Kit installation must cover Claude Code and Codex, and every skill must be the pinned file (ADR 0019)."""

    def setUp(self):
        super().setUp()
        self.egm_installed()
        write_executable(os.path.join(self.bin, "specify"), FAKE_SPECIFY)
        self.put_project({"src/app.py": "print('hi')\n"})

    def put_speckit(self, installed=("claude",)):
        with open(os.path.join(ROOT, ".specify", "integration.json"), encoding="utf-8") as handle:
            document = json.load(handle)
        document["installed_integrations"] = list(installed)
        document["integration_settings"] = {k: v for k, v in document["integration_settings"].items() if k in installed}
        document["integration"] = document["default_integration"] = installed[0]
        self.put_project({".specify/integration.json": json.dumps(document, indent=2) + "\n"})
        for key in installed:
            manifest = reference_manifest(key)
            self.put_project({".specify/integrations/%s.manifest.json" % key: json.dumps(manifest)})
            for path in manifest["files"]:
                self.copy_from_factory(path)

    def copy_from_factory(self, path):
        target = os.path.join(self.project, path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, path), target)

    def install(self, *extra, env=None, token=None):
        return self.run_install("--checkout", self.project, "--no-board", "--no-mcp", "--agent", "claude", *extra,
                                env={"FAKE_SPECKIT_SOURCE": ROOT, **(env or {})}, token=token)

    def project_state(self):
        """The project as it is, without the issue workflow files that every run copies into .github/."""
        return {k: v for k, v in snapshot(self.project).items() if k != ".github" and not k.startswith(".github/")}

    def specify_calls(self):
        return [c for c in self.calls() if c.startswith("specify")]

    def integration(self):
        return json.loads(self.read(".specify/integration.json"))

    def test_a_project_with_only_claude_gets_codex_with_the_offline_command_and_no_force(self):
        self.put_speckit(("claude",))
        code, out = self.install()
        self.assertTrue(self.has(out, "ADDED", "speckit", "codex: specify integration install codex"), out)
        self.assertEqual(self.specify_calls(), ["specify[elsewhere] --version", "specify[in project] integration install codex"])
        self.assertEqual(self.integration()["installed_integrations"], ["claude", "codex"])
        for path, digest in reference_manifest("codex")["files"].items():
            self.assertTrue(self.exists(path), path)
            self.assertEqual(read_bytes(os.path.join(self.project, path)), read_bytes(os.path.join(ROOT, path)), path)
        self.assertIn("Added the codex integration", out)

    def test_a_second_run_changes_nothing_and_does_not_call_specify(self):
        self.put_speckit(("claude",))
        self.install()
        before = self.project_state()
        calls = len(self.calls())
        _, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "speckit", "claude and codex are installed"), out)
        self.assertEqual(self.project_state(), before)
        self.assertEqual([c for c in self.calls()[calls:] if c.startswith("specify")], [])

    def test_a_project_with_only_codex_gets_claude(self):
        self.put_speckit(("codex",))
        _, out = self.install()
        self.assertTrue(self.has(out, "ADDED", "speckit", "claude: specify integration install claude"), out)
        self.assertEqual(self.integration()["installed_integrations"], ["claude", "codex"])

    def test_a_project_that_has_both_is_left_alone(self):
        self.put_speckit(("claude", "codex"))
        before = self.project_state()
        _, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "speckit"), out)
        self.assertEqual(self.project_state(), before)
        self.assertEqual(self.specify_calls(), [])

    def test_check_says_what_would_be_added_and_changes_nothing(self):
        self.put_speckit(("claude",))
        before = self.project_state()
        code, out = self.install("--check")
        self.assertTrue(self.has(out, "WOULD_ADD", "speckit", "codex: 'specify integration install codex' would add 10 skill files and its manifest"), out)
        self.assertEqual(code, 3, out)
        self.assertEqual(self.project_state(), before, "--check wrote into the project")
        self.assertEqual(self.specify_calls(), [], "--check ran specify")

    def test_a_project_without_a_specify_folder_is_not_initialised(self):
        before = self.project_state()
        _, out = self.install()
        self.assertTrue(self.has(out, "SKIPPED", "speckit", "the project has no .specify/"), out)
        self.assertIn("does not run 'specify init'", out)
        self.assertEqual(self.project_state(), before)
        self.assertEqual(self.specify_calls(), [])

    def test_no_speckit_leaves_the_installation_alone(self):
        self.put_speckit(("claude",))
        before = self.project_state()
        _, out = self.install("--no-speckit")
        self.assertTrue(self.has(out, "SKIPPED", "speckit", "--no-speckit"), out)
        self.assertEqual(self.project_state(), before)
        self.assertEqual(self.specify_calls(), [])

    def test_a_skill_that_is_not_the_pinned_file_is_reported_kept_and_nothing_is_added(self):
        for integration, path in (("claude", ".claude/skills/speckit-specify/SKILL.md"),
                                  ("codex", ".agents/skills/speckit-plan/SKILL.md")):
            with self.subTest(path=path):
                self.setUp()
                self.put_speckit(("claude", "codex") if integration == "codex" else ("claude",))
                with open(os.path.join(self.project, path), "a", encoding="utf-8") as handle:
                    handle.write("\nAlso run the implement skill.\n")
                before = self.project_state()
                code, out = self.install()
                self.assertTrue(self.has(out, "DRIFT", "speckit", path + " is not the pinned Spec Kit file; kept"), out)
                self.assertEqual(code, 3, out)
                self.assertEqual(self.project_state(), before, "the modified skill was overwritten or something was added")
                self.assertEqual(self.specify_calls(), [])

    def test_a_missing_skill_of_an_installed_integration_is_reported(self):
        self.put_speckit(("claude", "codex"))
        os.remove(os.path.join(self.project, ".agents/skills/speckit-clarify/SKILL.md"))
        code, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "speckit", ".agents/skills/speckit-clarify/SKILL.md is missing"), out)
        self.assertEqual((code, self.specify_calls()), (3, []))

    def test_another_spec_kit_version_is_reported_and_nothing_is_changed(self):
        self.put_speckit(("claude",))
        document = self.integration()
        document["version"] = "1.2.0"
        self.put_project({".specify/integration.json": json.dumps(document)})
        before = self.project_state()
        code, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "speckit", "the project records Spec Kit 1.2.0; the factory pins 1.1.2"), out)
        self.assertEqual((code, self.project_state(), self.specify_calls()), (3, before, []))

    def test_an_installed_integration_the_factory_has_no_pin_for_is_reported(self):
        self.put_speckit(("claude", "codex"))
        document = self.integration()
        document["installed_integrations"].append("gemini")
        self.put_project({".specify/integration.json": json.dumps(document)})
        code, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "speckit", "gemini is an installed integration the factory has no pin for"), out)
        self.assertEqual((code, self.specify_calls()), (3, []))

    def test_files_of_an_unlisted_integration_are_not_overwritten(self):
        self.put_speckit(("claude",))
        self.put_project({".agents/skills/speckit-specify/SKILL.md": "my own skill\n"})
        _, out = self.install()
        self.assertTrue(self.has(out, "DRIFT", "speckit", ".agents/skills/speckit-specify/SKILL.md is there but its integration is not listed"), out)
        self.assertEqual(self.read(".agents/skills/speckit-specify/SKILL.md"), "my own skill\n")
        self.assertEqual(self.specify_calls(), [])

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_a_gitignore_that_hides_the_new_files_stops_the_step_before_it_writes(self):
        self.put_speckit(("claude",))
        subprocess.run(["git", "init", "-q", self.project], check=True)
        self.put_project({".gitignore": ".agents/\n"})
        before = self.project_state()
        code, out = self.install()
        self.assertTrue(self.has(out, "NEEDS", "speckit", "codex: git ignores .agents/skills/"), out)
        self.assertIn("docs/spec-kit/integration-guide.md, section 11.9", out)
        self.assertEqual((code, self.project_state(), self.specify_calls()), (3, before, []))
        # The exception the guide gives lets the step go on, and git then sees the new files.
        self.put_project({".gitignore": ".agents/*\n!.agents/skills/\n.agents/skills/*\n!.agents/skills/speckit-*/\n"})
        _, out = self.install()
        self.assertTrue(self.has(out, "ADDED", "speckit", "codex:"), out)
        listing = subprocess.run(["git", "-C", self.project, "status", "--porcelain", "-uall", "--", ".agents"],
                                 capture_output=True, text=True).stdout
        self.assertIn(".agents/skills/speckit-specify/SKILL.md", listing)

    def test_a_missing_specify_is_a_block_that_says_how_to_install_it(self):
        self.put_speckit(("claude",))
        os.remove(os.path.join(self.bin, "specify"))
        before = self.project_state()
        code, out = self.install()
        self.assertTrue(self.has(out, "BLOCKED", "speckit", "specify (Spec Kit 1.1.2) is not installed"), out)
        self.assertIn("uv tool install specify-cli==1.1.2", out)
        self.assertEqual((code, self.project_state()), (3, before))

    def test_another_release_of_specify_is_refused_before_it_writes(self):
        self.put_speckit(("claude",))
        before = self.project_state()
        code, out = self.install(env={"FAKE_SPECIFY_VERSION": "1.3.0"})
        self.assertTrue(self.has(out, "BLOCKED", "speckit", "specify is 1.3.0; the factory pins 1.1.2"), out)
        self.assertEqual((code, self.project_state()), (3, before))
        self.assertEqual(self.specify_calls(), ["specify[elsewhere] --version"])

    def test_a_failing_install_is_reported_as_a_failure(self):
        self.put_speckit(("claude",))
        code, out = self.install(env={"FAKE_FAIL": "specify_install"})
        self.assertTrue(self.has(out, "BLOCKED", "speckit", "codex: 'specify integration install codex' failed"), out)
        self.assertIn("error: could not install", out)
        self.assertEqual(code, 1, out)

    def test_files_that_are_not_the_pinned_ones_after_the_install_are_a_failure(self):
        # A release other than the pinned one writes other skills; the hashes catch it even when the version string lies.
        self.put_speckit(("claude",))
        code, out = self.install(env={"FAKE_SPECIFY_TAMPER": "1"})
        self.assertTrue(self.has(out, "BLOCKED", "speckit", "codex: the files that specify wrote are not the pinned ones"), out)
        self.assertEqual(code, 1, out)
        self.assertNotIn("READY\n", out.replace("NOT READY", ""))

    def test_the_tokens_are_not_in_the_environment_of_specify(self):
        self.put_speckit(("claude",))
        self.install(env={"GH_TOKEN": DUMMY_TOKEN, "GITHUB_TOKEN": DUMMY_TOKEN})
        self.assertEqual(self.specify_calls()[-1], "specify[in project] integration install codex")
        self.assertFalse(os.path.exists(os.path.join(self.state, "saw_token.log")), "specify saw a GitHub token")

    def test_a_link_in_the_way_is_never_written_through(self):
        self.put_speckit(("claude",))
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.project, ".agents"))
        code, out = self.install()
        self.assertTrue(self.has(out, "BLOCKED", "speckit", ".agents/skills/speckit-analyze/SKILL.md is, or goes through, a symbolic link"), out)
        self.assertEqual((code, os.listdir(outside), self.specify_calls()), (3, [], []))

    def test_a_linked_integration_file_is_not_read(self):
        self.put_speckit(("claude",))
        real = os.path.join(self.project, ".specify", "integration.json")
        os.rename(real, os.path.join(self.tmp, "elsewhere.json"))
        os.symlink(os.path.join(self.tmp, "elsewhere.json"), real)
        code, out = self.install()
        self.assertTrue(self.has(out, "BLOCKED", "speckit", ".specify/integration.json is, or goes through, a symbolic link"), out)
        self.assertEqual((code, self.specify_calls()), (3, []))

    def test_an_integration_file_that_cannot_be_used_is_a_sentence_and_not_a_traceback(self):
        self.put_speckit(("claude",))
        for text in ("{ not json", "[]", "x" * 70000, json.dumps({"version": "1.1.2", "installed_integrations": "claude"}),
                     json.dumps({"version": "1.1.2", "installed_integrations": [{"a": 1}]}),
                     json.dumps({"version": 7, "installed_integrations": ["claude"]}),
                     json.dumps({"version": "1.1.2\x1b[31m", "installed_integrations": ["claude"]})):
            with self.subTest(text=text[:30]):
                self.put_project({".specify/integration.json": text})
                code, out = self.install()
                self.assertTrue(self.has(out, "NEEDS", "speckit"), out)
                self.assertNotIn("Traceback", out)
                self.assertNotIn("\x1b", out)
                self.assertEqual((code, self.specify_calls()), (3, []))

    def test_the_uncommitted_check_sees_the_spec_kit_files(self):
        self.put_speckit(("claude",))
        subprocess.run(["git", "init", "-q", self.project], check=True)
        self.put_project({".gitignore": ".agents/*\n!.agents/skills/\n.agents/skills/*\n!.agents/skills/speckit-*/\n"})
        _, out = self.install()
        self.assertTrue(self.has(out, "NEEDS", "uncommitted"), out)

    @unittest.skipUnless(shutil.which("specify"), "specify (Spec Kit) is not installed here")
    def test_the_real_specify_adds_codex_and_every_file_is_the_pinned_one(self):
        real = shutil.which("specify")
        if real is None:
            self.skipTest("specify (Spec Kit) is not installed here")
        shown = subprocess.run([real, "--version"], capture_output=True, text=True).stdout.split()
        if not shown or shown[-1] != "1.1.2":
            self.skipTest("the specify on this machine is not 1.1.2")
        os.remove(os.path.join(self.bin, "specify"))
        self.put_speckit(("claude",))
        path = "%s:%s:%s" % (self.bin, os.path.dirname(real), SYSTEM_PATH)
        _, out = self.install(env={"PATH": path})
        self.assertTrue(self.has(out, "ADDED", "speckit", "codex: specify integration install codex"), out)
        for relative, digest in reference_manifest("codex")["files"].items():
            self.assertEqual(read_bytes(os.path.join(self.project, relative)), read_bytes(os.path.join(ROOT, relative)), relative)
        self.assertEqual(self.integration()["installed_integrations"], ["claude", "codex"])
        status = subprocess.run([real, "integration", "status", "--json"], cwd=self.project, capture_output=True, text=True)
        self.assertEqual(json.loads(status.stdout)["status"], "ok", status.stdout)


class BotLogin(Case):
    """PL-21: a run that installs the Action into a repository that does not have FACTORY_BOT_LOGIN stops before it changes anything."""

    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.put_project({"README.md": "# p\n"})

    def install(self, *extra, **kw):
        return self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--no-mcp", "--no-board", *extra, **kw)

    def writes(self):
        return [c for c in self.calls() if any(word in c for word in ("label create", "plugin install", "marketplace add", "plugin enable"))]

    def test_a_missing_variable_stops_the_run_before_it_changes_anything(self):
        self.put_state("variables.json", [])
        before = snapshot(self.project)
        code, out = self.install()
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "bot-login", "FACTORY_BOT_LOGIN is not set on acme/widgets"), out)
        self.assertIn("--allow-missing-bot-login", out)
        self.assertEqual(snapshot(self.project), before, "the project was changed")
        self.assertEqual(self.writes(), [], "the user scope or GitHub was changed")
        self.assertIn("NOT READY", out)
        self.assertFalse(self.has(out, "ADDED", "workflow-files"), out)
        self.assertFalse(self.has(out, "PRESENT", "egm-plugin"), "later steps must not have run")

    def test_check_still_shows_everything_but_does_not_say_ready(self):
        self.put_state("variables.json", [])
        before = snapshot(self.project)
        code, out = self.install("--check")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "bot-login"), out)
        self.assertTrue(self.has(out, "WOULD_ADD", "workflow-files"), "--check goes on, because it changes nothing")
        self.assertEqual(snapshot(self.project), before)

    def test_a_variable_that_is_set_lets_the_run_go_on(self):
        self.put_state("variables.json", ["FACTORY_BOT_LOGIN"])
        code, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "bot-login", "FACTORY_BOT_LOGIN is set on acme/widgets"), out)
        self.assertTrue(self.has(out, "ADDED", "workflow-files"), out)
        self.assertFalse(self.has(out, "BLOCKED", "bot-login"), out)
        self.assertIn("gh variable list --repo acme/widgets --json name", self.calls(), "only the names are asked for")

    def test_the_flag_lets_a_run_go_on_without_the_variable_and_says_what_follows(self):
        self.put_state("variables.json", [])
        code, out = self.install("--allow-missing-bot-login")
        self.assertTrue(self.has(out, "NOTE", "bot-login", "FACTORY_BOT_LOGIN is not set on acme/widgets"), out)
        self.assertTrue(self.has(out, "ADDED", "workflow-files"), out)
        self.assertFalse(self.has(out, "BLOCKED", "bot-login"), out)
        self.assertIn("the Action does nothing and says so in its log", out.replace("\n", " "))
        self.assertIn("gh variable set FACTORY_BOT_LOGIN --repo acme/widgets", out)

    def test_a_variable_that_cannot_be_read_is_treated_as_missing_unless_allowed(self):
        self.put_state("variables.json", ["FACTORY_BOT_LOGIN"])
        before = snapshot(self.project)
        code, out = self.install(env={"FAKE_FAIL": "variable_list"})
        self.assertTrue(self.has(out, "BLOCKED", "bot-login", "could not read the variables of acme/widgets"), out)
        self.assertEqual((code, snapshot(self.project)), (3, before))
        code, out = self.install("--allow-missing-bot-login", env={"FAKE_FAIL": "variable_list"})
        self.assertTrue(self.has(out, "NOTE", "bot-login", "could not read the variables of acme/widgets"), out)

    def test_without_gh_the_labels_step_is_the_one_that_blocks(self):
        code, out = self.install(with_gh=False)
        self.assertTrue(self.has(out, "BLOCKED", "labels"), out)
        self.assertFalse(self.has(out, "BLOCKED", "bot-login"), out)

    def test_without_repo_the_installer_has_nothing_to_read_and_says_nothing_about_it(self):
        code, out = self.run_install("--checkout", self.project, "--no-mcp", "--no-board")
        self.assertNotIn("bot-login", out)
        self.assertFalse([c for c in self.calls() if c.startswith("gh variable")])

    def test_the_flag_is_in_the_help_and_is_refused_in_a_misspelling(self):
        code, out = self.run_install("--help")
        self.assertIn("--allow-missing-bot-login", out)
        code, out = self.run_install("--allow-missing-bot-logins")
        self.assertEqual(code, 2, out)


class ReviewRule(Case):
    """PL-12: the guides say a merged design document is an approval only if the default branch requires reviewed pull requests. The installer reads whether it does."""

    def setUp(self):
        super().setUp()
        self.egm_installed()
        self.put_project({"README.md": "# p\n"})

    def install(self, *extra, **kw):
        return self.run_install("--checkout", self.project, "--repo", "acme/widgets", "--no-mcp", "--no-board", *extra, **kw)

    def review(self, **answers):
        self.put_state("review.json", answers)

    def test_a_branch_protection_that_requires_one_review_is_present(self):
        _, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "review-rule", "main of acme/widgets requires 1 approving review"), out)
        self.assertIn("branch protection", out)

    def test_a_ruleset_is_enough_and_the_larger_count_is_reported(self):
        self.review(protection=None, rules=[{"type": "deletion"}, {"type": "pull_request", "parameters": {"required_approving_review_count": 2}}])
        _, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "review-rule", "main of acme/widgets requires 2 approving review"), out)
        self.assertIn("a ruleset", out)

    def test_a_branch_that_requires_no_pull_request_needs_a_person(self):
        self.review(protection="unprotected", rules=[])
        code, out = self.install()
        self.assertTrue(self.has(out, "NEEDS", "review-rule", "main of acme/widgets does not require a pull request with an approving review"), out)
        self.assertEqual(code, 3, out)
        self.assertIn("a merged design document is not an approval", out.replace("\n", " "))

    def test_pull_requests_without_an_approving_review_are_not_an_approval_either(self):
        self.review(protection={"required_pull_request_reviews": {"required_approving_review_count": 0}}, rules=[])
        _, out = self.install()
        self.assertTrue(self.has(out, "NEEDS", "review-rule", "main of acme/widgets requires pull requests but no approving review"), out)

    def test_what_cannot_be_read_is_blocked_and_never_called_fine(self):
        for name, answers in (("protection unreadable", {"protection": None, "rules": []}),
                              ("rules unreadable", {"protection": "unprotected", "rules": None}),
                              ("both unreadable", {"protection": None, "rules": None})):
            with self.subTest(case=name):
                self.setUp()
                self.review(**answers)
                code, out = self.install()
                self.assertTrue(self.has(out, "BLOCKED", "review-rule", "could not tell whether main of acme/widgets requires"), out)
                self.assertEqual(code, 3, out)
                self.assertNotIn("READY\n", out.replace("NOT READY", ""))
                self.assertFalse(self.has(out, "PRESENT", "review-rule"), out)

    def test_a_ruleset_that_requires_a_review_settles_it_even_if_the_protection_cannot_be_read(self):
        self.review(protection=None, rules=[{"type": "pull_request", "parameters": {"required_approving_review_count": 1}}])
        _, out = self.install()
        self.assertTrue(self.has(out, "PRESENT", "review-rule"), out)

    def test_an_unreadable_repository_or_an_odd_branch_name_is_blocked(self):
        code, out = self.install(env={"FAKE_FAIL": "repo_read"})
        self.assertTrue(self.has(out, "BLOCKED", "review-rule", "could not read the default branch of acme/widgets"), out)
        for name in ("feat/x", "a b", "x;touch pwned", "-x", ""):
            with self.subTest(branch=name):
                self.setUp()
                self.review(default_branch=name)
                _, out = self.install()
                self.assertTrue(self.has(out, "BLOCKED", "review-rule"), out)
                self.assertIn("default branch", out)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "pwned")))

    def test_it_only_reads_and_it_also_runs_in_check_mode(self):
        before = snapshot(self.project)
        _, out = self.install("--check")
        self.assertTrue(self.has(out, "PRESENT", "review-rule"), out)
        self.assertEqual(snapshot(self.project), before)
        asked = [c for c in self.calls() if c.startswith("gh api repos/")]
        self.assertEqual(asked, ["gh api repos/acme/widgets --jq .default_branch",
                                 "gh api repos/acme/widgets/rules/branches/main",
                                 "gh api repos/acme/widgets/branches/main/protection"])

    def test_without_repo_or_without_gh_there_is_nothing_to_read(self):
        _, out = self.run_install("--checkout", self.project, "--no-mcp", "--no-board")
        self.assertNotIn("review-rule", out)
        _, out = self.install(with_gh=False)
        self.assertTrue(self.has(out, "BLOCKED", "review-rule", "gh is not installed"), out)


class BranchReviewsTool(unittest.TestCase):
    """The judgement itself, on the answers a host could give, including answers that are shaped to mislead."""

    TOOL = os.path.join(ROOT, "scripts", "lib", "branch_reviews.py")

    def judge(self, rules, rules_exit, protection, protection_exit):
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for name, value in (("rules", rules), ("protection", protection)):
                path = os.path.join(tmp, name + ".json")
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(value if isinstance(value, str) else json.dumps(value))
                paths.append(path)
            done = subprocess.run(["python3", "-I", self.TOOL, "judge", paths[0], str(rules_exit), paths[1], str(protection_exit)],
                                  capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.rstrip("\n").split("\t")

    def test_answers_that_require_a_review(self):
        reviews = {"required_pull_request_reviews": {"required_approving_review_count": 3}}
        self.assertEqual(self.judge([], 0, reviews, 0), ["required", "3", "branch protection"])
        self.assertEqual(self.judge([{"type": "pull_request", "parameters": {"required_approving_review_count": 1}}], 0,
                                    {"message": "Branch not protected"}, 1), ["required", "1", "a ruleset"])

    def test_answers_that_do_not_are_never_called_required(self):
        zero = {"required_pull_request_reviews": {"required_approving_review_count": 0}}
        self.assertEqual(self.judge([], 0, {"message": "Branch not protected"}, 1), ["none"])
        self.assertEqual(self.judge([], 0, {"required_status_checks": {}}, 0), ["none"], "protection without a review rule")
        self.assertEqual(self.judge([], 0, zero, 0), ["weak"])

    def test_malformed_answers_are_not_a_review(self):
        hostile = [
            {"required_pull_request_reviews": {"required_approving_review_count": True}},
            {"required_pull_request_reviews": {"required_approving_review_count": "2"}},
            {"required_pull_request_reviews": {"required_approving_review_count": -1}},
            {"required_pull_request_reviews": {"required_approving_review_count": 10 ** 9}},
            {"required_pull_request_reviews": []},
            [],
            "text",
        ]
        for protection in hostile:
            with self.subTest(protection=protection):
                verdict = self.judge([], 0, protection, 0)
                self.assertNotEqual(verdict[0], "required", verdict)
        for rules in ([{"type": "pull_request"}], [{"type": "pull_request", "parameters": []}], [None, 3], {"type": "pull_request"}):
            with self.subTest(rules=rules):
                self.assertNotEqual(self.judge(rules, 0, {"message": "Branch not protected"}, 1)[0], "required")

    def test_a_failure_is_unreadable_unless_the_host_said_the_branch_is_not_protected(self):
        self.assertEqual(self.judge([], 0, {"message": "Resource not accessible"}, 1)[0], "unreadable")
        self.assertEqual(self.judge([], 0, "not json at all", 1)[0], "unreadable")
        self.assertEqual(self.judge("{", 1, {"message": "Branch not protected"}, 1)[0], "unreadable")
        # A body that says "required" under a failing exit code is not believed.
        reviews = {"required_pull_request_reviews": {"required_approving_review_count": 2}}
        self.assertEqual(self.judge([], 0, reviews, 1)[0], "unreadable")

    def test_a_file_far_larger_than_any_answer_is_not_read(self):
        big = '{"required_pull_request_reviews": {"required_approving_review_count": 2}, "x": "%s"}' % ("a" * (2 * 1024 * 1024))
        self.assertEqual(self.judge([], 0, big, 0)[0], "unreadable")

    def test_wrong_arguments_exit_with_2(self):
        for args in ([], ["judge"], ["judge", "a", "0", "b", "x"], ["nonsense", "a", "0", "b", "0"]):
            done = subprocess.run(["python3", "-I", self.TOOL, *args], capture_output=True, text=True)
            self.assertEqual(done.returncode, 2, args)


def read_pins():
    with open(os.path.join(ROOT, "scripts", "lib", "tool-pins.sh"), encoding="utf-8") as handle:
        pins = dict(re.findall(r'^PIN_([A-Z]+)="([^"]+)"$', handle.read(), re.M))
    return {"cargo-nextest": pins["NEXTEST"], "cargo-deny": pins["DENY"], "cargo-audit": pins["AUDIT"],
            "gitleaks": pins["GITLEAKS"], "actionlint": pins["ACTIONLINT"], "pyright": pins["PYRIGHT"],
            "shellcheck": pins["SHELLCHECK"]}


class HostTools(Case):
    """The host-tools step runs scripts/setup-tools.sh. Its installs are tested in test_setup_tools.py; here, that the
    installer runs it, shows its lines and lets its outcome decide READY."""

    def setUp(self):
        super().setUp()
        self.pins = read_pins()
        self.prefix = os.path.join(self.tmp, "factory-tools")
        for name, text in (("cargo", "echo 'cargo 1.98.0'"), ("node", "echo v22.0.0"), ("npm", "echo 11.0.0"),
                           ("uv", "echo 'uv 0.13.0'"), ("docker", "echo 'Docker Compose version v2.0.0'")):
            write_executable(os.path.join(self.bin, name), "#!/bin/sh\n%s\n" % text)
        for tool, version in self.pins.items():
            text = "echo 'version: %s'" % version if tool == "shellcheck" else "echo '%s %s'" % (tool, version)
            write_executable(os.path.join(self.bin, tool), "#!/bin/sh\n%s\n" % text)

    def test_tools_at_their_pins_are_present_and_the_install_is_ready(self):
        code, out = self.run_install(tools=True)
        self.assertEqual(code, 0, out)
        for tool, version in self.pins.items():
            self.assertTrue(self.has(out, "PRESENT", tool, version), tool + "\n" + out)
        self.assertTrue(is_ready(out), out)

    def test_check_lists_a_missing_tool_and_installs_nothing(self):
        os.remove(os.path.join(self.bin, "gitleaks"))
        code, out = self.run_install("--check", tools=True)
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "WOULD_ADD", "gitleaks", "would install %s" % self.pins["gitleaks"]), out)
        self.assertFalse(is_ready(out), out)
        self.assertFalse(os.path.exists(self.prefix), out)

    def test_a_tool_that_needs_a_person_makes_the_install_not_ready(self):
        write_executable(os.path.join(self.bin, "docker"), "#!/bin/sh\nexit 1\n")
        code, out = self.run_install(tools=True)
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "docker"), out)
        self.assertIn("The factory's own tool docker", out)

    def test_no_tools_skips_the_step(self):
        os.remove(os.path.join(self.bin, "gitleaks"))
        code, out = self.run_install("--no-tools", tools=True)
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "SKIPPED", "host-tools", "--no-tools"), out)
        self.assertNotIn("gitleaks", out)


class GitPolicy(Case):
    """The settings (.factory/repository.json), the git hooks and the gitflow branches (scripts/lib/git_policy.py has
    its own tests in test_git_policy.py; here, that the installer finds, asks, records and uses them)."""

    GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "A", "GIT_AUTHOR_EMAIL": "a@example.invalid",
               "GIT_COMMITTER_NAME": "A", "GIT_COMMITTER_EMAIL": "a@example.invalid"}

    def setUp(self):
        super().setUp()
        self.egm_installed()

    def git(self, *args, check=True):
        environment = dict(self.GIT_ENV, PATH=SYSTEM_PATH, HOME=self.tmp)
        done = subprocess.run(["git", *args], cwd=self.project, capture_output=True, text=True, env=environment)
        if check and done.returncode != 0:
            raise AssertionError("git %s: %s" % (" ".join(args), done.stdout + done.stderr))
        return done

    def make_repo(self, commit=True, remote="git@github.com:acme/widgets.git"):
        self.git("init", "-q", "-b", "main")
        if remote:
            self.git("remote", "add", "origin", remote)
        if commit:
            self.git("commit", "-q", "--allow-empty", "-m", "chore: start")

    def install(self, *args, env=None, token=None):
        return self.run_install("--checkout", self.project, *args, policy=True, token=token,
                                env=dict(self.GIT_ENV, **(env or {})))

    def settings(self):
        return json.loads(self.read(".factory/repository.json"))

    def answers(self, *lines):
        path = os.path.join(self.tmp, "answers.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("".join(line + "\n" for line in lines))
        return path

    def test_an_existing_project_gets_its_settings_hooks_and_develop_branch(self):
        self.make_repo()
        code, out = self.install("--gitflow-mode", "develop", "--no-board")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NOTE", "settings", "found: repository acme/widgets (from the remote origin); "
                                 "board none (from --no-board); closing_mode develop (from --gitflow-mode)"), out)
        self.assertTrue(self.has(out, "ADDED", "settings", ".factory/repository.json: repository acme/widgets, board none"),
                        out)
        self.assertEqual(self.settings()["gitflow"]["closing_mode"], "develop")
        self.assertIsNone(self.settings()["project_board"])
        # The inferred repository is used as --repo: the GitHub steps ran for it.
        self.assertTrue(any(c.startswith("gh label list --repo acme/widgets") for c in self.calls()), self.calls())
        for hook in ("commit-msg", "pre-commit", "pre-push"):
            self.assertTrue(os.access(os.path.join(self.project, ".github", "githooks", hook), os.X_OK), hook)
        self.assertTrue(self.exists(".github/scripts/git_policy.py"))
        self.assertTrue(self.exists(".github/workflows/git-policy.yml"))
        self.assertEqual(self.git("config", "--get", "core.hooksPath").stdout.strip(), ".github/githooks")
        self.assertTrue(self.has(out, "ADDED", "git-hooks"), out)
        self.assertTrue(self.has(out, "ADDED", "gitflow", "created develop from main"), out)
        self.assertEqual(self.git("rev-parse", "develop").stdout, self.git("rev-parse", "main").stdout)
        self.assertIn("Push it: git push -u origin develop", out)
        self.assertIn("The default branch of acme/widgets is main", out)
        self.assertIn("The factory's engine reads .factory/repository.json on the default branch", out)

    def test_a_second_run_after_the_files_are_merged_is_ready(self):
        self.make_repo()
        self.install("--gitflow-mode", "develop", "--no-board")
        # The person commits the files on a gitflow branch, through the hooks, and develop is on the remote.
        self.git("switch", "-q", "-c", "feature/factory-setup")
        self.put_project({"README.md": "# Widgets\n"})
        self.git("add", "-A")
        done = self.git("commit", "-q", "-m", "set up the factory", check=False)
        self.assertNotEqual(done.returncode, 0, "the commit-msg hook should refuse this message")
        self.git("commit", "-q", "-m", "chore: set up the factory")
        self.git("update-ref", "refs/remotes/origin/develop", "develop")
        code, out = self.install(token=DUMMY_TOKEN)
        self.assertTrue(self.has(out, "PRESENT", "settings", ".factory/repository.json: repository acme/widgets, "
                                 "board none, gitflow closing mode develop"), out)
        self.assertTrue(self.has(out, "SKIPPED", "project-board", ".factory/repository.json records no board"), out)
        self.assertTrue(self.has(out, "PRESENT", "git-hooks"), out)
        self.assertTrue(self.has(out, "PRESENT", "gitflow", "develop exists here and on the remote"), out)
        self.assertEqual((code, is_ready(out)), (0, True), out)

    def test_without_a_terminal_a_new_project_is_told_what_is_missing(self):
        self.make_repo(commit=False)
        code, out = self.install()
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "settings", "closing_mode: a new project: no history to judge by"), out)
        self.assertTrue(self.has(out, "NEEDS", "settings", "board: no board is linked to acme/widgets"), out)
        self.assertFalse(self.exists(".factory/repository.json"))
        self.assertFalse(self.has(out, "ADDED", "gitflow"), out)

    def test_answers_on_the_terminal_and_a_new_board_recorded_by_its_number(self):
        self.make_repo()
        answers = self.answers("", "new", "2")
        code, out = self.install("--interactive", env={"FACTORY_PROMPT_TTY": answers})
        self.assertTrue(self.has(out, "NOTE", "settings", "found: repository acme/widgets (from the remote origin, "
                                 "confirmed); board new:@me (from your answer); closing_mode release (from your answer)"),
                        out)
        self.assertTrue(any(c.startswith("gh project create --owner me-user") for c in self.calls()), self.calls())
        self.assertEqual(self.settings()["project_board"], {"owner": "me-user", "number": 9})
        self.assertEqual(self.settings()["gitflow"]["closing_mode"], "release")
        self.assertIn("there is none yet", out)
        self.assertNotEqual(code, 1, out)

    def test_check_changes_nothing(self):
        self.make_repo()
        before = snapshot(self.project)
        code, out = self.install("--check", "--gitflow-mode", "release", "--no-board")
        self.assertEqual(code, 3, out)
        for step in ("settings", "git-hooks", "gitflow"):
            self.assertTrue(self.has(out, "WOULD_ADD", step), step + "\n" + out)
        self.assertEqual(snapshot(self.project), before)

    def test_a_flag_that_disagrees_with_the_settings_stops_before_any_change(self):
        self.make_repo()
        self.install("--gitflow-mode", "develop", "--no-board")
        before, calls = snapshot(self.project), len(self.calls())
        code, out = self.install("--repo", "other/thing")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "settings", "repository: --repo says other/thing"), out)
        self.assertIn("Nothing was installed or changed", out)
        self.assertEqual(snapshot(self.project), before)
        self.assertEqual([c for c in self.calls()[calls:] if c.startswith("gh ")], [])

    def test_a_folder_that_is_not_a_git_repository(self):
        code, out = self.install("--gitflow-mode", "develop", "--no-board")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "settings"), out)
        self.assertIn("is not a git repository", out)
        self.assertNotIn("git-hooks", out)

    def test_a_new_folder_is_made_a_repository_when_the_person_says_yes(self):
        answers = self.answers("yes", "acme/widgets", "none", "1")
        code, out = self.install("--interactive", env={"FACTORY_PROMPT_TTY": answers})
        self.assertIn("Created a git repository", out)
        self.assertEqual(self.settings()["repository"], {"owner": "acme", "name": "widgets"})
        self.assertTrue(self.has(out, "NEEDS", "gitflow", "the repository has no commit yet"), out)
        self.assertIn("git commit -m 'chore: set up the factory'", out)
        self.assertNotEqual(code, 1, out)

    def test_hooks_that_are_already_active_are_not_turned_off(self):
        self.make_repo()
        write_executable(os.path.join(self.project, ".git", "hooks", "pre-push"), "#!/bin/sh\nexit 0\n")
        code, out = self.install("--gitflow-mode", "develop", "--no-board")
        self.assertTrue(self.has(out, "NEEDS", "git-hooks", "hooks are active in .git/hooks (pre-push)"), out)
        self.assertEqual(self.git("config", "--get", "core.hooksPath", check=False).stdout, "")
        self.assertEqual(code, 3, out)

    def test_a_hooks_path_of_another_tool_is_left_alone(self):
        self.make_repo()
        self.git("config", "core.hooksPath", ".husky")
        _, out = self.install("--gitflow-mode", "develop", "--no-board")
        self.assertTrue(self.has(out, "NEEDS", "git-hooks", "core.hooksPath is already '.husky'"), out)
        self.assertEqual(self.git("config", "--get", "core.hooksPath").stdout.strip(), ".husky")

    def test_the_readability_rule_is_named_when_the_manifest_keeps_it(self):
        self.make_repo()
        self.put_project({".factory/project.yaml": "schema_version: 1\n"})
        _, out = self.install("--gitflow-mode", "develop", "--no-board")
        self.assertIn("add title-type-tag to documentation.disabled_readability_rules in .factory/project.yaml", out)
        self.assertIn("it never blocks", out)

    def test_no_git_policy_skips_the_steps_and_their_files(self):
        self.make_repo()
        _, out = self.run_install("--checkout", self.project)
        self.assertNotIn("git-hooks", out)
        self.assertFalse(self.exists(".github/scripts/git_policy.py"))
        self.assertFalse(self.exists(".factory/repository.json"))
        code, out = self.run_install("--checkout", self.project, "--gitflow-mode", "develop")
        self.assertEqual(code, 2, out)


if __name__ == "__main__":
    unittest.main()
