#!/usr/bin/env python3
"""Tests for scripts/setup-tools.sh. Standard library only. Run it with:
    python3 -I scripts/tests/test_setup_tools.py

The script runs for real, under the system bash (3.2 on macOS), from a copy of the files it reads, in a temporary
folder. Every program it calls to install something is a fake on a PATH that holds nothing else: cargo, npm, brew and
curl write small stand-ins and log each call, and the "downloads" are archives built by the test. Nothing touches the
network, the person's PATH or their home folder. The copy's scripts/lib/tool-pins.sh records the SHA-256 of the test's
archives, because the real hashes belong to the real releases. Each test builds a situation, shows the outcome, and
where it matters changes one thing and shows that the outcome changes.
"""
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
BASH = "/bin/bash" if os.path.exists("/bin/bash") else (shutil.which("bash") or "bash")

# The real pins, read the way the scripts read them, so the tests follow a version change by themselves.
with open(os.path.join(ROOT, "scripts", "lib", "tool-pins.sh"), encoding="utf-8") as _handle:
    PINS = dict(re.findall(r'^PIN_([A-Z]+)="([^"]+)"$', _handle.read(), re.M))
PIN = {
    "cargo-nextest": PINS["NEXTEST"],
    "cargo-deny": PINS["DENY"],
    "cargo-audit": PINS["AUDIT"],
    "gitleaks": PINS["GITLEAKS"],
    "actionlint": PINS["ACTIONLINT"],
    "pyright": PINS["PYRIGHT"],
    "shellcheck": PINS["SHELLCHECK"],
}
PINNED_TOOLS = list(PIN)

# Basic programs the script needs, linked into the test's PATH folder. Nothing else from the machine is visible.
ESSENTIALS = ["cat", "cut", "dirname", "basename", "env", "grep", "head", "tail", "mkdir", "mktemp", "rm", "sed", "tr",
              "uname", "cp", "mv", "chmod", "ln", "tar", "gzip", "shasum", "sha256sum", "sort", "wc", "git", "perl",
              "bash", "sh"]

LOG = r'''
import os, sys
with open(os.path.join(os.environ["FAKE_STATE"], "calls.log"), "a", encoding="utf-8") as log:
    log.write(os.path.basename(sys.argv[0]) + " " + " ".join(sys.argv[1:]) + "\n")
'''

# A program that answers any question with one line: its name and version.
def version_program(name, version):
    return "#!/bin/sh\necho '%s %s'\n" % (name, version)


FAKE_CARGO = "#!/usr/bin/env python3\n" + LOG + r'''
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("cargo 1.98.0 (fake)")
elif args[:1] == ["install"]:
    if os.environ.get("FAKE_CARGO_FAIL"):
        print("error: could not compile", file=sys.stderr); sys.exit(101)
    root = args[args.index("--root") + 1]
    version = args[args.index("--version") + 1]
    name = [a for a in args[1:] if not a.startswith("-") and a not in (root, version)][0]
    os.makedirs(os.path.join(root, "bin"), exist_ok=True)
    path = os.path.join(root, "bin", name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\necho '%s %s'\n" % (name, version))
    os.chmod(path, 0o755)
else:
    sys.exit(64)
'''

FAKE_NPM = "#!/usr/bin/env python3\n" + LOG + r'''
import json
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("11.0.0")
elif args[:1] == ["ci"]:
    with open("package-lock.json", encoding="utf-8") as handle:
        version = json.load(handle)["packages"]["node_modules/pyright"]["version"]
    os.makedirs("node_modules/pyright", exist_ok=True)
    os.makedirs("node_modules/.bin", exist_ok=True)
    with open("node_modules/pyright/index.js", "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\necho 'pyright %s'\n" % version)
    os.chmod("node_modules/pyright/index.js", 0o755)
    os.symlink("../pyright/index.js", "node_modules/.bin/pyright")
else:
    sys.exit(64)
'''

# curl --output FILE URL: copies FAKE_DOWNLOADS/<last part of URL>, or fails as curl does for a 404.
FAKE_CURL = "#!/usr/bin/env python3\n" + LOG + r'''
import shutil
args = sys.argv[1:]
output, url = args[args.index("--output") + 1], args[-1]
source = os.path.join(os.environ["FAKE_DOWNLOADS"], url.rsplit("/", 1)[1])
if not url.startswith("https://github.com/") or not os.path.exists(source):
    print("curl: (22) The requested URL returned error: 404", file=sys.stderr); sys.exit(22)
shutil.copyfile(source, output)
'''

FAKE_BREW = "#!/usr/bin/env python3\n" + LOG + r'''
args = sys.argv[1:]
if args == ["install", "shellcheck"]:
    path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "shellcheck")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\necho 'version: %s'\n" % os.environ.get("FAKE_BREW_SHELLCHECK", "0.11.0"))
    os.chmod(path, 0o755)
else:
    sys.exit(64)
'''

FAKE_DOCKER = "#!/bin/sh\nif [ \"$1\" = compose ]; then echo 'Docker Compose version v2.0.0'; else echo 'Docker version 27.0.0'; fi\n"


def write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def archive_bytes(name, script):
    """A .tar.gz with one executable member called `name`, as the gitleaks and actionlint releases ship."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for member_name, text, mode in (("README.md", "readme\n", 0o644), (name, script, 0o755)):
            data = text.encode("utf-8")
            info = tarfile.TarInfo(member_name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def snapshot(root):
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
                with open(path, "rb") as handle:
                    state[rel] = ("file", handle.read())
    return state


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.factory = os.path.join(self.tmp, "factory")
        self.bin = os.path.join(self.tmp, "bin")
        self.state = os.path.join(self.tmp, "state")
        self.downloads = os.path.join(self.tmp, "downloads")
        for folder in (self.bin, self.state, self.downloads, os.path.join(self.factory, "scripts", "lib"),
                       os.path.join(self.factory, ".github", "tools", "pyright")):
            os.makedirs(folder)
        shutil.copy(os.path.join(ROOT, "scripts", "setup-tools.sh"), os.path.join(self.factory, "scripts"))
        for name in ("package.json", "package-lock.json"):
            shutil.copy(os.path.join(ROOT, ".github", "tools", "pyright", name),
                        os.path.join(self.factory, ".github", "tools", "pyright"))
        for name in ESSENTIALS:
            found = shutil.which(name)
            if found:
                os.symlink(found, os.path.join(self.bin, name))
        os.symlink(sys.executable, os.path.join(self.bin, "python3"))
        write_executable(os.path.join(self.bin, "cargo"), FAKE_CARGO)
        write_executable(os.path.join(self.bin, "npm"), FAKE_NPM)
        write_executable(os.path.join(self.bin, "node"), version_program("node", "v22.0.0"))
        write_executable(os.path.join(self.bin, "uv"), version_program("uv", "0.13.0"))
        write_executable(os.path.join(self.bin, "gh"), version_program("gh version", "2.0.0"))
        write_executable(os.path.join(self.bin, "docker"), FAKE_DOCKER)
        write_executable(os.path.join(self.bin, "curl"), FAKE_CURL)
        write_executable(os.path.join(self.bin, "brew"), FAKE_BREW)
        # The release archives the fake curl serves, and their hashes recorded in the copy of the pins file.
        hashes = {}
        for tool in ("gitleaks", "actionlint"):
            data = archive_bytes(tool, "#!/bin/sh\necho '%s'\n" % PIN[tool])
            hashes[tool] = hashlib.sha256(data).hexdigest()
            for platform in ("darwin_arm64", "darwin_x64", "darwin_amd64", "linux_x64", "linux_amd64", "linux_arm64"):
                with open(os.path.join(self.downloads, "%s_%s_%s.tar.gz" % (tool, PIN[tool], platform)), "wb") as out:
                    out.write(data)
        with open(os.path.join(ROOT, "scripts", "lib", "tool-pins.sh"), encoding="utf-8") as handle:
            pins = handle.read()
        pins = re.sub(r'^SHA256_GITLEAKS_([A-Z0-9_]+)="[0-9a-f]+"$', 'SHA256_GITLEAKS_\\1="%s"' % hashes["gitleaks"], pins, flags=re.M)
        pins = re.sub(r'^SHA256_ACTIONLINT_([A-Z0-9_]+)="[0-9a-f]+"$', 'SHA256_ACTIONLINT_\\1="%s"' % hashes["actionlint"], pins, flags=re.M)
        with open(os.path.join(self.factory, "scripts", "lib", "tool-pins.sh"), "w", encoding="utf-8") as handle:
            handle.write(pins)
        self.prefix_bin = os.path.join(self.factory, ".tools", "bin")

    # -- helpers -----------------------------------------------------------------------------
    def run_setup(self, *args, env=None):
        environment = {"PATH": self.bin, "FAKE_STATE": self.state, "FAKE_DOWNLOADS": self.downloads,
                       "HOME": os.path.join(self.tmp, "home"), "TMPDIR": self.tmp}
        environment.update(env or {})
        done = subprocess.run([BASH, os.path.join(self.factory, "scripts", "setup-tools.sh"), *args],
                              capture_output=True, text=True, env=environment)
        return done.returncode, done.stdout + done.stderr

    def has(self, out, state, step, detail=""):
        return re.search(r"(?m)^\s*%s\s+%s\s+%s" % (re.escape(state), re.escape(step), re.escape(detail)), out) is not None

    def calls(self):
        try:
            with open(os.path.join(self.state, "calls.log"), encoding="utf-8") as handle:
                return handle.read().splitlines()
        except FileNotFoundError:
            return []

    def installs(self):
        """The calls that download or install something (the fakes also log the questions about versions)."""
        return [c for c in self.calls() if c.startswith(("cargo install", "npm ci", "brew install", "curl "))]

    def put_tool(self, name, version):
        text = "#!/bin/sh\necho 'version: %s'\n" % version if name == "shellcheck" else version_program(name, version)
        write_executable(os.path.join(self.bin, name), text)

    def all_tools_at_pin(self):
        for tool in PINNED_TOOLS:
            self.put_tool(tool, PIN[tool])

    def tamper(self, tool):
        for name in os.listdir(self.downloads):
            if name.startswith(tool + "_"):
                with open(os.path.join(self.downloads, name), "ab") as handle:
                    handle.write(b"one more byte")


class PresentAtPin(Case):
    def test_tools_at_their_pins_are_present_and_nothing_is_installed(self):
        self.all_tools_at_pin()
        code, out = self.run_setup()
        self.assertEqual(code, 0, out)
        for tool in PINNED_TOOLS:
            self.assertTrue(self.has(out, "PRESENT", tool, PIN[tool]), out)
        self.assertEqual(out.rstrip().splitlines()[-1], "READY")
        self.assertEqual(self.installs(), [])
        self.assertFalse(os.path.exists(os.path.join(self.factory, ".tools")))

    def test_control_one_tool_at_another_version_is_not_present(self):
        self.all_tools_at_pin()
        self.put_tool("gitleaks", "8.0.0")
        code, out = self.run_setup("--check")
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "DRIFT", "gitleaks", "8.0.0 at"), out)
        self.assertFalse(self.has(out, "PRESENT", "gitleaks"), out)


class Installs(Case):
    def test_missing_tools_are_installed_at_their_pins_and_a_second_run_changes_nothing(self):
        code, out = self.run_setup()
        self.assertEqual(code, 0, out)
        for tool in PINNED_TOOLS:
            self.assertTrue(self.has(out, "ADDED", tool), tool + "\n" + out)
        for tool in ("cargo-nextest", "cargo-deny", "cargo-audit", "gitleaks", "actionlint", "pyright"):
            self.assertTrue(os.path.exists(os.path.join(self.prefix_bin, tool)), tool)
        calls = self.calls()
        prefix = os.path.join(self.factory, ".tools")
        self.assertIn("cargo install --locked --root %s cargo-deny --version %s" % (prefix, PIN["cargo-deny"]), calls)
        self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", calls)
        self.assertIn("brew install shellcheck", calls)
        self.assertTrue(any(c.startswith("curl ") and "/gitleaks_%s_" % PIN["gitleaks"] in c for c in calls), calls)
        self.assertTrue(self.has(out, "NOTE", "path", self.prefix_bin + " is not on your PATH"), out)
        before = len(self.installs())
        code, out = self.run_setup()
        self.assertEqual(code, 0, out)
        for tool in PINNED_TOOLS:
            self.assertTrue(self.has(out, "PRESENT", tool, PIN[tool]), tool + "\n" + out)
        self.assertEqual(len(self.installs()), before, "the second run installed something")

    def test_the_prefix_option_installs_elsewhere(self):
        elsewhere = os.path.join(self.tmp, "elsewhere")
        code, out = self.run_setup("--prefix", elsewhere)
        self.assertEqual(code, 0, out)
        self.assertTrue(os.path.exists(os.path.join(elsewhere, "bin", "gitleaks")))
        self.assertFalse(os.path.exists(os.path.join(self.factory, ".tools")))

    def test_a_tool_at_another_version_gets_the_pin_beside_it(self):
        self.all_tools_at_pin()
        self.put_tool("actionlint", "1.0.0")
        code, out = self.run_setup()
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "ADDED", "actionlint", PIN["actionlint"]), out)
        self.assertIn("1.0.0", out)  # the other copy is named, and was not touched
        with open(os.path.join(self.bin, "actionlint"), encoding="utf-8") as handle:
            self.assertIn("1.0.0", handle.read())

    def test_shellcheck_at_another_version_is_a_note_and_is_kept(self):
        self.all_tools_at_pin()
        self.put_tool("shellcheck", "0.9.0")
        code, out = self.run_setup()
        self.assertEqual(code, 0, out)
        self.assertTrue(self.has(out, "NOTE", "shellcheck", "0.9.0"), out)
        self.assertNotIn("brew install shellcheck", self.calls())


class WrongHash(Case):
    def test_a_wrong_hash_installs_nothing_and_fails(self):
        self.tamper("actionlint")
        code, out = self.run_setup()
        self.assertEqual(code, 1, out)
        self.assertTrue(self.has(out, "BLOCKED", "actionlint", "the archive's SHA-256 is"), out)
        self.assertIn("FAILED", out)
        # Nothing at all was installed: not the archive whose hash was right, not the cargo tools, not pyright.
        self.assertFalse(os.path.exists(os.path.join(self.factory, ".tools")), out)
        self.assertEqual([c for c in self.installs() if not c.startswith("curl ")], [], out)

    def test_control_the_same_run_with_the_right_archive_installs(self):
        code, out = self.run_setup()
        self.assertEqual(code, 0, out)
        self.assertTrue(os.path.exists(os.path.join(self.prefix_bin, "actionlint")))

    def test_a_check_run_downloads_nothing_so_it_cannot_see_a_wrong_hash(self):
        self.tamper("gitleaks")
        code, out = self.run_setup("--check")
        self.assertEqual(code, 3, out)
        self.assertEqual(self.installs(), [])


class CheckChangesNothing(Case):
    def test_check_reports_what_is_missing_and_writes_nothing(self):
        self.put_tool("cargo-deny", "0.1.0")
        before = [snapshot(self.factory), snapshot(self.bin)]
        code, out = self.run_setup("--check")
        self.assertEqual(code, 3, out)
        self.assertIn("Checking only. Nothing will be changed.", out)
        for tool in ("cargo-nextest", "cargo-audit", "gitleaks", "actionlint", "pyright"):
            self.assertTrue(self.has(out, "WOULD_ADD", tool, "would install %s" % PIN[tool]), tool + "\n" + out)
        self.assertTrue(self.has(out, "WOULD_ADD", "shellcheck", "would run: brew install shellcheck"), out)
        self.assertTrue(self.has(out, "DRIFT", "cargo-deny", "0.1.0 at"), out)
        self.assertIn("NOT READY", out)
        self.assertEqual(self.installs(), [])
        self.assertEqual(before, [snapshot(self.factory), snapshot(self.bin)])


class NeedsAPerson(Case):
    def test_without_rust_the_cargo_tools_need_a_person_and_the_rest_is_installed(self):
        os.remove(os.path.join(self.bin, "cargo"))
        code, out = self.run_setup()
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "cargo", "Rust is not installed"), out)
        for tool in ("cargo-nextest", "cargo-deny", "cargo-audit"):
            self.assertTrue(self.has(out, "NEEDS", tool, "cannot install: needs cargo"), out)
        self.assertTrue(self.has(out, "ADDED", "gitleaks"), out)
        self.assertEqual(out.count("rustup.rs"), 1, "the same advice is listed once")
        self.assertIn("NOT READY", out)

    def test_without_homebrew_a_missing_shellcheck_needs_a_person(self):
        self.all_tools_at_pin()
        os.remove(os.path.join(self.bin, "shellcheck"))
        os.remove(os.path.join(self.bin, "brew"))
        code, out = self.run_setup()
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "NEEDS", "shellcheck", "cannot install: needs Homebrew"), out)

    def test_missing_docker_uv_gh_and_node_are_reported_and_left_to_a_person(self):
        self.all_tools_at_pin()
        for name in ("docker", "uv", "gh", "node"):
            os.remove(os.path.join(self.bin, name))
        code, out = self.run_setup()
        self.assertEqual(code, 3, out)
        for name in ("docker", "uv", "gh", "node"):
            self.assertTrue(self.has(out, "NEEDS", name, "not installed"), name + "\n" + out)

    def test_a_download_that_fails_is_blocked_not_failed(self):
        self.all_tools_at_pin()
        os.remove(os.path.join(self.bin, "gitleaks"))
        for name in os.listdir(self.downloads):
            os.remove(os.path.join(self.downloads, name))
        code, out = self.run_setup()
        self.assertEqual(code, 3, out)
        self.assertTrue(self.has(out, "BLOCKED", "gitleaks", "could not download https://github.com/"), out)
        self.assertFalse(os.path.exists(os.path.join(self.prefix_bin, "gitleaks")))


class Arguments(Case):
    def test_an_unknown_argument_is_refused(self):
        code, out = self.run_setup("--no-such-flag")
        self.assertEqual(code, 2, out)

    def test_help_names_every_option(self):
        code, out = self.run_setup("--help")
        self.assertEqual(code, 0, out)
        for flag in ("--check", "--prefix", "--help"):
            self.assertIn(flag, out)


if __name__ == "__main__":
    unittest.main()
