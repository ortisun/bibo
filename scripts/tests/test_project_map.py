#!/usr/bin/env python3
"""Tests for scripts/lib/project_map.py (ADR 0016). Standard library only. Run it with:
    python3 -I scripts/tests/test_project_map.py

Each test builds a small project in a temporary directory, shows what the checker says, then changes exactly one
thing and shows that the answer changes. Tests that need git skip themselves loudly when git is missing.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.normpath(os.path.join(HERE, "..", "lib", "project_map.py"))


def build(root, files):
    for relative, text in files.items():
        path = os.path.join(root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)


def check(root, *extra):
    done = subprocess.run([sys.executable, "-I", TOOL, "check", root, *extra], capture_output=True, text=True)
    return done.returncode, done.stdout


class Mapping(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_a_fully_mapped_project_passes(self):
        build(self.tmp, {"README.md": "# root", "src/README.md": "# src", "src/a.py": "x=1", "src/deep/EGM.md": "# deep",
                         "src/deep/b.rs": "fn main(){}"})
        code, out = check(self.tmp)
        self.assertEqual(code, 0, out)
        self.assertIn("MAPPED", out)

    def test_a_missing_contract_is_listed_and_fails(self):
        build(self.tmp, {"README.md": "# root", "src/README.md": "# src", "src/a.py": "x=1", "src/deep/b.rs": "fn main(){}"})
        code, out = check(self.tmp)
        self.assertEqual(code, 1)
        self.assertIn("MISSING src/deep", out)
        self.assertNotIn("MISSING src\n", out)

    def test_the_root_always_needs_a_contract(self):
        build(self.tmp, {"docs/guide.txt": "words"})
        code, out = check(self.tmp)
        self.assertEqual((code, "MISSING ." in out), (1, True))

    def test_an_intermediate_directory_needs_one_because_a_directory_below_it_holds_code(self):
        build(self.tmp, {"README.md": "#", "a/b/c.go": "package c", "a/b/README.md": "#"})
        code, out = check(self.tmp)
        self.assertEqual((code, "MISSING a" in out), (1, True), out)

    def test_directories_without_code_do_not_need_one(self):
        build(self.tmp, {"README.md": "#", "assets/logo.png": "x", "docs/notes.md": "words", "data/rows.csv": "1,2"})
        self.assertEqual(check(self.tmp)[0], 0)

    def test_test_only_and_system_directories_are_skipped(self):
        build(self.tmp, {"README.md": "#", "tests/t.py": "x", "tests/inner/u.py": "x", "testdata/d.py": "x",
                         "node_modules/pkg/i.js": "x", "target/debug/b.rs": "x", "third_party/lib/l.c": "x"})
        self.assertEqual(check(self.tmp)[0], 0)

    def test_hidden_directories_are_skipped_so_the_installed_helper_does_not_count(self):
        build(self.tmp, {"README.md": "#", ".github/scripts/issue_workflow.py": "x", ".tooling/run.sh": "x"})
        self.assertEqual(check(self.tmp)[0], 0)
        build(self.tmp, {"visible/run.sh": "x"})
        self.assertEqual(check(self.tmp)[0], 1)

    def test_egmignore_is_honored(self):
        build(self.tmp, {"README.md": "#", "vendor/v.py": "x", ".egmignore": "# comment\nvendor\n"})
        self.assertEqual(check(self.tmp)[0], 0)
        os.remove(os.path.join(self.tmp, ".egmignore"))
        self.assertEqual(check(self.tmp)[0], 1)

    def test_a_chosen_contract_name_replaces_the_default(self):
        build(self.tmp, {"EGM.md": "#", "a.py": "x"})
        self.assertEqual(check(self.tmp)[0], 0)
        self.assertEqual(check(self.tmp, "--contract", "README.md")[0], 1)

    def test_a_missing_directory_is_a_usage_error(self):
        self.assertEqual(check(os.path.join(self.tmp, "nowhere"))[0], 2)

    @unittest.skipUnless(shutil.which("git"), "git is not installed, so the .gitignore tests did not run")
    def test_gitignore_is_honored(self):
        build(self.tmp, {"README.md": "#", "gen/out.py": "x", ".gitignore": "gen/\n"})
        subprocess.run(["git", "init", "-q", self.tmp], check=True)
        self.assertEqual(check(self.tmp)[0], 0)
        with open(os.path.join(self.tmp, ".gitignore"), "w", encoding="utf-8") as handle:
            handle.write("")
        self.assertEqual(check(self.tmp)[0], 1)


class HostileCheckout(unittest.TestCase):
    """The checkout is not trusted (PL-10, PL-18)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    @unittest.skipUnless(shutil.which("git"), "git is not installed, so the fsmonitor tests did not run")
    def test_the_command_a_checkout_names_as_its_file_system_monitor_is_not_run(self):
        build(self.tmp, {"README.md": "#", "src/a.py": "x=1\n", "src/README.md": "#"})
        subprocess.run(["git", "init", "-q", self.tmp], check=True)
        marker = os.path.join(self.tmp, "..", os.path.basename(self.tmp) + ".ran")
        script = os.path.join(self.tmp, "..", os.path.basename(self.tmp) + ".monitor.sh")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\ntouch '%s'\nexit 0\n" % marker)
        os.chmod(script, 0o755)
        self.addCleanup(lambda: [os.path.exists(f) and os.remove(f) for f in (marker, script)])
        subprocess.run(["git", "-C", self.tmp, "config", "core.fsmonitor", script], check=True)
        # The control: plain git does run it. Without this, a silent test would prove nothing.
        subprocess.run(["git", "-C", self.tmp, "ls-files", "--cached", "--others", "--exclude-standard"], capture_output=True)
        if not os.path.exists(marker):
            self.skipTest("this git does not run core.fsmonitor for ls-files, so the control cannot show the risk")
        os.remove(marker)
        code, out = check(self.tmp)
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(marker), "the checkout's file system monitor ran")

    def test_an_egmignore_that_is_a_link_is_not_followed(self):
        outside = os.path.join(self.tmp, "outside-patterns")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("*\n")
        project = os.path.join(self.tmp, "p")
        build(project, {"README.md": "#", "src/a.py": "x=1\n"})
        os.symlink(outside, os.path.join(project, ".egmignore"))
        code, out = check(project)
        self.assertEqual(code, 1, "the link's patterns would have ignored everything; they were not read")
        self.assertIn("MISSING src", out)

    def test_the_number_and_the_length_of_patterns_are_capped(self):
        project = os.path.join(self.tmp, "p")
        patterns = ["never-matches-%d" % i for i in range(600)] + ["src"]
        build(project, {"README.md": "#", "src/a.py": "x=1\n", ".egmignore": "\n".join(patterns) + "\n"})
        self.assertEqual(check(project)[0], 1, "pattern 601 is past the cap of 500, so it did not apply")
        build(project, {".egmignore": "\n".join(["src"] + ["x%d" % i for i in range(600)]) + "\n"})
        self.assertEqual(check(project)[0], 0, "a pattern inside the cap applies")
        build(project, {".egmignore": "s" + "r" * 300 + "\n"})
        self.assertEqual(check(project)[0], 1, "a pattern of 301 characters is skipped, not matched")

    def test_a_tree_with_too_many_files_is_refused_not_walked_for_ever(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("project_map", TOOL)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        setattr(module, "MAX_FILES", 5)
        build(self.tmp, {"f%d.txt" % i: "x" for i in range(20)})
        with self.assertRaises(ValueError):
            module._walk_files(self.tmp)


if __name__ == "__main__":
    unittest.main()
