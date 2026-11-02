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


if __name__ == "__main__":
    unittest.main()
