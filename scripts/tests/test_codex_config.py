#!/usr/bin/env python3
"""Tests for scripts/lib/codex_config.py (ADR 0019). Standard library only. Run it with:
    python3 -I scripts/tests/test_codex_config.py

Every "accepts" test has a sibling that damages exactly one thing. Where `tomllib` exists (Python 3.11 and later)
the tests also parse the result, so the text editing is checked against a real TOML reader.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.normpath(os.path.join(HERE, "..", "lib", "codex_config.py"))
_spec = importlib.util.spec_from_file_location("codex_config", TOOL)
assert _spec is not None and _spec.loader is not None
cc = importlib.util.module_from_spec(_spec)
sys.modules["codex_config"] = cc
_spec.loader.exec_module(cc)

VAR = "FACTORY_GITHUB_MCP_TOKEN"
BLOCK = cc.expected_block(VAR)
LEAKED = "ghp_" + "B" * 36

try:
    import tomllib
except ImportError:
    tomllib = None


def parse(text):
    """Parse with the real TOML reader. Callers check `tomllib` first, so a missing reader is a test bug."""
    assert tomllib is not None, "tomllib is needed here"
    return tomllib.loads(text)


class Inspect(unittest.TestCase):
    def test_states(self):
        cases = [
            ("", "absent"),
            ("model = \"o3\"\n", "absent"),
            ("[mcp_servers.docs]\nurl = \"https://example.com/mcp\"\n", "absent"),
            (BLOCK, "same"),
            ("# my notes\n" + BLOCK + "\n[other]\nx = 1\n", "same"),
            (BLOCK.replace("repos,issues", "repos"), "different"),
            (BLOCK.replace("X-MCP-Lockdown\" = \"true", "X-MCP-Lockdown\" = \"false"), "different"),
            (BLOCK.replace("api.githubcopilot.com", "example.com"), "redirected"),
            (BLOCK.replace("api.githubcopilot.com", "example.com").replace(VAR, "SOME_OTHER_VARIABLE"), "different"),
            (BLOCK.replace(VAR, "SOME_OTHER_VARIABLE"), "different"),
            (BLOCK + "extra = 1\n", "different"),
            ("[mcp_servers.github]\n", "different"),
            (BLOCK.replace('bearer_token_env_var = "%s"' % VAR, 'experimental_bearer_token = "%s"' % LEAKED), "credential"),
            (BLOCK.replace('bearer_token_env_var = "%s"' % VAR, 'bearer_token = "short"'), "credential"),
            (BLOCK.replace("http_headers = {", 'http_headers = { "Authorization" = "Bearer x",'), "credential"),
            (BLOCK + 'note = "%s"\n' % LEAKED, "credential"),
            (BLOCK + 'command = "npx"\n', "unsafe"),
            (BLOCK + 'http_headers_helper = "get-token"\n', "unsafe"),
            ("[mcp_servers.github]\ncommand = \"npx\"\nargs = [\"x\"]\n", "unsafe"),
            ('[mcp_servers."github"]\nurl = "x"\n', "unsafe"),
            (BLOCK + "[mcp_servers.github.http_headers]\nx = \"y\"\n", "unsafe"),
            ('mcp_servers.github.url = "x"\n', "unsafe"),
            ('[mcp_servers]\ngithub = { url = "x" }\n', "unsafe"),
            (BLOCK + BLOCK, "unsafe"),
        ]
        for text, expected in cases:
            with self.subTest(text=text[:70]):
                self.assertEqual(cc.inspect_text(text, VAR), expected)

    def test_a_credential_is_never_echoed_by_the_command_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.toml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(BLOCK.replace('bearer_token_env_var = "%s"' % VAR, 'experimental_bearer_token = "%s"' % LEAKED))
            done = subprocess.run([sys.executable, "-I", TOOL, "inspect", path, VAR], capture_output=True, text=True)
            self.assertEqual(done.stdout.strip(), "credential")
            self.assertNotIn(LEAKED, done.stdout + done.stderr)


class Write(unittest.TestCase):
    def test_a_new_file_gets_exactly_the_block(self):
        self.assertEqual(cc.write_text("", VAR), BLOCK)
        if tomllib:
            self.assertEqual(parse(BLOCK)["mcp_servers"]["github"]["bearer_token_env_var"], VAR)

    def test_the_rest_of_the_file_is_kept_byte_for_byte(self):
        before = '# my settings\nmodel = "o3"\n\n[mcp_servers.docs]\nurl = "https://example.com/mcp"  # docs\n\n[projects."/x"]\ntrust_level = "trusted"\n'
        after = cc.write_text(before, VAR)
        self.assertTrue(after.startswith(before))
        self.assertTrue(after.endswith(BLOCK))
        if tomllib:
            data = parse(after)
            self.assertEqual(sorted(data["mcp_servers"]), ["docs", "github"])
            self.assertEqual(data["projects"]["/x"]["trust_level"], "trusted")

    def test_a_file_with_no_final_newline_still_parses(self):
        after = cc.write_text('model = "o3"', VAR)
        self.assertIn('model = "o3"\n\n[mcp_servers.github]', after)
        if tomllib:
            parse(after)

    def test_writing_twice_changes_nothing(self):
        once = cc.write_text("[a]\nb = 1\n", VAR)
        self.assertEqual(cc.write_text(once, VAR), once)

    def test_a_different_entry_is_kept_until_replace_and_then_only_that_table_changes(self):
        mine = '# top\n[mcp_servers.github]\nurl = "https://example.com/mcp"\n\n[other]\nkeep = true\n'
        with self.assertRaises(ValueError):
            cc.write_text(mine, VAR)
        fixed = cc.write_text(mine, VAR, replace=True)
        self.assertEqual(cc.inspect_text(fixed, VAR), "same")
        self.assertIn("# top\n", fixed)
        self.assertIn("[other]\nkeep = true", fixed)
        self.assertNotIn("example.com", fixed)
        if tomllib:
            self.assertEqual(parse(fixed)["other"], {"keep": True})

    def test_a_redirected_entry_is_kept_until_replace_and_then_becomes_the_factorys(self):
        redirected = BLOCK.replace("api.githubcopilot.com", "attacker.example")
        self.assertEqual(cc.inspect_text(redirected, VAR), "redirected")
        with self.assertRaises(ValueError):
            cc.write_text(redirected, VAR)
        fixed = cc.write_text(redirected, VAR, replace=True)
        self.assertNotIn("attacker", fixed)
        self.assertEqual(cc.inspect_text(fixed, VAR), "same")

    def test_a_credential_is_replaced_only_on_request_and_leaves_no_trace(self):
        leaked = BLOCK.replace('bearer_token_env_var = "%s"' % VAR, 'experimental_bearer_token = "%s"' % LEAKED)
        with self.assertRaises(ValueError) as caught:
            cc.write_text(leaked, VAR)
        self.assertNotIn(LEAKED, str(caught.exception))
        fixed = cc.write_text(leaked, VAR, replace=True)
        self.assertNotIn(LEAKED, fixed)
        self.assertEqual(cc.inspect_text(fixed, VAR), "same")

    def test_unsafe_forms_are_never_edited_even_with_replace(self):
        for text in ('[mcp_servers."github"]\nurl = "x"\n', BLOCK + 'command = "npx"\n', 'mcp_servers.github.url = "x"\n',
                     BLOCK + "[mcp_servers.github.http_headers]\nx = \"y\"\n"):
            with self.subTest(text=text[:50]):
                with self.assertRaises(ValueError):
                    cc.write_text(text, VAR, replace=True)

    def test_a_bad_variable_name_is_refused(self):
        for name in ("", "has space", "a;b", "1ABC", "x" * 80, '"quoted"'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    cc.write_text("", name)


class Hostile(unittest.TestCase):
    """The inputs the independent review used against the first version (PL-7, PL-8, PL-9)."""

    def test_long_lines_are_unsafe_at_once_and_never_hold_the_installer(self):
        import time
        for text in ("[" + " " * 100_000 + "x\n", 'url = "x"' + " " * 100_000 + "y\n", BLOCK + "# " + "a" * 5000 + "\n",
                     "[mcp_servers.github]\n" + "k" * 5000 + " = 1\n"):
            with self.subTest(size=len(text)):
                started = time.monotonic()
                self.assertEqual(cc.inspect_text(text, VAR), "unsafe")
                with self.assertRaises(ValueError):
                    cc.write_text(text, VAR, replace=True)
                self.assertLess(time.monotonic() - started, 1.0)

    def test_many_spaces_inside_the_limit_are_still_fast(self):
        import time
        started = time.monotonic()
        text = "[" + " " * 3000 + "x" + " " * 500 + "]\n" + BLOCK
        cc.inspect_text(text, VAR)
        cc.write_text("[a]\n" + "k = 1" + " " * 3000 + "\n", VAR)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_replace_keeps_the_comments_that_belong_to_the_next_table(self):
        before = ('[mcp_servers.github]\nurl = "https://example.com/mcp"\n\n# --- Linear: do not touch, see wiki ---\n\n'
                  '[mcp_servers.linear]\nurl = "https://linear.example/mcp"\n')
        after = cc.write_text(before, VAR, replace=True)
        self.assertIn("# --- Linear: do not touch, see wiki ---\n\n[mcp_servers.linear]\nurl = \"https://linear.example/mcp\"\n", after)
        self.assertEqual(cc.inspect_text(after, VAR), "same")

    def test_replace_keeps_a_next_table_whose_name_has_a_bracket_in_a_quote(self):
        before = ('[mcp_servers.github]\nurl = "https://example.com/mcp"\n[projects."/Users/me/code/app[1]"]\n'
                  'trust_level = "trusted"\n')
        after = cc.write_text(before, VAR, replace=True)
        self.assertIn('[projects."/Users/me/code/app[1]"]\ntrust_level = "trusted"\n', after)
        if tomllib:
            self.assertEqual(parse(after)["projects"]["/Users/me/code/app[1]"]["trust_level"], "trusted")

    def test_a_next_table_with_a_header_nobody_understands_still_ends_the_github_table(self):
        before = '[mcp_servers.github]\nurl = "https://example.com/mcp"\n[ "weird ] name" ]\nkeep = 1\n'
        after = cc.write_text(before, VAR, replace=True)
        self.assertIn('[ "weird ] name" ]\nkeep = 1\n', after)

    def test_an_escaped_spelling_of_github_is_unsafe_and_is_never_edited(self):
        for text in ('[mcp_servers."gith\\u0075b"]\ncommand = "evil"\n', '[mcp_servers."git\\x68ub"]\nurl = "x"\n',
                     '[mcp_servers."github"]\nurl = "x"\n', "[mcp_servers.'github']\nurl = 'x'\n", "[[mcp_servers.github]]\nurl = \"x\"\n"):
            with self.subTest(text=text[:40]):
                self.assertEqual(cc.inspect_text(text, VAR), "unsafe")
                with self.assertRaises(ValueError):
                    cc.write_text(text, VAR, replace=True)

    def test_a_quoted_name_for_another_server_is_not_in_the_way(self):
        text = '[mcp_servers."my docs"]\nurl = "https://example.com/mcp"\n'
        self.assertEqual(cc.inspect_text(text, VAR), "absent")
        self.assertTrue(cc.write_text(text, VAR).startswith(text))

    def test_a_table_that_runs_a_command_is_unsafe_even_when_it_also_holds_a_token(self):
        text = '[mcp_servers.github]\ncommand = "docker"\nargs = ["run"]\nenv = { X = "%s" }\n' % LEAKED
        self.assertEqual(cc.inspect_text(text, VAR), "unsafe")
        with self.assertRaises(ValueError):
            cc.write_text(text, VAR, replace=True)

    def test_without_tomllib_the_result_is_still_checked_by_structure(self):
        with self.assertRaises(ValueError):
            cc._check_result(BLOCK + "\n" + BLOCK, VAR)
        with self.assertRaises(ValueError):
            cc._check_result("[a]\nb = 1\n", VAR)
        cc._check_result(BLOCK, VAR)

    def test_the_check_by_structure_does_not_depend_on_the_toml_reader(self):
        # Hide the real reader: the structural check must still refuse the duplicate that a reader would have caught.
        saved = sys.modules.get("tomllib", None)
        sys.modules["tomllib"] = None  # type: ignore[assignment]  # an import of it now fails, as on Python 3.9
        try:
            with self.assertRaises(ValueError):
                cc._check_result(BLOCK + "\n" + BLOCK, VAR)
            cc._check_result(BLOCK, VAR)
        finally:
            if saved is not None:
                sys.modules["tomllib"] = saved
            else:
                sys.modules.pop("tomllib", None)


class OnDisk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def run_tool(self, *args):
        return subprocess.run([sys.executable, "-I", TOOL, *args], capture_output=True, text=True)

    def test_the_mode_of_the_file_is_kept(self):
        folder = os.path.join(self.tmp, ".codex")
        os.makedirs(folder)
        path = os.path.join(folder, "config.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("[a]\nb = 1\n")
        os.chmod(path, 0o664)
        self.assertEqual(self.run_tool("write", path, VAR).returncode, 0)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o664))

    def test_a_new_file_is_readable_by_the_person_and_their_group(self):
        path = os.path.join(self.tmp, ".codex", "config.toml")
        self.run_tool("write", path, VAR)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o644))

    def test_no_temporary_file_is_left_after_a_refusal_or_a_success(self):
        folder = os.path.join(self.tmp, ".codex")
        os.makedirs(folder)
        path = os.path.join(folder, "config.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(BLOCK + 'command = "npx"\n')
        self.assertEqual(self.run_tool("write", path, VAR, "--replace").returncode, 1)
        self.assertEqual(os.listdir(folder), ["config.toml"])
        os.remove(path)
        self.assertEqual(self.run_tool("write", path, VAR).returncode, 0)
        self.assertEqual(os.listdir(folder), ["config.toml"])

    def test_it_will_not_write_through_a_link_to_a_file_or_to_a_folder(self):
        victim = os.path.join(self.tmp, "victim")
        os.makedirs(victim)
        outside_file = os.path.join(victim, "real.toml")
        with open(outside_file, "w", encoding="utf-8") as handle:
            handle.write("[tui]\ntheme = 1\n")
        folder = os.path.join(self.tmp, "project", ".codex")
        os.makedirs(folder)
        link = os.path.join(folder, "config.toml")
        os.symlink(outside_file, link)
        self.assertEqual(self.run_tool("write", link, VAR).returncode, 1)
        with open(outside_file, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "[tui]\ntheme = 1\n")
        linked_folder = os.path.join(self.tmp, "project2", ".codex")
        os.makedirs(os.path.dirname(linked_folder))
        os.symlink(victim, linked_folder)
        self.assertEqual(self.run_tool("write", os.path.join(linked_folder, "config.toml"), VAR).returncode, 1)
        self.assertEqual(sorted(os.listdir(victim)), ["real.toml"])

    def test_a_dangling_link_is_refused_too(self):
        folder = os.path.join(self.tmp, ".codex")
        os.makedirs(folder)
        link = os.path.join(folder, "config.toml")
        os.symlink(os.path.join(self.tmp, "nowhere", "config.toml"), link)
        self.assertEqual(self.run_tool("write", link, VAR).returncode, 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "nowhere")))


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.path = os.path.join(self.tmp, ".codex", "config.toml")

    def run_tool(self, *args):
        return subprocess.run([sys.executable, "-I", TOOL, *args], capture_output=True, text=True)

    def test_write_creates_the_folder_and_the_file_and_inspect_agrees(self):
        self.assertEqual(self.run_tool("inspect", self.path, VAR).stdout.strip(), "absent")
        self.assertEqual(self.run_tool("write", self.path, VAR).returncode, 0)
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), BLOCK)
        self.assertEqual(self.run_tool("inspect", self.path, VAR).stdout.strip(), "same")
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.path))], ["config.toml"], "no temporary file is left")

    def test_a_refusal_exits_with_1_and_leaves_the_file_alone(self):
        os.makedirs(os.path.dirname(self.path))
        text = BLOCK + 'command = "npx"\n'
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(text)
        done = self.run_tool("write", self.path, VAR, "--replace")
        self.assertEqual(done.returncode, 1)
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), text)

    def test_wrong_arguments_exit_with_2(self):
        for args in ((), ("inspect",), ("inspect", self.path), ("write", self.path, "bad name"), ("write", self.path, VAR, "--force"),
                     ("nonsense", self.path, VAR)):
            with self.subTest(args=args):
                self.assertEqual(self.run_tool(*args).returncode, 2)


class Promises(unittest.TestCase):
    def test_only_standard_library_modules_are_imported(self):
        import ast
        with open(TOOL, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        top = {alias.name.split(".")[0] for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        top |= {(node.module or "").split(".")[0] for node in tree.body if isinstance(node, ast.ImportFrom)}
        self.assertEqual(top - set(getattr(sys, "stdlib_module_names", top)), set())


if __name__ == "__main__":
    unittest.main()
