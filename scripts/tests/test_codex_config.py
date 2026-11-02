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
            (BLOCK.replace("api.githubcopilot.com", "example.com"), "different"),
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
