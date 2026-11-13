#!/usr/bin/env python3
"""Tests for the owner's tools of the first real run (docs/guides/first-real-run.md). Standard
library only, and no network: nothing here calls GitHub. Run it with:
    python3 -I scripts/tests/test_first_real_run.py

* scripts/github_app_manifest.py writes a manifest whose permissions are exactly the ones
  policies/security.yaml requires, with no webhook and no event, and a page that posts it.
* scripts/setup-fixture-repository.sh --check shows the gh calls it would make, a CODEOWNERS with
  real owners only, and a ruleset that pins both checks to the App, and changes nothing. The
  repository is public unless --private is given (GitHub Free has rulesets only on public
  repositories), and the copy holds nothing that looks like a secret.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MANIFEST_TOOL = ROOT / "scripts" / "github_app_manifest.py"
SETUP_TOOL = ROOT / "scripts" / "setup-fixture-repository.sh"


def load_manifest_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("github_app_manifest", MANIFEST_TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load_manifest_module()


class TheManifest(unittest.TestCase):
    def test_the_permissions_are_the_policys_and_none_is_forbidden(self) -> None:
        required, forbidden = TOOL.read_policy()
        self.assertEqual(required.get("administration"), "read")
        self.assertEqual(required.get("contents"), "write")
        self.assertEqual(required.get("metadata"), "read")
        self.assertFalse(set(required) & set(forbidden))
        self.assertIn("workflows", forbidden)
        document = TOOL.manifest("factory", "https://github.com", 8973, required)
        self.assertEqual(document["default_permissions"], required)
        self.assertIs(document["public"], False)

    def test_the_app_has_no_webhook(self) -> None:
        required, _ = TOOL.read_policy()
        document = TOOL.manifest("factory", "https://github.com", 8973, required)
        self.assertNotIn("hook_attributes", document)
        self.assertEqual(document["default_events"], [])

    def test_render_writes_the_manifest_and_a_page_that_posts_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "app"
            done = subprocess.run(
                [sys.executable, "-I", str(MANIFEST_TOOL), "render", "--out", str(out), "--org", "acme"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr)
            written = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            required, _ = TOOL.read_policy()
            self.assertEqual(written["default_permissions"], required)
            page = (out / "create-github-app.html").read_text(encoding="utf-8")
            self.assertIn("https://github.com/organizations/acme/settings/apps/new?state=", page)
            self.assertIn('name="manifest"', page)
            self.assertEqual(os.stat(out / "state").st_mode & 0o077, 0)

    def test_a_policy_that_requires_a_forbidden_permission_is_refused(self) -> None:
        text = (ROOT / "policies" / "security.yaml").read_text(encoding="utf-8")
        broken = text.replace("      administration: read\n", "      administration: read\n      workflows: write\n", 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "security.yaml"
            path.write_text(broken, encoding="utf-8")
            with self.assertRaises(TOOL.PolicyError):
                TOOL.read_policy(path)

    def test_a_code_that_is_not_a_code_is_refused_before_any_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for code in ["", "abc/../x", "a b"]:
                with self.assertRaises(ValueError):
                    TOOL.convert(code, Path(directory))


def setup(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SETUP_TOOL), *args], capture_output=True, text=True, check=False, cwd=ROOT
    )


class TheFixtureSetupInCheckMode(unittest.TestCase):
    def test_it_shows_each_gh_call_and_changes_nothing(self) -> None:
        before = sorted(p.name for p in (ROOT / "target").glob("e2e-fixture/*")) if (ROOT / "target").exists() else []
        done = setup("--check", "--app-id", "424242", "--owner", "@the-owner", "someone/fixture")
        self.assertEqual(done.returncode, 0, done.stderr)
        out = done.stdout
        self.assertIn("gh repo create someone/fixture --public", out)
        self.assertIn("anyone can read its code, its issues", out)
        self.assertIn("nothing in the copy looks like a secret", out)
        self.assertIn("gh label create factory --repo someone/fixture", out)
        self.assertIn("gh api --method POST repos/someone/fixture/rulesets --input", out)
        self.assertIn("gh api repos/someone/fixture/rulesets", out)
        self.assertIn("Nothing was done (--check)", out)
        after = sorted(p.name for p in (ROOT / "target").glob("e2e-fixture/*")) if (ROOT / "target").exists() else []
        self.assertEqual(before, after)

    def test_the_code_owners_are_real_and_the_checks_are_pinned_to_the_app(self) -> None:
        out = setup("--check", "--app-id", "424242", "--owner", "@the-owner", "someone/fixture").stdout
        self.assertNotIn("@example-org/", out)
        self.assertIn("* @the-owner", out)
        self.assertEqual(out.count('"integration_id": 424242'), 2)
        self.assertIn('"bypass_actors": []', out)
        self.assertIn('"require_code_owner_review": true', out)
        self.assertIn('"dismiss_stale_reviews_on_push": true', out)
        self.assertIn('{ "type": "non_fast_forward" }', out)
        self.assertIn('{ "type": "deletion" }', out)

    def test_the_factorys_fixture_is_public_by_default_and_private_on_request(self) -> None:
        public = setup("--check", "--app-id", "424242", "ortisun/factory-fixture-word-count")
        self.assertEqual(public.returncode, 0, public.stderr)
        self.assertIn("== 3. The public repository", public.stdout)
        self.assertIn("gh repo create ortisun/factory-fixture-word-count --public", public.stdout)
        self.assertIn("gh repo create ortisun/factory-fixture-word-count --public", setup(
            "--check", "--app-id", "424242", "--public", "ortisun/factory-fixture-word-count"
        ).stdout)
        private = setup("--check", "--app-id", "424242", "--private", "someone/fixture")
        self.assertEqual(private.returncode, 0, private.stderr)
        self.assertIn("gh repo create someone/fixture --private", private.stdout)
        self.assertNotIn("--public", private.stdout)
        self.assertNotIn("anyone can read", private.stdout)

    def test_the_usage_explains_why_public_is_the_default(self) -> None:
        out = setup("--help").stdout
        self.assertIn("--public", out)
        self.assertIn("GitHub Free offers rulesets only on", out)
        self.assertIn("ortisun/factory-fixture-word-count", out)

    def test_wrong_usage_is_refused(self) -> None:
        self.assertEqual(setup("--check", "--app-id", "1", "--public", "--private", "a/b").returncode, 2)
        self.assertEqual(setup("--check", "--app-id", "x", "a/b").returncode, 2)
        self.assertEqual(setup("--check", "--app-id", "1", "not-a-repository").returncode, 2)
        self.assertEqual(setup("--check", "--app-id", "1", "--owner", "@example-org/core", "a/b").returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
