#!/usr/bin/env python3
"""Tests for scripts/lib/project_board.py (ADR 0018).

Needs PyYAML, because the policy is YAML. Run it with:
    uv run --no-project --with pyyaml==6.0.3 python -I scripts/tests/test_project_board.py

No network and no GitHub: the one function that calls `gh` is replaced by a recorder, and the command line tests use
a fake `gh` program. Each test builds a correct input, shows what happens, then damages exactly one thing and shows
that the result changes.
"""
import ast
import copy
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:
    print("BLOCKED: PyYAML is not installed (uv run --no-project --with pyyaml==6.0.3 python -I ...)")
    sys.exit(3)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
TOOL = os.path.join(ROOT, "scripts", "lib", "project_board.py")

_spec = importlib.util.spec_from_file_location("project_board", TOOL)
assert _spec is not None and _spec.loader is not None
pb = importlib.util.module_from_spec(_spec)
sys.modules["project_board"] = pb
_spec.loader.exec_module(pb)

DUMMY_TOKEN = "dummy-board-value-that-is-not-a-secret-777"


def read(path):
    with open(path, "rb") as handle:
        return handle.read()


def real_policy():
    return yaml.safe_load(read(pb.DEFAULT_POLICY))


def workflow_config():
    return json.loads(read(pb.DEFAULT_WORKFLOW_CONFIG))


def config():
    return json.loads(pb.render(real_policy(), read(pb.DEFAULT_POLICY)))


def problems(policy, workflow=None):
    return pb.check_policy(policy, workflow if workflow is not None else workflow_config())


class PolicyCheck(unittest.TestCase):
    def test_the_real_policy_is_sound(self):
        self.assertEqual(problems(real_policy()), [])

    def test_each_damage_is_named(self):
        def unknown_top(p):
            p["surprise"] = 1

        def version(p):
            p["schema_version"] = 2

        def rule_to_nowhere(p):
            p["rules"][0]["stage"] = "vanished"

        def stage_never_reached(p):
            p["rules"] = [r for r in p["rules"] if r["stage"] != "designing"]

        def trigger_in_rule(p):
            p["rules"][0]["labels_any"].append("factory")

        def unknown_label(p):
            p["rules"][0]["labels_any"].append("factory: dreaming")

        def label_left_out(p):
            p["rules"] = [r for r in p["rules"] if r["stage"] != "idea"]
            p["rules"].append({"stage": "idea", "labels_any": ["design: in progress"]})

        def fallback_unknown(p):
            p["stages"][0]["fallback"] = ["vanished"]

        def fallback_loop(p):
            for stage in p["stages"]:
                if stage["key"] == "ready":
                    stage["fallback"] = ["idea"]

        def self_fallback(p):
            p["stages"][0]["fallback"] = ["idea"]

        def duplicate_stage(p):
            p["stages"].append(copy.deepcopy(p["stages"][0]))

        def duplicate_title(p):
            p["stages"][1]["title"] = "IDEA!"

        def matches_not_normal(p):
            p["stages"][0]["matches"] = ["Backlog"]

        def both_conditions(p):
            p["rules"][1]["labels_any"] = ["factory: done"]

        def no_condition(p):
            p["rules"][0] = {"stage": "stopped"}

        def closed_false(p):
            p["rules"][1]["issue_closed"] = False

        def long_title(p):
            p["stages"][0]["title"] = "x" * 60

        for damage, expected in (
            (unknown_top, "unknown-key"), (version, "schema-version"), (rule_to_nowhere, "rule-stage"),
            (stage_never_reached, "unreached-stage"), (trigger_in_rule, "trigger-label"), (unknown_label, "unknown-label"),
            (label_left_out, "uncovered-label"), (fallback_unknown, "fallback:"), (fallback_loop, "fallback-loop"),
            (self_fallback, "fallback-loop"), (duplicate_stage, "duplicate-stage"), (duplicate_title, "duplicate-title"),
            (matches_not_normal, "matches"), (both_conditions, "rule-condition"), (no_condition, "rule-condition"),
            (closed_false, "rule-condition"), (long_title, "title"),
        ):
            with self.subTest(damage=damage.__name__):
                policy = copy.deepcopy(real_policy())
                damage(policy)
                found = problems(policy)
                self.assertTrue(any(expected in line for line in found), (expected, found))

    def test_a_new_issue_workflow_label_with_no_rule_is_caught(self):
        workflow = workflow_config()
        workflow["labels"].append({"name": "factory: archived", "color": "ffffff", "description": "x", "kind": "factory"})
        found = problems(real_policy(), workflow)
        self.assertTrue(any("uncovered-label" in line and "factory: archived" in line for line in found), found)


class Rendering(unittest.TestCase):
    def test_the_checked_in_rendering_is_current(self):
        self.assertEqual(read(pb.DEFAULT_RENDERED).decode(), pb.render(real_policy(), read(pb.DEFAULT_POLICY)))

    def test_the_cli_accepts_the_real_files_and_reports_a_stale_rendering(self):
        done = subprocess.run([sys.executable, "-I", TOOL, "check"], capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout.startswith("OK")), (0, True), done.stdout + done.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            stale = os.path.join(tmp, "p.json")
            with open(stale, "w", encoding="utf-8") as handle:
                handle.write(read(pb.DEFAULT_RENDERED).decode().replace('"Idea"', '"Idea2"', 1))
            done = subprocess.run([sys.executable, "-I", TOOL, "check", "--rendered", stale], capture_output=True, text=True)
            self.assertEqual(done.returncode, 1)
            self.assertIn("stale-rendering", done.stdout)

    def test_titles_lists_every_stage_once_in_order(self):
        done = subprocess.run([sys.executable, "-I", TOOL, "titles", "--policy-json", pb.DEFAULT_RENDERED],
                              capture_output=True, text=True)
        self.assertEqual(done.stdout.strip().split(","), [s["title"] for s in config()["stages"]])
        self.assertEqual(len(done.stdout.strip().split(",")), 9)


class Stages(unittest.TestCase):
    def stage(self, labels, closed=False):
        return pb.stage_for(config(), labels, closed)

    def test_the_first_rule_that_fits_decides(self):
        cases = [
            ({"design: proposed"}, False, "idea"),
            ({"design: in progress"}, False, "designing"),
            ({"design: in review"}, False, "design_review"),
            ({"design: approved"}, False, "ready"),
            ({"factory: queued"}, False, "working"),
            ({"factory: working"}, False, "working"),
            ({"factory: waiting for a person"}, False, "needs_person"),
            ({"factory: blocked"}, False, "needs_person"),
            ({"factory: done"}, False, "in_review"),
            ({"factory: failed"}, False, "stopped"),
            ({"factory: rejected"}, False, "stopped"),
            # Two tracks at once: the factory's state wins over the design's.
            ({"design: approved", "factory: working"}, False, "working"),
            ({"design: approved", "factory: waiting for a person"}, False, "needs_person"),
            # A closed issue is done, unless the factory stopped.
            ({"factory: done"}, True, "done"),
            ({"design: approved"}, True, "done"),
            ({"factory: failed"}, True, "stopped"),
            ({"factory: waiting for a person"}, True, "done"),
        ]
        for labels, closed, expected in cases:
            with self.subTest(labels=sorted(labels), closed=closed):
                self.assertEqual(self.stage(labels, closed), expected)

    def test_an_issue_on_no_track_has_no_stage(self):
        self.assertIsNone(self.stage(set()))
        self.assertIsNone(self.stage({"bug", "help wanted"}))
        self.assertIsNone(self.stage({"factory"}), "the request itself does not move a card")
        self.assertIsNone(self.stage(set(), True), "closing an issue does not put it on a track")
        self.assertIsNone(self.stage({"bug"}, True), "nor does closing one that has only other labels")

    def test_every_label_of_the_workflow_lands_on_a_stage(self):
        for label in workflow_config()["labels"]:
            if label["kind"] == "trigger":
                continue
            with self.subTest(label=label["name"]):
                self.assertIsNotNone(self.stage({label["name"]}))


RICH = ["Backlog", "Design", "Design review", "Ready", "In progress", "Blocked", "In review", "Done", "Cancelled"]


class Mapping(unittest.TestCase):
    def test_a_board_with_the_usual_names_maps_each_stage_to_its_own_option(self):
        mapping, notes = pb.propose_mapping(config(), RICH)
        self.assertEqual(mapping, {"idea": "Backlog", "designing": "Design", "design_review": "Design review", "ready": "Ready",
                                   "working": "In progress", "needs_person": "Blocked", "in_review": "In review",
                                   "done": "Done", "stopped": "Cancelled"})
        self.assertEqual(notes, [])

    def test_the_default_three_column_board_still_shows_every_stage(self):
        mapping, notes = pb.propose_mapping(config(), ["Todo", "In Progress", "Done"])
        self.assertEqual(mapping["ready"], "Todo")
        self.assertEqual(mapping["idea"], "Todo")
        self.assertEqual(mapping["working"], "In Progress")
        self.assertEqual(mapping["designing"], "In Progress")
        self.assertEqual(mapping["stopped"], "In Progress")
        self.assertEqual(mapping["done"], "Done")
        self.assertTrue(all(value is not None for value in mapping.values()))
        self.assertTrue(any("Idea" in note and "Todo" in note for note in notes))

    def test_emoji_case_and_punctuation_do_not_matter(self):
        mapping, _ = pb.propose_mapping(config(), ["\U0001F4CB BACKLOG", "✅ Done!", "in-progress", "Ready  for   review"])
        self.assertEqual(mapping["idea"], "\U0001F4CB BACKLOG")
        self.assertEqual(mapping["done"], "✅ Done!")
        self.assertEqual(mapping["working"], "in-progress")
        self.assertEqual(mapping["in_review"], "Ready  for   review")

    def test_a_board_that_fits_nothing_maps_to_nothing_and_says_so(self):
        mapping, notes = pb.propose_mapping(config(), ["Alpha", "Beta"])
        self.assertTrue(all(value is None for value in mapping.values()))
        self.assertEqual(len(notes), 9)

    def test_the_proposal_only_ever_names_options_that_exist(self):
        for names in (RICH, ["Todo", "In Progress", "Done"], ["Alpha"], [], ["done", "Done", "DONE"], ["Review", "Design"]):
            with self.subTest(names=names):
                mapping, _ = pb.propose_mapping(config(), names)
                self.assertTrue(set(mapping.values()) <= set(names) | {None})

    def test_the_cli_writes_a_valid_config_and_leaves_the_fields_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            fields = os.path.join(tmp, "fields.json")
            with open(fields, "w", encoding="utf-8") as handle:
                json.dump({"fields": [{"name": "Title", "type": "ProjectV2Field"},
                                      {"name": "Status", "type": "ProjectV2SingleSelectField",
                                       "options": [{"id": "a", "name": n} for n in RICH]}], "totalCount": 2}, handle)
            before = read(fields)
            done = subprocess.run([sys.executable, "-I", TOOL, "map", "--policy-json", pb.DEFAULT_RENDERED, "--owner", "acme",
                                   "--owner-type", "organization", "--number", "7", "--fields", fields,
                                   "--status-field", "Status"], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            board = json.loads(done.stdout)
            self.assertEqual(pb.validate_board_config(config(), board), [])
            with open(fields, encoding="utf-8") as handle:
                self.assertEqual(pb.live_problems(board, json.load(handle)), [])
            self.assertEqual(read(fields), before)

    def test_a_field_that_does_not_exist_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            fields = os.path.join(tmp, "fields.json")
            with open(fields, "w", encoding="utf-8") as handle:
                json.dump({"fields": [{"name": "Title"}]}, handle)
            done = subprocess.run([sys.executable, "-I", TOOL, "map", "--policy-json", pb.DEFAULT_RENDERED, "--owner", "acme",
                                   "--owner-type", "user", "--number", "1", "--fields", fields, "--status-field", "Status"],
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 1)
            self.assertIn("no single-select field", done.stderr)

    def test_created_makes_the_identity_mapping_for_the_new_field(self):
        done = subprocess.run([sys.executable, "-I", TOOL, "map", "--policy-json", pb.DEFAULT_RENDERED, "--owner", "acme",
                               "--owner-type", "organization", "--number", "3", "--created"], capture_output=True, text=True)
        board = json.loads(done.stdout)
        self.assertEqual(board["status_field"], "Stage")
        self.assertEqual(board["options"]["design_review"], "Design review")
        self.assertEqual(pb.validate_board_config(config(), board), [])


def valid_board():
    mapping, _ = pb.propose_mapping(config(), RICH)
    return pb.board_config({"owner": "acme", "owner_type": "organization", "number": 7}, "Status", mapping)


class BoardConfig(unittest.TestCase):
    def test_a_good_config_is_accepted(self):
        self.assertEqual(pb.validate_board_config(config(), valid_board()), [])

    def test_each_damage_is_named(self):
        def bad_owner(b):
            b["project"]["owner"] = "a b; rm"

        def bad_type(b):
            b["project"]["owner_type"] = "enterprise"

        def zero(b):
            b["project"]["number"] = 0

        def boolean(b):
            b["project"]["number"] = True

        def missing_stage(b):
            del b["options"]["idea"]

        def extra_stage(b):
            b["options"]["surprise"] = "x"

        def number_option(b):
            b["options"]["idea"] = 5

        def extra_key(b):
            b["token"] = "x"

        def wrong_schema(b):
            b["schema"] = "other"

        def empty_field(b):
            b["status_field"] = ""

        for damage, expected in ((bad_owner, "project.owner"), (bad_type, "owner_type"), (zero, "project.number"),
                                 (boolean, "project.number"), (missing_stage, "options"), (extra_stage, "options"),
                                 (number_option, "options.idea"), (extra_key, "shape"), (wrong_schema, "schema"),
                                 (empty_field, "status_field")):
            with self.subTest(damage=damage.__name__):
                board = copy.deepcopy(valid_board())
                damage(board)
                found = pb.validate_board_config(config(), board)
                self.assertTrue(any(expected in line for line in found), (expected, found))

    def test_a_board_that_changed_is_reported(self):
        fields = {"fields": [{"name": "Status", "options": [{"id": "1", "name": n} for n in RICH if n != "Blocked"]}]}
        found = pb.live_problems(valid_board(), fields)
        self.assertEqual(len(found), 1)
        self.assertIn("Blocked", found[0])
        self.assertTrue(pb.live_problems(valid_board(), {"fields": [{"name": "Other", "options": []}]}))
        self.assertEqual(pb.live_problems(valid_board(), {"fields": [{"name": "Status", "options": [{"name": n} for n in RICH]}]}), [])


class FakeGitHub:
    """Records every call. The issue read and the board calls are answered from the data given."""

    def __init__(self, labels=("design: in review",), state="open", node_id: "str | None" = "I_kwDOAbc123", options=RICH,
                 project_found=True, role="write", lookup_fails=False):
        self.labels, self.state, self.node_id, self.options, self.project_found = labels, state, node_id, options, project_found
        self.role, self.lookup_fails = role, lookup_fails
        self.calls = []

    def __call__(self, args, token=None):
        self.calls.append((list(args), token))
        if args[0] == "api" and "/collaborators/" in args[1]:
            if self.lookup_fails:
                raise RuntimeError("gh api failed")
            return json.dumps({"role_name": self.role, "permission": "write" if self.role in ("write", "maintain", "admin") else "read"})
        if args[0] == "api" and args[1].startswith("repos/"):
            return json.dumps({"node_id": self.node_id, "state": self.state, "labels": [{"name": n} for n in self.labels]})
        query = next(a for a in args if a.startswith("query="))
        if "projectV2(number" in query:
            if not self.project_found:
                return json.dumps({"data": {"organization": None, "user": None}})
            node = {"projectV2": {"id": "PVT_1", "fields": {"nodes": [
                {}, {"id": "F_1", "name": "Status", "options": [{"id": "O_%d" % i, "name": n} for i, n in enumerate(self.options)]}]}}}
            return json.dumps({"data": {"organization": node, "user": node}})
        if "addProjectV2ItemById" in query:
            return json.dumps({"data": {"addProjectV2ItemById": {"item": {"id": "ITEM_1"}}}})
        return json.dumps({"data": {"updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "ITEM_1"}}}})

    def graphql_calls(self):
        return [(a, t) for a, t in self.calls if a[:2] == ["api", "graphql"]]


EVENT = {"action": "labeled", "issue": {"number": 12}, "sender": {"login": "alice", "type": "User"}}


class Sync(unittest.TestCase):
    def run_sync(self, fake, board=None, repo="acme/widgets"):
        return pb.sync(config(), board or valid_board(), EVENT, repo, DUMMY_TOKEN, run=fake)

    def test_the_issue_is_added_and_moved_with_the_ids_the_board_gave(self):
        fake = FakeGitHub()
        result = self.run_sync(fake)
        self.assertIn("Design review", result)
        calls = fake.graphql_calls()
        self.assertEqual(len(calls), 3)
        add = calls[1][0]
        self.assertIn("project=PVT_1", add)
        self.assertIn("content=I_kwDOAbc123", add)
        move = calls[2][0]
        self.assertIn("option=O_2", move)
        self.assertIn("field=F_1", move)
        self.assertIn("item=ITEM_1", move)

    def test_the_board_credential_goes_to_the_board_calls_only(self):
        fake = FakeGitHub()
        self.run_sync(fake)
        for args, token in fake.calls:
            if args[:2] == ["api", "graphql"]:
                self.assertEqual(token, DUMMY_TOKEN)
            else:
                self.assertIsNone(token, "the issue is read with the repository token")
        self.assertNotIn(DUMMY_TOKEN, json.dumps([a for a, _ in fake.calls]))

    def test_nothing_from_the_issue_is_put_in_the_text_of_a_query(self):
        hostile = "design: in review"
        fake = FakeGitHub(labels=(hostile,), node_id="I_kwDOhostile")
        self.run_sync(fake)
        for args, _ in fake.graphql_calls():
            query = next(a for a in args if a.startswith("query="))
            for secret in ("hostile", "acme", "widgets", "12", hostile):
                self.assertNotIn(secret, query)

    def test_an_issue_on_no_track_or_a_stage_with_no_option_does_nothing(self):
        fake = FakeGitHub(labels=("bug",))
        self.assertIn("no track", self.run_sync(fake))
        self.assertEqual(fake.graphql_calls(), [])
        board = copy.deepcopy(valid_board())
        board["options"]["design_review"] = None
        fake = FakeGitHub()
        self.assertIn("no option", self.run_sync(fake, board))
        self.assertEqual(fake.graphql_calls(), [])

    def test_a_closed_issue_goes_to_done(self):
        fake = FakeGitHub(labels=("factory: done",), state="closed")
        self.assertIn("'Done'", self.run_sync(fake))

    def test_a_user_project_is_asked_for_as_a_user_and_an_organization_as_an_organization(self):
        for owner_type, word in (("user", "user(login"), ("organization", "organization(login")):
            with self.subTest(owner_type=owner_type):
                board = copy.deepcopy(valid_board())
                board["project"]["owner_type"] = owner_type
                fake = FakeGitHub()
                self.run_sync(fake, board)
                self.assertIn(word, next(a for a in fake.graphql_calls()[0][0] if a.startswith("query=")))

    def test_a_board_that_lost_the_option_is_an_error_and_changes_nothing(self):
        fake = FakeGitHub(options=[n for n in RICH if n != "Design review"])
        with self.assertRaises(RuntimeError) as caught:
            self.run_sync(fake)
        self.assertIn("Design review", str(caught.exception))
        self.assertEqual(len(fake.graphql_calls()), 1, "only the read happened")

    def test_a_project_the_credential_cannot_see_is_an_error(self):
        with self.assertRaises(RuntimeError):
            self.run_sync(FakeGitHub(project_found=False))

    def test_a_refusal_from_github_is_an_error_with_a_short_message(self):
        def refusing(args, _token=None):
            if args[0] == "api" and "/collaborators/" in args[1]:
                return json.dumps({"role_name": "write"})
            if args[0] == "api" and args[1].startswith("repos/"):
                return json.dumps({"node_id": "I_x", "state": "open", "labels": [{"name": "design: proposed"}]})
            return json.dumps({"errors": [{"message": "Resource not accessible by integration " + "x" * 500}]})
        with self.assertRaises(RuntimeError) as caught:
            pb.sync(config(), valid_board(), EVENT, "acme/widgets", DUMMY_TOKEN, run=refusing)
        self.assertLess(len(str(caught.exception)), 250)

    def test_a_bad_node_id_or_repository_is_refused_before_any_board_call(self):
        for node in ("", "has space", "a;b", "x" * 300, None):
            with self.subTest(node=node):
                fake = FakeGitHub(node_id=node)
                with self.assertRaises(ValueError):
                    self.run_sync(fake)
                self.assertEqual(fake.graphql_calls(), [])
        for repo in ("acme", "../x", "acme/widgets; id", "a/b/c"):
            with self.subTest(repo=repo):
                with self.assertRaises(ValueError):
                    self.run_sync(FakeGitHub(), repo=repo)


class WhoMayMoveACard(unittest.TestCase):
    """An outside account must not write to the organisation's board by opening, closing or labelling an issue (PL-2)."""

    def run_sync(self, fake, sender, bot="", owners="", board=None, repo="acme/widgets", event_labels=None):
        event = dict(EVENT, sender=sender)
        return pb.sync(config(), board or valid_board(), event, repo, DUMMY_TOKEN, run=fake, bot_login=bot, extra_owners=owners)

    def test_triage_or_higher_may_and_read_or_none_may_not(self):
        for role, may in (("admin", True), ("maintain", True), ("write", True), ("triage", True), ("read", False), ("none", False)):
            with self.subTest(role=role):
                fake = FakeGitHub(role=role)
                self.run_sync(fake, {"login": "alice", "type": "User"})
                self.assertEqual(bool(fake.graphql_calls()), may)

    def test_an_issue_author_with_no_rights_closing_their_own_issue_writes_nothing(self):
        fake = FakeGitHub(labels=(), state="closed", role="read")
        result = self.run_sync(fake, {"login": "stranger", "type": "User"})
        self.assertIn("no triage rights", result)
        self.assertEqual(fake.graphql_calls(), [])

    def test_the_same_closed_issue_with_no_label_writes_nothing_even_for_a_maintainer(self):
        fake = FakeGitHub(labels=(), state="closed", role="admin")
        self.assertIn("no track", self.run_sync(fake, {"login": "maintainer", "type": "User"}))
        self.assertEqual(fake.graphql_calls(), [])

    def test_the_factorys_app_may_without_a_lookup_and_nobody_else_may_pose_as_it(self):
        fake = FakeGitHub(role="read")
        self.run_sync(fake, {"login": "my-factory[bot]", "type": "Bot"}, bot="my-factory[bot]")
        self.assertTrue(fake.graphql_calls())
        self.assertFalse(any("/collaborators/" in a[1] for a, _ in fake.calls), "the App needs no lookup")
        for sender, bot in (({"login": "my-factory[bot]", "type": "User"}, "my-factory[bot]"),
                            ({"login": "other[bot]", "type": "Bot"}, "my-factory[bot]"),
                            ({"login": "my-factory[bot]", "type": "Bot"}, "")):
            with self.subTest(sender=sender, bot=bot):
                fake = FakeGitHub(role="read")
                self.run_sync(fake, sender, bot=bot)
                self.assertEqual(fake.graphql_calls(), [])

    def test_a_failed_lookup_is_a_no(self):
        fake = FakeGitHub(lookup_fails=True)
        self.assertIn("no triage rights", self.run_sync(fake, {"login": "alice", "type": "User"}))
        self.assertEqual(fake.graphql_calls(), [])

    def test_a_login_that_is_not_a_login_is_refused_before_any_call(self):
        for login in ("", "../x", "a b", "a/b", "x" * 60, "a;b", None):
            with self.subTest(login=login):
                fake = FakeGitHub()
                self.run_sync(fake, {"login": login, "type": "User"})
                self.assertEqual(fake.calls, [])

    def test_a_missing_sender_is_a_no(self):
        fake = FakeGitHub()
        result = pb.sync(config(), valid_board(), {"action": "labeled", "issue": {"number": 12}}, "acme/widgets", DUMMY_TOKEN, run=fake)
        self.assertIn("no triage rights", result)
        self.assertEqual(fake.graphql_calls(), [])


class WhoseBoard(unittest.TestCase):
    """The credential cannot be aimed at somebody else's project by editing the config file (PL-11)."""

    def board_of(self, owner):
        board = copy.deepcopy(valid_board())
        board["project"]["owner"] = owner
        return board

    def run_sync(self, owner, repo="acme/widgets", extra=""):
        fake = FakeGitHub()
        result = pb.sync(config(), self.board_of(owner), EVENT, repo, DUMMY_TOKEN, run=fake, extra_owners=extra)
        return result, fake

    def test_the_repositorys_own_owner_is_allowed_whatever_the_case(self):
        for owner in ("acme", "ACME", "Acme"):
            with self.subTest(owner=owner):
                _, fake = self.run_sync(owner)
                self.assertTrue(fake.graphql_calls())

    def test_another_owner_is_refused_before_any_call_unless_the_repository_lists_it(self):
        with self.assertRaises(RuntimeError) as caught:
            self.run_sync("victim-org")
        self.assertIn("FACTORY_BOARD_OWNERS", str(caught.exception))
        _, fake = self.run_sync("victim-org", extra="other-org, victim-org")
        self.assertTrue(fake.graphql_calls())

    def test_junk_in_the_list_is_ignored_and_does_not_widen_it(self):
        with self.assertRaises(RuntimeError):
            self.run_sync("victim-org", extra="victim-org/../x, ;, victim org")

    def test_nothing_is_called_when_the_owner_is_refused(self):
        fake = FakeGitHub()
        with self.assertRaises(RuntimeError):
            pb.sync(config(), self.board_of("victim-org"), EVENT, "acme/widgets", DUMMY_TOKEN, run=fake)
        self.assertEqual(fake.calls, [])


FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
state = os.environ["FAKE_STATE"]
args = sys.argv[1:]
with open(os.path.join(state, "calls.log"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"args": args, "token": os.environ.get("GH_TOKEN", "")}) + "\n")
if args[0] == "api" and "/collaborators/" in args[1]:
    print(json.dumps({"role_name": os.environ.get("FAKE_ROLE", "write")}))
elif args[0] == "api" and args[1].startswith("repos/"):
    print(json.dumps({"node_id": "I_abc", "state": "open", "labels": [{"name": "design: proposed"}]}))
elif "projectV2(number" in " ".join(args):
    node = {"projectV2": {"id": "P", "fields": {"nodes": [{"id": "F", "name": "Status", "options": [{"id": "1", "name": "Backlog"}]}]}}}
    print(json.dumps({"data": {"organization": node, "user": node}}))
elif "addProjectV2ItemById" in " ".join(args):
    print(json.dumps({"data": {"addProjectV2ItemById": {"item": {"id": "IT"}}}}))
else:
    print(json.dumps({"data": {}}))
'''


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        gh = os.path.join(self.bin, "gh")
        with open(gh, "w", encoding="utf-8") as handle:
            handle.write(FAKE_GH)
        os.chmod(gh, os.stat(gh).st_mode | stat.S_IXUSR)
        self.event = os.path.join(self.tmp, "event.json")
        with open(self.event, "w", encoding="utf-8") as handle:
            json.dump(EVENT, handle)
        self.board = os.path.join(self.tmp, "project-board.json")

    def sync(self, token: "str | None" = DUMMY_TOKEN):
        environment = {"PATH": self.bin + ":/usr/bin:/bin", "FAKE_STATE": self.tmp, "GH_TOKEN": "repository-token-not-secret"}
        if token:
            environment["BOARD_TOKEN"] = token
        return subprocess.run([sys.executable, "-I", TOOL, "sync", "--event", self.event, "--policy-json", pb.DEFAULT_RENDERED,
                               "--board-config", self.board, "--repo", "acme/widgets"], capture_output=True, text=True,
                              env=environment)

    def write_board(self, board):
        with open(self.board, "w", encoding="utf-8") as handle:
            json.dump(board, handle)

    def test_a_project_with_no_board_config_is_not_an_error(self):
        done = self.sync()
        self.assertEqual(done.returncode, 0)
        self.assertIn("skipped", done.stdout)

    def test_a_board_without_a_credential_warns_and_does_not_fail(self):
        self.write_board(valid_board())
        done = self.sync(token=None)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("::warning::", done.stdout)

    def test_a_broken_config_fails_and_a_good_one_moves_the_card_without_printing_the_credential(self):
        broken = copy.deepcopy(valid_board())
        broken["project"]["number"] = 0
        self.write_board(broken)
        self.assertEqual(self.sync().returncode, 1)
        board = copy.deepcopy(valid_board())
        board["options"]["idea"] = "Backlog"
        board["options"]["design_review"] = "Backlog"
        self.write_board(board)
        done = self.sync()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn(DUMMY_TOKEN, done.stdout + done.stderr)
        with open(os.path.join(self.tmp, "calls.log"), encoding="utf-8") as handle:
            calls = [json.loads(line) for line in handle]
        graph = [c for c in calls if c["args"][:2] == ["api", "graphql"]]
        self.assertTrue(graph and all(c["token"] == DUMMY_TOKEN for c in graph))
        self.assertTrue(all(c["token"] != DUMMY_TOKEN for c in calls if c not in graph))


class Promises(unittest.TestCase):
    """What the module promises about itself."""

    def source(self):
        return read(TOOL).decode()

    def test_it_never_changes_a_field_that_exists(self):
        source = self.source()
        for mutation in ("updateProjectV2Field", "deleteProjectV2Field", "createProjectV2Field", "deleteProjectV2",
                         "updateProjectV2(", "singleSelectOptions"):
            self.assertNotIn(mutation, source)
        self.assertEqual(sorted(name for name in ("addProjectV2ItemById", "updateProjectV2ItemFieldValue") if name in source),
                         ["addProjectV2ItemById", "updateProjectV2ItemFieldValue"])

    def test_only_standard_library_modules_are_imported_at_the_top_level(self):
        tree = ast.parse(self.source())
        top = {alias.name.split(".")[0] for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        top |= {(node.module or "").split(".")[0] for node in tree.body if isinstance(node, ast.ImportFrom)}
        self.assertEqual(top - set(sys.stdlib_module_names if hasattr(sys, "stdlib_module_names") else top), set())
        self.assertNotIn("yaml", top)

    def test_it_makes_no_network_call_of_its_own(self):
        for forbidden in ("urllib.request", "http.client", "import requests", "socket"):
            self.assertNotIn(forbidden, self.source())


if __name__ == "__main__":
    unittest.main()
