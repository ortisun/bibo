#!/usr/bin/env python3
"""Tests for scripts/lib/issue_workflow.py (ADR 0016).

Needs PyYAML, because the policy is YAML. Run it with:
    uv run --no-project --with pyyaml==6.0.3 python -I scripts/tests/test_issue_workflow.py

No network and no GitHub: the one function that calls `gh` is replaced by a recorder. Each test builds a
correct input, shows that the check accepts it, then damages exactly one thing and shows that the damage is
named. A check that cannot fail would prove nothing, so every "accepts" test has a sibling that breaks it.
"""
import ast
import copy
import importlib.util
import json
import os
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
LIB = os.path.join(ROOT, "scripts", "lib")
TOOL = os.path.join(LIB, "issue_workflow.py")

# Loaded by path, the way the installer copies and runs it, so that no search path is involved.
_spec = importlib.util.spec_from_file_location("issue_workflow", TOOL)
assert _spec is not None and _spec.loader is not None
iw = importlib.util.module_from_spec(_spec)
sys.modules["issue_workflow"] = iw
_spec.loader.exec_module(iw)
BOT = "ortisun-software-factory[bot]"


def load(path):
    with open(path, "rb") as handle:
        return handle.read()


def real_policy():
    return yaml.safe_load(load(iw.DEFAULT_POLICY))


def real_approval():
    return yaml.safe_load(load(iw.DEFAULT_APPROVAL))


def real_machine():
    return json.loads(load(iw.DEFAULT_STATE_MACHINE))


def config():
    return json.loads(iw.render(real_policy(), load(iw.DEFAULT_POLICY)))


def problems(policy):
    return iw.check_policy(policy, real_approval(), real_machine())


class PolicyCheck(unittest.TestCase):
    def test_the_real_policy_is_sound(self):
        self.assertEqual(problems(real_policy()), [])

    def test_each_damage_is_named(self):
        def top(p):
            p["surprise"] = 1

        def version(p):
            p["schema_version"] = 2

        def trigger_differs(p):
            p["trigger"]["label"] = "build it"

        def trigger_in_namespace(p):
            p["trigger"]["label"] = "design: factory"

        def duplicate_label(p):
            p["design_track"]["states"].append(dict(p["design_track"]["states"][0]))

        def long_name(p):
            p["design_track"]["states"][0]["name"] = "x" * 60

        def bad_color(p):
            p["design_track"]["states"][0]["color"] = "ABCDEF"

        def long_description(p):
            p["factory_track"]["states"][0]["description"] = "d" * 101

        def edge_to_nowhere(p):
            p["design_track"]["transitions"].append({"from": "proposed", "to": "vanished"})

        def self_edge(p):
            p["design_track"]["transitions"].append({"from": "proposed", "to": "proposed"})

        def unreachable(p):
            p["design_track"]["transitions"] = [e for e in p["design_track"]["transitions"] if e["to"] != "approved"]

        def bad_start(p):
            p["design_track"]["start_states"] = ["vanished"]

        def no_start(p):
            p["design_track"]["start_states"] = []

        def job_state_missing(p):
            p["factory_track"]["states"] = [s for s in p["factory_track"]["states"] if s["job_state"] != "BLOCKED"]

        def job_state_invented(p):
            p["factory_track"]["states"].append(
                {"job_state": "DREAMING", "name": "dreaming", "color": "ffffff", "description": "Not a state."})

        def job_state_twice(p):
            p["factory_track"]["states"].append(dict(p["factory_track"]["states"][0], name="again"))

        def glob_escapes(p):
            p["design_track"]["approval_requires"]["design_document"]["path_glob"] = "docs/../x.md"

        def requirement_unknown(p):
            p["intake_requirements"]["design_track_requires"] = "vanished"

        def approver_missing(p):
            del p["intake_requirements"]["design_approved_by"]

        def approver_unknown(p):
            p["intake_requirements"]["design_approved_by"] = "everyone"

        def approver_is_the_requester(p):
            p["intake_requirements"]["design_approved_by"] = "requester"

        def approver_is_the_operator(p):
            p["intake_requirements"]["design_approved_by"] = "operator"

        def reply_cap_missing(p):
            del p["intake_requirements"]["design_reply_cap_per_issue"]

        def reply_cap_zero(p):
            p["intake_requirements"]["design_reply_cap_per_issue"] = 0

        def reply_cap_too_high(p):
            p["intake_requirements"]["design_reply_cap_per_issue"] = 101

        def reply_cap_is_text(p):
            p["intake_requirements"]["design_reply_cap_per_issue"] = "five"

        def reply_cap_is_a_flag(p):
            p["intake_requirements"]["design_reply_cap_per_issue"] = True

        def reply_window_missing(p):
            del p["intake_requirements"]["design_reply_window_hours"]

        def reply_window_zero(p):
            p["intake_requirements"]["design_reply_window_hours"] = 0

        def reply_window_too_long(p):
            p["intake_requirements"]["design_reply_window_hours"] = 169

        def prefix_changed(p):
            p["namespaces"]["factory"]["prefix"] = "bot: "

        def writer_changed(p):
            p["namespaces"]["factory"]["written_by"] = "people"

        cases = [
            (top, "unknown-key"), (version, "schema-version"), (trigger_differs, "trigger-mismatch"),
            (trigger_in_namespace, "trigger-namespace"), (duplicate_label, "duplicate-label"),
            (long_name, "label:"), (bad_color, "color"), (long_description, "description"),
            (edge_to_nowhere, "transition"), (self_edge, "goes nowhere"), (unreachable, "unreachable-state"),
            (bad_start, "start-state"), (no_start, "start-state"),
            (job_state_missing, "BLOCKED has no factory label"), (job_state_invented, "DREAMING is not a job state"),
            (job_state_twice, "mapped twice"), (glob_escapes, "path-glob"),
            (requirement_unknown, "intake-requirement"), (prefix_changed, "namespaces"), (writer_changed, "namespaces"),
            (approver_missing, "design-approver"), (approver_unknown, "design-approver"),
            (approver_is_the_requester, "design-approver"), (approver_is_the_operator, "design-approver"),
            (reply_cap_missing, "design-reply-cap"), (reply_cap_zero, "design-reply-cap"),
            (reply_cap_too_high, "design-reply-cap"), (reply_cap_is_text, "design-reply-cap"),
            (reply_cap_is_a_flag, "design-reply-cap"), (reply_window_missing, "design-reply-window"),
            (reply_window_zero, "design-reply-window"), (reply_window_too_long, "design-reply-window"),
        ]
        for damage, expected in cases:
            with self.subTest(damage=damage.__name__):
                policy = copy.deepcopy(real_policy())
                damage(policy)
                found = problems(policy)
                self.assertTrue(any(expected in line for line in found), (expected, found))

    def test_the_approver_of_a_design_is_a_designation_that_may_decide_it(self):
        # The real value is accepted, and so is each other designation that may decide a design;
        # the two that may not (the person who asks for work, and the operator) are the sibling
        # that proves the check can fail.
        self.assertEqual(real_policy()["intake_requirements"]["design_approved_by"], "approver")
        for allowed in ("approver", "security_approver", "repo_admin", "org_admin"):
            with self.subTest(allowed=allowed):
                policy = copy.deepcopy(real_policy())
                policy["intake_requirements"]["design_approved_by"] = allowed
                self.assertEqual(problems(policy), [])
        for refused in ("requester", "operator", "", None, "Approver", "approver "):
            with self.subTest(refused=refused):
                policy = copy.deepcopy(real_policy())
                policy["intake_requirements"]["design_approved_by"] = refused
                self.assertTrue(any("design-approver" in line for line in problems(policy)), refused)

    def test_the_cap_on_design_replies_is_a_whole_number_in_range_and_the_real_values_are_accepted(self):
        # DG-9. The real values load; zero, a missing value, text and a flag do not (they are the
        # sibling that proves the check can fail). The engine reads the same two keys.
        real = real_policy()["intake_requirements"]
        self.assertEqual((real["design_reply_cap_per_issue"], real["design_reply_window_hours"]), (5, 24))
        for cap, window in ((1, 1), (100, 168), (5, 24)):
            with self.subTest(cap=cap, window=window):
                policy = copy.deepcopy(real_policy())
                policy["intake_requirements"]["design_reply_cap_per_issue"] = cap
                policy["intake_requirements"]["design_reply_window_hours"] = window
                self.assertEqual(problems(policy), [])

    def test_a_new_engine_job_state_without_a_label_is_caught(self):
        machine = copy.deepcopy(real_machine())
        machine["machines"]["job"]["states"]["ARCHIVED"] = {}
        found = iw.check_policy(real_policy(), real_approval(), machine)
        self.assertTrue(any("ARCHIVED has no factory label" in line for line in found), found)


class Rendering(unittest.TestCase):
    def test_the_checked_in_rendering_is_current(self):
        self.assertEqual(load(iw.DEFAULT_RENDERED).decode(), iw.render(real_policy(), load(iw.DEFAULT_POLICY)))

    def test_rendering_is_deterministic(self):
        self.assertEqual(iw.render(real_policy(), b"x"), iw.render(real_policy(), b"x"))

    def test_a_changed_policy_changes_the_rendering(self):
        changed = real_policy()
        changed["design_track"]["states"][0]["description"] = "Another sentence."
        self.assertNotEqual(iw.render(changed, b"x"), iw.render(real_policy(), b"x"))

    def test_the_cli_reports_a_stale_rendering(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = os.path.join(tmp, "issue-workflow.json")
            with open(stale, "w", encoding="utf-8") as handle:
                handle.write(load(iw.DEFAULT_RENDERED).decode().replace('"approved"', '"approvedX"', 1))
            done = subprocess.run([sys.executable, "-I", TOOL, "check", "--rendered", stale], capture_output=True, text=True)
            self.assertEqual(done.returncode, 1)
            self.assertIn("stale-rendering", done.stdout)

    def test_the_cli_accepts_the_real_files(self):
        done = subprocess.run([sys.executable, "-I", TOOL, "check"], capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout.startswith("OK")), (0, True), done.stdout + done.stderr)

    def test_labels_lists_every_label_once_with_three_fields(self):
        done = subprocess.run([sys.executable, "-I", TOOL, "labels", "--config", iw.DEFAULT_RENDERED], capture_output=True, text=True)
        rows = [line.split("\t") for line in done.stdout.splitlines()]
        self.assertTrue(all(len(row) == 3 for row in rows))
        names = [row[0] for row in rows]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("factory", names)
        self.assertIn("design: approved", names)
        self.assertIn("factory: working", names)
        self.assertEqual(len(names), 1 + 4 + 10)


def decide(**override):
    args = dict(action="labeled", label="design: proposed", sender_login="alice", sender_type="User", current=set(),
                factory_bot_login=BOT, design_doc_exists=False)
    args.update(override)
    return iw.decide(config(), **args)


class Decide(unittest.TestCase):
    def test_the_trigger_label_is_never_added_or_removed(self):
        trigger = config()["trigger"]
        every = [lbl["name"] for lbl in config()["labels"]] + ["bug", "design: nonsense", "factory: nonsense"]
        for action in ("labeled", "unlabeled"):
            for label in every:
                for sender, kind in (("alice", "User"), (BOT, "Bot")):
                    for current in (set(), {trigger}, {label, trigger}, set(every)):
                        for exists in (False, True):
                            ops = decide(action=action, label=label, sender_login=sender, sender_type=kind,
                                         current=current, design_doc_exists=exists)
                            touched = [op for op in ops if op[0] in ("add_label", "remove_label") and op[1] == trigger]
                            self.assertEqual(touched, [], (action, label, sender, current))

    def test_a_label_outside_both_namespaces_is_left_alone(self):
        self.assertEqual(decide(label="bug", current={"bug"}), [])

    # --- the trigger label only warns --------------------------------------------------------
    def test_the_trigger_warns_when_a_design_is_not_approved(self):
        ops = decide(label="factory", current={"factory", "design: in review"})
        self.assertEqual([op[0] for op in ops], ["comment"])
        self.assertIn(iw.GATE_MARKER, ops[0][1])

    def test_the_trigger_is_quiet_when_the_design_is_approved_or_absent_or_removed(self):
        self.assertEqual(decide(label="factory", current={"factory", "design: approved"}), [])
        self.assertEqual(decide(label="factory", current={"factory"}), [])
        self.assertEqual(decide(action="unlabeled", label="factory", current={"design: in review"}), [])

    # --- the factory namespace has one writer ------------------------------------------------
    def test_a_person_cannot_set_a_factory_label(self):
        ops = decide(label="factory: done", current={"factory: done", "factory: working"})
        self.assertEqual(ops[0], ("remove_label", "factory: done"))
        self.assertEqual(ops[1][0], "comment")

    def test_the_app_may_set_one_factory_label_and_the_others_go(self):
        ops = decide(label="factory: done", sender_login=BOT, sender_type="Bot",
                     current={"factory: done", "factory: working", "bug"})
        self.assertEqual(ops, [("remove_label", "factory: working")])

    def test_the_app_login_is_compared_without_case(self):
        ops = decide(label="factory: done", sender_login=BOT.upper(), sender_type="Bot", current={"factory: done"})
        self.assertEqual(ops, [])

    def test_the_login_alone_is_not_enough_the_account_must_be_a_bot(self):
        ops = decide(label="factory: done", sender_login=BOT, sender_type="User", current={"factory: done"})
        self.assertEqual(ops[0], ("remove_label", "factory: done"))

    def test_with_no_app_configured_nobody_may_set_a_factory_label(self):
        ops = decide(label="factory: done", sender_login=BOT, sender_type="Bot", current={"factory: done"}, factory_bot_login="")
        self.assertEqual(ops[0], ("remove_label", "factory: done"))

    def test_even_the_app_cannot_invent_a_factory_label(self):
        ops = decide(label="factory: dreaming", sender_login=BOT, sender_type="Bot", current={"factory: dreaming"})
        self.assertEqual(ops[0], ("remove_label", "factory: dreaming"))

    def test_a_person_who_removes_the_status_sees_it_put_back(self):
        ops = decide(action="unlabeled", label="factory: working", current=set())
        self.assertEqual(ops[0], ("add_label", "factory: working"))

    def test_the_app_may_remove_a_status(self):
        self.assertEqual(decide(action="unlabeled", label="factory: working", sender_login=BOT, sender_type="Bot"), [])

    # --- the design track ---------------------------------------------------------------------
    def test_legal_starts_and_moves(self):
        self.assertEqual(decide(label="design: proposed", current={"design: proposed"}), [])
        self.assertEqual(decide(label="design: in progress", current={"design: in progress"}), [])
        self.assertEqual(decide(label="design: in progress", current={"design: proposed", "design: in progress"}),
                         [("remove_label", "design: proposed")])
        self.assertEqual(decide(label="design: in review", current={"design: in progress", "design: in review"}),
                         [("remove_label", "design: in progress")])
        self.assertEqual(decide(label="design: in progress", current={"design: in review", "design: in progress"}),
                         [("remove_label", "design: in review")])
        self.assertEqual(decide(label="design: in progress", current={"design: approved", "design: in progress"}),
                         [("remove_label", "design: approved")])

    def test_illegal_starts_and_moves_are_reverted_with_a_reason(self):
        for label, current in (
            ("design: in review", {"design: in review"}),
            ("design: approved", {"design: approved"}),
            ("design: approved", {"design: proposed", "design: approved"}),
            ("design: in review", {"design: proposed", "design: in review"}),
            ("design: proposed", {"design: in progress", "design: proposed"}),
        ):
            with self.subTest(label=label, current=sorted(current)):
                ops = decide(label=label, current=current, design_doc_exists=True)
                self.assertEqual(ops[0], ("remove_label", label))
                self.assertEqual(ops[1][0], "comment")
                self.assertEqual(len(ops), 2, "the label that was there before stays")

    def test_approval_needs_a_design_document_that_exists(self):
        body = "Design document: docs/designs/webhook-delivery.md\n"
        current = {"design: in review", "design: approved"}
        self.assertEqual(decide(label="design: approved", current=current, design_doc_exists=True),
                         [("remove_label", "design: in review")])
        ops = decide(label="design: approved", current=current, design_doc_exists=False)
        self.assertEqual(ops[0], ("remove_label", "design: approved"))
        self.assertIn("design document", ops[1][1])

    def test_taking_a_design_label_away_is_allowed(self):
        self.assertEqual(decide(action="unlabeled", label="design: approved", current=set()), [])

    def test_an_unknown_design_label_is_removed_and_its_name_is_not_echoed(self):
        hostile = "design: <script>alert(1)</script>"
        ops = decide(label=hostile, current={hostile})
        self.assertEqual(ops[0], ("remove_label", hostile))
        self.assertNotIn("script", ops[1][1])
        self.assertIn("design: proposed", ops[1][1])


class DesignDocument(unittest.TestCase):
    def path(self, body):
        return iw.design_document_path(config(), body)

    def test_a_good_line_is_accepted(self):
        self.assertEqual(self.path("Intro\nDesign document: docs/designs/a-b_c.md\nMore"), "docs/designs/a-b_c.md")
        self.assertEqual(self.path("Design document:   docs/designs/a.md   \n"), "docs/designs/a.md")

    def test_a_windows_line_ending_is_accepted(self):
        self.assertEqual(self.path("Intro\r\nDesign document: docs/designs/a.md\r\n"), "docs/designs/a.md")

    def test_every_malformed_line_is_refused(self):
        for body in (
            "Design document: docs/designs/../../etc/passwd.md",
            "Design document: docs/designs/sub/dir.md",
            "Design document: /docs/designs/a.md",
            "Design document: docs/other/a.md",
            "Design document: docs/designs/a.md and more text",
            "Design document: docs/designs/a.txt",
            "  Design document: docs/designs/a.md",
            "See Design document: docs/designs/a.md",
            "Design document: docs/designs/a.md\\..\\b.md",
            "Design document:",
            "",
            None,
        ):
            with self.subTest(body=body):
                self.assertIsNone(self.path(body))

    def test_the_first_line_wins(self):
        self.assertEqual(self.path("Design document: docs/designs/a.md\nDesign document: docs/designs/b.md"),
                         "docs/designs/a.md")


class FakeGitHub:
    """Answers the issue, its events and its comments. Records every call."""

    def __init__(self, labels, body="", comments=None, events=None, missing=()):
        self.labels, self.body, self.comments, self.events, self.calls = labels, body, comments or [], events or [], []
        self.missing = set(missing)

    def __call__(self, method, path, fields=None, paginate=False):
        self.calls.append((method, path, dict(fields or {})))
        if method == "GET" and "/events" in path:
            return json.dumps(self.events)
        if method == "GET" and path.endswith("/comments"):
            return json.dumps(self.comments)
        if method == "GET":
            return json.dumps({"labels": [{"name": n} for n in self.labels], "body": self.body})
        if method == "DELETE" and path.rsplit("/", 1)[-1] in self.missing:
            raise iw.NotFound("gone")
        return ""


def labeled(name, login="alice", kind="User"):
    return {"event": "labeled", "label": {"name": name}, "actor": {"login": login, "type": kind}}


def event(action="labeled", label="design: in progress", login="alice", kind="User", payload_labels=()):
    return {"action": action, "label": {"name": label}, "sender": {"login": login, "type": kind},
            "issue": {"number": 7, "labels": [{"name": n} for n in payload_labels]}}


class Apply(unittest.TestCase):
    def run_apply(self, fake, ev, docs=".", bot=BOT, repo="acme/widgets"):
        return iw.apply_event(config(), ev, repo, docs, bot, api=fake)

    def test_it_reads_the_labels_again_instead_of_trusting_the_event(self):
        # The payload says the issue has only the new label. GitHub says there is an older one.
        fake = FakeGitHub(["design: proposed", "design: in progress"])
        self.run_apply(fake, event(payload_labels=["design: in progress"]))
        self.assertIn(("DELETE", "repos/acme/widgets/issues/7/labels/design%3A%20proposed", {}), fake.calls)

    def test_a_revert_removes_the_label_with_an_encoded_path(self):
        fake = FakeGitHub(["design: approved"])
        self.run_apply(fake, event(label="design: approved"))
        deletes = [c for c in fake.calls if c[0] == "DELETE"]
        self.assertEqual(deletes, [("DELETE", "repos/acme/widgets/issues/7/labels/design%3A%20approved", {})])
        self.assertTrue(any(c[0] == "POST" and c[1].endswith("/comments") for c in fake.calls))

    def test_a_clean_event_makes_no_change(self):
        fake = FakeGitHub(["design: in progress"])
        self.run_apply(fake, event())
        self.assertEqual([c[0] for c in fake.calls], ["GET", "GET"], "the issue and its events were read; nothing was changed")

    def test_the_design_document_is_looked_for_on_disk_and_a_symlink_does_not_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "docs", "designs"))
            target = os.path.join(tmp, "elsewhere.md")
            for name in ("real.md", "link.md"):
                self.assertFalse(os.path.exists(os.path.join(tmp, "docs", "designs", name)))
            with open(os.path.join(tmp, "docs", "designs", "real.md"), "w", encoding="utf-8") as handle:
                handle.write("# Design\n")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("x")
            os.symlink(target, os.path.join(tmp, "docs", "designs", "link.md"))
            for name, approved in (("real.md", True), ("link.md", False), ("absent.md", False)):
                with self.subTest(name=name):
                    fake = FakeGitHub(["design: in review", "design: approved"], body="Design document: docs/designs/%s\n" % name)
                    self.run_apply(fake, event(label="design: approved"), docs=tmp)
                    removed_approval = ("DELETE", "repos/acme/widgets/issues/7/labels/design%3A%20approved", {}) in fake.calls
                    self.assertEqual(removed_approval, not approved)

    def test_the_gate_comment_is_posted_once(self):
        ev = event(label="factory")
        first = FakeGitHub(["factory", "design: in review"])
        self.run_apply(first, ev)
        self.assertEqual(sum(1 for c in first.calls if c[0] == "POST"), 1)
        mine = [{"user": {"login": "github-actions[bot]", "type": "Bot"}, "body": iw.GATE_MARKER + "\nearlier gate comment"}]
        again = FakeGitHub(["factory", "design: in review"], comments=mine)
        self.run_apply(again, ev)
        self.assertEqual(sum(1 for c in again.calls if c[0] == "POST"), 0)

    def test_a_comment_by_somebody_else_cannot_silence_the_gate_comment(self):
        planted = [{"user": {"login": "mallory"}, "body": iw.GATE_MARKER}]
        fake = FakeGitHub(["factory", "design: in review"], comments=planted)
        self.run_apply(fake, event(label="factory"))
        self.assertEqual(sum(1 for c in fake.calls if c[0] == "POST"), 1)

    def test_a_comment_that_is_not_the_actions_own_gate_comment_cannot_silence_it(self):
        # PL-12. The marker pasted by a person, quoted inside another comment, or posted under another account or kind
        # of account does not count. Each case below is a comment that the old test (the marker anywhere) accepted.
        bot = {"login": "github-actions[bot]", "type": "Bot"}
        cases = {
            "by a person": {"user": {"login": "mallory", "type": "User"}, "body": iw.GATE_MARKER + "\nx"},
            "by a person who is named like the bot": {"user": {"login": "github-actions", "type": "User"}, "body": iw.GATE_MARKER},
            "by the bot's name but not a bot account": {"user": {"login": "github-actions[bot]", "type": "User"},
                                                        "body": iw.GATE_MARKER},
            "with no author": {"body": iw.GATE_MARKER},
            "quoted after other text": {"user": bot, "body": "> " + iw.GATE_MARKER + "\nsomeone replied"},
            "after a first line": {"user": bot, "body": "Hello\n" + iw.GATE_MARKER},
        }
        for name, comment in cases.items():
            with self.subTest(comment=name):
                fake = FakeGitHub(["factory", "design: in review"], comments=[comment])
                self.run_apply(fake, event(label="factory"))
                self.assertEqual(sum(1 for c in fake.calls if c[0] == "POST"), 1, "the gate comment must be posted")
        # The control: the Action's own comment, as it writes it, does silence the next one.
        own = FakeGitHub(["factory", "design: in review"], comments=[{"user": bot, "body": iw.GATE_MARKER + "\nThis issue is on the design track"}])
        self.run_apply(own, event(label="factory"))
        self.assertEqual(sum(1 for c in own.calls if c[0] == "POST"), 0)

    def test_a_link_in_any_part_of_the_path_means_there_is_no_design_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            elsewhere = os.path.join(tmp, "elsewhere")
            os.makedirs(elsewhere)
            with open(os.path.join(elsewhere, "a.md"), "w", encoding="utf-8") as handle:
                handle.write("# Design\n")
            root = os.path.join(tmp, "repo")
            os.makedirs(os.path.join(root, "docs"))
            os.symlink(elsewhere, os.path.join(root, "docs", "designs"))   # the FOLDER is a link
            fake = FakeGitHub(["design: in review", "design: approved"], body="Design document: docs/designs/a.md\n",
                              events=[labeled("design: approved")])
            self.run_apply(fake, event(label="design: approved"), docs=root)
            self.assertIn(("DELETE", "repos/acme/widgets/issues/7/labels/design%3A%20approved", {}), fake.calls)
            self.assertTrue(iw.plain_file(elsewhere, "a.md"), "the control: with no link the same file counts")

    def test_a_repository_name_with_extra_characters_is_refused(self):
        for repo in ("acme/widgets; rm -rf /", "acme", "acme/widgets/extra", "acme/wid gets", "../x"):
            with self.subTest(repo=repo):
                with self.assertRaises(ValueError):
                    self.run_apply(FakeGitHub([]), event(), repo=repo)

    def test_a_failed_call_stops_the_run(self):
        def failing(*_args, **_kwargs):
            raise RuntimeError("gh api failed")
        with self.assertRaises(RuntimeError):
            iw.apply_event(config(), event(label="design: approved"), "acme/widgets", ".", BOT, api=failing)

    def test_the_cli_ignores_an_event_that_is_not_a_label_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "event.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"action": "opened", "issue": {"number": 1}}, handle)
            done = subprocess.run([sys.executable, "-I", TOOL, "apply", "--event", path, "--config", iw.DEFAULT_RENDERED,
                                   "--repo", "acme/widgets"], capture_output=True, text=True)
            self.assertEqual((done.returncode, "nothing to do" in done.stdout), (0, True), done.stderr)


class WithoutTheBotLogin(unittest.TestCase):
    """PL-21: until FACTORY_BOT_LOGIN names the factory's App, the Action cannot tell the factory's labels from a person's.
    It then does nothing at all and says so, instead of removing the factory's status labels and commenting each time."""

    def run_cli(self, env, action="labeled", label="factory: done", kind="User"):
        """Runs `issue_workflow.py apply` as the workflow does, with a `gh` that records every call and answers one issue."""
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = os.path.join(tmp, "bin")
            os.makedirs(bin_dir)
            log = os.path.join(tmp, "gh.log")
            fake = os.path.join(bin_dir, "gh")
            with open(fake, "w", encoding="utf-8") as handle:
                handle.write('#!/bin/sh\necho "$@" >> "%s"\nprintf \'{"labels":[{"name":"factory: done"}],"body":""}\'\n' % log)
            os.chmod(fake, 0o755)
            path = os.path.join(tmp, "event.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(event(action=action, label=label, login="alice", kind=kind), handle)
            done = subprocess.run([sys.executable, "-I", TOOL, "apply", "--event", path, "--config", iw.DEFAULT_RENDERED,
                                   "--repo", "acme/widgets"], capture_output=True, text=True,
                                  env={"PATH": bin_dir + ":/usr/bin:/bin", **env})
            calls = []
            if os.path.exists(log):
                with open(log, encoding="utf-8") as handle:
                    calls = handle.read().splitlines()
            return done, calls

    def test_with_the_variable_set_the_same_event_is_judged_and_gh_is_called(self):
        # The control: a person added a factory label. With the App named, the Action reads the issue and removes it.
        done, calls = self.run_cli({"FACTORY_BOT_LOGIN": BOT})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(calls, "gh was never called, so the tests below would pass for the wrong reason")
        self.assertTrue(any("-X DELETE" in call for call in calls), calls)

    def test_with_the_variable_unset_it_changes_nothing_and_says_so(self):
        for name, env in (("absent", {}), ("empty", {"FACTORY_BOT_LOGIN": ""}), ("blank", {"FACTORY_BOT_LOGIN": "  \t"})):
            for action in ("labeled", "unlabeled"):
                with self.subTest(variable=name, action=action):
                    done, calls = self.run_cli(env, action=action)
                    self.assertEqual(done.returncode, 0, done.stderr)
                    self.assertEqual(calls, [], "the Action called GitHub (read or write) without knowing who the factory is")
                    self.assertIn("nothing done: the repository variable FACTORY_BOT_LOGIN is not set", done.stdout)
                    self.assertIn("::warning title=FACTORY_BOT_LOGIN is not set::", done.stdout)
                    self.assertFalse([line for line in done.stdout.splitlines()
                                      if line.startswith(("remove_label ", "add_label ", "comment "))],
                                     "an operation was reported, so one was carried out")

    def test_an_event_that_is_not_a_label_event_is_still_ignored_first(self):
        # The order of the two answers is part of the contract the older test relies on.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "event.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"action": "opened", "issue": {"number": 1}}, handle)
            done = subprocess.run([sys.executable, "-I", TOOL, "apply", "--event", path, "--config", iw.DEFAULT_RENDERED,
                                   "--repo", "acme/widgets"], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
            self.assertIn("nothing to do: not a label event", done.stdout)

    def test_the_board_steps_of_the_shipped_workflow_do_nothing_either(self):
        workflow = yaml.safe_load(load(ShippedFiles.WORKFLOW))
        steps = {step["name"]: step for step in workflow["jobs"]["labels"]["steps"]}
        for name in ("Create a short-lived credential for the board", "Move the issue on the board"):
            with self.subTest(step=name):
                self.assertIn("vars.FACTORY_BOT_LOGIN != ''", steps[name].get("if", ""), "this step must wait for the variable")
        # The step that applies the workflow has no condition: it runs, logs why it did nothing, and the warning shows.
        self.assertNotIn("if", steps["Apply the issue workflow"])


class ShippedFiles(unittest.TestCase):
    """The forms and the Action are copied into other people's repositories. They must not widen anyone's authority."""

    FORMS = os.path.join(ROOT, "onboarding", "github", "ISSUE_TEMPLATE")
    WORKFLOW = os.path.join(ROOT, "onboarding", "github", "workflows", "issue-workflow.yml")

    def forms(self):
        for name in sorted(os.listdir(self.FORMS)):
            yield name, yaml.safe_load(load(os.path.join(self.FORMS, name)))

    def test_no_form_applies_the_trigger_label_and_every_label_it_applies_exists(self):
        known = {label["name"] for label in config()["labels"]}
        for name, form in self.forms():
            for label in form.get("labels", []):
                with self.subTest(form=name, label=label):
                    self.assertNotEqual(label, config()["trigger"])
                    self.assertTrue(label.startswith("design: "), "a form may start a design, nothing else")
                    self.assertIn(label, known)

    def test_the_forms_ask_for_checkable_outcomes_and_put_no_prefix_on_the_title(self):
        for name, form in self.forms():
            if name == "config.yml":
                continue
            with self.subTest(form=name):
                self.assertNotIn("title", form, "the master prompt forbids a title prefix")
                ids = [part["id"] for part in form["body"] if "id" in part]
                self.assertIn("acceptance", ids)
                required = [part["id"] for part in form["body"] if part.get("validations", {}).get("required")]
                self.assertIn("problem", required)

    def test_the_new_solution_form_starts_a_design_and_the_change_form_does_not(self):
        forms = dict(self.forms())
        self.assertEqual(forms["new-solution.yml"]["labels"], ["design: proposed"])
        self.assertNotIn("labels", forms["change-request.yml"])

    def test_the_action_asks_for_the_least_permission_and_never_interpolates_issue_text(self):
        workflow = yaml.safe_load(load(self.WORKFLOW))
        self.assertEqual(workflow["permissions"], {"contents": "read", "issues": "write"})
        self.assertEqual(list(workflow[True]), ["issues"], "the key `on` is read as true by YAML 1.1")
        self.assertEqual(sorted(workflow[True]["issues"]["types"]), ["closed", "labeled", "reopened", "unlabeled"])
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"@[0-9a-f]{40}$", "actions are pinned to a full commit")
                for field in ("run", "with"):
                    self.assertNotIn("github.event", str(step.get(field, "")),
                                     "event text must reach the script through the event file only")
                self.assertNotIn("pull_request_target", str(step))

    def test_the_checkout_does_not_leave_the_repository_token_on_disk(self):
        # PL-20: this was never tested. The Action only reads two folders, so nothing needs the token after the checkout.
        workflow = yaml.safe_load(load(self.WORKFLOW))
        checkouts = [step for step in workflow["jobs"]["labels"]["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")]
        self.assertEqual(len(checkouts), 1)
        self.assertIs(checkouts[0]["with"]["persist-credentials"], False)
        self.assertEqual(checkouts[0]["with"]["sparse-checkout"].split(), [".github", "docs/designs"])

    def test_the_board_credential_reaches_the_board_steps_only(self):
        workflow = yaml.safe_load(load(self.WORKFLOW))
        steps = workflow["jobs"]["labels"]["steps"]
        by_name = {step["name"]: step for step in steps}
        for name, step in by_name.items():
            text = str(step)
            if name in ("Create a short-lived credential for the board", "Move the issue on the board"):
                continue
            self.assertNotIn("secrets.", text, name)
            self.assertNotIn("BOARD_TOKEN", text, name)
        mint = by_name["Create a short-lived credential for the board"]
        asked = sorted(key for key in mint["with"] if key.startswith("permission-"))
        self.assertEqual(asked, ["permission-issues", "permission-organization-projects"])
        self.assertEqual(mint["with"]["permission-issues"], "read")
        move = by_name["Move the issue on the board"]
        for name in ("FACTORY_BOT_LOGIN", "FACTORY_BOARD_OWNERS"):
            self.assertIn("vars.", move["env"][name], "a variable of the repository, not a secret")
            self.assertNotIn("secrets.", move["env"][name])
        self.assertEqual(move["env"]["GH_TOKEN"], "${{ github.token }}", "the issue is read with the repository token")
        self.assertIn("secrets.FACTORY_BOARD_TOKEN", move["env"]["BOARD_TOKEN"])

    def test_the_action_never_names_the_trigger_label(self):
        text = load(self.WORKFLOW).decode()
        code_lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
        self.assertNotIn("--add-label factory", "\n".join(code_lines))
        self.assertNotIn("labels/factory", "\n".join(code_lines))


class Reconcile(unittest.TestCase):
    """The whole issue is judged on every run, so a run that GitHub dropped cannot leave a bad label (PL-1)."""

    def run_reconcile(self, current, events=(), bot=BOT, doc=False, restored=()):
        return iw.reconcile(config(), current=set(current), labelers=iw.last_labelers(list(events)), factory_bot_login=bot,
                            design_doc_exists=doc, restored=restored)

    def removed(self, ops):
        return sorted(op[1] for op in ops if op[0] == "remove_label")

    def test_a_factory_label_set_by_the_app_stays_and_one_set_by_a_person_goes(self):
        mine = [labeled("factory: working", BOT, "Bot")]
        self.assertEqual(self.run_reconcile({"factory: working"}, mine), [])
        by_hand = [labeled("factory: done", "alice")]
        self.assertEqual(self.removed(self.run_reconcile({"factory: done"}, by_hand)), ["factory: done"])

    def test_a_factory_label_with_no_event_is_removed_because_nothing_shows_who_set_it(self):
        self.assertEqual(self.removed(self.run_reconcile({"factory: done"}, [])), ["factory: done"])

    def test_the_login_alone_is_not_enough_the_account_must_be_a_bot_and_one_must_be_configured(self):
        impostor = [labeled("factory: done", BOT, "User")]
        self.assertEqual(self.removed(self.run_reconcile({"factory: done"}, impostor)), ["factory: done"])
        by_app = [labeled("factory: done", BOT, "Bot")]
        self.assertEqual(self.removed(self.run_reconcile({"factory: done"}, by_app, bot="")), ["factory: done"])

    def test_only_the_latest_factory_label_stays(self):
        events = [labeled("factory: working", BOT, "Bot"), labeled("factory: done", BOT, "Bot")]
        ops = self.run_reconcile({"factory: working", "factory: done"}, events)
        self.assertEqual(self.removed(ops), ["factory: working"])

    def test_only_the_latest_design_label_stays(self):
        events = [labeled("design: proposed"), labeled("design: in progress"), labeled("design: in review")]
        ops = self.run_reconcile({"design: proposed", "design: in progress", "design: in review"}, events, doc=True)
        self.assertEqual(self.removed(ops), ["design: in progress", "design: proposed"])

    def test_approved_stays_only_with_a_design_document(self):
        events = [labeled("design: approved")]
        self.assertEqual(self.removed(self.run_reconcile({"design: approved"}, events, doc=False)), ["design: approved"])
        self.assertEqual(self.run_reconcile({"design: approved"}, events, doc=True), [])

    def test_a_label_the_workflow_does_not_define_goes_and_its_name_is_never_echoed(self):
        hostile = "design: <img src=x onerror=1>"
        ops = self.run_reconcile({hostile, "factory: nonsense"}, [labeled(hostile), labeled("factory: nonsense", BOT, "Bot")])
        self.assertEqual(self.removed(ops), sorted([hostile, "factory: nonsense"]))
        comment = [op[1] for op in ops if op[0] == "comment"][0]
        self.assertNotIn("img", comment)

    def test_a_label_that_was_just_put_back_is_not_judged_by_the_old_events(self):
        self.assertEqual(self.run_reconcile({"factory: working"}, [], restored={"factory: working"}), [])

    def test_the_trigger_label_and_labels_outside_both_groups_are_never_touched(self):
        every = [label["name"] for label in config()["labels"]]
        for current in (set(every), {"factory", "bug"}, {"factory", "design: approved", "factory: done"}):
            for events in ([], [labeled("factory", "alice"), labeled("bug")]):
                ops = self.run_reconcile(current, events)
                self.assertNotIn("factory", self.removed(ops))
                self.assertNotIn("bug", self.removed(ops))

    def test_a_healthy_issue_gets_no_operation_and_no_comment(self):
        events = [labeled("design: approved"), labeled("factory: working", BOT, "Bot"), labeled("bug")]
        self.assertEqual(self.run_reconcile({"design: approved", "factory: working", "bug", "factory"}, events, doc=True), [])


class DroppedRuns(unittest.TestCase):
    """GitHub keeps one waiting run per issue. A skipped event must not leave a bad label behind."""

    def apply_for(self, fake, label="bug", login="alice"):
        return iw.apply_event(config(), event(label=label, login=login), "acme/widgets", ".", BOT, api=fake)

    def test_a_later_unrelated_event_heals_a_label_an_earlier_dropped_run_should_have_removed(self):
        fake = FakeGitHub(["design: approved", "factory: done", "bug"],
                          events=[labeled("design: approved"), labeled("factory: done"), labeled("bug")])
        self.apply_for(fake)
        deleted = sorted(c[1].rsplit("/", 1)[-1] for c in fake.calls if c[0] == "DELETE")
        self.assertEqual(deleted, ["design%3A%20approved", "factory%3A%20done"])
        self.assertEqual(sum(1 for c in fake.calls if c[0] == "POST" and c[1].endswith("/comments")), 1)

    def test_with_the_same_labels_set_by_the_app_and_a_design_document_nothing_changes(self):
        fake = FakeGitHub(["design: approved", "factory: working", "bug"], body="Design document: docs/designs/a.md\n",
                          events=[labeled("design: approved"), labeled("factory: working", BOT, "Bot"), labeled("bug")])
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "docs", "designs"))
            with open(os.path.join(tmp, "docs", "designs", "a.md"), "w", encoding="utf-8") as handle:
                handle.write("# Design\n")
            iw.apply_event(config(), event(label="bug"), "acme/widgets", tmp, BOT, api=fake)
        self.assertEqual([c for c in fake.calls if c[0] in ("DELETE", "POST")], [])

    def test_a_label_that_is_already_gone_is_not_a_failure(self):
        fake = FakeGitHub(["factory: done"], events=[labeled("factory: done")], missing={"factory%3A%20done"})
        self.apply_for(fake, label="factory: done")
        self.assertTrue(any(c[0] == "DELETE" for c in fake.calls))

    def test_a_restored_status_label_is_not_removed_again_in_the_same_run(self):
        # A person removed the app's label. The event rules put it back. The state check must not undo that.
        fake = FakeGitHub([], events=[labeled("factory: working", BOT, "Bot"),
                                      {"event": "unlabeled", "label": {"name": "factory: working"}, "actor": {"login": "alice", "type": "User"}}])
        ev = event(action="unlabeled", label="factory: working")
        iw.apply_event(config(), ev, "acme/widgets", ".", BOT, api=fake)
        self.assertEqual(sum(1 for c in fake.calls if c[0] == "POST" and c[1].endswith("/labels")), 1)
        self.assertEqual(sum(1 for c in fake.calls if c[0] == "DELETE"), 0)

    def test_the_trigger_label_is_refused_as_a_namespace_member_in_a_tampered_config(self):
        tampered = config()
        tampered["factory"]["prefix"] = "fact"
        with self.assertRaises(ValueError):
            iw.apply_event(tampered, event(label="bug"), "acme/widgets", ".", BOT, api=FakeGitHub([]))


class Pages(unittest.TestCase):
    def test_the_layouts_of_gh_paginate_are_read(self):
        self.assertEqual(iw.parse_pages('[{"a":1},{"a":2}]\n[{"a":3}]'), [{"a": 1}, {"a": 2}, {"a": 3}])
        self.assertEqual(iw.parse_pages('[[{"a":1}],[{"a":2}]]'), [{"a": 1}, {"a": 2}])
        self.assertEqual(iw.parse_pages(""), [])
        self.assertEqual(iw.parse_pages("[]"), [])

    def test_a_404_from_gh_is_a_not_found_and_any_other_failure_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            for number, (stderr, expected) in enumerate((("gh: Not Found (HTTP 404)", iw.NotFound),
                                                         ("gh: Forbidden (HTTP 403)", RuntimeError))):
                # One folder per case: the system caches an executable by its file, and a rewritten file runs stale.
                folder = os.path.join(tmp, "case%d" % number)
                os.makedirs(folder)
                fake = os.path.join(folder, "gh")
                with open(fake, "w", encoding="utf-8") as handle:
                    handle.write("#!/bin/sh\necho '%s' >&2\nexit 1\n" % stderr)
                os.chmod(fake, 0o755)
                old = os.environ["PATH"]
                os.environ["PATH"] = folder + ":" + old
                try:
                    with self.assertRaises(RuntimeError) as caught:
                        iw.gh_api("DELETE", "repos/a/b/issues/1/labels/x")
                finally:
                    os.environ["PATH"] = old
                self.assertIs(type(caught.exception), expected, stderr)

    def test_a_log_line_cannot_carry_a_control_code_or_a_workflow_command(self):
        self.assertEqual(iw._clean("a\nb::error::x\x1b[0m"), "a?b::error::x?[0m")


class StandardLibraryOnly(unittest.TestCase):
    """The installer copies this file into a repository that has nothing installed. It must import the standard library only."""

    def test_only_standard_library_modules_are_imported_at_the_top_level(self):
        with open(TOOL, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        top = {alias.name.split(".")[0] for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        top |= {(node.module or "").split(".")[0] for node in tree.body if isinstance(node, ast.ImportFrom)}
        self.assertEqual(top - set(sys.stdlib_module_names if hasattr(sys, "stdlib_module_names") else top), set())
        self.assertNotIn("yaml", top)

    def test_it_makes_no_network_call_of_its_own(self):
        with open(TOOL, encoding="utf-8") as handle:
            source = handle.read()
        for forbidden in ("urllib.request", "http.client", "import requests", "socket"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
