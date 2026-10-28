#!/usr/bin/env python3
"""Tests for scripts/lib/factory_ops.py and the lock in scripts/lib/ops.sh (work package s1-local-deployment).

No Docker, no PostgreSQL. Run it with:   python3 -I scripts/tests/test_factory_ops.py

Each test builds a small, correct input, shows that the check passes on it, then damages exactly one thing and shows
that the check fails and names the damage. A check that cannot fail would prove nothing, so every "passes" test has a
sibling that breaks it.
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.normpath(os.path.join(HERE, "..", "lib"))
OPS = os.path.join(LIB, "factory_ops.py")


def run(*args, stdin=None):
    done = subprocess.run([sys.executable, "-I", OPS, *args], input=stdin, capture_output=True, text=True)
    lines = [l.split("\t") for l in done.stdout.splitlines() if "\t" in l]
    return done.returncode, {l[0]: (l[1], l[2] if len(l) > 2 else "") for l in lines}, done


def write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)


FACTS = {
    "server_version": "18.6", "server_version_num": 180006,
    "schema": {"migrations": 18, "latest": "20261027001800"},
    "roles": [
        {"name": "factory_app", "login": False, "super": False, "createdb": False, "createrole": False, "replication": False,
         "bypassrls": False, "inherit": True, "conn_limit": -1, "member_of": []},
        {"name": "factory_api", "login": True, "super": False, "createdb": False, "createrole": False, "replication": False,
         "bypassrls": False, "inherit": True, "conn_limit": -1, "member_of": ["factory_app:inherit=t:set=t:admin=f"]},
    ],
    "fingerprints": {"tables": "a" * 64, "policies": "b" * 64, "columns": "c" * 64},
    "heads": {"ledger": [{"tenant": "t1", "job": "j1", "sequence": 3, "hash": "sha256:" + "d" * 64}],
              "audit": [{"tenant": "t1", "sequence": 5, "hash": "sha256:" + "e" * 64}]},
    "chain": {"ledger_chains": 1, "ledger_bad": [], "audit_chains": 1, "audit_bad": []},
    "artifact_rows": ["sha256:" + "1" * 64],
    "sessions": 0,
}
TABLES = {"jobs": {"rows": 3, "sha256": "f" * 64}, "ledger_entries": {"rows": 10, "sha256": "0" * 64}}
BLOB = "1" * 64
LIST_TEXT = "%s 12 sha256/11/11/%s\n" % (BLOB, BLOB)


class BackupFolderCase(TempDirCase):
    """A backup folder built by `manifest` and `sums`, then checked and damaged."""

    def make_backup(self):
        for name, text in (("database.dump", "dump bytes"), ("globals.sql", "SET x;\n"), ("artifacts.tar", "tar bytes")):
            write(self.path(name), text)
        write(self.path("artifacts.list"), LIST_TEXT)
        write(self.path("facts.json"), json.dumps(FACTS))
        write(self.path("tables.json"), json.dumps(TABLES))
        code, _, done = run("manifest", "--dir", self.dir, "--facts", self.path("facts.json"), "--tables", self.path("tables.json"),
                            "--artifact-list", self.path("artifacts.list"), "--database", "factory")
        self.assertEqual(code, 0, done.stderr)
        self.assertEqual(run("sums", "--dir", self.dir)[0], 0)

    def test_a_good_backup_passes_its_checksums(self):
        self.make_backup()
        code, checks, _ = run("check-sums", "--dir", self.dir)
        self.assertEqual(code, 0)
        self.assertEqual(checks["backup-checksums"][0], "PASS")
        self.assertEqual(checks["manifest-names-the-same-hashes"][0], "PASS")

    def test_one_flipped_byte_in_the_dump_fails(self):
        self.make_backup()
        self.assertEqual(run("corrupt", "--file", self.path("database.dump"), "--offset", "3")[0], 0)
        code, checks, _ = run("check-sums", "--dir", self.dir)
        self.assertEqual(code, 1)
        self.assertEqual(checks["backup-checksums"][0], "FAIL")
        self.assertIn("database.dump", checks["backup-checksums"][1])

    def test_a_missing_file_fails(self):
        self.make_backup()
        os.remove(self.path("artifacts.tar"))
        code, checks, _ = run("check-sums", "--dir", self.dir)
        self.assertEqual(code, 1)
        self.assertIn("artifacts.tar is missing", checks["backup-checksums"][1])

    def test_fixed_checksums_agree_again_so_the_other_checks_must_catch_it(self):
        self.make_backup()
        run("corrupt", "--file", self.path("database.dump"), "--offset", "3")
        run("rehash", "--dir", self.dir)
        self.assertEqual(run("check-sums", "--dir", self.dir)[0], 0)

    def test_checksums_that_disagree_with_the_manifest_fail(self):
        self.make_backup()
        manifest = read_json(self.path("manifest.json"))
        manifest["files"]["database.dump"] = "0" * 64
        write(self.path("manifest.json"), json.dumps(manifest))
        run("sums", "--dir", self.dir)  # SHA256SUMS now matches the edited manifest file, but not its own hashes
        code, checks, _ = run("check-sums", "--dir", self.dir)
        self.assertEqual(code, 1)
        self.assertEqual(checks["manifest-names-the-same-hashes"][0], "FAIL")

    def test_the_manifest_records_what_the_restore_will_compare(self):
        self.make_backup()
        manifest = read_json(self.path("manifest.json"))
        self.assertEqual(manifest["format"], "factory-backup/1")
        self.assertEqual(manifest["database"]["server_major"], 18)
        self.assertEqual(manifest["schema"]["migrations"], 18)
        self.assertEqual(manifest["artifacts"]["count"], 1)
        self.assertTrue(manifest["created_at"].endswith("Z"))
        self.assertTrue(manifest["quiesced"])
        self.assertFalse(manifest["database"]["roles_file_has_passwords"])

    def compare(self, manifest_edit=None, facts_edit=None, tables_edit=None):
        self.make_backup()
        facts, tables = copy.deepcopy(FACTS), copy.deepcopy(TABLES)
        if facts_edit:
            facts_edit(facts)
        if tables_edit:
            tables_edit(tables)
        write(self.path("restored-facts.json"), json.dumps(facts))
        write(self.path("restored-tables.json"), json.dumps(tables))
        return run("compare-db", "--manifest", self.path("manifest.json"), "--facts", self.path("restored-facts.json"),
                   "--tables", self.path("restored-tables.json"))

    def test_an_identical_database_passes_every_comparison(self):
        code, checks, _ = self.compare()
        self.assertEqual(code, 0, checks)
        self.assertTrue(all(status == "PASS" for status, _ in checks.values()))

    def test_a_behind_schema_fails(self):
        code, checks, _ = self.compare(facts_edit=lambda f: f["schema"].update(migrations=17))
        self.assertEqual((code, checks["schema-version"][0]), (1, "FAIL"))

    def test_a_missing_role_fails(self):
        code, checks, _ = self.compare(facts_edit=lambda f: f["roles"].pop())
        self.assertEqual((code, checks["roles-exist"][0]), (1, "FAIL"))

    def test_a_login_in_the_wrong_group_fails(self):
        def edit(f):
            f["roles"][1]["member_of"] = ["factory_system:inherit=t:set=t:admin=f"]
        code, checks, _ = self.compare(facts_edit=edit)
        self.assertEqual((code, checks["roles-attributes-and-memberships"][0]), (1, "FAIL"))

    def test_a_changed_policy_fingerprint_fails_and_names_the_kind(self):
        code, checks, _ = self.compare(facts_edit=lambda f: f["fingerprints"].update(policies="9" * 64))
        self.assertEqual((code, checks["fingerprint-policies"][0]), (1, "FAIL"))
        self.assertEqual(checks["fingerprint-tables"][0], "PASS")

    def test_a_changed_row_count_fails(self):
        code, checks, _ = self.compare(tables_edit=lambda t: t["jobs"].update(rows=2))
        self.assertEqual((code, checks["row-counts"][0]), (1, "FAIL"))

    def test_a_changed_row_with_the_same_count_fails_the_content_hash(self):
        code, checks, _ = self.compare(tables_edit=lambda t: t["jobs"].update(sha256="1" * 64))
        self.assertEqual((code, checks["row-counts"][0], checks["content-hash"][0]), (1, "PASS", "FAIL"))

    def test_a_chain_that_lost_its_tail_fails_the_head_check_although_it_still_verifies(self):
        def edit(f):
            f["heads"]["ledger"][0].update(sequence=2, hash="sha256:" + "7" * 64)
        code, checks, _ = self.compare(facts_edit=edit)
        self.assertEqual((code, checks["ledger-heads"][0], checks["ledger-verify-chain-in-database"][0]), (1, "FAIL", "PASS"))

    def test_a_bad_chain_reported_by_the_database_fails(self):
        code, checks, _ = self.compare(facts_edit=lambda f: f["chain"].update(ledger_bad=[{"tenant": "t1", "job": "j1", "first_bad": 2}]))
        self.assertEqual((code, checks["ledger-verify-chain-in-database"][0]), (1, "FAIL"))

    def test_another_major_version_fails(self):
        code, checks, _ = self.compare(facts_edit=lambda f: f.update(server_version="17.2", server_version_num=170002))
        self.assertEqual((code, checks["server-major-version"][0]), (1, "FAIL"))


class ArtifactCase(TempDirCase):
    def compare(self, recorded, found, extra=()):
        write(self.path("recorded.list"), recorded)
        write(self.path("found.list"), found)
        return run("compare-artifacts", "--recorded", self.path("recorded.list"), "--found", self.path("found.list"), *extra)

    def test_identical_blobs_pass(self):
        code, checks, _ = self.compare(LIST_TEXT, LIST_TEXT)
        self.assertEqual(code, 0)
        self.assertEqual(checks["artifacts-hash-equals-name"][0], "PASS")

    def test_a_lost_blob_fails(self):
        code, checks, _ = self.compare(LIST_TEXT, "")
        self.assertEqual((code, checks["artifacts-same-files"][0]), (1, "FAIL"))

    def test_a_blob_that_no_longer_hashes_to_its_name_fails_both_ways(self):
        damaged = "%s 12 sha256/11/11/%s\n" % ("2" * 64, BLOB)
        code, checks, _ = self.compare(LIST_TEXT, damaged)
        self.assertEqual(code, 1)
        self.assertEqual(checks["artifacts-byte-identical"][0], "FAIL")
        self.assertEqual(checks["artifacts-hash-equals-name"][0], "FAIL")

    def test_wrong_modes_or_owner_fail(self):
        write(self.path("state.json"), json.dumps({"files_not_0400": 1, "folders_not_0700": 0}))
        code, checks, _ = self.compare(LIST_TEXT, LIST_TEXT, ("--state", self.path("state.json")))
        self.assertEqual((code, checks["artifacts-owner-and-modes"][0]), (1, "FAIL"))

    def test_an_index_row_without_a_blob_fails(self):
        write(self.path("facts.json"), json.dumps({"artifact_rows": ["sha256:" + "3" * 64]}))
        code, checks, _ = self.compare(LIST_TEXT, LIST_TEXT, ("--database-facts", self.path("facts.json")))
        self.assertEqual((code, checks["artifact-index-rows-have-blobs"][0]), (1, "FAIL"))


def ledger_rows(job="j1", count=3):
    rows, previous = [], None
    for sequence in range(1, count + 1):
        text = json.dumps({"sequence": sequence, "claim": "c%d" % sequence}, sort_keys=True)
        digest = "sha256:" + hashlib.sha256(((previous or "") + "\n" + text).encode()).hexdigest()
        rows.append({"tenant_id": "t1", "job_id": job, "sequence": sequence, "prev_entry_hash": previous,
                     "entry_hash": digest, "canonical_json": text})
        previous = digest
    return rows


class LedgerCase(TempDirCase):
    def verify(self, rows, manifest_heads=None):
        args = ["verify-ledger"]
        if manifest_heads is not None:
            write(self.path("m.json"), json.dumps({"heads": {"ledger": manifest_heads}}))
            args += ["--manifest", self.path("m.json")]
        return run(*args, stdin=json.dumps(rows))

    def test_an_intact_chain_verifies(self):
        rows = ledger_rows()
        code, checks, _ = self.verify(rows, [{"tenant": "t1", "job": "j1", "sequence": 3, "hash": rows[-1]["entry_hash"]}])
        self.assertEqual(code, 0)
        self.assertEqual(checks["ledger-chain-rebuilt-outside-postgresql"][0], "PASS")
        self.assertEqual(checks["ledger-heads-equal-manifest"][0], "PASS")

    def test_an_edited_document_fails(self):
        rows = ledger_rows()
        rows[1]["canonical_json"] = rows[1]["canonical_json"].replace("c2", "cX")
        code, checks, _ = self.verify(rows)
        self.assertEqual((code, checks["ledger-chain-rebuilt-outside-postgresql"][0]), (1, "FAIL"))
        self.assertIn("sequence 2", checks["ledger-chain-rebuilt-outside-postgresql"][1])

    def test_a_forged_link_fails(self):
        rows = ledger_rows()
        rows[2]["prev_entry_hash"] = "sha256:" + "0" * 64
        code, checks, _ = self.verify(rows)
        self.assertEqual((code, checks["ledger-chain-rebuilt-outside-postgresql"][0]), (1, "FAIL"))

    def test_a_gap_fails(self):
        rows = ledger_rows()
        del rows[1]
        code, checks, _ = self.verify(rows)
        self.assertEqual((code, checks["ledger-chain-rebuilt-outside-postgresql"][0]), (1, "FAIL"))

    def test_a_lost_tail_passes_alone_and_fails_against_the_recorded_head(self):
        rows = ledger_rows()
        truncated = rows[:2]
        code, checks, _ = self.verify(truncated, [{"tenant": "t1", "job": "j1", "sequence": 3, "hash": rows[-1]["entry_hash"]}])
        self.assertEqual(checks["ledger-chain-rebuilt-outside-postgresql"][0], "PASS")
        self.assertEqual((code, checks["ledger-heads-equal-manifest"][0]), (1, "FAIL"))


class RetentionCase(TempDirCase):
    def backup(self, name, with_manifest=True, fmt="factory-backup/1"):
        os.makedirs(self.path(name))
        if with_manifest:
            write(os.path.join(self.dir, name, "manifest.json"), json.dumps({"format": fmt}))

    def test_only_the_newest_are_kept_and_only_real_backups_are_touched(self):
        for stamp in ("20261001T000000Z", "20261002T000000Z", "20261003T000000Z", "20261004T000000Z"):
            self.backup("factory-backup-" + stamp)
        self.backup("factory-backup-20260101T000000Z-no-manifest", with_manifest=False)
        self.backup("factory-backup-20260102T000000Z-other-format", fmt="something/else")
        self.backup("notes-from-a-person")
        code, _, done = run("prune", "--root", self.dir, "--keep", "2")
        self.assertEqual(code, 0, done.stderr)
        left = sorted(os.listdir(self.dir))
        self.assertEqual(left, ["factory-backup-20260101T000000Z-no-manifest", "factory-backup-20260102T000000Z-other-format",
                                "factory-backup-20261003T000000Z", "factory-backup-20261004T000000Z", "notes-from-a-person"])

    def test_keep_zero_still_keeps_the_newest(self):
        self.backup("factory-backup-20261001T000000Z")
        self.backup("factory-backup-20261002T000000Z")
        run("prune", "--root", self.dir, "--keep", "0")
        self.assertEqual(sorted(os.listdir(self.dir)), ["factory-backup-20261002T000000Z"])


class ReportCase(TempDirCase):
    def report(self, lines):
        write(self.path("checks.tsv"), "".join(lines))
        code, _, done = run("report", "--checks", self.path("checks.tsv"), "--tool", "t", "--out", self.path("r.json"), "--meta", "k=v")
        return code, read_json(self.path("r.json"))

    def test_all_pass_is_pass_and_the_file_is_private(self):
        code, report = self.report(["a\tPASS\tok\n", "b\tSKIP\tno lan\n"])
        self.assertEqual((code, report["result"], report["counts"]["PASS"], report["meta"]["k"]), (0, "PASS", 1, "v"))
        self.assertEqual(os.stat(self.path("r.json")).st_mode & 0o777, 0o600)

    def test_one_failure_is_fail_and_is_named(self):
        code, report = self.report(["a\tPASS\tok\n", "b\tFAIL\tbad\n"])
        self.assertEqual((code, report["result"], report["failed"]), (1, "FAIL", ["b"]))

    def test_no_checks_at_all_is_not_a_pass(self):
        code, report = self.report([])
        self.assertEqual((code, report["result"]), (1, "FAIL"))


def rendered():
    """A rendered Compose file (docker compose config --format json) that follows the rules."""
    hardened = {"cap_drop": ["ALL"], "read_only": True, "security_opt": ["no-new-privileges:true"], "mem_limit": "1", "pids_limit": 1}
    return {
        "networks": {"data": {}, "broker": {"internal": True}, "probe_net": {"internal": True}},
        "services": {
            "postgres": dict(hardened, image="postgres:18.6@sha256:" + "a" * 64, profiles=["local"], networks={"data": None},
                             cap_add=["CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"],
                             ports=[{"host_ip": "127.0.0.1", "published": "55432", "target": 5432}]),
            "artifacts-init": dict(hardened, image="postgres:18.6@sha256:" + "a" * 64, profiles=["local"], cap_add=["CHOWN", "DAC_OVERRIDE", "FOWNER"],
                                   network_mode="none"),
            "sandbox-probe": dict(hardened, image="factory-sandbox/agent:x", pull_policy="never", profiles=["test"],
                                  networks={"probe_net": None}),
            "api": dict(hardened, image="factory-api:local", pull_policy="never", profiles=["factory"], networks={"data": None},
                        user="10010:10010", environment={"FACTORY_DB_API_PASSWORD_FILE": "/run/secrets/x"}),
            "worker": dict(hardened, image="factory-worker:local", pull_policy="never", profiles=["factory"],
                           networks={"data": None, "broker": None}, user="10010:10010"),
        },
    }


class TopologyCase(TempDirCase):
    def check(self, edit=None):
        config = rendered()
        if edit:
            edit(config)
        write(self.path("c.json"), json.dumps(config))
        return run("check-topology", "--config", self.path("c.json"))

    def test_the_designed_layout_passes_every_rule(self):
        code, checks, _ = self.check()
        self.assertEqual(code, 0, {k: v for k, v in checks.items() if v[0] != "PASS"})

    def test_a_port_on_every_interface_fails(self):
        code, checks, _ = self.check(lambda c: c["services"]["postgres"]["ports"][0].update(host_ip="0.0.0.0"))
        self.assertEqual((code, checks["ports-loopback-only"][0]), (1, "FAIL"))

    def test_a_sandbox_on_the_database_network_fails(self):
        code, checks, _ = self.check(lambda c: c["services"]["sandbox-probe"]["networks"].update(data=None))
        self.assertEqual(code, 1)
        self.assertEqual(checks["topology-sandbox-shares-no-network-with-postgres"][0], "FAIL")
        self.assertEqual(checks["topology-sandbox-never-on-data-or-broker"][0], "FAIL")

    def test_a_sandbox_network_that_is_not_internal_fails(self):
        code, checks, _ = self.check(lambda c: c["networks"]["probe_net"].update(internal=False))
        self.assertEqual((code, checks["topology-sandbox-network-is-internal"][0]), (1, "FAIL"))

    def test_postgres_on_a_second_network_fails(self):
        code, checks, _ = self.check(lambda c: c["services"]["postgres"]["networks"].update(broker=None))
        self.assertEqual((code, checks["topology-postgres-only-on-data"][0]), (1, "FAIL"))

    def test_an_unpinned_image_fails(self):
        code, checks, _ = self.check(lambda c: c["services"]["postgres"].update(image="postgres:18"))
        self.assertEqual(code, 1)
        self.assertEqual(checks["images-pinned-or-never-pulled"][0], "FAIL")
        self.assertEqual(checks["postgres-image-is-18-by-digest"][0], "FAIL")

    def test_postgres_17_fails(self):
        code, checks, _ = self.check(lambda c: c["services"]["postgres"].update(image="postgres:17-alpine@sha256:" + "a" * 64))
        self.assertEqual((code, checks["postgres-image-is-18-by-digest"][0]), (1, "FAIL"))

    def test_the_docker_socket_or_an_added_capability_fails(self):
        def edit(c):
            c["services"]["worker"]["volumes"] = [{"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}]
            c["services"]["api"]["cap_add"] = ["NET_ADMIN"]
        code, checks, _ = self.check(edit)
        self.assertEqual((code, checks["hardening-every-service"][0]), (1, "FAIL"))
        self.assertIn("Docker socket", checks["hardening-every-service"][1])
        self.assertIn("NET_ADMIN", checks["hardening-every-service"][1])

    def test_a_password_value_in_the_environment_fails(self):
        code, checks, _ = self.check(lambda c: c["services"]["api"]["environment"].update(FACTORY_DB_PASSWORD="hunter2"))
        self.assertEqual((code, checks["no-secret-in-environment"][0]), (1, "FAIL"))

    def test_a_factory_service_running_as_root_fails(self):
        code, checks, _ = self.check(lambda c: c["services"]["api"].update(user="0:0"))
        self.assertEqual((code, checks["factory-services-run-as-10010"][0]), (1, "FAIL"))


class LockCase(TempDirCase):
    """The shared Docker lock (scripts/lib/ops.sh), the same file the Rust tests lock."""

    def script(self, body, wait="2"):
        env = dict(os.environ, FACTORY_DOCKER_LOCK_DIR=self.dir, FACTORY_DOCKER_LOCK_WAIT_SECONDS=wait,
                   FACTORY_DOCKER_HOLD_SECONDS="20", OPS_TOOL="lock-test")
        return subprocess.run(["bash", "-c", ". '%s/ops.sh'; ops_install_traps; %s" % (LIB, body)], env=env,
                              capture_output=True, text=True, timeout=60)

    def test_the_lock_file_is_the_one_the_rust_tests_use(self):
        done = self.script("ops_lock_path")
        self.assertEqual(done.stdout, os.path.join(self.dir, "factory-docker-network.lock"))

    def test_a_second_taker_is_blocked_while_the_first_holds_the_lock(self):
        holder = subprocess.Popen(
            ["bash", "-c", ". '%s/ops.sh'; ops_install_traps; ops_lock_acquire 5; echo held; sleep 6" % LIB],
            env=dict(os.environ, FACTORY_DOCKER_LOCK_DIR=self.dir, FACTORY_DOCKER_HOLD_SECONDS="20", OPS_TOOL="holder"),
            stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "held")
            done = self.script("ops_lock_acquire 2; echo got-it")
            self.assertEqual(done.returncode, 3, done.stderr)
            self.assertIn("BLOCKED", done.stderr)
            self.assertNotIn("got-it", done.stdout)
        finally:
            holder.kill()
            holder.wait()
            holder.stdout.close()

    def test_the_lock_is_free_again_after_the_holder_ends(self):
        self.assertEqual(self.script("ops_lock_acquire 2; true").returncode, 0)
        done = self.script("ops_lock_acquire 2; echo got-it")
        self.assertEqual((done.returncode, done.stdout.strip().splitlines()[-1]), (0, "got-it"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
