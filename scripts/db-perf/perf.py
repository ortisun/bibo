#!/usr/bin/env python3
"""Database performance harness (work package s1-database-review).

Starts a scratch PostgreSQL cluster of its own on 127.0.0.1 (a high port, no unix socket, SCRAM passwords made at
run time), applies the migrations, loads deterministic synthetic data (scripts/db-perf/load.sql), and measures the hot
queries of the storage crate as the REAL login roles with row-level security forced, never as a superuser.

Standard library only. Run it through scripts/db-perf.sh. Nothing here talks to a network or to any database
that it did not create. The cluster and its data directory are removed when the run ends.

What it measures (see docs/database/performance.md for the method and the numbers):

  series      each hot statement or short statement sequence, in the transaction shape the Store uses:
              BEGIN; set the tenant; set the limits; statements; COMMIT. Time per command comes from psql's own
              \\timing, over the extended protocol with named prepared statements, 1,000 warm iterations and
              60 cold-ish ones (right after a server restart).
  plans       EXPLAIN (ANALYZE, BUFFERS) per statement, as the login, for a big tenant and a small tenant.
  rls         the same tenant series with row-level security disabled, to price the policy itself.
  concurrency pgbench runs: ledger appends on one job, on 16 jobs of one tenant, audit appends on one tenant and on 16
              tenants, claim finders, outbox relays that drain a backlog, sweeper next to heartbeats.
  churn       heartbeats for a minute; table and index growth, dead tuples, HOT updates, autovacuum.
  checks      the hash chains verify; no sequential scan on a large table on the claim path; numbers are only
              reported for a login that is not a superuser, does not bypass row-level security and owns nothing.

Exit codes: 0 every verdict passed, 1 a verdict failed, 2 bad usage, 3 BLOCKED (a tool is missing),
4 REFUSED (the harness would have measured as a role that bypasses the policies, or the chains do not verify).
"""

from __future__ import annotations

import argparse
import atexit
import dataclasses
import hashlib
import json
import os
import platform
import random
import re
import secrets
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIGRATIONS = ROOT / "migrations"

EXIT_FAIL, EXIT_USAGE, EXIT_BLOCKED, EXIT_REFUSED = 1, 2, 3, 4

DB = "perf"            # the measured database: read only series, plans, RLS ablation
DBW = "perf_w"         # a clone of it for everything that writes
SUPER = "postgres"
LOGINS = {
    "worker": ("perfdb_worker", ["factory_app"]),
    "api": ("perfdb_api", ["factory_app", "factory_resolver"]),
    "engine": ("perfdb_engine", ["factory_system"]),
}

TX_LIMITS = ("30000ms", "5000ms")   # the defaults of PoolSettings (statement 30 s, lock 5 s)
SEQSCAN_LARGE = 5000                # a sequential scan of a table with more rows than this fails the verdict (jobs holds 10,000 at 100,000 rows)


class Refused(Exception):
    """The harness will not report: it would measure outside the real login, or the data is not sound."""


class Blocked(Exception):
    pass


def say(text: str = "") -> None:
    print(text, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------
# The cluster.

def find_bin() -> Path:
    candidates: list[Path] = []
    if os.environ.get("FACTORY_PG_BIN"):
        candidates.append(Path(os.environ["FACTORY_PG_BIN"]))
    candidates += [Path(p) for p in os.environ.get("PATH", "").split(os.pathsep) if p]
    candidates += [Path(p) for p in (
        "/opt/homebrew/opt/postgresql@18/bin", "/usr/local/opt/postgresql@18/bin", "/usr/lib/postgresql/18/bin",
        "/opt/homebrew/opt/postgresql@17/bin", "/usr/lib/postgresql/17/bin")]
    for d in candidates:
        if all((d / t).exists() for t in ("initdb", "pg_ctl", "postgres", "psql", "pgbench")):
            return d
    raise Blocked("no PostgreSQL install with initdb, pg_ctl, postgres, psql and pgbench was found (set FACTORY_PG_BIN)")


def free_port() -> int:
    for _ in range(200):
        port = random.SystemRandom().randint(40000, 59999)
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise Blocked("no free port found")


class Cluster:
    def __init__(self, bin_dir: Path, keep: bool, extra_settings: list[str], deployed_defaults: bool = False):
        self.deployed_defaults = deployed_defaults
        self.bin = bin_dir
        self.keep = keep
        self.extra = extra_settings
        self.root = Path(tempfile.mkdtemp(prefix="factory-dbperf-"))
        self.data = self.root / "data"
        self.port = free_port()
        self.passwords = {SUPER: secrets.token_hex(16)}
        self.started = False
        self.version = ""

    # -- process control
    def _run(self, name: str, *args: str, check: bool = True, env: Optional[dict] = None) -> subprocess.CompletedProcess:
        return subprocess.run([str(self.bin / name), *args], check=check, capture_output=True, text=True, env=env)

    def _options(self) -> str:
        options = ["-c", "listen_addresses=127.0.0.1", "-c", f"port={self.port}", "-c", "unix_socket_directories="]
        if not self.deployed_defaults:       # the measuring cluster watches itself; the "as deployed" one changes nothing else
            options += ["-c", "shared_preload_libraries=pg_stat_statements", "-c", "pg_stat_statements.track=all", "-c", "track_io_timing=on",
                        "-c", "max_connections=100", "-c", "log_min_duration_statement=-1"]
        for s in self.extra:
            options += ["-c", s]
        return " ".join(options)

    def _pg_start(self) -> None:
        log = self.root / "server.log"
        # The log file takes the server's output, so the server does not hold the pipes of this process open.
        proc = self._run("pg_ctl", "-D", str(self.data), "-l", str(log), "-w", "-t", "60", "-o", self._options(), "start", check=False)
        if proc.returncode != 0:
            tail = log.read_text()[-2000:] if log.exists() else ""
            raise Blocked(f"the scratch cluster did not start: {proc.stderr.strip()} {tail}")
        self.started = True

    def start(self) -> None:
        pwfile = self.root / "super.pw"
        pwfile.write_text(self.passwords[SUPER])
        pwfile.chmod(0o600)
        self._run("initdb", "-D", str(self.data), "-U", SUPER, "--auth-host=scram-sha-256", "--auth-local=scram-sha-256",
                  "-E", "UTF8", "--no-locale", f"--pwfile={pwfile}")
        pwfile.unlink()
        self._pg_start()
        self.version = self.psql(SUPER, DB_ADMIN, "SHOW server_version", tuples=True).strip()

    def stop(self, mode: str = "fast") -> None:
        if self.started:
            self._run("pg_ctl", "-D", str(self.data), "-m", mode, "-w", "stop", check=False)
            self.started = False

    def restart(self) -> None:
        self.stop("fast")
        self._pg_start()

    def destroy(self) -> None:
        self.stop("immediate")
        if not self.keep:
            shutil.rmtree(self.root, ignore_errors=True)

    # -- clients
    def env(self, user: str) -> dict:
        e = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        e["PGPASSWORD"] = self.passwords[user]
        e["PGHOST"] = "127.0.0.1"
        e["PGPORT"] = str(self.port)
        e["PGCONNECT_TIMEOUT"] = "10"
        return e

    def psql(self, user: str, db: str, sql: Optional[str] = None, file: Optional[Path] = None, vars: Optional[dict] = None,
             tuples: bool = False, check: bool = True, single_tx: bool = False, quiet: bool = True) -> str:
        args = ["-X", "-v", "ON_ERROR_STOP=1", "-U", user, "-d", db]
        if quiet:
            args.append("-q")
        if tuples:
            args += ["-At", "-F", "\x1f"]
        for k, v in (vars or {}).items():
            args += ["-v", f"{k}={v}"]
        if single_tx:
            args.append("-1")
        if sql is not None:
            args += ["-c", sql]
        if file is not None:
            args += ["-f", str(file)]
        proc = subprocess.run([str(self.bin / "psql"), *args], capture_output=True, text=True, env=self.env(user))
        if check and proc.returncode != 0:
            raise RuntimeError(f"psql as {user} on {db} failed ({proc.returncode}): {proc.stderr.strip()[:1500]}")
        return proc.stdout if check else (proc.stdout + proc.stderr, proc.returncode)  # type: ignore[return-value]

    def query(self, user: str, db: str, sql: str) -> list[list[str]]:
        out = self.psql(user, db, sql, tuples=True)
        return [line.split("\x1f") for line in out.splitlines() if line != ""]

    def scalar(self, user: str, db: str, sql: str) -> str:
        rows = self.query(user, db, sql)
        return rows[0][0] if rows else ""


DB_ADMIN = "postgres"   # maintenance database for administration


# ---------------------------------------------------------------------------------------------
# Provisioning: schema, roles, data.

def migration_dirs() -> list[Path]:
    return sorted(p for p in MIGRATIONS.iterdir() if p.is_dir())


def provision(cl: Cluster, rows: int, upto: Optional[str] = None) -> None:
    njobs = max(rows // 10, 100)
    cl.psql(SUPER, DB_ADMIN, f'CREATE DATABASE "{DB}" ENCODING \'UTF8\' TEMPLATE template0 LC_COLLATE \'C\' LC_CTYPE \'C\'')
    cl.psql(SUPER, DB, "CREATE TABLE __diesel_schema_migrations (version varchar(50) PRIMARY KEY, run_on timestamp NOT NULL DEFAULT now())")
    for d in migration_dirs():
        if upto and d.name > upto:
            break
        cl.psql(SUPER, DB, file=d / "up.sql", single_tx=True)
        version = re.sub(r"\D", "", d.name.split("_", 1)[0])
        cl.psql(SUPER, DB, f"INSERT INTO __diesel_schema_migrations (version) VALUES ('{version}')")
    for key, (name, groups) in LOGINS.items():
        cl.passwords[name] = secrets.token_hex(16)
        cl.psql(SUPER, DB, f"CREATE ROLE {name} LOGIN PASSWORD '{cl.passwords[name]}' NOSUPERUSER NOCREATEDB NOCREATEROLE "
                           f"NOREPLICATION NOBYPASSRLS IN ROLE {', '.join(groups)}")
    say(f"loading {rows:,} rows per hot table ({njobs:,} jobs); this takes a minute or two")
    t0 = time.time()
    cl.psql(SUPER, DB, file=HERE / "load.sql", vars={"rows": rows, "njobs": njobs})
    say(f"loaded in {time.time() - t0:.0f} s")
    # The harness helper schema is readable by the logins (the plan tables stay closed).
    cl.psql(SUPER, DB, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
    cl.psql(SUPER, DB, "GRANT USAGE ON SCHEMA perf TO factory_app, factory_system")
    cl.psql(SUPER, DB, "CREATE EXTENSION IF NOT EXISTS pgstattuple")


def refresh_leases(cl: Cluster, db: str) -> None:
    """The leases and deadlines of the load are relative to the moment it ran. Put them back where the load meant them to be:
    one attempt in ten holds a lease that expired five minutes ago, one in seven is past its deadline, the rest are live for 55 minutes."""
    cl.psql(SUPER, db, """BEGIN;
      SET LOCAL session_replication_role = replica;
      UPDATE attempts a SET lease_expires_at = CASE WHEN p.n % 10 = 0 THEN now() - interval '5 minutes' ELSE now() + interval '55 minutes' END,
                            last_heartbeat_at = now() - interval '10 seconds',
                            deadline_at = CASE WHEN p.n % 7 = 0 THEN now() - interval '1 minute' ELSE now() + interval '3 hours' END
        FROM perf.job_plan p WHERE a.tenant_id = p.tenant_id AND a.job_id = p.job_id AND a.status = 'RUNNING';
      UPDATE stage_runs s SET not_before = now() - interval '2 days' + p.n * interval '10 seconds'
        FROM perf.job_plan p WHERE s.tenant_id = p.tenant_id AND s.job_id = p.job_id AND s.status = 'READY';
      COMMIT;""")
    cl.psql(SUPER, db, "VACUUM (ANALYZE) attempts, stage_runs")


def clone_for_writes(cl: Cluster) -> None:
    cl.psql(SUPER, DB_ADMIN, f'CREATE DATABASE "{DBW}" TEMPLATE "{DB}" STRATEGY FILE_COPY')
    cl.psql(SUPER, DBW, file=HERE / "scenarios.sql")


# ---------------------------------------------------------------------------------------------
# Identity: numbers are only reported for the real login.

def preflight(cl: Cluster, role: str, db: str, rls_expected: bool = True) -> dict:
    """Prove that `role`'s login is what the design allows. Raises Refused if not."""
    login = LOGINS[role][0]
    out, rc = cl.psql(login, db, vars={"who": login}, check=False, tuples=True, sql=(
        "SELECT json_build_object('user', current_user, 'session_user', session_user, 'super', r.rolsuper, "
        "'bypassrls', r.rolbypassrls, 'createrole', r.rolcreaterole, 'owns', (SELECT count(*) FROM pg_class c WHERE c.relowner = r.oid), "
        "'groups', (SELECT json_agg(g.rolname ORDER BY g.rolname) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid WHERE m.member = r.oid), "
        "'is_superuser_setting', current_setting('is_superuser')) FROM pg_roles r WHERE r.rolname = current_user"))
    if rc != 0:
        raise Refused(f"the harness could not log in as {login}: {out.strip()[:300]}")
    facts = json.loads(out.strip().splitlines()[-1])
    problems = []
    if facts["super"] or facts["is_superuser_setting"] == "on":
        problems.append("is a superuser")
    if facts["bypassrls"]:
        problems.append("has BYPASSRLS")
    if facts["owns"]:
        problems.append("owns relations")
    if facts["user"] != login or facts["session_user"] != login:
        problems.append(f"is {facts['user']}/{facts['session_user']}, not {login}")
    if sorted(facts["groups"] or []) != sorted(LOGINS[role][1]):
        problems.append(f"belongs to {facts['groups']}, expected {LOGINS[role][1]}")
    if problems:
        raise Refused(f"REFUSED: {login} {', '.join(problems)}. A number measured there says nothing about the real login.")
    if rls_expected:
        unforced = cl.scalar(SUPER, db, "SELECT count(*) FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' "
                             "AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped) "
                             "AND NOT (c.relrowsecurity AND c.relforcerowsecurity)")
        if unforced != "0":
            raise Refused(f"REFUSED: {unforced} tenant tables do not have row-level security enabled and forced; the numbers would not be those of the design")
    return facts


GUARD = ("SELECT 1 / (NOT r.rolsuper AND NOT r.rolbypassrls AND r.rolname = :'who' AND session_user = :'who')::int "
         "FROM pg_roles r WHERE r.rolname = current_user;")


# ---------------------------------------------------------------------------------------------
# The statements. Each is the text the storage crate sends (file and function in `rust`), with the placeholders it uses.

S_TENANT = "SELECT set_config('factory.tenant_id', $1, true)"
S_LIMITS = "SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $2, true)"
S_COMBINED = "SELECT set_config('factory.tenant_id', $1, true), set_config('statement_timeout', $2, true), set_config('lock_timeout', $3, true)"


@dataclasses.dataclass
class Series:
    id: str
    role: str                    # worker | engine | api
    pool: str                    # big | small | long | system | api
    steps: list[tuple[str, str]]  # (prepared name, sql)
    bind: Callable[[dict, int], list[list[str]]]
    budget_ms: float
    what: str
    rust: str
    writes: bool = False
    seqscan_forbidden: bool = True
    tenant: bool = True          # opens the transaction with the tenant setting
    claim_path: bool = False


def b_job(r, i): return [[r["tenant_id"], r["job_id"]]]


def _q(sql: str) -> str:
    return " ".join(sql.split())


CLAIM = _q("""SELECT s.tenant_id, s.job_id, s.id, s.version, s.not_before FROM stage_runs s
  JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
  WHERE s.status = 'READY' AND s.not_before <= now() ORDER BY s.not_before, s.id LIMIT $1 FOR NO KEY UPDATE OF s SKIP LOCKED""")
LEASE_EXPIRED = _q("""SELECT tenant_id, job_id, stage_run_id, id, version FROM attempts WHERE status IN ('STARTING', 'RUNNING')
  AND lease_expires_at < now() ORDER BY lease_expires_at, id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED""")
DEADLINE = _q("""SELECT tenant_id, job_id, stage_run_id, id, version FROM attempts WHERE status IN ('STARTING', 'RUNNING')
  AND deadline_at < now() ORDER BY deadline_at, id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED""")
TEARDOWN = _q("""SELECT tenant_id, job_id, stage_run_id, id, version FROM attempts WHERE status = 'CANCELLING'
  AND teardown_deadline_at < now() ORDER BY teardown_deadline_at, id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED""")
RELAY = _q("SELECT event_id FROM outbox WHERE published_at IS NULL ORDER BY seq LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED")

RUN_COLS = "id, job_id, stage_kind, run_number, status, version, lease_epoch, max_attempts, not_before, gate_outcome, gate_report_sha256, created_at, updated_at, finished_at"
ATT_COLS = "id, job_id, stage_run_id, attempt_number, status, version, lease_owner, lease_epoch, lease_expires_at, last_heartbeat_at, deadline_at, failure_class, output_sha256, created_at, ended_at"
OUTBOX_COLS = ("seq, event_id, event_type, event_version, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, reason_code, "
               "correlation_id, causation_id, occurred_at, producer, traceparent, payload, payload_schema_name, payload_schema_version")
ART_COLS = "tenant_id, content_sha256, size_bytes, media_type, created_by_job_id, created_by_stage_run_id, created_at"


def run_id(n: int, k: int) -> str:
    return uid("run", n * 100 + k)


def uid(kind: str, n: int) -> str:
    """Python mirror of perf.uid (checked against the database in self_check)."""
    h = hashlib.md5(f"{kind}:{n}".encode()).hexdigest()
    s = f"{n:012x}" + "7" + h[0:3] + "8" + h[3:18]
    return f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"


def sha(kind: str, n: int) -> str:
    return "sha256:" + hashlib.sha256(f"{kind}:{n}".encode()).hexdigest()


def series_catalogue(limit: int = 10) -> list[Series]:
    S: list[Series] = []
    add = S.append
    # ---- the engine login (system scope): finders
    add(Series("claim_candidates", "engine", "system", [("q", CLAIM)], lambda r, i: [[str(limit)]], 5.0,
               "find_claim_candidates: READY runs of ACTIVE jobs, oldest first, LIMIT 10, FOR NO KEY UPDATE SKIP LOCKED",
               "crates/storage/src/pg/system.rs CLAIM_CANDIDATES", tenant=False, claim_path=True))
    add(Series("due_lease_expired", "engine", "system", [("q", LEASE_EXPIRED)], lambda r, i: [[str(limit)]], 5.0,
               "find_due_attempts: lease expired (A07)", "crates/storage/src/pg/system.rs LEASE_EXPIRED", tenant=False, claim_path=True))
    add(Series("due_deadline_passed", "engine", "system", [("q", DEADLINE)], lambda r, i: [[str(limit)]], 5.0,
               "find_due_attempts: attempt deadline passed (A06)", "crates/storage/src/pg/system.rs DEADLINE_PASSED", tenant=False, claim_path=True))
    add(Series("due_teardown_passed", "engine", "system", [("q", TEARDOWN)], lambda r, i: [[str(limit)]], 5.0,
               "find_due_attempts: teardown deadline passed (A10)", "crates/storage/src/pg/system.rs TEARDOWN_PASSED", tenant=False, claim_path=True))
    add(Series("outbox_relay_poll", "engine", "system", [("q", RELAY)], lambda r, i: [["100"]], 5.0,
               "relay: unpublished outbox rows in order, LIMIT 100, FOR NO KEY UPDATE SKIP LOCKED",
               "docs/database/tests/outbox.sql (the relay is not in the Rust crate yet)", tenant=False))
    # ---- tenant reads, for a big tenant and a small one
    for pool in ("big", "small"):
        add(Series(f"job_get@{pool}", "worker", pool,
                   [("q", "SELECT id, repository_id, status, version, autonomy_level, pipeline_scope, ledger_head_sequence, ledger_head_hash, created_at, updated_at, terminal_at FROM jobs WHERE tenant_id = $1 AND id = $2")],
                   b_job, 5.0, "get_job by tenant and id", "crates/storage/src/pg/jobs.rs"))
        add(Series(f"list_jobs_page@{pool}", "worker", pool,
                   [("q", "SELECT id, repository_id, status, version, created_at FROM jobs WHERE tenant_id = $1 AND (created_at, id) < ($2::timestamptz, $3::uuid) ORDER BY created_at DESC, id DESC LIMIT $4")],
                   lambda r, i: [[r["tenant_id"], r["created_at"], r["job_id"], "50"]], 5.0, "list_jobs: next page by keyset, 50 rows", "crates/storage/src/pg/jobs.rs"))
        add(Series(f"list_jobs_repo@{pool}", "worker", pool,
                   [("q", "SELECT id, repository_id, status, version, created_at FROM jobs WHERE tenant_id = $1 AND repository_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3")],
                   lambda r, i: [[r["tenant_id"], r["repository_id"], "50"]], 5.0, "list_jobs: one repository, 50 rows (jobs_repository_listing_idx)", "crates/storage/src/pg/jobs.rs"))
        add(Series(f"stage_runs_by_job@{pool}", "worker", pool,
                   [("q", f"SELECT {RUN_COLS} FROM stage_runs WHERE tenant_id = $1 AND job_id = $2 ORDER BY created_at, run_number, id")],
                   b_job, 5.0, "list_stage_runs of one job (timeline)", "crates/storage/src/pg/stage_runs.rs:208"))
        add(Series(f"check_run_history@{pool}", "worker", pool,
                   [("q", f"SELECT {ATT_COLS} FROM attempts WHERE tenant_id = $1 AND job_id = $2 ORDER BY created_at, attempt_number")],
                   b_job, 5.0, "attempts of every stage run of one job (the check run history)", "crates/storage/src/pg/attempts.rs list, by job"))
        add(Series(f"gate_records_by_job@{pool}", "worker", pool,
                   [("q", "SELECT id, stage_kind, run_number, status, gate_outcome, gate_report_sha256, finished_at FROM stage_runs WHERE tenant_id = $1 AND job_id = $2 AND gate_outcome IS NOT NULL ORDER BY created_at"),
                    ("a", "SELECT id, decision, approver_principal_id, pr_head_sha, expires_at FROM approvals WHERE tenant_id = $1 AND job_id = $2 ORDER BY created_at")],
                   lambda r, i: [[r["tenant_id"], r["job_id"]], [r["tenant_id"], r["job_id"]]], 5.0, "gate outcomes of one job and its approvals", "crates/storage/src/pg/stage_runs.rs, approvals.rs"))
        add(Series(f"outbox_timeline@{pool}", "worker", pool,
                   [("q", f"SELECT {OUTBOX_COLS} FROM outbox WHERE tenant_id = $1 AND job_id = $2 AND seq >= $3 ORDER BY seq LIMIT $4")],
                   lambda r, i: [[r["tenant_id"], r["job_id"], "0", "100"]], 5.0, "read_events: the outbox events of one job", "crates/storage/src/pg/outbox.rs read"))
        add(Series(f"ledger_timeline@{pool}", "worker", pool,
                   [("e", "SELECT 1 FROM jobs WHERE tenant_id = $1 AND id = $2"),
                    ("q", "SELECT canonical_json, entry_hash FROM ledger_entries WHERE tenant_id = $1 AND job_id = $2 AND sequence >= $3 ORDER BY sequence LIMIT $4")],
                   lambda r, i: [[r["tenant_id"], r["job_id"]], [r["tenant_id"], r["job_id"], "1", "100"]], 5.0, "read_ledger: the entries of one job, first 100", "crates/storage/src/pg/ledger.rs read"))
        add(Series(f"ledger_tail@{pool}", "worker", pool,
                   [("q", "SELECT sequence, entry_hash FROM ledger_entries WHERE tenant_id = $1 AND job_id = $2 ORDER BY sequence DESC LIMIT 1"),
                    ("h", "SELECT ledger_head_sequence AS sequence, ledger_head_hash AS hash FROM jobs WHERE tenant_id = $1 AND id = $2")],
                   lambda r, i: [[r["tenant_id"], r["job_id"]], [r["tenant_id"], r["job_id"]]], 5.0, "ledger tail: last entry of a job, and the head on the job row", "crates/storage/src/pg/ledger.rs head; plans.sql"))
        add(Series(f"audit_timeline@{pool}", "worker", pool,
                   [("q", "SELECT sequence, event_id, action, decision, created_at, hash FROM audit_events WHERE tenant_id = $1 AND job_id = $2 ORDER BY sequence LIMIT $3")],
                   lambda r, i: [[r["tenant_id"], r["job_id"], "100"]], 5.0, "read_audit of one job", "crates/storage/src/pg/audit.rs"))
        add(Series(f"audit_tail@{pool}", "worker", pool,
                   [("q", "SELECT sequence, hash FROM audit_events WHERE tenant_id = $1 ORDER BY sequence DESC LIMIT 1")],
                   lambda r, i: [[r["tenant_id"]]], 5.0, "audit tail: the head of the tenant's chain", "docs/database/tests/plans.sql"))
        add(Series(f"artifact_lookup@{pool}", "worker", pool,
                   [("q", f"SELECT {ART_COLS} FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2")],
                   lambda r, i: [[r["tenant_id"], r["out_sha"]]], 5.0, "get_artifact_index by tenant and sha256", "crates/storage/src/pg/artifact_index.rs get"))
        add(Series(f"artifact_consumers@{pool}", "worker", pool,
                   [("q", "SELECT stage_run_id, job_id, direction FROM stage_run_artifacts WHERE tenant_id = $1 AND content_sha256 = $2")],
                   lambda r, i: [[r["tenant_id"], r["out_sha"]]], 5.0, "runs that consumed one artifact hash (invalidation)", "docs/database/tests/plans.sql"))
    add(Series("ledger_tail@long", "worker", "long",
               [("q", "SELECT sequence, entry_hash FROM ledger_entries WHERE tenant_id = $1 AND job_id = $2 ORDER BY sequence DESC LIMIT 1")],
               b_job, 5.0, "ledger tail of a 200 entry job", "crates/storage/src/pg/ledger.rs head"))
    add(Series("ledger_timeline@long", "worker", "long",
               [("q", "SELECT canonical_json, entry_hash FROM ledger_entries WHERE tenant_id = $1 AND job_id = $2 AND sequence >= $3 ORDER BY sequence LIMIT $4")],
               lambda r, i: [[r["tenant_id"], r["job_id"], "1", "100"]], 8.0, "read_ledger of a 200 entry job, first 100 (about 120 KB)", "crates/storage/src/pg/ledger.rs read"))
    # ---- the API login: the two lookups before a tenant is known (no tenant setting)
    add(Series("resolve_token", "api", "api", [("q", "SELECT * FROM resolve_token($1::bytea, $2)")],
               lambda r, i: [[r["token_hash"], "factory-api"]], 5.0, "resolve_token(hash, audience)", "crates/storage/src/pg/principals.rs", tenant=False))
    add(Series("resolve_installation", "api", "api", [("q", "SELECT * FROM resolve_installation($1::bigint, $2::bigint)")],
               lambda r, i: [[r["installation"], r["github_repo"]]], 5.0, "resolve_installation(installation, repository)", "crates/storage/src/pg/principals.rs", tenant=False))
    return S


def write_series(state: dict) -> list[Series]:
    """Statements that write. They run on the clone and commit, so the deferred triggers run too."""
    heads = state["heads"]

    def doc_for(job: str, run: str, att: Optional[str], seq: int, prev: Optional[str], entry: str) -> tuple[str, str]:
        meta = {"entry_id": entry, "job_id": job, "stage_run_id": run, "sequence": seq,
                "recorded_at": "2026-10-28T12:00:00Z", "execution_mode": "production",
                "recorded_by": {"component": "workflow.gate-evaluator", "fidelity": "real"}}
        if att:
            meta["attempt_id"] = att
        body = {"schema_version": 1, "metadata": meta,
                "claim": {"statement": "The gate for this stage passed on the job branch: the build, the tests and the lint check all returned zero, and the report hash matches the stored report. " + "The evidence is attached. " * 4,
                          "kind": "measured_fact", "assurance_level": "VERIFIED_IN_SANDBOX"},
                "evidence": [{"kind": "artifact", "sha256": sha("out", seq), "media_type": "application/json", "size_bytes": 4096},
                             {"kind": "artifact", "sha256": sha("out", seq + 1), "media_type": "application/json", "size_bytes": 8192},
                             {"kind": "command", "argv": ["cargo", "nextest", "run", "--workspace"], "exit_code": 0}],
                "confidence": {"level": "high", "rationale": "The gate report hash matches the stored report and the sandbox was real."},
                "invalidates": [], "prev_entry_hash": prev}
        text = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return text, "sha256:" + hashlib.sha256(((prev or "") + "\n" + text).encode()).hexdigest()

    def b_start(r, i):
        t, run = r["tenant_id"], r["ready_run"]
        return [[t, run], [t, r["job_id"]], [t, run], [t, run, uid("attnew", r["n"])], [t, run, "1"],
                [t, uid("attnew", r["n"]), r["job_id"], run, "1", "STARTING", "perf-worker-a", "1", "30000000", "3600000000"]]

    start = Series("start_attempt", "worker", "active", [
        ("s1", "SELECT job_id AS id FROM stage_runs WHERE tenant_id = $1 AND id = $2"),
        ("s2", "SELECT status FROM jobs WHERE tenant_id = $1 AND id = $2 FOR SHARE"),
        ("s3", "SELECT status, version, lease_epoch, max_attempts, attempts_before_last_answer, (not_before <= now()) AS due FROM stage_runs WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE"),
        ("s4", "SELECT coalesce(max(attempt_number), 0) AS last_number, coalesce(bool_or(status IN ('STARTING', 'RUNNING', 'CANCELLING')), false) AS live, coalesce(bool_or(id = $3), false) AS id_taken FROM attempts WHERE tenant_id = $1 AND stage_run_id = $2"),
        ("s5", f"UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1 WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = 'READY' RETURNING {RUN_COLS}"),
        ("s6", f"INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, status, lease_owner, lease_epoch, lease_expires_at, deadline_at) VALUES ($1, $2, $3, $4, $5::int, $6, $7, $8::bigint, now() + $9::bigint * interval '1 microsecond', now() + $10::bigint * interval '1 microsecond') RETURNING {ATT_COLS}"),
    ], b_start, 10.0, "start_attempt: job FOR SHARE, run FOR NO KEY UPDATE, count attempts, swap the run to RUNNING, insert the attempt; commit runs the deferred checks",
        "crates/storage/src/pg/attempts.rs start_attempt", writes=True, claim_path=True)
    heartbeat = Series("heartbeat", "worker", "live", [
        ("q", "UPDATE attempts SET lease_expires_at = now() + $5::bigint * interval '1 microsecond', last_heartbeat_at = now(), version = version + 1 WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND lease_epoch = $4 AND status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at > now() RETURNING status, lease_expires_at, deadline_at")],
        lambda r, i: [[r["tenant_id"], r["live_attempt"], r["owner"], "1", "30000000"]], 5.0, "heartbeat: renew the lease of a live attempt",
        "crates/storage/src/pg/attempts.rs heartbeat", writes=True, claim_path=True)

    def b_append(r, i):
        job = r["job_id"]
        seq, prev = heads[job]
        entry = uid("ledw", (r["n"] << 20) + seq + 1)
        run = run_id(r["n"], 1 + seq % 10)
        text, h = doc_for(job, run, None, seq + 1, prev, entry)
        heads[job] = (seq + 1, h)
        t = r["tenant_id"]
        return [[t, job], [t, job, str(seq + 1), entry, run, "2026-10-28T12:00:00Z", "production", "workflow.gate-evaluator", "real",
                           "measured_fact", "VERIFIED_IN_SANDBOX", "high", "{}", prev if prev else "", h, text],
                [t, job, str(seq + 1), h, str(seq)]]

    append = Series("append_ledger_entry", "worker", "append", [
        ("s1", "SELECT ledger_head_sequence AS sequence, ledger_head_hash AS hash FROM jobs WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE"),
        ("s2", "INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, attempt_id, recorded_at, execution_mode, recorded_component, recorded_fidelity, claim_kind, assurance_level, confidence_level, invalidates, prev_entry_hash, entry_hash, canonical_json) VALUES ($1, $2, $3::bigint, $4, $5, NULL, $6::timestamptz, $7, $8, $9, $10, $11, $12, $13::uuid[], NULLIF($14, ''), $15, $16)"),
        ("s3", "UPDATE jobs SET ledger_head_sequence = $3::bigint, ledger_head_hash = $4 WHERE tenant_id = $1 AND id = $2 AND ledger_head_sequence = $5::bigint"),
    ], b_append, 15.0, "append_ledger_entry: lock the job and read the head, insert the entry (trigger re-verifies the hash), move the head",
        "crates/storage/src/pg/ledger.rs append", writes=True)

    def b_event(r, i):
        t = r["tenant_id"]
        return [[t, r["job_id"]], [t, uid("evtw", (r["n"] << 8) + i % 200), "stage_run.ready", "1", r["job_id"], "stage_run", r["quiet_run"], "1", "S01",
                uid("corr", r["n"]), "2026-10-28T12:00:00Z", "workflow.engine", '{"stage":"perf","summary":"Ready."}']]

    event = Series("enqueue_event", "worker", "quiet", [
        ("s1", "SELECT 1 FROM jobs WHERE tenant_id = $1 AND id = $2"),
        ("s2", "INSERT INTO outbox (tenant_id, event_id, event_type, event_version, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, correlation_id, occurred_at, producer, payload) VALUES ($1, $2, $3, $4::int, $5, $6, $7, $8::bigint, $9, $10, $11::timestamptz, $12, $13::jsonb) ON CONFLICT DO NOTHING"),
    ], b_event, 10.0, "enqueue_event: insert one outbox row (deferred aggregate check at commit)", "crates/storage/src/pg/outbox.rs enqueue", writes=True)

    def b_art(r, i):
        t = r["tenant_id"]
        return [[t, r["job_id"], run_id(r["n"], 1)],
                [t, sha("new", (r["n"] << 20) + i), "4096", "application/json", "local-fs", r["job_id"], run_id(r["n"], 1)],
                [t, sha("new", (r["n"] << 20) + i)]]

    art = Series("index_artifact", "worker", "quiet", [
        ("s1", "SELECT EXISTS (SELECT 1 FROM stage_runs WHERE tenant_id = $1 AND job_id = $2 AND id = $3) AS found"),
        ("s2", "INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend, created_by_job_id, created_by_stage_run_id) VALUES ($1, $2, $3::bigint, $4, $5, $6, $7) ON CONFLICT (tenant_id, content_sha256) DO NOTHING"),
        ("s3", f"SELECT {ART_COLS} FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2"),
    ], b_art, 10.0, "index_artifact: check the origin, insert, read back", "crates/storage/src/pg/artifact_index.rs index", writes=True)

    def b_audit(r, i):
        return [[r["tenant_id"], uid("audw", (r["n"] << 20) + i), "service", "engine", "gate.result", f"job:{r['n']}:perf:{i}", "record",
                 "The engine recorded the decision after the gate result was stored.", sha("policy", 1), r["job_id"], uid("corr", r["n"])]]

    audit = Series("audit_append", "worker", "quiet", [
        ("q", "INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, job_id, correlation_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)")],
        b_audit, 15.0, "audit append: the trigger takes the tenant's advisory lock, reads the tail, hashes", "crates/storage/src/pg/audit.rs", writes=True)
    return [start, heartbeat, append, event, art, audit]


# ---------------------------------------------------------------------------------------------
# Parameter pools, from the plan tables (superuser reads; the logins never see them).

def load_pools(cl: Cluster, db: str, seed: int) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    def sql_rows(where: str, order_extra: str, n: int) -> str:
        return f"""
      SELECT json_build_object('n', j.n, 'class', j.class, 'tenant_idx', j.tenant_idx, 'tenant_id', j.tenant_id, 'job_id', j.job_id,
             'repository_id', jr.repository_id, 'created_at', jr.created_at)
        FROM perf.job_plan j JOIN public.jobs jr ON jr.tenant_id = j.tenant_id AND jr.id = j.job_id
       WHERE {where} ORDER BY md5(j.n::text || '{seed}') {order_extra} LIMIT {n}"""
    pools_sql = {
        "big": sql_rows("j.tenant_idx = 1", "", 400),
        "small": sql_rows("j.tenant_idx >= 6", "", 400),
        "long": sql_rows("j.n % 500 = 0", "", 60),
        "active": sql_rows("j.class = 'A'", "", 600),
        "live": sql_rows("j.class = 'A' AND j.n % 10 <> 0 AND j.n % 7 <> 0", "", 600),
        "quiet": sql_rows("j.class = 'C'", "", 600),
        "append": sql_rows("j.class = 'C' AND j.n % 500 <> 0", "", 600),
    }
    pools: dict[str, list[dict]] = {}
    for name, q in pools_sql.items():
        rows = [json.loads(line) for line in cl.psql(SUPER, db, q, tuples=True).splitlines() if line]
        for r in rows:
            n = r["n"]
            r["out_sha"] = sha("out", n * 100 + 1 + (n % 3))
            r["ready_run"] = run_id(n, 6)
            r["quiet_run"] = run_id(n, 4)
            r["live_attempt"] = uid("att", (n * 100 + 7) * 10 + 1)
            r["owner"] = f"worker-{n % 8}"
        pools[name] = rows
    # lookups
    tok = cl.query(SUPER, db, "SELECT encode(token_hash, 'hex'), tenant_id FROM api_tokens ORDER BY id LIMIT 200")
    repos = cl.query(SUPER, db, "SELECT github_installation_id, github_repository_id FROM repositories ORDER BY github_repository_id LIMIT 400")
    pools["api"] = [{"token_hash": "\\x" + t[0], "installation": r[0], "github_repo": r[1]} for t, r in zip(tok * 3, repos)]
    pools["system"] = [{}]
    for rows in pools.values():
        rng.shuffle(rows)
    return pools


# ---------------------------------------------------------------------------------------------
# Timing with psql.

TIME_RE = re.compile(r"^Time: ([0-9.]+) ms")


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def summarize(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {"n": len(values), "p50": round(pct(values, 50), 3), "p95": round(pct(values, 95), 3), "p99": round(pct(values, 99), 3),
            "mean": round(statistics.fmean(values), 3), "max": round(max(values), 3)}


def sql_lit(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def psql_param(v: str) -> str:
    # psql meta-command arguments: single-quoted, doubling quotes. A value that begins with a backslash or holds a newline is not used here.
    return "'" + v.replace("\\", "\\\\").replace("'", "''") + "'"


def build_script(s: Series, pool: list[dict], iterations: int, login: str, preamble: str, rng_offset: int = 0) -> tuple[str, int, int]:
    """Returns (script, prelude_commands, commands_per_iteration)."""
    lines = ["\\set ON_ERROR_STOP on", "\\o /dev/null", GUARD, "\\timing on"]
    prelude = 0
    names = []
    if s.tenant:
        if preamble == "combined":
            lines.append(f"{S_COMBINED} \\parse p_all")
            prelude += 1
        else:
            lines.append(f"{S_TENANT} \\parse p_tenant")
            lines.append(f"{S_LIMITS} \\parse p_limits")
            prelude += 2
    else:
        lines.append(f"{S_LIMITS} \\parse p_limits")
        prelude += 1
    for name, sql in s.steps:
        lines.append(f"{sql} \\parse {name}")
        prelude += 1
        names.append(name)
    per = 2 + len(s.steps)       # BEGIN, steps, COMMIT
    per += (1 if (s.tenant and preamble == "combined") else 2) if s.tenant else 1
    for i in range(iterations):
        row = pool[(i + rng_offset) % len(pool)]
        binds = s.bind(row, i)
        lines.append("BEGIN;")
        if s.tenant:
            if preamble == "combined":
                lines.append(f"\\bind_named p_all {psql_param(row['tenant_id'])} {psql_param(TX_LIMITS[0])} {psql_param(TX_LIMITS[1])} \\g")
            else:
                lines.append(f"\\bind_named p_tenant {psql_param(row['tenant_id'])} \\g")
                lines.append(f"\\bind_named p_limits {psql_param(TX_LIMITS[0])} {psql_param(TX_LIMITS[1])} \\g")
        else:
            lines.append(f"\\bind_named p_limits {psql_param(TX_LIMITS[0])} {psql_param(TX_LIMITS[1])} \\g")
        for (name, _), params in zip(s.steps, binds):
            lines.append(f"\\bind_named {name} " + " ".join(psql_param(p) for p in params) + " \\g")
        lines.append("COMMIT;")
    return "\n".join(lines) + "\n", prelude, per


def run_timed(cl: Cluster, s: Series, pool: list[dict], iterations: int, db: str, preamble: str = "separate", login_override: Optional[str] = None,
              rng_offset: int = 0, work: Optional[Path] = None) -> list[dict]:
    login = login_override or LOGINS[s.role][0]
    script, prelude, per = build_script(s, pool, iterations, login, preamble, rng_offset)
    path = (work or Path(tempfile.gettempdir())) / f"series-{re.sub(r'[^a-z0-9_]', '_', s.id)}.sql"
    path.write_text(script)
    proc = subprocess.run([str(cl.bin / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", f"who={LOGINS[s.role][0]}", "-U", login, "-d", db, "-f", str(path)],
                          capture_output=True, text=True, env=cl.env(login))
    if proc.returncode != 0:
        err = proc.stderr.strip()
        if "division by zero" in err:
            raise Refused(f"REFUSED: the session for series {s.id} is {login}, which is a superuser or bypasses row-level security (the guard statement failed). No numbers are reported.")
        raise RuntimeError(f"series {s.id} failed as {login}: {err[:800]}")
    times = [float(m.group(1)) for line in proc.stdout.splitlines() if (m := TIME_RE.match(line))]
    times = times[prelude:]
    if len(times) != per * iterations:
        raise RuntimeError(f"series {s.id}: expected {per * iterations} timings, parsed {len(times)}")
    out = []
    for i in range(iterations):
        t = times[i * per:(i + 1) * per]
        nsteps = len(s.steps)
        if s.tenant:
            pre = 1 + (1 if preamble == "combined" else 2)
        else:
            pre = 2
        out.append({"tx": sum(t), "begin": t[0], "preamble": sum(t[1:pre]), "query": sum(t[pre:pre + nsteps]), "commit": t[-1],
                    "steps": t[pre:pre + nsteps]})
    return out


def measure_series(cl: Cluster, s: Series, pool: list[dict], db: str, warm_n: int, cold_n: int, work: Path, phase: str, preamble: str = "separate") -> dict:
    n = cold_n if phase == "cold" else warm_n + 30
    runs = run_timed(cl, s, pool, n, db, preamble=preamble, work=work)
    if phase == "warm":
        runs = runs[30:]
    return {k: summarize([r[k] for r in runs]) for k in ("tx", "query", "preamble", "begin", "commit")} | {"steps": [summarize([r["steps"][j] for r in runs]) for j in range(len(s.steps))]}


# ---------------------------------------------------------------------------------------------
# Plans.

def literal_sql(sql: str, params: list[str]) -> str:
    out = sql
    for idx in range(len(params), 0, -1):
        v = params[idx - 1]
        lit = v if re.fullmatch(r"-?\d+", v) else sql_lit(v)
        out = re.sub(rf"\${idx}(?!\d)", lit.replace("\\", "\\\\"), out)
    return out


def walk(node: dict, acc: list[dict]) -> None:
    acc.append(node)
    for ch in node.get("Plans", []) or []:
        walk(ch, acc)


def explain_series(cl: Cluster, s: Series, row: dict, db: str, rel_rows: dict[str, float]) -> dict:
    login = LOGINS[s.role][0]
    binds = s.bind(row, 0)
    cmds = ["BEGIN"]
    if s.tenant:
        cmds.append(f"SELECT set_config('factory.tenant_id', {sql_lit(row['tenant_id'])}, true)")
    cmds.append(f"SELECT set_config('statement_timeout', '{TX_LIMITS[0]}', true), set_config('lock_timeout', '{TX_LIMITS[1]}', true)")
    marks = []
    for (name, sql), params in zip(s.steps, binds):
        cmds.append("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + literal_sql(sql, params))
        marks.append(len(cmds) - 1)
    cmds.append("ROLLBACK")
    # run each EXPLAIN twice (the second is warm) except for writes, which are rolled back and so safe to repeat
    plans = []
    for rep in range(2):
        script = "\\set ON_ERROR_STOP on\n\\pset format unaligned\n\\pset tuples_only on\n" + GUARD + "\n" + "\n".join(
            (c + ";") if not c.startswith("EXPLAIN") else (c + ";") for c in cmds) + "\n"
        proc = subprocess.run([str(cl.bin / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", f"who={login}", "-U", login, "-d", db, "-f", "-"],
                              input=script, capture_output=True, text=True, env=cl.env(login))
        if proc.returncode != 0:
            err = proc.stderr
            if "division by zero" in err:
                raise Refused(f"REFUSED: plan session for {s.id} is not the real login")
            raise RuntimeError(f"EXPLAIN for {s.id} failed: {err[:800]}")
        blobs = []
        buf: list[str] = []
        for line in proc.stdout.splitlines():
            if not buf and line != "[":
                continue          # the output of the set_config statements and the guard
            buf.append(line)
            if line == "]":
                blobs.append(json.loads("\n".join(buf)))
                buf = []
        plans = blobs
    steps = []
    for (name, sql), blob in zip(s.steps, plans):
        top = blob[0]
        nodes: list[dict] = []
        walk(top["Plan"], nodes)
        seq = [{"relation": n.get("Relation Name"), "rows_in_table": rel_rows.get(n.get("Relation Name", ""), 0), "rows_scanned": n.get("Actual Rows", 0) * n.get("Actual Loops", 1) + n.get("Rows Removed by Filter", 0) * n.get("Actual Loops", 1)}
               for n in nodes if n["Node Type"] == "Seq Scan"]
        idx = [{"index": n.get("Index Name"), "type": n["Node Type"], "relation": n.get("Relation Name")} for n in nodes if "Index" in n["Node Type"] and n.get("Index Name")]
        texts = " ".join(str(n.get(k, "")) for n in nodes for k in ("Filter", "Index Cond", "One-Time Filter", "Recheck Cond", "Join Filter"))
        steps.append({
            "step": name, "node_types": [n["Node Type"] for n in nodes], "seq_scans": seq, "index_scans": idx,
            "actual_rows": top["Plan"].get("Actual Rows"), "execution_ms": round(top.get("Execution Time", 0), 3), "planning_ms": round(top.get("Planning Time", 0), 3),
            "shared_hit": top["Plan"].get("Shared Hit Blocks", 0), "shared_read": top["Plan"].get("Shared Read Blocks", 0),
            "rows_removed_by_filter": sum(n.get("Rows Removed by Filter", 0) for n in nodes),
            "rls_in_plan": "current_setting" in texts, "triggers": [{"name": t["Trigger Name"], "ms": round(t["Time"], 3), "calls": t["Calls"]} for t in top.get("Triggers", [])],
            "root": top["Plan"]["Node Type"],
        })
    return {"steps": steps}


# ---------------------------------------------------------------------------------------------
# What the policy does to a plan.

def policy_probe(cl: Cluster, pools: dict) -> dict:
    """Plans, as the real logins, that show what the policy expression becomes: a one-time filter when the query names the tenant,
    an index condition when it does not, and nothing at all for the system role (USING (true))."""
    r = pools["big"][0]
    worker, engine = LOGINS["worker"][0], LOGINS["engine"][0]

    def plan(login: str, role: str, tenant: Optional[str], sql: str) -> str:
        cmds = ["BEGIN"]
        if tenant:
            cmds.append(f"SELECT set_config('factory.tenant_id', {sql_lit(tenant)}, true)")
        cmds.append("EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, TIMING OFF, SUMMARY OFF) " + sql)
        cmds.append("ROLLBACK")
        script = "\\set ON_ERROR_STOP on\n\\o /dev/null\n" + GUARD + "\n\\o\n\\pset tuples_only on\n" + ";\n".join(cmds) + ";\n"
        proc = subprocess.run([str(cl.bin / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", f"who={login}", "-U", login, "-d", DB, "-f", "-"],
                              input=script, capture_output=True, text=True, env=cl.env(login))
        if proc.returncode != 0:
            raise RuntimeError(f"policy probe failed as {login}: {proc.stderr[:500]}")
        return "\n".join(line for line in proc.stdout.splitlines() if line.strip() and not re.fullmatch(r"[0-9a-f-]{36}", line.strip()))

    t, j = r["tenant_id"], r["job_id"]
    return {
        "names_the_tenant": plan(worker, "worker", t, f"SELECT id, status FROM jobs WHERE tenant_id = '{t}' AND id = '{j}'"),
        "forgets_the_tenant_by_primary_key": plan(worker, "worker", t, f"SELECT id, status FROM jobs WHERE id = '{j}'"),
        "forgets_the_tenant_on_a_timeline": plan(worker, "worker", t, f"SELECT seq FROM outbox WHERE job_id = '{j}' ORDER BY seq LIMIT 100"),
        "no_tenant_setting": plan(worker, "worker", None, f"SELECT id FROM jobs WHERE id = '{j}'"),
        "system_role_claim": plan(engine, "engine", None, "SELECT s.id FROM stage_runs s JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE' "
                                                          "WHERE s.status = 'READY' AND s.not_before <= now() ORDER BY s.not_before, s.id LIMIT 10 FOR NO KEY UPDATE OF s SKIP LOCKED"),
    }


# ---------------------------------------------------------------------------------------------
# Verification of the chains.

def verify_chains(cl: Cluster, db: str) -> dict:
    bad_ledger = cl.query(SUPER, db, "SELECT tenant_id, id, ledger_verify_chain(tenant_id, id) AS bad FROM jobs WHERE ledger_verify_chain(tenant_id, id) IS NOT NULL ORDER BY 1, 2 LIMIT 20")
    bad_audit = cl.query(SUPER, db, "SELECT id, audit_verify_chain(id) FROM tenants WHERE audit_verify_chain(id) IS NOT NULL")
    counts = cl.query(SUPER, db, "SELECT (SELECT count(*) FROM jobs), (SELECT count(*) FROM tenants WHERE kind = 'customer'), (SELECT count(*) FROM ledger_entries), (SELECT count(*) FROM audit_events)")[0]
    return {"jobs_checked": int(counts[0]), "tenants_checked": int(counts[1]), "ledger_entries": int(counts[2]), "audit_events": int(counts[3]),
            "ledger_unsound": bad_ledger, "audit_unsound": bad_audit}


# ---------------------------------------------------------------------------------------------
# pgbench scenarios.

def pgbench(cl: Cluster, login: str, db: str, script: str, clients: int, seconds: int, work: Path, tag: str, defines: Optional[dict] = None) -> dict:
    sp = work / f"{tag}.pgb"
    sp.write_text(script)
    logdir = work / f"log-{tag}"
    logdir.mkdir(exist_ok=True)
    args = [str(cl.bin / "pgbench"), "-n", "-M", "prepared", "-c", str(clients), "-j", str(min(clients, 4)), "-T", str(seconds), "-U", login, "-d", db,
            "-f", str(sp), "--log", f"--log-prefix={logdir}/b", "-r"]
    for k, v in (defines or {}).items():
        args += ["-D", f"{k}={v}"]
    proc = subprocess.run(args, capture_output=True, text=True, env=cl.env(login))
    text = proc.stdout + proc.stderr
    lat = []
    for f in logdir.glob("b.*"):
        for line in f.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2].isdigit():
                lat.append(int(parts[2]) / 1000.0)
        f.unlink()
    m_tps = re.search(r"tps = ([0-9.]+)", text)
    m_fail = re.search(r"number of failed transactions: (\d+)", text)
    m_done = re.search(r"number of transactions actually processed: (\d+)", text)
    if (proc.returncode != 0 and not m_done) or (m_done and int(m_done.group(1)) == 0) or (m_fail and m_done and int(m_fail.group(1)) > 0 and int(m_done.group(1)) == 0):
        raise RuntimeError(f"pgbench {tag} ran no transaction: {text[-900:]}")
    return {"tag": tag, "clients": clients, "seconds": seconds, "tps": float(m_tps.group(1)) if m_tps else 0.0,
            "transactions": int(m_done.group(1)) if m_done else len(lat), "failed": int(m_fail.group(1)) if m_fail else 0,
            "latency_ms": summarize(lat)}


def pgbench_median(cl: Cluster, login: str, db: str, script: str, clients: int, seconds: int, work: Path, tag: str, repeats: int) -> dict:
    """Runs the same scenario `repeats` times and returns the run with the median throughput, with all the throughputs listed."""
    runs = [pgbench(cl, login, db, script, clients, seconds, work, f"{tag}-r{i}") for i in range(repeats)]
    runs.sort(key=lambda r: r["tps"])
    best = dict(runs[len(runs) // 2])
    best["tps_runs"] = [round(r["tps"]) for r in runs]
    best["tag"] = tag
    return best


# ---------------------------------------------------------------------------------------------
# Main measurement run.

def stat_snapshot(cl: Cluster, db: str, tables: list[str]) -> dict:
    out = {}
    for t in tables:
        row = cl.query(SUPER, db, f"SELECT pg_relation_size('{t}'), pg_indexes_size('{t}'), n_live_tup, n_dead_tup, n_tup_upd, n_tup_hot_upd, coalesce(autovacuum_count,0), coalesce(vacuum_count,0), coalesce(last_autovacuum::text,'') "
                                   f"FROM pg_stat_user_tables WHERE relname = '{t}'")[0]
        out[t] = {"heap_bytes": int(row[0]), "index_bytes": int(row[1]), "live": int(row[2]), "dead": int(row[3]), "updates": int(row[4]),
                  "hot_updates": int(row[5]), "autovacuum_count": int(row[6]), "vacuum_count": int(row[7]), "last_autovacuum": row[8]}
    return out


def index_sizes(cl: Cluster, db: str, table: str) -> dict:
    rows = cl.query(SUPER, db, f"SELECT indexrelid::regclass::text, pg_relation_size(indexrelid) FROM pg_index WHERE indrelid = '{table}'::regclass ORDER BY 1")
    return {r[0]: int(r[1]) for r in rows}


def run_all(args: argparse.Namespace) -> int:
    started = time.time()
    bin_dir = find_bin()
    cl = Cluster(bin_dir, args.keep, args.pg_setting)
    cleaned = {"done": False}

    def cleanup(*_):
        if not cleaned["done"]:
            cleaned["done"] = True
            cl.destroy()

    atexit.register(cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (cleanup(), sys.exit(130)))
    work = cl.root / "work"
    work.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"schema": "factory-db-perf/1", "rows": args.rows, "seed": args.seed, "break": args.break_,
                              "host": {"platform": platform.platform(), "machine": platform.machine(), "python": platform.python_version()},
                              "caveats": ["one laptop, one run: the numbers are relative, not capacity claims",
                                          "the scratch cluster uses the PostgreSQL defaults of the deployed image (shared_buffers 128MB, fsync on); the OS file cache is warm",
                                          "clients and server share the machine; loopback round trips are in every timing"]}
    refused: list[str] = []
    try:
        say(f"cluster: starting a scratch PostgreSQL on 127.0.0.1:{cl.port} in {cl.root}")
        cl.start()
        report["postgres"] = cl.version
        provision(cl, args.rows)
        for role in LOGINS:
            report.setdefault("identity", {})[role] = preflight(cl, role, DB)
        self_check(cl, DB)

        # ---- chain verification right after the load (and the deliberate break)
        if args.break_ == "chain":
            say("break: damaging one ledger entry's document (triggers off) to show the verification catches it")
            cl.psql(SUPER, DB, "BEGIN; SET LOCAL session_replication_role = replica; UPDATE ledger_entries SET canonical_json = replace(canonical_json, 'The evidence is attached.', 'The evidence is detached.') "
                               "WHERE (tenant_id, job_id, sequence) = (SELECT tenant_id, job_id, 3 FROM ledger_entries WHERE sequence = 3 ORDER BY job_id LIMIT 1); COMMIT;")
        chains = verify_chains(cl, DB)
        report["chains_after_load"] = chains
        if chains["ledger_unsound"] or chains["audit_unsound"]:
            raise Refused(f"REFUSED: the synthetic data's hash chain does not verify (ledger: {chains['ledger_unsound'][:3]}, audit: {chains['audit_unsound'][:3]}). Numbers on unsound data are not reported.")

        sizes = cl.query(SUPER, DB, "SELECT relname, reltuples::bigint, pg_total_relation_size(oid) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' ORDER BY 3 DESC")
        dataset: dict[str, Any] = {r[0]: {"rows": int(r[1]), "total_bytes": int(r[2])} for r in sizes}
        dataset["_database_bytes"] = int(cl.scalar(SUPER, DB, f"SELECT pg_database_size('{DB}')"))
        report["dataset"] = dataset
        report["tenants"] = [{"idx": int(r[0]), "jobs": int(r[1]), "stage_runs": int(r[2])} for r in cl.query(
            SUPER, DB, "SELECT t.idx, t.jobs, (SELECT count(*) FROM stage_runs s WHERE s.tenant_id = t.id) FROM perf.tenant_plan t WHERE t.idx IN (1, 2, 5, 6, 30, 50) ORDER BY 1")]
        rel_rows: dict[str, float] = {k: float(v["rows"]) for k, v in dataset.items() if not k.startswith("_")}

        pools = load_pools(cl, DB, args.seed)
        catalogue = [s for s in series_catalogue() if not args.only or any(re.search(p, s.id) for p in args.only)]

        def pool_for(s: Series) -> list[dict]:
            return pools[s.pool]

        warm_n, cold_n = (200, 20) if args.quick else (1000, 60)

        # ---- the guard: refuse to measure as someone else
        login_override = SUPER if args.break_ == "superuser" else None

        # ---- cold-ish pass first: restart the server, then run the first iterations of each series
        refresh_leases(cl, DB)
        say("measuring (cold-ish): restart, then the first iterations of each series")
        cl.restart()
        results: dict[str, dict] = {}
        for s in catalogue:
            try:
                if login_override:
                    run_timed(cl, s, pool_for(s), 3, DB, login_override=login_override, work=work)
                for role in {s.role}:
                    preflight(cl, role, DB)
                res = measure_series(cl, s, pool_for(s), DB, warm_n, cold_n, work, "cold")
            except Refused as e:
                refused.append(str(e))
                break
            results[s.id] = {"series": s, "cold": res}
        if refused:
            raise Refused(refused[0])

        say("measuring (warm)")
        for s in catalogue:
            results[s.id]["warm"] = measure_series(cl, s, pool_for(s), DB, warm_n, cold_n, work, "warm")
            results[s.id]["warm_combined"] = measure_series(cl, s, pool_for(s), DB, warm_n, cold_n, work, "warm", preamble="combined") if s.tenant and s.id in args.combined_for else None

        # ---- the transaction frame: what a transaction costs with nothing in it
        frame = Series("frame", "worker", "big", [("q", "SELECT 1")], lambda r, i: [[]], 1.0, "an empty transaction", "-")
        frame_sep = measure_series(cl, frame, pools["big"], DB, warm_n, cold_n, work, "warm")
        frame_comb = measure_series(cl, frame, pools["big"], DB, warm_n, cold_n, work, "warm", preamble="combined")
        frame_sys = measure_series(cl, dataclasses.replace(frame, role="engine", tenant=False), pools["big"], DB, warm_n, cold_n, work, "warm")
        report["frame"] = {"tenant_transaction_separate_set_statements": frame_sep, "tenant_transaction_one_set_statement": frame_comb, "system_transaction": frame_sys}

        # ---- plans
        say("capturing plans (EXPLAIN ANALYZE, BUFFERS) as the real logins")
        plans: dict[str, dict] = {}
        for s in catalogue:
            pl = {}
            pl["a"] = explain_series(cl, s, pool_for(s)[0], DB, rel_rows)
            plans[s.id] = pl
        # the generic plan check for the tenant statements: the plan a prepared statement settles on after five runs
        generic = {}
        for s in catalogue:
            if s.tenant and len(s.steps) == 1:
                generic[s.id] = generic_plan(cl, s, pool_for(s)[0], DB)

        # ---- drop-index break: the harness must show the regression
        broken: Optional[dict] = None
        if args.break_ and args.break_.startswith("drop-index="):
            idx_name = args.break_.split("=", 1)[1]
            affected = [s for s in catalogue if any(i["index"] == idx_name for st in plans[s.id]["a"]["steps"] for i in st["index_scans"])]
            if not affected:
                raise Refused(f"the index {idx_name} is not used by any measured series; nothing to break")
            say(f"break: dropping index {idx_name}; re-measuring {[s.id for s in affected]}")
            cl.psql(SUPER, DB, f"DROP INDEX {idx_name}")
            cl.psql(SUPER, DB, "ANALYZE")
            broken = {"index": idx_name, "series": {}}
            for s in affected:
                after = measure_series(cl, s, pool_for(s), DB, warm_n, cold_n, work, "warm")
                p_after = explain_series(cl, s, pool_for(s)[0], DB, rel_rows)
                broken["series"][s.id] = {"before_p95_tx_ms": results[s.id]["warm"]["tx"]["p95"], "after_p95_tx_ms": after["tx"]["p95"],
                                         "after_seq_scans": [x for st in p_after["steps"] for x in st["seq_scans"]]}
                results[s.id]["warm"] = after
                plans[s.id]["a"] = p_after
        report["break_drop_index"] = broken

        # ---- row-level security ablation
        say("pricing row-level security: the tenant series again with the policies disabled")
        rls_off: dict[str, dict] = {}
        if not args.break_ or not args.break_.startswith("drop-index"):
            tenant_tables = [r[0] for r in cl.query(SUPER, DB, "SELECT c.relname FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND c.relkind='r' AND c.relrowsecurity")]
            for t in tenant_tables:
                cl.psql(SUPER, DB, f'ALTER TABLE "{t}" DISABLE ROW LEVEL SECURITY')
            try:
                for s in catalogue:
                    if s.tenant:
                        rls_off[s.id] = measure_series(cl, s, pool_for(s), DB, warm_n, cold_n, work, "warm")
            finally:
                for t in tenant_tables:
                    cl.psql(SUPER, DB, f'ALTER TABLE "{t}" ENABLE ROW LEVEL SECURITY')
            for role in LOGINS:
                preflight(cl, role, DB)       # proves the policies are back
        report["rls_off"] = {k: v for k, v in rls_off.items()}
        report["policy_probe"] = policy_probe(cl, pools)

        # ---- rows into the report
        rows_out = []
        for s in catalogue:
            w, c = results[s.id]["warm"], results[s.id]["cold"]
            steps = plans[s.id]["a"]["steps"]
            seq_big = [x for st in steps for x in st["seq_scans"] if x["rows_in_table"] > SEQSCAN_LARGE]
            idxs = sorted({i["index"] for st in steps for i in st["index_scans"]})
            p95 = w["tx"]["p95"]
            verdict = "PASS"
            notes = []
            if p95 > s.budget_ms:
                verdict = "FAIL"
                notes.append(f"p95 {p95} ms is over the {s.budget_ms} ms budget")
            if seq_big and s.seqscan_forbidden:
                verdict = "FAIL"
                notes.append("sequential scan of " + ", ".join(f"{x['relation']} ({int(x['rows_in_table']):,} rows)" for x in seq_big))
            if s.claim_path and seq_big:
                notes.append("the claim path scans a table sequentially")
            off = rls_off.get(s.id)
            rls_delta = None
            if off:
                rls_delta = {"query_p50_on_ms": w["query"]["p50"], "query_p50_off_ms": off["query"]["p50"], "tx_p50_on_ms": w["tx"]["p50"], "tx_p50_off_ms": off["tx"]["p50"],
                             "query_p95_on_ms": w["query"]["p95"], "query_p95_off_ms": off["query"]["p95"]}
            rows_out.append({
                "rls_delta": rls_delta,
                "id": s.id, "role": LOGINS[s.role][0], "what": s.what, "rust": s.rust, "writes": s.writes, "budget_p95_ms": s.budget_ms,
                "warm": w, "cold": c, "warm_one_set_statement": results[s.id].get("warm_combined"), "rls_off": off,
                "plan": plans[s.id]["a"], "generic_plan_index_only": generic.get(s.id), "indexes": idxs, "rows_returned": steps[-1]["actual_rows"] if steps else None,
                "plan_root": [st["root"] for st in steps], "seq_scans_large": seq_big, "verdict": verdict, "notes": notes,
            })
        report["series"] = rows_out
        deltas = [r["rls_delta"] for r in rows_out if r["rls_delta"]]
        if deltas:
            report["rls_cost"] = {
                "series_compared": len(deltas),
                "median_query_p50_on_ms": round(statistics.median(d["query_p50_on_ms"] for d in deltas), 3),
                "median_query_p50_off_ms": round(statistics.median(d["query_p50_off_ms"] for d in deltas), 3),
                "median_of_differences_query_p50_ms": round(statistics.median(d["query_p50_on_ms"] - d["query_p50_off_ms"] for d in deltas), 3),
                "median_of_differences_tx_p50_ms": round(statistics.median(d["tx_p50_on_ms"] - d["tx_p50_off_ms"] for d in deltas), 3),
                "largest_query_p50_difference_ms": round(max(d["query_p50_on_ms"] - d["query_p50_off_ms"] for d in deltas), 3),
            }
        report["_pools"] = {k: len(v) for k, v in pools.items()}

        # ---- the write path, concurrency, churn: on the clone
        if not args.skip_writes:
            say("cloning the database for the write paths")
            clone_for_writes(cl)
            refresh_leases(cl, DBW)
            for role in LOGINS:
                cl.psql(SUPER, DBW, "GRANT USAGE ON SCHEMA perf TO factory_app, factory_system")
            wpools = load_pools(cl, DBW, args.seed)
            wstate = {"heads": {}}
            for r in wpools["append"]:
                row = cl.query(SUPER, DBW, f"SELECT ledger_head_sequence, ledger_head_hash FROM jobs WHERE tenant_id = '{r['tenant_id']}' AND id = '{r['job_id']}'")[0]
                wstate["heads"][r["job_id"]] = (int(row[0]), row[1])
            wseries = write_series(wstate)
            wrows = []
            for s in wseries:
                pool = wpools[s.pool]
                n_w = min(len(pool), 500 if s.id != "start_attempt" else min(len(pool), 300))
                if s.id == "append_ledger_entry":
                    n_w = 600
                try:
                    warm = run_timed(cl, s, pool, n_w, DBW, work=work)
                except Refused:
                    raise
                lat: dict[str, Any] = {k: summarize([r[k] for r in warm[20:]]) for k in ("tx", "query", "preamble", "commit")}
                lat["steps"] = [summarize([r["steps"][j] for r in warm[20:]]) for j in range(len(s.steps))]
                wrows.append({"id": s.id, "role": LOGINS[s.role][0], "what": s.what, "rust": s.rust, "budget_p95_ms": s.budget_ms, "writes": True, "warm": lat,
                              "verdict": "PASS" if lat["tx"]["p95"] <= s.budget_ms else "FAIL",
                              "notes": [] if lat["tx"]["p95"] <= s.budget_ms else [f"p95 {lat['tx']['p95']} ms is over the {s.budget_ms} ms budget"]})
            report["write_series"] = wrows
            report["concurrency"] = concurrency(cl, work, wpools, args)
            report["claim_stress"] = claim_stress(cl, work, args, wpools)
            if not args.skip_churn:
                report["churn"] = churn(cl, work, args)
            report["chains_after_writes"] = verify_chains(cl, DBW)
            if report["chains_after_writes"]["ledger_unsound"] or report["chains_after_writes"]["audit_unsound"]:
                raise Refused("REFUSED: the chains no longer verify after the write tests (ledger or audit)")
            report["pg_stat_statements_top"] = [
                {"query": r[0][:140], "calls": int(r[1]), "total_ms": float(r[2]), "mean_ms": float(r[3])} for r in cl.query(
                    SUPER, DBW, "SELECT regexp_replace(left(query, 160), '\\s+', ' ', 'g'), calls, round(total_exec_time::numeric, 1), round(mean_exec_time::numeric, 3) "
                                "FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database()) ORDER BY total_exec_time DESC LIMIT 12")]
        report["catalog"] = catalog_report(cl, DBW if not args.skip_writes else DB)
        report["settings"] = settings_report(cl)
        report["elapsed_s"] = round(time.time() - started)
    except Refused as e:
        say(str(e))
        report["refused"] = str(e)
        write_outputs(args, report, final=True)
        cleanup()
        return EXIT_REFUSED
    except Blocked as e:
        say(f"BLOCKED: {e}")
        cleanup()
        return EXIT_BLOCKED
    write_outputs(args, report, final=True)
    failed = [r["id"] for r in report.get("series", []) + report.get("write_series", []) if r["verdict"] != "PASS"]
    cleanup()
    return EXIT_FAIL if failed else 0


def generic_plan(cl: Cluster, s: Series, row: dict, db: str) -> dict:
    login = LOGINS[s.role][0]
    name, sql = s.steps[0]
    binds = s.bind(row, 0)[0]
    # PREPARE needs types; let the server infer them, then plan with force_generic_plan.
    script = ("SET plan_cache_mode = force_generic_plan;\n" + f"PREPARE g AS {sql};\n" +
              f"EXPLAIN (COSTS OFF) EXECUTE g({', '.join(sql_lit(b) if not re.fullmatch(r'-?\d+', b) else b for b in binds)});\n")
    proc = subprocess.run([str(cl.bin / "psql"), "-X", "-q", "-At", "-U", login, "-d", db, "-f", "-"], input=script, capture_output=True, text=True, env=cl.env(login))
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:200]}
    text = proc.stdout
    return {"indexes": sorted(set(re.findall(r"(?:Index|Index Only|Bitmap Index) Scan(?: Backward)? using (\w+)", text))),
            "seq_scans": re.findall(r"Seq Scan on (\w+)", text)}


# Fragments of the statements the harness repeats, and the Rust file that must still contain each one. If the code changes a
# statement, the harness refuses to describe the old one.
DRIFT = {
    "crates/storage/src/pg/system.rs": [
        "JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'",
        "WHERE s.status = 'READY' AND s.not_before <= now() ORDER BY s.not_before, s.id LIMIT $1 FOR NO KEY UPDATE OF s SKIP LOCKED",
        "AND lease_expires_at < now() ORDER BY lease_expires_at, id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED",
        "AND deadline_at < now() ORDER BY deadline_at, id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED",
        "WHERE status = 'CANCELLING' AND teardown_deadline_at < now() ORDER BY teardown_deadline_at, id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED",
    ],
    "crates/storage/src/pg/attempts.rs": [
        "WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND lease_epoch = $4 AND status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at > now()",
        "SELECT status FROM jobs WHERE tenant_id = $1 AND id = $2 FOR SHARE",
        "FROM stage_runs WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE",
        "FROM attempts WHERE tenant_id = $1 AND stage_run_id = $2",
    ],
    "crates/storage/src/pg/ledger.rs": [
        "FROM jobs WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE",
        "WHERE tenant_id = $1 AND job_id = $2 AND sequence >= $3 ORDER BY sequence LIMIT $4",
        "UPDATE jobs SET ledger_head_sequence = $3, ledger_head_hash = $4 WHERE tenant_id = $1 AND id = $2 AND ledger_head_sequence = $5",
    ],
    "crates/storage/src/pg/outbox.rs": ["WHERE tenant_id = $1 AND job_id = $2 AND seq >= $3 ORDER BY seq LIMIT $4"],
    "crates/storage/src/pg/artifact_index.rs": ["FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2"],
    "crates/storage/src/pg/stage_runs.rs": ["WHERE tenant_id = $1 AND job_id = $2 ORDER BY created_at, run_number, id"],
    "crates/storage/src/pg/tx.rs": ["SELECT set_config('factory.tenant_id', $1, true)",
                                     "SELECT set_config('statement_timeout', $1, true), set_config('lock_timeout', $2, true)"],
}


def source_drift() -> list[str]:
    missing = []
    for rel, fragments in DRIFT.items():
        path = ROOT / rel
        if not path.exists():
            missing.append(f"{rel} (file missing)")
            continue
        text = re.sub(r"\\\n\s*", "", path.read_text())      # a backslash at the end of a line inside a Rust string joins the lines
        text = " ".join(text.split())
        for fragment in fragments:
            if " ".join(fragment.split()) not in text:
                missing.append(f"{rel}: {fragment}")
    return missing


def self_check(cl: Cluster, db: str) -> None:
    """The Python and SQL identifier functions agree, and the Rust source still holds the statements the catalogue repeats."""
    drift = source_drift()
    if drift:
        raise Refused("REFUSED: the code no longer contains a statement this harness repeats, so its numbers would describe a query that is not sent:\n  " + "\n  ".join(drift))
    sql_val = cl.scalar(SUPER, db, "SELECT perf.uid('job', 123) || '|' || perf.sha('out', 7)")
    py_val = f"{uid('job', 123)}|{sha('out', 7)}"
    if sql_val != py_val:
        raise Refused(f"the harness's identifier functions disagree with the database: {sql_val} != {py_val}")


def settings_report(cl: Cluster) -> dict:
    rows = cl.query(SUPER, DBW if cl.scalar(SUPER, DB_ADMIN, f"SELECT count(*) FROM pg_database WHERE datname = '{DBW}'") == "1" else DB,
                    "SELECT name, setting, unit FROM pg_settings WHERE name IN ('max_connections','superuser_reserved_connections','shared_buffers','work_mem','maintenance_work_mem',"
                    "'autovacuum','autovacuum_naptime','autovacuum_vacuum_scale_factor','autovacuum_vacuum_threshold','autovacuum_vacuum_insert_scale_factor','autovacuum_analyze_scale_factor','autovacuum_max_workers',"
                    "'autovacuum_vacuum_cost_delay','statement_timeout','lock_timeout','idle_in_transaction_session_timeout','idle_session_timeout','random_page_cost','effective_cache_size',"
                    "'default_statistics_target','plan_cache_mode','synchronous_commit','fsync','wal_level','max_wal_size','checkpoint_timeout','track_io_timing','shared_preload_libraries','jit') ORDER BY name")
    return {r[0]: (r[1] + (r[2] or "")) for r in rows}


# ---------------------------------------------------------------------------------------------
# Concurrency and churn.

def concurrency(cl: Cluster, work: Path, pools: dict, args: argparse.Namespace) -> dict:
    out: dict[str, Any] = {}
    secs = 3 if args.quick else 5
    login_w, login_e = LOGINS["worker"][0], LOGINS["engine"][0]
    # hot jobs: 16 completed jobs of the big tenant (one per client)
    hot = [r for r in pools["append"] if r["tenant_idx"] == 1][:16]
    cl.psql(SUPER, DBW, "CREATE TABLE perf.hot_jobs (i int PRIMARY KEY, tenant_id uuid, job_id uuid, run_id uuid, tenant_idx int)")
    for i, r in enumerate(hot):
        cl.psql(SUPER, DBW, f"INSERT INTO perf.hot_jobs VALUES ({i}, '{r['tenant_id']}', '{r['job_id']}', '{run_id(r['n'], 1)}', 1)")
    # 16 tenants' hot jobs (one job per tenant, tenants 1..16)
    spread = {}
    for r in pools["append"]:
        spread.setdefault(r["tenant_idx"], r)
    cl.psql(SUPER, DBW, "CREATE TABLE perf.spread_jobs (i int PRIMARY KEY, tenant_id uuid, job_id uuid, run_id uuid)")
    for i, (idx, r) in enumerate(sorted(spread.items())[:16]):
        cl.psql(SUPER, DBW, f"INSERT INTO perf.spread_jobs VALUES ({i}, '{r['tenant_id']}', '{r['job_id']}', '{run_id(r['n'], 1)}')")
    cl.psql(SUPER, DBW, "GRANT SELECT ON perf.hot_jobs, perf.spread_jobs TO factory_app")

    def tx(inner: str, table: str, mod: int, sleep_ms: int = 0) -> str:
        body = f"""\\set i :client_id % {mod}
SELECT tenant_id::text AS tid, job_id::text AS jid, run_id::text AS rid FROM perf.{table} WHERE i = :i \\gset
BEGIN;
SELECT set_config('factory.tenant_id', :tid, true);
{inner}
{f"SELECT pg_sleep({sleep_ms / 1000.0});" if sleep_ms else ""}
COMMIT;
"""
        return body

    append_one = "SELECT perf.append_next(:tid::uuid, :jid::uuid, :rid::uuid);"
    audit_one = ("INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, job_id, correlation_id) "
                 "VALUES (:tid::uuid, gen_random_uuid(), 'service', 'engine', 'gate.result', 'job-perf', 'record', 'The engine recorded the decision.', "
                 f"'sha256' || chr(58) || '{sha('policy', 1)[7:]}', :jid::uuid, gen_random_uuid());")
    scen = []
    for clients in (1, 4, 16):
        # one job, all clients: the head of one chain is the contended row
        scen.append(("ledger_append_one_job", clients, tx(append_one.replace(":jid", ":jid"), "hot_jobs", 1)))
    for clients in (4, 16):
        scen.append(("ledger_append_16_jobs_one_tenant", clients, tx(append_one, "hot_jobs", 16)))
        scen.append(("ledger_append_16_tenants", clients, tx(append_one, "spread_jobs", 16)))
        scen.append(("audit_append_one_tenant", clients, tx(audit_one, "hot_jobs", 1)))
        scen.append(("audit_append_16_tenants", clients, tx(audit_one, "spread_jobs", 16)))
        scen.append(("audit_append_one_tenant_hold_20ms", clients, tx(audit_one, "hot_jobs", 1, sleep_ms=20)))
    results = []
    for name, clients, script in scen:
        if name.startswith("ledger"):
            pass
        r = pgbench_median(cl, login_w, DBW, script, clients, secs, work, f"{name}-{clients}", 1 if args.quick else 3)
        r["scenario"] = name
        results.append(r)
        say(f"  {name} x{clients}: {r['tps']:.0f} tps, p95 {r['latency_ms'].get('p95')} ms, failed {r['failed']}")
    out["write_contention"] = results

    # claim finders: N engine clients ask for 10 candidates at once; with and without holding the locks for 5 ms
    claim_plain = f"BEGIN;\nSELECT set_config('statement_timeout', '30000ms', true);\n{CLAIM.replace('$1', '10')};\nCOMMIT;\n"
    claim_hold = f"BEGIN;\nSELECT set_config('statement_timeout', '30000ms', true);\n{CLAIM.replace('$1', '10')};\nSELECT pg_sleep(0.005);\nCOMMIT;\n"
    finders = []
    for clients in (1, 4, 16):
        for name, script in (("claim_finders", claim_plain), ("claim_finders_hold_5ms", claim_hold)):
            r = pgbench_median(cl, login_e, DBW, script, clients, secs, work, f"{name}-{clients}", 1 if args.quick else 3)
            r["scenario"] = name
            finders.append(r)
            say(f"  {name} x{clients}: {r['tps']:.0f} tps, p95 {r['latency_ms'].get('p95')} ms")
    out["claim_finders"] = finders

    # relays drain a backlog: every fifth outbox row becomes unpublished again; N relays take 100 at a time
    relay = []
    relay_before = stat_snapshot(cl, DBW, ["outbox"])["outbox"]
    relay_sql = ("BEGIN;\nWITH c AS (SELECT seq FROM outbox WHERE published_at IS NULL ORDER BY seq LIMIT 100 FOR NO KEY UPDATE SKIP LOCKED) "
                 "UPDATE outbox o SET published_at = now(), publish_attempts = o.publish_attempts + 1 FROM c WHERE o.seq = c.seq;\nCOMMIT;\n")
    for clients in (1, 4, 16):
        cl.psql(SUPER, DBW, "BEGIN; SET LOCAL session_replication_role = replica; UPDATE outbox SET published_at = NULL, publish_attempts = 0 WHERE seq % 5 = 0; COMMIT;")
        cl.psql(SUPER, DBW, "VACUUM (ANALYZE) outbox")
        backlog = int(cl.scalar(SUPER, DBW, "SELECT count(*) FROM outbox WHERE published_at IS NULL"))
        t0 = time.time()
        r = pgbench(cl, login_e, DBW, relay_sql, clients, 60, work, f"relay-{clients}") if False else relay_drain(cl, login_e, work, relay_sql, clients, backlog)
        r["backlog"] = backlog
        r["drain_s"] = round(time.time() - t0, 2)
        r["duplicates"] = int(cl.scalar(SUPER, DBW, "SELECT count(*) FROM outbox WHERE publish_attempts > 1"))
        r["still_unpublished"] = int(cl.scalar(SUPER, DBW, "SELECT count(*) FROM outbox WHERE published_at IS NULL"))
        relay.append(r)
        say(f"  relay x{clients}: drained {backlog} in {r['drain_s']} s, duplicates {r['duplicates']}, left {r['still_unpublished']}")
    out["relay_drain"] = relay
    relay_after = stat_snapshot(cl, DBW, ["outbox"])["outbox"]
    out["relay_table_stats"] = {"before": relay_before, "after": relay_after}

    # sweeper next to heartbeats
    cl.psql(SUPER, DBW, "CREATE TABLE perf.live_attempts AS SELECT row_number() OVER (ORDER BY id)::int AS k, tenant_id, id, lease_owner FROM attempts WHERE status = 'RUNNING' AND lease_expires_at > now() + interval '10 minutes' LIMIT 600")
    cl.psql(SUPER, DBW, "ALTER TABLE perf.live_attempts ADD PRIMARY KEY (k); GRANT SELECT ON perf.live_attempts TO factory_app")
    n_live = int(cl.scalar(SUPER, DBW, "SELECT count(*) FROM perf.live_attempts"))
    out["live_attempts"] = n_live
    hb = heartbeat_script(n_live)
    sweep = f"BEGIN;\n{LEASE_EXPIRED.replace('$1', '10')};\nCOMMIT;\n"
    res: dict[str, Any] = {}      # concurrent pgbench runs: heartbeats (4 clients) and the sweeper (1 client)

    def run(tag, login, script, clients):
        try:
            res[tag] = pgbench(cl, login, DBW, script, clients, secs, work, tag)
        except Exception as e:           # surfaced below, in the main thread
            res[tag] = e
    solo = pgbench(cl, login_e, DBW, sweep, 1, secs, work, "sweeper-alone")
    th = [threading.Thread(target=run, args=("heartbeats-with-sweeper", login_w, hb, 4)), threading.Thread(target=run, args=("sweeper-with-heartbeats", login_e, sweep, 1))]
    [t.start() for t in th]
    [t.join() for t in th]
    for v in res.values():
        if isinstance(v, Exception):
            raise v
    out["sweeper_and_heartbeats"] = {"sweeper_alone": solo, "heartbeats_with_sweeper": res["heartbeats-with-sweeper"], "sweeper_with_heartbeats": res["sweeper-with-heartbeats"]}
    return out


def claim_stress(cl: Cluster, work: Path, args: argparse.Namespace, pools: dict) -> dict:
    """The claim query when the head of the queue is full of runs it must skip, and when the READY backlog is large."""
    claim = next(x for x in series_catalogue() if x.id == "claim_candidates")
    rel_rows = {r[0]: float(r[1]) for r in cl.query(SUPER, DBW, "SELECT relname, reltuples FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r'")}
    iters = 200 if args.quick else 600

    def measure(label: str) -> dict:
        runs = run_timed(cl, claim, [{}], iters + 30, DBW, work=work)[30:]
        plan = explain_series(cl, claim, {}, DBW, rel_rows)
        st = plan["steps"][0]
        return {"label": label, "ready_runs": int(cl.scalar(SUPER, DBW, "SELECT count(*) FROM stage_runs WHERE status = 'READY'")),
                "ready_runs_of_active_jobs": int(cl.scalar(SUPER, DBW, "SELECT count(*) FROM stage_runs s JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id WHERE s.status = 'READY' AND j.status = 'ACTIVE'")),
                "tx": summarize([r["tx"] for r in runs]), "query": summarize([r["query"] for r in runs]), "execution_ms": st["execution_ms"], "shared_hit": st["shared_hit"],
                "shared_read": st["shared_read"], "rows_removed_by_filter": st["rows_removed_by_filter"], "indexes": sorted({i["index"] for i in st["index_scans"]}),
                "seq_scans": st["seq_scans"], "node_types": st["node_types"]}

    out = {"steps": [measure("baseline: about 900 READY runs, 10 percent of them belong to a paused job")]}

    def add_runs(count: int, job_status: str, base: int, age: str, tag: str) -> None:
        """Insert `count` jobs of tenant 1, each with one READY stage run, with the triggers off (as the load does)."""
        cl.psql(SUPER, DBW, f"""
          BEGIN;
          SET LOCAL session_replication_role = replica;
          INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, status, version, execution_mode, autonomy_level, pipeline_scope, correlation_id, idempotency_key, created_at, updated_at)
          SELECT t.id, perf.uid('{tag}job', g), perf.uid('repo', 1000001), perf.uid('pri', 11), '{job_status}', 2, 'production', 'L1', ARRAY['INTAKE'],
                 perf.uid('{tag}corr', g), '{tag}-' || g, now(), now()
            FROM perf.tenant_plan t, generate_series({base + 1}, {base + count}) g WHERE t.idx = 1;
          INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status, version, not_before, created_at, updated_at)
          SELECT t.id, perf.uid('{tag}run', g), perf.uid('{tag}job', g), 'INTAKE', 1, 'READY', 1, now() - interval '{age}' + g * interval '1 millisecond', now(), now()
            FROM perf.tenant_plan t, generate_series({base + 1}, {base + count}) g WHERE t.idx = 1;
          COMMIT;
          ANALYZE jobs; ANALYZE stage_runs;""")

    add_runs(5000, "PAUSED", 0, "10 days", "junk")
    out["steps"].append(measure("5,000 more READY runs at the head of the queue whose jobs are PAUSED (the claim must skip them)"))
    add_runs(20000, "ACTIVE", 0, "5 days", "burst")
    out["steps"].append(measure("plus 20,000 READY runs of ACTIVE jobs behind them (a burst of admitted jobs)"))
    finders = []
    for clients in (1, 4, 16):
        script = f"BEGIN;\nSELECT set_config('statement_timeout', '30000ms', true);\n{CLAIM.replace('$1', '10')};\nCOMMIT;\n"
        r = pgbench(cl, LOGINS["engine"][0], DBW, script, clients, 3 if args.quick else 6, work, f"claim-burst-{clients}")
        finders.append(r)
    out["finders_with_burst"] = finders
    return out


def catalog_report(cl: Cluster, db: str) -> dict:
    unindexed = cl.query(SUPER, db, """
      SELECT c.conrelid::regclass::text, c.conname, array_to_string(ARRAY(SELECT a.attname FROM unnest(c.conkey) k JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k), ',')
        FROM pg_constraint c
       WHERE c.contype = 'f' AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.conrelid
               AND (i.indkey::text || ' ') LIKE (array_to_string(c.conkey, ' ') || ' %'))
       ORDER BY 1, 2""")
    indexes = cl.query(SUPER, db, """
      SELECT s.relname, s.indexrelname, pg_relation_size(s.indexrelid), s.idx_scan, i.indisunique, i.indpred IS NOT NULL
        FROM pg_stat_user_indexes s JOIN pg_index i ON i.indexrelid = s.indexrelid
       WHERE s.schemaname = 'public' ORDER BY pg_relation_size(s.indexrelid) DESC LIMIT 40""")
    tables = cl.query(SUPER, db, """
      SELECT relname, pg_relation_size(oid), pg_indexes_size(oid), coalesce(pg_total_relation_size(reltoastrelid), 0), reltuples::bigint
        FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' ORDER BY pg_total_relation_size(oid) DESC""")
    return {"foreign_keys_without_an_index": [{"table": r[0], "constraint": r[1], "columns": r[2]} for r in unindexed],
            "largest_indexes": [{"table": r[0], "index": r[1], "bytes": int(r[2]), "scans": int(r[3]), "unique": r[4] == "t", "partial": r[5] == "t"} for r in indexes],
            "tables": [{"table": r[0], "heap_bytes": int(r[1]), "index_bytes": int(r[2]), "toast_bytes": int(r[3]), "rows": int(r[4])} for r in tables]}


def heartbeat_script(n_live: int) -> str:
    """A worker renews the lease of one of the live attempts, in a tenant transaction, as heartbeat() does."""
    return (f"\\set k random(1, {n_live})\nSELECT tenant_id::text AS tid, id::text AS aid, lease_owner AS owner FROM perf.live_attempts WHERE k = :k \\gset\nBEGIN;\n"
            "SELECT set_config('factory.tenant_id', :tid, true);\n"
            "UPDATE attempts SET lease_expires_at = now() + interval '30 seconds', last_heartbeat_at = now(), version = version + 1 WHERE tenant_id = :tid::uuid AND id = :aid::uuid AND lease_owner = :owner AND lease_epoch = 1 AND status IN ('STARTING','RUNNING','CANCELLING') AND lease_expires_at > now();\nCOMMIT;\n")


def relay_drain(cl: Cluster, login: str, work: Path, script: str, clients: int, backlog: int) -> dict:
    """pgbench cannot stop on a condition; it runs for a fixed count of transactions that is enough to drain with margin."""
    per_client = max(backlog // (100 * clients) + 8, 8)
    sp = work / f"relay-{clients}.pgb"
    sp.write_text(script)
    args = [str(cl.bin / "pgbench"), "-n", "-M", "prepared", "-c", str(clients), "-j", str(min(clients, 4)), "-t", str(per_client), "-U", login, "-d", DBW, "-f", str(sp)]
    t0 = time.time()
    proc = subprocess.run(args, capture_output=True, text=True, env=cl.env(login))
    text = proc.stdout + proc.stderr
    m_tps = re.search(r"tps = ([0-9.]+)", text)
    m_lat = re.search(r"latency average = ([0-9.]+) ms", text)
    m_fail = re.search(r"number of failed transactions: (\d+)", text)
    return {"clients": clients, "tps": float(m_tps.group(1)) if m_tps else 0.0, "mean_ms": float(m_lat.group(1)) if m_lat else None,
            "failed": int(m_fail.group(1)) if m_fail else 0, "wall_s": round(time.time() - t0, 2), "rc": proc.returncode}


def churn_pass(cl: Cluster, work: Path, hb: str, secs: int, tag: str) -> dict:
    """One run of heartbeats from a clean start, and what it did to the attempts table."""
    refresh_leases(cl, DBW)
    cl.psql(SUPER, DBW, "VACUUM (ANALYZE) attempts")
    cl.psql(SUPER, DBW, "SELECT pg_stat_reset()")
    before = stat_snapshot(cl, DBW, ["attempts"])["attempts"]
    idx_before = index_sizes(cl, DBW, "attempts")
    run = pgbench(cl, LOGINS["worker"][0], DBW, hb, 4, secs, work, tag)
    time.sleep(2)
    after = stat_snapshot(cl, DBW, ["attempts"])["attempts"]
    if after["updates"] == 0:
        raise RuntimeError("the churn run updated no row of attempts (every lease had lapsed?); its numbers would mean nothing")
    return {"seconds": secs, "heartbeats": run, "attempts_before": before, "attempts_after": after,
            "hot_share": round(after["hot_updates"] / after["updates"], 4), "dead_per_update": round(after["dead"] / after["updates"], 4),
            "index_bytes_before": idx_before, "index_bytes_after": index_sizes(cl, DBW, "attempts"),
            "pgstattuple_approx_after": cl.query(SUPER, DBW, "SELECT approx_tuple_percent, dead_tuple_percent, approx_free_percent FROM pgstattuple_approx('attempts')")[0]}


def sweeper_numbers(cl: Cluster, work: Path, tag: str) -> dict:
    """The expired-lease finder, one client, and its plan."""
    sweep_sql = f"BEGIN;\n{LEASE_EXPIRED.replace('$1', '10')};\nCOMMIT;\n"
    run = pgbench(cl, LOGINS["engine"][0], DBW, sweep_sql, 1, 4, work, tag)
    engine = next(x for x in series_catalogue() if x.id == "due_lease_expired")
    rel_rows: dict[str, float] = {"attempts": float(cl.scalar(SUPER, DBW, "SELECT reltuples::bigint FROM pg_class WHERE relname = 'attempts'"))}
    plan = explain_series(cl, engine, {}, DBW, rel_rows)["steps"][0]
    return {"tps": run["tps"], "latency_ms": run["latency_ms"], "nodes": plan["node_types"], "indexes": [i["index"] for i in plan["index_scans"]],
            "execution_ms": plan["execution_ms"], "shared_hit": plan["shared_hit"], "seq_scans": plan["seq_scans"]}


def churn(cl: Cluster, work: Path, args: argparse.Namespace) -> dict:
    """Heartbeats for a while: what happens to the heap and the indexes of attempts. First on the schema as it is (migration 19 took
    the index on the lease away), then, in the same database, with that index put back, which is the schema before migration 19."""
    secs = 20 if args.quick else 90
    tables = ["attempts", "outbox", "stage_runs", "jobs"]
    n_live = int(cl.scalar(SUPER, DBW, "SELECT count(*) FROM perf.live_attempts"))
    hb = heartbeat_script(n_live)
    # The earlier heartbeat runs left 30 second leases, which have lapsed by now; refresh_leases (in churn_pass) puts live ones back.
    current = churn_pass(cl, work, hb, secs, "churn-current")
    time.sleep(5)                                                        # give autovacuum its chance
    after_wait = stat_snapshot(cl, DBW, tables)
    cl.psql(SUPER, DBW, "VACUUM (ANALYZE) attempts")
    after_vacuum = stat_snapshot(cl, DBW, tables)
    sweeper_current = sweeper_numbers(cl, work, "churn-sweeper-current")
    cl.psql(SUPER, DBW, "CREATE INDEX attempts_lease_expiry_idx ON attempts (lease_expires_at) WHERE status IN ('STARTING', 'RUNNING')")
    cl.psql(SUPER, DBW, "ANALYZE attempts")
    try:
        before_migration = churn_pass(cl, work, hb, min(secs, 45), "churn-before-migration")
        sweeper_before = sweeper_numbers(cl, work, "churn-sweeper-before-migration")
    finally:
        cl.psql(SUPER, DBW, "DROP INDEX attempts_lease_expiry_idx")
    return {"seconds": secs, "live_attempts": n_live, "current_schema": current, "after_wait": after_wait, "after_vacuum": after_vacuum,
            "sweeper_current_schema": sweeper_current, "schema_before_migration_19": before_migration, "sweeper_before_migration_19": sweeper_before,
            "settings": {k: v for k, v in settings_report(cl).items() if k.startswith("autovacuum")}}


# ---------------------------------------------------------------------------------------------
# Output.

def fmt_ms(x: Any) -> str:
    return "-" if x is None or (isinstance(x, float) and x != x) else f"{x:.2f}"


def markdown(report: dict) -> str:
    o: list[str] = []
    o.append(f"Rows per hot table: {report['rows']:,}. PostgreSQL {report.get('postgres', '?')}. Seed {report['seed']}. Break: {report.get('break') or 'none'}.")
    if "refused" in report:
        o.append("")
        o.append(report["refused"] if report["refused"].startswith("REFUSED") else f"REFUSED: {report['refused']}")
        return "\n".join(o)
    if "series" in report:
        o.append("")
        o.append("Read series (one transaction: BEGIN, set the tenant, set the limits, the statement, COMMIT; client side time of the whole transaction).")
        o.append("")
        o.append("| Series | Login | p50 ms | p95 ms | cold p95 ms | query p50 RLS on / off ms | Budget ms | Plan root | Indexes | Verdict |")
        o.append("|---|---|---:|---:|---:|---:|---:|---|---|---|")
        for r in report["series"]:
            d = r.get("rls_delta")
            rls = f"{fmt_ms(d['query_p50_on_ms'])} / {fmt_ms(d['query_p50_off_ms'])}" if d else "-"
            o.append(f"| `{r['id']}` | {r['role']} | {fmt_ms(r['warm']['tx']['p50'])} | {fmt_ms(r['warm']['tx']['p95'])} | {fmt_ms(r['cold']['tx']['p95'])} | {rls} | {r['budget_p95_ms']} | "
                     f"{' + '.join(r['plan_root'])} | {', '.join(r['indexes']) or '-'} | {r['verdict']}{(': ' + '; '.join(r['notes'])) if r['notes'] else ''} |")
    if report.get("break_drop_index"):
        b = report["break_drop_index"]
        o.append("")
        o.append(f"Deliberate break: the index `{b['index']}` was dropped after the first measurement. Per series, p95 of the whole transaction before and after, and the sequential scans the plan then showed:")
        o.append("")
        o.append("| Series | p95 before ms | p95 after ms | Sequential scans after |")
        o.append("|---|---:|---:|---|")
        for sid, v in b["series"].items():
            scans = ", ".join("%s (%s rows)" % (x["relation"], format(int(x["rows_in_table"]), ",")) for x in v["after_seq_scans"]) or "-"
            o.append(f"| `{sid}` | {fmt_ms(v['before_p95_tx_ms'])} | {fmt_ms(v['after_p95_tx_ms'])} | {scans} |")
    if "rls_cost" in report:
        o.append("")
        o.append(f"Row-level security, priced by disabling the policies and repeating the tenant series: {json.dumps(report['rls_cost'])}")
    if "frame" in report:
        f = report["frame"]
        o.append("")
        o.append("Transaction frame (nothing in the transaction but `SELECT 1`), p50 / p95 ms: " + "; ".join(
            f"{k}: {fmt_ms(v['tx']['p50'])} / {fmt_ms(v['tx']['p95'])}" for k, v in f.items()))
    if "write_series" in report:
        o.append("")
        o.append("| Write path (committed, on the clone) | p50 ms | p95 ms | Budget ms | Verdict |")
        o.append("|---|---:|---:|---:|---|")
        for r in report["write_series"]:
            o.append(f"| `{r['id']}` | {fmt_ms(r['warm']['tx']['p50'])} | {fmt_ms(r['warm']['tx']['p95'])} | {r['budget_p95_ms']} | {r['verdict']} |")
    if "claim_stress" in report:
        o.append("")
        o.append("| Claim queue state | READY runs (of ACTIVE jobs) | query p50 ms | p95 ms | buffers hit | rows removed by filter | index |")
        o.append("|---|---:|---:|---:|---:|---:|---|")
        for st in report["claim_stress"]["steps"]:
            o.append(f"| {st['label']} | {st['ready_runs']:,} ({st['ready_runs_of_active_jobs']:,}) | {fmt_ms(st['query']['p50'])} | {fmt_ms(st['query']['p95'])} | {st['shared_hit']:,} | {st['rows_removed_by_filter']:,} | {', '.join(st['indexes'])} |")
    if "concurrency" in report:
        c = report["concurrency"]
        o.append("")
        o.append("| Concurrency scenario | Clients | tps | p50 ms | p95 ms | Failed |")
        o.append("|---|---:|---:|---:|---:|---:|")
        for r in c["write_contention"] + c["claim_finders"]:
            o.append(f"| {r['scenario']} | {r['clients']} | {r['tps']:.0f} | {fmt_ms(r['latency_ms'].get('p50'))} | {fmt_ms(r['latency_ms'].get('p95'))} | {r['failed']} |")
        o.append("")
        o.append("| Relay drains a backlog | Clients | Backlog | Wall s | tps | Duplicate publishes | Left |")
        o.append("|---|---:|---:|---:|---:|---:|---:|")
        for r in c["relay_drain"]:
            o.append(f"| outbox relay | {r['clients']} | {r['backlog']:,} | {r['drain_s']} | {r['tps']:.0f} | {r['duplicates']} | {r['still_unpublished']} |")
        sw = c["sweeper_and_heartbeats"]
        o.append("")
        o.append(f"Sweeper alone: {sw['sweeper_alone']['tps']:.0f} tps, p95 {fmt_ms(sw['sweeper_alone']['latency_ms'].get('p95'))} ms. Next to 4 heartbeating clients: sweeper {sw['sweeper_with_heartbeats']['tps']:.0f} tps, "
                 f"p95 {fmt_ms(sw['sweeper_with_heartbeats']['latency_ms'].get('p95'))} ms; heartbeats {sw['heartbeats_with_sweeper']['tps']:.0f} tps, p95 {fmt_ms(sw['heartbeats_with_sweeper']['latency_ms'].get('p95'))} ms.")
    if "churn" in report:
        ch = report["churn"]
        o.append("")
        o.append(f"Churn: heartbeats by 4 clients on {ch['live_attempts']} live attempts, each pass from a vacuumed table, the leases refreshed first.")
        o.append("")
        o.append("| Schema | Heartbeats | tps | Heap-only (HOT) share | Dead tuples left | attempts heap bytes before to after | attempts index bytes before to after |")
        o.append("|---|---:|---:|---:|---:|---|---|")
        for label, key in (("migration 19 (no index keyed on the lease)", "current_schema"), ("before migration 19 (index on the lease)", "schema_before_migration_19")):
            p = ch[key]
            b, a = p["attempts_before"], p["attempts_after"]
            o.append(f"| {label}, {p['seconds']} s | {p['heartbeats']['transactions']:,} | {p['heartbeats']['tps']:.0f} | {p['hot_share']:.4f} | {a['dead']:,} | "
                     f"{b['heap_bytes']:,} to {a['heap_bytes']:,} | {sum(p['index_bytes_before'].values()):,} to {sum(p['index_bytes_after'].values()):,} |")
        a2, a3 = ch["after_wait"]["attempts"], ch["after_vacuum"]["attempts"]
        o.append("")
        o.append(f"After the 90 second pass on the current schema, with the PostgreSQL defaults: autovacuum runs {a2['autovacuum_count']}, dead tuples {a2['dead']:,} five seconds later; "
                 f"after one VACUUM: heap {a3['heap_bytes']:,} bytes, indexes {a3['index_bytes']:,} bytes, dead tuples {a3['dead']:,}.")
        sw, sb = ch["sweeper_current_schema"], ch["sweeper_before_migration_19"]
        o.append("")
        o.append(f"Sweeper (lease expired, LIMIT 10, one client): current schema {sw['tps']:.0f} tps, p95 {fmt_ms(sw['latency_ms'].get('p95'))} ms, plan {' / '.join(sw['nodes'])} on {', '.join(sw['indexes'])}; "
                 f"before migration 19 {sb['tps']:.0f} tps, p95 {fmt_ms(sb['latency_ms'].get('p95'))} ms, plan {' / '.join(sb['nodes'])} on {', '.join(sb['indexes'])}.")
    if report.get("catalog", {}).get("foreign_keys_without_an_index"):
        o.append("")
        o.append("Foreign keys with no index that starts with their columns: " + "; ".join(f"{x['table']}({x['columns']})" for x in report["catalog"]["foreign_keys_without_an_index"]))
    return "\n".join(o)


def write_outputs(args: argparse.Namespace, report: dict, final: bool) -> None:
    def clean(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: clean(v) for k, v in o.items() if k != "series_obj"}
        if isinstance(o, (list, tuple)):
            return [clean(v) for v in o]
        return o
    data = clean(report)
    if args.report:
        Path(args.report).write_text(json.dumps(data, indent=1, sort_keys=False, default=str))
        say(f"report: {args.report}")
    text = markdown(data)
    if args.markdown:
        Path(args.markdown).write_text(text + "\n")
    print(text)


def idle_demo(cl: Cluster, with_timeout: bool) -> dict:
    """A worker session that stops after taking a row lock, and a second session that needs the same row."""
    row = cl.query(SUPER, DB, "SELECT tenant_id, job_id FROM perf.job_plan WHERE class = 'A' ORDER BY n LIMIT 1")[0]
    t, j = row[0], row[1]
    login = LOGINS["worker"][0]
    cl.psql(SUPER, DB, f"ALTER ROLE {login} " + ("SET idle_in_transaction_session_timeout = '2s'" if with_timeout else "RESET idle_in_transaction_session_timeout"))
    first = subprocess.Popen([str(cl.bin / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", login, "-d", DB], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=cl.env(login))
    assert first.stdin is not None
    first.stdin.write(f"BEGIN;\nSELECT set_config('factory.tenant_id', '{t}', true);\nSELECT 1 FROM jobs WHERE tenant_id = '{t}' AND id = '{j}' FOR NO KEY UPDATE;\n")
    first.stdin.flush()
    time.sleep(0.5)
    t0 = time.time()
    out, rc = cl.psql(login, DB, check=False, tuples=True, sql=(
        f"BEGIN; SELECT set_config('factory.tenant_id', '{t}', true); SET LOCAL lock_timeout = '5s'; "
        f"SELECT 1 FROM jobs WHERE tenant_id = '{t}' AND id = '{j}' FOR NO KEY UPDATE; COMMIT;"))
    waited = round(time.time() - t0, 2)
    first.stdin.close()
    try:
        _, first_err = first.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        first.kill()
        _, first_err = first.communicate()
    cl.psql(SUPER, DB, f"ALTER ROLE {login} RESET idle_in_transaction_session_timeout")
    return {"with_idle_in_transaction_session_timeout_2s": with_timeout, "second_session_waited_s": waited, "second_session_exit": rc,
            "second_session_said": out.strip().splitlines()[-1][:160] if out.strip() else "", "first_session_said": first_err.strip()[:200]}


def run_check_settings(args: argparse.Namespace) -> int:
    """Settings of the server as deployed (no flags beyond the address), and what they allow: extensions, timeouts, autovacuum."""
    cl = Cluster(find_bin(), args.keep, [], deployed_defaults=True)
    atexit.register(cl.destroy)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (cl.destroy(), sys.exit(130)))
    cl.start()
    provision(cl, args.rows)
    report: dict[str, Any] = {"schema": "factory-db-settings/1", "postgres": cl.version, "rows": args.rows}
    report["settings"] = settings_report(cl)
    out, _ = cl.psql(SUPER, DB, "SELECT count(*) FROM pg_stat_statements", check=False, tuples=True)
    report["pg_stat_statements_without_preload"] = out.strip().splitlines()[-1][:220] if out.strip() else ""
    report["role_defaults"] = cl.query(SUPER, DB, "SELECT coalesce(r.rolname, '(all roles)'), s.setconfig::text FROM pg_db_role_setting s LEFT JOIN pg_roles r ON r.oid = s.setrole")
    report["settings_seen_by_each_login"] = {}
    for _, (login, _groups) in LOGINS.items():
        outl, _ = cl.psql(login, DB, check=False, tuples=True, sql=("SELECT current_setting('statement_timeout') || ' / ' || current_setting('lock_timeout') || ' / ' "
                                                                    "|| current_setting('idle_in_transaction_session_timeout')"))
        report["settings_seen_by_each_login"][login] = outl.strip()
    report["idle_in_transaction"] = [idle_demo(cl, False), idle_demo(cl, True)]
    tables = cl.query(SUPER, DB, "SELECT relname, reltuples::bigint, coalesce(reloptions::text, '') FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' "
                                 "AND relname IN ('attempts','stage_runs','jobs','outbox','ledger_entries','audit_events','artifacts')")
    report["table_storage_options"] = {r[0]: {"reltuples": int(r[1]), "reloptions": r[2]} for r in tables}
    print(json.dumps(report, indent=1))
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=1))
    return 0


def run_check_backup(args: argparse.Namespace) -> int:
    """Does a dump taken the way scripts/backup.sh takes it hold everything the schema holds? A round trip into a second database,
    compared by the catalog fingerprint the migrations suite uses, by row counts, by the chains and by isolation through a real login."""
    cl = Cluster(find_bin(), args.keep, [], deployed_defaults=True)
    atexit.register(cl.destroy)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (cl.destroy(), sys.exit(130)))
    cl.start()
    provision(cl, args.rows)
    fingerprint = ROOT / "docs" / "database" / "tests" / "catalog_fingerprint.sql"
    dump = cl.root / "database.dump"
    globals_sql = cl.root / "globals.sql"
    env = cl.env(SUPER)
    t_dump = time.time()
    subprocess.run([str(cl.bin / "pg_dump"), "-U", SUPER, "-d", DB, "--format=custom", "--lock-wait-timeout=30s", "-f", str(dump)], check=True, env=env)
    dump_seconds = round(time.time() - t_dump, 2)
    subprocess.run([str(cl.bin / "pg_dumpall"), "-U", SUPER, "--globals-only", "--no-role-passwords", "-f", str(globals_sql)], check=True, env=env)
    toc = subprocess.run([str(cl.bin / "pg_restore"), "--list", str(dump)], check=True, capture_output=True, text=True).stdout
    by_type: dict[str, int] = {}
    for line in toc.splitlines():
        m = re.match(r"^\d+; \d+ \d+ ((?:[A-Z]+ ?)+) ", line)
        if m:
            key = m.group(1).strip()
            by_type[key] = by_type.get(key, 0) + 1
    catalog = {k: int(cl.scalar(SUPER, DB, q)) for k, q in {
        "TABLE": "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'",
        "INDEX (not constraints)": "SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE c.relnamespace='public'::regnamespace AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid=i.indexrelid)",
        "CONSTRAINT (primary and unique)": "SELECT count(*) FROM pg_constraint WHERE connamespace='public'::regnamespace AND contype IN ('p','u')",
        "FK CONSTRAINT": "SELECT count(*) FROM pg_constraint WHERE connamespace='public'::regnamespace AND contype='f'",
        "CHECK CONSTRAINT": "SELECT count(*) FROM pg_constraint WHERE connamespace='public'::regnamespace AND contype='c'",
        "TRIGGER": "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='public'::regnamespace AND NOT t.tgisinternal",
        "POLICY": "SELECT count(*) FROM pg_policy",
        "ROW SECURITY": "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relrowsecurity",
        "FUNCTION": "SELECT count(*) FROM pg_proc WHERE pronamespace='public'::regnamespace",
        "VIEW": "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='v'",
        "SCHEMA (perf, the harness's own)": "SELECT count(*) FROM pg_namespace WHERE nspname='perf'",
        "EXTENSION": "SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql'",
    }.items()}
    cl.psql(SUPER, DB_ADMIN, 'CREATE DATABASE "perf_r" TEMPLATE template0')
    t_restore = time.time()
    subprocess.run([str(cl.bin / "pg_restore"), "--exit-on-error", "--single-transaction", "-U", SUPER, "-d", "perf_r", str(dump)], check=True, env=env)
    restore_seconds = round(time.time() - t_restore, 2)

    def fingerprint_of(db: str) -> str:
        return subprocess.run([str(cl.bin / "psql"), "-X", "-At", "-U", SUPER, "-d", db, "-f", str(fingerprint)], capture_output=True, text=True, env=env).stdout.strip()

    fp_src, fp_dst = fingerprint_of(DB), fingerprint_of("perf_r")

    def definitions_of(db: str) -> set[str]:
        """The lines the fingerprint hashes, one per definition, so a difference can be named."""
        text = fingerprint.read_text()
        cut = text.rindex("SELECT encode(sha256(")
        listing = text[:cut] + "SELECT d FROM defs;"
        done = subprocess.run([str(cl.bin / "psql"), "-X", "-At", "-U", SUPER, "-d", db], input=listing, capture_output=True, text=True, env=env)
        return set(done.stdout.split("\n"))

    only_source, only_restored = (sorted(definitions_of(DB) - definitions_of("perf_r"))[:8], sorted(definitions_of("perf_r") - definitions_of(DB))[:8]) if fp_src != fp_dst else ([], [])
    tables = [r[0] for r in cl.query(SUPER, DB, "SELECT relname FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r' ORDER BY 1")]
    mismatched = []
    for t in tables:
        a = cl.scalar(SUPER, DB, f'SELECT count(*) FROM "{t}"')
        b = cl.scalar(SUPER, "perf_r", f'SELECT count(*) FROM "{t}"')
        if a != b:
            mismatched.append(f"{t}: {a} != {b}")
    outbox_src = cl.scalar(SUPER, DB, "SELECT max(seq) FROM outbox")
    cl.psql(SUPER, "perf_r", "INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, correlation_id, occurred_at, producer, payload) "
                             "SELECT tenant_id, gen_random_uuid(), 'job.admitted', id, 'job', id, 1, 'J01', correlation_id, now(), 'workflow.engine', '{}' FROM jobs LIMIT 1")
    next_seq = cl.scalar(SUPER, "perf_r", "SELECT max(seq) FROM outbox")
    chains = verify_chains(cl, "perf_r")
    worker = LOGINS["worker"][0]
    t1 = cl.scalar(SUPER, DB, "SELECT id FROM perf.tenant_plan WHERE idx = 1")
    t2 = cl.scalar(SUPER, DB, "SELECT id FROM perf.tenant_plan WHERE idx = 2")
    out1, _ = cl.psql(worker, "perf_r", check=False, tuples=True, sql=(f"BEGIN; SELECT set_config('factory.tenant_id', '{t1}', true); "
                                                                          f"SELECT count(*) FILTER (WHERE tenant_id = '{t1}') || '/' || count(*) FROM jobs; ROLLBACK;"))
    out2, _ = cl.psql(worker, "perf_r", check=False, tuples=True, sql=(f"BEGIN; SELECT set_config('factory.tenant_id', '{t2}', true); "
                                                                          f"SELECT count(*) FILTER (WHERE tenant_id = '{t1}') FROM jobs; ROLLBACK;"))
    globals_text = globals_sql.read_text()
    last = lambda text: text.strip().splitlines()[-1] if text.strip() else text  # noqa: E731
    report = {
        "schema": "factory-db-backup-coverage/1", "postgres": cl.version, "rows": args.rows,
        "toc_entries_by_type": dict(sorted(by_type.items())), "catalog_counts": catalog,
        "catalog_fingerprint_equal": fp_src == fp_dst, "fingerprint": fp_src,
        "only_in_the_source": [line[:300] for line in only_source], "only_in_the_restored": [line[:300] for line in only_restored],
        "differences_are_only_parentheses": fp_src != fp_dst and {line.replace("(", "").replace(")", "") for line in only_source} == {line.replace("(", "").replace(")", "") for line in only_restored},
        "tables": len(tables), "row_count_mismatches": mismatched,
        "outbox_identity_continues": {"max_seq_before": outbox_src, "next_seq_after_restore_and_one_insert": next_seq},
        "chains_on_the_restored_database": chains,
        "isolation_on_the_restored_database_through_the_worker_login": {"tenant_1_sees": last(out1), "tenant_2_sees_tenant_1_jobs": last(out2)},
        "globals_sql": {"bytes": len(globals_text), "create_role_lines": len(re.findall(r"^CREATE ROLE ", globals_text, re.M)),
                        "membership_lines": len(re.findall(r"^GRANT .* TO ", globals_text, re.M)), "mentions_password": bool(re.search(r"PASSWORD", globals_text)),
                        "has_role_level_settings": bool(re.search(r"ALTER ROLE .* SET ", globals_text))},
        "statistics_in_dump": any("STATISTICS" in k for k in by_type),
        "planner_statistics_rows_in_pg_stats": {"source": int(cl.scalar(SUPER, DB, "SELECT count(*) FROM pg_stats WHERE schemaname = 'public'")),
                                                "restored": int(cl.scalar(SUPER, "perf_r", "SELECT count(*) FROM pg_stats WHERE schemaname = 'public'"))},
        "dump": {"seconds": dump_seconds, "bytes": dump.stat().st_size, "restore_seconds": restore_seconds,
                 "database_bytes": int(cl.scalar(SUPER, DB, f"SELECT pg_database_size('{DB}')"))},
        "not_in_the_dump": ["the artifact blobs (backed up beside it by scripts/backup.sh)", "WAL: there is no point in time recovery, a restore returns to the moment of the dump",
                            "the passwords of the logins (set again from the secret files)"],
    }
    print(json.dumps(report, indent=1))
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=1))
    same_catalog = report["catalog_fingerprint_equal"] or report["differences_are_only_parentheses"]
    ok = same_catalog and not mismatched and not chains["ledger_unsound"] and not chains["audit_unsound"]
    return 0 if ok else EXIT_FAIL


def run_prototype(args: argparse.Namespace) -> int:
    """The partitioning prototypes of docs/database/retention-and-partitioning.md, on a scratch cluster with the synthetic data."""
    cl = Cluster(find_bin(), args.keep, args.pg_setting)
    atexit.register(cl.destroy)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (cl.destroy(), sys.exit(130)))
    say(f"cluster: starting a scratch PostgreSQL on 127.0.0.1:{cl.port}")
    cl.start()
    provision(cl, args.rows)
    cl.psql(SUPER, DB, "UPDATE perf.tenant_plan SET jobs = jobs")      # touch nothing; keeps the plan tables as loaded
    proc = subprocess.run([str(cl.bin / "psql"), "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", SUPER, "-d", DB, "-f", str(HERE / "partition_prototype.sql")],
                          capture_output=True, text=True, env=cl.env(SUPER))
    lines = []
    for line in proc.stderr.splitlines():
        m = re.search(r"NOTICE:\s+(proto \|.*)$", line)
        if m:
            lines.append(m.group(1))
    print("\n".join(lines))
    if proc.returncode != 0:
        say(f"the prototype script failed: {proc.stderr[-1500:]}")
        return EXIT_FAIL
    if args.report:
        Path(args.report).write_text(json.dumps({"schema": "factory-db-perf-prototype/1", "rows": args.rows, "postgres": cl.version, "lines": lines}, indent=1))
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rows", type=int, default=100000, help="rows in each hot table (default 100000)")
    p.add_argument("--seed", type=int, default=20261028, help="seed for the choice of the parameters (the data itself has no randomness)")
    p.add_argument("--report", help="write the machine-readable report (JSON) here")
    p.add_argument("--markdown", help="write the table here")
    p.add_argument("--keep", action="store_true", help="leave the cluster and its data directory (you stop and delete it yourself)")
    p.add_argument("--quick", action="store_true", help="fewer iterations and shorter concurrency runs, for a smoke test")
    p.add_argument("--only", action="append", default=[], help="run only the series whose id matches this regular expression (repeatable)")
    p.add_argument("--skip-writes", action="store_true", help="skip the write paths, the concurrency runs and the churn run")
    p.add_argument("--skip-churn", action="store_true")
    p.add_argument("--break", dest="break_", help="a deliberate break that the harness must catch: superuser | chain | drop-index=NAME")
    p.add_argument("--prototype", choices=["partitions"], help="run the partitioning prototypes instead of the measurements")
    p.add_argument("--check", choices=["settings", "backup"], help="settings: the server as deployed (timeouts, extensions, autovacuum, an idle transaction that holds a lock); backup: a dump and restore round trip")
    p.add_argument("--pg-setting", action="append", default=[], help="an extra server setting, name=value (repeatable)")
    p.add_argument("--combined-for", action="append", default=["job_get@big"], help="series that are also timed with one set statement in place of two")
    a = p.parse_args(argv)
    if a.break_ and not (a.break_ in ("superuser", "chain") or a.break_.startswith("drop-index=")):
        p.error("--break is superuser, chain or drop-index=NAME")
    return a


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.check:
            if args.rows == 100000:
                args.rows = 20000
            return run_check_settings(args) if args.check == "settings" else run_check_backup(args)
        if args.prototype:
            if args.rows == 100000:
                args.rows = 30000
            return run_prototype(args)
        return run_all(args)
    except Blocked as e:
        say(f"BLOCKED: {e}")
        return EXIT_BLOCKED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
