#!/usr/bin/env python3
"""Helpers for the backup, restore, drill and smoke scripts (work package s1-local-deployment).

Standard library only. Run it as `python3 -I scripts/lib/factory_ops.py <command> ...`.

The shell scripts talk to Docker and PostgreSQL. This file does the parts that are easier to get right
in a real language and easier to test without Docker: building the manifest of a backup, comparing the
facts of a restored database with the manifest, rebuilding the hash chain of the evidence ledger
outside PostgreSQL, collecting check results into a machine-readable report, pruning old backups, and
damaging a file on purpose for the deliberate-break tests.

Every command that finds a problem prints one line per check to standard output as
`<name><TAB><PASS|FAIL><TAB><detail>` and exits 1 when any check failed. The scripts append those
lines to one file and `report` turns that file into JSON.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sys

FORMAT = "factory-backup/1"
# The files a backup holds, apart from the manifest, which names the others.
BACKUP_FILES = ["database.dump", "globals.sql", "artifacts.tar", "artifacts.list"]
# Everything a backup folder holds. Nothing else belongs there; in particular no secret file of the stack (the
# decision signing key, the webhook secret, the database URLs and passwords): they are not part of a backup.
BACKUP_FOLDER_FILES = set(BACKUP_FILES) | {"manifest.json", "SHA256SUMS"}
BLOB_PATH = re.compile(r"^sha256/([0-9a-f]{2})/([0-9a-f]{2})/([0-9a-f]{64})$")


def now_utc():
    # The system clock is read here, in the script, and never in the application (ADR 0011).
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def emit(name, ok, detail=""):
    """Print one check line. Tabs and newlines in the detail would break the format."""
    clean = re.sub(r"[\t\r\n]+", " ", str(detail))[:600]
    print("%s\t%s\t%s" % (name, "PASS" if ok else "FAIL", clean))
    return ok


def read_artifact_list(path):
    """Lines of `<sha256> <size> <path>`, sorted by path. Returns {path: (sha256, size)}."""
    entries = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            digest, size, blob = line.split(" ", 2)
            entries[blob] = (digest, int(size))
    return entries


# --------------------------------------------------------------------------------------------
# manifest


def cmd_manifest(args):
    facts = load(args.facts)
    tables = load(args.tables)
    blobs = read_artifact_list(args.artifact_list)
    manifest = {
        "format": FORMAT,
        "created_at": now_utc(),
        "label": args.label,
        "database": {
            "name": args.database,
            "server_version": facts["server_version"],
            "server_major": facts["server_version_num"] // 10000,
            "image": args.image,
            "dump_format": "custom",
            "dump_tool": args.dump_tool,
            "roles_file_has_passwords": False,
        },
        "schema": facts["schema"],
        "roles": facts["roles"],
        "fingerprints": facts["fingerprints"],
        "heads": facts["heads"],
        "chain": {k: facts["chain"][k] for k in ("ledger_chains", "audit_chains")},
        "tables": tables,
        "artifacts": {
            "count": len(blobs),
            "bytes": sum(size for _, size in blobs.values()),
            "list_sha256": sha256_file(args.artifact_list),
            "rows_in_database": facts["artifact_rows"],
        },
        "quiesced": facts["sessions"] == 0,
        "files": {},
    }
    for name in BACKUP_FILES:
        manifest["files"][name] = sha256_file(os.path.join(args.dir, name))
    with open(os.path.join(args.dir, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


# --------------------------------------------------------------------------------------------
# comparing a restored database with the manifest


def cmd_compare_db(args):
    manifest = load(args.manifest)
    facts = load(args.facts)
    tables = load(args.tables)
    failed = False

    want, got = manifest["schema"], facts["schema"]
    failed |= not emit("schema-version", want == got,
                       "backup %s migrations (latest %s); restored %s (latest %s)"
                       % (want["migrations"], want["latest"], got["migrations"], got["latest"]))
    failed |= not emit("server-major-version",
                       manifest["database"]["server_major"] == facts["server_version_num"] // 10000,
                       "backup PostgreSQL %s; restored PostgreSQL %s"
                       % (manifest["database"]["server_version"], facts["server_version"]))

    want_roles = {r["name"]: r for r in manifest["roles"]}
    got_roles = {r["name"]: r for r in facts["roles"]}
    missing = sorted(set(want_roles) - set(got_roles))
    extra = sorted(set(got_roles) - set(want_roles))
    failed |= not emit("roles-exist", not missing and not extra,
                       "missing: %s; unexpected: %s" % (missing or "none", extra or "none"))
    different = sorted(n for n in want_roles if n in got_roles and want_roles[n] != got_roles[n])
    failed |= not emit("roles-attributes-and-memberships", not different,
                       "different: %s" % (different or "none"))

    for name, want_hash in sorted(manifest["fingerprints"].items()):
        got_hash = facts["fingerprints"].get(name)
        failed |= not emit("fingerprint-" + name, want_hash == got_hash,
                           "equal" if want_hash == got_hash else "backup %s.. restored %s.." % (want_hash[:12], str(got_hash)[:12]))

    want_tables, got_tables = manifest["tables"], tables
    missing_t = sorted(set(want_tables) - set(got_tables))
    extra_t = sorted(set(got_tables) - set(want_tables))
    failed |= not emit("tables-exist", not missing_t and not extra_t,
                       "missing: %s; unexpected: %s" % (missing_t or "none", extra_t or "none"))
    wrong_rows = sorted(t for t in want_tables if t in got_tables and want_tables[t]["rows"] != got_tables[t]["rows"])
    failed |= not emit("row-counts", not wrong_rows,
                       ("%d tables, %d rows in total" % (len(want_tables), sum(v["rows"] for v in want_tables.values())))
                       if not wrong_rows else "different: " + ", ".join(
                           "%s %s->%s" % (t, want_tables[t]["rows"], got_tables[t]["rows"]) for t in wrong_rows))
    wrong_hash = sorted(t for t in want_tables if t in got_tables and want_tables[t]["sha256"] != got_tables[t]["sha256"])
    failed |= not emit("content-hash", not wrong_hash,
                       "every table hash equal" if not wrong_hash else "different: " + ", ".join(wrong_hash))

    failed |= not emit("ledger-heads", manifest["heads"]["ledger"] == facts["heads"]["ledger"],
                       "%d chains" % len(manifest["heads"]["ledger"]))
    failed |= not emit("audit-heads", manifest["heads"]["audit"] == facts["heads"]["audit"],
                       "%d chains" % len(manifest["heads"]["audit"]))
    chain = facts["chain"]
    failed |= not emit("ledger-verify-chain-in-database", not chain["ledger_bad"] and
                       chain["ledger_chains"] == manifest["chain"]["ledger_chains"],
                       "%d chains checked; first bad: %s" % (chain["ledger_chains"], chain["ledger_bad"] or "none"))
    failed |= not emit("audit-verify-chain-in-database", not chain["audit_bad"] and
                       chain["audit_chains"] == manifest["chain"]["audit_chains"],
                       "%d chains checked; first bad: %s" % (chain["audit_chains"], chain["audit_bad"] or "none"))
    return 1 if failed else 0


# --------------------------------------------------------------------------------------------
# the ledger chain, rebuilt outside PostgreSQL


def cmd_verify_ledger(args):
    """Rebuild every job's chain from a JSON export of ledger_entries and compare the heads.

    entry_hash = "sha256:" + hex(SHA-256(prev_entry_hash + "\\n" + canonical_json)), with an empty
    previous hash for entry 1 (docs/database/ledger-and-audit.md). This does not call the database's
    verifier, so it does not trust the function that lives in the database being checked.
    """
    rows = json.load(sys.stdin)
    chains = {}
    for row in rows:
        chains.setdefault((row["tenant_id"], row["job_id"]), []).append(row)
    problem = None
    heads = []
    for key in sorted(chains):
        previous = None
        for expected, row in enumerate(sorted(chains[key], key=lambda r: r["sequence"]), start=1):
            if row["sequence"] != expected:
                problem = "job %s: sequence %s where %s was expected" % (key[1], row["sequence"], expected)
            elif row["prev_entry_hash"] != (previous["entry_hash"] if previous else None):
                problem = "job %s sequence %s: prev_entry_hash does not name the entry before" % (key[1], expected)
            else:
                text = (row["prev_entry_hash"] or "") + "\n" + row["canonical_json"]
                rebuilt = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
                if rebuilt != row["entry_hash"]:
                    problem = "job %s sequence %s: entry_hash does not match its stored document" % (key[1], expected)
            if problem:
                break
            previous = row
        if problem or previous is None:
            break
        heads.append({"tenant": key[0], "job": key[1], "sequence": previous["sequence"], "hash": previous["entry_hash"]})
    ok = problem is None
    emit("ledger-chain-rebuilt-outside-postgresql", ok,
         ("%d chains, %d entries" % (len(chains), len(rows))) if ok else str(problem))
    if ok and args.manifest:
        want = sorted(load(args.manifest)["heads"]["ledger"], key=lambda h: (h["tenant"], h["job"]))
        ok = emit("ledger-heads-equal-manifest", want == heads, "%d chains" % len(heads))
    return 0 if ok else 1


# --------------------------------------------------------------------------------------------
# the artifact directory


def cmd_compare_artifacts(args):
    """Compare the blobs found on disk with the list the backup recorded and with the database."""
    manifest = load(args.manifest) if args.manifest else None
    want = read_artifact_list(args.recorded)
    got = read_artifact_list(args.found)
    failed = False
    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    failed |= not emit("artifacts-same-files", not missing and not extra,
                       "%d files; missing: %s; unexpected: %s" % (len(want), missing[:3] or "none", extra[:3] or "none"))
    changed = sorted(p for p in want if p in got and want[p] != got[p])
    failed |= not emit("artifacts-byte-identical", not changed,
                       "every file hash and size equals the recorded one" if not changed else "different: %s" % changed[:3])
    # A blob's name is its hash (ADR 0008), so a file whose bytes no longer hash to its own name is
    # damaged even if nobody recorded anything.
    misnamed = []
    for path, (digest, _) in got.items():
        m = BLOB_PATH.match(path)
        if not m or m.group(3) != digest or path.split("/")[1] != digest[:2] or path.split("/")[2] != digest[2:4]:
            misnamed.append(path)
    failed |= not emit("artifacts-hash-equals-name", not misnamed,
                       "every blob hashes to its own file name" if not misnamed else "damaged: %s" % sorted(misnamed)[:3])
    if manifest:
        failed |= not emit("artifacts-list-hash", sha256_file(args.recorded) == manifest["artifacts"]["list_sha256"],
                           "the recorded list is the one the manifest names")
    on_disk = {digest for digest, _ in got.values()}
    rows = [h.split(":", 1)[1] for h in manifest["artifacts"]["rows_in_database"]] if manifest else []
    if args.database_facts:
        rows = [h.split(":", 1)[1] for h in load(args.database_facts)["artifact_rows"]]
    if manifest or args.database_facts:
        lost = sorted(h for h in rows if h not in on_disk)
        failed |= not emit("artifact-index-rows-have-blobs", not lost,
                           "%d index rows, all with a blob" % len(rows) if not lost else "no blob for %s" % lost[:3])
    if args.state:
        state = load(args.state)
        bad = {k: v for k, v in state.items() if v}
        failed |= not emit("artifacts-owner-and-modes", not bad,
                           "files 0400, folders 0700, owned by the factory user (10010:10010 unless FACTORY_UID is set), no link or other kind of entry"
                           if not bad else "wrong: %s" % bad)
    return 1 if failed else 0


# --------------------------------------------------------------------------------------------
# report, retention, damage


def cmd_report(args):
    checks = []
    with open(args.checks, encoding="utf-8") as handle:
        for line in handle:
            parts = line.rstrip("\n").split("\t", 2)
            if len(parts) == 3 and parts[1] in ("PASS", "FAIL", "SKIP"):
                checks.append({"name": parts[0], "status": parts[1], "detail": parts[2]})
    meta = dict(item.split("=", 1) for item in args.meta)
    failed = [c["name"] for c in checks if c["status"] == "FAIL"]
    report = {
        "format": "factory-report/1",
        "tool": args.tool,
        "generated_at": now_utc(),
        "result": "FAIL" if failed or not checks else "PASS",
        "failed": failed,
        "counts": {s: sum(1 for c in checks if c["status"] == s) for s in ("PASS", "FAIL", "SKIP")},
        "meta": meta,
        "checks": checks,
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0 if report["result"] == "PASS" else 1


CAP_ALLOWED = {"postgres": {"CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"}, "artifacts-init": {"CHOWN", "DAC_OVERRIDE", "FOWNER"}}
SECRET_WORDS = ("PASSWORD", "SECRET", "TOKEN", "APIKEY", "API_KEY", "PRIVATE_KEY")


KEY_SECRET = "decision_signing_key"


def secret_target(service, source):
    """Where a service mounts the secret `source`, as an absolute path, or None if it does not mount it. Compose
    renders a long-form target without a slash as a name under /run/secrets."""
    for entry in service.get("secrets") or []:
        if entry.get("source") == source:
            target = entry.get("target") or source
            return target if target.startswith("/") else "/run/secrets/" + target
    return None


def decision_key_file(text):
    """The decisions.key_file a configuration file names, or None. The files are small and written in one of two
    shapes (a block, or a one-line table), and a full YAML reader is not in the standard library."""
    lines = [re.sub(r"\s#.*$", "", line) for line in text.splitlines() if not line.lstrip().startswith("#")]
    flat = "\n".join(lines)
    inline = re.search(r"^decisions:\s*\{[^}]*\bkey_file:\s*([^\s,}]+)", flat, re.M)
    if inline:
        return inline.group(1)
    block = re.search(r"^decisions:[ \t]*\n((?:[ \t]+.*\n?)+)", flat, re.M)
    if block:
        key = re.search(r"^[ \t]+key_file:\s*(\S+)", block.group(1), re.M)
        return key.group(1) if key else None
    return None


def configuration_key_file(service, target):
    """The key file named by the configuration file that the service mounts at `target`; None when it cannot be read."""
    for volume in service.get("volumes") or []:
        if volume.get("target") == target:
            try:
                with open(volume["source"], encoding="utf-8") as handle:
                    return decision_key_file(handle.read())
            except OSError:
                return None
    return None


def cmd_check_topology(args):
    """Check the rendered Compose file (docker compose config --format json, all profiles) against the layout rules
    of docs/security/sandbox-policy.md section 5 and the hardening rules of the sandbox policy. No Docker daemon
    is needed: it reads a file."""
    config = load(args.config)
    services = config["services"]
    networks = config.get("networks", {})
    failed = False

    def nets(name):
        return set((services[name].get("networks") or {}).keys())

    failed |= not emit("topology-postgres-only-on-data", nets("postgres") == {"data"}, "postgres is on %s" % sorted(nets("postgres")))
    probe_nets = nets("sandbox-probe")
    internal = all(networks.get(n, {}).get("internal") is True for n in probe_nets) and bool(probe_nets)
    failed |= not emit("topology-sandbox-network-is-internal", internal, "sandbox-probe is on %s, internal: %s" % (sorted(probe_nets), internal))
    shared = probe_nets & nets("postgres")
    failed |= not emit("topology-sandbox-shares-no-network-with-postgres", not shared, "shared networks: %s" % (sorted(shared) or "none"))
    failed |= not emit("topology-broker-network-is-internal", networks.get("broker", {}).get("internal") is True, "broker internal")
    on_data = sorted(n for n in services if "data" in nets(n))
    failed |= not emit("topology-data-network-members", set(on_data) <= {"postgres", "api", "worker"}, "on data: %s" % on_data)
    failed |= not emit("topology-sandbox-never-on-data-or-broker", not (probe_nets & {"data", "broker"}), "sandbox-probe networks %s" % sorted(probe_nets))

    bad_ports = []
    for name, svc in services.items():
        for port in svc.get("ports") or []:
            if port.get("host_ip") != "127.0.0.1":
                bad_ports.append("%s:%s" % (name, port.get("published")))
    failed |= not emit("ports-loopback-only", not bad_ports, "every published port is bound to 127.0.0.1" if not bad_ports else "not loopback: %s" % bad_ports)

    unpinned = [n for n, s in services.items()
                if "@sha256:" not in s["image"] and s.get("pull_policy") != "never"]
    failed |= not emit("images-pinned-or-never-pulled", not unpinned,
                       "every image is a digest or pull_policy never" if not unpinned else "unpinned: %s" % unpinned)
    failed |= not emit("postgres-image-is-18-by-digest", services["postgres"]["image"].startswith("postgres:18") and "@sha256:" in services["postgres"]["image"],
                       services["postgres"]["image"][:40])

    lax = []
    for name, svc in services.items():
        if svc.get("privileged") or svc.get("network_mode") == "host" or svc.get("pid") == "host" or svc.get("ipc") == "host":
            lax.append(name + ": privileged or host namespace")
        extra = set(svc.get("cap_add") or []) - CAP_ALLOWED.get(name, set())
        if extra:
            lax.append("%s: cap_add %s" % (name, sorted(extra)))
        if "ALL" not in (svc.get("cap_drop") or []):
            lax.append(name + ": does not drop all capabilities")
        if not svc.get("read_only"):
            lax.append(name + ": root file system is writable")
        if "no-new-privileges:true" not in (svc.get("security_opt") or []):
            lax.append(name + ": no-new-privileges missing")
        if not svc.get("mem_limit") or not svc.get("pids_limit"):
            lax.append(name + ": no memory or process limit")
        if not svc.get("profiles"):
            lax.append(name + ": no profile")
        for vol in svc.get("volumes") or []:
            if "docker.sock" in str(vol.get("source", "")):
                lax.append(name + ": mounts the Docker socket")
    failed |= not emit("hardening-every-service", not lax, "all %d services: caps dropped, read-only root, no-new-privileges, limits, a profile, no socket" % len(services) if not lax else "; ".join(lax))

    leaked = []
    for name, svc in services.items():
        for key, value in (svc.get("environment") or {}).items():
            if any(word in key.upper() for word in SECRET_WORDS) and not key.upper().endswith("_FILE") and value not in (None, ""):
                leaked.append("%s.%s" % (name, key))
    failed |= not emit("no-secret-in-environment", not leaked, "secret-like names are *_FILE paths only" if not leaked else "values in: %s" % leaked)

    # The api and the worker run as one numeric, non-root user, and that user owns the artifact volume: the job
    # artifacts-init gives the volume to the owner it names, and the storage crate writes as the service user.
    # 10010:10010 unless FACTORY_UID and FACTORY_GID are set (a Linux host whose secret files belong to someone else).
    users = {n: services[n].get("user") for n in ("api", "worker") if n in services}
    init_command = " ".join(str(w) for w in (services.get("artifacts-init", {}).get("command") or []))
    owner = re.search(r"install -d -m 0700 -o (\d+) -g (\d+) /artifacts", init_command)
    volume_owner = "%s:%s" % owner.groups() if owner else None
    one_user = len(set(users.values())) == 1 and bool(users)
    numeric = all(isinstance(u, str) and re.fullmatch(r"[1-9]\d*:\d+", u) for u in users.values())
    failed |= not emit("factory-services-run-as-the-volume-owner",
                       one_user and numeric and all(u == volume_owner for u in users.values()),
                       "api and worker run as %s; artifacts-init gives the volume to %s" % (users, volume_owner or "nobody (command not recognised)"))

    # The decision signing key: the api signs with it and the worker verifies with it, so both mount the same file
    # at the same path, and no other service has any business with it.
    paths = {n: secret_target(svc, KEY_SECRET) for n, svc in services.items()}
    holders = sorted(n for n, path in paths.items() if path)
    shared = holders == ["api", "worker"] and paths["api"] == paths["worker"]
    failed |= not emit("decision-key-in-api-and-worker-only", shared,
                       "the api and the worker both mount %s" % paths.get("api") if shared else
                       "the key is mounted in %s (paths %s); it belongs in api and worker, at one path" %
                       (holders or "no service", sorted({str(paths[n]) for n in holders}) or "none"))
    # ...and the path each configuration file gives is the path the secret is mounted at.
    wrong = []
    for name in ("api", "worker"):
        named = configuration_key_file(services.get(name, {}), "/etc/factory/%s.yaml" % name)
        if named is None or named != paths.get(name):
            wrong.append("%s: its configuration names %s, the key is mounted at %s" % (name, named or "no key file", paths.get(name)))
    failed |= not emit("decision-key-path-matches-configuration", not wrong,
                       "both configuration files name the path the key is mounted at" if not wrong else "; ".join(wrong))
    return 1 if failed else 0


def cmd_lines(args):
    """Print the checks of a report as check lines with a prefix, or only the names of the failed ones."""
    report = load(args.report)
    if args.failed_only:
        print(" ".join(report["failed"]))
        return 0
    for check in report["checks"]:
        print("%s%s\t%s\t%s" % (args.prefix, check["name"], check["status"], check["detail"]))
    return 0


def cmd_prune(args):
    """Delete all but the newest `keep` backups under root. Only a folder that is named like a backup and
    holds a manifest of this format is ever touched; anything else in the folder is left alone."""
    found = []
    for name in sorted(os.listdir(args.root)):
        folder = os.path.join(args.root, name)
        manifest = os.path.join(folder, "manifest.json")
        if not (name.startswith("factory-backup-") and os.path.isdir(folder) and not os.path.islink(folder)
                and os.path.isfile(manifest)):
            continue
        try:
            if load(manifest).get("format") != FORMAT:
                continue
        except (OSError, ValueError):
            continue
        found.append(name)
    keep = max(args.keep, 1)  # the newest backup is never deleted
    for name in found[:-keep] if len(found) > keep else []:
        shutil.rmtree(os.path.join(args.root, name))
        print("pruned %s" % name)
    print("kept %d of %d backups" % (min(len(found), keep), len(found)))
    return 0


def cmd_corrupt(args):
    """Flip one bit of one byte, for the deliberate-break tests. The offset counts from the start."""
    with open(args.file, "r+b") as handle:
        handle.seek(args.offset)
        byte = handle.read(1)
        if not byte:
            print("offset %d is past the end of %s" % (args.offset, args.file), file=sys.stderr)
            return 2
        handle.seek(args.offset)
        handle.write(bytes([byte[0] ^ 0x01]))
    return 0


def cmd_rehash(args):
    """For the deliberate-break tests only: make SHA256SUMS and the manifest's file hashes agree with the files
    as they are now. It stands for someone who damaged a backup and then fixed the checksums to hide it, or for a
    backup that was damaged before it was ever checksummed. The restore must still catch the damage."""
    path = os.path.join(args.dir, "manifest.json")
    manifest = load(path)
    for name in BACKUP_FILES:
        manifest["files"][name] = sha256_file(os.path.join(args.dir, name))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return cmd_sums(args)


def cmd_manifest_set(args):
    """For the deliberate-break tests only: set one value in the manifest (a dotted key), then rehash."""
    path = os.path.join(args.dir, "manifest.json")
    manifest = load(path)
    node = manifest
    keys = args.key.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = json.loads(args.value)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return cmd_rehash(args)


def cmd_tar_drop(args):
    """For the deliberate-break tests only: rewrite a tar without one member (a lost artifact file)."""
    import tarfile
    source, target = args.tar, args.tar + ".new"
    dropped = 0
    with tarfile.open(source) as old, tarfile.open(target, "w", format=tarfile.GNU_FORMAT) as new:
        for member in old:
            if member.name.lstrip("./") == args.member.lstrip("./"):
                dropped += 1
                continue
            new.addfile(member, old.extractfile(member) if member.isfile() else None)
    os.replace(target, source)
    return 0 if dropped == 1 else 2


def cmd_sums(args):
    """Write SHA256SUMS for the files of a backup folder (the manifest included)."""
    names = BACKUP_FILES + ["manifest.json"]
    with open(os.path.join(args.dir, "SHA256SUMS"), "w", encoding="utf-8") as handle:
        for name in names:
            handle.write("%s  %s\n" % (sha256_file(os.path.join(args.dir, name)), name))
    return 0


def cmd_check_sums(args):
    """Check SHA256SUMS and that the manifest names the same hashes. Exits 1 on any difference."""
    failed = False
    listed = {}
    try:
        with open(os.path.join(args.dir, "SHA256SUMS"), encoding="utf-8") as handle:
            for line in handle:
                digest, name = line.rstrip("\n").split("  ", 1)
                listed[name] = digest
    except OSError as error:
        return 0 if emit("backup-checksums", False, "cannot read SHA256SUMS: %s" % error) else 1
    bad = []
    for name in BACKUP_FILES + ["manifest.json"]:
        path = os.path.join(args.dir, name)
        if name not in listed:
            bad.append("%s is not listed" % name)
        elif not os.path.isfile(path):
            bad.append("%s is missing" % name)
        elif sha256_file(path) != listed[name]:
            bad.append("%s does not match its checksum" % name)
    failed |= not emit("backup-checksums", not bad, "all %d files match SHA256SUMS" % len(listed) if not bad else "; ".join(bad))
    # A file the backup does not define is refused and named. A name that starts with a dot (.DS_Store, a file
    # manager's own) is not a stray.
    strays = sorted(n for n in os.listdir(args.dir) if n not in BACKUP_FOLDER_FILES and not n.startswith("."))
    failed |= not emit("backup-holds-only-its-own-files", not strays,
                       "the folder holds only the files of a backup" if not strays else
                       "not part of a backup: %s. A backup never holds a secret; take the file out" % ", ".join(strays))
    if not bad:
        manifest = load(os.path.join(args.dir, "manifest.json"))
        same = all(manifest["files"].get(n) == listed.get(n) for n in BACKUP_FILES)
        failed |= not emit("manifest-names-the-same-hashes", manifest.get("format") == FORMAT and same,
                           "the manifest and SHA256SUMS agree")
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("manifest")
    p.add_argument("--dir", required=True)
    p.add_argument("--facts", required=True)
    p.add_argument("--tables", required=True)
    p.add_argument("--artifact-list", required=True)
    p.add_argument("--database", required=True)
    p.add_argument("--image", default="")
    p.add_argument("--dump-tool", default="")
    p.add_argument("--label", default="")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("compare-db")
    p.add_argument("--manifest", required=True)
    p.add_argument("--facts", required=True)
    p.add_argument("--tables", required=True)
    p.set_defaults(func=cmd_compare_db)

    p = sub.add_parser("verify-ledger")
    p.add_argument("--manifest")
    p.set_defaults(func=cmd_verify_ledger)

    p = sub.add_parser("compare-artifacts")
    p.add_argument("--manifest")
    p.add_argument("--recorded", required=True)
    p.add_argument("--found", required=True)
    p.add_argument("--state")
    p.add_argument("--database-facts")
    p.set_defaults(func=cmd_compare_artifacts)

    p = sub.add_parser("report")
    p.add_argument("--checks", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--out")
    p.add_argument("--meta", action="append", default=[])
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("check-topology")
    p.add_argument("--config", required=True)
    p.set_defaults(func=cmd_check_topology)

    p = sub.add_parser("lines")
    p.add_argument("--report", required=True)
    p.add_argument("--prefix", default="")
    p.add_argument("--failed-only", action="store_true")
    p.set_defaults(func=cmd_lines)

    p = sub.add_parser("prune")
    p.add_argument("--root", required=True)
    p.add_argument("--keep", type=int, required=True)
    p.set_defaults(func=cmd_prune)

    p = sub.add_parser("corrupt")
    p.add_argument("--file", required=True)
    p.add_argument("--offset", type=int, required=True)
    p.set_defaults(func=cmd_corrupt)

    p = sub.add_parser("sums")
    p.add_argument("--dir", required=True)
    p.set_defaults(func=cmd_sums)

    p = sub.add_parser("rehash")
    p.add_argument("--dir", required=True)
    p.set_defaults(func=cmd_rehash)

    p = sub.add_parser("manifest-set")
    p.add_argument("--dir", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--value", required=True)
    p.set_defaults(func=cmd_manifest_set)

    p = sub.add_parser("tar-drop")
    p.add_argument("--tar", required=True)
    p.add_argument("--member", required=True)
    p.set_defaults(func=cmd_tar_drop)

    p = sub.add_parser("check-sums")
    p.add_argument("--dir", required=True)
    p.set_defaults(func=cmd_check_sums)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
