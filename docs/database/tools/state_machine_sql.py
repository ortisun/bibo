"""Turn docs/architecture/state-machine.json (and two schemas) into SQL.

    python3 -I docs/database/tools/state_machine_sql.py seed     docs/architecture/state-machine.json
    python3 -I docs/database/tools/state_machine_sql.py expected docs/architecture/state-machine.json

`seed` prints the INSERT statements that fill the three state machine reference tables. They were
pasted into migrations/2026-10-27-000100_foundation/up.sql. A later change to the state machine
needs a new migration that applies the difference; do not edit the foundation migration.

`expected` prints CREATE TABLE and INSERT statements for the dbtest schema, which the `statuses`
database test compares with the live tables. It also prints the required fields of two schemas, so
the tests can check that the rows are able to carry the contracts.

The script reads files and prints text. It writes nothing and needs only the standard library.
"""
import hashlib
import json
import os
import sys

MACHINES = ["job", "stage_run", "attempt", "task_node"]


def q(value):
    return "'" + value.replace("'", "''") + "'"


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def states(doc):
    for machine in MACHINES:
        spec = doc["machines"][machine]
        for status, info in spec["states"].items():
            yield machine, status, status == spec["initial"], bool(info.get("terminal"))


def transitions(doc):
    for machine in MACHINES:
        for t in doc["machines"][machine]["transitions"]:
            yield machine, t["id"], t["event"], t["to"], t["emits"]


def edges(doc):
    for machine in MACHINES:
        for t in doc["machines"][machine]["transitions"]:
            for origin in t["from"]:
                yield machine, origin, t["id"]


def values(rows, fmt):
    return ",\n".join("  (" + fmt(r) + ")" for r in rows) + ";"


def seed(doc, table_prefix=""):
    out = []
    out.append("INSERT INTO %sstate_machine_states (machine, status, is_initial, is_terminal) VALUES" % table_prefix)
    out.append(values(states(doc), lambda r: "%s, %s, %s, %s" % (q(r[0]), q(r[1]), str(r[2]).lower(), str(r[3]).lower())))
    out.append("")
    out.append("INSERT INTO %sstate_machine_transitions (machine, transition_id, event, to_status, emits) VALUES" % table_prefix)
    out.append(values(transitions(doc), lambda r: "%s, %s, %s, %s, %s" % (q(r[0]), q(r[1]), q(r[2]), q(r[3]), "NULL" if r[4] is None else q(r[4]))))
    out.append("")
    out.append("INSERT INTO %sstate_machine_edges (machine, from_status, transition_id) VALUES" % table_prefix)
    out.append(values(edges(doc), lambda r: "%s, %s, %s" % (q(r[0]), q(r[1]), q(r[2]))))
    return "\n".join(out)


def schema_required(schema_dir):
    """Required top-level and metadata fields of the two schemas the rows must carry."""
    ledger = load(os.path.join(schema_dir, "evidence-ledger-entry.schema.json"))
    event = load(os.path.join(schema_dir, "domain-event.schema.json"))
    rows = []
    for name in ledger["required"]:
        rows.append(("evidence-ledger-entry", name))
    for name in ledger["properties"]["metadata"]["required"]:
        rows.append(("evidence-ledger-entry.metadata", name))
    for name in ledger["properties"]["metadata"]["properties"]["recorded_by"]["required"]:
        rows.append(("evidence-ledger-entry.metadata.recorded_by", name))
    for name in event["required"]:
        rows.append(("domain-event", name))
    for name in event["properties"]["aggregate"]["required"]:
        rows.append(("domain-event.aggregate", name))
    return rows


def examples(schema_dir):
    """The valid example documents of the two contracts the rows must carry.

    Ledger entries are re-sequenced to be the first entry of their job, with entry_hash removed, and
    written as canonical JSON text (sorted keys, no spaces, no ASCII escaping). The example hashes in
    schemas/examples are placeholders, so the test computes a real one. The examples share one job id
    and one stage run id although they mix execution modes, so each gets its own job and stage run.
    Events are kept as they are.
    """
    def uuid_from(seed):
        h = hashlib.md5(seed.encode("utf-8")).hexdigest()
        return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])

    rows = []
    ledger_dir = os.path.join(schema_dir, "examples", "evidence-ledger-entry", "valid")
    for name in sorted(os.listdir(ledger_dir)):
        entry = load(os.path.join(ledger_dir, name))
        entry.pop("entry_hash", None)
        entry["metadata"]["sequence"] = 1
        entry["metadata"]["job_id"] = uuid_from("job:" + name)
        entry["metadata"]["stage_run_id"] = uuid_from("run:" + name)
        entry["prev_entry_hash"] = None
        text = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        rows.append(("ledger", name, text))
    event_dir = os.path.join(schema_dir, "examples", "domain-event", "valid")
    for name in sorted(os.listdir(event_dir)):
        event = load(os.path.join(event_dir, name))
        rows.append(("event", name, json.dumps(event, sort_keys=True, ensure_ascii=False)))
    return rows


def expected(doc, schema_dir):
    out = []
    out.append("CREATE TABLE dbtest.expected_states (machine text, status text, is_initial boolean, is_terminal boolean);")
    out.append("INSERT INTO dbtest.expected_states VALUES")
    out.append(values(states(doc), lambda r: "%s, %s, %s, %s" % (q(r[0]), q(r[1]), str(r[2]).lower(), str(r[3]).lower())))
    out.append("CREATE TABLE dbtest.expected_transitions (machine text, transition_id text, event text, to_status text, emits text);")
    out.append("INSERT INTO dbtest.expected_transitions VALUES")
    out.append(values(transitions(doc), lambda r: "%s, %s, %s, %s, %s" % (q(r[0]), q(r[1]), q(r[2]), q(r[3]), "NULL" if r[4] is None else q(r[4]))))
    out.append("CREATE TABLE dbtest.expected_edges (machine text, from_status text, transition_id text);")
    out.append("INSERT INTO dbtest.expected_edges VALUES")
    out.append(values(edges(doc), lambda r: "%s, %s, %s" % (q(r[0]), q(r[1]), q(r[2]))))
    out.append("CREATE TABLE dbtest.expected_stage_kinds (stage_kind text);")
    out.append("INSERT INTO dbtest.expected_stage_kinds VALUES")
    out.append(values([(s["kind"],) for s in doc["pipeline"]["stages"]], lambda r: q(r[0])))
    out.append("CREATE TABLE dbtest.expected_schema_fields (schema_name text, field text);")
    out.append("INSERT INTO dbtest.expected_schema_fields VALUES")
    out.append(values(schema_required(schema_dir), lambda r: "%s, %s" % (q(r[0]), q(r[1]))))
    out.append("CREATE TABLE dbtest.example_documents (kind text, name text, doc text);")
    out.append("INSERT INTO dbtest.example_documents VALUES")
    out.append(values(examples(schema_dir), lambda r: "%s, %s, %s" % (q(r[0]), q(r[1]), q(r[2]))))
    return "\n".join(out)


def main(argv):
    if len(argv) != 3 or argv[1] not in ("seed", "expected"):
        sys.stderr.write(__doc__)
        return 2
    mode, path = argv[1], argv[2]
    doc = load(path)
    if doc.get("schema_version") != 1:
        sys.stderr.write("state-machine.json schema_version is not 1; update this script and add a migration\n")
        return 1
    if mode == "seed":
        print(seed(doc))
    else:
        # state-machine.json sits in <root>/docs/architecture, the schemas in <root>/schemas.
        schema_dir = os.path.join(os.path.dirname(os.path.abspath(path)), "..", "..", "schemas")
        print(expected(doc, os.path.normpath(schema_dir)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
