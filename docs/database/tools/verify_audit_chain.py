"""Verify one tenant's audit chain without PostgreSQL's help.

    psql -At -c "SELECT json_agg(row_to_json(a) ORDER BY sequence) FROM audit_events a WHERE tenant_id = '<uuid>'" \
      | python3 -I docs/database/tools/verify_audit_chain.py

Reads a JSON array of audit_events rows on standard input. For every row it checks that the sequence
runs 1, 2, 3 with no gap, that prev_hash is the hash of the row before, that canonical_json is exactly
what the columns say (rebuilt here from the policy's field list, keys sorted, no whitespace), and that
hash is SHA-256 over prev_hash, a newline and canonical_json. Prints the first problem and exits 1,
or prints a summary and exits 0.

This is the reference for the hourly verification job (policies/security.yaml, audit). It shows that
an outside program can rebuild the chain from the table alone. It does not read the external anchor:
a missing tail is invisible without it.
"""
import hashlib
import json
import sys
from datetime import datetime, timezone

FIELDS = [
    "action", "actor_id", "actor_type", "correlation_id", "created_at", "decision", "event_id",
    "job_id", "policy_hash", "prev_hash", "reason", "sequence", "stage_run_id", "subject", "tenant_id",
]


def canonical(row):
    created = datetime.fromisoformat(row["created_at"]).astimezone(timezone.utc)
    values = {name: row[name] for name in FIELDS if name != "created_at"}
    values["created_at"] = created.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    return json.dumps(values, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(prev_hash, text):
    return "sha256:" + hashlib.sha256(((prev_hash or "") + "\n" + text).encode("utf-8")).hexdigest()


def main():
    rows = json.load(sys.stdin)
    if not rows:
        print("no rows to verify", file=sys.stderr)
        return 1
    previous = None
    for expected_sequence, row in enumerate(rows, start=1):
        if row["sequence"] != expected_sequence:
            print("sequence %s where %s was expected" % (row["sequence"], expected_sequence), file=sys.stderr)
            return 1
        if row["prev_hash"] != (previous["hash"] if previous else None):
            print("sequence %s: prev_hash does not name the previous row" % row["sequence"], file=sys.stderr)
            return 1
        rebuilt = canonical(row)
        if rebuilt != row["canonical_json"]:
            print("sequence %s: canonical_json differs from the columns\n  stored : %s\n  rebuilt: %s"
                  % (row["sequence"], row["canonical_json"], rebuilt), file=sys.stderr)
            return 1
        if digest(row["prev_hash"], row["canonical_json"]) != row["hash"]:
            print("sequence %s: hash does not match its text" % row["sequence"], file=sys.stderr)
            return 1
        previous = row
    print("verified %d audit events outside PostgreSQL (head %s)" % (len(rows), previous["hash"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
