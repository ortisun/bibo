#!/usr/bin/env python3
"""Check the P0 coverage matrix and render it into docs/security/p0-coverage.md.

Usage (from the repository root):
    python3 -I docs/security/tools/check_p0_coverage.py --check     # validate, fail when the document is out of date
    python3 -I docs/security/tools/check_p0_coverage.py --write     # validate and rewrite the document
    python3 -I docs/security/tools/check_p0_coverage.py --summary   # print the counts by status
    python3 -I docs/security/tools/check_p0_coverage.py --self-test # break the data on purpose and show each break is caught

The data is docs/security/p0-coverage.json. The document is generated from it and must never be
edited by hand. Only the standard library is used, and nothing here runs a test, a build or a
container: the check reads files, so it is cheap and the same on every machine.

What --check fails on:
  * a P0 test of the negative test catalog that has no row, or a row for a test that is not a P0
    test of the catalog;
  * a row whose test name is not defined (as a function) in the named source file, or whose name
    does not start with the catalog naming rule (negative_ followed by the lower-case id);
  * a status that the evidence does not support: "proven" with no control-off variant, with a
    variant that does not exist, or with no test that can run without Docker or a live provider;
    "control_off_missing" that lists a variant; "missing" that lists a test; "blocked" with no
    reason;
  * a control-off variant that is not what it says: a mutation name that the script does not
    define, a break test or defect that the file does not contain, a variant that claims to catch a
    test of another row, or a mutation with test filters that none of the caught tests matches;
  * a row whose owner is not in docs/architecture/work-packages.json;
  * a document that differs from what the data produces;
  * (--check also runs --self-test) a deliberate break of the data that the validation does not
    catch.
"""

import ast
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "docs/security/p0-coverage.json"
TARGET = ROOT / "docs/security/p0-coverage.md"
CATALOG = ROOT / "docs/security/negative-test-catalog.md"
WORK_PACKAGES = ROOT / "docs/architecture/work-packages.json"
WP_TOOL = ROOT / "docs/architecture/tools/check_work_packages.py"

STATUSES = ("proven", "control_off_missing", "blocked", "missing")
STATUS_TEXT = {
    "proven": "implemented, control-off proven",
    "control_off_missing": "implemented, control-off missing",
    "blocked": "BLOCKED",
    "missing": "missing",
}
NEEDS = ("docker", "live_provider")
BLOCK_KINDS = ("docker", "live_provider", "human")
CONTROL_KINDS = ("mutation", "break_test", "defect")
ROW_KEYS = {"id", "status", "tests", "control_off", "blocked", "parts_blocked", "findings", "note"}
FINDING_KEYS = {"id", "owner", "title", "detail", "smallest_fix", "severity"}
TEST_KEYS = {"name", "file", "needs"}
CONTROL_KEYS = {
    "mutation": {"kind", "script", "name", "catches"},
    "break_test": {"kind", "file", "name", "catches"},
    "defect": {"kind", "file", "symbol", "catches"},
}
RUN_KEYS = {"script", "name", "date", "result", "failed"}
TOP_KEYS = {"schema_version", "catalog", "work_packages", "recorded", "findings", "audit_events", "mutation_runs", "rows"}
POLICY = ROOT / "policies/security.yaml"
PRODUCTIONS = ("engine", "handler", "api", "differently_named", "other_stream", "none")
EVENT_KEYS = {"type", "owner", "production", "source", "token", "note"}


def fail(errors) -> NoReturn:
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    sys.exit(1)


def load_catalog():
    """The P0 rows of the catalog, read by the parser of check_work_packages.py (one parser only)."""
    spec = importlib.util.spec_from_file_location("check_work_packages", WP_TOOL)
    if spec is None or spec.loader is None:
        fail([f"cannot load {WP_TOOL.relative_to(ROOT)}"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_catalog()


def read_text(rel):
    path = ROOT / rel
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def defines_function(source, name):
    return re.search(r"\bfn\s+" + re.escape(name) + r"\b", source) is not None


def mutation_catalog(rel):
    """{name: filters or None} for the dictionary MUTATIONS or the list BREAKS of a script."""
    source = read_text(rel)
    if source is None:
        return None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    found = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id not in ("MUTATIONS", "BREAKS"):
            continue
        value = node.value
        if isinstance(value, ast.Dict):
            for key in value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    found[key.value] = None
        elif isinstance(value, ast.List):
            for element in value.elts:
                if not isinstance(element, ast.Tuple) or not element.elts:
                    continue
                head = element.elts[0]
                if not (isinstance(head, ast.Constant) and isinstance(head.value, str)):
                    continue
                filters = None
                last = element.elts[-1]
                if isinstance(last, ast.List):
                    filters = [x.value for x in last.elts if isinstance(x, ast.Constant) and isinstance(x.value, str)]
                found[head.value] = filters
    return found


def crate_dir(rel):
    parts = rel.split("/")
    if parts[0] in ("crates", "apps") and len(parts) > 1:
        return "/".join(parts[:2])
    return parts[0]


def validate(doc):
    errors = []
    unknown = set(doc) - TOP_KEYS
    if unknown:
        errors.append(f"unknown top-level keys {sorted(unknown)}")
    if doc.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    catalog = load_catalog()
    p0 = {k for k, v in catalog.items() if v["priority"] == "P0" and k.startswith("NT-")}
    wp_doc = json.loads(WORK_PACKAGES.read_text(encoding="utf-8"))
    owners = {e["id"]: e for e in wp_doc["negative_tests"]["entries"]}
    wps = {w["id"] for w in wp_doc["work_packages"]}
    rows = doc.get("rows", [])
    seen = {}
    for row in rows:
        rid = row.get("id", "?")
        if rid in seen:
            errors.append(f"{rid}: more than one row")
        seen[rid] = row
    for missing in sorted(p0 - set(seen)):
        errors.append(f"{missing}: a P0 test of the catalog has no row")
    for extra in sorted(set(seen) - p0):
        errors.append(f"{extra}: has a row but is not a P0 test of the catalog")
    runs = doc.get("mutation_runs", [])
    errors += validate_audit_events(doc.get("audit_events", []), wps)
    finding_ids = set()
    for f in doc.get("findings", []):
        if set(f) != FINDING_KEYS:
            errors.append(f"finding {f.get('id', '?')}: keys must be {sorted(FINDING_KEYS)}")
            continue
        if f["id"] in finding_ids:
            errors.append(f"finding {f['id']}: listed twice")
        finding_ids.add(f["id"])
        if f["owner"] not in wps:
            errors.append(f"finding {f['id']}: owner {f['owner']} is not a work package")
        if f["severity"] not in ("high", "medium", "low"):
            errors.append(f"finding {f['id']}: severity must be high, medium or low")
    for row in rows:
        for fid in row.get("findings", []):
            if fid not in finding_ids:
                errors.append(f"{row.get('id', '?')}: names finding {fid}, which is not listed")
    for fid in sorted(finding_ids):
        if not any(fid in row.get("findings", []) for row in rows):
            errors.append(f"finding {fid} is not reported by any row")
    for run in runs:
        if set(run) != RUN_KEYS:
            errors.append(f"mutation_runs entry {run}: keys must be {sorted(RUN_KEYS)}")
            continue
        names = mutation_catalog(run["script"])
        if names is None or run["name"] not in names:
            errors.append(f"mutation_runs: {run['name']} is not defined in {run['script']}")
        if run["result"] not in ("CAUGHT", "MISSED", "INVALID"):
            errors.append(f"mutation_runs: {run['name']}: result must be CAUGHT, MISSED or INVALID")
    for rid, row in seen.items():
        errors += validate_row(rid, row, owners, wps)
    return errors, catalog, owners


def required_audit_types():
    text = POLICY.read_text(encoding="utf-8")
    section = text.split("must_record:", 1)[1].splitlines()[1:]
    out = []
    for line in section:
        line = line.strip()
        if not line.startswith("- "):
            break
        out.append(line[2:].strip())
    return out


def camel(name):
    return "".join(part.capitalize() for part in name.split("_"))


def production_sources():
    """The text of every production source of the workspace, by path, without the audit module of
    the workflow crate (where the enum is defined) and without tests."""
    found = {}
    for base in ("crates", "apps"):
        for path in sorted((ROOT / base).glob("*/src/**/*.rs")):
            rel = path.relative_to(ROOT).as_posix()
            if rel.startswith("crates/workflow/src/audit/"):
                continue
            found[rel] = path.read_text(encoding="utf-8")
    return found


def validate_audit_events(events, wps):
    """The owner matrix of NT-AUD-03: the types are the ones the policy requires, in its order; each
    has an owner that is a work package; and what the matrix says is produced in production code is
    what the sources say."""
    errors = []
    required = required_audit_types()
    listed = [e.get("type") for e in events]
    if listed != required:
        errors.append(f"audit_events types {listed} differ from audit.must_record of the policy {required}")
    sources = None
    for e in events:
        label = e.get("type", "?")
        if set(e) != EVENT_KEYS:
            errors.append(f"audit_events {label}: keys must be {sorted(EVENT_KEYS)}")
            continue
        if e["owner"] not in wps:
            errors.append(f"audit_events {label}: owner {e['owner']} is not a work package")
        if e["production"] not in PRODUCTIONS:
            errors.append(f"audit_events {label}: production must be one of {list(PRODUCTIONS)}")
            continue
        if not e["note"].strip():
            errors.append(f"audit_events {label}: needs a note")
        if e["production"] == "none":
            if sources is None:
                sources = production_sources()
            hits = [rel for rel, text in sources.items() if f"AuditKind::{camel(label)}" in text or f'"{label}"' in text]
            if hits:
                errors.append(f"audit_events {label}: the matrix says nothing writes it, but {hits} mention it; set production and source")
        else:
            text = read_text(e["source"])
            if text is None:
                errors.append(f"audit_events {label}: source {e['source']} does not exist")
            else:
                for token in [t.strip() for t in e["token"].split("|")]:
                    if token not in text:
                        errors.append(f"audit_events {label}: {e['source']} does not contain {token}")
    return errors


def validate_row(rid, row, owners, wps):
    errors = []
    unknown = set(row) - ROW_KEYS
    if unknown:
        errors.append(f"{rid}: unknown keys {sorted(unknown)}")
    status = row.get("status")
    if status not in STATUSES:
        return errors + [f"{rid}: status must be one of {list(STATUSES)}"]
    owner = owners.get(rid)
    if owner is None:
        errors.append(f"{rid}: no owner in work-packages.json negative_tests.entries")
    elif owner["wp"] not in wps:
        errors.append(f"{rid}: owner {owner['wp']} is not a work package")
    tests = row.get("tests", [])
    control = row.get("control_off", [])
    prefix = "negative_" + rid.lower().replace("-", "_")
    names = set()
    runnable = set()
    for t in tests:
        if set(t) - TEST_KEYS or not {"name", "file"} <= set(t):
            errors.append(f"{rid}: test entry {t} must have name, file and optional needs")
            continue
        needs = t.get("needs", [])
        if any(n not in NEEDS for n in needs):
            errors.append(f"{rid}: {t['name']}: needs must be a subset of {list(NEEDS)}")
        if not t["name"].startswith(prefix):
            errors.append(f"{rid}: {t['name']} does not start with {prefix} (the naming rule of the catalog)")
        source = read_text(t["file"])
        if source is None:
            errors.append(f"{rid}: {t['name']}: file {t['file']} does not exist")
        elif not defines_function(source, t["name"]):
            errors.append(f"{rid}: {t['name']} is not defined in {t['file']}")
        if t["name"] in names:
            errors.append(f"{rid}: {t['name']} is listed twice")
        names.add(t["name"])
        if not needs:
            runnable.add(t["name"])
    caught_runnable = set()
    for c in control:
        errors += validate_control(rid, c, tests, names)
        caught_runnable |= {n for n in c.get("catches", []) if n in runnable}
    if status == "missing":
        if tests or control:
            errors.append(f"{rid}: status missing but the row lists tests or control-off variants")
    else:
        if not tests:
            errors.append(f"{rid}: status {status} but no test is listed")
        if not any(t["name"].startswith(prefix) for t in tests):
            errors.append(f"{rid}: no listed test follows the naming rule {prefix}")
    all_blocked = bool(tests) and all(t.get("needs") for t in tests)
    if status == "proven":
        if not control:
            errors.append(f"{rid}: status proven but no control-off variant is named")
        elif not caught_runnable:
            errors.append(f"{rid}: status proven but no control-off variant catches a test that runs without Docker or a live provider")
        if all_blocked:
            errors.append(f"{rid}: status proven but every test needs Docker or a live provider; the row is blocked")
    if status == "control_off_missing":
        if control:
            errors.append(f"{rid}: status control_off_missing but control-off variants are listed")
        if all_blocked:
            errors.append(f"{rid}: every test needs Docker or a live provider; the row is blocked")
    if status == "blocked":
        blocked = row.get("blocked")
        if not isinstance(blocked, dict) or set(blocked) != {"kind", "reason"} or blocked.get("kind") not in BLOCK_KINDS or not str(blocked.get("reason", "")).strip():
            errors.append(f"{rid}: status blocked needs blocked = {{kind: one of {list(BLOCK_KINDS)}, reason: text}}")
    elif row.get("blocked") is not None:
        errors.append(f"{rid}: blocked is only for status blocked (use parts_blocked for a part)")
    for part in row.get("parts_blocked", []):
        if not isinstance(part, dict) or set(part) != {"part", "kind", "reason"} or part["kind"] not in BLOCK_KINDS or not str(part["reason"]).strip():
            errors.append(f"{rid}: parts_blocked entry {part} needs part, kind and reason")
    entry = owners.get(rid)
    if entry and entry.get("scope") == "partial" and not str(row.get("note", "")).strip():
        errors.append(f"{rid}: the work package marks this entry partial, so the row needs a note that says what is covered")
    return errors


def validate_control(rid, c, tests, names):
    errors = []
    kind = c.get("kind")
    if kind not in CONTROL_KINDS:
        return [f"{rid}: control-off kind must be one of {list(CONTROL_KINDS)}: {c}"]
    if set(c) != CONTROL_KEYS[kind]:
        return [f"{rid}: control-off {kind} entry needs exactly the keys {sorted(CONTROL_KEYS[kind])}: {c}"]
    catches = c["catches"]
    if not isinstance(catches, list) or not catches:
        errors.append(f"{rid}: control-off variant {c.get('name', c.get('symbol'))} catches no test")
        catches = []
    for n in catches:
        if n not in names:
            errors.append(f"{rid}: control-off variant {c.get('name', c.get('symbol'))} claims to catch {n}, which is not a test of this row")
    where = c.get("script") or c.get("file")
    if read_text(where) is None:
        return errors + [f"{rid}: {where} does not exist"]
    homes = {crate_dir(t["file"]) for t in tests if t["name"] in catches} or {crate_dir(t["file"]) for t in tests}
    if kind == "mutation":
        catalog = mutation_catalog(where)
        if catalog is None or c["name"] not in catalog:
            errors.append(f"{rid}: mutation {c['name']} is not defined in {where}")
        else:
            filters = catalog[c["name"]]
            cross_crate = where.startswith("tests/security/")
            if filters is not None:
                for n in catches:
                    if not any(f in n for f in filters):
                        errors.append(f"{rid}: mutation {c['name']} runs only the filters {filters} (nextest matches a filter as part of a name), none of which selects {n}")
            if not cross_crate and not set(homes) <= {crate_dir(where)}:
                errors.append(f"{rid}: mutation {c['name']} belongs to {crate_dir(where)}, which is not the crate of the tests it claims to catch ({sorted(homes)})")
    elif kind == "break_test":
        source = read_text(where) or ""
        if not defines_function(source, c["name"]):
            errors.append(f"{rid}: break test {c['name']} is not defined in {where}")
        if crate_dir(where) not in homes and not catches:
            errors.append(f"{rid}: break test {c['name']} is in {crate_dir(where)}, not the crate of this row")
    else:
        source = read_text(where) or ""
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(c["symbol"]) + r"(?![A-Za-z0-9_])", source) is None:
            errors.append(f"{rid}: defect {c['symbol']} is not in {where}")
    return errors


def short(name, limit=88):
    return name if len(name) <= limit else name[: limit - 1] + "…"


def render(doc, catalog, owners):
    rows = sorted(doc["rows"], key=lambda r: r["id"])
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    runs = {(r["script"], r["name"]): r for r in doc.get("mutation_runs", [])}
    out = []
    w = out.append
    w("| Status | Count |")
    w("|---|---|")
    for s in STATUSES:
        w(f"| {STATUS_TEXT[s]} | {counts[s]} |")
    w(f"| P0 tests of the catalog | {len(rows)} |")
    w("")
    w("### The matrix")
    w("")
    w("| Test | Title | Owner (work package, crate) | Tests in the repository | Control-off variant | Status |")
    w("|---|---|---|---|---|---|")
    for r in rows:
        o = owners[r["id"]]
        scope = " (partial)" if o.get("scope") == "partial" else ""
        tests = r.get("tests", [])
        shown = [f"`{short(t['name'])}`" + (" [Docker]" if "docker" in t.get("needs", []) else "") + (" [live provider]" if "live_provider" in t.get("needs", []) else "") for t in tests[:3]]
        if len(tests) > 3:
            shown.append(f"and {len(tests) - 3} more")
        control = []
        for c in r.get("control_off", [])[:3]:
            label = c.get("name") or c.get("symbol")
            ran = ""
            if c["kind"] == "mutation":
                run = runs.get((c["script"], c["name"]))
                ran = f", {run['result'].lower()} {run['date']}" if run else ", not run in this review"
            control.append(f"{c['kind'].replace('_', ' ')} `{short(label, 60)}`{ran}")
        extra = len(r.get("control_off", [])) - 3
        if extra > 0:
            control.append(f"and {extra} more")
        status = STATUS_TEXT[r["status"]]
        if r["status"] == "blocked":
            status += f" ({r['blocked']['kind'].replace('_', ' ')})"
        title = catalog[r["id"]]["title"].replace("|", "/")
        w(f"| {r['id']} | {title} | {o['wp']}, {o['crate']}{scope} | {'<br>'.join(shown) or 'none'} | {'<br>'.join(control) or 'none'} | {status} |")
    w("")
    sections = (
        ("blocked", "### BLOCKED", "Each of these needs something this machine does not have. A test in this list has not passed here and is not counted as a pass."),
        ("missing", "### Missing", "Each of these P0 tests has no test of the catalog name in the repository."),
        ("control_off_missing", "### Implemented, control-off missing", "Each of these tests exists and runs, and nothing in the repository shows that it fails when its control is removed."),
    )
    for status, heading, intro in sections:
        picked = [r for r in rows if r["status"] == status]
        w(heading)
        w("")
        if not picked:
            w("None.")
            w("")
            continue
        w(intro)
        w("")
        for r in picked:
            reason = ""
            if status == "blocked":
                reason = f" {r['blocked']['reason']}"
            w(f"- **{r['id']}**{reason}{(' ' + r['note']) if r.get('note') else ''}")
        w("")
    parts = [(r["id"], p) for r in rows for p in r.get("parts_blocked", [])]
    w("### Parts that are BLOCKED inside a row")
    w("")
    if parts:
        w("A row can be proven for the parts that run and still hold a part that cannot run yet. The part is stated here and never counted as a pass.")
        w("")
        for rid, p in parts:
            w(f"- **{rid}**, part {p['part']} ({p['kind'].replace('_', ' ')}): {p['reason']}")
    else:
        w("None.")
    w("")
    notes = [r for r in rows if r.get("note") and r["status"] not in ("blocked", "missing", "control_off_missing")]
    if notes:
        w("### Notes on rows")
        w("")
        for r in notes:
            w(f"- **{r['id']}**: {r['note']}")
        w("")

    w("### Open findings that a P0 test reports")
    w("")
    if doc.get("findings"):
        w("A finding is a defect that a P0 test found. The test is red until the defect is fixed, and it is not weakened. Each has an owner and the smallest fix.")
        w("")
        for f in doc["findings"]:
            rows_with = ", ".join(r["id"] for r in rows if f["id"] in r.get("findings", []))
            w(f"- **{f['id']}** ({f['severity']}, owner {f['owner']}, reported by {rows_with}): {f['title']} {f['detail']} Smallest fix: {f['smallest_fix']}")
    else:
        w("None.")
    w("")
    w("### Audit event types and their owners (NT-AUD-03)")
    w("")
    w("The policy requires fourteen types of audit event (`audit.must_record`). The scripted scenario of `negative_nt_aud_03` makes each of them appear with an actor, the policy hash and the correlation id of its job. This table says who owns each type and whether production code writes it. The checker compares the table with the sources, so a type that gains an emitter, or loses one, fails the check until the table says so.")
    w("")
    w("| Type | Owner | Written in production code | Where |")
    w("|---|---|---|---|")
    meaning = {
        "engine": "yes, by the engine",
        "handler": "yes, by a stage handler",
        "api": "yes, by the API under the required name",
        "differently_named": "under other names",
        "other_stream": "in another stream",
        "none": "no",
    }
    for e in doc["audit_events"]:
        where = e["source"] and f"`{e['source']}`" or "none"
        w(f"| `{e['type']}` | {e['owner']} | {meaning[e['production']]} | {where}. {e['note']} |")
    w("")
    w("### Control-off variants that were run for this review")
    w("")
    if runs:
        w("| Script | Variant | Date | Result | Tests that failed |")
        w("|---|---|---|---|---|")
        for run in doc["mutation_runs"]:
            failed = ", ".join(f"`{short(n, 70)}`" for n in run["failed"]) or "none"
            w(f"| `{run['script']}` | `{run['name']}` | {run['date']} | {run['result']} | {failed} |")
    else:
        w("None were run.")
    w("")
    return "\n".join(out)


BEGIN = "<!-- GENERATED:begin matrix -->"
END = "<!-- GENERATED:end matrix -->"


def apply(text, body):
    pattern = re.compile("(" + re.escape(BEGIN) + r")(.*?)(" + re.escape(END) + ")", re.DOTALL)
    if not pattern.search(text):
        return None
    return pattern.sub(lambda m: m.group(1) + "\n" + body + "\n" + m.group(3), text)


def self_test(doc):
    """Breaks the data on purpose, in memory, and shows that validate() catches each break.

    A checker that cannot fail proves nothing. Each case changes one thing, runs the same
    validation as --check, and needs an error that says what was broken. The data itself must be
    valid first."""
    import copy

    errors, _, _ = validate(doc)
    if errors:
        return [f"the data is not valid, so the breaks prove nothing: {errors[:3]}"]
    row = next(r for r in doc["rows"] if r["status"] == "proven" and r["control_off"])

    def remove_a_row(d):
        d["rows"] = [r for r in d["rows"] if r["id"] != "NT-SBX-01"]

    def a_test_that_does_not_exist(d):
        next(r for r in d["rows"] if r["id"] == row["id"])["tests"][0]["name"] = row["tests"][0]["name"] + "_that_is_not_there"

    def a_file_that_does_not_exist(d):
        next(r for r in d["rows"] if r["id"] == row["id"])["tests"][0]["file"] = "crates/nothing/tests/nothing.rs"

    def control_off_without_a_mutation(d):
        target = next(r for r in d["rows"] if r["id"] == row["id"])
        target["control_off"][0] = dict(target["control_off"][0], name="a break that no script defines")

    def proven_without_a_variant(d):
        next(r for r in d["rows"] if r["id"] == row["id"])["control_off"] = []

    def a_control_off_for_a_test_of_another_row(d):
        target = next(r for r in d["rows"] if r["id"] == row["id"])
        target["control_off"][0] = dict(target["control_off"][0], catches=["negative_nt_not_a_test_of_this_row"])

    def blocked_without_a_reason(d):
        next(r for r in d["rows"] if r["status"] == "blocked")["blocked"] = {"kind": "docker", "reason": " "}

    def drop_an_audit_event_type(d):
        d["audit_events"] = d["audit_events"][:-1]

    def an_owner_that_is_not_a_work_package(d):
        d["audit_events"][0]["owner"] = "s9-nobody"

    def an_emitter_that_the_sources_do_not_hold(d):
        d["audit_events"][1]["token"] = "AuditKind::ThisDoesNotExist"

    cases = [
        ("remove a P0 row", remove_a_row, "has no row"),
        ("point a row at a test that does not exist", a_test_that_does_not_exist, "is not defined in"),
        ("point a row at a file that does not exist", a_file_that_does_not_exist, "does not exist"),
        ("claim control-off with a mutation that is not defined", control_off_without_a_mutation, "is not defined in"),
        ("claim control-off with no variant", proven_without_a_variant, "no control-off variant"),
        ("claim control-off for a test that is not in the row", a_control_off_for_a_test_of_another_row, "not a test of this row"),
        ("block a row with no reason", blocked_without_a_reason, "needs blocked"),
        ("drop an audit event type", drop_an_audit_event_type, "differ from audit.must_record"),
        ("give an audit event type an owner that is not a work package", an_owner_that_is_not_a_work_package, "is not a work package"),
        ("name an emitter that the sources do not hold", an_emitter_that_the_sources_do_not_hold, "does not contain"),
    ]
    problems = []
    for label, change, expected in cases:
        broken = copy.deepcopy(doc)
        change(broken)
        found, _, _ = validate(broken)
        if not any(expected in e for e in found):
            problems.append(f"self-test: '{label}' was not caught (wanted an error with '{expected}', got {found[:2]})")
    return problems


def main():
    mode = "--check" if len(sys.argv) < 2 else sys.argv[1]
    if mode not in ("--check", "--write", "--summary", "--self-test"):
        fail([f"unknown mode {mode}"])
    doc = json.loads(DATA.read_text(encoding="utf-8"))
    errors, catalog, owners = validate(doc)
    if errors:
        fail(errors)
    if mode in ("--check", "--self-test"):
        problems = self_test(doc)
        if problems:
            fail(problems)
        if mode == "--self-test":
            print("self-test: every deliberate break was caught")
            return
    rows = doc["rows"]
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    if mode == "--summary":
        print(f"P0 tests: {len(rows)}")
        for s in STATUSES:
            print(f"  {STATUS_TEXT[s]}: {counts[s]}")
        return
    text = TARGET.read_text(encoding="utf-8")
    new_text = apply(text, render(doc, catalog, owners))
    if new_text is None:
        fail([f"{TARGET.relative_to(ROOT)} has no GENERATED markers for the matrix"])
    if mode == "--write":
        TARGET.write_text(new_text, encoding="utf-8")
        print(f"wrote {TARGET.relative_to(ROOT)}")
        return
    if new_text != text:
        fail([f"{TARGET.relative_to(ROOT)} is out of date; run with --write"])
    print(f"p0-coverage.json valid; document in sync; {len(rows)} P0 tests; " + ", ".join(f"{counts[s]} {STATUS_TEXT[s]}" for s in STATUSES))


if __name__ == "__main__":
    main()
