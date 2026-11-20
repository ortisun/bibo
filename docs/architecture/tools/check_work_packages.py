#!/usr/bin/env python3
"""Validate docs/architecture/work-packages.json and render it into slice-plan.md.

Usage (from the repository root):
    python3 -I docs/architecture/tools/check_work_packages.py --check   # validate, fail on doc drift
    python3 -I docs/architecture/tools/check_work_packages.py --write   # validate and rewrite the doc
    python3 -I docs/architecture/tools/check_work_packages.py --summary # print waves and the critical path

Only the standard library is used. Sections of slice-plan.md between
<!-- GENERATED:begin NAME --> and <!-- GENERATED:end NAME --> are owned by this script.

Ownership rule checked here: two work packages whose owned paths overlap must be ordered by
dependency, so no two packages that can run at the same time own the same file.
"""
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "docs/architecture/work-packages.json"
TARGET = ROOT / "docs/architecture/slice-plan.md"


def fail(errors) -> NoReturn:
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    sys.exit(1)


def norm(path):
    return path[:-3] if path.endswith("/**") else path


def overlaps(a, b):
    a, b = norm(a), norm(b)
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


CATALOG = ROOT / "docs/security/negative-test-catalog.md"


def read_catalog():
    """Parse the security specialist's catalog (read only). Returns {id: {title, level, owners, priority}}."""
    rows = {}
    for line in CATALOG.read_text().splitlines():
        if not re.match(r"^\| *(NT|ST)-", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        first = cells[0]
        if first.startswith("NT-"):
            tid, _, title = first.partition(" ")
            last = cells[-1]
            pm = re.search(r"\bP([0-3])\b", last)
            rows[tid] = {"title": title.strip(), "level": last.split(",")[0].strip(), "owners": " ".join(re.findall(r"`([a-z_]+)`", last)) or last,
                         "priority": ("P" + pm.group(1)) if pm else None}
        else:
            rows[first] = {"title": cells[1][:90] if len(cells) > 1 else "", "level": "static", "owners": "CI", "priority": "static"}
    return rows


def mentioned_tests(wp):
    text = " ".join(c["check"] + " " + (c["command"] or "") for c in wp["done"])
    ids = set(re.findall(r"\bNT-[A-Z]+-\d{2}\b", text))
    for a, n in re.findall(r"nt_([a-z]+)_(\d{2})", text):
        ids.add(f"NT-{a.upper()}-{n}")
    for n in re.findall(r"\bst_(\d{2})\b", text):
        ids.add(f"ST-{n}")
    for n in re.findall(r"\bST-(\d{2})\b", text):
        ids.add(f"ST-{n}")
    return ids


def validate_negative(doc, wps):
    errors = []
    nt = doc["negative_tests"]
    if not CATALOG.exists():
        return [f"{CATALOG} not found"]
    cat = read_catalog()
    p0 = {k for k, v in cat.items() if v["priority"] == "P0"}
    mapped = {e["id"]: e for e in nt["entries"]}
    if len(mapped) != len(nt["entries"]):
        errors.append("negative_tests: duplicate entry id")
    for k in sorted(p0 - set(mapped)):
        errors.append(f"P0 test {k} has no owner in negative_tests.entries (list it, or add it to gaps with a reason)")
    for k in sorted(set(mapped) - set(cat)):
        errors.append(f"negative_tests lists {k}, which is not in the catalog")
    crates = {c["name"] for c in json.loads((ROOT / "docs/architecture/crate-dependency-rules.json").read_text())["crates"]}
    apps = {a["name"] for a in json.loads((ROOT / "docs/architecture/crate-dependency-rules.json").read_text())["apps"]}
    for e in nt["entries"] + nt["static_checks"]:
        if e["wp"] not in wps:
            errors.append(f"{e['id']}: unknown work package {e['wp']}")
            continue
        if e["crate"] not in crates | apps | {"xtask", "ci"}:
            errors.append(f"{e['id']}: crate {e['crate']} does not exist in the layout")
        owned = wps[e["wp"]]["owns"]
        if not any(norm(e["location"]) == norm(o) or norm(e["location"]).startswith(norm(o) + "/") for o in owned):
            errors.append(f"{e['id']}: location {e['location']} is not inside the paths owned by {e['wp']}")
        crate_dir = {"xtask": "xtask", "ci": ".github"}.get(e["crate"]) or (f"crates/{e['crate']}" if e["crate"] in crates else f"apps/{e['crate']}")
        if not e["location"].startswith(crate_dir):
            errors.append(f"{e['id']}: location {e['location']} is not inside crate {e['crate']} ({crate_dir})")
        for a in e.get("also", []):
            if a not in wps:
                errors.append(f"{e['id']}: unknown also work package {a}")
        if e.get("scope") == "partial" and not e.get("reduced_scope_reason"):
            errors.append(f"{e['id']}: a partial entry needs reduced_scope_reason")
        if e.get("blocked_part") and e.get("scope") != "full":
            errors.append(f"{e['id']}: a part that is blocked until a spike has run belongs to an entry with full scope")
    for k in [x["id"] for x in nt["static_checks"]]:
        if k not in cat:
            errors.append(f"static check {k} is not in the catalog")
    for k in sorted({x for x in cat if x.startswith("ST-")} - {x["id"] for x in nt["static_checks"]}):
        errors.append(f"static check {k} has no owner")
    allowed = {e["id"]: {e["wp"], *e.get("also", [])} for e in nt["entries"] + nt["static_checks"]}
    for i, w in wps.items():
        for t in mentioned_tests(w):
            if t not in allowed:
                errors.append(f"{i} mentions {t}, which has no entry in negative_tests")
            elif i not in allowed[t]:
                errors.append(f"{i} mentions {t}, but the entry assigns it to {sorted(allowed[t])}")
    for g in nt["gaps"]:
        for t in re.findall(r"NT-[A-Z]+-\d{2}", g["test"]):
            if t not in mapped:
                errors.append(f"gap names {t}, which is not mapped")
            elif mapped[t].get("scope") != "partial":
                errors.append(f"gap names {t}, whose entry is not marked partial")
    for e in nt["entries"]:
        if e.get("scope") == "partial" and not any(e["id"] in g["test"] for g in nt["gaps"]):
            errors.append(f"{e['id']} is partial but no gap explains what is uncovered")
    return errors


def closure(wps):
    ancestors = {}

    def visit(i):
        if i in ancestors:
            return ancestors[i]
        ancestors[i] = set()
        for d in wps[i]["depends_on"]:
            if d in wps:
                ancestors[i] |= {d} | visit(d)
        return ancestors[i]

    for i in wps:
        visit(i)
    return ancestors


def analyze(doc):
    wps = {w["id"]: w for w in doc["work_packages"]}
    weights = doc["size_weights"]
    waves, finish, best = {}, {}, {}

    def wave(i):
        if i not in waves:
            waves[i] = 0 if not wps[i]["depends_on"] else 1 + max(wave(d) for d in wps[i]["depends_on"])
        return waves[i]

    def fin(i):
        if i not in finish:
            prev = max((fin(d) for d in wps[i]["depends_on"]), default=0)
            finish[i] = prev + weights[wps[i]["size"]]
            best[i] = max(wps[i]["depends_on"], key=lambda d: finish[d], default=None) if wps[i]["depends_on"] else None
        return finish[i]

    for i in wps:
        wave(i)
        fin(i)
    end = max(finish, key=lambda i: finish[i])
    path = []
    cur = end
    while cur is not None:
        path.append(cur)
        cur = best[cur]
    path.reverse()
    total = finish[end]
    successors = {i: [] for i in wps}
    for i, w in wps.items():
        for d in w["depends_on"]:
            successors[d].append(i)
    latest = {}

    def lf(i):
        if i not in latest:
            latest[i] = min((lf(s) - weights[wps[s]["size"]] for s in successors[i]), default=total)
        return latest[i]

    slack = {i: lf(i) - finish[i] for i in wps}
    return waves, finish, path, slack


def validate(doc):
    errors = []
    roles = set(doc["roles"])
    wps = {}
    for w in doc["work_packages"]:
        if w["id"] in wps:
            errors.append(f"duplicate work package id {w['id']}")
        wps[w["id"]] = w
    if errors:
        return errors, None
    title_bad = [re.compile(r"\|"), re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+\s*[:|]"), re.compile(r"^\[[^\]]+\]"), re.compile(r"\[[A-Z_]+:[^\]]*\]")]
    for i, w in wps.items():
        if not re.fullmatch(r"s[01]-[a-z0-9-]+", i):
            errors.append(f"{i}: id must look like s0-name or s1-name")
        if w["slice"] != int(i[1]):
            errors.append(f"{i}: slice {w['slice']} does not match the id prefix")
        if w["owner_role"] not in roles:
            errors.append(f"{i}: unknown owner role {w['owner_role']}")
        if w["size"] not in doc["size_weights"]:
            errors.append(f"{i}: unknown size {w['size']}")
        t = w["title"]
        if not (3 <= len(t) <= 100) or any(p.search(t) for p in title_bad) or not t[0].isupper():
            errors.append(f"{i}: title is not plain sentence-case English: {t!r}")
        if t.endswith("."):
            errors.append(f"{i}: title should not end with a period")
        if len(w["summary"]) < 40:
            errors.append(f"{i}: summary is too short to be useful")
        for d in w["depends_on"]:
            if d not in wps:
                errors.append(f"{i}: unknown dependency {d}")
            elif w["slice"] == 0 and wps[d]["slice"] == 1:
                errors.append(f"{i}: a Slice 0 package must not depend on Slice 1 package {d}")
        if not w["owns"]:
            errors.append(f"{i}: owns no path")
        if not any(c["kind"] in ("command", "test") for c in w["done"]):
            errors.append(f"{i}: needs at least one done criterion that a command or a test can check")
        for n, c in enumerate(w["done"], 1):
            if c["kind"] not in ("command", "test", "review"):
                errors.append(f"{i} done #{n}: unknown kind {c['kind']}")
            if c["kind"] in ("command", "test") and not c["command"]:
                errors.append(f"{i} done #{n}: a {c['kind']} criterion needs a command")
            if c["kind"] == "review" and c["command"]:
                errors.append(f"{i} done #{n}: a review criterion must not have a command")
            if len(c["check"]) < 20:
                errors.append(f"{i} done #{n}: criterion text is too short")
    if errors:
        return errors, None
    # cycles
    state = {}

    def visit(n, path):
        if state.get(n) == 1:
            errors.append("dependency cycle: " + " -> ".join(path + [n]))
            return
        if state.get(n) == 2:
            return
        state[n] = 1
        for d in wps[n]["depends_on"]:
            visit(d, path + [n])
        state[n] = 2

    for n in wps:
        visit(n, [])
    if errors:
        return errors, None
    # ownership
    anc = closure(wps)
    ids = list(wps)
    for x in range(len(ids)):
        for y in range(x + 1, len(ids)):
            a, b = ids[x], ids[y]
            for pa in wps[a]["owns"]:
                for pb in wps[b]["owns"]:
                    if overlaps(pa, pb) and not (a in anc[b] or b in anc[a]):
                        errors.append(f"concurrent ownership overlap: {a} owns {pa} and {b} owns {pb}, and neither depends on the other")
    for i, w in wps.items():
        for p in w["owns"]:
            for ext in doc["external_owners"]:
                if overlaps(p, ext["path"]):
                    errors.append(f"{i} owns {p}, which overlaps {ext['path']} owned by {ext['owner']}")
    # ports
    ports = {p["name"]: p for p in doc["ports"]}
    for name, p in ports.items():
        if p["defined_by"] not in wps:
            errors.append(f"port {name}: defined_by {p['defined_by']} is not a work package")
        for who in p["consumers"] + p["implemented_by"]:
            if who not in wps:
                errors.append(f"port {name}: {who} is not a work package")
        if not p["implemented_by"]:
            errors.append(f"port {name} has no real implementation planned")
        consumers = {i for i, w in wps.items() if name in w["consumes_ports"]}
        implementers = {i for i, w in wps.items() if name in w["implements_ports"]}
        if consumers != set(p["consumers"]):
            errors.append(f"port {name}: consumers {sorted(p['consumers'])} differ from packages that list it {sorted(consumers)}")
        if implementers != set(p["implemented_by"]):
            errors.append(f"port {name}: implemented_by {sorted(p['implemented_by'])} differs from packages that list it {sorted(implementers)}")
        definers = {i for i, w in wps.items() if name in w["exposes_ports"]}
        if definers != {p["defined_by"]}:
            errors.append(f"port {name}: exposed by {sorted(definers)}, expected only {p['defined_by']}")
    for i, w in wps.items():
        for key in ("consumes_ports", "implements_ports", "exposes_ports"):
            for name in w[key]:
                if name not in ports:
                    errors.append(f"{i} {key} references unknown port {name}")
    errors += validate_negative(doc, wps)
    if errors:
        return errors, None
    return [], analyze(doc)


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def code(s):
    return f"`{s}`"


def render(doc, analysis):
    waves, finish, path, slack = analysis
    wps = {w["id"]: w for w in doc["work_packages"]}
    crit = {i for i, v in slack.items() if v == 0}
    weights = doc["size_weights"]
    order = [w["id"] for w in doc["work_packages"]]
    sections = {}

    sections["wp-summary"] = table(["Work package", "Id", "Slice", "Role", "Size", "Wave", "Depends on", "Critical path"], [
        (w["title"], code(w["id"]), w["slice"], w["owner_role"], w["size"], waves[w["id"]], ", ".join(code(d) for d in w["depends_on"]) or "none", "yes" if w["id"] in crit else "")
        for w in doc["work_packages"]])

    for s in (0, 1):
        blocks = []
        for w in doc["work_packages"]:
            if w["slice"] != s:
                continue
            i = w["id"]
            lines = [f"#### {w['title']}", "",
                     table(["Field", "Value"], [
                         ("Id", code(i)), ("Owner role", w["owner_role"]), ("Reviewers", ", ".join(w["reviewers"]) or "none"),
                         ("Size", f"{w['size']} (relative weight {weights[w['size']]})"), ("Wave", waves[i]),
                         ("On the critical path", "yes" if i in crit else "no"),
                         ("Depends on", ", ".join(code(d) for d in w["depends_on"]) or "none")]), "",
                     w["summary"], "",
                     "Owns: " + ", ".join(code(p) for p in w["owns"]), "",
                     "Inputs: " + "; ".join(w["inputs"]), ""]
            if w["exposes_ports"] or w["implements_ports"] or w["consumes_ports"]:
                lines.append("Ports: defines " + (", ".join(code(p) for p in w["exposes_ports"]) or "none") + "; implements " + (", ".join(code(p) for p in w["implements_ports"]) or "none") + "; uses " + (", ".join(code(p) for p in w["consumes_ports"]) or "none") + ".")
                lines.append("")
            lines.append("Done when:")
            lines.append("")
            lines.append(table(["#", "Check", "How", "Command or evidence"], [
                (n, c["check"], c["kind"], code(c["command"]) if c["command"] else "reviewer sign-off recorded in the pull request") for n, c in enumerate(w["done"], 1)]))
            blocks.append("\n".join(lines))
        sections[f"wp-details-{s}"] = "\n\n".join(blocks)

    rows = []
    for w in doc["work_packages"]:
        for p in w["owns"]:
            rows.append((code(p), code(w["id"]), w["owner_role"], w["slice"]))
    for e in doc["external_owners"]:
        rows.append((code(e["path"]), e["owner"], "outside this plan", ""))
    rows.sort(key=lambda r: r[0])
    sections["ownership-map"] = table(["Path", "Owner", "Role", "Slice"], rows)

    nodes = {i: i.replace("-", "_") for i in order}
    lines = ["flowchart LR", "  classDef crit fill:#fde8e8,stroke:#b42318,color:#400;", "  classDef norm fill:#f3f6fb,stroke:#4a6fa5,color:#102a43;"]
    for s, name in ((0, "Slice 0: foundation"), (1, "Slice 1: end-to-end MVP")):
        lines.append(f"  subgraph slice{s}[\"{name}\"]")
        for i in order:
            if wps[i]["slice"] == s:
                lines.append(f"    {nodes[i]}[\"{i}\"]")
        lines.append("  end")
    for i in order:
        for d in wps[i]["depends_on"]:
            lines.append(f"  {nodes[d]} --> {nodes[i]}")
    for i in order:
        lines.append(f"  class {nodes[i]} {'crit' if i in crit else 'norm'};")
    sections["wp-graph"] = "```mermaid\n" + "\n".join(lines) + "\n```"

    total = finish[path[-1]]
    others = [i for i in order if slack[i] == 0 and i not in path]
    sections["critical-path"] = table(["Step", "Work package", "Size", "Cumulative weight"], [
        (n + 1, f"{wps[i]['title']} ({code(i)})", wps[i]["size"], finish[i]) for n, i in enumerate(path)]) + f"\n\nTotal relative weight along the longest chain: {total}." + (
        "\n\nOther packages with zero slack, because a second chain ties with the first. A delay in any of them delays the end: " + ", ".join(code(i) for i in others) + "." if others else "")
    sections["slack"] = table(["Work package", "Earliest finish", "Slack"], [(code(i), finish[i], slack[i]) for i in sorted(order, key=lambda x: (slack[x], finish[x]))])

    by_wave = {}
    for i in order:
        by_wave.setdefault(waves[i], []).append(i)
    sections["waves"] = table(["Wave", "Can start when the previous waves it needs are done", "Packages"], [
        (n, "nothing" if n == 0 else f"packages of wave {n - 1} or earlier", ", ".join(code(i) for i in ids)) for n, ids in sorted(by_wave.items())])

    sections["ports-registry"] = table(["Port", "Crate", "Defined by", "Fake", "Real implementation", "Built by", "Used by"], [
        (code(p["name"]), p["crate"], code(p["defined_by"]), p["fake"], p["real"], ", ".join(code(c) for c in p["implemented_by"]), ", ".join(code(c) for c in p["consumers"]) or "its own crate") for p in doc["ports"]])

    cat = read_catalog()
    nt = doc["negative_tests"]
    p0 = [k for k, v in cat.items() if v["priority"] == "P0"]
    p0_entries = [e for e in nt["entries"] if cat[e["id"]]["priority"] == "P0"]
    full = sum(1 for e in p0_entries if e.get("scope") == "full")
    part = sum(1 for e in p0_entries if e.get("scope") == "partial")
    blocked = sum(1 for e in p0_entries if e.get("blocked_part"))
    other = {pr: sum(1 for v in cat.values() if v["priority"] == pr) for pr in ("P1", "P2")}
    p1_mapped = sum(1 for e in nt["entries"] if cat[e["id"]]["priority"] == "P1")
    sections["negative-test-summary"] = (f"The catalog has {len(p0)} P0 tests. {len(p0_entries)} are mapped to a work package and a crate: {full} with full scope and {part} with reduced scope, listed under gaps. "
                                         f"{blocked} of the full ones have a part that stays BLOCKED until a spike has run. "
                                         f"{len(p0) - len({e['id'] for e in p0_entries})} have no owner. The catalog also has {other['P1']} P1 and {other['P2']} P2 tests, which it requires before Slice 2 and later ({p1_mapped} P1 mapped so far), and {len(nt['static_checks'])} static checks, all mapped.")
    sections["negative-test-map"] = table(["Test", "Title", "Catalog level", "Catalog owner", "Work package", "Crate", "Also", "Scope"], [
        (code(e["id"]), cat[e["id"]]["title"], cat[e["id"]]["level"], cat[e["id"]]["owners"], code(e["wp"]), code(e["crate"]), ", ".join(code(a) for a in e.get("also", [])) or "", e["scope"])
        for e in nt["entries"] if cat[e["id"]]["priority"] == "P0"])
    sections["static-check-map"] = table(["Check", "What it proves", "Work package", "Where"], [
        (code(e["id"]), cat[e["id"]]["title"], code(e["wp"]), code(e["location"])) for e in nt["static_checks"]])
    sections["negative-test-gaps"] = table(["Test", "Not covered in Slice 1", "Why", "Resolved in"], [
        (g["test"], g["uncovered"], g["reason"], g["resolves_in"]) for g in nt["gaps"]])
    sections["negative-test-blocked-parts"] = table(["Test", "Part that reports BLOCKED, with the reason"], [(code(e["id"]), e["blocked_part"]) for e in nt["entries"] if e.get("blocked_part")])
    return sections


def check_port_sketches(doc):
    """Every registered port must appear as `pub trait Name` in a rust code fence of slice-plan.md."""
    text = TARGET.read_text()
    fences = "\n".join(re.findall(r"```rust\n(.*?)```", text, re.S))
    traits = set(re.findall(r"pub trait (\w+)", fences))
    errors = []
    for p in doc["ports"]:
        if p["name"] not in traits:
            errors.append(f"port {p['name']} has no `pub trait {p['name']}` sketch in slice-plan.md")
    registered = {p["name"] for p in doc["ports"]}
    for t in sorted(traits - registered):
        if not (t.endswith("Ops") or t in ("StageHandler",)):
            errors.append(f"slice-plan.md sketches trait {t}, which is not in the ports registry (helper traits must end in Ops)")
    return errors


def apply(text, sections):
    missing = []
    for name, body in sections.items():
        pattern = re.compile(rf"(<!-- GENERATED:begin {re.escape(name)} -->)(.*?)(<!-- GENERATED:end {re.escape(name)} -->)", re.S)
        if not pattern.search(text):
            missing.append(name)
            continue
        text = pattern.sub(lambda m: m.group(1) + "\n" + body + "\n" + m.group(3), text)
    return text, missing


def main():
    mode = "--check" if len(sys.argv) < 2 else sys.argv[1]
    if mode not in ("--check", "--write", "--summary"):
        fail([f"unknown mode {mode}"])
    doc = json.loads(SOURCE.read_text())
    errors, analysis = validate(doc)
    if errors or analysis is None:
        fail(errors or ["analysis failed"])
    waves, finish, path, slack = analysis
    if mode == "--summary":
        print("waves:", {w: [i for i in waves if waves[i] == w] for w in sorted(set(waves.values()))})
        print("longest chain:", " -> ".join(path), f"(weight {finish[path[-1]]})")
        print("zero slack:", sorted(i for i in slack if slack[i] == 0))
        return
    text = TARGET.read_text()
    new_text, missing = apply(text, render(doc, analysis))
    if missing:
        fail([f"marker pair not found in {TARGET.name}: {m}" for m in missing])
    if mode == "--write":
        TARGET.write_text(new_text)
        errs = check_port_sketches(doc)
        if errs:
            fail(errs)
        print(f"wrote {TARGET.relative_to(ROOT)}")
        return
    errs = check_port_sketches(doc)
    if errs:
        fail(errs)
    if new_text != text:
        fail([f"{TARGET.relative_to(ROOT)} is out of date; run with --write"])
    n = len(doc["work_packages"])
    zero = sum(1 for v in slack.values() if v == 0)
    print(f"work-packages.json valid; doc in sync; {n} packages; longest chain weight {finish[path[-1]]}; {zero} packages with zero slack")


if __name__ == "__main__":
    main()
