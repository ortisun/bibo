#!/usr/bin/env python3
"""Validate docs/architecture/crate-dependency-rules.json and render it into overview.md.

Usage (from the repository root):
    python3 -I docs/architecture/tools/check_crate_rules.py --check   # validate, fail on doc drift
    python3 -I docs/architecture/tools/check_crate_rules.py --write   # validate and rewrite the doc

Only the standard library is used. Sections of overview.md between
<!-- GENERATED:begin NAME --> and <!-- GENERATED:end NAME --> are owned by this script.
"""
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "docs/architecture/crate-dependency-rules.json"
TARGET = ROOT / "docs/architecture/overview.md"


def fail(errors) -> NoReturn:
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    sys.exit(1)


def validate(doc):
    errors = []
    crates = {c["name"]: c for c in doc["crates"]}
    if len(crates) != len(doc["crates"]):
        errors.append("duplicate crate name")
    for c in doc["crates"]:
        n = c["name"]
        for dep in c["depends_on"]:
            if dep not in crates:
                errors.append(f"{n}: depends on unknown crate {dep}")
                continue
            d = crates[dep]
            if d["ring"] >= c["ring"] and not (n == "ports" and dep == "domain"):
                errors.append(f"{n} (ring {c['ring']}) must not depend on {dep} (ring {d['ring']}): dependencies point inward only")
        if "testkit" in c["depends_on"]:
            errors.append(f"{n}: testkit may only be a dev-dependency (DEP-03)")
        for dev in c["dev_depends_on"]:
            if dev != "testkit":
                errors.append(f"{n}: dev_depends_on may only name testkit, not {dev}")
            elif c["ring"] <= 1:
                errors.append(f"{n}: rings 0 and 1 must not use testkit, which depends on them")
            elif c["layer"] == "test-support":
                errors.append(f"{n}: testkit must not depend on itself")
    # cycle check on regular edges
    state = {}

    def visit(n, path):
        if state.get(n) == 1:
            errors.append("dependency cycle: " + " -> ".join(path + [n]))
            return
        if state.get(n) == 2:
            return
        state[n] = 1
        for d in crates[n]["depends_on"]:
            if d in crates:
                visit(d, path + [n])
        state[n] = 2

    for n in crates:
        visit(n, [])
    # the composition library (ADR 0015) is ring 3 and only binaries may depend on it (DEP-11)
    composition = [c["name"] for c in doc["crates"] if c["layer"] == "composition"]
    others = [c for c in doc["crates"] if c["layer"] != "composition"]
    for c in doc["crates"]:
        if c["layer"] == "composition":
            if c["ring"] <= max(o["ring"] for o in others):
                errors.append(f"{c['name']}: the composition library must sit in a ring above every other library")
            if c["dev_depends_on"] not in ([], ["testkit"]):
                errors.append(f"{c['name']}: dev_depends_on may only name testkit")
        for dep in c["depends_on"] + c["dev_depends_on"]:
            if dep in composition:
                errors.append(f"{c['name']} depends on the composition library {dep}; only binaries may (DEP-11)")
    # adapters and application crates must not depend on each other
    for c in doc["crates"]:
        for dep in c["depends_on"]:
            if dep in crates and crates[dep]["ring"] == 2 and c["ring"] == 2:
                errors.append(f"{c['name']} depends on peer {dep}")
    ids = [r["id"] for r in doc["rules"]]
    if len(ids) != len(set(ids)):
        errors.append("duplicate rule id")
    return errors


def cell(text):
    return str(text).replace("|", "\\|")


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def render(doc):
    crates = doc["crates"]
    by_layer = {}
    for c in crates:
        by_layer.setdefault(c["layer"], []).append(c["name"])
    lines = ["flowchart TB",
             "  classDef inner fill:#e8f1fb,stroke:#2b5d9b,color:#10294a;",
             "  classDef app fill:#eef7ea,stroke:#3b7a2a,color:#173410;",
             "  classDef adapter fill:#fdf1e3,stroke:#a35a00,color:#3d2200;",
             "  classDef test fill:#f3f3f3,stroke:#777,color:#222,stroke-dasharray: 4 3;",
             "  classDef root fill:#f5e9f7,stroke:#7a2a8a,color:#2d0f33;",
             "  subgraph roots[\"Ring 3: composition roots\"]",
             "    apps[\"binaries: " + ", ".join(a["name"] for a in doc["apps"]) + "\"]"]
    for n in by_layer.get("composition", []):
        lines.append(f"    {n}[\"{n} (library)\"]")
    lines += ["  end",
             "  subgraph application[\"Ring 2: application\"]"]
    for n in by_layer.get("application", []):
        lines.append(f"    {n}")
    lines += ["  end", "  subgraph adapters[\"Ring 2: adapters\"]"]
    for n in by_layer.get("adapter", []):
        lines.append(f"    {n}")
    lines += ["  end",
              "  subgraph inner[\"Rings 0 and 1: pure core\"]",
              "    ports",
              "    domain",
              "  end",
              "  testkit[\"testkit (dev-dependency only)\"]"]
    lines += ["  apps --> application", "  apps --> adapters"]
    for n in by_layer.get("composition", []):
        lines += [f"  apps --> {n}", f"  {n} --> application", f"  {n} --> adapters", f"  {n} --> ports"]
    for c in crates:
        if c["layer"] in ("application", "adapter"):
            for d in c["depends_on"]:
                lines.append(f"  {c['name']} --> {d}")
        if c["name"] == "ports":
            lines.append("  ports --> domain")
    for c in crates:
        if c["layer"] == "test-support":
            for d in c["depends_on"]:
                lines.append(f"  testkit --> {d}")
    for c in crates:
        if "testkit" in c["dev_depends_on"]:
            lines.append(f"  {c['name']} -. dev only .-> testkit")
    for n in by_layer.get("domain", []) + by_layer.get("ports", []):
        lines.append(f"  class {n} inner;")
    for n in by_layer.get("application", []):
        lines.append(f"  class {n} app;")
    for n in by_layer.get("adapter", []):
        lines.append(f"  class {n} adapter;")
    lines.append("  class testkit test;")
    lines.append("  class apps root;")
    for n in by_layer.get("composition", []):
        lines.append(f"  class {n} root;")
    graph = "```mermaid\n" + "\n".join(lines) + "\n```"

    rows = []
    for c in crates:
        deps = ", ".join(c["depends_on"]) or "none"
        dev = ", ".join(c["dev_depends_on"]) or "none"
        rows.append((f"`{c['name']}`", f"`{doc['package_prefix']}{c['name']}`", c["ring"], c["layer"], deps, dev, c["slice"], c["responsibility"]))
    for a in doc["apps"]:
        rows.append((f"`{a['name']}`", f"`{doc['package_prefix']}{a['name']}`", 3, "binary", "all library crates it wires", "none", a["slice"], a["responsibility"]))
    crate_table = table(["Crate", "Package", "Ring", "Layer", "May depend on", "Dev only", "Slice", "Responsibility"], rows)

    deferred = table(["Not created yet", "Planned slice", "Lives in meanwhile", "Extract when", "Why it is not needed now"], [
        (f"`{d['name']}`" if "," not in d["name"] else d["name"], d["slice"], d["interim_home"], d["extract_when"], d["why_deferred"]) for d in doc["deferred"]])
    rules = table(["Rule", "Statement", "Enforced by"], [(r["id"], r["statement"], r["enforced_by"]) for r in doc["rules"]])
    rings = table(["Ring", "Name", "Rule"], [(r["ring"], r["name"], r["rule"]) for r in doc["rings"]])
    return {"crate-graph": graph, "crate-table": crate_table, "deferred-crates": deferred, "dependency-rules": rules, "rings": rings}


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
    if mode not in ("--check", "--write"):
        fail([f"unknown mode {mode}"])
    doc = json.loads(SOURCE.read_text())
    errors = validate(doc)
    if errors:
        fail(errors)
    text = TARGET.read_text()
    new_text, missing = apply(text, render(doc))
    if missing:
        fail([f"marker pair not found in {TARGET.name}: {m}" for m in missing])
    if mode == "--write":
        TARGET.write_text(new_text)
        print(f"wrote {TARGET.relative_to(ROOT)}")
        return
    if new_text != text:
        fail([f"{TARGET.relative_to(ROOT)} is out of date; run with --write"])
    print(f"crate-dependency-rules.json valid; doc in sync; {len(doc['crates'])} library crates, {len(doc['apps'])} binaries, {len(doc['deferred'])} deferred entries")


if __name__ == "__main__":
    main()
