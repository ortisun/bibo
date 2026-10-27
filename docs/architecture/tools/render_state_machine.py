#!/usr/bin/env python3
"""Validate docs/architecture/state-machine.json and render its tables into state-machine.md.

Usage (from the repository root):
    python3 -I docs/architecture/tools/render_state_machine.py --check   # validate, fail on doc drift
    python3 -I docs/architecture/tools/render_state_machine.py --write   # validate and rewrite the doc

Only the standard library is used. Sections of state-machine.md between
<!-- GENERATED:begin NAME --> and <!-- GENERATED:end NAME --> are owned by this script.
"""
import json
import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "docs/architecture/state-machine.json"
TARGET = ROOT / "docs/architecture/state-machine.md"


def fail(errors) -> NoReturn:
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    sys.exit(1)


def validate(doc):
    errors = []
    guards = doc["guards"]
    actors = doc["actors"]
    used_guards = set()
    for mname, m in doc["machines"].items():
        states = m["states"]
        if m["initial"] not in states:
            errors.append(f"{mname}: initial state {m['initial']} is not declared")
        seen = {}
        ids = set()
        outgoing = {s: 0 for s in states}
        reachable = {m["initial"]}
        for t in m["transitions"]:
            tid = t["id"]
            if tid in ids:
                errors.append(f"{mname}: duplicate transition id {tid}")
            ids.add(tid)
            if t["guard"] not in guards:
                errors.append(f"{mname}/{tid}: unknown guard {t['guard']}")
            used_guards.add(t["guard"])
            for a in t["actors"]:
                if a not in actors:
                    errors.append(f"{mname}/{tid}: unknown actor {a}")
            if t["to"] not in states:
                errors.append(f"{mname}/{tid}: unknown target state {t['to']}")
            for f in t["from"]:
                if f not in states:
                    errors.append(f"{mname}/{tid}: unknown source state {f}")
                    continue
                key = (f, t["event"])
                if key in seen:
                    errors.append(f"{mname}/{tid}: ({f}, {t['event']}) already used by {seen[key]}; transitions must be deterministic")
                seen[key] = tid
                outgoing[f] += 1
                if states[f].get("terminal") and not (states[f].get("supersedable") and t["event"] == "supersede"):
                    errors.append(f"{mname}/{tid}: terminal state {f} must not have outgoing transitions")
        changed = True
        while changed:
            changed = False
            for t in m["transitions"]:
                if any(f in reachable for f in t["from"]) and t["to"] not in reachable:
                    reachable.add(t["to"])
                    changed = True
        for s, meta in states.items():
            if s not in reachable:
                errors.append(f"{mname}: state {s} is unreachable from {m['initial']}")
            if not meta.get("terminal") and outgoing[s] == 0:
                errors.append(f"{mname}: non-terminal state {s} has no outgoing transition (dead end)")
    unused = set(guards) - used_guards
    if unused:
        errors.append(f"guards defined but never used: {sorted(unused)}")
    kinds = [s["kind"] for s in doc["pipeline"]["stages"]]
    if len(kinds) != len(set(kinds)):
        errors.append("pipeline: duplicate stage kind")
    position = {k: i for i, k in enumerate(kinds)}
    for s in doc["pipeline"]["stages"]:
        for r in s["requires"]:
            if r not in position:
                errors.append(f"pipeline: {s['kind']} requires unknown stage {r}")
            elif position[r] >= position[s["kind"]]:
                errors.append(f"pipeline: {s['kind']} requires {r}, which is not earlier in the order")
    for r in doc["pipeline"]["rework_routes"]:
        for k in (r["from_stage"], r["target_stage"]):
            if k not in position:
                errors.append(f"rework route references unknown stage {k}")
    for rule in doc["pipeline"]["invalidation_rules"]:
        for k in rule["supersedes"]:
            if k not in position:
                errors.append(f"invalidation rule references unknown stage {k}")
    # DOCUMENTING and DOCUMENTATION_REVIEW must sit after REVIEW and before DELIVERY and APPROVAL (INV-11).
    for a, b in (("REVIEW", "DOCUMENTING"), ("DOCUMENTING", "DOCUMENTATION_REVIEW"),
                 ("DOCUMENTATION_REVIEW", "DELIVERY"), ("DELIVERY", "APPROVAL")):
        if position[a] >= position[b]:
            errors.append(f"pipeline order: {a} must come before {b}")
    return errors


def cell(text):
    return str(text).replace("|", "\\|")


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def render_machine(name, m):
    states = table(["State", "Terminal", "Meaning"], [
        (f"`{s}`", "yes (can be superseded)" if v.get("supersedable") else ("yes" if v.get("terminal") else "no"), v["meaning"])
        for s, v in m["states"].items()])
    trans = table(["ID", "From", "Event", "Guard", "To", "May request", "Emits"], [
        (t["id"], ", ".join(f"`{f}`" for f in t["from"]), f"`{t['event']}`", f"`{t['guard']}`", f"`{t['to']}`",
         ", ".join(t["actors"]), f"`{t['emits']}`" if t["emits"] else "none")
        for t in m["transitions"]])
    lines = ["stateDiagram-v2", f"  [*] --> {m['initial']}"]
    for t in m["transitions"]:
        for f in t["from"]:
            lines.append(f"  {f} --> {t['to']}: {t['event']}")
    for s, v in m["states"].items():
        if v.get("terminal") and not v.get("supersedable"):
            lines.append(f"  {s} --> [*]")
    diagram = "```mermaid\n" + "\n".join(lines) + "\n```"
    key = name.replace("_", "-")
    return {f"{key}-states": states, f"{key}-transitions": trans, f"{key}-diagram": diagram}


def render(doc):
    sections = {}
    for name, m in doc["machines"].items():
        sections.update(render_machine(name, m))
    sections["actors"] = table(["Actor", "Meaning"], [(f"`{k}`", v) for k, v in doc["actors"].items()])
    sections["guards"] = table(["Guard", "Plain-English definition"], [(f"`{k}`", v) for k, v in doc["guards"].items()])
    sections["pipeline"] = table(["#", "Stage kind", "Requires", "Executor", "Gate (the GATING phase of this stage)", "Human gate", "Slice"], [
        (i + 1, f"`{s['kind']}`", ", ".join(f"`{r}`" for r in s["requires"]) or "none", s["executor"], s["gate"], s["human_gate"], s["slice"])
        for i, s in enumerate(doc["pipeline"]["stages"])])
    sections["rework-routes"] = table(["Failing stage", "Trigger", "New run of", "Note"], [
        (f"`{r['from_stage']}`", r["trigger"], f"`{r['target_stage']}`", r["note"] or "") for r in doc["pipeline"]["rework_routes"]])
    sections["invalidation"] = table(["When", "These runs become SUPERSEDED"], [
        (r["when"], ", ".join(f"`{k}`" for k in r["supersedes"])) for r in doc["pipeline"]["invalidation_rules"]])
    sections["assurance-levels"] = table(["Level", "Minimum evidence", "Slice", "Note"], [
        (f"`{l['level']}`", "; ".join(l["requires_evidence"]), l["slice"], l.get("note", "")) for l in doc["assurance_levels"]["levels"]])
    sections["release-states"] = ", ".join(f"`{v}`" for v in doc["assurance_levels"]["release_states"]["values"])
    sections["invariants"] = table(["ID", "Invariant", "Enforced by", "Verified by"], [
        (i["id"], i["statement"], "; ".join(i["enforced_by"]), "; ".join(i["verified_by"])) for i in doc["invariants"]])
    return sections


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
    counts = {n: len(m["transitions"]) for n, m in doc["machines"].items()}
    print(f"state-machine.json valid; doc in sync; transitions per machine: {counts}")


if __name__ == "__main__":
    main()
