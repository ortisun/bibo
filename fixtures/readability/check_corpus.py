#!/usr/bin/env python3
"""Validate the readability test corpus in fixtures/readability.

Usage (from the repository root):
    python3 -I fixtures/readability/check_corpus.py                    # structure, coverage, policy table
    python3 -I fixtures/readability/check_corpus.py --coverage         # same, and print the rule coverage table
    python3 -I fixtures/readability/check_corpus.py --prompt-examples  # same, and check the master prompt examples
    python3 -I fixtures/readability/check_corpus.py --self-test        # prove the validator rejects malformed input

Exit codes: 0 valid, 1 the corpus is invalid, 2 usage error, 3 BLOCKED because a required input
file could not be read (an unreadable master prompt is never reported as a pass).

Only the standard library is used. The script checks that the corpus is well formed and consistent.
It does not implement the readability rules. Those belong to the readability gate.
"""
import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, TypeGuard

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_POLICY = ROOT / "docs/reference/documentation-policy.md"
DEFAULT_PROMPT = ROOT / "universal_agentic_software_factory_master_prompt.md"

MIN_PASS_CASES = 8
MIN_BAD_CASES = 20
REQUIRED_DOMAINS = ["games", "trading", "ml-research", "native-apps", "web"]
REQUIRED_TAGS = ["hidden-id-chain", "unexpanded-acronym", "vague-title", "prompt-injection"]
DOC_TYPES = ["tutorial", "how-to", "reference", "explanation", "adr", "changelog"]
SOURCES = ["master-prompt", "authored"]
SEVERITIES = ["warn", "block"]
MODES = ["deterministic", "reviewer"]
VERDICTS = ["pass", "warn", "block"]
EXPECTED_PROMPT_BAD = 11
EXPECTED_PROMPT_GOOD = 10
RULE_PREFIXES = ("title-", "task-", "body-", "pr-", "doc-", "text-", "translation-")

SLUG = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$")
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,79}$")
REQUIRED_LISTS = [
    "acronym_allowlist", "not_abbreviation_words", "generic_verbs", "generic_nouns", "generic_articles",
    "placeholder_nouns", "status_subjects", "status_phrases", "conventional_commit_types",
    "role_stamp_prefixes", "metadata_line_keys", "filler_phrases", "required_task_sections",
    "deterministic_language_detection",
]
CASE_FIELDS = {"id", "kind", "domain", "source", "prompt_ref", "tags", "exercises", "breaks", "verdict",
               "reason", "suggested_fix", "input"}
CASE_REQUIRED = ["id", "kind", "domain", "source", "exercises", "breaks", "verdict", "reason", "input"]
EFFECTIVE_KINDS = {"translation": {"translation", "request"}, "identity_pair": {"identity_pair", "title"}}


# ---------------------------------------------------------------- loading

def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except FileNotFoundError:
        return None, [f"{path}: file not found"]
    except (OSError, UnicodeDecodeError) as e:
        return None, [f"{path}: cannot read: {e}"]
    except json.JSONDecodeError as e:
        return None, [f"{path}: invalid JSON: {e}"]


def is_str_list(v: Any, allow_empty: bool = True) -> TypeGuard[list[str]]:
    return bool(isinstance(v, list) and (allow_empty or v) and all(isinstance(x, str) and x for x in v))


# ---------------------------------------------------------------- rules.json

def validate_rules(doc):
    """Return (context, errors). The context holds the vocabulary the cases are checked against."""
    errs = []
    ctx = {"rules": {}, "invariants": set(), "kinds": [], "domains": [], "tags": []}
    if not isinstance(doc, dict):
        return ctx, ["rules.json: top level must be an object"]
    if doc.get("corpus_format") != 1:
        errs.append("rules.json: corpus_format must be 1")
    if doc.get("verdicts") != VERDICTS:
        errs.append(f"rules.json: verdicts must be exactly {VERDICTS}")
    for key in ("kinds", "domains", "tags"):
        v = doc.get(key)
        if not is_str_list(v, allow_empty=False) or len(set(v)) != len(v):
            errs.append(f"rules.json: {key} must be a non-empty list of unique strings")
        else:
            ctx[key] = v
    missing = [d for d in REQUIRED_DOMAINS if d not in ctx["domains"]]
    if missing:
        errs.append(f"rules.json: domains must include {missing}")
    inv = doc.get("invariants")
    if not isinstance(inv, list) or not inv:
        errs.append("rules.json: invariants must be a non-empty list")
    else:
        for i, item in enumerate(inv):
            if not (isinstance(item, dict) and set(item) == {"id", "summary"} and SLUG.match(str(item.get("id", "")))
                    and isinstance(item.get("summary"), str) and item["summary"]):
                errs.append(f"rules.json: invariants[{i}] needs exactly 'id' (a slug) and 'summary'")
            else:
                ctx["invariants"].add(item["id"])
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        errs.append("rules.json: rules must be a non-empty list")
        rules = []
    for i, r in enumerate(rules):
        where = f"rules.json: rules[{i}]"
        if not isinstance(r, dict):
            errs.append(f"{where}: must be an object")
            continue
        rid = r.get("id")
        where = f"rules.json: rule '{rid}'"
        allowed = {"id", "family", "severity", "mode", "applies_to", "summary", "definition", "pattern", "suggested_fix"}
        for k in sorted(set(r) - allowed):
            errs.append(f"{where}: unknown field '{k}'")
        for k in ("id", "family", "severity", "mode", "applies_to", "summary", "definition", "suggested_fix"):
            if k not in r:
                errs.append(f"{where}: missing field '{k}'")
        if not (isinstance(rid, str) and SLUG.match(rid)):
            errs.append(f"{where}: id must be a slug so it can be used as a gate check id")
            continue
        if rid in ctx["rules"]:
            errs.append(f"{where}: duplicate rule id")
        if r.get("severity") not in SEVERITIES:
            errs.append(f"{where}: severity must be one of {SEVERITIES}")
        if r.get("mode") not in MODES:
            errs.append(f"{where}: mode must be one of {MODES}")
        if r.get("mode") == "reviewer" and r.get("severity") != "warn":
            errs.append(f"{where}: reviewer rules must have severity warn, because a model judgement never blocks by itself")
        ap = r.get("applies_to")
        if not is_str_list(ap, allow_empty=False) or any(k not in ctx["kinds"] for k in ap):
            errs.append(f"{where}: applies_to must be a non-empty list of known kinds")
        for k in ("family", "summary", "definition", "suggested_fix"):
            if k in r and not (isinstance(r[k], str) and r[k].strip() and "\n" not in r[k]):
                errs.append(f"{where}: {k} must be a non-empty single-line string")
        if "pattern" in r:
            try:
                re.compile(r["pattern"])
            except (re.error, TypeError) as e:
                errs.append(f"{where}: pattern does not compile: {e}")
        ctx["rules"][rid] = r
    lists = doc.get("lists")
    if not isinstance(lists, dict):
        errs.append("rules.json: lists must be an object")
    else:
        for name in REQUIRED_LISTS:
            if not is_str_list(lists.get(name), allow_empty=False):
                errs.append(f"rules.json: lists.{name} must be a non-empty list of strings")
        gh = lists.get("guide_headings")
        if not (isinstance(gh, dict) and set(gh) == {"prerequisites", "expected_result", "troubleshooting"}
                and all(is_str_list(v, allow_empty=False) for v in gh.values())):
            errs.append("rules.json: lists.guide_headings needs prerequisites, expected_result and troubleshooting lists")
    return ctx, errs


# ---------------------------------------------------------------- cases

def expected_verdict(breaks, rules):
    if not breaks:
        return "pass"
    return "block" if any(rules[r]["severity"] == "block" for r in breaks) else "warn"


def one_line(v, lo, hi):
    return isinstance(v, str) and lo <= len(v) <= hi and "\n" not in v and "\r" not in v and v == v.strip()


def check_rule_list(value, ctx, where, field, kinds=None):
    errs = []
    if not is_str_list(value) or len(set(value)) != len(value):
        return [f"{where}: {field} must be a list of unique strings"]
    for r in value:
        if r not in ctx["rules"]:
            errs.append(f"{where}: {field} names unknown rule '{r}'")
        elif kinds is not None and not (set(ctx["rules"][r]["applies_to"]) & kinds):
            errs.append(f"{where}: rule '{r}' does not apply to kind '{sorted(kinds)[0] if len(kinds) == 1 else '/'.join(sorted(kinds))}'")
    return errs


def check_text_fields(obj, where, need_body=True):
    errs = []
    if not isinstance(obj, dict):
        return [f"{where}: must be an object"]
    t = obj.get("title")
    if not (isinstance(t, str) and t and "\n" not in t and "\r" not in t):
        errs.append(f"{where}: title must be a non-empty single-line string")
    if need_body:
        b = obj.get("body")
        if not (isinstance(b, list) and b and all(isinstance(x, str) and "\n" not in x and "\r" not in x for x in b)):
            errs.append(f"{where}: body must be a non-empty list of lines and no line may contain a line break")
    return errs


def join_text(obj):
    return obj.get("title", "") + "\n" + "\n".join(obj.get("body", []))


def check_input(case, ctx, where):
    kind, inp = case.get("kind"), case.get("input")
    errs = []
    if not isinstance(inp, dict):
        return [f"{where}: input must be an object"]
    allowed = {
        "title": {"title"},
        "request": {"title", "body"},
        "task": {"title", "body"},
        "pull_request": {"title", "body"},
        "documentation": {"title", "body", "doc_type"},
        "translation": {"original", "rendering", "must_preserve", "technical_intent"},
        "identity_pair": {"metadata", "versions"},
    }.get(kind)
    if allowed is None:
        return errs
    for k in sorted(set(inp) - allowed):
        errs.append(f"{where}: input has unknown field '{k}' for kind '{kind}'")
    for k in sorted(allowed - set(inp)):
        errs.append(f"{where}: input is missing field '{k}' for kind '{kind}'")
    if errs:
        return errs
    if kind == "title":
        errs += check_text_fields(inp, f"{where}: input", need_body=False)
    elif kind in ("request", "task", "pull_request"):
        errs += check_text_fields(inp, f"{where}: input")
    elif kind == "documentation":
        errs += check_text_fields(inp, f"{where}: input")
        if inp["doc_type"] not in DOC_TYPES:
            errs.append(f"{where}: doc_type must be one of {DOC_TYPES}")
    elif kind == "translation":
        src, ren = inp["original"], inp["rendering"]
        errs += check_text_fields(src, f"{where}: input.original")
        errs += check_text_fields(ren, f"{where}: input.rendering")
        if not (isinstance(src, dict) and isinstance(src.get("language"), str) and src["language"]):
            errs.append(f"{where}: input.original.language must be a language tag such as pt-BR")
        if not is_str_list(inp["technical_intent"], allow_empty=False):
            errs.append(f"{where}: technical_intent must be a non-empty list of strings")
        if not is_str_list(inp["must_preserve"]):
            errs.append(f"{where}: must_preserve must be a list of strings")
        elif not errs:
            for term in inp["must_preserve"]:
                if term not in join_text(src):
                    errs.append(f"{where}: must_preserve term '{term}' is not in the original text")
                if term not in join_text(ren):
                    errs.append(f"{where}: must_preserve term '{term}' is missing from the English rendering")
    elif kind == "identity_pair":
        md, vs = inp["metadata"], inp["versions"]
        if not (isinstance(md, dict) and md and all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in md.values())):
            errs.append(f"{where}: metadata must be a non-empty object of string or integer identifiers")
        if not (isinstance(vs, list) and len(vs) >= 2):
            errs.append(f"{where}: versions must list at least two versions of the same item")
        else:
            union, worst = set(), "pass"
            for i, v in enumerate(vs):
                vw = f"{where}: versions[{i}]"
                if not (isinstance(v, dict) and set(v) == {"label", "title", "verdict", "breaks"}):
                    errs.append(f"{vw}: needs exactly label, title, verdict and breaks")
                    continue
                if not one_line(v["label"], 1, 80):
                    errs.append(f"{vw}: label must be a short single line")
                errs += check_text_fields(v, vw, need_body=False)
                sub = check_rule_list(v["breaks"], ctx, vw, "breaks", {"title"})
                errs += sub
                if not sub:
                    exp = expected_verdict(v["breaks"], ctx["rules"])
                    if v["verdict"] != exp:
                        errs.append(f"{vw}: verdict '{v['verdict']}' does not match its breaks, which give '{exp}'")
                    union |= set(v["breaks"])
                    if VERDICTS.index(exp) > VERDICTS.index(worst):
                        worst = exp
            if not errs:
                if set(case.get("breaks", [])) != union:
                    errs.append(f"{where}: breaks must be the union of the version breaks {sorted(union)}")
                if case.get("verdict") != worst:
                    errs.append(f"{where}: verdict must be the worst version verdict '{worst}'")
    return errs


def validate_case(case, ctx, where):
    errs = []
    if not isinstance(case, dict):
        return [f"{where}: a case must be an object"]
    cid = case.get("id", "?")
    where = f"{where}: case '{cid}'"
    for k in CASE_REQUIRED:
        if k not in case:
            errs.append(f"{where}: missing field '{k}'")
    for k in sorted(set(case) - CASE_FIELDS):
        errs.append(f"{where}: unknown field '{k}'")
    if errs:
        return errs
    if not (isinstance(cid, str) and CASE_ID.match(cid)):
        errs.append(f"{where}: id must match {CASE_ID.pattern}")
    kind = case["kind"]
    if kind not in ctx["kinds"]:
        errs.append(f"{where}: kind must be one of {ctx['kinds']}")
    if case["domain"] not in ctx["domains"]:
        errs.append(f"{where}: domain must be one of {ctx['domains']}")
    if case["source"] not in SOURCES:
        errs.append(f"{where}: source must be one of {SOURCES}")
    elif (case["source"] == "master-prompt") != ("prompt_ref" in case):
        errs.append(f"{where}: prompt_ref is required for source 'master-prompt' and not allowed otherwise")
    if "prompt_ref" in case and not one_line(case["prompt_ref"], 3, 80):
        errs.append(f"{where}: prompt_ref must be a short single line")
    if "tags" in case:
        tags = case["tags"]
        if not is_str_list(tags, allow_empty=False) or len(set(tags)) != len(tags) or any(t not in ctx["tags"] for t in tags):
            errs.append(f"{where}: tags must be a non-empty list of unique known tags {ctx['tags']}")
    ex = case["exercises"]
    if not is_str_list(ex, allow_empty=False) or len(set(ex)) != len(ex):
        errs.append(f"{where}: exercises must be a non-empty list of unique rule or invariant ids")
    else:
        for r in ex:
            if r not in ctx["rules"] and r not in ctx["invariants"]:
                errs.append(f"{where}: exercises names unknown rule or invariant '{r}'")
    eff = EFFECTIVE_KINDS.get(kind, {kind})
    b_errs = check_rule_list(case["breaks"], ctx, where, "breaks", eff)
    errs += b_errs
    if not b_errs and is_str_list(ex):
        for r in case["breaks"]:
            if r not in ex:
                errs.append(f"{where}: broken rule '{r}' must also be listed in exercises")
    if case["verdict"] not in VERDICTS:
        errs.append(f"{where}: verdict must be one of {VERDICTS}")
    elif not b_errs and kind != "identity_pair":
        exp = expected_verdict(case["breaks"], ctx["rules"])
        if case["verdict"] != exp:
            errs.append(f"{where}: verdict '{case['verdict']}' does not match breaks {case['breaks']}, which give '{exp}'")
    if not one_line(case["reason"], 10, 250):
        errs.append(f"{where}: reason must be one line of 10 to 250 characters")
    if case["verdict"] == "pass":
        if "suggested_fix" in case:
            errs.append(f"{where}: a passing case must not have a suggested_fix")
    elif "suggested_fix" not in case or not one_line(case.get("suggested_fix"), 5, 300):
        errs.append(f"{where}: a case with verdict warn or block needs a one-line suggested_fix of 5 to 300 characters")
    errs += check_input(case, ctx, where)
    return errs


def load_cases(corpus_dir):
    cases, errs = [], []
    files = sorted((corpus_dir / "cases").glob("*.json")) if (corpus_dir / "cases").is_dir() else []
    if not files:
        return cases, [f"{corpus_dir / 'cases'}: no case files found"]
    for f in files:
        doc, e = read_json(f)
        errs += e
        if doc is None:
            continue
        if not (isinstance(doc, dict) and set(doc) == {"corpus_format", "cases"} and doc["corpus_format"] == 1
                and isinstance(doc["cases"], list)):
            errs.append(f"{f.name}: must be an object with 'corpus_format': 1 and a 'cases' list")
            continue
        for c in doc["cases"]:
            cases.append((f.name, c))
    return cases, errs


def cross_check(named_cases, ctx):
    """Checks that need the whole corpus. Returns (errors, coverage)."""
    errs = []
    seen = {}
    for fname, c in named_cases:
        cid = c.get("id") if isinstance(c, dict) else None
        if cid in seen:
            errs.append(f"{fname}: duplicate case id '{cid}' (first seen in {seen[cid]})")
        elif cid is not None:
            seen[cid] = fname
    cases = [c for _, c in named_cases if isinstance(c, dict) and c.get("verdict") in VERDICTS]
    passing = [c for c in cases if c["verdict"] == "pass"]
    bad = [c for c in cases if c["verdict"] != "pass"]
    if len(passing) < MIN_PASS_CASES:
        errs.append(f"corpus: needs at least {MIN_PASS_CASES} passing cases, found {len(passing)}")
    if len(bad) < MIN_BAD_CASES:
        errs.append(f"corpus: needs at least {MIN_BAD_CASES} bad cases (warn or block), found {len(bad)}")
    for c in bad:
        if not c.get("breaks"):
            errs.append(f"case '{c.get('id')}': a bad example must declare the rule id it breaks in breaks")
    for d in REQUIRED_DOMAINS:
        in_d = [c for c in cases if c.get("domain") == d]
        if not any(c["verdict"] == "pass" for c in in_d):
            errs.append(f"corpus: domain '{d}' has no passing case")
        if not any(c["verdict"] != "pass" for c in in_d):
            errs.append(f"corpus: domain '{d}' has no warn or block case")
    for tag in REQUIRED_TAGS:
        if not any(tag in (c.get("tags") or []) for c in cases):
            errs.append(f"corpus: no case has the required adversarial tag '{tag}'")
    for kind in ("translation", "identity_pair"):
        if not any(c.get("kind") == kind for c in cases):
            errs.append(f"corpus: no case of kind '{kind}'")
    cov = {rid: {"breaks": 0, "near": 0} for rid in ctx["rules"]}
    for c in cases:
        for r in c.get("breaks", []):
            if r in cov:
                cov[r]["breaks"] += 1
        for r in c.get("exercises", []):
            if r in cov and r not in c.get("breaks", []):
                cov[r]["near"] += 1
    for rid, v in cov.items():
        if v["breaks"] == 0:
            errs.append(f"rule '{rid}' has no case that breaks it")
        if v["near"] == 0:
            errs.append(f"rule '{rid}' has no near-miss case that exercises it without breaking it")
    return errs, cov


# ---------------------------------------------------------------- policy table

def check_policy(policy_text, ctx):
    errs = []
    rows = {}
    for line in policy_text.splitlines():
        m = re.match(r"^\|\s*`([a-z0-9-]+)`\s*\|(.*)\|\s*$", line)
        if m:
            rows[m.group(1)] = [c.strip() for c in m.group(2).split("|")]
    for rid, r in ctx["rules"].items():
        cells = rows.get(rid)
        if cells is None:
            errs.append(f"policy: the rule table has no row for '{rid}'")
        elif len(cells) < 2 or cells[0] != r["severity"] or cells[1] != r["mode"]:
            errs.append(f"policy: row for '{rid}' says {cells[:2]} but rules.json says [{r['severity']!r}, {r['mode']!r}]")
    for rid in rows:
        if rid.startswith(RULE_PREFIXES) and rid not in ctx["rules"]:
            errs.append(f"policy: the rule table lists '{rid}', which is not in rules.json")
    return errs


# ---------------------------------------------------------------- prompt examples

def backticks(s):
    return re.findall(r"`([^`]+)`", s)


def extract_prompt_examples(lines):
    """Return (bad, good, errors) taken from the master prompt itself."""
    errs, bad, good = [], [], []

    def find(prefix):
        for ln in lines:
            if ln.startswith(prefix):
                return ln
        errs.append(f"prompt: cannot find the line that starts with {prefix!r}. The prompt changed, so update this extractor")
        return None

    ln = find("1. Use short, descriptive, sentence-case titles")
    if ln:
        good += backticks(ln)
    ln = find("3. Avoid opaque prefixes")
    if ln:
        cut = ln.find("Prefer")
        if cut < 0:
            errs.append("prompt: rule 3 no longer contains the word 'Prefer'")
        else:
            bad += backticks(ln[:cut])
            good += backticks(ln[cut:])
    ln = find("6. Decompose work into meaningful")
    if ln:
        bad += backticks(ln)
    ln = find("**Bad examples**:")
    if ln:
        bad += backticks(ln)
    for i, ln in enumerate(lines):
        if ln.startswith("**Good examples**"):
            for nxt in lines[i + 1:]:
                if not nxt.startswith("- "):
                    break
                bt = backticks(nxt)
                if bt:
                    good.append(bt[0])
            break
    else:
        errs.append("prompt: cannot find '**Good examples**'. The prompt changed, so update this extractor")
    for prefix, target in (("- Preferred issue:", good), ("- Preferred task:", good)):
        ln = find(prefix)
        if ln and backticks(ln):
            target.append(backticks(ln)[0])
    ln = find("- Avoid:")
    if ln:
        bad += backticks(ln)
    if not errs:
        if len(bad) != EXPECTED_PROMPT_BAD or len(good) != EXPECTED_PROMPT_GOOD:
            errs.append(f"prompt: found {len(bad)} bad and {len(good)} good examples, expected {EXPECTED_PROMPT_BAD} and "
                        f"{EXPECTED_PROMPT_GOOD}. The prompt changed, so update this extractor and the corpus")
    return bad, good, errs


def check_prompt_examples(named_cases, prompt_lines):
    bad, good, errs = extract_prompt_examples(prompt_lines)
    if errs:
        return errs
    prompt_cases = [c for _, c in named_cases if isinstance(c, dict) and c.get("source") == "master-prompt"]
    by_title = {}
    for c in prompt_cases:
        raw_input = c.get("input")
        inp = raw_input if isinstance(raw_input, dict) else {}
        by_title.setdefault(inp.get("title"), []).append(c)
    for t in bad:
        cs = by_title.get(t)
        if not cs:
            errs.append(f"prompt example (bad) is not in the corpus: {t!r}")
        elif not all(c.get("verdict") in ("warn", "block") for c in cs):
            errs.append(f"prompt example (bad) must have verdict warn or block: {t!r}")
    for t in good:
        cs = by_title.get(t)
        if not cs:
            errs.append(f"prompt example (good) is not in the corpus: {t!r}")
        elif not all(c.get("verdict") == "pass" for c in cs):
            errs.append(f"prompt example (good) must have verdict pass: {t!r}")
    known = set(bad) | set(good)
    for t in by_title:
        if t not in known:
            errs.append(f"a case claims to quote the master prompt but its title is not a prompt example: {t!r}")
    return errs


# ---------------------------------------------------------------- self test

def _sample_ctx():
    def rule(rid, sev, mode, applies):
        return {"id": rid, "family": "t", "severity": sev, "mode": mode, "applies_to": applies,
                "summary": "s", "definition": "d", "suggested_fix": "f"}
    return {
        "rules": {"r-block": rule("r-block", "block", "deterministic", ["title"]),
                  "r-warn": rule("r-warn", "warn", "deterministic", ["title"]),
                  "r-review": rule("r-review", "warn", "reviewer", ["task"])},
        "invariants": {"inv"},
        "kinds": ["title", "request", "task", "pull_request", "documentation", "translation", "identity_pair"],
        "domains": ["general", "games", "trading", "ml-research", "native-apps", "web"],
        "tags": ["adversarial"],
    }


def _sample_case():
    return {"id": "sample-case", "kind": "title", "domain": "general", "source": "authored", "exercises": ["r-block"],
            "breaks": ["r-block"], "verdict": "block", "reason": "A sample reason for the self test.",
            "suggested_fix": "Write a sentence.", "input": {"title": "A | B"}}


def _set(path, value):
    def f(c):
        c[path] = value
    return f


def _del(path):
    def f(c):
        c.pop(path, None)
    return f


def _in_input(key, value):
    def f(c):
        c["input"][key] = value
    return f


SELF_TESTS = [
    ("missing reason", _del("reason"), "missing field 'reason'"),
    ("unknown verdict", _set("verdict", "maybe"), "verdict must be one of"),
    ("unknown rule id", lambda c: c.update(breaks=["no-such-rule"], exercises=["no-such-rule"]), "unknown rule 'no-such-rule'"),
    ("verdict contradicts breaks", _set("verdict", "pass"), "does not match breaks"),
    ("blocking rule labelled warn", _set("verdict", "warn"), "does not match breaks"),
    ("passing case that still has a fix", lambda c: c.update(breaks=[], verdict="pass"), "must not have a suggested_fix"),
    ("id with capital letters", _set("id", "Sample_Case"), "id must match"),
    ("rule that does not apply to the kind", lambda c: c.update(kind="request", input={"title": "t", "body": ["x"]}), "does not apply to kind"),
    ("broken rule missing from exercises", _set("exercises", ["inv"]), "must also be listed in exercises"),
    ("warn case without a suggested fix", lambda c: (c.pop("suggested_fix"), c.update(breaks=["r-warn"], exercises=["r-warn"], verdict="warn")), "needs a one-line suggested_fix"),
    ("master-prompt case without prompt_ref", _set("source", "master-prompt"), "prompt_ref is required"),
    ("unknown extra field", _set("owner", "nobody"), "unknown field 'owner'"),
    ("title with a line break", _in_input("title", "line one\nline two"), "single-line string"),
    ("input field missing", lambda c: c.update(kind="request", breaks=[], exercises=["inv"], verdict="pass",
                                               input={"title": "t"}) or c.pop("suggested_fix"), "input is missing field 'body'"),
    ("body line with a line break", lambda c: c.update(kind="request", breaks=[], exercises=["inv"], verdict="pass",
                                                       input={"title": "t", "body": ["a\nb"]}) or c.pop("suggested_fix"),
     "no line may contain a line break"),
    ("translation loses a required term",
     lambda c: (c.pop("suggested_fix"), c.update(kind="translation", breaks=[], exercises=["inv"], verdict="pass", input={
         "original": {"language": "pt-BR", "title": "Salvar progresso", "body": ["Usem o coyote time que ja existe."]},
         "rendering": {"title": "Save progress", "body": ["Use the existing grace period."]},
         "must_preserve": ["coyote time"], "technical_intent": ["Save progress"]})), "is missing from the English rendering"),
]


def run_self_test():
    ctx = _sample_ctx()
    problems = 0
    base_errs = validate_case(_sample_case(), ctx, "sample")
    if base_errs:
        print("self-test: the sample case is not valid, so the test is meaningless:", file=sys.stderr)
        for e in base_errs:
            print(f"  {e}", file=sys.stderr)
        return 1
    print("self-test: the unmodified sample case is accepted")
    for name, mutate, needle in SELF_TESTS:
        c = copy.deepcopy(_sample_case())
        mutate(c)
        errs = validate_case(c, ctx, "sample")
        hit = [e for e in errs if needle in e]
        if hit:
            print(f"self-test: rejected  {name}: {hit[0]}")
        else:
            problems += 1
            print(f"self-test: NOT REJECTED  {name} (expected an error containing {needle!r}, got {errs})", file=sys.stderr)
    dup = [("a.json", _sample_case()), ("b.json", _sample_case())]
    dup_errs, _ = cross_check(dup, ctx)
    if any("duplicate case id" in e for e in dup_errs):
        print("self-test: rejected  duplicate case ids: " + next(e for e in dup_errs if "duplicate case id" in e))
    else:
        problems += 1
        print("self-test: NOT REJECTED  duplicate case ids", file=sys.stderr)
    bad_rules = {"corpus_format": 1, "verdicts": VERDICTS, "kinds": ["title"], "domains": REQUIRED_DOMAINS, "tags": ["adversarial"],
                 "invariants": [{"id": "inv", "summary": "s"}], "lists": {},
                 "rules": [{"id": "r-review", "family": "t", "severity": "block", "mode": "reviewer", "applies_to": ["title"],
                            "summary": "s", "definition": "d", "suggested_fix": "f"}]}
    _, rule_errs = validate_rules(bad_rules)
    if any("reviewer rules must have severity warn" in e for e in rule_errs):
        print("self-test: rejected  blocking reviewer rule: " + next(e for e in rule_errs if "reviewer rules" in e))
    else:
        problems += 1
        print("self-test: NOT REJECTED  blocking reviewer rule", file=sys.stderr)
    total = len(SELF_TESTS) + 2
    print(f"self-test: {total - problems} of {total} malformed inputs were rejected")
    return 0 if problems == 0 else 1


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate the readability test corpus.")
    ap.add_argument("--corpus-dir", type=Path, default=HERE, help="directory that holds rules.json and cases/ (default: this script's directory)")
    ap.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help="documentation policy file whose rule table must match rules.json")
    ap.add_argument("--prompt", type=Path, default=DEFAULT_PROMPT, help="master prompt file used by --prompt-examples")
    ap.add_argument("--prompt-examples", action="store_true", help="check that every good and bad example in the master prompt is in the corpus")
    ap.add_argument("--coverage", action="store_true", help="print how many cases break or guard each rule")
    ap.add_argument("--self-test", action="store_true", help="prove that the validator rejects malformed input, then exit")
    args = ap.parse_args(argv)

    if args.self_test:
        return run_self_test()

    corpus = args.corpus_dir.resolve()
    rules_doc, errs = read_json(corpus / "rules.json")
    ctx, rule_errs = validate_rules(rules_doc) if rules_doc is not None else ({"rules": {}, "invariants": set(), "kinds": [], "domains": [], "tags": []}, [])
    errs += rule_errs
    named, load_errs = load_cases(corpus)
    errs += load_errs
    for fname, c in named:
        errs += validate_case(c, ctx, fname)
    cross_errs, cov = cross_check(named, ctx)
    errs += cross_errs

    policy_note = ""
    try:
        policy_text = args.policy.read_text(encoding="utf-8")
        errs += check_policy(policy_text, ctx)
        policy_note = "policy rule table matches rules.json"
    except OSError as e:
        errs.append(f"policy: cannot read {args.policy}: {e}")

    blocked = None
    if args.prompt_examples:
        try:
            prompt_lines = args.prompt.read_text(encoding="utf-8").splitlines()
        except OSError as e:
            blocked = f"BLOCKED: cannot read the master prompt at {args.prompt}: {e}. The prompt examples were not checked."
        else:
            errs += check_prompt_examples(named, prompt_lines)

    if errs:
        for e in errs:
            print(f"error: {e}", file=sys.stderr)
        print(f"FAILED: {len(errs)} problem(s) in the readability corpus", file=sys.stderr)
        return 1

    cases = [c for _, c in named]
    n_pass = sum(c["verdict"] == "pass" for c in cases)
    n_warn = sum(c["verdict"] == "warn" for c in cases)
    n_block = sum(c["verdict"] == "block" for c in cases)
    print(f"ok: {len(cases)} cases in {len({f for f, _ in named})} files: {n_pass} pass, {n_warn} warn, {n_block} block")
    print(f"ok: {len(ctx['rules'])} rules, each with at least one breaking case and one near-miss case; {policy_note}")
    print("ok: domains " + ", ".join(REQUIRED_DOMAINS) + " each have a passing and a failing case; "
          "required adversarial tags present: " + ", ".join(REQUIRED_TAGS))
    if args.coverage:
        width = max(len(r) for r in ctx["rules"])
        print(f"\n{'rule'.ljust(width)}  severity  mode           breaks  near-miss")
        for rid, r in ctx["rules"].items():
            print(f"{rid.ljust(width)}  {r['severity'].ljust(8)}  {r['mode'].ljust(13)}  {str(cov[rid]['breaks']).rjust(6)}  {str(cov[rid]['near']).rjust(9)}")
        by_domain = {d: sum(c["domain"] == d for c in cases) for d in ctx["domains"]}
        print("\ncases per domain: " + ", ".join(f"{d} {n}" for d, n in by_domain.items()))
        by_kind = {k: sum(c["kind"] == k for c in cases) for k in ctx["kinds"]}
        print("cases per kind: " + ", ".join(f"{k} {n}" for k, n in by_kind.items()))
    if args.prompt_examples:
        if blocked:
            print(blocked, file=sys.stderr)
            return 3
        print(f"ok: all {EXPECTED_PROMPT_BAD} bad and {EXPECTED_PROMPT_GOOD} good examples from the master prompt are in the corpus "
              "with the right verdict")
    return 0


if __name__ == "__main__":
    sys.exit(main())
