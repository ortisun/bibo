# Readability test corpus

Labelled examples of good and bad human-facing text, and the catalog of rules they exercise. They are the shared specification for two consumers: the readability gate, which an engineer will build as deterministic rules, and the independent language-quality reviewer, which is a model.

The policy that explains why the rules exist is [`docs/reference/documentation-policy.md`](../../docs/reference/documentation-policy.md). This directory holds the machine-readable side.

Everything in the cases is made up for testing. Product names, commands, numbers and identifiers do not describe a real system. Do not copy a command from here into real documentation.

## Files

| Path | What it is |
|---|---|
| `rules.json` | The rule catalog: id, severity, mode, the artifact kinds it applies to, a definition, a suggested fix, and the word lists the deterministic rules use. Also the allowed kinds, domains, tags and three invariants. |
| `cases/*.json` | The cases. Each file is `{"corpus_format": 1, "cases": [...]}`. Files are grouped by theme only. A case can go in any file. |
| `check_corpus.py` | Standard-library Python validator. It checks structure and consistency. It does not implement the rules. |

Case files: `prompt-examples` (the master prompt's own titles, verbatim), `titles`, `requests`, `tasks`, `pull-requests`, `documentation`, `translations` (Portuguese requests with the expected English rendering), `identity` (identifiers stay stable when text changes) and `adversarial`.

## Verdicts

Every case has one expected `verdict`.

| Verdict | Meaning | Gate outcome (see the policy, section 9.3) |
|---|---|---|
| `pass` | No finding. | PASSED |
| `warn` | At least one warning and no blocking finding. | PASSED, with the warnings reported |
| `block` | At least one blocking finding. | FAILED |

A rule's severity (`warn` or `block`) is fixed in `rules.json`. The verdict of a case is derived from the rules it breaks, and the validator checks that the two agree. The word `block` here is a rule severity. It is not the gate outcome BLOCKED, which means a gate could not run.

A rule has a `mode`. A `deterministic` rule is decided by code. A `reviewer` rule is a model judgement and can only warn, because a model judgement never blocks by itself. The validator rejects a reviewer rule with severity `block`.

## Case format

The fields before `input` are the case header. A bad example declares the rule ids it breaks in `breaks`.

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique across the corpus. Lower-case letters, digits and hyphens. |
| `kind` | yes | What is being checked: `title`, `request`, `task`, `pull_request`, `documentation`, `translation` or `identity_pair`. |
| `domain` | yes | `general`, `games`, `trading`, `ml-research`, `native-apps`, `web` or `platform`. |
| `source` | yes | `master-prompt` for a title copied from the master prompt, otherwise `authored`. |
| `prompt_ref` | with `master-prompt` | Where in the prompt it comes from, for example `communication-policy/bad-examples`. |
| `tags` | no | `adversarial`, `hidden-id-chain`, `unexpanded-acronym`, `vague-title`, `prompt-injection`, `quoted-evasion`, `localization`, `boundary`, `source-as-output`. |
| `exercises` | yes | The rules (or invariants) this case is evidence for. At least one. |
| `breaks` | yes | The rules the case violates. Empty for `pass`. Every id must also be in `exercises`. |
| `verdict` | yes | `pass`, `warn` or `block`. |
| `reason` | yes | One line saying why the case has this verdict. |
| `suggested_fix` | for `warn` and `block` | One line of advice. It is guidance for the author, not an exact string to match. |
| `input` | yes | The text under test. The shape depends on `kind`. |

A case in `exercises` but not in `breaks` is a **near miss**: text that looks like it might trip the rule and must not. Every rule has at least one breaking case and at least one near miss.

### Input shapes

| `kind` | `input` |
|---|---|
| `title` | `{"title": "..."}` |
| `request` | `{"title": "...", "body": ["line", "line"]}`. A request is the normalized text the factory writes, with no required template. |
| `task` | Same as `request`. A task must also have the four template sections. |
| `pull_request` | Same as `request`. |
| `documentation` | `{"title": "...", "doc_type": "how-to", "body": [...]}`. `doc_type` is `tutorial`, `how-to`, `reference`, `explanation`, `adr` or `changelog`. |
| `translation` | `{"original": {"language": "pt-BR", "title": "...", "body": [...]}, "rendering": {"title": "...", "body": [...]}, "must_preserve": [...], "technical_intent": [...]}`. The verdict is for the English `rendering`, checked as a `request`. The original is data and is not checked. |
| `identity_pair` | `{"metadata": {...identifiers...}, "versions": [{"label", "title", "verdict", "breaks"}, ...]}`. Each version is a title checked as a `title`. The case verdict is the worst version verdict. |

A `body` is a list of lines. Join them with `\n` and add no trailing newline. A line is never allowed to contain a line break. This keeps multi-line Markdown readable in review. The title is checked exactly as written, including any trailing space the case needs for a rule.

### Example

```json
{
  "id": "title-prefix-ticket-code-colon",
  "kind": "title",
  "domain": "web",
  "source": "authored",
  "exercises": ["title-opaque-prefix"],
  "breaks": ["title-opaque-prefix"],
  "verdict": "block",
  "reason": "A work item code in front of the title duplicates what metadata already holds.",
  "suggested_fix": "Add password reset support",
  "input": { "title": "WI-0192: Add password reset support" }
}
```

## How a rule maps to cases

A rule id appears in three places: the `rules` list in `rules.json`, the `breaks` and `exercises` of cases, and the rule table in the policy. The rule id is also a valid `check_id` for a gate report, so the gate can report it unchanged.

```bash
python3 -I fixtures/readability/check_corpus.py --coverage
```

prints, for each rule, how many cases break it and how many are near misses. To see every case for one rule, search the case files for the id.

## How the gate should use the corpus

1. Read `rules.json` and every file in `cases/`. For each case, build the text from `input`.
2. Run the deterministic rules only. Compare the set of rule ids the gate reports with the case's `breaks` filtered to rules whose `mode` is `deterministic`. Compare the verdict derived from those findings with the verdict derived from the same filtered `breaks`. A case that lists only reviewer rules must come out clean from the deterministic gate.
3. Where a rule is a heuristic (`text-not-english`, `text-abbreviation-unexpanded`, `title-not-sentence-case`), the cases at the boundary are the specification. If a case looks wrong, ask the documenter to change the case. Do not tune the code around it.
4. For `translation`, check the `rendering` as a `request`. Separately, check that every `must_preserve` string appears in the rendering. The validator already checks the fixture is consistent that way.
5. For `identity_pair`, run each version's title. The metadata must come out of the gate unchanged and no version may add an identifier to a title.
6. For every case, check that the input text is byte-for-byte unchanged after the gate runs (invariant `input-never-edited`).
7. Reviewer rules are tested by the reviewer evaluation, not by the deterministic tests. There the reviewer must report each reviewer id in `breaks` for a bad case, and must not report a reviewer id that a near-miss case lists in `exercises`. Extra findings on a bad case are not errors. Its findings are always warnings. The reviewer must receive the text as data (invariant `text-is-data`).

## Adding a case

1. Pick the file by theme and copy a similar case.
2. Give it a new unique id. Fill in `exercises`, `breaks`, `verdict`, `reason` and, for `warn` and `block`, `suggested_fix`.
3. Run `python3 -I fixtures/readability/check_corpus.py`. Fix what it reports.
4. Make sure the label is true by the rule's definition in `rules.json`, not by how it feels.
5. Add the text under test with no more content than the case needs.

To copy a title from the master prompt, use `source: "master-prompt"`, give a `prompt_ref`, and copy the title exactly. `--prompt-examples` reads the prompt and fails when an example is missing, when its verdict is wrong, or when a case claims to quote the prompt but does not.

## Adding or changing a rule

Write the breaking case and the near miss first and watch the validator fail. Then add the rule to `rules.json` and a row to the rule table in the policy. The validator checks that the table's severity and mode agree with `rules.json`. Section 10 of the policy has the full steps.

## Running the validator

```bash
python3 -I fixtures/readability/check_corpus.py                    # structure, coverage, policy table
python3 -I fixtures/readability/check_corpus.py --coverage         # also print coverage per rule
python3 -I fixtures/readability/check_corpus.py --prompt-examples  # also check the master prompt examples
python3 -I fixtures/readability/check_corpus.py --self-test        # prove the validator rejects malformed input
python3 -I fixtures/readability/check_corpus.py --corpus-dir DIR   # validate a copy of the corpus
```

| Exit code | Meaning |
|---|---|
| 0 | The corpus is valid. |
| 1 | The corpus is invalid. Every problem is printed. |
| 2 | Wrong command-line arguments. |
| 3 | BLOCKED. A required input, such as the master prompt for `--prompt-examples`, could not be read. This is never reported as a pass. |

What it checks:

- Every case has the required fields and no unknown ones. Ids are unique. Verdicts, kinds, domains and tags are known.
- Every rule id exists and applies to the case's kind. `breaks` agrees with `verdict`. Non-passing cases have a suggested fix.
- Text fields have the right shape. Translation fixtures keep their `must_preserve` terms in both texts.
- There are at least 8 passing and 20 bad cases. Each of the five domains has a passing and a failing case. The required adversarial tags are present.
- Every rule has a breaking case and a near miss.
- The policy's rule table matches `rules.json`.

What it does not check: whether a label is right. That is a review question, and it is answered by the rule definitions and by the gate once it exists.

A `pattern` in `rules.json` covers only the part of a definition that a regular expression can express. The definition text is authoritative. The five patterns were written without look-around or backreferences and all five compile with the Rust `regex` crate (version 1.13.1, built with cargo 1.98.0 in a scratch project on 2026-10-27). They have not been run against the corpus in Rust.
