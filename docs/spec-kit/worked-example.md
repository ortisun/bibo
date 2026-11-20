# Worked example: producing the Slice 1 specification with Spec Kit

This walkthrough shows how the factory's own constitution and the Slice 1 specification (`specs/001-end-to-end-mvp/`) were produced with the installed Spec Kit 1.1.2. It satisfies the master prompt's request for "a worked example of a real spec produced by the installed integration" (section 16). It also says plainly which parts are tool output and which parts a person or agent wrote by hand.

For the reasoning behind the commands, and the facts they rely on, see the [integration guide](integration-guide.md).

## What is real and what is not

| Artifact | How it was produced |
| --- | --- |
| `.specify/` and `.claude/skills/speckit-*` | `specify init`, tool output |
| `.specify/memory/constitution.md` | The real `/speckit-constitution` skill, run headlessly by Claude Code. One hand step afterwards: the skill's scratch "Sync Impact Report" comment was deleted, as the skill itself instructs. |
| `specs/001-end-to-end-mvp/spec.md`, first draft | The real `/speckit-specify` skill, run headlessly. |
| Three answers under `## Clarifications` | The real `/speckit-clarify` skill asked the questions. **The Product Owner agent answered them** by choosing the recommended option each time. No human has confirmed them. |
| `checklists/requirements.md` | Written and ticked by the specify skill itself. |
| `checklists/requirements-quality.md` | The real `/speckit-checklist` skill. The skill left every item unchecked. The notes under each item were added by hand afterwards. |
| Review edits to `spec.md` | **Written by hand** by the Product Owner agent after reading the checklist. They are not tool output. Section 8 lists every change. |

The specification is a **draft**. Nobody independent has reviewed it, no human has confirmed the seven decisions recorded in its `## Clarifications` section, no checklist item is ticked, and it has not been frozen or committed. It must not be treated as an approved requirement until those steps happen.

The model that ran the skills was Claude Sonnet 5.5 (`claude-sonnet-5-5`) inside Claude Code 2.1.311. A second, separate run used Codex 0.163.0 on a throwaway project to check the Codex syntax (section 9). Its output is not part of this repository.

## 1. Initialise Spec Kit in the repository

I first probed the same procedure in two throwaway copies of the repository, one per host, to learn the file list before touching this repository. The expected list matched the real result exactly.

```text
$ cd ortisun-software-factory-ai
$ specify init --here --force --non-interactive --integration claude
```

The command added 30 files and changed nothing else. Before and after, `README.md`, `.gitignore` and the master prompt had the same SHA-256 values.

```text
.claude/skills/speckit-{analyze,checklist,clarify,constitution,converge,implement,plan,specify,tasks,taskstoissues}/SKILL.md
.specify/.gitignore
.specify/init-options.json
.specify/integration.json
.specify/integrations/claude.manifest.json
.specify/integrations/speckit.manifest.json
.specify/memory/.constitution-template.json
.specify/memory/constitution.md                 (placeholders at this point)
.specify/scripts/bash/{check-prerequisites,common,create-new-feature,resolve-template,setup-plan,setup-tasks}.sh
.specify/templates/{checklist,constitution,plan,spec,tasks}-template.md
.specify/workflows/speckit/workflow.yml
.specify/workflows/workflow-registry.json
```

Only the Claude Code integration was installed at the time of this example. The Codex integration was added to this repository later, on 2026-11-03, with `specify integration install codex` (see integration guide sections 3.4 and 11.9). The listing above is therefore the Claude Code part of what is committed now.

Check after init:

```text
$ specify integration status --json
{ "status": "ok", "default_integration": "claude", "installed_integrations": ["claude"],
  "multi_install_safe": true, "missing_managed_files": 0, "modified_managed_files": 0, "findings": [] }
```

## 2. Make an isolated run copy

The skills run shell commands and write files, so I did not point them at the working repository, where other specialists were writing at the same time. I copied the initialised files into a scratch directory, made it a Git repository with one baseline commit, and ran the skills there. Afterwards I copied the produced files back and recorded their hashes.

```text
$ cp README.md .gitignore universal_agentic_software_factory_master_prompt.md <scratch>/run-claude/
$ cp -R .specify .claude <scratch>/run-claude/
$ cd <scratch>/run-claude && git init -q -b main && git add -A && git commit -q -m "spec kit init baseline"
```

The master prompt is in the run copy because the prompts below tell the skills to read it.

## 3. Drive the skills headlessly

One `claude -p` process stayed open for all seven turns. A small driver script (integration guide, Appendix B) sent each turn as a stream-json user message and waited for the `result` event. The exact options:

```text
claude -p --input-format stream-json --output-format stream-json --verbose \
  --session-id a24d12a5-012e-471f-b17a-b7a82a583088 \
  --model sonnet --effort medium \
  --permission-mode acceptEdits --permission-prompts none \
  --strict-mcp-config --setting-sources project,local \
  --max-budget-usd 10 --disallowedTools AskUserQuestion \
  --allowedTools 'Read,Write,Edit,Glob,Grep,Skill,Bash(.specify/scripts/bash/*),Bash(mkdir:*),Bash(cp:*),Bash(ls:*),Bash(cat:*),Bash(date:*),Bash(wc:*),Bash(test:*),Bash(git status:*),Bash(git rev-parse:*)'
```

`AskUserQuestion` was disabled so that the skills print their questions as text, which is how the skill files describe them. MCP servers and user-level settings were turned off to keep the run small and repeatable.

## 4. Constitution (turn 1)

Prompt, sent as the first message. The principles come from the master prompt's non-negotiables.

<details>
<summary>Full text of turn 1</summary>

```text
/speckit-constitution Project name: Ortisun Software Factory. Ratification date: 2026-10-27, which is also the last amended date. This is the first version, so set the version to 1.0.0. Use eight core principles instead of five. Write every principle as a declarative, testable rule using MUST and MUST NOT, with a short rationale. The source of truth for these principles is universal_agentic_software_factory_master_prompt.md in the repository root; read it for wording and intent but do not copy long passages.

The eight principles, in this order:

I. Spec Kit governs specification only. The official GitHub Spec Kit is the only mechanism that authors the constitution, feature specifications, clarifications and requirement-quality checklists. Its plan, tasks, analyze, implement, converge and tasks-to-issues capabilities MUST NOT be used as the delivery pipeline and are available only through an explicit, audited compatibility setting. The factory MUST integrate with the installed Spec Kit version and its real invocation syntax and MUST NOT invent commands. Spec Kit artifacts keep their original format, and a separate specification gate reads them.

II. Deterministic shell, probabilistic specialists. Code and policy decide state transitions, authorization, timeouts, budgets, check execution, ordering and merges. Agents interpret, design, write code and review. Agents MUST NOT change factory state or merge on their own. A stage advances only when its gate verifies evidence, never because an agent says it succeeded.

III. Evidence-first completion. A claim of success without verifiable evidence (command output with exit status, a check report, a diff, a commit, an artifact hash) is not success. A missing or skipped check MUST be reported as blocked or not applicable and MUST NOT be reported as passed. A PASS state MUST NOT be fabricated, and any mock or fake component MUST be labelled wherever it appears.

IV. Untrusted data is never an instruction. Issue text, repository files, dependency contents, documentation, web pages, tool output and model output are data, not higher-priority instructions. The factory MUST enforce tool allowlists, secret scanning, egress limits and scoped short-lived credentials, and MUST keep the original untrusted text separate from the normalized request.

V. Plain-English, human-readable artifacts. All human-facing text is clear, professional English, whatever language the request arrived in. Titles are short, sentence-case and describe a concrete outcome, with no opaque prefixes, ID chains or role labels. Immutable identifiers live in metadata, not in titles. A readability gate flags violations without silently changing requirements.

VI. Human gates and safe defaults. Auto-merge is off by default and auto-deploy is never on by default. Merging and deployment need explicit human authorization or an explicit per-repository policy backed by objective gates. Anything involving money, secrets, physical actuation or regulated workflows needs explicit human approval.

VII. Independent verification. The agent that builds a change MUST NOT be the only judge of it. Reviewers and validators receive the frozen specification, the diff and verified evidence, not the builder's self-justification. A builder MUST NOT edit protected tests, gate configuration, CI workflows, security configuration or evaluation fixtures to make checks pass. Gate definitions come from protected, centrally managed sources.

VIII. Versioned, immutable intent. An approved specification is frozen and versioned with content hashes. A requirement change creates a new revision and invalidates the downstream plans, tasks, reviews and documentation that depended on it. Changes to this constitution are tracked and approved separately from feature requests.

Second section, named "Engineering and quality constraints": the factory's own code follows strict test-driven development, SOLID design and explicit design contracts at module boundaries; real behaviour is preferred over mocks, fake adapters are allowed only in deterministic tests and a real provider integration may be claimed only after a real adapter smoke test, otherwise it is marked blocked; large artifacts are stored by content hash; sandboxes MUST be unprivileged, resource-bounded and network-restricted; the technical foundation is the one stated in section 1 of the master prompt, and any deviation needs a recorded architecture decision.

Third section, named "Delivery workflow and quality gates": work is delivered as verified vertical slices with real checks run after each slice; every stage has a contract with inputs, outputs, budget, timeout, evidence and a named gate; documentation is a mandatory stage with its own independent review and quality gate; pull requests stay in draft until validation and review thresholds pass; an unresolved failing check blocks promotion.

Governance: amendments are proposed as a pull request, need explicit human approval, and carry a version bump (MAJOR for removed or redefined principles, MINOR for added principles or sections, PATCH for clarifications). Every specification, architecture decision and pull request is reviewed for compliance with this constitution, and a justified exception needs a recorded architecture decision. Runtime guidance lives in the documentation under docs/ and in the master prompt.

Write only .specify/memory/constitution.md and follow the skill's normal procedure, including the Sync Impact Report and the final summary.
```

</details>

Result: success in 28 seconds and 6 model calls, 0.132 US dollars. The skill read the template, read the master prompt, and wrote `.specify/memory/constitution.md` at version 1.0.0 with eight principles, three further sections and a governance block. It put a "Sync Impact Report" comment at the top and told me to remove it before commit. Its summary said no placeholders remained.

Hand step: I deleted the comment block, as the skill instructs. Nothing else in the file was changed.

## 5. Specification (turn 2)

<details>
<summary>Full text of turn 2</summary>

```text
/speckit-specify Slice 1 of the Ortisun Software Factory: a genuine end-to-end minimum viable product. Short name for the feature directory: end-to-end-mvp. The factory is an autonomous system that turns a GitHub issue into a reviewed draft pull request. The source requirement is universal_agentic_software_factory_master_prompt.md in the repository root; read sections 0 to 4, 7 to 11, 15 and 16 and the final engineering standard, and read .specify/memory/constitution.md. This specification covers only Slice 1 as defined in section 15 of that document.

The outcome: an authorized person files a GitHub issue against a small fixture repository, and the factory carries it through every supported stage until a human can approve or reject a linked draft pull request. The stages in order are intake, repository context, specification, architecture and task plan, sandboxed single builder, real checks, independent technical review, professional documentation, documentation quality gate, draft pull request, and manual approval. Every stage stores its outputs, and every claim of success is backed by evidence. A failed check or gate blocks promotion. Auto-merge and auto-deploy are off by default.

People involved: the requester who files the issue, the operator who inspects the job and approves or rejects the result, and the independent reviewers that check the work.

Behaviour the specification must cover, each as testable requirements and acceptance scenarios:
1. Authorization. Only issues carrying the factory label and filed by an authorized person are accepted. Others are rejected with a short plain-English explanation and an audit record. The original issue text is stored unchanged and separately from the normalized request. Instructions hidden in issue text or repository files are treated as data and never obeyed.
2. Intake. The factory classifies the request type, impact, ambiguity and risk. It asks one focused question or declines an out-of-policy request, and the human can override with an audit trail. A request written in Portuguese produces an accurate English specification, a readable English task plan, an English pull request and English documentation without losing the technical intent.
3. Repository context. The factory records the fixture repository's language, build system, tests, documentation and protected paths, each with a commit and file reference.
4. Specification. The requirements come from the installed official Spec Kit with its canonical files preserved. A specification gate checks required fields, traceable acceptance criteria, contradictions and checklist state before the specification is frozen with a version and content hashes.
5. Architecture and task plan. An independent design and a task plan map to every acceptance criterion, with no orphan criteria, no dependency cycles, readable titles without prefixes, and internal identifiers kept in metadata.
6. Build. A single builder works in an isolated, resource-bounded, network-restricted sandbox and cannot change protected tests, continuous-integration files or gate configuration to make checks pass.
7. Real checks. Build, lint and tests actually run. Each produces a machine-readable report with the command, tool versions, timestamps, exit code, logs and an evidence hash. A check that did not run is never reported as passed.
8. Independent technical review. The reviewer sees the frozen specification, the diff and verified evidence, not the builder's own justification, and returns one of four verdicts: pass, changes required, block, or needs human decision, with findings that cite files and lines.
9. Professional documentation. A documentation stage, an independent documentation review and a documentation quality gate check that links resolve, examples run, the prose is natural English, and the claims match the implemented behaviour.
10. Draft pull request. It links the issue, the specification revision, the plan and the evidence manifest, includes a test matrix and review summary, and stays a draft until every gate passes.
11. Manual approval. The operator can approve, reject, pause, request rework or cancel. Nothing merges automatically.
12. Persistence. Every stage, state transition (with its reason) and artifact is stored with a content hash, so the job timeline can be reconstructed afterwards.
13. Demonstration. A recorded walkthrough on the fixture repository shows a real run with no unstated mocks.

Explicitly out of scope for this slice: crash recovery and durable scheduling (Slice 2), parallel multi-agent execution and incremental replanning (Slice 3), the operations dashboard, evaluation harness, role-based access control and multi-tenancy (Slice 4), auto-merge, deployment, and any domain other than the single fixture domain.

Keep the requirements technology-agnostic. The technology stack for the factory itself is a constraint stated in section 1 of the master prompt; mention it only as an assumption or constraint, not in the functional requirements. Use these canonical Spec Kit sections and headings only, and record out-of-scope items, constraints, risks and non-functional expectations inside the Edge Cases, Requirements, Success Criteria and Assumptions sections. Do not add new top-level sections. Create the specification and the standard quality checklist exactly as the skill procedure requires. If anything needs a human decision, use at most three NEEDS CLARIFICATION markers and present the questions as the skill describes.
```

</details>

Result: success in 95 seconds and 10 model calls, 0.361 US dollars. The skill:

1. Chose the directory `specs/001-end-to-end-mvp` (sequential numbering, as `.specify/init-options.json` says).
2. Created `spec.md` and `checklists/requirements.md`.
3. Wrote `.specify/feature.json` with `{"feature_directory": "specs/001-end-to-end-mvp"}` using a shell redirect, not a script.
4. Created no Git branch (there was no branch hook) and ran no hooks, because `.specify/extensions.yml` does not exist.
5. Asked no clarification questions. It recorded its defaults under `## Assumptions`.

The first draft had 10 user stories, 38 acceptance scenarios, 14 edge cases, 37 functional requirements, 12 key entities and 13 success criteria. All 16 items in `requirements.md` were ticked by the skill itself.

## 6. Clarification (turns 3 to 6)

Turn 3 sent the skill invocation with a limit on the number of questions:

```text
/speckit-clarify Ask at most three questions in total. Focus on decisions that change an acceptance test, who is authorized to act, or how a failure is reported. Skip anything the master prompt already settles. Write each question in plain English.
```

The skill asked one question per turn. I answered each in a single letter.

| Asked and answered | Question the skill asked | Recommended | My answer | Recorded as |
| --- | --- | --- | --- | --- |
| asked in turn 3, answered in turn 4 | Who counts as an authorized person for filing an issue the factory will act on? (FR-001) | A: a named allowlist in protected factory configuration | `A` | FR-001 rewritten; Assumptions updated |
| asked in turn 4, answered in turn 5 | If a job stops because a stage or gate fails, who is told, and where? (FR-020, FR-036) | A: a comment on the issue plus a stored reason | `A` | new FR-038 |
| asked in turn 5, answered in turn 6 | When the reviewer says "changes required", how many times may the builder redo the work before the job stops and asks a human? (FR-023) | B: two rework rounds | `B` | new FR-039 |

The skill wrote a `## Clarifications` section with a `### Session 2026-10-27` heading and one bullet per answer, then reported that `requirements.md` still passed 16 of 16 items.

One tool-side event is worth knowing. In turn 4 the model tried to edit the spec with a `python3` heredoc. My allowlist did not include it, so the call was denied (visible in `permission_denials` in the result event), and the model finished the edit with the `Edit` tool. The denial did not break the run.

The three answers are my picks of the recommended option. They are business and policy decisions about who may start work, how failures are reported and how long a job may run, so a human must confirm them.

## 7. Requirements-quality checklist (turn 7)

```text
/speckit-checklist Requirements-quality review of the whole specification for a human reviewer before the specification gate. Focus areas: stage gates and evidence, handling of untrusted input and authorization, and human-readable output. Depth: standard. Audience: reviewer. Scope: the full specification, including the clarifications. Do not ask clarifying questions; use these answers. Name the file requirements-quality.md.
```

Result: success in 41 seconds, 0.170 US dollars. The skill produced `checklists/requirements-quality.md` with 36 items (`CHK001` to `CHK036`), all unchecked, in five groups.

The skill's first action failed, and this matters for the adapter:

```text
$ .specify/scripts/bash/check-prerequisites.sh --json --template checklist-template
ERROR: plan.md not found in .../specs/001-end-to-end-mvp
Run /speckit-plan first to create the implementation plan.
```

The model said, "The prerequisite script insists on `plan.md`, which this factory deliberately doesn't create. I'll get the paths and the template another way." It called `resolve-template.sh checklist-template --json`, read the spec directly, and wrote the checklist. So the result is good, but it depended on the model recovering. See integration guide section 11.1.

The checklist raised real gaps. The five the skill called out first were documentation rework limits, untrusted sources beyond issue text, the operator's authorization, an acceptance scenario for the readability gate, and requirement numbering.

## 8. Review edits (by hand)

I read the 36 items against the spec as the reviewing Product Owner. For each gap that was a clear requirement-level omission I edited `spec.md`. For questions that belong to later design work I left the item open and said where it will be settled. These edits are **not Spec Kit output**.

| Change in `spec.md` | Answers checklist item |
| --- | --- |
| FR-001: authorization is checked at acceptance and again before the draft pull request; the allowlist also designates operators | CHK019 |
| FR-002: audit record content, append-only, readable by operators; the rejection text must not reveal the allowlist | CHK020, CHK021 |
| FR-003: later stages receive the original issue text only as quoted data | CHK022 |
| FR-004: lists every untrusted source named in the constitution | CHK016 |
| FR-007: "authorized human" becomes "operator" | CHK017 |
| FR-012: defines checklist state for the specification gate | CHK007 |
| FR-020: four result states defined once; "blocked" means one thing | CHK008, CHK011 |
| FR-026: documentation review runs first; the documentation gate is the last gate | CHK005 |
| FR-029: operator actions via command line or pull request comment; operator designation checked on each action | CHK018, CHK035 |
| FR-032: a gate validates structured agent output before a stage advances | CHK010 |
| FR-034: scope of the readability gate; quoted text marked as quotation | CHK027, CHK029, CHK032 |
| FR-038: comment states the stage, the reason and the next step | CHK031 |
| FR-039 and FR-040 moved to a new group after FR-038; FR-037 and FR-038 swapped so numbers run in order | CHK015 |
| FR-039: documentation defects get the same two rework rounds; documentation is re-checked after code changes | CHK004, CHK005 |
| FR-040 (new): the same issue event never starts a second job | CHK024 |
| Story 5, scenario 4 (new): readability gate scenario | CHK028 |
| Story 6, scenario 6 (new): secret scanning scenario | CHK025 |
| SC-001: the "unattended run" excludes the question and escalation paths | CHK014 |
| Assumptions: what happens when the sandbox or credentials are unavailable | CHK036 |
| Key entities: added Allowlist | none |
| `## Clarifications`: a note that the three answers are the Product Owner agent's, plus four bullets for the hand decisions, each marked as pending human confirmation | none |

In `checklists/requirements-quality.md` I added one header paragraph and one "Reviewer note" line under each item. The notes say either "Addressed by hand edit" or "Open", with the stage that will settle it. I ticked nothing. The checklist's own rule says only a reviewer may tick an item, and the constitution says the author must not be the only judge. Twenty-five items are marked addressed and eleven open (CHK001 to CHK003, CHK006, CHK009, CHK012, CHK013, CHK023, CHK026, CHK030, CHK033).

## 9. Codex check on a throwaway project

To fill in the Codex column of the invocation matrix I ran one skill on Codex in a separate scratch project with a trivial feature. This did not produce any file in this repository.

```text
$ specify init --here --force --non-interactive --integration codex      # in the scratch project
$ codex exec -C <scratch>/probe-codex -s workspace-write --json -o last-message.txt \
    '$speckit-specify A small command-line tool that converts a temperature between Celsius and Fahrenheit. Do not ask clarifying questions; record informed defaults as assumptions. Do not run any other Spec Kit skill.'
```

Result: exit 0 in 186 seconds. Codex created `specs/001-convert-temperature/spec.md` and `checklists/requirements.md` and wrote `.specify/feature.json`. Token use was 332,039 input (287,616 cached) and 8,665 output. The `Feature Branch` field read ``main (existing branch; no branch-creation hook configured)``, while the Claude run wrote the directory name. The first check also showed Codex finds the skills offline: `codex debug prompt-input` listed all ten under the project skill root.

## 10. Copy back and verify

I copied the produced files into the repository, then applied the hand edits there.

```text
specs/001-end-to-end-mvp/spec.md
specs/001-end-to-end-mvp/checklists/requirements.md
specs/001-end-to-end-mvp/checklists/requirements-quality.md
.specify/memory/constitution.md
.specify/feature.json                     (gitignored by Spec Kit; local pointer only)
```

Checks run in the repository afterwards:

```text
$ specify integration status --json                  -> status "ok", 0 modified, 0 missing
$ .specify/scripts/bash/check-prerequisites.sh --json --paths-only
  -> FEATURE_DIR .../specs/001-end-to-end-mvp, BRANCH 001-end-to-end-mvp
$ (throwaway gate script, integration guide section 10.1, rules 1-7 and 9) -> all pass
$ grep for "[NEEDS CLARIFICATION", "[FEATURE NAME]", "$ARGUMENTS" in spec.md  -> none
$ grep for rust|docker|postgres|nats|tokio|axum|diesel|kubernetes|react in spec.md -> none
```

Hashes (SHA-256):

| File | As generated by the skill | Final in the repository |
| --- | --- | --- |
| `.specify/memory/constitution.md` | `f94bec86969cf3489a9ca2cfb4f2895d4e8a19a11feb1b020c9088ed2dcecd95` | `6a5f61dad0ca796e0a21ce714e9f6aa2dc670689104e8132ae057587b8bf34f7` |
| `specs/001-end-to-end-mvp/spec.md` | `ef3ce0b4f8901eb35adb124cb3b8b34b5011253a6df1500d229542cb801b7772` | `6e76c2c6b79f3d91706e2fac559ad09db1f8f64fff0a70c815fd2698594f0927` |
| `checklists/requirements.md` | `478480f3acc8d21a47c92924aca137a737cd7376a95a2f1609e8544e6d4423ba` | `478480f3acc8d21a47c92924aca137a737cd7376a95a2f1609e8544e6d4423ba` (unchanged) |
| `checklists/requirements-quality.md` | `a02b37e53a9e887e68162b473efa320fd8351a962850ac5e7b73512645d2f688` | `38d1756f4d0efd65f356efb6ca656e8a51b796dbf54f0e9d754cad3cafbd333e` |

The "as generated" values are the files exactly as the skills left them. The difference between generated and final for `spec.md` is the hand edit in section 8: 29 lines added and 15 removed, counted by `diff`.

## 11. Cost and time

| Run | Host and model | Time | Cost |
| --- | --- | --- | --- |
| Seven-turn session (constitution, specify, clarify with 3 answers, checklist) | Claude Code 2.1.311, `claude-sonnet-5-5` | about 224 s | 0.893 US dollars (reported by the CLI) |
| One specify turn on a trivial feature | Codex 0.163.0, model not recorded | 186 s | not reported; 332,039 input and 8,665 output tokens |

These are the only two model runs made for this work.

## 12. What a person still has to do

1. Confirm or change the seven decisions recorded in `## Clarifications` (listed in the table below).
2. Have an independent reviewer go through `checklists/requirements-quality.md`, tick the items that now hold, and either settle or waive the eleven open ones. Until then the specification gate must report the checklist as incomplete.
3. Approve and freeze the specification, commit it, and record the revision, commit and hashes in the factory's own records.
4. Review the constitution at version 1.0.0 and record approval. The ratification date `2026-10-27` is the date it was written, and a person has not yet ratified it.

| Decision | Chosen by | Where it lives |
| --- | --- | --- |
| Authorized requesters come from a named allowlist in protected configuration | Product Owner agent | FR-001 |
| A failed job is reported by a comment on the issue plus a stored reason | Product Owner agent | FR-038 |
| Two rework rounds, then a human decides | Product Owner agent | FR-039 |
| Operators come from the same allowlist, with a separate designation | Product Owner agent, by hand | FR-001, FR-007, FR-029 |
| Documentation rework has the same two-round limit | Product Owner agent, by hand | FR-039 |
| Checklist state: an open marker or an unresolved checklist item blocks the specification gate | Product Owner agent, by hand | FR-012 |
| The "unattended run" measure excludes the question and escalation paths | Product Owner agent, by hand | SC-001 |

## 13. How to reproduce

1. Install Spec Kit 1.1.2 and Claude Code 2.1.311, and run `specify init --here --force --non-interactive --integration claude` in an empty Git repository that contains the master prompt.
2. Save the turn 1 and turn 2 texts above as `turn-1.txt` and `turn-2.txt`, and write the other turns from sections 6 and 7.
3. Run the driver from the integration guide with the options in section 3, and create each next turn file after reading the previous turn's output.
4. Expect different wording each time. The structure, the file names and the post-conditions in integration guide section 8.4 should hold. The text will not match byte for byte.
