# Documentation policy

- Status: Slice 1 baseline, revised on 2026-10-29. The readability gate (`crates/workflow/src/gates/readability`) and the documentation gate (`crates/workflow/src/gates/docs`) are built and ran in the test-mode runs of the factory. No live run has applied this policy to a real repository.
- Date: 2026-10-27
- Author: documenter
- Review: not yet independently reviewed. An architecture review is still needed before this policy is treated as settled.
- Source: the master prompt (the communication and documentation policy at the top, section 10, and the Stage 11 gate), the contract schemas in [`schemas/`](../../schemas/README.md), and requirements FR-025, FR-026 and FR-034 of the [Slice 1 specification](../../specs/001-end-to-end-mvp/spec.md).
- Machine-readable form: [`fixtures/readability/rules.json`](../../fixtures/readability/rules.json) and the test cases beside it. The rule table in section 9.4 must match that file, and `python3 -I fixtures/readability/check_corpus.py` checks that it does.

## 1. What this policy covers

This policy answers three questions.

1. How does the factory write? Sections 2 to 7 cover language, titles, task bodies, abbreviations, identifiers and pull request text.
2. Which documents does a change need? Section 8 covers the documentation set, the impact policy and the Diátaxis split.
3. How do the two gates decide? Section 9 covers the Human-Readable Artifact Quality Gate (the readability gate) and the Documentation Quality Gate, what each may block, and what each outcome means.

The readers of this file are the agents that plan, write and review documentation, and the engineers who build the gates. If the policy and the master prompt disagree, the master prompt wins and this file is wrong.

## 2. Language

### 2.1 English for everything the factory writes for people

All human-facing text is clear, professional English, whatever language the request arrived in. That covers:

- requirements and Spec Kit artifacts;
- issues, tasks, subtasks and acceptance criteria;
- technical documentation, architecture decision records, README files and generated guides;
- pull request titles and bodies, changelogs and release notes;
- review findings, code comments and agent reports shown to people;
- dashboard labels and GitHub comments.

### 2.2 What stays in its original language

The factory does not translate these silently. It keeps the original and writes its own explanation around it in English.

| Kept as it is | Why | How it is marked |
|---|---|---|
| Code identifiers and symbols | They are names in code. | Code span. |
| Quoted user text | It is evidence of what was asked. | Blockquote or double quotation marks, with an English explanation next to it. |
| External source citations | Accuracy. | Quotation, plus an English summary. |
| Product names | They are names. | As written. |
| Domain terms such as IPCA (a Brazilian inflation index), Selic (a Brazilian interest rate) or "coyote time" | The people who use the product use these terms. | As written, explained in English at the first mention when the term is not widely understood. |
| Content a product must show in another language, such as localized interface labels | The product requires it. | Code span, quotation, or the product's own locale files. |

The original is kept as evidence beside the English text. It never replaces it.

### 2.3 Product localization

When a product must be localized, the end-user interface strings are written in the requested locale. The engineering documentation stays in English. A task that asks for Brazilian Portuguese checkout labels is written in English and quotes the labels, for example "Finalizar compra".

### 2.4 Translation assumptions

A translation never adds, drops or softens a requirement. A "never" stays a "never". When the source is ambiguous, the factory asks one focused question (FR-006) instead of guessing, and it records any assumption it had to make as an assumption in the specification. An independent reviewer compares the English text with the original and the stated technical intent.

## 3. Titles

A title tells a capable teammate what will be different when the work is done.

1. Keep it short and in sentence case: capitalise the first word and proper names only. Aim for 90 characters or fewer. The contract schemas accept 3 to 100.
2. Name a concrete outcome. Start with a strong verb when that helps: "Add password reset support", "Validate trading data before backtesting", "Improve character movement on slopes".
3. Leave out opaque prefixes, taxonomy tags, machine-looking labels, ID chains, role labels and pipeline-stage stamps. Do not end with a period or an ellipsis.
4. Keep immutable identifiers (UUIDs, database keys, trace identifiers, graph node identifiers, correlation identifiers) in metadata, links, hidden fields or the sidebar. Use native GitHub issue numbers to refer to GitHub items. Do not invent a second numbering scheme in the title.
5. Branch names and file paths may use short machine-safe slugs. That is not permission to make a title cryptic.

The master prompt's own examples:

- Good: `Add password reset support`, `Add OpenID Connect login`, `Calculate discounted cash flow estimates`, `Detect invalid market data before model training`, `Add offline progress saving for the puzzle game`.
- Bad: `SF-FEAT-027 | FIN-VAL | AGT-QNT: DCF MOD`, `T-028 | UI | URGENT`, `FEAT-042 | BE-AUTH | P1 | Implement OIDC`, `TASK-13: [AGENT:BACKEND] Do work`, `DOC-07: DRL-RUNBOOK-REV2`, `Fix stuff`, `Implement part 3`, `Agent task complete`, `Update documentation`, `Edit file A`, `Run command B`.

All of them are in the test corpus with the rule they break.

## 4. Task and issue bodies

1. Use natural, complete sentences of 35 words or fewer. A new contributor must understand the item without decoding agent terminology.
2. Use this template, in this order: **Why this matters**, **What needs to change**, **Acceptance criteria**, **Verification**, and **Dependencies** only when there are some. The title is the first part of the template.
3. Say how success will be verified. Acceptance criteria are things a person or a test can observe.
4. Keep bookkeeping out of the text: risk, agent assignment, runtime, cost, status, retries and specification revision belong in structured fields.
5. Split work into outcome-focused tasks. `Edit file A` and `Run command B` are not tasks unless they are independently verifiable. A task that combines unrelated features cannot be reviewed or rolled back on its own.
6. Comments, error explanations, reviewer feedback and escalation questions are short, respectful, specific and linked to evidence. Chatbot filler and motivational phrasing take the place of facts, so they are left out.

## 5. Abbreviations

Spell out an uncommon abbreviation at its first mention: "discounted cash flow (DCF)". Keep widely understood names such as API, SQL, GPU, ML and OIDC when the audience knows them. Spell the name out where it could be read two ways: `FPS` can mean frames per second or first-person shooter. Avoid internal acronyms even when they are technically valid.

"Widely understood" is a list, not a feeling. The starter list is `lists.acronym_allowlist` in `rules.json`. The master prompt names API, SQL, GPU, ML and OIDC. The other entries are the documenter's starting choice. Change the list through a reviewed change that adds a case.

## 6. Identifiers and metadata

- Identifiers do not depend on display text, so rewording a title cannot change one. Rewording changes display text only.
- The gate never moves an identifier into a title and never rewrites one. A reworded item keeps every metadata field it had.
- The first line of a body is not a place for a chain of codes either. The corpus includes a clean title over a body that starts with `SF-FEAT-031 | UI-PAUSE | AGT-FE | P2 | wave-3 | spec-rev-4`. A check on the title alone would pass it, so the gate checks the body prefix.
- A UUID in running text is a warning. The same value is fine in a link target or a code span.

## 7. Pull request text

A pull request title follows section 3. The body says what changed for the user in plain sentences, how it was checked, and where the evidence is: the issue, the specification revision, the task, decisions, test runs and the documents that changed. It does not report its own success in cheerful phrasing. The delivery stage adds the evidence manifest hash and the links to the specification, the plan and the documentation.

## 8. The documentation set

### 8.1 Four forms of documentation (Diátaxis)

The master prompt asks for the Diátaxis split where it fits. Every document the factory writes has one main form, and a page that mixes forms is split.

| Form | The reader asks | Written as | Typical factory documents | Quick test |
|---|---|---|---|---|
| Tutorial | "Teach me by doing." | A guided lesson with one safe path and a visible result. | Getting started, first run of a sample project. | Could a newcomer finish it without knowing the system? |
| How-to guide | "How do I reach this goal?" | Ordered steps for a task the reader already understands. | Install, configure, restore after an outage, upgrade, run a runbook. | Does it start with a goal and end with a result? |
| Reference | "What exactly is this?" | Neutral, complete, structured facts. Generated from source where the source defines them. | Command and flag lists, configuration keys, API and schema pages, glossary. | Can you look something up without reading the rest? |
| Explanation | "Why is it like this?" | Discussion of context, design and trade-offs. | Architecture overview, decision records, security model, domain assumptions. | Does it answer why and not how? |

A how-to guide explains what problem it solves, its prerequisites, ordered steps, the expected result, how to validate it, and troubleshooting. It uses examples that a reader can actually run.

### 8.2 The documentation impact policy

The factory writes the smallest set of documents that covers what the change touches. It does not write every artifact for every change.

1. Start from the change: the specification, the diff, the public interfaces, the operating procedures and the release risk.
2. Ask who is affected: end users, developers, integrators, operators, reviewers.
3. For each affected behavior and audience, pick the form from 8.1 and the document from 8.3.
4. Update an existing document before writing a new one. A near-duplicate is a defect.
5. Add the domain content from 8.4 only when the change touches that behavior.
6. Record the result in the documentation plan: audience, pages affected, owner, sources and acceptance criteria. The plan is the master prompt's `documentation_plan.json`. Its schema is defined by the documentation stage package. Until it exists, the information is kept in a structured record and never in titles.
7. If nothing needs documenting, the answer is NOT_APPLICABLE with the rule that led there, not a blank PASSED. The PR text is still written and still checked.
8. The documents may already be written when the documentation stage runs: the builder often updates the README and the changelog together with the code. The documentation writer then checks each page of the plan against the change, marks it covered, lists no file as written and changes nothing. The stage accepts that report and records that no documentation commit was needed; the documentation review still reads the pages, because the reviewer is shown the pages the gates judged and not only what the writer committed (9.9). The writer's word is contradicted, and the attempt fails, only when it names a file as written and the tree shows no change. A file the writer changes outside the README, the changelog and `docs/` is a separate matter: the scope gate fails it and nothing is committed.

For a significant new product, the full onboarding set applies (last row of 8.3).

### 8.3 Required documents per change type

Every change has pull request text with links to the issue, the specification acceptance criteria, decisions and tests. The table lists the documents beyond that.

| Change type | Required documents | Audience | Form | Not applicable when |
|---|---|---|---|---|
| New user-visible feature | Update the user guide or add a task guide. Add reference entries for each new setting, command or screen. Add a changelog entry, and a release-note line when it ships in a release. | End users | How-to guide, reference, changelog | Never. A feature is user-visible by definition. |
| Bug fix | Add a changelog entry for a fix users can notice. Correct any page that described the old behavior. Add a troubleshooting entry if users meet the symptom. | End users, operators | Changelog, the corrected page in its own form | No user could observe the defect and no document describes the behavior. |
| Refactor with no change in behavior or interface | Update only pages that name the moved or renamed parts, such as architecture views and developer guide paths. | Developers | Explanation or reference, as already written | No document references a changed file and no public interface changed. |
| New or changed public interface: API, SDK, command line, configuration key, schema, event | Reference page, generated from the source of truth where one exists. At least one runnable example. Changelog entry. | Integrators, developers, operators for configuration | Reference, how-to for the example | The interface did not change. |
| Breaking change, on top of any type above | Upgrade guide with before and after steps. Changelog entry marked as breaking. Deprecation notice when a transition period exists. | Everyone who uses the interface | How-to guide, changelog | The change is not breaking. |
| Data or schema migration | Steps to apply, verify and roll back. Notes on downtime and data impact. A decision record when it is hard to reverse. | Operators, developers | How-to guide (runbook), explanation | No stored data changes. |
| Architecturally significant decision | A decision record with the options considered. Update the architecture overview and its diagrams, kept as source-controlled text. | Maintainers, reviewers | Explanation | The decision is local and cheap to reverse. |
| Infrastructure, deployment or pipeline change | Update the deployment and configuration reference. Change the runbook when an operating procedure changes. Include rollback steps. | Operators, site reliability engineers | How-to guide (runbook), reference | No operating procedure or configuration changed. |
| Security-relevant change: authentication, secrets, trust boundary, permissions | Update the security model and threat assumptions. Give operators the configuration guidance. No secret appears in the text. | Operators, security reviewers | Explanation, reference | Policy or a profile rule says the change does not touch the security posture. |
| Dependency or toolchain change | Update prerequisites and the version-compatibility matrix. Add a changelog entry when users are affected. | Developers, operators | Reference | No document names the version and users cannot see the change. |
| Documentation-only change | The changed documents themselves, checked for links, examples and readability. | Readers of those documents | The form each document already has | Never. The gate checks the changed pages. |
| Test-only or build-script-only change | Nothing beyond the pull request text, unless contributor instructions name the changed command. | Reviewers | Pull request text | No contributor document names the changed command. |
| New product or major component | The onboarding set: README and getting started, installation and setup, user guide, developer guide (repository layout, build and test, extension points, conventions), architecture overview with decision records, operations (configuration reference, deployment, monitoring, backup and restore, runbooks, troubleshooting), and the security model. | All audiences the product has | Tutorial, how-to guides, reference, explanation | Never, but the plan may leave out audiences the product does not have. |

"Not applicable when" is always an observable condition that a deterministic rule, a domain profile or policy can evaluate. An agent's opinion is not a valid reason.

### 8.4 Domain additions

When a change touches the behavior of one of these domains, add the matching content. Record assumptions, experimental limits and reproducibility requirements for each.

| Domain | Add | Main readers |
|---|---|---|
| Games | Player controls. Gameplay systems. Level and content pipeline. Asset licences. Supported hardware. Engine and editor setup. Performance budgets. Modding or multiplayer contracts when they exist. | Players, designers, engine developers |
| Trading and quantitative research | Instruments. Data lineage and adjusted prices. Safeguards against look-ahead and survivorship bias. Execution assumptions. Cost and slippage models. Risk controls. How backtest and live results differ. Reproducibility and operational safeguards. | Researchers, risk owners, operators |
| Valuation and financial research | Method and formulas. Sources and as-of dates. Assumptions and discount rates. Scenario and sensitivity analysis. Provenance. Limits and how to read the result. | Analysts, reviewers |
| Machine learning, deep learning and reinforcement learning | Dataset provenance and licences. Split and leakage controls. Feature definitions. Experiment configuration and seeds. Commands that reproduce training and inference. Model card. Evaluation metrics. Environments and reward definitions. Hyperparameters. Known limits. Drift and monitoring guidance. | Researchers, engineers, stakeholders |
| Workflow engines and distributed systems | State machine and failure semantics. Idempotency. Retry semantics. Delivery guarantees. Protocol contracts. Consistency model. Observability. Recovery steps. | Developers, operators |
| Web, mobile and desktop applications | User journeys. Accessibility. Supported versions. Platform setup. Signing and release procedures. Permissions and data privacy. Interface component documentation. Deployment or distribution steps. | Users, developers, release managers |

### 8.5 Documentation as code

- Documents are Markdown, or the project's own standard format, in version control. They are committed on the same branch as the code and reviewed in the same pull request.
- Headings are stable and sentence case, so links and anchors survive. Each section is reachable from an index or from the README.
- Diagrams are source-controlled text. The repository checks Mermaid blocks with `docs/architecture/tools/check-mermaid.sh`, and its README says the check covers syntax only and does not render. A diagram that was only syntax-checked is reported that way.
- Machine-defined facts are generated from the source of truth. Explanations are written by a person or agent and reviewed independently.
- Information about a document, such as its audience, form and sources, is typed metadata kept in the documentation plan. It is not put in the title.
- Public documentation and release notes are published only after the release gate. The default pull request flow does not publish.

### 8.6 Evidence-linked claims

Every statement about behavior, performance, safety or compatibility traces to one of these:

- a test;
- a command output with its exit status;
- a code location at a commit;
- a schema;
- a measurement with its date and method;
- a cited source with its date;
- expert judgment, named as such.

Three more rules for claims:

- Label what is not measured as a simulation result, an assumption or a hypothesis.
- Do not describe planned or mocked behavior as shipped, and do not write "fast" or "safe" without a number or a test.
- State the limits of the evidence, such as one machine, one market or simulator only. Treat a claim written by a model as unverified until it is checked against the source.

### 8.7 What is never published

Secrets, private code, and sensitive financial or data artifacts do not appear in public documentation. Examples use made-up values that are clearly synthetic.

## 9. The gates

### 9.1 Two checks and one principle

The **readability gate** runs before the factory creates or updates an issue, a task plan, a specification, a pull request, release notes or documentation. The **Documentation Quality Gate** runs in the `DOCUMENTATION_REVIEW` stage, after `DOCUMENTING` and before `DELIVERY`, and again when later code changes invalidate the documentation.

Both follow one principle: code decides what code can decide, and an independent reviewer judges what code cannot. The deterministic part blocks. The reviewer advises.

### 9.2 What PASSED, FAILED, BLOCKED and NOT_APPLICABLE mean

These are the outcomes of a gate report, as defined in [`gate-report.schema.json`](../../schemas/gate-report.schema.json). The schema enforces most of the third column. A PASSED report needs commands that ran with exit code 0, or an in-process gate. A BLOCKED report needs a blocked reason. A NOT_APPLICABLE report needs a reason and has no commands. The last column is a rule for how the gates are built.

| Outcome | It means | The report must show | It is never |
|---|---|---|---|
| PASSED | Every check that applies ran and succeeded. | Each command executed with exit code 0 and no timeout, or an in-process gate. Tool versions. No failures. | Recorded because nothing ran. |
| FAILED | A check ran and found a violation. | At least one failure with a check id and a plain-English message. A file and line when known. | Offset by a pass of a different check. |
| BLOCKED | A check that is required could not run. | What was missing: `tool_unavailable`, `tool_probe_failed`, `dependency_unavailable`, `policy_unresolvable`, `environment_unsupported` or `design_not_approved`, and the names of the missing items. `design_not_approved` is the code of the design gate at intake. It stands for a design that is not approved and also for a job whose text is not the text of its issue (the reason `text_not_the_issue`), and the delivery stage stops with the same code when the design is no longer approved right before the pull request is opened. | Turned into PASSED. The stage does not advance. |
| NOT_APPLICABLE | There is nothing for this gate to check on this change. | A recorded reason: `no_matching_files`, `profile_excludes_gate`, `policy_excludes_gate` or `change_type_excludes_gate`, decided by a deterministic rule, a domain profile or policy, with a plain-English justification. | Decided by an agent's opinion. Used when a check was merely skipped. |

Short version: tool absence is never success. A missing tool gives BLOCKED. An empty scope gives NOT_APPLICABLE with a recorded reason. Only checks that ran give PASSED or FAILED. A diagram that has no parser in the sandbox is BLOCKED. Documentation with no diagrams is NOT_APPLICABLE for that check.

The independent reviewer uses a different vocabulary, from [`review-verdict.schema.json`](../../schemas/review-verdict.schema.json): `PASS`, `CHANGES_REQUIRED`, `BLOCK` and `NEEDS_HUMAN`. A reviewer `BLOCK` is a review verdict. It is not the gate outcome BLOCKED, and a reviewer cannot overrule a failed deterministic check (specification, user story 7).

### 9.3 Block and warn in the readability gate

A rule has a severity, `block` or `warn`.

- **block** means the gate outcome is FAILED. The artifact must be corrected before the stage can advance. Each blocking finding is an entry in `failures`, with the rule id as the `check_id`.
- **warn** means the gate still passes. The finding names the problem and gives a suggested fix. Warnings are reported separately from blocking findings.
- The gate outcome is BLOCKED only when the gate itself cannot run, for example when its language word lists cannot be loaded. A rule never produces BLOCKED.

| Corpus verdict | Findings | Gate outcome |
|---|---|---|
| pass | None. | PASSED |
| warn | Warnings only. | PASSED, with the warnings reported (see open decision 1) |
| block | At least one blocking finding. | FAILED |

A rule may block only when all three of these hold.

1. Code can decide it from the text and the kind of artifact alone.
2. The author can fix it without changing what the requirement asks for.
3. The master prompt or the contract schemas name it as something to avoid, or the schema already rejects it.

Everything else warns. A finding made by the reviewer is always a warning.

The gate judges a page's title only when the change sets or changes it. A title the page already had at the commit the job started from belongs to the project, and the documentation writer may not rename the project's pages to please a rule, so the title rules do not read it; the body of the page is still judged. In the thirty-fifth real run the README of the word count tool kept its title, `word-count`, the name of the program, and the gate failed the page three times for a title the change never touched.

### 9.4 The rules

Each rule has an identifier that is also a valid `check_id` in a gate report. The exact definition, the word lists and the reference patterns are in `fixtures/readability/rules.json`. Where a rule is a heuristic, the test corpus is the specification at the boundary.

| Rule | Severity | Mode | What it checks |
|---|---|---|---|
| `title-schema-shape` | block | deterministic | The title is shorter than 3 or longer than 100 characters, has leading or trailing whitespace, or contains a line break. |
| `title-opaque-prefix` | block | deterministic | The title starts with an identifier chain, a ticket-style code followed by a separator, or a bracketed tag. |
| `title-machine-label` | block | deterministic | The title contains a pipe, a bracketed tag that is not at the start, a role or agent stamp, or no ordinary word at all. |
| `title-vague` | block | deterministic | The title names no concrete outcome. It is made only of generic words, points at a placeholder such as 'part 3' or 'file A', or reports a status. |
| `title-type-tag` | warn | deterministic | The title starts with a type tag and a colon, such as 'feat(auth):' or 'URGENT:'. |
| `title-not-sentence-case` | warn | deterministic | The title is in all capitals or in Title Case instead of sentence case. |
| `title-too-long` | warn | deterministic | The title is 91 to 100 characters long. |
| `title-trailing-punctuation` | warn | deterministic | The title ends with a period, colon, semicolon, comma, exclamation mark or ellipsis. |
| `title-lacks-concrete-outcome` | warn | reviewer | The title is well formed but does not say what will be different afterwards, for example 'Improve the authentication module'. |
| `task-missing-section` | block | deterministic | A task body lacks one of the four required sections, or the section is empty. |
| `body-metadata-prefix` | block | deterministic | The first line of the body is an identifier chain, a tag chain or a metadata stamp, even if the title is fine. |
| `body-metadata-lines` | warn | deterministic | A line outside code states internal bookkeeping such as 'Assigned agent: backend-2' or 'Retries: 2'. |
| `pr-missing-evidence-link` | warn | deterministic | A pull request body links to nothing: no link, no URL, no issue number and no file path. |
| `doc-guide-missing-part` | warn | deterministic | A how-to guide or tutorial lacks prerequisites, numbered steps, an expected result or troubleshooting. |
| `text-not-english` | block | deterministic | Human-facing prose outside quotations and code is not written in English. |
| `text-quotation-dominates` | warn | deterministic | Most of the prose is a non-English quotation, so the English explanation is missing or thin. |
| `text-abbreviation-unexpanded` | warn | deterministic | An abbreviation that is not on the widely understood list is used without being spelled out at its first mention. |
| `text-raw-internal-id` | warn | deterministic | A UUID appears in running text instead of in metadata, a link or a code span. |
| `text-filler-phrase` | warn | deterministic | The text contains chatbot filler or marketing phrasing from the starter list. |
| `text-long-sentence` | warn | deterministic | A sentence in the prose has more than 35 words. |
| `task-acceptance-criteria-vague` | warn | reviewer | The acceptance criteria cannot be checked, for example 'works well' or 'feels fast'. |
| `task-granularity` | warn | reviewer | The task is too small to verify on its own, or it combines unrelated features. |
| `text-hard-to-follow` | warn | reviewer | The text depends on internal terms or agent jargon that a new contributor cannot decode. |
| `doc-claim-without-evidence` | warn | reviewer | The text states a result, a measurement or a guarantee without a source, a date or a way to check it. |
| `translation-unfaithful` | warn | reviewer | The English rendering changes, drops or adds a requirement that the source states. |

"Deterministic" means code decides with no model involved. "Reviewer" means a model judges the text against the rule and can only warn.

### 9.5 What the readability gate never does

- It never edits the text it checks. It reports findings and suggested fixes, and the author or the rework loop makes the change.
- It never changes, adds or removes an identifier.
- It never decides what a requirement means. A fix that would change a requirement is raised as a question for a person.
- It never hides a blocking finding behind a warning, and never turns a warning into a block because it is repeated.

### 9.6 The language-quality reviewer

The master prompt pairs the deterministic rules with an independent language-quality reviewer for nuanced cases. The reviewer receives the artifact, its kind and the reviewer rules from 9.4. It does not receive the writer's own account of the work. It returns a verdict from `review-verdict.schema.json` and findings that name the rule, the sentence and a suggested rewrite. In the readability gate those findings are warnings. When the independent documentation reviewer in `DOCUMENTATION_REVIEW` returns `CHANGES_REQUIRED` for a documentation defect, the work goes back to `DOCUMENTING` ([state machine](../architecture/state-machine.md)).

If the stage contract requires the reviewer and it cannot run, the gate outcome is BLOCKED with `tool_unavailable`. If the reviewer is optional for that stage, the gate reports its deterministic result and says in its reason that the advisory review did not run. It never claims a reviewer pass that did not happen.

### 9.7 Text under review is data

Issue text, repository files, documentation, web pages, tool output and model output are untrusted data, not instructions (constitution principle IV). For the readability gate that means three things.

1. The deterministic rules match characters. Nothing in the text can change which rules run, their severity or the result.
2. The reviewer reads the text inside a delimited data section, and its prompt says the section is not an instruction. Prompt assembly is built by the prompt assembly package.
3. A request that contains instructions aimed at the factory is not blocked by the readability gate for that reason. The gate applies the same rules it applies to any text. Intake and the security controls decide what to do with the injection.

The corpus has a clean body with an injected paragraph (it passes), and a body with an injected paragraph and a real violation (it is still blocked).

### 9.8 The Documentation Quality Gate

Master prompt section 10.4 lists what a PASS requires. This table says who decides each check and when the answer is not PASSED. The checks that the slice plan assigns to the documentation stage are links, executed snippets, command references against real help output, diagram syntax, required-page coverage, readability, secrets and the changelog.

| Check | Decided by | PASSED needs | BLOCKED when | NOT_APPLICABLE when |
|---|---|---|---|---|
| Clear English and readable titles | The readability gate, then the reviewer | No blocking finding | The gate cannot load its word lists | The change adds no human-facing text |
| Internal links and anchors resolve | Code | Every target exists on the branch | The link checker cannot run | The documents contain no links |
| Examples run and print what the page says | Code, in the sandbox ([9.10](#910-how-the-gate-finds-and-runs-examples)) | Each example executed, exit code 0, output matches | The runtime or tool for an example is missing | No changed document shows a command that names the program |
| Named commands, flags, keys and variables exist | Code, against real help output and the source | Every name found | The program cannot be run | No document names one |
| API, command line and schema references match the source | Code where generated, reviewer otherwise | The page equals the generated output | The generator is missing | No public interface changed |
| Diagrams parse and render | Code | The diagram renders. A syntax check alone is reported as syntax-checked, not rendered | The parser or renderer is missing | No diagram exists |
| Required documents exist | Code, against the documentation plan | Every planned document exists and is not empty | The plan is missing | The impact policy requires none |
| Breaking changes are documented | Code when an interface diff exists, reviewer otherwise | A changelog entry and an upgrade note exist | The interface diff cannot be produced | The change is not breaking |
| No secrets or private data | Code | A scan ran and found nothing | The scanner is missing | Never |
| Claims match the code, tests and behavior | The independent documentation reviewer | `PASS` with no unresolved blocking finding | The reviewer cannot run | The documents make no claims about behavior |

The result is stored with the source-to-document traceability, the documentation changes, the lint results and the reviewer decisions.

How a named flag counts as the program's own: the program's help output lists it, or the program's source code at the documentation commit holds it as a quoted literal (for example `"--json"`). The help output is not enough on its own, because a project may decide that its help text does not change: in the thirty-fifth real run the owner kept the help text of the word count tool as it was, the README documented the new `--json` flag, and the check called the flag invented. A command counts as the program's when the help output names it. An environment variable counts when the source reads it or the help output names it.

### 9.9 What the documentation reviewer reads

The independent documentation reviewer must judge exactly the pages the gates judged, over the same commits. The gate report binds its result to three commits: the job's base commit, the code head and the documentation head. The reviewer's inputs are bound to the same three.

| Input | What it holds | Commits |
|---|---|---|
| `frozen_specification` | The frozen specification. | None |
| `documentation_plan` | The documentation plan. | None |
| `code_diff` | The patch of the code change. | Base commit to code head |
| `documentation_diff` | The patch of every page the gates judged: each Markdown file the change adds or modifies, and nothing else. | Base commit to documentation head |
| `gate_reports` | The reports of the readability gate and of each check, in words. | Those of the gate report |
| `people_answers` | What people answered when a documentation review of this job asked them a question: the earlier runs of the stage first, then this run. It comes from the factory's own record of their answers, and it says so when nobody was asked. | None |
| `project_rules` | The project's rules for agents ([project rules](../architecture/project-rules.md)). | Base commit |

Why the documentation diff starts at the base commit and not at the code head. The builder often writes the README and the changelog together with the code, and the writer then changes nothing (8.2, item 8). A patch from the code head to the documentation head is empty in that case. The gates still judge those pages, because they read the change from the base commit. In the thirty-seventh real run the reviewer received the empty patch, could not see the pages, and stopped the job to ask a person whether a documentation commit was missing. A page written in the code commits is therefore in both diffs. That is intended: the code diff shows what the code does, the documentation diff shows every page under review.

When no page changed, the documentation diff is not left empty. It says, in one sentence, that no documentation page changed between the base commit and the documentation head. An empty block means something went wrong; a stated absence does not.

Why the reviewer receives people's answers. When the reviewer returns `NEEDS_HUMAN`, a person answers and the stage runs again. Without the answer the reviewer asks the same question again. The answers come from the factory's record, never from a file the writer wrote, so they are not the writer's account of its work. They are decisions of the people who own the job: the reviewer reads them as settled and does not ask them again.

Why the answers of earlier runs come too. A documentation review run does not live for the whole job. When a later round sends the work back to documenting, to implementation or to the specification, the engine creates a new documentation review run, and when the code changes it supersedes the run and creates another. The new run has no answers of its own yet, so without the earlier ones the reviewer asks a settled question again. The reviewer therefore receives the answers given to every earlier documentation review run of the same job, oldest run first and each run's answers in the order they were given, and then the answers given to this run. The two groups have their own headings, so the reviewer can tell an answer to an earlier round from an answer to this one.

The options weighed for where these answers come from:

| Option | What it would do | Why it was or was not chosen |
|---|---|---|
| A new, narrow seam that reads the answers of the earlier runs of the stage from the store (chosen) | The composition root implements it over the stored links of a person's answers, the same records the specification stage reads. | It gives the stage exactly what it needs and nothing else, it does not change what a rework round means to any other stage, and it can serve another reviewer later without a change to its callers. |
| The rework seam (`ReworkSource`) that the specification stage reads | It already carries `earlier_answers`. | It answers only for the run a rework move sent the work back to. The documentation review run is re-created after its target, so it would get no answers, and widening the seam would make every re-created run look like a rework round to the stages that use it. |
| Only the chain of runs a rework names (`rework_of`) | The answers of the runs this run replaced one by one. | A run superseded because the code changed is not named by the run after it, so its answers would be lost. Every earlier run of the stage in the same job covers both ways a run is replaced. |
| The engine adds the earlier answers to the answers of this run | The stage would read them with its own. | Every stage counts the answers of its own run to know which round it is in. Mixing in earlier runs would change that count for all of them. |

An answer to an earlier run may be about pages that later changed. It is still a decision of the people who own the job, and the reviewer reads it beside the pages as they are now.

The record of the review stores the hash of each input it gave, the list of pages the documentation diff holds, and how many answers came from this run and how many from earlier runs.

### 9.10 How the gate finds and runs examples

The check `docs-examples` runs every example of the program that a changed page shows, and compares what the program prints with the output the page shows. It must never pass a page whose examples it did not run. In the thirty-sixth and thirty-seventh real runs it did: the README showed the new option in the fixture's own style, a `sh` block with `word-count notes.txt` and then a `text` block with the output, and also `printf 'one two three\n' | word-count --json`. The gate knew only lines that start with `$ word-count`, found nothing, and reported `NOT_APPLICABLE` ("no command of the program to run"). A page full of examples that nobody ran looked like a page with no examples.

**What counts as an example.** A command line names the program when the program's name is the first word of the line, or of any command of its pipeline, after any variables set before it (such as `LANG=C`). The gate reads two forms of block.

| Form | Where | The command | The output it compares |
|---|---|---|---|
| Prompt form | A block of language `console`, `shell-session`, `sh`, `bash`, `shell`, `zsh` or `text` | Each line that starts with `$ ` and names the program | The lines after it, up to the next `$ ` line or the end of the block |
| Script form | A block of language `sh`, `bash`, `shell` or `zsh` that has no `$ ` line | Each line that names the program. Empty lines and lines that start with `#` are not commands. | The next block of the page, when its language is `text`, `output`, `plaintext` or `txt`, it has no `$ ` line, and no heading stands between the two blocks |

An example with no output shown must still run and end with exit code 0. A script block that holds more than one command of the program and is followed by an output block is reported: the gate cannot tell which command printed that output. Lines that name another program, such as `cargo build`, are not examples of the program and are left alone.

**How an example runs.** The gate runs the built program in the verify sandbox with the example's arguments, as an argument vector, never through a shell. Quotes and backslashes are read the way the standard Unix shell (`sh`, as the Portable Operating System Interface (POSIX) standard defines it) reads them, with no expansion. One pipeline is understood without a shell, because it is the usual way to show a program that reads standard input:

* `printf 'TEXT' | program ARGUMENTS`, where `TEXT` is one argument whose only escapes are `\n`, `\t`, `\r`, `\\` and `%%`;
* `echo WORDS | program ARGUMENTS` or `echo -n WORDS | program ARGUMENTS`, where no word holds a backslash.

The factory works out the bytes `printf` or `echo` would print, and the sandbox gives them to the program as its standard input. The program is always the process whose output is compared.

The program runs in the read-only checkout of the documentation commit, with the root of the repository as its working directory. A file an example names, such as `notes.txt` in `word-count notes.txt`, must therefore be in the repository at that path. The gate creates no file for an example: a file it made up would make the example pass with input the page never showed. An example whose file is missing ends with the program's own error and fails with `example-failed`, which tells the writer to show an input the repository holds. This is why the word count fixture keeps a `notes.txt` at its root, the file its README's examples count.

**An example the gate cannot run is reported, never passed.** Any other command that names the program is reported with the rule `example-not-runnable`, and the check fails: a pipe into another program, a redirect, a chain (`;`, `&&`, `||`), a background `&`, a command or variable substitution, a glob, a `~`, a variable set before the command, a line that continues on the next line, or a `printf` or `echo` the gate does not read. The message says which forms the gate runs, so the writer can show the example in one of them. An example that ran and printed other output fails with `example-output-differs`, and one that ended with another exit code fails with `example-failed`. `NOT_APPLICABLE` means only that no changed page shows a command that names the program.

The report names every command it ran. Its evidence lines name each example by page, line and the command as written, and the hash of the standard input when the example had one, so the report vouches for exactly the examples it ran.

The options weighed:

| Option | What it would do | Why it was or was not chosen |
|---|---|---|
| Recognise the script form, paired with the next output block (chosen) | Reads examples in the style many projects already use. | The gate follows the project's style instead of making the writer change it, and the pairing rule is strict enough that an output block is never compared with the wrong command. |
| Run the command line through `/bin/sh -c` in the verify sandbox | Any shell example would run. | The sandbox has no network and a read-only checkout, so a shell would not escape it. What a shell adds is that the page's text becomes a program: it could chain or substitute other commands and print the expected output itself, such as `word-count notes.txt > /dev/null; echo '{"lines":1}'`, and the gate would pass an example whose output the program never printed. The page is written by an agent, so the evidence would be the agent's word again. A shell also breaks the rule of the sandbox port that a command is never a shell string, and its behaviour depends on which shell the image has (`echo` and `printf` differ between them). |
| Understand the `printf` and `echo` pipeline without a shell (chosen) | Covers the common way to show standard input. | The factory computes the input and the program alone produces the output, so the evidence stays about the program. Everything else stays reported. |
| Require the writer to use `$ ` lines | One form only. | It puts the gate's limit on every project's style, and a page written another way would still need to be reported, not ignored. The prompt form stays supported. |

## 10. Changing this policy

1. Write the case first: a breaking case, and a near-miss case that must stay clean. Run `python3 -I fixtures/readability/check_corpus.py` and watch it fail.
2. Change the rule in `rules.json`, then the rule table in section 9.4.
3. Run the validator again. It checks structure, rule coverage, the master prompt examples (`--prompt-examples`) and that the table above matches `rules.json`.
4. The software architect reviews the change. A change that makes a warning into a block also needs the three conditions in 9.3 stated in the pull request.

## 11. Open decisions

These need an owner. None of them is settled by this file.

1. **Where warnings go in a gate report.** Settled. `gate-report.schema.json` now has an optional `warnings` array beside `failures`, and a PASSED report may carry warnings. The [schema README](../../schemas/README.md) records the change.
2. **Duplicate tasks.** Master prompt rule 10 lists duplicate task detection. It compares tasks with each other, so it does not fit a one-artifact corpus. A set-based case kind would be needed.
3. **External links.** The sandbox may have no network. Whether the documentation gate checks external URLs, and what it reports for the ones it cannot check, is not decided. Until then it must not report them as valid.
4. **Conventional-commit tags.** `feat(auth):` is a warning here because many teams use it by habit. Whether a target repository may switch the rule off is not decided.
5. **Languages.** Deterministic detection is required for Portuguese only, because it is the only non-English language the master prompt names. Other languages reach the reviewer, who can only warn.
6. **Look-alike characters.** A prefix written with look-alike letters from another alphabet would not match the patterns. The corpus does not cover it.
7. **Unfaithful translation.** The reviewer rule `translation-unfaithful` warns. The specification (user story 3) wants a person or reviewer to confirm that technical intent survives. The stage that does this must decide whether a finding routes to `NEEDS_HUMAN`.
8. **Starter lists and thresholds.** The acronym list, the filler list, the generic-word lists and the numbers (90 characters for a title, 35 words for a sentence) are starting choices. The master prompt names no number. The 35-word ceiling comes from the documenter role's own readability standard. They need an owner who reviews changes.
9. **Front matter.** The documenter role's page standard asks for front matter on every page: owner, status, last review date and the commit it was validated against. The documents in this repository use a bullet header instead, and the schemas do not define front matter. Which one applies to factory-written documents is not decided.

## 12. Sources

- Master prompt: communication and documentation policy (rules 1 to 11 and the examples), section 10 (documentation phase, quality gate, examples) and the Stage 11 gate.
- [`schemas/gate-report.schema.json`](../../schemas/gate-report.schema.json) and [`schemas/review-verdict.schema.json`](../../schemas/review-verdict.schema.json) for the outcome and verdict vocabularies, and the `humanTitle` definition that rule `title-schema-shape` mirrors.
- [`docs/architecture/state-machine.md`](../architecture/state-machine.md) for where `DOCUMENTING` and `DOCUMENTATION_REVIEW` sit.
- [`specs/001-end-to-end-mvp/spec.md`](../../specs/001-end-to-end-mvp/spec.md): FR-006, FR-008, FR-016, FR-025, FR-026, FR-034.
- [`.specify/memory/constitution.md`](../../.specify/memory/constitution.md): principles III, IV and V.
- [`docs/architecture/slice-plan.md`](../architecture/slice-plan.md): the readability gate and documentation stage packages.
