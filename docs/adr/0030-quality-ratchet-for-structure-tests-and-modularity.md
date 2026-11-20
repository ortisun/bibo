# 0030: A change may not make the code worse: a quality ratchet on structure, test strength and modularity, measured on every job

- Status: **Proposed on 2026-11-20, pending the owner's decisions listed at the end.** Nothing is built. The design is in [quality-ratchet.md](../architecture/quality-ratchet.md).
- Date: 2026-11-20
- Deciders: the owner asked for the code and practices that give the best, best tested and most modular software; the engineer wrote the design.
- Related: [ADR 0003](0003-sandbox-strategy.md) (the verify sandbox), [ADR 0008](0008-artifact-store-and-evidence-ledger.md) (evidence documents), [ADR 0010](0010-failure-escalation-routing-and-invalidation.md) (rework limits), [ADR 0011](0011-canonical-time-and-numbers.md) (integers), [ADR 0021](0021-troubleshooter-agent-and-mcp-sources.md) (issues written by code for a person to triage), [architecture overview](../architecture/overview.md) (the deferred `quality` crate), [threat model](../security/threat-model.md) (the residual risk of weak tests).
- Numbering note: records 0022 to 0029 exist on other branches that are not merged into `develop` yet. This record takes the next free number so that the numbers stay monotonic when they meet.

## Context and problem statement

The owner asked (in Portuguese, 2026-11-20) for the factory's code and practices to be the ones that produce the best, best tested and most modular software. Three outside sources were read for this record. The first is a measurement study, the other two are collections of practice:

1. **SlopCodeBench** (Orlanski and others, arXiv 2603.24755, version 2 of 2026-05-07). Coding agents extend their own code over 3 to 8 checkpoints of a task. The study finds that passing tests hide a steady decay of the code.
2. **12-factor-agents** (HumanLayer, last commit 2025-09-21). Its principles for building agents as mostly deterministic software with small model steps.
3. **antislop** (Miqdad Badjuber, MIT, last commit 2026-11-20). A rulebook against generic output of coding agents. Most of it is about web pages and copy, and one part is about code comments.

The study measured what the factory has not:

- No agent solved any problem end to end. The best one passed 14.8 percent of checkpoints when every earlier test also had to keep passing.
- Structural erosion rose in 77 percent of trajectories and verbosity in 75.5 percent. Agent code was 2.3 times as verbose and 2.0 times as eroded as 473 open source Python repositories, and it got worse 5 to 7 times faster per change than human repositories.
- The share of passed tests that the specification names fell from 64.6 to 35.5 percent across a trajectory. The behavior that was asked for is the behavior that broke later.
- Edits got smaller late in a trajectory (from 97.4 to 29.5 percent of lines changed), while duplication grew 96 percent. Agents patched locally instead of restructuring. One `main` function went from a cyclomatic complexity of 13 to 92 in eight checkpoints.
- A prompt that lists the patterns to avoid cut the starting erosion by up to 62.3 percent and verbosity by up to 34.8 percent. It did not stop the decay, it cost 2.4 points of pass rate and about 12 percent more spend.
- The cost of a checkpoint grew 2.2 times over a trajectory, and the size of the code predicted cost (correlation 0.502) better than erosion did. Erosion did not predict the next checkpoint's pass rate (correlation −0.018).

The factory today:

- **Already has what the study's harness has.** A fresh container per run with only the workspace carried forward (ADR 0003). The whole test suite compared with a run of the base commit, so a broken earlier behavior fails. Tests that may not be removed, skipped or weakened (`gates/scope/weakening.rs`). Lints that may not be relaxed (`gates/scope/lint.rs`). A reviewer who never sees the builder's own account.
- **Measures nothing about the shape of the code.** No gate reads complexity, duplication or verbosity. None reads how much of the new code the tests run, whether they would notice a wrong line, or how the modules depend on each other. The reviewer prompt names "maintainability" in one sentence, and the study shows that a judgment in a prompt does not hold the line.
- **Plans a home for this.** The architecture overview lists a `quality` crate that is not created yet, to be extracted "when the gate catalog needs tool-specific dependencies (static analysis, mutation, fuzzing)". The threat model names "mutation testing for high-value code" as a way to reduce the residual risk of tests that assert nothing.

The question: how does the factory make every change it delivers leave the code at least as well structured, as well tested and as modular as it found it? The answer must use evidence a model cannot talk its way past, and stay correct to the last integer.

## What was checked

On 2026-11-20.

- **The study**, from its arXiv abstract page and its HTML version 2 (read through a fetch agent). About the last 5,700 characters of the appendix were not read. The numbers above are from the abstract, Table 1 and the result sections. The paper has two small inconsistencies of its own (the core pass rate attributed to two different models, and "up to a third" against "up to 62.3 percent" for erosion). Only Python was evaluated, and the comparison with human repositories is not a controlled experiment. **Verified from the paper, not reproduced.**
- **12-factor-agents**, from the README, the twelve factor pages and the appendix on pre-fetching context, read raw from GitHub. The images of factor 12 and the draft agent-to-human specification were not read. **Verified from the pages.**
- **antislop**, from the README, `antislop.md` and the five skill files, read raw from GitHub. The repository enforces nothing in a user's project: its "Delivery Gate" is a report the agent writes about itself. It publishes no measurement of its effect. **Verified from the files.**
- **This repository** at `develop` (5b5dcbe). Read: the gate modules under `crates/workflow/src/gates` and the gate report schema, with its `baseline_comparison` that already says `improved` or `regressed`. Also the profile schema (`mandatory_gates`, `conditional_gates`, `tool_probes`) and the readability catalog (`fixtures/readability/rules.json`, with deterministic and reviewer rules). Also the baseline run of `REPOSITORY_INTELLIGENCE`, the builder and code reviewer prompts, and the deferred crate table.

Not verified: the current versions, licenses and output formats of the candidate tools named in the design. Their cost on the fixture repository is also unmeasured. Whether the measures move on real jobs of this factory is unknown until it is measured.

## Decision 1: measure in the verify sandbox, decide on the host

### Considered options

1. **Ask the reviewer agent to judge maintainability.** Free to build. Rejected: the study shows that guidance in a prompt improves the start and does not stop the decay. A judgment also cannot be repeated, compared between two commits or kept as a number over time.
2. **Parse the code on the host, in the control plane** (syntax-tree parsers linked into the workflow crate). One place, no sandbox round trip. Rejected: it puts parsers for every language, mostly written in C, on untrusted input inside the control plane. It also puts language code into the core ring, against the hexagonal rule of ADR 0002.
3. **Read the target repository's own continuous integration.** Rejected: its configuration is the repository's, not the factory's. Many repositories have none, and its results arrive after the pull request, not at the gate.
4. **Chosen: the language tools run in the verify sandbox, the decision runs on the host.** A profile names the measurement tools of its language. They are pinned in the verify image and probed like every other tool. They run at the base commit and at the head commit, with no network, from the trusted gate definitions. They write one normalized document per commit (`code-measures`, version 1). A new `quality` crate on the host reads both documents and computes every number and every verdict in pure integer code. Languages differ only in the tools that fill the document. The rules and the arithmetic are written once.

### Outcome

Option 4. This is the trigger the overview names for extracting the `quality` crate, so the gates live there and not in `workflow::gates`. The base commit's document is made once, in the baseline run of `REPOSITORY_INTELLIGENCE`, and stored under the hash of the base commit and of the gate definitions. The head commit's document is made in `VALIDATION`. A document whose paths or lines do not exist in the commit it claims to describe is refused, and the gate is `BLOCKED`. A tool that is missing or fails its probe also blocks. A gate that cannot measure never passes.

## Decision 2: three families of measures, kept apart

The study rejects composite scores such as the maintainability index, because one number hides which thing got worse. The factory keeps three gates, each with its own report, so a profile can require each one separately and a builder is told exactly what to fix.

| Gate | Answers | Measures (all integers, ratios in parts per thousand) |
|---|---|---|
| `code-structure` | Is the code harder to understand than before? | Erosion (the study's formula, below), functions above the complexity threshold, duplication, verbosity |
| `test-strength` | Do the tests run and check the new code? | Coverage of the added and changed executable lines, mutation score on those lines |
| `modularity` | Do the parts depend on each other more badly than before? | New dependency cycles between modules, new edges that break a layering rule the project declares |

Erosion is the study's measure, written in integers so that it has one exact value. Each function gets a mass: its cyclomatic complexity times the integer square root of a million times its source lines. Erosion is the share of all mass held by functions above the threshold, in parts per thousand, rounded down. The threshold is 10 by default, the convention the study uses. Verbosity is the share of lines that a deterministic rule of the catalog flags or that belong to a duplicate, also in parts per thousand. The exact definitions, a worked example and the boundary rules are in the [design](../architecture/quality-ratchet.md#the-arithmetic).

## Decision 3: a ratchet against the base commit, not a fixed bar

### Considered options

1. **Fixed thresholds for the whole repository** (for example, erosion below 400 parts per thousand). Simple to state. Rejected: a repository that is already above the bar could never take a change. A repository far below it could get worse for years without a word. The study's human repositories averaged 340 parts per thousand of erosion, so no single bar fits every project.
2. **Report the measures and let a person decide.** Rejected as the whole answer: the study's point is that decay is gradual and that nobody reads trend numbers on every change.
3. **Chosen: a ratchet.** A change fails only for what it makes worse in the code it touches. Existing debt never fails a change, so a legacy repository can adopt the gates on its first job. The trend of the whole repository is recorded on every job and raises a warning, never a failure.

### Outcome

A change fails the gate when, in what it adds or changes:

- a function is new or got more complex and is above the complexity threshold;
- a run of lines appears twice or more in the head commit and includes an added line, where the base commit had fewer copies of it;
- an added line is flagged by a catalog rule whose severity is `block`;
- fewer than 900 parts per thousand of the added and changed executable lines ran under the tests;
- with at least 20 viable mutants on the changed lines, fewer than 800 parts per thousand of them were killed;
- the head commit has a dependency cycle that holds an edge the base commit did not have;
- the head commit has a dependency edge that a layering rule of the project forbids and the base commit did not have.

Every comparison is made on cross-multiplied integers, never on rounded ratios, so a rounding step cannot flip a verdict. The gate report's existing `baseline_comparison.delta` says `improved`, `none` or `regressed` for the repository as a whole. A failure goes back to the builder as rework, inside the existing rework limit, and a limit that is reached asks a person (ADR 0010). The numbers 900, 800, 20 and 10 are defaults pending the owner's confirmation.

Exclusions (generated code, vendored code, a parser table that is complex on purpose) are listed in the `quality` section of the project manifest at the protected base, each with a reason. There is no exclusion comment in the source: a builder could write one, and a builder cannot change the manifest.

## Decision 4: agents get the rules up front and the failures in a compact form

From 12-factor-agents (factors 3, 9 and 13) and the study's prompting result. A prompt helps at the start and does not hold the line, so it is used together with the gate, never instead of it.

- **Pre-fetched, deterministically** (factor 13). The builder's input gains `quality_hotspots`. These are the functions of the files its task owns that are already above the threshold at the base commit, with their numbers. The builder then knows before it starts that adding a branch to one of them will fail, and that it must split the function first. This is the study's failure mode (local patches on a growing function) turned into a rule known up front.
- **The rules, in the prompt.** The builder prompt gains a short list of the patterns the study and antislop name. They are one function doing several jobs, the same block copied for each option instead of a helper, and comments that restate the code. Decorative separators, end-of-block comments and vague to-do notes complete the list. Each is linked to the catalog rule that will check it.
- **Failures, compact** (factors 3 and 9). A failure names the path, the line, the function, the numbers before and after, and the fix the catalog suggests. A surviving mutant names its line and what was changed. No source text is copied into the report.
- **Judgment where measurement cannot reach.** Rules marked `reviewer` in the catalog become the code reviewer's maintainability checklist. Examples are a comment that restates its code, an abstraction with one user, and a name that hides what a function does. As with every gate, the reviewer's `PASS` cannot outweigh a failed measure.
- **Measured, not assumed.** The builder prompt's quality section is a variant that is tried on a share of jobs and kept only if it helps (see Decision 6). The study found that such guidance costs pass rate.

## Decision 5: the trajectory of each repository is recorded, and a person is asked to consolidate

The study's unit is a trajectory of checkpoints. For the factory, every job on a repository is one checkpoint.

- Every job stores a `quality-measures` evidence document (version 1) in the artifact store, cited by a ledger entry (ADR 0008). It holds the whole repository's measures at the head commit: erosion, verbosity, duplication, lines of code, functions above the threshold, the largest complexity, coverage, cycles, and the job's spend and changed lines. It also says how many test failures were regressions of earlier behavior and how many belonged to the new requirement, which the study shows must be told apart.
- A job that ended without a head commit counts as a failure in the flow measures and is left out of the quality measures. Nothing is imputed for it.
- A **consolidation proposal** is written when a repository's erosion or duplication rose on each of the last five jobs, or is 50 parts per thousand above its value at onboarding. The proposal is an issue in the target repository from a closed template, written by code, at most one open per repository, in the same way as the troubleshooter's triage issue (ADR 0021, Decision 7). It becomes work only when a person labels it. A consolidation job must keep every test green and every mutant killed that was killed before, and must lower the measure that triggered it.

When ADR 0029 (process metrics, on another branch) is accepted, these measures become entries of its catalog with their definitions. Until then the evidence documents are the record.

## Decision 6: the ratchet is proven on a run of checkpoints before it is called done

A gate that was only tested on single changes would repeat the mistake the study describes. Before the gates are required by a profile, the Rust word count fixture is extended into a trajectory of five issues that build on each other, with acceptance tests the builder does not see. The factory runs it with and without the ratchet. The gates are called done when both of these hold:

- with the ratchet, erosion and duplication do not rise across the five checkpoints;
- the share of checkpoints that pass with all earlier tests still passing is not lower than without it.

This trajectory is also the first evaluation of the deferred `evals` crate. The same gates run on this repository's own code in `scripts/ci.sh`, against the merge base with `develop`, so the factory holds itself to the rule it applies.

## Practices taken from the three sources, and where they land

| Source | Practice | Where it lands |
|---|---|---|
| SlopCodeBench | Measure the shape of the code over iterations, not only the pass rate | Decisions 2 and 5 |
| SlopCodeBench | Two separate signals, no composite score | Decision 2 |
| SlopCodeBench | Regression failures told apart from new failures; crashed runs not imputed | Decision 5 |
| SlopCodeBench | Hidden tests and a run of checkpoints as the benchmark | Decision 6 |
| 12-factor-agents, factors 3 and 9 | Own the context; compact errors fed back with a retry limit | Decision 4 |
| 12-factor-agents, factor 13 | Pre-fetch what the agent will certainly need | Decision 4 (`quality_hotspots`) |
| 12-factor-agents, factor 2 | Prompts are code with versions and evaluations | Decision 4 (measured variant), Decision 6 |
| antislop, code skill | Comment patterns that add nothing | Catalog rules, deterministic where a pattern can be matched and reviewer-only otherwise |
| antislop, Delivery Gate | A gate before delivery | Kept as a principle and made stronger: the factory measures and never takes an agent's own pass report |

## Owner decisions this record needs

1. **New tools in the verify image for Rust**, the first language, because the fixture and the factory are Rust. They are a complexity measurer, a structural search tool for the catalog rules and a coverage tool with the LLVM tools component. A mutation tester and a module graph reader complete the set. Candidates are named in the design. Each is a new dependency, and ADR 0009 says a new dependency needs a person's approval. *Recommended: approve, pinned by version and checksum through `scripts/setup-tools.sh` and the image rebuild.*
2. **The defaults.** Complexity threshold 10 and a duplicate window of 6 lines. Changed-line coverage of 900 parts per thousand, and a mutation score of 800 parts per thousand from 20 viable mutants. At most 200 mutants per run, chosen deterministically from the job identifier when there are more. A consolidation proposal at 5 rising jobs, or at 50 parts per thousand above onboarding.
3. **When the gates start to fail jobs.** *Recommended: the rules on new and changed code fail from the first job, because a ratchet cannot hurt existing debt. The repository trend only warns.*
4. **Whether the factory may open a consolidation issue in a target repository.** This is a new write with an `issues: write` token for that repository. *Recommended: yes, from the closed template, at most one open per repository.*
5. **Whether the same gates run on this repository in `scripts/ci.sh`.** *Recommended: yes.*

## Consequences

Good:

- A repository's structure, test strength and modularity cannot get worse through the factory without a failed gate, and existing debt never blocks a change.
- Weak tests, the residual risk the threat model names, become measurable: a test that asserts nothing kills no mutant.
- The measures give the factory and its owner the trajectory the study says is invisible in pass rates.
- New languages are a profile, pinned tools and catalog rows. The arithmetic and the rules are written once.

Costs:

- Mutation testing is the expensive part. A run is bounded by the mutant cap and the gate's time limit, and its cost on real jobs is unmeasured.
- Five new tools in the verify image, each to pin, probe, rebuild and keep current.
- More rework rounds at first. The study saw guidance cost 2 to 4 points of pass rate. Decision 6 is there to see whether the ratchet does the same.
- Coverage and mutation results come from running the builder's code, so they can be forged in the same way a test report can. A test can detect that it runs under a mutant and fail on purpose. The threat model will gain an entry for this when the gates are built, with the reviewer, the weakening gate and the hidden acceptance tests of Decision 6 as mitigations. Measures from static reading (structure, duplication, modularity) do not run the builder's code.
- Two new schemas (`code-measures` and `quality-measures`) and two additive changes (`quality_hotspots` in the builder input, the `quality` section of the project manifest), each with a version note.

Not decided here: hidden acceptance tests written by an agent separate from the builder for every job. Decision 6 uses them for the evaluation only. Making them part of every job adds a stage, so it needs its own record. Also not decided: the gates of a web capability pack, which belong to the pack's own record. They would check contrast, keyboard use, page semantics and layout at each width (antislop rules 3, 25, 27, 32, 39 and 40).
