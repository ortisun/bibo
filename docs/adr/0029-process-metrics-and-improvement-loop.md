# 0029: The factory measures its own process, records the numbers in the knowledge base, and improves itself under evidence

- Status: **Decided by the owner on 2026-11-20**: the owner confirmed the decisions listed under "Decisions the owner confirmed on 2026-11-20". Built: the arithmetic of Decision 2, the metric catalogue, the snapshot of nine metrics from stored facts with its route and command (four of them since the facts of the pull requests, the attempts and the task runs are stored: the section "Where the facts of query version 2 are stored" of the design weighs the options), and the rules of tier A experiments. Not built: writing the entries into a knowledge base, a schedule, applying a tier A setting to a job, the retrospective agent and the sweeps. The table "What is built and what is not" of the design has the detail. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the owner set the goal; the engineer weighed the options.
- Related: [ADR 0011](0011-canonical-time-and-numbers.md) (canonical numbers), [ADR 0013](0013-telemetry-wiring.md) (telemetry), [ADR 0027](0027-capability-packs.md) (packs and their evaluation), [ADR 0028](0028-project-knowledge-base.md) (the knowledge base), the master prompt section 12 (learning, evaluation and cost engineering), [observability conventions](../observability/conventions.md). The design is in [process-metrics-and-improvement.md](../architecture/process-metrics-and-improvement.md).

## Context and problem statement

The owner asked (in Portuguese, 2026-11-20) for three things on top of the knowledge base:

1. Metrics, statistics and numbers that show where the process can get better.
2. All of it as part of the knowledge base.
3. Through the knowledge base, improve the whole development process automatically and make development, testing and deployment faster.

The factory already emits operational metrics (stage durations, gate failures, retries, spend) to VictoriaMetrics, and keeps every attempt, decision and cost in PostgreSQL and the evidence ledger. Nothing turns those into numbers a person or an agent can act on, nothing compares one way of working with another, and nothing records what was tried and what it changed.

The master prompt sets two limits that this record keeps: "no autonomous prompt/model promotion based only on self-scored results; require measured improvement and approval policy", and "rollback any change that degrades validated outcomes". Agents may never change a policy or a gate file.

## Decision 1: where the numbers live

### Considered options

1. **Only in dashboards** (VictoriaMetrics and Grafana-style views). Good for operations. Rejected as the whole answer: dashboard numbers are floating point, sampled and short-lived, nobody reviews them, and an agent cannot read them as knowledge.
2. **Every raw number in the knowledge base.** Rejected: thousands of rows a day in Markdown, in the project's repository, is noise for people and churn for pull requests.
3. **Three layers** (chosen):
   - **Raw facts** stay where they are written: PostgreSQL rows and the evidence ledger are the source of truth for every number; VictoriaMetrics stays the operational view.
   - **Definitions** of every metric go into the knowledge base as entries of kind `metric`: what is counted, the unit, the formula, the rounding rule, the valid range and the minimum sample size.
   - **Snapshots and improvements** go into the knowledge base as entries of kind `measurement` (a dated report computed from the raw facts at a stated commit and window) and `improvement` (a hypothesis, the change, the measured before and after, and the decision).

### Outcome

Chosen: **option 3**. The knowledge base holds what a person or an agent needs to reason about the process; the database holds the facts that prove it. Every number in a snapshot names the query version and the window it came from, so it can be recomputed.

**Cost:** a snapshot job and its pull requests; snapshots are only as fresh as their schedule (weekly by default).

## Decision 2: how numbers are computed so that they are right

The owner's rule puts calculation errors first. Every metric follows these rules:

- **Integers, never floating point, in the computation.** Durations in milliseconds as `u64`; money in micro United States dollars as `i64` (one dollar is 1 000 000), taken from the broker's metering in the database, not from the floating-point counter `factory_spend_usd_total`; counts as `u64`; every sum with checked arithmetic, and an overflow is an error, never a wrap.
- **Ratios as two integers.** A rate is stored as a numerator and a denominator and only divided for display.
- **Stated rounding.** Display rounds half to even, to one decimal place for percentages and to whole milliseconds for durations, at the last step only.
- **Percentiles by nearest rank** over the exact sorted samples of the window, not from histogram buckets.
- **Minimum sample.** A metric with fewer samples than its stated minimum (20 by default) is shown as "too few samples", never as a number.
- **Comparisons with uncertainty.** A before-and-after comparison of a rate reports a Wilson score interval at 95 percent; a comparison of durations or costs reports the difference of medians with a bootstrap interval from a fixed seed. A change counts as an improvement only if the interval excludes zero in the right direction.
- **Ledger limit.** Every integer written to a ledger entry stays within 2^53 - 1 (ADR 0011).

Every formula has tests at zero, one, the maximum, negative input where the type allows it, and the rounding edge.

**Revision note, 2026-11-21.** Building the arithmetic made two points of this decision precise; neither changes it. The interval of a difference of two rates is Newcombe's hybrid score interval, which is built from the two Wilson intervals. The normal quantile is the conventional 1.96. The exact rules are in the section "How each number is computed" of the [design](../architecture/process-metrics-and-improvement.md).

## Decision 3: how far the improvement is automatic

### Considered options

1. **Fully automatic.** The factory changes its own prompts, models, packs, gates and policies when its numbers say so. Rejected: the master prompt forbids promotion on self-scored results, an agent that can weaken a gate to make its numbers look better is the failure the gates exist to stop, and a regression would reach every project at once.
2. **People only.** The factory reports numbers and people decide everything. Safe, but slow, and it does not meet the owner's goal.
3. **Automatic up to the point where risk begins, in three tiers** (chosen):
   - **Tier A, reversible operational settings, promoted automatically with automatic rollback.** Examples: which tests run first, how many tasks run in parallel, cache use, which model tier starts a task of a known kind when both tiers already passed the evaluation, the order of independent reviewers. A tier A change runs as a controlled experiment on a share of jobs, is promoted only when Decision 2's comparison shows an improvement and no guard metric (escaped defects, gate failure rate, human rejections) worsens, and is rolled back automatically if a guard metric worsens later. Every promotion and rollback is an `improvement` entry and a ledger entry.
   - **Tier B, behaviour of agents, proposed automatically, approved by a person.** Examples: a prompt change, a new or changed skill, a pack's evaluation cases, the default model of a role. The factory drafts the change, runs it against the held-out evaluation suite, and opens a draft pull request with the measured before and after. A person approves.
   - **Tier C, policies, gates, security and approvals, never changed by the factory.** The factory may open an issue that describes a pattern it measured ("gate X failed 40 times for one cause"); a person decides.

### Outcome

Chosen: **option 3**. It makes the common, safe improvements fast and keeps every change that could weaken the factory's own checks in human hands.

**Cost:** the experiment machinery (a share of jobs on a variant, guard metrics, rollback) is real work, and tier A settings must be declared one by one with their safe range.

## Decision 4: what the knowledge base does to make the work faster

These are the mechanisms, each measured by a metric of the catalogue, so the claim "faster" is checked and not assumed:

1. **Less rediscovery.** The relevant knowledge block (ADR 0028) gives agents the features, flows and rules a task touches. Measured by tokens and tool calls per task, before and after.
2. **Targeted tests.** Entries name the tests that enforce each rule and the code paths of each feature. Together with the change's paths, they give a test selection to run first; the full suite still runs in the gate. Measured by time to first failing test and by escaped defects.
3. **Known slow and flaky tests.** The measurement snapshots list the slowest tests and the tests whose result changed without a code change. A flaky test is reported to a person as an issue (tier C: the factory never skips a test on its own).
4. **Learned playbooks.** When the same kind of task succeeds repeatedly with the same steps, the factory proposes a skill for the pack (tier B).
5. **Deployment.** Deployment stays outside the factory's loop, as the master prompt requires. Where a project deploys through its own pipeline, the factory reads, read-only, the four delivery measures (lead time for changes, deployment frequency, change failure rate, time to restore service) and records them in the snapshots, so a slow or risky deployment process becomes visible.

## Decision 5: retrospectives and scheduled sweeps

Two more sources of improvement, both ending in something a person decides.

1. **A retrospective on finished jobs.** A `retrospective` agent reads the recorded run of a job after it ends (the stage outcomes, gate reports, rework rounds, tool-call records and the person's review comments, all already stored as evidence) and proposes changes to skills, prompts or knowledge entries. It is tier B: its output is a draft pull request against the pack or the knowledge base, measured against the held-out evaluation suite, and a person approves. It runs on a sample of jobs and on every job that needed rework or was rejected, under a daily budget of its own.
2. **Scheduled sweeps of a project.** On a schedule the project's owner sets, the factory looks through the project for one named concern (performance, security, dead code, stale documents, knowledge drift) and records what it finds. Options weighed for the result: opening pull requests directly was rejected, because every job of the factory belongs to an issue a person accepted (FR-001, functional requirement 1 of the Slice 1 specification), and unrequested pull requests in bulk are hard to review. Chosen: a sweep opens **issues for triage**, as the troubleshooter does, each with its evidence; an issue becomes factory work only when a person labels it.

## Decision 6: whose numbers go where

- A **project's** numbers go into that project's knowledge base: its jobs, its tests, its defects. They never include another tenant's data.
- The **factory's** numbers across projects (per agent, per pack, per model) go into the factory operator's own knowledge base, aggregated, with no project name, path or text, and only when at least five projects contribute to a number, so no single project can be recognised from it.

## Decisions the owner confirmed on 2026-11-20

1. Raw numbers stay in the database; definitions, snapshots and improvements go into the knowledge base (Decision 1).
2. The three tiers, and in particular that the factory never changes its policies, gates or approvals itself (Decision 3).
3. A weekly snapshot by default.
4. Retrospectives propose by pull request and sweeps open issues for triage; neither starts work on its own (Decision 5).
5. Merging stays with a person. A project may want low-risk pull requests merged automatically when measurable budgets hold (a frame-rate budget, a load-size budget). The pack gates of ADR 0027 produce exactly those measurements, but the choice to merge without a person belongs to the approval policy and its autonomy levels, which the factory never changes itself. It is the owner's decision and is not taken here.

## What was not verified

- That any of the mechanisms of Decision 4 makes a real job faster. Each is a hypothesis until its metric moves on real jobs.
- The size of the samples a small project produces in a week; many metrics may stay "too few samples" for a long time, and a monthly window may be needed.
