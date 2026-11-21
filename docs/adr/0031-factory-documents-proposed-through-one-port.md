# 0031: The factory proposes its own documents in a project through one port, from a closed set of branches

- Status: **Proposed on 2026-11-21**, pending the owner. Built on the branch `feature/knowledge-measurements`.
- Date: 2026-11-21
- Deciders: the owner set the goal (a weekly snapshot in each project's knowledge base, ADR 0029, confirmed decisions 1 and 3); the engineer weighed the options.
- Related: [ADR 0026](0026-project-rules-installed-by-pull-request.md) (the rules pull request and its port), [ADR 0028](0028-project-knowledge-base.md) (the knowledge base), [ADR 0029](0029-process-metrics-and-improvement-loop.md) (the snapshot). The port is specified in [ports v1.6](../architecture/ports-v1.6.md); the design is the section "The weekly measurement pull request" of [process-metrics-and-improvement.md](../architecture/process-metrics-and-improvement.md).

## Context and problem statement

ADR 0029 puts each project's weekly snapshot into that project's knowledge base, and ADR 0028 says knowledge changes only by a pull request a person merges. The factory already writes one document of its own into a project: `AGENTS.md`, by the draft pull request of ADR 0026, through the port `ProjectRulesHost`. That port is built for one branch, `factory/project-rules`, and its marker carries a template version. The snapshot needs a second branch and a marker that names a week.

## Decision 1: one port or two

### Considered options

1. **A second port** (`KnowledgeHost`) with the same four operations and its own branch. No change to a reviewed port. Rejected: two adapters, two fakes and two contract suites for the same four GitHub calls, and every later document the factory proposes (a harvest at onboarding, a playbook) would add a third.
2. **Put the snapshot into the rules pull request.** One pull request for everything the factory writes. Rejected: the rules pull request is driven by the template version, a person who declines a version would also decline the numbers, and one review would mix a rule change with a weekly report.
3. **Generalize the rules port into a proposal port over a closed set of branches** (chosen). `ProposalHost` takes a `ProposalBranch`, an enum with one variant for each document the factory proposes: `ProjectRules` (`factory/project-rules`) and `KnowledgeMeasurements` (`factory/knowledge-measurements`). Each branch has its own marker form. The adapter still writes only to branches the enum names, so the security property of ADR 0026 (the factory writes to no branch but its own, never to the default branch, never merges) stays one rule that a test can check.

### Outcome

Chosen: **option 3**. A new document of the factory is a new variant and a marker form, not a new port. **Cost:** a revision of a reviewed port (renames in the port, the adapter, the fake, the contract suite and the rules check), and a pull request on GitHub stays tied to the one branch it comes from, so one document can have one open pull request at a time.

## Decision 2: when the snapshot runs

### Considered options

1. **A separate program on a schedule** (like the troubleshooter's). Rejected for now: a second program to deploy for a weekly task that needs the same store and GitHub credentials the worker already holds.
2. **When a job ends.** Rejected: a week with many jobs would propose many times, and a week with none never.
3. **In the worker, before a claim, like the rules check** (chosen). At most once an hour for one tenant, the worker looks at the last whole ISO week (Monday 00:00 UTC to the next Monday). A repository whose week is already proposed is left alone, so the GitHub calls happen once a week for each repository.

### Outcome

Chosen: **option 3**. **Cost:** a worker that never claims never proposes; a factory with no work has nothing to measure either.

## Decision 3: what one pull request holds

### Considered options

1. **One pull request for each week.** Rejected: GitHub refuses a second open pull request from the same branch, and a branch per week is not a closed set.
2. **Replace the open pull request with the newest week.** Rejected: a week nobody merged yet would be lost.
3. **One open pull request that gains each new week** (chosen). When the pull request of an earlier week is still open, the new week's entry and its line in the index are added on top of it, and its title and body name the newest week. A merged pull request is followed by a new one. A pull request a person closed without merging declines the weeks it held; the next week is proposed again.

### Outcome

Chosen: **option 3**. The index is read from the head of the open pull request when there is one, and from the default branch otherwise, so no week already proposed is dropped. **Cost:** an unreviewed pull request grows by one file a week; its body says how many weeks it holds.

## Decision 4: which projects get it

- Only a repository that is enabled, whose default branch has `docs/knowledge/README.md`: the project accepted the knowledge base (the rules pull request of template version 2 adds it). A repository without it gets nothing, so the two pull requests of the factory never create the same file.
- Only for a week with at least one sample of a measured metric in that repository. A week with no work says nothing worth a pull request.
- Missed weeks are not proposed later. A worker that did not run for a month proposes the last whole week only.
- The switch `github.propose_knowledge_measurements` turns it off; it is on by default, as ADR 0029 confirmed a weekly snapshot by default.

## What was not verified

- Against the real GitHub: none of it. The adapter calls are those of ADR 0026, tested against the fake GitHub server of the test kit.
- That people of a real project read a weekly pull request of numbers. It must be watched on the first real projects.
