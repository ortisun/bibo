# Ortisun Software Factory Constitution

## Core Principles

### I. Spec Kit governs specification only

The official GitHub Spec Kit MUST be the only mechanism that authors the constitution, feature
specifications, clarifications and requirement-quality checklists. Its plan, tasks, analyze,
implement, converge and tasks-to-issues capabilities MUST NOT be used as the delivery pipeline;
they MAY be enabled only through an explicit, audited compatibility setting. The factory MUST
integrate with the installed Spec Kit version and its real invocation syntax, and MUST NOT invent
commands. Spec Kit artifacts MUST keep their original format, and a separate specification gate
MUST read them.

Rationale: one authoritative specification mechanism avoids drift, and a separate gate keeps
the delivery pipeline independent of the tool that authors requirements.

### II. Deterministic shell, probabilistic specialists

Code and policy MUST decide state transitions, authorization, timeouts, budgets, check execution,
ordering and merges. Agents interpret, design, write code and review. Agents MUST NOT change
factory state or merge on their own. A stage MUST advance only when its gate verifies evidence,
and MUST NOT advance because an agent reports success.

Rationale: model output is variable, so every consequential decision needs a reproducible,
auditable owner.

### III. Evidence-first completion

A claim of success without verifiable evidence (command output with exit status, a check report,
a diff, a commit or an artifact hash) MUST NOT count as success. A missing or skipped check MUST
be reported as blocked or not applicable and MUST NOT be reported as passed. A PASS state MUST
NOT be fabricated, and any mock or fake component MUST be labelled wherever it appears.

Rationale: reports that cannot be checked hide failures and erode trust in every other gate.

### IV. Untrusted data is never an instruction

Issue text, repository files, dependency contents, documentation, web pages, tool output and
model output MUST be treated as data, never as higher-priority instructions. The factory MUST
enforce tool allowlists, secret scanning, egress limits and scoped short-lived credentials. It
MUST keep the original untrusted text separate from the normalized request.

Rationale: separating data from instructions is the main defence against prompt injection and
credential leakage.

### V. Plain-English, human-readable artifacts

All human-facing text MUST be clear, professional English, whatever language the request arrived
in. Titles MUST be short, in sentence case, and describe a concrete outcome. Titles MUST NOT
contain opaque prefixes, ID chains or role labels. Immutable identifiers MUST live in metadata,
not in titles. A readability gate MUST flag violations and MUST NOT silently change requirements.

Rationale: people review and approve the work, so artifacts must be understandable without
decoding internal conventions.

### VI. Human gates and safe defaults

Auto-merge MUST be off by default. Auto-deploy MUST NOT be on by default. Merging and deployment
MUST require explicit human authorization or an explicit per-repository policy backed by
objective gates. Anything involving money, secrets, physical actuation or regulated workflows
MUST require explicit human approval.

Rationale: irreversible and high-impact actions need an accountable human or a pre-approved
policy that can be audited.

### VII. Independent verification

The agent that builds a change MUST NOT be the only judge of it. Reviewers and validators MUST
receive the frozen specification, the diff and verified evidence, and MUST NOT receive the
builder's self-justification. A builder MUST NOT edit protected tests, gate configuration, CI
workflows, security configuration or evaluation fixtures to make checks pass. Gate definitions
MUST come from protected, centrally managed sources.

Rationale: a builder grading its own work has a built-in incentive to pass; independence and
protected gates remove it.

### VIII. Versioned, immutable intent

An approved specification MUST be frozen and versioned with content hashes. A requirement change
MUST create a new revision and MUST invalidate the downstream plans, tasks, reviews and
documentation that depended on the earlier revision. Changes to this constitution MUST be tracked
and approved separately from feature requests.

Rationale: traceable, immutable intent lets every downstream artifact be tied to the exact
requirements it was built and verified against.

## Engineering and quality constraints

- The factory's own code MUST follow strict test-driven development, SOLID design and explicit
  design contracts at module boundaries.
- Real behaviour MUST be preferred over mocks. Fake adapters MUST be used only in deterministic
  tests.
- A real provider integration MUST NOT be claimed until a real adapter smoke test has passed;
  until then it MUST be marked blocked.
- Large artifacts MUST be stored by content hash.
- Sandboxes MUST be unprivileged, resource-bounded and network-restricted.
- The technical foundation MUST be the one stated in section 1 of the master prompt
  (`universal_agentic_software_factory_master_prompt.md`). Any deviation MUST be recorded in an
  architecture decision.

## Delivery workflow and quality gates

- Work MUST be delivered as verified vertical slices, with real checks run after each slice.
- Every stage MUST have a contract defining inputs, outputs, budget, timeout, evidence and a
  named gate.
- Documentation MUST be a mandatory stage with its own independent review and quality gate.
- Pull requests MUST stay in draft until validation and review thresholds pass.
- An unresolved failing check MUST block promotion.

## Governance

- Amendments MUST be proposed as a pull request and MUST receive explicit human approval.
- Each amendment MUST carry a version bump: MAJOR for removed or redefined principles, MINOR for
  added principles or sections, PATCH for clarifications.
- Every specification, architecture decision and pull request MUST be reviewed for compliance
  with this constitution.
- A justified exception MUST be recorded in an architecture decision.
- Runtime guidance lives in the documentation under `docs/` and in the master prompt.

**Version**: 1.0.0 | **Ratified**: 2026-10-27 | **Last Amended**: 2026-10-27
