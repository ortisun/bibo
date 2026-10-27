# Architecture decision records

One decision per file, in the order they were made. The format follows MADR: context, considered options, outcome, consequences. Each record names its status and says what was verified and what was not.

This directory is `docs/adr/`, as the master prompt's workspace layout (section 14) specifies. The harness default is `docs/adrs/`. If the project later moves to the harness convention, rename the directory in one commit and update the links.

| Number | Decision | Status |
|---|---|---|
| [0001](0001-orchestration-engine.md) | Orchestrate with a narrow PostgreSQL durable state machine. Temporal is not integrated. | Accepted |
| [0002](0002-workspace-layout-and-dependency-rule.md) | Hexagonal workspace in four rings. Twelve library crates and four binaries in Slice 1. | Accepted |
| [0003](0003-sandbox-strategy.md) | Hardened ephemeral containers under a supervisor, a masked git workspace, two ports, labelled fakes. Aligned with the security sandbox policy. | Accepted, revised 2026-10-27 |
| [0004](0004-event-model.md) | Transactional outbox to NATS JetStream, at-least-once, idempotent consumers. Outbox written in Slice 1, relay in Slice 2. | Accepted |
| [0005](0005-agent-runtime-adapter-boundary.md) | `AgentRuntime` port with probed Claude Code and Codex adapters that run inside the sandbox behind a model broker. API keys, not subscription logins. | Accepted; location and credentials decided by default, pending confirmation; open spike |
| [0006](0006-spec-kit-boundary.md) | Spec Kit only in the specification stage, behind the `spec_adapter` anti-corruption layer. Revision, checklist and argument handling need a spike. | Accepted, revised 2026-10-27; open spike |
| [0007](0007-persistence-access-and-tenancy.md) | Diesel with `diesel-async`; tenant on every row and every call. | Accepted |
| [0008](0008-artifact-store-and-evidence-ledger.md) | Content-addressed artifacts and a hash-chained, append-only evidence ledger. | Accepted |
| [0009](0009-operating-defaults-pending-confirmation.md) | Six operating defaults: agent in the sandbox, API keys behind a broker, L0 without rulesets, human approval for new dependencies, named requester allowlist, two rework rounds. | Decided by default, pending human confirmation |

## Rules for this directory

1. Write an ADR for a choice that is costly to reverse or that a future maintainer will ask about. Skip naming and library micro-choices.
2. A record needs at least two real options, the reason each lost, and at least one cost of the chosen one.
3. Accepted records are not edited in substance. To change a decision, write a new record and set the old status to `Superseded by NNNN`. Fixing a typo or a broken link is fine.
4. State what was checked, with dates and sources, and what was not. Mark every external claim as verified or unverified.
5. A record changes in the same pull request as the code it governs.
6. Keep the numbers monotonic and the file names `NNNN-kebab-title.md`.
7. Mirror each accepted record into project memory with `save_decision`, using the number and title, and keep this table current.
