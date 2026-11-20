# Agentic practices the factory follows

- Status: first version, 2026-11-20. It records choices of three architecture decision records (ADR): [ADR 0027](../adr/0027-capability-packs.md), [ADR 0028](../adr/0028-project-knowledge-base.md) and [ADR 0029](../adr/0029-process-metrics-and-improvement-loop.md), which the owner confirmed on 2026-11-20 and which are not built.
- Form: reference.
- Goal: say which practices of the field the factory uses, which it is trying, and which it avoids, with the source and the date of each.
- Review: at least once a quarter, and whenever a new model, a new revision of the Model Context Protocol (MCP) or a new host tool arrives. The next review is due by 2027-02-20.

## How to read the status

| Status | Meaning |
|---|---|
| Adopted | The factory does this, or a decision record commits it to. |
| Trial | Worth trying on a share of jobs, with a metric that decides. |
| Assess | Worth watching. Nothing is planned. |
| Hold | Not used, with the reason. |

A practice moves up only with evidence: a passed evaluation suite or a measured improvement. Being new is not a reason. This is the rule of the Method Registry in the master prompt.

## Workflow and orchestration

| Practice | Status | Where and why |
|---|---|---|
| A fixed workflow where the steps are known, an agent only inside a step | Adopted | The pipeline is a durable state machine (ADR 0001). Agents do not decide the order of stages. |
| Orchestrator and workers | Adopted | The planner writes a task plan and builders each take one task. The orchestrator is code, not a model. |
| Routing to a specialist by the content of the task | Adopted | The composer of ADR 0027 picks pack agents by touched paths, task kind and risk tier. |
| Parallel independent reviewers | Adopted | Reviewers of a pack run beside the code reviewer and never see the builder's summary. |
| Evaluator and optimizer loop with a hard limit | Adopted | Rework rounds are counted for each phase and capped at two (ADR 0022). Gates give pass or fail results, not opinions. |
| A critic on a different model from the author | Adopted | The model routing policy forbids the architect's model for the critic. |
| Minimum sufficient team | Adopted | A specialist runs only when its trigger matches. More agents cost more and do not mean better work. |
| Free delegation between agents | Hold | The delegation depth is zero. An agent that starts agents is hard to bound and to audit. |
| Agents that grant themselves tools | Hold | Only the policy engine grants tools. |

## Context

| Practice | Status | Where and why |
|---|---|---|
| Untrusted text in a marked data envelope, never as instruction | Adopted | Every prompt (see `agents/README.md`). |
| Skills loaded on demand (progressive disclosure) in the Agent Skills format | Adopted | ADR 0027, Decision 5. The model sees a name and a description and reads the body when it needs it. |
| A small, selected block of project knowledge for each task | Adopted | ADR 0028, Decision 4. Selected by links, by code. Giving a model everything makes it worse, not better. |
| Knowledge kept as reviewed files in the project's repository | Adopted | ADR 0028, Decision 1. |
| Search by full text and by links | Adopted | ADR 0028, Decision 4. |
| Semantic search with embeddings | Trial | ADR 0028, Decisions 4 and 6. Needs a local embedding model. Decided by whether full-text search misses entries that matter. |
| Knowledge drawn from chat tools and meeting notes | Trial | ADR 0028, Decision 3. Off by default, one source at a time, because the text goes to the model provider. |

## Tools and the Model Context Protocol

| Practice | Status | Where and why |
|---|---|---|
| Servers behind a gateway that holds the credentials and offers a closed tool list | Adopted | ADR 0027, Decision 6. |
| Local servers with no credential and no network, from a pinned image | Adopted | ADR 0027, Decision 6. |
| Servers and skills installed from a public marketplace at run time | Hold | ADR 0027, Decision 2. A skill is text the agent obeys. It enters only through a reviewed import with pinned bytes. |
| The protocol revision of 2026-07-28 (stateless requests, extensions, stricter authorization) | Assess | Not verified against the gateway. A short test must show which revision the gateway and each upstream server speak. |
| Write tools on outside systems | Hold | Off unless the security policy grants the tool to the role. Money, accounts and production are never grantable. |

## Evaluation and improvement

| Practice | Status | Where and why |
|---|---|---|
| Promotion of an agent, a prompt or a pack only by a held-out evaluation suite | Adopted | ADR 0027, Decision 7. |
| Exact integer arithmetic for every process number, with a minimum sample | Adopted | ADR 0029, Decision 2. |
| Controlled experiments with guard metrics and automatic rollback, for reversible settings | Adopted | ADR 0029, Decision 3, tier A. |
| A retrospective agent that reads finished runs and proposes better skills | Trial | ADR 0029, Decision 5. Its proposals are pull requests a person approves. |
| Scheduled sweeps that open issues for triage | Trial | ADR 0029, Decision 5. |
| Pull request bodies built from measured evidence, with the risk stated | Adopted | The extension point `delivery.evidence` of ADR 0027. |
| Automatic merge of low-risk changes | Assess | The owner's decision, under the approval policy. The factory does not merge today. |
| The factory changing its own policies or gates | Hold | ADR 0029, Decision 3, tier C. |

## Sources

Read on 2026-11-20. Blog posts are opinions of their authors. Where a claim was not checked against a primary source, the decision record says so.

| Source | Used for |
|---|---|
| [The 2026-07-28 MCP specification](https://blog.modelcontextprotocol.io/posts/2026-07-28/) and its [list of changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog) | The state of the protocol. |
| [Agent Skills as an open standard](https://www.ahood.dev/blog/agent-skills-open-standard) and [the SKILL.md format](https://www.agensi.io/learn/agent-skills-open-standard) | The skill format and its limits across host tools. Secondary sources. |
| [Design patterns for agentic workloads](https://orchestrator.dev/blog/2026-10-09-agentic-workload-design-patterns/) and [orchestration patterns in production](https://www.requesty.ai/blog/multi-agent-orchestration-patterns-that-work-in-production) | The workflow patterns. Practitioner blogs; their cost figures are not used. |
| [SurrealDB releases](https://surrealdb.com/releases) | The current version line of SurrealDB. |
| ["You Shouldn't Be Coding Anymore. You Should Be Building a Factory."](https://www.youtube.com/watch?v=nwMNQJ_Wtw8), Web Dev Cody, 2026-11-05 | The owner's reference. Ideas taken from it: people work at the input and at the review of the factory; the pull request body carries the evidence and the risk; a retrospective improves the skills; outside context joins the knowledge base through MCP, with care for private data; scheduled sweeps; merging by risk. |
