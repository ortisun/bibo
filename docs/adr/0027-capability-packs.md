# 0027: The factory adapts to each kind of software through capability packs

- Status: **Decided by the owner on 2026-11-20**: the owner confirmed the decisions listed under "Decisions the owner confirmed on 2026-11-20". Nothing is built yet. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the owner set the goal; the engineer weighed the options.
- Related: the master prompt (sections on the domain capability profile registry, the Agent Registry and Capability/Skill Registry, and the Team Composer), [ADR 0005](0005-agent-runtime-adapter-boundary.md) (agent runtime boundary), [ADR 0006](0006-spec-kit-boundary.md) (pinned skills), [ADR 0019](0019-claude-code-and-codex-alike.md) (Claude Code and Codex alike), [ADR 0026](0026-project-rules-installed-by-pull-request.md) (project rules), the troubleshooter record on `origin/fix/agent-report-channel` (its MCP gateway, see "Dependencies"). The design is in [capability-packs.md](../architecture/capability-packs.md).

## Context and problem statement

The owner asked (in Portuguese, 2026-11-20) that every agent, workflow and skill of the factory be built with the best current practice in AI, agentic patterns and MCP, and that the factory be **modular**: a web product should get the agents it needs (a frontend engineer, for example), a game should get game agents, and a finance product should get the skills, agents and MCP servers that finance needs.

The master prompt asks for the same thing in other words: a versioned registry of domain capability profiles, an agent registry and a skill registry rather than a fixed list of agents, a Team Composer that picks the minimum sufficient team, and new domains added "without changes to core orchestration code".

What exists today:

- **Ten agents** in `agents/`, each with a manifest that already has `domains` and `skills` fields (both unused: every agent says `general-software` and no skills).
- **Two domain capability profiles** in `profiles/` (`general-software`, `rust-command-line-tool`), both drafts, with `required_skills` and `optional_skills` fields that are empty. Slice 1 resolves one static profile.
- **Skills**: only the Spec Kit skills, pinned by SHA-256 and mounted read-only into the user skill root of the specification stage. Every other stage runs with skills off.
- **MCP**: every job agent starts with `--strict-mcp-config` and no server. The troubleshooter (on `origin/fix/agent-report-channel`) added the first MCP use, through a gateway in the control plane that holds the credentials and offers a closed tool list.
- **Hooks already in the contracts**: a planned task has `required_specialist` (a role and its skills), the intake classifier returns `domain_tags`, the project manifest has `domain_tags`, and the approval policy has `extra_review` for named conditions.

So the pieces exist, but nothing bundles them, nothing selects them for a job, and nothing proves that a domain agent is good before it runs.

## What was checked

On 2026-11-20, through web search. These are external claims, **not verified against the primary specifications** unless marked.

- **MCP**: the current specification revision is dated 2026-07-28. Per the official MCP blog and changelog, it makes the protocol stateless (version, client identity and capabilities travel in each request), adds an extensions framework (long-running tasks, MCP Apps, enterprise-managed authorization), requires clients to validate the `iss` of an authorization response (RFC 9207), and deprecates dynamic client registration in favour of client ID metadata documents. The official MCP Registry holds metadata only and points at packages or remote URLs; one source says it is still a preview. One secondary source says Roots, Sampling and Logging were deprecated; no second source confirmed it.
- **Agent Skills**: Anthropic published Agent Skills (`SKILL.md` with YAML front matter, optional `references/` and `scripts/`) as an open standard in December 2025. Several sources say OpenAI's Codex reads the same format, which matches what this repository already measured: the Spec Kit install writes the same skills to `.claude/skills/` and `.agents/skills/` (ADR 0019). Host-specific fields (Claude Code `context: fork`, Codex `openai.yaml`) do not carry across. Adoption counts disagree between sources and are not used here.
- **Agentic patterns**: practitioner sources agree on a small set: start with the simplest pattern that works, prefer a deterministic workflow over a free agent where the steps are known, use orchestrator and workers, routing, parallel fan-out, and an evaluator-optimizer loop with binary, checkable criteria and a hard iteration cap, and trace every call. The cost figures in those sources come from single blogs and are not used.

The sources and the date of each are listed in [agentic-practices.md](../reference/agentic-practices.md).

## Decision 1: the unit of modularity is a capability pack

### Considered options

1. **Separate registries, no bundle.** Profiles, agents, skills and MCP servers each live in their own registry, and a job picks from each. Rejected: the parts of a domain change together (a game agent needs the game skills, the game gates and the game evaluation cases), so they would be versioned apart and could drift. A person adding "games" would have to edit four places and could forget one.
2. **A Claude Code plugin (or a Codex plugin) as the unit.** Plugins already bundle skills, agents, commands, hooks and MCP servers, and the ecosystem is large. Rejected as the internal unit: a plugin agent is a prompt with a tool list. It carries no input or output schema, no evidence requirement, no resource limits, no evaluation suite and no least-privilege paths, all of which the factory's manifest has and the policy engine needs. Plugin hooks and plugin MCP servers would also run inside the sandbox with whatever they declare, which the sandbox policy forbids (threat model: repository-resident configuration). And it would tie the factory to one host, against ADR 0019.
3. **A factory capability pack** (chosen): one versioned directory that bundles a domain capability profile, the agents (factory manifests), the skills (Agent Skills format), the MCP servers the pack may use, the gates, the evaluation cases and the documentation requirements. Each part keeps its existing contract. The pack adds a manifest that ties them together, a version and a review status.

### Outcome

Chosen: **option 3**, because the parts that change together then live and version together, the existing contracts (agent manifest, profile, policy) stay the enforcement points, and a pack can still be **exported** as a Claude Code or Codex plugin for people who work interactively (the design phase with EGM already works that way). Export is a later step, not part of this record.

The ten current agents and the `general-software` profile become the **core pack**, always active. They stay in `agents/` and `profiles/` for now; the loader treats those directories as the core pack, so nothing moves and no hash changes.

**Cost:** a new manifest kind, a loader, and a composer to build and test. Pack authors must learn one more file.

## Decision 2: where packs come from, and how far they are trusted

### Considered options

1. **Only packs written in this repository.** Safest, but the factory would ignore the large and fast-moving body of public skills and MCP servers, which is the "news of the market" the owner asked for.
2. **Install packs, skills or MCP servers from public marketplaces at run time.** Most current, but a skill is a prompt that the agent obeys and may carry scripts. Installing one at run time is a supply-chain path straight into the agent's instructions, with no review and no pinned bytes. Rejected.
3. **First-party packs in this repository, with a reviewed import for outside content** (chosen). Outside skills and MCP server images may be used, but only after an import that copies the bytes into a pack (or pins an image by digest), records the source, the licence and the date, and goes through a pull request like any code. At run time only pinned bytes are used, exactly as the Spec Kit skills are today.

### Outcome

Chosen: **option 3**. A pack lives in `packs/<pack-id>/`. Every skill file and every bundled script is pinned by SHA-256 in the pack manifest; a modified file blocks the worker, as a modified Spec Kit skill does. An MCP server image is pinned by digest. A remote MCP server is pinned by URL and by the list of tools the pack allows, and the gateway refuses any tool not on that list even if the server starts to offer it.

**Cost:** using a new public skill takes a pull request, not a click. This is the intended friction.

## Decision 3: how a job gets its packs

### Considered options

1. **The model chooses.** The intake classifier picks the packs it thinks fit. Rejected as the deciding step: a classifier reads the issue text, which is untrusted, so an issue could ask for a pack that grants more tools. Its choice would also not be reproducible.
2. **Only the project declares.** The project manifest (`.factory/project.yaml`, read from the protected base branch) lists its packs. Reproducible and reviewed by the project's owners, but a web project that adds a payment feature would not get the finance pack until someone edits the manifest.
3. **A deterministic composer over declared packs, with the model allowed to propose** (chosen). The project manifest declares packs (by domain tag or by id with a version range). The intake classifier may propose a domain tag the manifest does not declare. The composer activates a declared pack on its own; a proposed one waits for a person to confirm (the job goes to `NEEDS_HUMAN` with one question), and the confirmation is recorded.

### Outcome

Chosen: **option 3**. The composer is pure code, not an agent: it resolves the packs, their dependencies and their conflicts, picks the agents whose triggers match the task (touched paths, risk tier, task kind), and writes a **pack lock** for the job: each pack's id, version and manifest digest, and why each agent was selected. The lock goes into the evidence ledger, so a later reader can tell exactly which agents, skills and tools a job had. This follows the master prompt: the Team Composer derives the minimum sufficient team and logs why, and the deterministic policy engine, not an agent, approves tool grants.

**Cost:** a new domain that the project did not declare needs a person's yes once per job, or an edit to the project manifest.

## Decision 4: how a pack extends the pipeline

### Considered options

1. **A pack may add stages to the state machine.** Most flexible. Rejected: the state machine is proven against `state-machine.json`, persisted in database CHECK constraints and shared by every job. A pack that adds a stage changes core orchestration, which the master prompt rules out, and two packs could add conflicting stages.
2. **A pack contributes only at named extension points of the existing stages** (chosen). The engine keeps its stages. A pack may add: domain checklist items to the specification stage; an advisor or critic to the architecture stage; specialist builders that the planner can assign through `required_specialist`; extra independent reviewers that run in parallel in the review stage under the conditions the pack names; deterministic gates in the validation stage; documentation requirements to the documentation stage; evidence sections of the pull request body in the delivery stage (screenshots, measured budgets, the risk of the change).
3. **A pack ships its own workflow** (a sub-pipeline the engine calls). Rejected for now: it would need a second durable engine inside the first. Revisit if a domain needs a long, separate process (training a model for days, for example).

### Outcome

Chosen: **option 2**. The extension points are a closed list in the pack schema. A new extension point is a change to the engine and needs its own record.

**Cost:** a domain that truly needs a new stage cannot have it through a pack alone.

## Decision 5: how skills reach an agent

### Considered options

1. **Paste skill text into the prompt.** Simple and host-independent. Rejected: every skill would cost its full size in every run, and the prompt hash would change whenever a skill changes.
2. **Mount pinned skills read-only per run, in the Agent Skills format** (chosen). The runtime adapter mounts the skills the composer selected for that agent into the host's user skill root (Claude Code) or the Codex equivalent, the same way the Spec Kit skills are mounted today. The model sees each skill's name and description and loads the body only when it needs it (progressive disclosure), which keeps the context small.

### Outcome

Chosen: **option 2**. A skill is never a permission: a script bundled with a skill runs only through `exec.run` in the sandbox, under the agent's own grants. An agent sees only the skills its manifest lists and the composer selected, never all the skills of a pack.

**Cost:** the mount must be built for both hosts and checked by a negative test (an unlisted skill is not visible).

## Decision 6: how MCP servers reach an agent

### Considered options

1. **Each agent starts the MCP servers it wants, inside the sandbox.** Rejected: a server that needs a credential would put that credential in the sandbox, against the rule that the sandbox holds only its run token (ADR 0020), and remote servers would widen egress.
2. **Every MCP server goes through the gateway.** Uniform, but a credential-free local tool (a headless browser driver such as Playwright, a game engine running headless) would need a network path out of the sandbox for no gain.
3. **Two classes** (chosen):
   - **Sandbox-local servers**: no credential and no network, started over stdio inside the sandbox from an image pinned by digest. Example: a browser automation server in the `verify` sandbox for a web product's gates.
   - **Gateway servers**: anything that needs a credential or reaches the network (market data, observability, a design tool). The agent reaches them only through the factory's MCP gateway, which holds the credentials, offers a closed tool list per role, limits calls and bytes, redacts results and records every call.

### Outcome

Chosen: **option 3**. A pack declares each server with its class, its pin, and for each role the tools it allows and their access (`read` or `write`). Write tools on a gateway server are off unless the security policy allows that tool for that role; actions on money, accounts or production stay in `never_grantable`. The tool lists in a pack can only narrow what the policy allows, never widen it.

**Cost:** the gateway, built for the troubleshooter alone, must become a general part of the factory that serves job runs (see "Dependencies").

## Decision 7: what makes a pack agent good enough to run

### Considered options

1. **Trust the prompt.** Rejected: nothing in this repository has measured a real model following any prompt yet, and a domain prompt that sounds expert can still be wrong.
2. **A pack is promoted by evidence** (chosen). A pack moves `draft` → `reviewed` → `active` like a profile. To become `active`, every agent of the pack passes its conformance fixtures and its domain evaluation suite at the pack's minimum pass rate, against the models named in its manifest, and a person reviews the pack. Only active packs drive production jobs. A new technique or a newer model enters through the same evaluation, not because it is new (the master prompt's Method Registry rule).

### Outcome

Chosen: **option 2**, with the patterns the factory adopts recorded and dated in [agentic-practices.md](../reference/agentic-practices.md), reviewed at least once a quarter. That file is the factory's answer to "use what is best on the market": each practice has a status (adopted, trial, assess, hold), a source and the evidence that moved it.

**Cost:** an evaluation suite per domain is real work, and a pack is not usable in production until it has one.

## Consequences

- New domains (web, games, finance, and later others) are added as packs, with no change to the engine, the state machine or the policy engine's code.
- The security model does not move: tool grants are still decided by the policy engine against the role of the agent; a pack agent declares a **base role** that already exists in the tool table (`builder`, `code_reviewer`, `ux_reviewer`, `security_reviewer`, and the others) and can only narrow its paths and tools. A pack that needs a new base role needs a reviewed change to `policies/security.yaml`.
- Every job records which packs, agents, skills and MCP tools it had.
- The first packs to write are `web-product`, `game` and `finance` (the owner's three examples). Their contents are sketched in the design document and are proposals, not commitments.

## Dependencies

- **The MCP gateway** exists only on `origin/fix/agent-report-channel` (merged there from `feat/troubleshooter-agent`). The local branch `fix/agent-report-channel` and that origin branch have diverged (22 local commits, 63 on origin on 2026-11-20). The two branches also both used the number **0021** for different records (the solo approval mode here, the troubleshooter there). Revision 2026-11-20: `develop`, which holds the troubleshooter and the gateway, was merged into this branch; the troubleshooter kept 0021 and the solo approval mode became 0022. Building Decision 6 no longer waits for that merge.

## Decisions the owner confirmed on 2026-11-20

1. The pack as the unit, with plugin export later (Decision 1).
2. Outside skills and MCP servers only through a reviewed import with pinned bytes, never installed at run time (Decision 2).
3. A pack proposed by the classifier and not declared by the project waits for a person's yes (Decision 3).
4. The order of the first packs: web product, game, finance.

## What was not verified

- Whether Claude Code and Codex both honour a per-run skill mount for stages other than the specification stage (measured only for the four Spec Kit skills on Claude Code 2.1.311).
- Whether the gateway built on `rmcp` 3.11 can serve the 2026-07-28 revision of MCP, and which upstream servers named in the design document speak it.
- Any of the candidate public skills or MCP servers named in the design document. Each is a candidate until an import has read it.
