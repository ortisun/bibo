# 0028: Each project keeps a knowledge base in its own repository, and every job adds to it

- Status: **Decided by the owner on 2026-11-20**: the owner confirmed the decisions listed under "Decisions the owner confirmed on 2026-11-20". Decision 6 and confirmed item 4 are **superseded by [ADR 0032](0032-knowledge-index-in-postgresql.md)** (2026-11-21): the index lives in PostgreSQL, not in SurrealDB. Nothing is built yet. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the owner set the goal; the engineer weighed the options.
- Related: [ADR 0026](0026-project-rules-installed-by-pull-request.md) (the `docs/` skeleton the factory installs), [ADR 0027](0027-capability-packs.md) (capability packs and the MCP gateway), the master prompt section 12 (memory with provenance). The design is in [project-knowledge-base.md](../architecture/project-knowledge-base.md).

## Context and problem statement

The owner asked (in Portuguese, 2026-11-20) for a knowledge base that always gains the project's knowledge: its features, its flows, its business rules, and the like.

Today an agent learns about a project from three things: the frozen specification of the job, the repository map built by the repository stage, and the files it reads. What the project *is* (which features exist, how an order moves from cart to invoice, which rule says a refund over a limit needs a second approval) lives in people's heads, in old issues, or nowhere. Each job rediscovers it, or misses it. A business rule that no agent knows about is a rule the next change can break without any gate noticing.

The master prompt asks for semantic, episodic and procedural memory "with provenance, validity windows, access boundaries and feedback-based pruning". This record covers the **project's** knowledge. The factory's own memory across projects (what worked, which prompts failed) is a separate concern for Slice 4 and is not decided here.

## Decision 1: where the knowledge lives

### Considered options

1. **A database in the control plane** (rows or a vector store). Fast to query and easy to update from any stage. Rejected as the source of truth: the people of the project cannot read or review it, it is not versioned with the code it describes, and when code and knowledge disagree nobody can tell which commit each belongs to. It also locks the project's knowledge inside the factory: a project that stops using the factory loses it.
2. **An outside wiki or document tool** (Notion, Confluence and the like). People already use them. Rejected: a second place to keep current, a credential the factory would need, no link to commits, and the owner's rule is that `docs/` is the single source of truth.
3. **Structured Markdown in the project's own repository, under `docs/knowledge/`, with a derived index in the control plane** (chosen). Each entry is a file with a small header (stable identifier, kind, status, sources) and a plain-language body, with Mermaid for flows. It is reviewed in pull requests and versioned with the code. The factory builds a search index from it at each base commit; the index is a cache that can always be thrown away and rebuilt.

### Outcome

Chosen: **option 3**. It follows the owner's documentation rule (the documents are the source of truth, organised, written for humans) and keeps the knowledge with the project. The index gives agents fast search without becoming a second truth.

**Cost:** knowledge changes only through pull requests, so it is as current as the last merged pull request, not the last conversation.

## Decision 2: what an entry is

### Considered options

1. **Free-form pages.** Easy to write. Rejected: an agent cannot tell a business rule from a description, and nothing can check that a rule is still enforced.
2. **Typed entries with stable identifiers and links to their evidence** (chosen). Six kinds: `feature`, `flow`, `business-rule`, `term` (glossary), `integration` (an outside system the project talks to), and `constraint` (a legal, regulatory or technical limit). Each has an identifier that never changes (for example `BR-0007`, business rule 7), a status (`proposed`, `active`, `retired`), its sources (the specification, the code paths and the tests that enforce it), the commit at which it was last verified, and the entries it supersedes. Decisions stay in `docs/adr/`; an entry links to them instead of copying them. [ADR 0029](0029-process-metrics-and-improvement-loop.md) adds three kinds for the numbers of the process: `metric`, `measurement` and `improvement`.

### Outcome

Chosen: **option 2**. A business rule marked `active` must name at least one test that enforces it, or say plainly that none exists yet. That turns the knowledge base into something a gate can check, not only a text.

**Cost:** writing an entry takes a little more care than writing a page.

## Decision 3: who adds knowledge, and when

### Considered options

1. **People only.** Accurate, but it does not "always add knowledge": in practice, it stops after the first month.
2. **A separate periodic job** that reads the code and rewrites the knowledge base. Rejected: a large rewrite nobody asked for is hard to review, and it would describe code, not intent.
3. **Every factory job adds to it, inside the pull request that changes the code, plus one harvest at onboarding** (chosen).
   - The **specification stage** reads the active entries the request touches and flags a conflict between the request and an active business rule as a question for a person, never as a silent change.
   - The **documentation stage** gains a knowledge step: it adds or updates the entries the change creates or alters (a new feature, a changed flow, a new rule) in the same pull request as the code.
   - The **documentation reviewer** checks the entries against the diff and the specification.
   - The answer a person gives to a `NEEDS_HUMAN` question, and decisions from the design phase, are recorded as **proposed** entries with who said it and when, so knowledge that exists only in a conversation is not lost.
   - At **onboarding**, the factory opens one draft pull request that harvests a first knowledge base from the existing code, documents and specifications. Every harvested entry starts as `proposed` until a person accepts it.

   - **Outside sources** where the team talks (a chat tool, meeting notes, a document store) may feed the knowledge base through read-only tools on the MCP gateway (ADR 0027), one source at a time, each switched on by the project's owner. What is read becomes a **proposed** entry with its source and date, in a pull request, and is never used as knowledge before a person merges it. This matters because such text is sent to the model provider: a source is off by default, the redactor runs on everything read, and the owner chooses the channels or folders, never "everything".

### Outcome

Chosen: **option 3**. Knowledge grows with each change, is reviewed with that change, and is never merged by the factory (the factory never merges).

**Cost:** each job's documentation stage does a little more work, and the onboarding harvest is one more pull request for a person to review.

## Decision 4: how agents read it

### Considered options

1. **Put the whole knowledge base in every prompt.** Rejected: it grows without bound and wastes context on what the task does not touch.
2. **Let agents read the files.** They already can (`fs.read` on the workspace), and this stays. Alone it is not enough: an agent does not know which of two hundred entries matter.
3. **Two ways, both deterministic where it matters** (chosen):
   - The stage gives each agent a **relevant knowledge** block: the entries linked to the specification, to the task's owned paths and to the terms the request uses, selected by code from the links, not by a model. It is data of class `repo_file`, like the project rules.
   - A read-only tool on the MCP gateway (ADR 0027), `knowledge.search` and `knowledge.get`, lets an agent look further. It searches the index of the job's base commit only.

### Outcome

Chosen: **option 3**. The search starts **lexical and by links** (full-text search over the entries, and the graph of their links). Semantic search with embeddings is recorded as a trial in [agentic-practices.md](../reference/agentic-practices.md): it needs an embedding model, and the factory's default subscription mode (ADR 0020) has none, so the model would have to run locally in the control plane. It is switched on only if the evaluation shows lexical search missing entries that matter. The engine that holds the index is Decision 6.

**Cost:** the index must be rebuilt for each new base commit (it is small: text files of one repository).

## Decision 5: how the knowledge stays true

### Considered options

1. **Trust it.** Rejected: knowledge that is wrong is worse than none, because agents act on it.
2. **Check it in the documentation quality gate** (chosen). The gate checks that every link resolves, that every code path and test an active entry names exists at the head of the change, and that every active entry whose code paths the change touched was reviewed in this change (it was either updated, or its `last_verified` was moved after a check). A business rule that loses its last enforcing test fails the gate.

### Outcome

Chosen: **option 2**. Knowledge drift becomes a gate finding, like documentation drift is today.

**Cost:** a change that touches many paths may have to confirm many entries.

## Decision 6: which engine holds the index

The owner said (2026-11-20) that he likes SurrealDB, a multi-model database that serves graph, relational, document and vector queries from one engine. The knowledge index is exactly that mix: entries are documents, their links are a graph, search is full-text, and semantic search would be vectors.

### Considered options

1. **PostgreSQL only.** Full-text search, recursive queries for the link graph, and the `pgvector` extension if vectors arrive. No new system to run, and the tenancy rules (row-level security, ADR 0012) already exist. But the graph queries the knowledge base needs most ("which rules, flows and tests does this path reach, three links out") are awkward recursive SQL, and vectors would add an extension to the database that holds the ledger.
2. **SurrealDB for the knowledge index, behind a port; PostgreSQL stays the source of truth for everything else** (chosen). A new port, `KnowledgeIndex`, with a SurrealDB adapter. The index is derived from the files in the repository, so it holds nothing that cannot be rebuilt: it needs no backup, and losing it costs a rebuild, not data.
3. **SurrealDB for everything, replacing PostgreSQL.** Rejected: jobs, leases, the outbox and the hash-chained ledger rest on PostgreSQL's transactions, row-level security and the tested migrations (ADR 0001, 0007, 0008, 0012), and the master prompt names PostgreSQL as the source of truth. Replacing it would redo the most reviewed part of the factory for no gain to the knowledge base.

### Outcome

Chosen: **option 2**. It uses SurrealDB where its model fits best and where a fault in it cannot lose or corrupt a record of the factory. Because it sits behind a port with a contract test suite and a labelled fake (as every adapter does), the engine can be replaced by a PostgreSQL adapter without touching a caller.

Each tenant and repository gets its own SurrealDB namespace and database, so one job cannot query another project's knowledge. The same store holds the factory operator's own knowledge base and the measurement entries of [ADR 0029](0029-process-metrics-and-improvement-loop.md); the raw numbers they are computed from stay in PostgreSQL.

**Cost:** a second database to deploy, monitor and upgrade, and a new direct dependency (the SurrealDB Rust client), which the dependency policy requires the owner to approve.

**Checked on 2026-11-20 (web search, release index of surrealdb.com):** the latest stable line is listed as 4.0, patch 4.0.1 dated 2026-11-09, with the 3.x line still patched. **Not verified:** the licence terms of the 4.0 line and whether they suit the factory's deployment; the state of its full-text, graph and vector indexes in 4.0; the Rust client's version and its dependency tree; isolation between namespaces under load. A short spike must answer these before the adapter is written, as the spikes for the agent runtime and Spec Kit did.

## Security

The knowledge base is text from the repository. It is **data, not instructions**: an entry that says "ignore the tests" changes nothing. It is wrapped in the same data envelope as every other repository file. The index is per tenant and per repository, and a job can search only its own repository at its own base commit.

## Decisions the owner confirmed on 2026-11-20

1. The knowledge base lives in the project's repository, and the factory's database holds only a rebuildable index (Decision 1).
2. Every job updates it in its own pull request, and onboarding harvests a first version (Decision 3).
3. Lexical search first, semantic search only after an evaluation shows the need (Decision 4).
4. SurrealDB as the engine of the knowledge index only, behind a port, after a spike; PostgreSQL stays the source of truth for jobs, the ledger and the raw numbers (Decision 6). This includes approving the SurrealDB Rust client as a new direct dependency.

## What was not verified

- How large a real project's knowledge base grows, and whether the documentation stage's budget covers the extra step.
- Whether the onboarding harvest produces entries a person would accept. It must be measured on a real repository.

## Revision note (2026-11-21): the index moves to PostgreSQL

The owner reversed Decision 6 on 2026-11-21: the knowledge index uses PostgreSQL, and SurrealDB is not used. [ADR 0032](0032-knowledge-index-in-postgresql.md) records the decision and how the index works in PostgreSQL (full-text search, a link table walked by a bounded recursive query, row-level security). Decision 6 and item 4 of "Decisions the owner confirmed on 2026-11-20" are kept above as they were decided, and no longer hold. The approval of the SurrealDB Rust client as a dependency is withdrawn. The other decisions of this record stand.
