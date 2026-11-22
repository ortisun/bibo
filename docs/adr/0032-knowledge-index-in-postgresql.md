# 0032: The knowledge index lives in PostgreSQL, not in SurrealDB

- Status: **Decided by the owner on 2026-11-21**. Supersedes Decision 6 of [ADR 0028](0028-project-knowledge-base.md) and item 4 of its "Decisions the owner confirmed on 2026-11-20". The rest of ADR 0028 stands. Nothing of the index is built yet. No independent review has covered it.
- Date: 2026-11-21
- Deciders: the owner chose the engine; the engineer weighed how to use it.
- Related: [ADR 0007](0007-persistence-access-and-tenancy.md) (Diesel, tenant on every row), [ADR 0012](0012-row-level-security-in-slice-1.md) (row-level security), [ADR 0028](0028-project-knowledge-base.md) (the knowledge base). The design is in [project-knowledge-base.md](../architecture/project-knowledge-base.md).

## Context and problem statement

ADR 0028 keeps each project's knowledge in its own repository (`docs/knowledge/`) and gives the factory a derived index for search and for following links. Its Decision 6 put that index in SurrealDB behind a `KnowledgeIndex` port, after a spike, and asked the owner to approve the SurrealDB Rust client as a new dependency. Neither the spike nor the adapter was started.

On 2026-11-21 the owner said (in Portuguese): use PostgreSQL itself, he does not want SurrealDB. This record says how the index works in PostgreSQL, so that the choice is complete and not only a change of name.

What the index must do, from ADR 0028 and its design:

1. Find entries by words in their titles and bodies (lexical search first; semantic search only after an evaluation shows the need, ADR 0028 Decision 4).
2. Follow links between entries, a bounded number of links out ("which rules, flows and tests does this path reach").
3. Answer for one tenant, one repository and one base commit, and never for another.
4. Hold nothing that cannot be rebuilt from the files.

## Considered options

1. **Tables in the factory's PostgreSQL database, behind the `KnowledgeIndex` port** (chosen). Full-text search with a `tsvector` column and a GIN index, links in an edge table walked by a recursive query with a depth bound, tenant isolation by the row-level security of ADR 0012. No new system and no new dependency: Diesel and `diesel-async` are already there.
2. **A separate PostgreSQL database or server only for the index.** Keeps search load away from the database that holds jobs and the ledger, and would keep an extension such as `pgvector` out of it. Rejected for now: a second database to deploy, back up and migrate, for an index that is small (a project's knowledge base is hundreds of entries, not millions) and needs no extension. Because the index sits behind a port, it can move to its own database later without touching a caller, if a measurement shows the load matters or vectors arrive.
3. **No stored index: read the files at the base commit on every query.** Always true to the commit and needs no table. Rejected: the MCP gateway's `knowledge.search` would need a checkout of every repository it serves, and each query would parse every entry again. The relevant-knowledge block that code builds for an agent's prompt (ADR 0028 Decision 4) still reads the files of the job's own workspace; the index serves search and the gateway.

## Decision outcome

Chosen: **option 1**.

- **Port.** `KnowledgeIndex` stays as ADR 0028 named it: rebuild the index of a repository at a commit from its parsed entries, search it, get an entry, and list the entries a set of entries reaches within a number of links. It gets a contract test suite and a labelled fake, as every port does. The adapter is in `crates/storage`, beside the other PostgreSQL stores.
- **Tables.** A migration adds three tables, with `tenant_id` first in every key and forced row-level security with the `tenant_isolation` policy of ADR 0012, written by the worker's tenant login:
  - `knowledge_index_snapshots`: one row for each repository and commit indexed, with the time it was built and the number of entries. A job's searches name its base commit, so a search can never see another commit's entries.
  - `knowledge_index_entries`: the identifier, kind, status, title and body of each entry of a snapshot, with a generated `tsvector` column over title and body and a GIN index on it.
  - `knowledge_index_links`: one row for each link from one entry of a snapshot to another, with its kind (`links` or `supersedes`).
- **Search.** The text search configuration is `simple`: entries may be written in any language, and one language's stemmer would treat the others badly. Results are ranked by `ts_rank_cd` and then by identifier, so the same query on the same snapshot returns the same order. A query is parsed with `websearch_to_tsquery`, which accepts any text without a syntax error.
- **Links.** A recursive query with a `CYCLE` clause and a depth limit that the caller gives and the adapter caps at 3. PostgreSQL 16 or later, which the factory already requires, has the clause.
- **Life of a snapshot.** A snapshot is built when a job needs a commit that has none, and dropped when no unfinished job names its commit and a newer snapshot of the repository exists. Losing all of them costs a rebuild, not data.
- **Vectors.** Not part of this decision. If an evaluation shows semantic search finds entries the lexical search misses, a new record decides between `pgvector` in this database and option 2.

### Costs

- Full-text search in PostgreSQL ranks less well than a dedicated search engine, and `simple` does no stemming: "rule" does not find "rules". The evaluation of ADR 0028 Decision 4 measures whether that matters before anything else is added.
- The link queries are recursive SQL, which is harder to read than a graph query language. They are few, and each one sits in one adapter function with its own tests.
- The index shares the database that holds jobs and the ledger. Its writes are rebuilds of a few hundred rows per job and its GIN index is small, so no effect is expected; none has been measured.

## Consequences

- No SurrealDB dependency, spike, deployment or monitoring. The approval of the SurrealDB Rust client in ADR 0028 is withdrawn.
- The tenancy, migrations, backups and tests the factory already has cover the index.
- ADR 0028 keeps its other decisions: the repository is the source of truth, every job adds to it in its own pull request, and the documentation gate checks it for drift.

## What was checked and what was not

- **Checked in the repository on 2026-11-21:** no code names SurrealDB, and no `KnowledgeIndex` port, adapter or table exists, so nothing has to be removed. The `repositories` table keys on `(tenant_id, id)`, which the new tables reference.
- **Not checked:** the ranking quality of `simple` with `ts_rank_cd` on a real project's knowledge base; the time to rebuild a snapshot of a large knowledge base; the query plans of the recursive link query on a real one.
