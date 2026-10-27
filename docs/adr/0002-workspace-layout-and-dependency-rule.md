# 0002: Hexagonal workspace in four rings; twelve library crates and four binaries in Slice 1

- Status: Accepted
- Date: 2026-10-27
- Deciders: software_architect
- Related: [overview](../architecture/overview.md), [`crate-dependency-rules.json`](../architecture/crate-dependency-rules.json), [slice plan](../architecture/slice-plan.md)

## Context and problem statement

The master prompt (section 14) suggests sixteen library crates and five applications. The repository is empty. Several engineers, a DBA, QA and others will start in parallel once the contracts are fixed. They need boundaries that let them avoid editing the same files, and the project rule is hexagonal architecture: the domain has no I/O and adapters depend inward.

How many crates do Slices 0 and 1 justify, and how is the dependency rule enforced rather than hoped for?

## Decision drivers

- Parallel work needs separate ownership. A crate is the cleanest unit: its own manifest, its own tests.
- The dependency rule must fail the build when broken.
- An empty crate is cost without benefit: manifest upkeep, compile units, review surface and a boundary nobody has tested.
- The first end-to-end run (Slice 1) is the proof that matters.
- Some boundaries are worth a compile-time wall from the start: the database, process execution, the Spec Kit file layout.

## Considered options

1. **All crates from section 14 on day one.** Matches the prompt's picture. Most would hold a few hundred lines and a guessed boundary.
2. **One application crate with modules, plus adapters.** Fewer manifests. The ring discipline would rest on convention and code review.
3. **Rings with the minimum set of crates.** Create a crate only when it is an adapter with its own dependency set, an anti-corruption layer for a foreign format, or a pure model or contract other crates share. Everything else starts as a module and is extracted when a stated trigger fires.

## Decision outcome

Chosen: **option 3**.

### The rule for creating a crate

A new crate needs at least one of these reasons, written in `crate-dependency-rules.json`:

1. It adapts an external system and brings dependencies the inner code must not see (`storage`, `runtime`, `sandbox`, `github`, `egress`, `observability`).
2. It is an anti-corruption layer that confines a foreign format to one place (`spec_adapter`).
3. It is pure model or contract code that many crates share (`domain`, `ports`).
4. It is test support that must never reach production (`testkit`).
5. It implements schema validation and registry loading behind ports (`contracts`).

Otherwise the code is a module. Each deferred crate has a named home and an extraction trigger in the rules file.

### The four rings

| Ring | Contents | May depend on |
|---|---|---|
| 0 | `domain` | external crates on a short allow list |
| 1 | `ports` | `domain` |
| 2 | application crates (`workflow`, `spec_adapter`) and adapter crates (`storage`, `runtime`, `sandbox`, `github`, `egress`, `contracts`, `observability`), plus `testkit` | `domain` and `ports`; never a peer |
| 3 | binaries (`api`, `worker`, `cli`, `egress-sidecar`) | everything below; the only place where adapters are chosen |

Slice 1 therefore has **twelve library crates** and **four binaries**. The twelfth crate, `egress`, was added when the security review required a model broker and a per-job relay for agents that run inside the sandbox ([ADR 0005](0005-agent-runtime-adapter-boundary.md)). The generated table and graph are in [overview.md](../architecture/overview.md). The list of what is deferred, with the reason and the extraction trigger for each, is in the same file.

`ports` is separate from `domain` because they change at different speeds. The domain model and state machine settle early and change rarely. The ports are the contracts every adapter owner codes against, and they are the part most likely to need small revisions during Slice 1. Separating them lets the architect freeze `domain` after Slice 0 and review every `ports` change on its own.

Packages are named `factory-<crate>` and live in `crates/<crate>`. The toolchain is pinned in `rust-toolchain.toml` to 1.98.0, the version installed and used for every check in this repository, with edition 2024, which `cargo new` selects on that toolchain.

The security documents say "the policy crate". In this layout that is the module `domain::policy` (pure evaluation) with its file loader in `contracts`, until the extraction trigger in the rules file fires. Secret redaction is the module `domain::redaction`.

### How the rule is enforced

| Rule | Mechanism | Status |
|---|---|---|
| Only the edges in `crate-dependency-rules.json` exist | An `xtask check-architecture` command reads `cargo metadata` and fails on any other workspace edge | Designed. Built in work package `s0-workspace-skeleton` |
| `testkit` appears only as a dev-dependency | Same command, using the dependency kind in `cargo metadata` | Designed |
| Inner crates make no clock, file, network or process calls | `clippy.toml` in each of `domain`, `ports`, `workflow`, `spec_adapter` with `disallowed-methods` and `disallowed-types`, run as `cargo clippy -- -D warnings` | **Verified** on 2026-10-27: in a scratch crate, `SystemTime::now`, `std::fs::read_to_string`, `std::process::Command::new` and `std::fs::File` were each reported as an error. Not yet tried: `uuid::Uuid::now_v7` and `uuid::Uuid::new_v4`, which belong on the list too |
| Only `sandbox` spawns `docker` or `git`, only `runtime` spawns an agent tool, no crate spawns a shell (rule DEP-10, static check ST-03) | The same `xtask` command by source scan, plus a process spawn recorder in the end-to-end tests | Designed |
| Dangerous container flags appear only in the posture verifier's deny list and in tests (ST-04); no merge or deploy path without the approval check (ST-05); workspace reads only through the ingestion module (ST-09) | The same `xtask` command by source scan | Designed |
| No `unsafe` | `[workspace.lints.rust] unsafe_code = "forbid"` | Designed |
| Licenses and advisories | `cargo deny check`; `cargo-deny` 0.x is installed locally | Designed |
| Inner crates avoid I/O features of `tokio` | The same `xtask` command compares the resolved features in `cargo metadata` with the allow list | Designed |

The clock, the random generator and the identifier generator come through the `Clock` and `IdGenerator` ports. That keeps the state machine deterministic in tests.

### Composition and tests

- Binaries wire adapters to use cases. No library crate chooses an adapter.
- The CLI calls the same use cases in process in Slice 1, with the operator identity from configuration. It becomes an HTTP client when the API settles (Slice 4).
- `testkit` holds every fake. Each fake reports `fidelity = fake`, and the engine records that in the ledger. Rules in the schemas and in invariant INV-08 stop fake evidence from supporting a claim in production mode.

## Consequences

- Good: the compile-time walls sit where they pay off, around the database, process execution, the GitHub client and the Spec Kit layout; a work package maps to a crate or a directory with no shared files; the first run is not delayed by boundaries that nobody has exercised.
- Bad: `workflow` is large, because every stage handler and the gates live in it as modules. Merge pressure is real. Module-level ownership and pre-declared `mod` lines in the skeleton reduce it, and the extraction triggers say when to split.
- Bad: `ports` becomes a coordination point. Every change needs architect review, and the Slice 0 plan freezes a first version before the adapters start.
- Bad: `workflow` uses `tokio` for timers and synchronization. The runtime is not entirely absent from the application ring. The feature allow list (`sync`, `time`, `rt`, `macros`) and the clippy bans on file, network and process types keep it away from I/O.
- Neutral: the sixteen-crate layout in the prompt is a guide, and this ADR departs from it knowingly. A crate is extracted when its trigger fires, with an ADR only if the extraction changes a boundary.

## Pros and cons of the options

**All crates on day one**: matches the prompt and gives each name an owner. Costs sixteen manifests, many placeholder boundaries and more cross-crate edits when the guessed boundaries move.

**One application crate**: simplest to start. Gives up compile-time protection for the adapters and makes parallel ownership a matter of discipline, which is what this ADR is trying not to depend on.

**Rings with a minimum set**: see above.
