# 0015: Share the composition core as a ring 3 library crate

- Status: Decided by the lead for work package `s1-apps-composition`. **Pending confirmation by the architect**, who has not reviewed the rules-file change yet.
- Date: 2026-10-28
- Deciders: the lead. The edit to the rules file and to `xtask` was made by the software engineer under the lead's instruction.
- Related: [ADR 0002](0002-workspace-layout-and-dependency-rule.md), [ADR 0013](0013-telemetry-wiring.md), [the rules file](../architecture/crate-dependency-rules.json), [the overview](../architecture/overview.md)

## Context and problem statement

The first part of `s1-apps-composition` wrote the composition core inside `apps/worker`: the typed configuration, the profiles, the registry of ports with the check that a profile accepts each one, the start-up checks, the redactor and the registry of the factory's secret values, the health report, and the seams that the stage handlers declare and only a composition root can implement. The API and the operator CLI are the next two parts of the same work package, and both need all of it. ADR 0013 already says that every binary builds the same redactor from the same policy and passes it to telemetry.

ADR 0002 gives the dependency rule: an application binary depends on library crates only (`DEP-01`), and a library crate depends on a lower ring. The rules file lists twelve libraries and none of them is a place for code that wires several adapters, because the rule says only a binary may do that (`DEP-08`). So the shared core had nowhere legal to live. In the first part it lived in the library target of the worker, and `apps/worker/README.md` listed the consequence: the API cannot link it, and the only alternative is to copy the modules.

How does the factory share the composition core between binaries without breaking the ring rule?

## What was checked

On 2026-10-28, in this repository.

- `xtask/src/topology.rs` allows an edge from a binary to any library, and refuses an edge from a binary to another binary.
- `DEP-02` computes the ring of a binary as one above the highest library ring. A library in ring 3 would have pushed the binaries to ring 4 unless the computation changed.
- The shared core uses no `main`, no HTTP route and no handling of process arguments. The worker loop (`run`) and the broker listener (`broker_host`) are the only modules that are specific to a process that claims work.
- After the extraction 81 tests ran before and 81 after, all passing, and `cargo xtask check-architecture` passes with the new entry.

Not checked: how much longer a build of the CLI takes when it links every adapter through this crate. No measurement was taken.

## Considered options

1. **Let apps link apps.** The API and the CLI depend on the library target of the worker. This needs an exception to `DEP-01` that applies to every binary, makes the API's dependency list say "the API needs the worker", and pulls the worker's loop and the broker listener into the API. It also leaves the shared core owned by a binary, which is the wrong direction for code that three binaries must agree on.
2. **One binary.** A single `factory` program with `worker`, `api` and `cli` subcommands. Nothing is shared by linking because everything is one program. It changes the four binaries that ADR 0002 and the slice plan assume. It also puts the credential handling of every role in every process: the model broker keys would be linked into the process that receives webhooks. The deployment can still run one role per container, but the code of the other roles stays in the image.
3. **Duplicate the core in each app.** Cheapest on day one. The redactor, the configuration reader, the profile check and the seams are security code: a second copy that drifts is a second way to start production with a fake or to miss a secret. The factory exists to enforce one set of rules, so two copies of the enforcement would be a defect waiting to happen.
4. **Put the core in an existing library.** Rings 0 and 1 cannot hold it (they take no I/O). A ring 2 crate cannot depend on its peers (`DEP-02`), and the core depends on nearly all of them.
5. **A ring 3 library crate that only binaries may use.** Chosen.

## Decision outcome

Chosen: **option 5.** A new crate `crates/composition`, package `factory-composition`, library `factory_composition`.

- **Rules file.** A new `crates` entry with `ring: 3` and `layer: composition`. In this file every entry of `crates` is a library, so the layer is the only new field; the rules reader (`xtask`) and the generator of the overview (`check_crate_rules.py`) read it. Its `depends_on` lists every library it wires, from ring 0 to ring 2. `testkit` is a dev-dependency only (`DEP-03`). Its `external_allow` list is the one the worker used: `async-trait`, `serde`, `serde_json`, `thiserror`, `tracing`, `tokio` with `rt`, `time`, `sync`, `macros` and `signal`, `time` with `std`, `uuid` with `std`.
- **Ring.** The composition library sits in ring 3, the ring of the composition roots. The rules reader derives the binaries' ring as one above the highest ring of the other libraries, so both end up in ring 3, and a library in another ring is refused when the file is read. An edge from a binary to the composition library is allowed even though the rings are equal.
- **New rule `DEP-11`.** Only a binary in `apps/` may depend on the composition library, in any dependency kind; no crate in rings 0 to 2 may. The library has no binary target and defines no function named `main` (a build script is not the library). `xtask check-architecture` enforces the edge from `cargo metadata` and the absence of `main` by source scan, and its tests show each case failing.
- **`DEP-08`** says binaries and the composition library are the only crates that depend on more than one adapter.
- **`ST-13`.** The library may call `TenantScope::new`, as the worker could. `PlatformScope::receiver` stays allowed in the API alone, and the library does not use it. `DEP-10` and `ST-03` still apply: only `sandbox` starts processes, and the library only calls the sandbox through the ports.
- **`DEP-09`, one narrow exemption.** Building the Spec Kit provider means writing the adapter's two public type names, which contain the word the rule keeps out of every crate but the adapter. The rules file gains `spec_kit_public_names` (`SpecKitConfig`, `SpecKitProvider`); the scan blanks exactly those two names before it looks for a term. A path in a string, `.specify` or `speckit-specify` in the composition library is still a finding, and `xtask` tests show both. The library finds the installation file through the adapter's own constant, not a path of its own.
- **What stays in a binary.** `main`, the worker loop and the broker listener in `apps/worker`; HTTP routing and webhook handling in `apps/api`; the handling of process arguments and the commands in `apps/cli`. The library holds no business rule: the engine decides, the adapters act, and the library chooses and connects them.

The generated overview and the rules table are regenerated from the rules file (`python3 -I docs/architecture/tools/check_crate_rules.py --write`).

## Consequences

**Good.**
- One redactor, one profile check and one set of seams for all three binaries. The API and the CLI start from tested code.
- The ring rule keeps its meaning: nothing below ring 3 can reach the composition code, and a binary cannot reach another binary.
- A test of a seam runs in the library without starting a worker.

**Costs.**
- A thirteenth library to maintain, and ring 3 now holds two kinds of thing (binaries and a library). The rules file and the overview say so.
- Every binary that depends on the library links every adapter. The CLI gains the Docker and GitHub adapters in its binary whether it uses them or not. If that matters, the library can grow features for the adapters later; nothing here prevents it.
- The library can grow into a catch-all. The guard is the rule that it holds no `main`, no HTTP route, no handling of process arguments and no loop, plus review. A business rule found in it is a defect to move to the engine.
- ADR 0002 says "twelve library crates"; it now carries a revision note that points here.

## Revisit when

A second library appears that needs the same ring 3 treatment (then ask whether the layer needs a sub-structure), or when the link cost of the CLI becomes a complaint.
