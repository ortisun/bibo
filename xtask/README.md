# xtask

Repository tooling for the architecture checks. It is not part of the product, and the rules file allows it `std` and `serde_json` only.

## Commands

```
cargo xtask check-architecture [--manifest-path PATH] [--rules PATH]
cargo xtask check-links        [--root PATH] [--rules PATH]
cargo xtask check-invariants   [--root PATH] [--register PATH]
cargo xtask check-generated    [--root PATH] [--rules PATH]
cargo xtask clippy-toml
```

Each check exits with 0 when everything holds, 1 when it found something, and 2 when it could not run (bad arguments, an unreadable rules file, a failing `cargo metadata`, a program that does not start). A finding prints one line, `error[RULE]: where: what`.

- `check-architecture` reads `docs/architecture/crate-dependency-rules.json`, runs `cargo metadata`, and scans the Rust sources. The workspace must hold exactly the crates and binaries that the rules file lists, each in its listed directory, so a missing crate is a `LAYOUT` failure. `--allow-missing-crates` turns that off; only the tests of xtask use it.
- `check-links` checks every relative link in the Markdown files: the target file exists and, when the link names a heading, the heading exists (GitHub spelling). It skips code, HTML comments and URLs, and it reads inline links, images, reference definitions, undefined references and `href` and `src` attributes. A heading underlined with `===` or `---` is not seen.
- `check-invariants` (review finding F-24) reads the `invariants` list of `docs/architecture/state-machine.json` and fails when an id is named by no `#[test]` function (`fn inv_05_...`) and no comment (`// INV-05`) under `crates/`. It finds the name, not whether the test is any good.
- `check-generated` runs the `--check` command of every generated file in the `generated_artifacts` list of the rules file. A command that cannot start is reported as blocked and exits with 2, never as a pass.
- `clippy-toml` prints the DEP-05 ban list. Create each inner crate's file with `cargo xtask clippy-toml > crates/<name>/clippy.toml`.

## Where the lists come from

Every list the source scans use is in the `source_scans` section of the rules file: the four inner crates, the shells, the programs each crate may spawn, the one file that may spawn, the container flags, the posture verifier prefix, the ingestion directory, the constructors and the crates that may call them, the generated files and the limits on resolved features. A reviewer changes a list in that one file. A crate named there that is not in `crates` or `apps` stops the check with exit code 2, and `tests/source_scans.rs` fails if a list of strings is declared as a constant in the xtask sources.

## What each rule checks

| Rule | What it checks | Where |
|---|---|---|
| DEP-01 to DEP-03, DEP-08, `LAYOUT` | `cargo metadata` against the rules file. | `src/topology.rs` |
| DEP-04 | Every library crate except test support, adapters included, uses only the external crates and features of its `external_allow` list. An external package comes from the public registry: a path or git dependency under an allowed name fails (F-31). A path dependency named like a workspace crate must point at it. | `src/topology.rs` |
| DEP-05, bans | Each inner crate has a `clippy.toml` with every ban. Tests compile a scratch crate against the real `time`, `uuid` and `tokio` and prove each ban fires. | `src/clippy_bans.rs` |
| DEP-05, silencing | No `allow` or `expect` of `clippy::disallowed_methods`, `clippy::disallowed_types`, `clippy::all` or `warnings` in an inner crate, in `src`, `tests`, `benches` or `examples`, also inside `cfg_attr`, and no manifest or cargo configuration that sets them to allow. | `src/clippy_bans.rs`, `src/lints.rs` |
| DEP-05, features | The features Cargo resolves for `time`, `uuid` and `tokio` with the whole workspace unified stay within the limit in `source_scans.dep_05.resolved_features`. Another crate that enables `time/std` gives the domain crate `now_utc`, and the manifest of the domain crate does not show it. | `src/topology.rs` |
| DEP-06 | The root manifest sets the lint that DEP-06 names, and every package inherits it. | `src/lints.rs` |
| DEP-09 | `Store::begin_system` only in `workflow`; the Spec Kit layout only in `spec_adapter`; no `ChangeHost` method starting with `merge`, `ready` or `undraft`. | `src/static_checks.rs` |
| DEP-10, ST-03 | Only the file named in `source_scans.dep_10.spawn_file` mentions `std::process::Command`, `tokio::process` or another spawning path, through any import, alias, glob or type alias. In that file, each `Command::new` names a program that its crate may spawn, and none names a shell. | `src/static_checks.rs` |
| ST-01 | `safe.directory` set to `*` in any non-prose file. | `src/static_checks.rs` |
| ST-02, ST-04, ST-05 | No `==` on a MAC or signature; container flags only in the posture verifier; no merge or deploy function, route or workflow. | `src/static_checks.rs` |
| ST-07 | Every span name, `factory.` field, `error.type`, metric and label written in a `tracing` call, and every literal that looks like a factory name, is in the tables of `docs/observability/conventions.md`. | `src/st07.rs` |
| ST-09 | Reads of the file system in `sandbox`, `runtime`, `spec_adapter` and `workflow` only in `crates/sandbox/src/workspace/`, found through resolved paths. | `src/static_checks.rs` |
| ST-13 | `TenantScope::new`, `SystemScope::engine`, `PlatformScope::receiver`, `IngestedChange::new` and the literals of `ResolvedPrincipal` and `ResolvedRepository` only in the crates the rules file lists. | `src/static_checks.rs` |
| ST-14 | The `workflow` crate does not mention `MeteringOps`. | `src/static_checks.rs` |

DEP-07 is `cargo deny` and is not checked here. ST-06, ST-08 and ST-10 belong to other CI steps.

## How the scans decide what is test code

Review finding F-12 showed that the old scans decided "test code" from file and directory names, and that a `#[cfg(test)]` attribute could hide the code after it. Now:

- `src/syntax.rs` lexes Rust into tokens with matching delimiters. An attribute covers its own element only: an item, a statement, a field, a variant, a parameter or a match arm, and never past the group it sits in.
- An item is test code when its `cfg` is false in every build that is not a test build: `cfg(test)` and `cfg(all(test, x))` are, `cfg(not(test))` and `cfg(any(test, x))` are not.
- A file is test code when a test-only `mod` declares it or when it starts with `#![cfg(test)]`. A file called `tests.rs` or `webhook_tests.rs`, or a directory called `tests` inside `src`, is production code unless a test-only `mod` declares it. A file in `src` that no module declares is scanned. `#[path]` and `include!` are followed, and so are the target roots that `cargo metadata` reports.
- The `tests`, `benches` and `examples` directories at the crate root are separate Cargo targets. They are not scanned, except for the silencing check, which reads every `.rs` file of an inner crate.

## What the scans cannot see

The scans read tokens. They do not expand macros and do not follow a path through a re-export in another file, so these slip past them:

- A name built at run time (`concat!`, `paste!`, a `const` passed to `Command::new`). A program that is not a string literal is reported in a crate that may not spawn, and accepted in the spawn file.
- A spawn or a banned call behind a macro that another crate defines, or code generated by a build script (`include!(concat!(env!("OUT_DIR"), ...))` is not followed).
- A path imported in one file and re-exported from another under a new name, when the re-export itself names no spawning path. In practice the re-export has to name the real path once, and that mention is the finding.
- Names bound in one module and used in another module of the same file are treated as one scope. That can add a finding and never hides one.
- A struct literal that a pattern also matches (`let ResolvedPrincipal { .. } = x`) is reported like a construction.
- `ST-07` does not know which span a field belongs to, and it does not read a name passed through a variable or a function.
- `RUSTFLAGS` set in the environment of CI, and a `clippy.toml` that `CLIPPY_CONF_DIR` replaces.
- Text in Markdown is not scanned by the source scans, and `check-links` does not follow a link to a heading underlined with `===`.

The process spawn recorder in the end-to-end tests covers the run-time side of DEP-10 and ST-03.

A real parser such as the `syn` crate (licence MIT or Apache-2.0, with `proc-macro2` and `unicode-ident` beneath it) would give exact item boundaries, but it would not expand macros or follow re-exports either, so it closes less of the list above than it seems to. It is not a dependency of xtask. The rules file allows xtask `std` and `serde_json` only, so adding it needs a change to that file approved by the architect and a person.

## CI steps

`scripts/ci.sh` and the workflow own the wiring. These are the commands, from the repository root:

```
cargo xtask check-architecture
cargo xtask check-links
cargo xtask check-invariants
cargo xtask check-generated      # needs python3
python3 -I docs/architecture/tools/check_crate_rules.py --check
```

## Tests

```
cargo nextest run -p xtask                       # everything
cargo nextest run -p xtask static_checks         # DEP-09, DEP-10, ST-xx fixtures
cargo nextest run -p xtask dependency_rules      # DEP-01 to DEP-04, DEP-06, DEP-08
cargo nextest run -p xtask clippy_bans           # the DEP-05 proof
cargo nextest run -p xtask review_bypasses       # the mutations of review finding F-12
cargo nextest run -p xtask source_scans          # the lists come from the rules file
cargo nextest run -p xtask invariant_register    # check-invariants
```

Each integration test builds a small workspace in a temporary directory, with its own rules file and stub external crates (no network), and runs the real `xtask` binary on it. The baseline workspace satisfies every rule and uses the real `source_scans` section and the real conventions page. A failing fixture changes one thing and expects exit code 1 and the rule's id. The `clippy_bans` tests need clippy for the pinned toolchain and the registry cache of `time`, `uuid` and `tokio` at the versions in `Cargo.lock` (build the workspace once); they fail with `BLOCKED` if either is missing. They ignore `CARGO_TARGET_DIR` and the other build variables of the caller.

To add a rule: write the failing fixture first, check that it fails for the right reason, then add the check.
