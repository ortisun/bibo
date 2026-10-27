# xtask

Repository tooling for the architecture checks. It is not part of the product, and the rules file allows it `std` and `serde_json` only.

## Commands

```
cargo xtask check-architecture [--manifest-path PATH] [--rules PATH]
cargo xtask clippy-toml
```

`check-architecture` reads `docs/architecture/crate-dependency-rules.json`, runs `cargo metadata`, and scans the Rust sources. It exits with 0 when every rule holds, 1 when a rule is broken, and 2 when it could not run (bad arguments, an unreadable rules file, a failing `cargo metadata`). A violation prints one line, `error[RULE]: where: what`, then the wording of each broken rule from the rules file.

The workspace must hold exactly the crates and binaries that the rules file lists, each in its listed directory, so a missing crate is a `LAYOUT` failure. `--require-all-crates` is accepted as a synonym of this default. `--allow-missing-crates` turns the missing-crate failure off. Only the tests of xtask use it, because their fixture workspaces list far fewer crates than the real rules file.

`clippy-toml` prints the DEP-05 ban list. Create each inner crate's file with `cargo xtask clippy-toml > crates/<name>/clippy.toml`.

## What each rule checks

| Rule | Source of the check | Where it lives |
|---|---|---|
| DEP-01 to DEP-04, DEP-08, `LAYOUT` | `cargo metadata` against the rules file. Nothing is repeated in Rust. | `src/topology.rs` |
| DEP-06 | The root manifest sets the lint that DEP-06 names in `enforced_by` (read from the rules file), and every workspace package has `[lints] workspace = true`. `cargo metadata` does not report lints, so the manifests are read as text. | `src/lints.rs` |
| DEP-05 | Each of `domain`, `ports`, `workflow`, `spec_adapter` has a `clippy.toml` that holds every ban. Tests compile a scratch crate to prove each ban fires. | `src/clippy_bans.rs` |
| DEP-09, DEP-10, ST-02 to ST-05, ST-09 | Text scan of production Rust sources. | `src/static_checks.rs` |
| ST-01 | Text scan of every non-prose file in the repository. | `src/static_checks.rs` |

DEP-07 is `cargo deny` and is not checked here.

## Limits of the source scans

The scans read text. They blank comments, string contents (for identifier scans) and items marked `#[cfg(test)]` first, and they skip `tests`, `benches` and `examples` directories and files named `tests.rs`, `*_test.rs` and `*_tests.rs`. They never follow symbolic links, and a symbolic link to a directory inside a crate's `src` stops the check with an error because it would hide code. They miss code that builds a name at run time, and they read one line at a time. The process spawn recorder in the end-to-end tests covers the run-time side of DEP-10 and ST-03.

Parameters that the rules file states only in prose are constants in `src/static_checks.rs` and `src/clippy_bans.rs`: which crate may spawn which program, where the posture verifier and the ingestion module live, which four crates carry the ban list. Unit tests check that every crate they name is still in the rules file and that the rule wording still mentions them.

Two path conventions follow from that:

- The posture verifier is a file or directory whose name starts with `posture`, under `crates/sandbox/src/`. Only there may a dangerous container flag appear (ST-04).
- The ingestion module is `crates/sandbox/src/workspace/`. In `sandbox`, `runtime`, `spec_adapter` and `workflow`, filesystem reads are allowed only there (ST-09).

## Tests

```
cargo nextest run -p xtask                 # everything
cargo nextest run -p xtask static_checks   # the DEP-09, DEP-10 and ST-xx fixtures
cargo nextest run -p xtask clippy_bans     # the DEP-05 proof
```

Each integration test builds a small workspace in a temporary directory, with its own rules file and stub external crates (no network), and runs the real `xtask` binary on it. The baseline workspace satisfies every rule. A failing fixture changes one thing and expects exit code 1 and the rule's id. The `dependency_rules` tests cover DEP-01 to DEP-04, DEP-06 and DEP-08. The `clippy_bans` tests need clippy for the pinned toolchain and fail with `BLOCKED` if it is missing.

To add a rule: write the failing fixture first, check that it fails for the right reason, then add the check.
