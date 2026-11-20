# Contract tests for the word-count fixture

These tests pin the fixture repository that the end-to-end run works on,
[`fixtures/repos/word-count`](../../fixtures/repos/word-count/README.md). If the fixture drifts, the
end-to-end proof stops meaning what it says, so the checks run on every change to it.

## What is pinned

| Check | What it holds |
|---|---|
| Layout | The files the run needs exist, and there is no build script, no cargo configuration directory and no `.git` entry. |
| No dependencies | `Cargo.toml` lists no dependency of any kind, the lock file lists only the project, and the project is its own workspace root, so it builds with no network and does not join the factory's workspace. |
| Manifest | `.factory/project.yaml` loads through the same loader and schema as the intake stage. It declares the gates `format`, `lint`, `build` and `unit-tests` (the last two mandatory), protects `.factory/**`, `CODEOWNERS` and `tests/golden/**`, and names documents that exist. |
| Owners | `CODEOWNERS` has a catch-all rule and covers the manifest, the stored samples and itself. |
| Secrets | No file holds text in the shape of a secret. |
| README | It documents exactly the options the built tool has, runs only cargo commands that the gates run, and every example output is what the tool prints. |
| Open gap | The tool still refuses `--json`, and the files the planned change adds do not exist. |
| Commands | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo build` and `cargo test` pass offline on a copy, on the host and in the pinned verify image with no network. |

Each check is also run on a copy of the fixture with one deliberate defect, and must fail.

## Run it

```text
scripts/e2e.sh --check-fixture        # files, host and the pinned image; BLOCKED (3) without Docker
scripts/e2e.sh --check-fixture-host   # files and host only
cd tests/contract && cargo test       # the contract tests
```

The tests in `tests/verify_image.rs` need Docker and the image `factory-sandbox/verify`. Without
them they panic with a message that starts `BLOCKED:`. They are never skipped.

The project is its own cargo workspace and is not a member of the factory workspace.
