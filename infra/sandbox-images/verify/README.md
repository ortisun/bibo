# The verify image

`factory-sandbox/verify` is the container that runs the trusted gates: `cargo build`, `cargo test`, `cargo fmt --check` and `cargo clippy`. It holds the Rust toolchain at the version in `rust-toolchain.toml` and nothing else that a gate does not need.

It serves two sandbox profiles (`images.json`, `profile_images`):

- `verify`: no network, source mounted read-only, one writable output directory.
- `fetch_deps`: the same image with the per-job network, to run `cargo fetch --locked` through the sidecar. It runs no repository code.

## What is in it

| Part | Source |
|---|---|
| Debian 13 userland, `gcc`, `libc6-dev`, CA certificates, `rustc` and `cargo` 1.98.0 | the official `rust:1.98.0-slim-trixie` image, pinned by index digest |
| `clippy` and `rustfmt` 1.98.0 | the archives from the dated Rust dist directory, each pinned by SHA-256 (the values come from the signed channel manifest) |
| One user, `agent`, uid and gid 10001, home `/home/agent` (empty) | created by `lib/harden.sh` |

The toolchain lives in `/opt/rust`. It is the toolchain from the official image, moved there with its libraries, so it runs without rustup and without any environment variable. `PATH` is the only variable the image sets.

## What is not in it, on purpose

- **No shell.** `sh`, `bash`, `dash` and the rest are deleted (`lib/shells.txt`). Gates are typed commands started with an argument vector, and `sandbox-policy.md` forbids starting a shell. A container with no shell also has nothing for an injected command string to run in. `cargo build`, `test`, `fmt`, `clippy` and `rustdoc` work without one (`test.sh`, rule `OFFLINE-BUILD`). A dependency whose build script starts `sh` will fail here. The dependency-free fixture does not.
- **No git, no GitHub command line, no package manager, no network client, no account tools, no interpreter** (`lib/forbidden-binaries.txt`). Rustup is deleted too, so nothing can fetch a toolchain. Cargo stays, because it is the build tool: it can download crates only when a network exists, and the `verify` profile has none. Cargo links libgit2 for git dependencies. That is not a git binary, and it has nothing to reach.
- **No setuid or setgid file.** The bits are cleared on every file, and the programs that need them (`su`, `mount`, `passwd`, and so on) are deleted.
- **No hook, no MCP server, no settings file, no agent tool.**

## How the supervisor runs it

Use the numeric user from `images.json` (`--user 10001:10001`) and the rest of the profile in `docs/security/sandbox-policy.md` section 3.2. Two facts about this image matter for the adapter:

- **Set `TMPDIR` to the output directory** (for example `/out/tmp`, created by the supervisor) when a gate runs `cargo test`. `/tmp` is `noexec` in the profile, and `rustdoc` runs the programs it builds from its temporary directory. `test.sh` sets it and the doc test passes. The run without it was not tried, so treat it as a precaution until the adapter's tests say otherwise.
- **Set `CARGO_TARGET_DIR` to the writable output directory** and `CARGO_HOME` to a path under the tmpfs home. Both must be on the supervisor's environment allowlist. Add `CARGO_NET_OFFLINE=true` for the `verify` profile as a second line behind `--network none`.

## Build and test

```sh
infra/sandbox-images/verify/build.sh        # builds and records the digest in images.json
infra/sandbox-images/test.sh --only verify  # posture tests
infra/sandbox-images/smoke.sh --only verify # the offline toolchain run alone
```
