# 0023: An agent's build writes in the output directory, never in the workspace

- Status: **Proposed, pending the owner**. Built on the branch `fix/agent-report-channel` from real run 32 of scenario E1. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the engineer, for the owner to confirm.
- Amends: the closed tool environment of `crates/runtime/src/command.rs` (`EnvName`, NT-TOOL-06) by four names. Related: [ADR 0005](0005-agent-runtime-adapter-boundary.md) (Model A: the tool and its commands share one container), `docs/security/sandbox-policy.md` sections 6.1, 6.5 and 7.

## Context and problem statement

Commit `abbc402` put the image's Rust toolchain on the `PATH` the adapters give Claude Code and Codex, so in run 32 the builder found `cargo` and ran `cargo test`. Cargo wrote its `target/` directory beside the manifest, inside `/workspace`. The ingestion audit then refused every file under `target/debug/...` as a `deny_write` path, the gate `protected-paths-unchanged` failed, and the `IMPLEMENTATION` stage run ended BLOCKED with nothing committed.

The adapters start every tool with `env -i` and a closed list of variables (NT-TOOL-06), so nothing set on the container or in the image reaches the tool. The `verify` and `fetch_deps` sandboxes already set `CARGO_TARGET_DIR=/out/target`, `CARGO_HOME`, `CARGO_NET_OFFLINE` and `TMPDIR=/out` on the container (`crates/composition/src/sandbox_specs.rs`, `profile_env`), but the `agent` profile set none, and `env -i` would have dropped them anyway. The agent image's Dockerfile said "the supervisor sets the cargo variables", which was not true.

## What the `agent` sandbox has (checked in the code, 2026-11-20)

- **`/out` is always there.** `WorkspaceMounts::out` is a required field; `create_args` (`crates/sandbox/src/container/args.rs`) binds it read-write at `/out` for every profile, with no `noexec` (only the `/tmp` tmpfs carries `noexec`), and the bind allowlist names it. A workspace from the provider and the scratch workspace of a stage with no repository both make it.
- **`/out` is never ingested.** `ingest` walks the checkout only (`crates/sandbox/src/workspace/ingest.rs`); no host code reads an `agent` sandbox's `out/`. The gate commands that `cat` a report from `/out` run in a `verify` sandbox, whose workspace is a new attempt directory: `make_directories` creates `out/` with `create_dir`, so it is always empty at the start, and the agent's `/out` can never reach a gate. `dispose` removes the attempt directory with it.
- **`/out` has a size limit.** The watchdog measures `/workspace` and `/out` together and kills the container past `workspace_disk_mb` (2048 MB for `agent` in `policies/security.yaml`).
- **The home and `/tmp` are `noexec`.** A test binary or a `rustdoc` doctest cannot run from there, which is why the `verify` sandbox already uses `/out` as `TMPDIR`.
- **The network reaches the broker's sidecar only**, so cargo cannot reach a registry.

## Considered options

1. **`CARGO_TARGET_DIR=/out/target`, set by the adapters from configuration** (chosen). The output directory is writable, executable, size-capped, never ingested and new for each workspace. It is the place the `verify` sandbox already builds into, so the builder and the trusted gates name the same directory, from one constant (`factory_ports::sandbox::BUILD_TARGET_DIR`). No new mount, no change to the spec, the posture check or the ingestion.
2. **A dedicated mount for the target directory**, for example a writable cache under `/caches`. It could survive between attempts and speed up builds. Rejected: a target directory that outlives an attempt is a channel from one untrusted run to the next (build-script outputs, planted artifacts, incremental state), the spec, the bind allowlist, the posture verifier and the watchdog would each need a new case, and the speed is not worth that while the attempt-local directory works. It stays the option to revisit if build time becomes the bottleneck, with a cache written only by a trusted run, as `fetch_deps` does.
3. **Teach ingestion to skip paths the repository's `.gitignore` ignores.** Rejected for the audit's security role. The audit sees every byte the sandbox wrote, and `.gitignore` is a file the repository and the agent control: the agent could add a pattern that hides a planted file, a nested `.git`, a link or a FIFO from the walk, and the protected path and hidden path checks would then rest on the attacker's own list. It would also leave a gigabyte-sized `target/` in the tree the host walks and the watchdog counts, and still fail for a project that does not ignore `target/`.
4. **A fixed exclusion of `target/` in the ingestion rules.** Rejected: the generic audit would learn about one build tool, a repository that tracks a `target/` directory would lose its checks there, and the agent would get a fixed path whose contents are never looked at.
5. **`CARGO_TARGET_DIR` in the run's home under `/tmp`.** Rejected: the scratch tmpfs is `noexec`, so `cargo test` could build but not run the tests, and its 512 MB would hold little of a build.
6. **Set the variables on the `agent` container** (`profile_env`). Rejected: `env -i` clears them before the tool starts, which is the point of NT-TOOL-06; only the adapter's own list reaches the tool.

## Decision outcome

Option 1. `EnvName` gains `CARGO_TARGET_DIR`, `CARGO_HOME`, `CARGO_NET_OFFLINE` and `TMPDIR`. `factory_runtime::command::BuildEnv` (target directory, temporary directory, offline) is a field of `ClaudeCodeConfig` and `CodexConfig`; the composition root fills it from `sandbox_specs::agent_build_env()`, which takes the target directory and the temporary directory from the same constants the `verify` sandbox uses and sets `offline` to true. Each run gets `CARGO_TARGET_DIR=/out/target`, `CARGO_HOME=<the run's home>/.cargo`, `CARGO_NET_OFFLINE=true` and `TMPDIR=/out`. The probe commands do not get them; they start no build.

NT-TOOL-06 still holds: the names are from the closed set and the values are fixed text from configuration, refused if they hold a control character. Nothing the request, the repository, the prompt or the agent wrote becomes a name or a value. A repository's `.cargo/config.toml` `build.target-dir` does not move the build back, because cargo prefers the environment variable. The agent can still run `CARGO_TARGET_DIR=target cargo test` in its own shell; the audit then refuses the change as before, so the failure stays closed.

### Costs

- The build counts against the `agent` profile's 2048 MB disk cap, where before it would have counted too (in `/workspace`). A large debug build can reach it and the watchdog kills the container; the cap is the policy's to raise.
- Each attempt builds from scratch: the target directory does not survive the attempt (option 2 is the faster, riskier alternative).
- `CARGO_NET_OFFLINE=true` with an empty `CARGO_HOME` means a project with crates.io dependencies cannot resolve them in the `agent` sandbox. That was already true (no network), and the variable only makes cargo fail at once instead of after a connection timeout. Giving the builder the vendored or cached dependencies is a separate decision.

## What was checked and what was not

- Checked: the unit test `a_builders_cargo_writes_outside_the_workspace_in_a_place_that_runs_programs` (`crates/runtime/src/command.rs`), the scripted runs of both adapters in `negative_nt_tool_06_hostile_request_values_never_become_environment_names`, the composition test that the builder and the `verify` sandbox build into the same place, and the ports test of the layout constants.
- Not checked here: a real `cargo test` by the builder in the agent image (the real-container test `negative_nt_tool_06_the_tools_environment_is_the_adapters_list_...` now also asserts the variables in the tool's shell, but it needs images this host does not hold), and a rerun of scenario E1.
