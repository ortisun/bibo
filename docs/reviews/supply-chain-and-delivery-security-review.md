# Security review of the supply chain gates and the delivery boundary

- Reviewer: security specialist, acting as an independent reviewer. I wrote none of the code under review and changed none of it.
- Date: 2026-10-28
- Commit reviewed: `8680915` (`feat/slice-0-foundation`, "Merge the supply chain gates"; the worktree was fast-forwarded from `119607d`).
- Scope A: `crates/workflow/src/gates/supply_chain/**`, its tests and data, work package `s1-supply-chain-gates`, `policies/security.yaml`, `policies/approval.yaml`, `deny.toml`, `crates/domain/src/policy/dependency.rs`, the threat model (T-29, T-30) and NT-SUP-01 to NT-SUP-06.
- Scope B: the seven policy contradictions the builder reported.
- Scope C: the five gaps at the delivery and approval boundary reported by the author of the stage-contract suite.
- What I added: the test target `crates/workflow/tests/supply_chain_review/` (found by cargo without a `[[test]]` line, so no existing file was edited) and this document.
- Attacker model: someone who controls the candidate repository, or a dependency author, and nothing else. No credentials, no access to the ledger, no access to the composition root.

## Verdicts

| Scope | Verdict | Why |
|---|---|---|
| A. Supply chain gates | **FAIL** | Three high findings let a candidate repository get past the two controls the policy calls absolute: a human decision on every new direct dependency (SC-1, SC-2) and an advisory scan that cannot be silenced by the repository being scanned (SC-5). Each is proven with a failing test, and SC-1 and SC-5 with the real tools. |
| B. Policy contradictions | **PASS WITH CONDITIONS** | None of the seven gives an attacker a lever on its own. Most block legitimate work and fail closed. Item 7 is a real gap in binding, and items 2 and 4 must be closed before the first real dependency can be approved. |
| C. Delivery and approval boundary | **PASS WITH CONDITIONS** | No path found by which a human is shown a pull request that the engine should have blocked, as long as the engine pins inputs from passed runs only. All five items are missing second checks, and two of them contradict the stated habit of the stages to re-verify at the boundary. |

Scope A turns to PASS WITH CONDITIONS when SC-1, SC-2, SC-3, SC-5, SC-6 and SC-7 are fixed and their tests are un-ignored. Nothing below needs a design change; each fix is local to the gate package.

### What the numbers say

Scope A has 10 confirmed defects (3 high, 5 medium, 2 low), each with a test that fails on the current code, and 8 hypotheses, which have no failing test. Scopes B and C are judgements: 7 items and 5 items. Twenty-one new tests pass and pin what held.

## How I worked

I read the module, the policy and the tests, then attacked. Where cargo or cargo-audit could answer a question, I asked the real tool in a scratch directory outside the repository (cargo 1.98.0, cargo-audit 0.22.2, both offline, no network). I did not run any hostile fixture, build script or container on the host. Tests that fail by design are marked `#[ignore = "confirmed defect SC-n: ..."]`; tests without `ignore` pass and pin what held.

## Findings, scope A

Command for every confirmed row: `cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored <prefix>`, with the prefix in the Evidence column. Paths are under `crates/workflow/src/gates/supply_chain/`.

| ID | Sev | Status | Evidence | Impact | Smallest fix | Owner |
|---|---|---|---|---|---|---|
| SC-1 | high | confirmed | `cargo.rs:183` `reference` drops the `(source)` part; `model.rs:128` `resolve` returns `None` for two matches; `integrity.rs:378` `else { continue }`. Prefix `sc1_`. A lockfile written by real cargo for this shape was accepted by `cargo fetch --locked` and `cargo metadata --locked`. | A new registry package whose name and version equal those of a workspace member added in the same change is never a new direct dependency. No person is asked, the registry facts are not read, a `fetch_deps` container is made. One extra three-line `Cargo.toml` is enough. | Keep the source in `LockedRef`; match on name, version and source. When a reference does not resolve to exactly one package, add a violation instead of `continue`. | workflow (gate) |
| SC-2 | high | confirmed | `diff.rs:84` matches by version only, and the second package of a name and version is dropped from `added`. Cargo writes the path copy first. Prefix `sc2_`. | A registry copy of a base workspace member's name and version leaves the diff empty. `lock_changed()` is false, nothing is fetched, the advisories and SBOM gates report NOT_APPLICABLE ("the dependency set did not change"), and the internal-name check never sees it. The approval stage treats NOT_APPLICABLE as clear. | Compare the lockfiles as multisets of (normalized name, version, source kind and host). | workflow |
| SC-3 | medium | confirmed | `integrity.rs:373-381` and `policies/security.yaml` `new_means: name_absent_from_base_commit_lockfile`; `run.rs` `SupplyChainConfig.internal_names` is operator configuration. Prefix `sc3_`. | A crates.io package named like an internal workspace member, at any other version, is "not new" and needs no person, unless the operator happened to list that name. This is the textbook dependency confusion. | In `gate::run`, add the name of every `Origin::Path` package of the base lockfiles to `internal_names`. Change the policy wording to "absent from the base lockfile for the same kind of source". | workflow, then policy and domain |
| SC-4 | medium | confirmed | `diff.rs:60` scans all packages once per name and allocates on each comparison; `model.rs:128` `resolve` scans all packages per edge; `integrity.rs:388` `found.contains`. Prefix `sc4_`. Measured: 500 packages 61 ms, 1 000 203 ms, 2 000 824 ms, 4 000 3.39 s (debug). | A candidate lockfile at the 8 MiB bound (about 40 000 packages) holds a worker for minutes in debug and tens of seconds in release, on the host, before any sandbox limit. The check runs inside the async task. | Index packages once (`BTreeMap` by normalized name, a map for `resolve`). Refuse a lockfile above a package bound with a violation. Run the sync part in `spawn_blocking`. | workflow; composition for the blocking call |
| SC-5 | high | confirmed with the real tool | `cargo.rs:48` `kind_of` returns `None` for `.cargo/audit.toml`; `model.rs` `Side::of` drops it; `tools.rs:156` `parse_audit` ignores `settings.ignore`. Prefix `sc5_`. | `cargo audit` reads `.cargo/audit.toml` from the candidate checkout. With `[advisories] ignore = ["RUSTSEC-..."]` the real tool printed `found:false,count:0` and exit code 0 for a lockfile that otherwise gave `found:true`. The advisories gate reports PASSED. The same file can point `[database] path` at a database the candidate wrote. | Make `.cargo/audit.toml` a build-configuration file whose every key is unrecognised (any new or changed line fails). In `parse_audit`, refuse an answer whose `settings.ignore` is not empty. | workflow |
| SC-6 | medium | confirmed with the real tool | `tools.rs:36` `--no-fetch`; `parse_audit` never reads `database`. Prefix `sc6_`. | With `--no-fetch`, cargo-audit prints `last-commit:null,last-updated:null` and does not check age. A scratch database whose only commit was dated 2025-01-01 gave exit code 0 and a clean answer. `deny.toml` demands `maximum-db-staleness = "P7D"` for the factory's own CI; the gate has no such rule. | Have the image build write the database date to a file, probe it in the `verify` sandbox next to `cargo audit --version`, and BLOCK when it is missing or older than the bound. Record the date in the report. | workflow, infra images, policy (the bound) |
| SC-7 | medium | confirmed | `gate.rs:84-92` calls `RegistryMetadata::lookup` with candidate text; the name is validated later in `Plan::consider` (`review.rs`, `decide`). Prefix `sc7_`. | Names such as `../../admin`, `a?b=c` and `x%2f%2e%2e` reached the registry source before validation. The source speaks HTTP with control-plane egress. | Validate name and version with the domain rule first; call `lookup` only for a valid request. Document that implementations must percent-encode. | workflow; composition for the client |
| SC-8 | low | confirmed | `review.rs:249-253` writes `registry.repository` and `registry.license` raw. Prefix `sc8_`. | Text chosen by a package author, of any length, goes to the ledger and the decision page. | Pass both through `plain` and a length bound, as the rest of the gate does. | workflow |
| SC-9 | low | confirmed | `cargo.rs:121-131` reads `package.build` and `lib.proc-macro` only. Prefix `sc9_`. Cargo 1.98.0 lists a `custom-build` target for `[project] build = "x.rs"` and for a plain `build.rs`, and a `proc-macro` target for `crate-type = ["proc-macro"]`. | The `build-code-added` warning is blind to three spellings. It is only a warning, so the effect is small. | Read the `[project]` alias and `crate-type`. Leave the implicit `build.rs` to the path rule `**/build.rs` of the semantic checks. | workflow |
| SC-10 | medium | confirmed | `review.rs:349-399` `conclude` escalates only the closure of a new direct dependency; `report.rs` turns the rest into the warning `build-code-added`. `policies/security.yaml` says `build_script_added` blocks until `security_review`. Prefix `sc10_`. | A new transitive crate with a build script, pulled in by a feature flag or a changed manifest, passes the review with a warning. | Escalate every touched package that has build code and is new to the build. To know "new", read `cargo metadata` of the base lockfile too. Needs the approval action of B-2. | workflow, policy |
| H-1 | medium | hypothesis | `approval.rs:132-147`: `covers` and `satisfies` look at name, version, checksum and designation only. Passing tests `requirement_*` in `requirements.rs` show the record has no job, tenant or repository and that an old policy hash still covers. | An approval can be reused under a different policy bundle, after the approver left the allowlist, or (if loaded by the wrong key) in another job or tenant. | Add `policy_hash` to `Settings` and drop approvals that differ. Store job, tenant and repository in the ledger row and load by (tenant, job). Check the allowlist when loading. | workflow, composition |
| H-2 | medium | hypothesis | `model.rs` `Side::of(path, text)`; `gate.rs` `Inputs.head` and `Inputs.head_commit` are separate. Passing test `requirement_a_symbolic_link_blob_*`. | A symbolic link is a blob whose text is its target path. `version=4` is a valid empty lockfile, and cargo follows the link. The gate cannot see mode 120000 or a submodule. Separately, nothing ties the `Side` text to the commit the sandbox checks out. | Make the input a list of `(path, mode, text)` bound to a `CommitSha`; refuse any mode other than a regular file for a dependency file; assert `head.commit == head_commit`. | workflow (type), composition (read) |
| H-3 | low | hypothesis | `policies/security.yaml` `new_means`; `integrity.rs:282` `Upgrade => continue`. | A version upgrade, a second major version and the promotion of a transitive crate to a direct one get no human decision and no release-age check. The policy says so on purpose. A compromised new release of an existing crate reaches the build with only the audit tool in the way, and SC-5 and SC-6 weaken that. | Policy decision. Cheapest control: apply the 30-day first-release rule to every package that changed, as a warning that needs a security approver. | policy owner |
| H-4 | low | hypothesis | `domain/src/policy/dependency.rs` `within_one_edit`. Measured on 26 names. | Only a single edit is flagged. `reqwest-rs`, `clap-derive-macros`, `anyhow-ext`, `rnio` go to an ordinary approver. The human still decides, so this is scrutiny level, not a bypass. The popular list is 200 names written by hand (its own provenance says so). | Add suffix and prefix rules; refresh the list from the registry dump. | policy owner, domain |
| H-5 | low | hypothesis | `infra/sandbox-images/verify/Dockerfile` installs none of cargo-audit, cargo-deny or cargo-sbom. `tools.rs:36`. | With today's images the advisories gate is always BLOCKED (fail closed). Warnings (unmaintained, unsound, yanked) never block, while the factory's own CI uses `--deny warnings`. Offline, cargo-audit cannot check yanked status. Policy lists five scanners; the package runs one. | Build the tools into the image with the database; decide whether `--deny warnings` applies to candidates. | infra images, policy |
| H-6 | low | hypothesis | `run.rs:376` runs `cargo --version` without the command policy. | The vector is constant. The image has no rustup (`infra/sandbox-images/lib/toolchain.sh` removes it), so a `rust-toolchain.toml` cannot trigger a download. No exposure today. | Pass it through `allowed` for uniformity. | workflow |
| H-7 | low | hypothesis | `tools.rs:213` `is_cyclonedx` checks `bomFormat` only. | A document with no components passes as an SBOM. | Check `specVersion` and that the component count is at least the package count. | workflow |
| H-8 | low | hypothesis | `toml.rs` is TOML 1.0 only. | Cargo 1.98.0 accepts TOML 1.1 (multi-line inline tables, trailing commas, `\x` escapes). The reader refuses them, so a candidate fails closed, and a **base** file using them blocks every job on that repository. A first `Cargo.lock` with no manifest change is refused by `lockfile-only-edit`. Availability only. | Add the 1.1 forms to the reader with differential tests, or document the limit. | workflow |

## Details of the confirmed findings

### SC-1. A new registry package beside a same-named workspace member

How to see it with real cargo (scratch directory, offline):

1. Make a workspace with members `app` and `evil` (both `0.1.0` or `1.0.0`), and a directory source `vendor/evil` holding a second package `evil` of the same version with a `.cargo-checksum.json`. Replace `crates-io` by that directory in `.cargo/config.toml`.
2. `app` depends on `evil_reg = { package = "evil", version = "1.0.0" }`.
3. `cargo generate-lockfile --offline` writes `app`, then `evil` with no source, then `evil` with `source = "registry+https://github.com/rust-lang/crates.io-index"`, and `app` lists `"evil 1.0.0 (registry+...)"`.
4. `cargo fetch --locked --offline` and `cargo metadata --locked --offline` accept it.

The gate reads that lockfile (the test uses the same text without the replacement config, which is what the candidate would commit) and finds nothing to ask a person about. Through the whole gate (`sc1_the_gate_does_not_fetch_...`) a fetch container is made with no approval and with unknown registry facts, the worst case that normally goes to a security approver.

The same root cause hides the edge in `review.rs:401` `closure`, so build code under such a package never escalates either.

### SC-2 and SC-3. Name and version are not an identity

The base commit has an internal member `foo 0.1.0`. The candidate adds the registry package `foo 0.1.0`. In the lockfile the path package is first, `compare_name` pairs the old `foo 0.1.0` with it, and the registry package is filtered out of `added` because "the base already has that version". Result: the diff is empty. The advisories gate and the SBOM gate then say NOT_APPLICABLE with the reason "the dependency set did not change", and the engine and the approval stage count NOT_APPLICABLE as clear. The test `sc2_the_gate_scans_a_registry_copy_of_an_internal_member` shows both gates in that state.

With another version, `foo 9.9.9`, the diff sees the package, but the policy rule "new means the name is absent from the base lockfile" counts the internal member as the name, so the package is not new. The only protection is `internal_names`, which the operator fills by hand. `control_the_listed_internal_name_catches_...` passes: when the name is listed, a higher version is caught. SC-3 says the list must not depend on a person remembering.

### SC-5. The repository configures the scanner that judges it

```text
$ cargo audit --json --no-fetch --no-yanked --db ./advisory-db        # lockfile locks somecrate 1.0.0
... "vulnerabilities":{"found":true,"count":1,...}
$ printf '[advisories]\nignore = ["RUSTSEC-2020-0001"]\n' > .cargo/audit.toml
$ cargo audit --json --no-fetch --no-yanked --db ./advisory-db ; echo $?
... "settings":{...,"ignore":["RUSTSEC-2020-0001"],...},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}
0
```

The database in that run was a scratch git repository with one advisory (patched in 2.0.0). `--no-yanked` and `--db` were mine, to stay offline. The gate runs the tool in the candidate checkout, the file is part of the candidate, and `Side::of` throws away every path `kind_of` does not know. The tool even prints the ignore list back, and the parser does not read it.

### SC-6. The audit cannot say how old its database is

A scratch database with one commit dated 2025-01-01, run with `--no-fetch`, gave exit code 0, `found:false`, and `"last-commit":null,"last-updated":null`. The builder's own scripted audit prints `"database":{}`. The gate passes on both. The test is gate-level and uses the builder's harness.

### SC-7 and SC-8. Text from outside travels unchecked

`gate::run` asks for registry facts first and validates afterwards. The validation exists (`DependencyPolicy::decide` returns `InvalidName`), it is just in the wrong place. For the evidence, `plain` is used for every candidate string except `repository` and `license`, which come from a package author.

### SC-10. Build code arrives without a person

`conclude` finds the packages with a build script or a procedural macro among the touched packages. It escalates to a security approver only those that sit under a new direct dependency. The others produce the warning `build-code-added`. The policy table says `build_script_added` blocks until a security review. This cannot be fixed without an approval action for build code (B-2) and, for upgrades, without a record of what the base commit already had.

## What I tried that held

- **Manifest reader against cargo.** 86 crafted manifests were put through `cargo metadata --no-deps --offline` and through `CargoFormat::parse_manifest`. Both accepted 56 and read the same (package names and source kinds, no exception); cargo accepted and the reader refused 3 (TOML 1.1); both refused 13; cargo refused and the reader accepted 14, which is harmless because cargo cannot build them. The forms tried: renames, `target.'cfg(..)'` and quoted target names with dots, `dev_dependencies` and `build_dependencies` spellings, dotted keys at the root, inline tables, quoted and escaped keys (`"path"`), CRLF, a byte order mark, comments that mention `git`, multi-line strings with line-ending backslashes, `[ dependencies . evil ]`, arrays of tables, workspace inheritance with and without rename, optional dependencies, patch and replace in four spellings, duplicate keys, a table extended by a dotted key, control and look-alike characters. The only differences were in build-code detection (SC-9: a plain `build.rs`, a `[project]` table, `crate-type = ["proc-macro"]`). Thirty-seven of the manifests are kept as a recorded table in `reader.rs`, with cargo's answer written next to each, so the test needs no cargo. The three that the reader refuses are a false rejection, not a bypass. The other 49 of the 86 were exploratory and are not kept.
- **Build configuration.** 24 key spellings that redirect a fetch, name a program, set an environment or are simply unknown all fail the gate when new, including `include`, a quoted key that holds a dot, an inline table, `[alias]` (which would let `cargo audit` be replaced), `credential-alias`, `[target.*] runner`, and both file names in any directory. Unknown keys fail closed.
- **Lockfile layouts.** Versions 1, 5, a string and a float are refused; 2, 3, 4 are read. A lockfile with checksums in `[metadata]` is refused.
- **Order of fetch and decision.** `run::fetch` and `run::scan` re-check `Plan::may_fetch` themselves and return `PolicyDenied`; `gate::run` is not the only guard. The builder's tests cover the direct call.
- **Approval record.** `AuthorizedApproval::new` is `pub(crate)`, so the proof cannot be forged outside the domain crate. `from_json` refused a numeric id given as text, zero, a negative, a fraction, null, an upper-case checksum, a short checksum, another action or ecosystem, a short reason, a bad time, a bad hash, an unknown designation and a missing allowlist version. I read `authority.rs:1062-1081`: a missing requester with a new dependency is denied, and so is self-approval; the builder's tests cover both and a security-approver case that an ordinary approver cannot decide. I did not re-run those against the real allowlist file, which does not exist yet.
- **Names.** A look-alike Cyrillic letter is not a crate name and is refused as an invalid request. `-`, `_` and case are one letter.
- **Licenses.** `AND`, `OR`, `WITH`, `LicenseRef`, a missing field, an empty field, unbalanced parentheses, a trailing operator, a semicolon and an expression over 256 characters: nothing denied was let through. An `OR` that includes one allowed license passes, which is what the policy says.
- **Fail-open search.** Every `unwrap_or`, `Default` and early `return` in the package turns an unknown into the worst case (an unknown age is young, an unknown existence needs a security approver, an unreadable stdout is BLOCKED, a missing tool version turns PASSED into BLOCKED in `report.rs`). NOT_APPLICABLE is produced in three places only (`report.rs:427`, `:602`, `:725`); two are sound, the third is SC-2's effect and R-1.
- **Inputs the candidate cannot reach.** The popular-name list is `include_str!` data; the license list equals `deny.toml` by test; the clock is the port; approvals, internal names and registry facts do not come from the repository.
- **Sandbox request.** The fetch environment is a fixed list checked against `allowed_env_names` and `forbidden_env_names` (`ports/src/sandbox.rs:690`); there is no job token; the image removes rustup, so a `rust-toolchain.toml` cannot download a toolchain or point at a repository-owned one.
- **Tool output.** The metadata and audit parsers bound the package count and the advisory count, treat a truncated stream as unusable, and refuse a document whose `found` and `count` disagree.

## Scope B. The seven items the builder reported

| # | What | Verdict | Exploitable? | Smallest correct fix | Owner |
|---|---|---|---|---|---|
| B-1 | `command_sets` has no SBOM subcommand, so the SBOM gate is NOT_APPLICABLE, or BLOCKED when required. | Acceptable for now, with a condition. The policy asks for an SBOM only for a release or a high-risk job (`sbom.required_for`), and the master prompt says "where applicable". For every other job the report is true: the tool cannot run and the policy excludes the gate. For a release it is a permanent BLOCK. | No. The risk is that `SbomRule.required` is set wrong. If the composition root hard-codes `false`, a release passes with no SBOM. | Add `sbom` to the `cargo` `allowed_subcommands` once the image has `cargo-sbom`; build the tool into the image. The composition root sets `required` from the job's risk tier or release flag, never as a constant. | policy, infra images, composition |
| B-2 | `build_script_added` has `blocks_until: security_review` and `approval.yaml` has no such action. | A contradiction. The gate blocks and nobody can lift the block. Today the closure of a new direct dependency is released by a security approver's decision on the dependency itself, which approves the package, not the build code. | Not directly. A block with no key invites an out-of-band merge, and SC-10 shows the gate does not block at all for non-direct build code. | Add `approve_build_code` to `approval.yaml` (security approver, human, bound to package name, version and checksum). Use it in `conclude` and in the path rule for `build.rs`. | policy, then workflow |
| B-3 | No `WorkspacePurpose` for `fetch_deps`; it uses `Agent`, which is writable. | Real but small. The profile says `rw` limited to dependency directories. `Agent` makes the whole checkout writable and hides the `Hidden` paths, which is also what `fetch_deps` needs. `cargo fetch --locked` and `cargo metadata --locked` do not write source files. | No. Without code execution in this profile nothing uses the write access. | Add `WorkspacePurpose::FetchDeps`: read-only checkout, writable cache only. | ports, sandbox adapter, then workflow |
| B-4 | No command or ledger writer exists for a per-dependency approval; the approval verbs are PR-level. | A gap that stops all real use. Every new direct dependency BLOCKS forever. The danger is the shortcut: reusing the pull-request approval, which binds to no name, version or checksum. | Not today. Yes if the shortcut is taken. | A port for the decision ledger and a command `approve-dependency` that calls `approval::authorize` and `DependencyApproval::record` with the exact subject shown, stores job, tenant and repository, and runs the reason through the redactor (`record` does not). | ports, composition |
| B-5 | A new path dependency between workspace members fails the gate with no approval route. | Stricter than the policy, which says `registry_or_source_changed` blocks until human approval. Blocks monorepo work. | No. | Allow a path dependency whose target is a member of the same `[workspace]` (deterministic), or route it to a human action. Decide which. | policy owner |
| B-6 | `within_one_edit` is duplicated (`domain/src/policy/dependency.rs` and `integrity.rs:599` `near_miss`). | The two bodies are identical today. A change to one only would give two different "near" rules. | No. | Expose one function from the domain crate and call it from the gate. | domain |
| B-7 | A policy-hash change does not invalidate a recorded dependency approval. | A real binding gap, same as H-1 (`requirement_an_approval_decided_under_an_old_policy_hash_*` passes today). An approval decided under a weaker bundle stays valid after the bundle tightens. | Only with a policy change in between; no attacker lever. | Compare `approval.policy_hash` with the current hash in `Plan::new` and treat a mismatch as awaiting. | workflow, composition passes the hash |

## Scope C. The delivery and approval boundary

I read `delivery/input.rs`, `delivery/manifest.rs`, `delivery/documentation_gate.rs`, `delivery/contract.rs`, `approval/handler.rs`, `documentation_review/gates.rs` and `gates/framework/resolve.rs`, and the list of cases in `tests/stage_contracts/`. The deciding fact is `delivery/contract.rs`: every input is pinned from `upstream_output`, which accepts only runs with status `Passed`, and a run is `Passed` only when `resolve` returned `Pass` (a failed or blocked gate, a `CHANGES_REQUIRED` or `NEEDS_HUMAN` verdict, or a blocked reviewer does not give one).

| # | Gap | Can a human approve a pull request that should have been blocked? | Smallest fix |
|---|---|---|---|
| C-a | Delivery and approval parse the specification but do not require `status == approved`. Planning (`run.rs:91`), architecture (`run.rs:70`) and validation (`handler.rs:163`) do. | Only if the engine hands delivery a different specification than validation saw, for example a superseded one after a re-freeze. The validation binding (`binding.rs`) has no specification hash, so nothing would notice. Low. | Check `status == Approved` in `delivery::input::read`; add the specification hash to the validation binding. |
| C-b | The `documentation-review` verdict is read by hash only, in delivery and in approval. | No, while the documentation-review run is `Passed` only on `Resolution::Pass`. The code reviewer's verdict is checked (`manifest.rs:252`); this one is not, which is inconsistent. Low. | Parse it in `read` and refuse anything other than PASS, as for the code review. |
| C-c | Approval's `gates_clear` covers the validation reports and not the documentation gate reports, which it reads only to count translation warnings. | No for a FAILED report (the run could not be `Passed`). A BLOCKED report with a recorded disposition is clear for validation and unchecked for documentation, which is the same outcome by another route. The flag shown to the person says "clear" for a set it did not examine. Low to medium for honesty of the display. | Fold `documentation.reports` into `gates_clear` with the same `decided` rule. |
| C-d | Three copies of `parse_candidate` (implementation, validation, delivery). | No. The bodies are identical today. The risk is drift, and the three feed different decisions about which commit is delivered. Low. | One function in a shared module, with one test. |
| C-e | The specification's `metadata.job_id` and `commit_sha` (and `execution_mode`) are compared with nothing. | No, again only through an engine fault. The fields exist to be compared. A specification from another job or from a test-mode job would be accepted. Low. | Compare `job_id` with the running job, `commit_sha` with the base commit, and `execution_mode` with the job's, in delivery and approval. |

Verdict C is PASS WITH CONDITIONS: all five are cheap, and C-a and C-c should be done before the first real approval.

## What I could not verify, and why

- **A real registry.** No network. Registry facts (existence, first publication, license) were tested only through scripted tables. The registry client does not exist yet.
- **The real audit tool inside the pinned image.** cargo-audit 0.22.2 is installed on this machine and I ran it offline with a scratch database. The verify image has no cargo-audit, cargo-deny or cargo-sbom (H-5), so the advisories gate has never run against the real image.
- **`cargo sbom`.** Not installed here. Its command line in `tools.rs` is data, marked unverified by the builder, and still is.
- **Docker and the egress sidecar.** Not used. I did not verify the allow-list of hosts, the proxy variables, the writable cache across jobs of one tenant and repository, or that `fetch_deps` really has no job token. I read the types that enforce these (`FixedEnv`, `SandboxPolicy`, `create_verified`), not the adapter.
- **`cargo fetch` and `cargo metadata` against a hostile `build.rs`.** The instruction was not to run hostile fixtures on the host. I rely on cargo's documented behaviour that neither command compiles. The builder's test uses a scripted cargo.
- **The composition root.** It is being written elsewhere. Everything it must do is under the next heading.
- **Case-insensitive file systems.** A Docker Desktop bind mount on macOS is case-insensitive; `cargo.lock` against `Cargo.lock` was not tried.
- **Delivery and approval.** Scope C is a reading, not an attack with fixtures.

## Requirements on the composition root

The gate assumes each of these. They are requirements, because nothing in the library enforces them.

1. **Complete, regular, matched inputs (R-1, R-4, H-2).** Build `base` and `head` from the object store for exactly the base commit recorded at job start and exactly `head_commit`. Read every `Cargo.toml`, `Cargo.lock`, `.cargo/config` and `.cargo/config.toml` in the whole tree (and `.cargo/audit.toml` once SC-5 is fixed). Refuse the run (BLOCKED) on a listing error, a truncated listing, or any dependency file whose mode is not a regular file (symbolic link 120000, submodule 160000). An empty `Side` makes the integrity gate say NOT_APPLICABLE (`requirement_an_empty_side_*`).
2. **Configuration from outside the repository.** `internal_names` from organization configuration, plus (after SC-3) the base path packages. `popular` from the bundled list. `licenses` equal to `deny.toml`. `SbomRule.required` from the job's risk tier or release flag, never a constant.
3. **Environment.** `FetchSandbox.env` and `VerifySandbox.env` come from the command policy's `env` and `env_by_profile` (`CARGO_NET_OFFLINE=false` for fetch only), proxy variables set to the sidecar only, no credentials, no `CARGO_HOME` from the repository. The names must pass `allowed_env_names`. No job token (the gate already passes `None`).
4. **Images.** Pinned by digest, with rustup absent, `cargo-audit`, `cargo-sbom` and the advisory database inside, the database date readable (SC-6), and caches read-only in `verify`.
5. **Registry client.** Treat the name and version as hostile text: validate against the crate-name grammar, percent-encode, fixed host, no redirects off the host, bounded response and time. Return the default record on any error (the gate reads it as the worst case). Run through the control-plane egress path only.
6. **Approvals.** Load them from the ledger by (tenant, job), only rows written by the approval command through `approval::authorize` and `DependencyApproval::record`. Drop a row whose `policy_hash` is not the current one, whose `allowlist_version` is not valid now, or whose approver is no longer on the allowlist (H-1, B-7). Store job, tenant, repository and the subject the person saw. Never read an approval from the stage output document, an artifact the sandbox wrote, or a repository file. Redact the reason.
7. **One entry point.** Call `gate::run`; store `Done.evidence`; do not call `run::fetch` or `run::scan` directly. Treat `StageError::PolicyDenied` as a stop, not a retry.
8. **Execution.** Run the synchronous part (reader, diff) in `spawn_blocking` and bound the number of files and the total bytes before the call (SC-4).
9. **Workspace for the fetch.** Until `WorkspacePurpose::FetchDeps` exists (B-3), do not give the fetch workspace credentials or the object store.
10. **Command policy.** `cargo` keeps `audit`, `metadata` and `fetch` in `allowed_subcommands`, and `--locked` is forced for `fetch_deps` and `metadata`. Add `sbom` with the tool (B-1).

## Reproduce

```text
# the passing tests (21)
cargo test -p factory-workflow --test supply_chain_review --locked

# every confirmed defect (16 tests; all fail by design)
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored

# one finding at a time
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc1_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc2_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc3_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc4_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc5_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc6_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc7_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc8_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc9_
cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored sc10_
```

The tests use the builder's harness (`files.rs`, `people.rs`, `world.rs`) by path and do not change it. SC-4 takes no reading of the clock, because the workspace bans `Instant::now`; it runs the check on a thread and waits with a deadline. The cargo and cargo-audit evidence of SC-1, SC-5 and SC-6 was produced in scratch directories outside the repository; the steps are written out above so anyone can repeat them.

Checks run on this branch: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo xtask check-architecture`, and the secret scan (`./scripts/ci.sh --only secret-scan`) all pass. The builder's `supply_chain` target still passes (85 tests).

## Status after fixes

- Author of the fixes: the software engineer, on branch `worktree-agent-acab5747c201423c3`, from `8b2db5a`. I did not review my own work: a re-review follows, and the table below is a claim for the re-reviewer to check, not a verdict.
- The review's own text above is left as the reviewer wrote it. Where it says "fails by design", the test is no longer ignored (`cargo test -p factory-workflow --test supply_chain_review --locked -- --ignored` runs nothing).
- Where a test of the review had to change, it is named below with the reason.

### What is fixed

| ID | Status | What changed | Tests |
|---|---|---|---|
| SC-1 | fixed | A lockfile reference keeps its source (`LockedRef.origin`). `LockIndex::resolve` answers `One`, `Ambiguous` or `Dangling`, and an ambiguous or dangling reference is a violation (`lockfile-reference-ambiguous`, `lockfile-reference-dangling`), never a `continue`. | `sc1_*`, `identity::a_reference_that_names_two_packages_is_a_finding_and_is_not_skipped`, `identity::a_reference_that_names_no_package_is_a_finding` |
| SC-2 | fixed | The lock diff identifies a package by name, version and source, and equal identities pair off one to one. | `sc2_*`, `diff::tests::a_registry_package_beside_a_member_of_the_same_name_and_version_is_added`, `..._a_member_replaced_by_a_registry_package_...` |
| SC-3 | fixed | The names of the base commit's members are internal names without an operator list. A registry package with a member's name is a new direct dependency (a person decides, and the policy engine flags the internal name for a security approver). A registry package with a member's name **and version** is a `dependency-confusion` violation, direct or not. | `sc3_*`, `identity::the_name_of_a_base_member_is_internal_without_an_operator_list`, `identity::a_registry_twin_of_a_member_*` |
| SC-4 | fixed | The diff, the reference lookup and the name checks are linear (maps built once). A lockfile above 10 000 packages is unreadable (`MAX_LOCKED_PACKAGES`), and a change with more than 100 new direct dependencies is refused (`MAX_NEW_DIRECT`). 4 000 packages run in about 0.1 s in debug (the review measured 3.39 s). | `sc4_*` (three tests) |
| SC-5 | fixed, with a limit | `.cargo/audit.toml` is a build configuration file (every key unrecognised), and `deny.toml` and `audit.toml` anywhere in the tree are compared as text: add, edit or remove is a violation. File names are matched without regard to case. `parse_audit` refuses an answer whose `settings` hide advisories (`ignore`, `severity`, `target_arch`, `target_os`), as BLOCKED with the reason. **Limit:** cargo-audit 0.22.2 has no flag for a configuration path, so "the base commit's configuration" is enforced by equality (the candidate's file may not differ from the base's) and not by pointing the tool elsewhere. A base commit that has an `ignore` list therefore makes the advisories gate BLOCKED for that repository, which fails closed. | `sc5_*` (seven tests), the audit script `Ignoring` in the harness |
| SC-6 | fixed, policy row missing | The age of the advisory database is a fact (`AdvisoryDatabase::updated_at`) the composition root supplies from where the image was built. A clean audit against a database that is unknown, in the future or older than the limit is BLOCKED (`dependency_unavailable`) with the age; a clean one records how old the database was. The limit is `SupplyChainConfig.advisory_db_max_age_days`, default 7 (the `maximum-db-staleness = "P7D"` of `deny.toml`). `policies/security.yaml` has no row for it. | `sc6_*`, `gate_run::an_audit_against_a_database_*`, `validation::supply::an_advisory_database_older_than_the_limit_*` |
| SC-7 | fixed | `gate::run` asks the policy engine whether the name and version are a valid request before it calls `RegistryMetadata::lookup`; an invalid one is never sent and is refused by name afterwards. The review's own test became vacuous (see "Tests I changed"), so a second test was added. | `sc7_*` (two tests) |
| SC-8 | fixed | `repository` and `license` go through `plain` and a 200-character bound before the evidence. The URL characters `?`, `=`, `#` and `%` become `?`, so the stored link is for reading, not for following. | `sc8_*` |
| SC-9 | fixed | `[project]` is read as `[package]`, `crate-type = ["proc-macro"]` is a procedural macro, and a plain `build.rs` next to a manifest (matched without regard to case, unless `build = false`) is build code. The gate reads the presence of `build.rs` files only, never their text. | `sc9_*` (five tests) |
| SC-10 | fixed, policy row missing | A package that is new to the build and has a build script or is a procedural macro waits for a security approver, whoever asked for it; the decision is a `DependencyApproval` of a security approver on that exact name, version and checksum, and the evidence lists the subjects (`build_code_awaiting_a_security_approver`). A package that only changed version is not asked again: the gate has no record of what the base commit's version ran. | `sc10_*` (three tests) |
| H-1, B-7 | fixed | A recorded approval names its tenant and job (`DecisionScope`) and the review drops a decision for another tenant or job or taken under another policy hash. | `requirements::requirement_an_approval_names_its_tenant_and_its_job_and_no_other_covers`, `..._under_an_old_policy_hash_no_longer_covers_...`, `validation::supply::a_decision_taken_under_another_policy_or_for_another_job_does_not_count` |
| H-2 | partial | The stage refuses a dependency file that the patch shows as a symbolic link or a gitlink on either side. A link that the change does not touch cannot be seen: `JobRepo` returns bytes and no mode. | `supply::tests::a_dependency_file_that_becomes_a_link_or_a_submodule_is_found`, and the host-side link rule |
| H-4 | fixed | A name that is a popular name with one or two decorations (`reqwest-rs`, `clap-derive-macros`, `anyhow-ext`, `rust-serde`) is flagged as near a popular name, and a new direct dependency with it goes to a security approver. A name on the popular list is never a look-alike of another. The domain's own rule is unchanged (the domain is not mine to edit). | `lookalike::*`, `names::tests::a_name_is_a_lookalike_*` |
| H-7 | partial | An SBOM document must name `bomFormat` and a non-empty `specVersion` and list at least one component when the lockfile holds a registry package. The stricter "as many components as packages" was not done: the tool is unverified and the lockfile also holds development dependencies. | `tools::tests::only_a_cyclonedx_document_that_lists_its_components_is_an_sbom` |
| C-a | fixed | Delivery and approval require the specification to have status `approved`. | `negative::a_specification_that_is_not_approved_is_not_delivered`, `approval_stage::a_specification_that_is_not_approved_stops_the_approval_stage`, `boundary::break_a_specification_that_is_not_approved_*` |
| C-b | fixed | The `documentation-review` verdict is parsed and must be a `PASS` that names exactly the stored reports of the documentation gate (by identifier and by the hash of the stored report) and the frozen specification (`DocumentationGate::check_review`). The approval stage pins the specification and the verdict as inputs (`approval::contract::SOURCES` has seven now) and checks them again. | `negative::a_documentation_review_*`, `approval_stage::a_documentation_review_that_does_not_hold_*`, `boundary::break_a_tampered_documentation_review_*` |
| C-c | fixed | `gates_clear` covers the validation reports and the documentation gate reports by the same rule. | `approval_stage::the_documentation_gate_is_part_of_what_the_person_is_told_is_clear` |
| C-d | partial | The validation and the delivery stage share one `parse_candidate`. The third copy is in `stages/implementation/input.rs`, outside the paths I may edit. | `validation::input::tests`, the stage_contracts names test |

### The gate in the validation stage

`stages/validation/supply.rs` is the only caller of `gate::run`. The handler makes the four reports on every run and stores them with the other reports; the contract names them (`SUPPLY_CHAIN_GATES`), so an un-wired gate leaves a named gate with no report and the stage blocks (21 validation tests fail when the reports are dropped).

- A host-side rule refused the change: all four are BLOCKED, and no container is made.
- The change touches no dependency file (`RunSupplyChain::WhenDependencyFilesChange`, the default; `Always` is the other setting): all four are NOT_APPLICABLE, nothing is read, nothing is made.
- Otherwise both commits are listed with `JobRepo::list_at("**")` (a list as long as `max_paths` is taken as cut) and the dependency files are read with bounds on their number, size and total, from the committed trees, never the sandbox.
- The seams come in through `ValidationConfig.supply_chain` (`SupplyChainSeams`): `RecordedApprovals` (loaded by tenant and job), `RegistryMetadata`, `AdvisoryDatabase` and the settings (fetch sandbox, licenses, popular and internal names, SBOM rule, age limit, bounds). The verify sandbox, policy engine and redactor are the stage's own.
- The plan's decisions are stored in the `validation-evidence` document under `dependency_review`.

### How a person is asked, exactly

1. A new direct dependency with no recorded decision makes `dependency-review` BLOCKED with the code `policy_unresolvable`. The missing item reads `a recorded human decision for: <name> <version> (<designation>[: reasons])`. No fetch container is made. The engine ends the stage run as blocked (`Resolution::Blocked(GateBlocked("dependency-review"))`).
2. The verdict the person gives is the **dependency approval**: the policy action `add_new_direct_dependency`, decided through `approval::authorize` and stored with `DependencyApproval::record(authorization, subject, policy_hash, DecisionScope { tenant, job }, reason)`. The subject (name, version, checksum), the designation that must decide (`approver`, or `security_approver` when the registry facts are bad or unknown) and the reasons are in `validation-evidence.dependency_review.new_direct_dependencies`. For build code in a package that no new direct dependency brings, the same record by a security approver on the subject in `build_code_awaiting_a_security_approver`.
3. The command that lets the blocked stage run go again is the operator's `UnblockRerun` (S17). Its guard `G_BLOCK_CLEARED_RERUN` has two alternatives, a capability re-probe and "the missing dependency is now available"; there is none for "a decision was recorded", so the composition root has to pass `dependency_now_available = true`. That is the nearest fit, and the state machine owner should decide whether to add the alternative.
4. `Decision::Override` (S18) is **not** the way: it passes the stage without a decision bound to a package, a version and a checksum. The override policy for the block code `policy_unresolvable` on gate `dependency-review` must say that it is not permitted.
5. What does not exist yet is the writer: no command or ledger row writes a dependency approval (B-4). Until the composition root builds it, every new direct dependency blocks for good, which fails closed.

### What the lead must add, because I may not edit it

- `policies/approval.yaml`, `actions`: a row `approve_build_code` (requires human, `approver_roles: [security_approver]`, bound to name, version and checksum, threats T-29 and T-30). SC-10 uses `add_new_direct_dependency` with the designation `security_approver` as the carrier of that decision until the row exists. The row `add_new_direct_dependency` also needs its `when` text to say that it covers build code in a new package.
- `policies/security.yaml`, `supply_chain`: `advisory_database: { max_age_days: 7 }`, read by the composition root into `advisory_db_max_age_days`; and the wording of `new_direct_dependency.new_means` should become "the name is absent from the base commit's lockfile as anything but a member of the project (a package with no source)", which is what the gate does.
- `policies/security.yaml`, `supply_chain` or the stage settings: whether the dependency gates run on every change (`RunSupplyChain::Always`) or only when a dependency file changes. The policy has no row; the default is "only then".
- The override policy: no override for `policy_unresolvable` on `dependency-review` (see 4 above).
- `docs/architecture/state-machine.md`, guard `G_BLOCK_CLEARED_RERUN`: an alternative for a recorded decision (see 3 above).
- The domain crate: `within_one_edit` and the decoration rule of H-4 belong in `DependencyPolicy` (B-6); the gate keeps its own copy in `names.rs` until then.

### Requirements on the composition root, after the fixes

1. **Complete, regular, matched inputs.** The stage now builds `base` and `head` from the object store for the two commits it holds, lists the whole tree, bounds the read, and blocks on a failed, cut or oversized read. Still the composition root's: the `JobRepo` adapter must return an error, not an empty list, when the listing fails, and should expose the file mode so that a link the change does not touch can be refused (H-2).
2. **Configuration from outside the repository.** Unchanged, except that the members of the base commit are added to `internal_names` by the gate. `SbomRule.required` still comes from the job's risk tier or release flag.
3. **Environment.** Unchanged.
4. **Images.** Unchanged, and now the date of the advisory database must reach the `AdvisoryDatabase` seam (a label or a file written by the image build). The image still lacks `cargo-audit`, `cargo-sbom` and the database (H-5): the advisories gate is BLOCKED until it has them.
5. **Registry client.** Still the client's own duty to percent-encode, fix the host, refuse redirects off the host, bound the response and the time, and return the default record on any error. The gate now sends it only names and versions that pass the policy engine's rule.
6. **Approvals.** Load by tenant and job from rows written by the approval command, and drop a row whose approver left the allowlist or whose `allowlist_version` is not valid now (the gate drops other tenants, other jobs and other policy hashes itself). Store the job and tenant in the row; `DependencyApproval::to_json` writes `tenant_id` and `job_id` and `from_json` refuses a row without them. Redact the reason (`record` does not).
7. **One entry point.** `stages/validation/supply.rs` is it. Treat `StageError::PolicyDenied` as a stop.
8. **Execution.** Run the stage's synchronous reading in `spawn_blocking` if the runtime is shared with latency-sensitive work: the checks are linear and bounded now (10 000 packages, 100 new direct dependencies, 2 000 files, 32 MiB), but they still run in the async task.
9. **Workspace for the fetch.** Unchanged (B-3).
10. **Command policy.** Unchanged, and `sbom` is still absent from `allowed_subcommands` (B-1).

### What is not fixed, and why

- **H-3** (an upgrade, a second major version or a promotion to direct gets no human decision): a policy decision.
- **H-5** (the image has none of the scanners): infra images.
- **H-6** (`cargo --version` outside the command policy): the policy has no entry for a bare `--version`, so passing it through `allowed` would block the fetch for good; the vector is constant and the image has no rustup.
- **H-8** (TOML 1.1): availability only; not done.
- **B-3** (`WorkspacePurpose::FetchDeps`): ports. **B-4** (the approval command and ledger writer): ports and composition root. **B-5** (a path dependency between members): policy. **B-2** (the approval row): see above.
- **C-d**, the copy in `stages/implementation/input.rs`; **C-e** (the specification's job, commit and mode compared with the running job): not done, because the stages do not hold the running job's mode at that point and I judged it larger than a small change.
- **A gap I saw while fixing, not in the review:** `Origin::Git` holds the host only. A package that stays a git package on the same host and changes repository or revision has an equal origin and no checksum, so the diff does not see it if the base already held it from git. The base should never hold a git package under this policy, so the exposure is small.
- **Dependency files that are unchanged symbolic links** (H-2), and a **bound of 50 000 paths** for the tree listing: a monorepo above it is BLOCKED, which fails closed and has to be raised by configuration.
- **A base commit with an `ignore` list in `.cargo/audit.toml`** blocks the advisories gate for that repository (SC-5 limit).

### Tests I changed

- `identity::control_the_listed_internal_name_catches_a_registry_package_with_another_version` became `control_the_listed_internal_name_still_reaches_a_security_approver`. After SC-3 the package is a new direct dependency that a security approver decides, not a violation, and the test asserts that and the flag.
- `requirements::requirement_an_approval_names_no_job_no_tenant_and_no_repository` and `..._an_old_policy_hash_still_covers_the_dependency` described the behaviour that H-1 and B-7 removed. They now pin the new binding. The repository is still not in the record.
- `registry_input::sc7_the_registry_source_is_never_asked_about_a_name_that_is_not_a_crate_name` stopped being a test of SC-7: the name `a b` makes a dangling lockfile reference, which is a finding of its own, and the lookups never start. It is kept, and `sc7_only_the_ordinary_name_reaches_the_registry_source` tests the lookup with names the lockfile can reference.
- `freshness::sc6_*` sets the world's database age to unknown (`World::database_updated(None)`); the harness default is a database one day old.

### Deliberate breaks

Each break was made in the source, the named tests were run, and the source was restored. A break that no test noticed was a reason to add a test, and two were added (see the commit "Sharpen the tests").

| Break | Caught by |
|---|---|
| The diff keyed by version only | three tests in `diff.rs`. No integration test notices, because the one-to-one pairing and the other checks catch the same input independently. |
| Ambiguous references resolved by taking the first | `cargo::tests::a_reference_keeps_its_source_*`, `identity::a_reference_that_names_two_packages_*` |
| The candidate's audit configuration trusted | nine tests (`only_dependency_files_are_recognised`, `scanner_absence_is_blocked_*`, seven `sc5_*`) |
| The age of the database not checked | `gate_run::an_audit_against_a_database_*` (three), `sc6_*`, `validation::supply::an_advisory_database_older_than_the_limit_*` |
| The registry client called without validating the name | `sc7_only_the_ordinary_name_reaches_the_registry_source` (the review's own test did not notice) |
| The gate not wired into the validation stage | 21 tests in the validation target, the contract test among them |
| The approved-specification check removed from delivery and approval | `negative::a_specification_that_is_not_approved_is_not_delivered`, `approval_stage::a_specification_that_is_not_approved_stops_the_approval_stage`, `boundary::break_a_specification_that_is_not_approved_*` (the first version of the last two passed for another reason, because the changed specification no longer matched the verdict, and were sharpened) |
| The documentation review read by hash only | three tests in the delivery target and one in `stage_contracts::boundary` |
| `gates_clear` without the documentation reports | `approval_stage::the_documentation_gate_is_part_of_what_the_person_is_told_is_clear` |

## Changes by the lead, after the fixes

- Author: the software engineer, on branch `worktree-agent-a2deb145ce58a4797`, from `520aa88`. This section lists what the fix author could not edit (the policies, the state machine, the domain crate) and the Rust that had to travel with it. It is a claim for the re-reviewer, not a verdict.
- Each change was written test first, and each has a deliberate break in the table at the end.

### What was done

| Item | What changed | Where the proof is |
|---|---|---|
| B-2, SC-10 | `approval.yaml` has the action `approve_build_code` (a security approver, human at every level, bound to the exact name, version and checksum of the package whose build script or macro comes in, threats T-29 and T-30), and the row `add_new_direct_dependency` says it does not cover build code. The policy engine refuses to build when the row names anyone but the security approver, and answers `approver_designations(action)`, so the gate names no designation. The gate records two kinds of decision (`ApprovalKind`) and one never stands for the other. The person is asked about the package that has the build code, not the direct dependency above it. The evidence key is now `build_code_awaiting_a_decision`. | `policy_content::build_code_of_a_new_package_is_a_security_approvers_own_decision`, `authority::approving_build_code_is_a_security_approvers_decision_and_nobody_elses`, `engine::a_policy_that_lets_anyone_but_a_security_approver_approve_build_code_does_not_build`, `build_code::sc10_*` |
| SC-6, SC-3 wording | `supply_chain.advisory_database.max_age_days: 7` (the `P7D` of `deny.toml`, checked equal by a test), a typed field of the loaded policy, a ceiling in the tighten table. `SupplyChainSettings::from_policy` starts from it, and the gate uses the lower of the configured value and the policy's: a composition root may lower the limit and never raise it. `new_means` is `name_absent_from_base_commit_lockfile_as_anything_but_a_project_member`; the engine reads exactly that and refuses the old wording. | `validation::supply::the_composition_root_may_lower_the_database_age_limit_and_never_raise_it`, `..._even_when_the_stage_was_built_without_reading_the_policy`, `tighten::negative_nt_pol_02_*`, `dependency_risk_budget::the_wording_of_new_*` |
| Run always, or only on a dependency file | **Only when a change touches a dependency file**, written as the policy value `supply_chain.dependency_gates.run_when: dependency_files_change`. `always` is the stricter value: a project policy or the configuration may move to it and never back. Reasons below. | `validation::supply::the_policy_can_make_the_gates_run_on_every_change_and_the_configuration_cannot_undo_it`, `tighten::a_project_cannot_move_the_dependency_gates_back_*` |
| Override of an unresolved review | `gate_integrity.non_overridable_blocks` lists `dependency-review` with `policy_unresolvable`. The engine will not build without that entry, `authorize_override` returns `NoOverrideForBlock`, and `OverrideFacts::from_policy` and `OverrideFacts::for_reports` compute the fact `policy_permits` from the policy and from the stage's gate reports, so a caller does not write it. A project may add entries and never remove one. | `validation::supply::nobody_overrides_the_block_of_a_dependency_that_waits_for_a_decision` (through the stage), `override_policy.rs` (through the engine and the in-memory store), `authority::nobody_overrides_*` |
| `UnblockRerun` guard | `G_BLOCK_CLEARED_RERUN` has a third alternative, "a decision on the dependency was recorded". It is in `state-machine.json`, in the rendered document, in the domain guard and in the engine, which reads it from what it stored. There is no flag to pass. A decision counts only for the attempt that blocked the run. | `guards::tests::a_block_is_cleared_by_*`, `dependency_decision::an_unblock_with_no_recorded_decision_is_refused_*`, `..::a_decision_made_before_a_later_block_does_not_clear_it`; `cargo xtask check-invariants` still finds INV-01 to INV-11 |
| B-4 | `Engine::record_dependency_decision`, over the existing ports, and `LedgerApprovals` (a `RecordedApprovals` that reads the ledger). No port changed. The pure parser and resolver of the words a person writes are in `gates::supply_chain::command`. See below. | `crates/workflow/tests/dependency_decision.rs` (14 tests), `command::tests::*` |
| B-6, H-4 | `within_one_edit`, `is_decorated` and `DECORATIONS` are public in `domain::policy::dependency`. The policy engine uses both (a decorated popular name goes to a security approver), and the gate's copies are deleted. | `dependency_risk_budget::the_edit_rule_and_the_decoration_rule_*`, `..::a_popular_name_with_a_decoration_*` |
| `Origin::Git` | Holds host, repository and pinned revision. A git package that moves repository or revision on the same host is a `SourceChanged`. | `cargo::tests::a_git_package_that_moves_repository_or_revision_on_one_host_is_a_difference`, `diff::tests::a_git_package_on_the_same_host_*` |
| C-d | `implementation::input` re-exports the one `Candidate` and `parse_candidate` of the validation stage. | `implementation::input::tests::the_candidate_is_the_one_the_validation_stage_reads` |

### Why the dependency gates run only when a dependency file changes

The master prompt asks for "dependency/SBOM/license checks ... where applicable". The gates judge a change: new names, changed sources, the code that comes in. Run on every change, the advisory scan would fail an unrelated change for an advisory published after the base commit against a package the change never touched, and the change could not fix it. That judgment, whether the repository's existing dependencies have a known advisory today, belongs to a scheduled scan of the base branch. **That scan does not exist yet**, so nothing currently notices a new advisory against a dependency that stays unchanged. The policy owner should decide whether to build it or to switch `run_when` to `always`. The value is in the policy so that this is a one-line decision and not a code change.

### How a person decides, now

1. The review blocks with `policy_unresolvable` and stores, in `validation-evidence.dependency_review`, the packages that await a decision (`new_direct_dependencies` with `approval: null`, and `build_code_awaiting_a_decision`), each with name, version, checksum and the designation the policy names.
2. The API or the command line reads the words (`parse_dependency_command`: `/factory approve-dependency <name> <version> [checksum prefix] [reason]`, or the same without the prefix; `approve-build-code` for build code), finds the one awaited package they name (`resolve`), asks the policy engine for the proof (`approval::authorize` or `authorize_build_code`), and calls `Engine::record_dependency_decision` with the proof and the exact package.
3. The engine checks the proof against the acting principal's numeric id and the roles that principal holds now, that the stage run is a blocked validation run, and that its own stored evidence awaits exactly that package of that kind with a designation that is enough. It binds the record to the policy hash it runs under, stores the document, links it to the stage run, appends one ledger entry (an expert judgment that names the person and cites the document by hash) and audits it. A repeated command writes nothing.
4. The operator's `UnblockRerun` now passes the guard, the stage runs again, and the gate reads the decisions back through `LedgerApprovals`.

### What the composition root still has to do

- Build `SupplyChainSettings` with `from_policy`. Use `LedgerApprovals` as `SupplyChainSeams.approvals`. Build `OverrideFacts` with `from_policy` or `for_reports` and never write `policy_permits` by hand.
- Implement the entry point that reads a comment or a command line and calls the functions in step 2. It must run the person's reason through the redactor first: **the engine has no redactor** (`EngineDeps` has none), so `RecordDependencyDecision.reason` is `HumanText` and not redacted text. This is the one requirement of item 6 above that the engine cannot meet by itself.
- Keep reading the allowlist for each call (`Authority::roles`). The engine re-reads the roles, but the proof is made by the caller with the allowlist version it read.

### What is not done, and the contradictions I found

- **The engine does not enforce the override rule on its own.** `Decision::Override` still takes `OverrideFacts` from the caller, and the engine's block event records the cause code (`gate-blocked`) and not the gate or the report's code. A caller that writes `policy_permits: true` by hand still gets the override accepted. The rule is enforced where the facts are computed. To make the engine enforce it, the block event would carry the blocked gate and code and the override would read them back. That is a change to the engine's event payload, and I did not make it.
- **No scheduled scan of the base branch** (see above).
- **The decision is not stored in a table of its own.** It is a ledger entry plus an artifact plus a stage-run link. That is enough for the gate and for `UnblockRerun`, and it needs no port change. A query "every decision of tenant X" would need a scan of ledgers.
- **A repeated command is recognised through the role of its link**, not through the outbox, because a decision writes no outbox event (it changes no status). The duplicate check of ground rule 7 by `Timeline::has_applied` does not see it.
- **`approval.yaml` `commands.verbs`** still lists the six verbs of the pull request. The two new verbs are read by the dependency parser and are not in that list. If the project wants one list, the verb table of `stages::approval::command` and the policy list change together.
- **H-3, H-5, B-1, B-3, B-5, C-e** are untouched, as before.

### Deliberate breaks of this section

Each was made in the source (or the policy file), the named tests were run, and the source was restored.

| Break | Caught by |
|---|---|
| An override accepted for the unresolved review (`block_may_be_overridden` always true) | six tests: `authority::nobody_overrides_*`, `engine::a_policy_that_allows_an_override_*`, `override_policy` (three), `validation::supply::nobody_overrides_*` |
| The guard alternative removed | five tests: `guards::tests` (two), `dependency_decision` (three) |
| The approval taken without comparing the numeric id | not caught at first: the test used a person of another designation, so the role check refused it before the id was compared. The test now uses a second approver, and `a_proof_made_for_another_person_is_refused` fails on the break |
| A stored record that names a person by login accepted as an approval | `review::a_stored_record_that_names_a_person_by_login_is_not_an_approval` |
| `approve_build_code` granted to an ordinary approver, in the policy file | seven tests, among them `policy_content::build_code_of_a_new_package_is_a_security_approvers_own_decision` and `policy_domain_fixture` |
| The same, in the engine's own check | `engine::a_policy_that_lets_anyone_but_a_security_approver_approve_build_code_does_not_build` |
| A project policy that raises the database age limit (the rule turned into a floor) | `tighten::negative_nt_pol_02_each_widening_is_refused_and_names_its_key` and `..._tightenings_are_accepted` |
| The row for the age limit removed from the tighten table | `tighten::negative_nt_pol_02_tightenings_are_accepted` (the key is frozen, so a lower value is refused) |
| The configuration may raise the limit above the policy | `validation::supply::the_composition_root_may_lower_*` and `..._even_when_the_stage_was_built_without_reading_the_policy` |
| The stage ignores the policy's `run_when` | `validation::supply::the_policy_can_make_the_gates_run_on_every_change_*` |
| A dependency decision accepted as the decision on build code | `build_code::sc10_only_a_build_code_decision_*`, `gate_run::build_code_blocks_until_*` |
| The engine does not check that the evidence awaits the package | `dependency_decision::a_decision_is_recorded_only_for_a_package_the_evidence_shows` and two more |
| The engine does not check that the designation is enough | `dependency_decision::an_ordinary_approver_cannot_decide_what_needs_a_security_approver` |
| The parser in `cargo.rs` keeps the host only | `cargo::tests::a_git_package_that_moves_repository_or_revision_on_one_host_is_a_difference` (the diff test builds origins by hand and did not notice) |
