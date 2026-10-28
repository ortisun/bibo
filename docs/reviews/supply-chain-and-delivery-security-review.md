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
