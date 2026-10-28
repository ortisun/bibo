//! The whole gate against the in-memory ports: what is fetched and when, what runs where, and
//! what each of the four reports says.

use factory_domain::contracts::gate_report::{BlockedCode, ExecutorKind, SandboxNetwork};
use factory_domain::policy::SandboxProfileKind;
use factory_domain::policy::commands::CommandVerdict;
use factory_domain::policy::decision::Designation;
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::GateOutcome;
use factory_ports::artifact::ArtifactStore;
use factory_ports::sandbox::{NetworkAttachment, SandboxProfile};
use factory_workflow::gates::supply_chain::approval::{DependencyApproval, Subject};
use factory_workflow::gates::supply_chain::facts::{RegistryRecord, StaticRegistry};
use factory_workflow::gates::supply_chain::findings::check;
use factory_workflow::gates::supply_chain::report::gate;
use factory_workflow::handlers::StageError;

use super::files::{Files, base, head_adding, lock, manifest, member, reg, sum, with};
use super::people::{
    APPROVER, REQUESTER, SECURITY, approve, authorized, decide, engine, human, policy_hash,
};
use super::review::{at, old_and_licensed, plan_with, record, table};
use super::world::{
    Attempt, AuditScript, Marker, Script, Where, World, metadata, unknown_registry,
};

fn registry() -> StaticRegistry {
    StaticRegistry::new().with("some-crate", old_and_licensed())
}

fn subject() -> Subject {
    Subject {
        name: "some-crate".to_owned(),
        version: "0.1.0".to_owned(),
        checksum: sum('c'),
    }
}

fn by_approver() -> DependencyApproval {
    approve(APPROVER, "bob", Designation::Approver, &subject()).expect("recorded")
}

fn by_security() -> DependencyApproval {
    approve(SECURITY, "sam", Designation::SecurityApprover, &subject()).expect("recorded")
}

fn head() -> Files {
    head_adding("some-crate", "0.1.0", 'c')
}

fn clean() -> Script {
    Script {
        metadata: metadata(&[("some-crate", "0.1.0", Some("MIT"), false)]),
        ..Script::default()
    }
}

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| (*word).to_owned()).collect()
}

async fn run(world: &World, head: &Files, approvals: &[DependencyApproval]) -> super::world::Ran {
    world
        .gate(&base(), head, &registry(), approvals, false)
        .await
        .expect("the gate runs")
}

// ---------------------------------------------------------------------------------------------
// The order: nothing is fetched before the decision
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_change_that_adds_no_dependency_passes_quickly_and_makes_no_container() {
    let world = World::new();
    let ran = world
        .gate(&base(), &base(), &unknown_registry(), &[], false)
        .await
        .expect("the gate runs");
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::NotApplicable);
    assert_eq!(ran.outcome(gate::SBOM), GateOutcome::NotApplicable);
    assert!(
        world.sandbox.created().is_empty(),
        "no container for a change with no dependency"
    );
    assert!(!ran.done.fetched && !ran.done.scanned);
    assert_eq!(
        ran.report(gate::INTEGRITY).environment.executor_kind,
        ExecutorKind::InProcess
    );
}

#[tokio::test]
async fn negative_nt_sup_01_nothing_is_fetched_before_the_decision() {
    let world = World::new();
    let ran = run(&world, &head(), &[]).await;
    assert!(
        world.sandbox.created().is_empty(),
        "no fetch_deps container before the decision"
    );
    assert!(world.tools.calls().is_empty());
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    let reason = ran
        .report(gate::REVIEW)
        .blocked_reason
        .as_ref()
        .expect("a reason");
    assert_eq!(reason.code, BlockedCode::PolicyUnresolvable);
    let missing = ran.missing(gate::REVIEW);
    assert!(
        missing.contains("some-crate 0.1.0") && missing.contains("approver"),
        "{missing}"
    );
    // The scanners did not run, and a gate that did not run is blocked, never passed.
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
    assert_eq!(ran.outcome(gate::SBOM), GateOutcome::Blocked);
    assert!(
        ran.done.evidence.is_some(),
        "the request for a person is ledger evidence"
    );
}

#[tokio::test]
async fn negative_nt_sup_01_a_package_no_one_knows_goes_to_a_security_approver_and_nothing_is_fetched()
 {
    let world = World::new();
    let ran = world
        .gate(
            &base(),
            &head(),
            &unknown_registry(),
            &[by_approver()],
            false,
        )
        .await
        .expect("the gate runs");
    let missing = ran.missing(gate::REVIEW);
    assert!(missing.contains("security_approver"), "{missing}");
    assert!(missing.contains("not known"), "{missing}");
    assert!(
        world.sandbox.created().is_empty(),
        "an approver's decision does not cover this case"
    );
}

#[tokio::test]
async fn negative_nt_sup_01_a_decision_for_another_version_starts_nothing() {
    let world = World::new();
    let later = head_adding("some-crate", "0.1.1", 'c');
    let ran = run(&world, &later, &[by_approver()]).await;
    assert!(world.sandbox.created().is_empty());
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    let swapped = head_adding("some-crate", "0.1.0", 'd');
    let ran = run(&world, &swapped, &[by_approver()]).await;
    assert!(world.sandbox.created().is_empty());
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
}

#[tokio::test]
async fn the_fetch_and_the_scan_refuse_to_start_without_a_decision() {
    let world = World::new();
    let commit = world.push(&head()).await;
    let plan = plan_with(
        &head(),
        &table(&[("some-crate", old_and_licensed())]),
        &[],
        &[],
    );
    assert!(!plan.may_fetch());
    assert_eq!(
        world.fetch_directly(&plan, &commit).await.err(),
        Some(StageError::PolicyDenied)
    );
    assert_eq!(
        world.scan_directly(&plan, &commit).await.err(),
        Some(StageError::PolicyDenied)
    );
    assert!(world.sandbox.created().is_empty());
}

#[tokio::test]
async fn a_recorded_decision_lets_the_fetch_start_and_the_scan_follow() {
    let world = World::new();
    world.tools.set(clean());
    let ran = run(&world, &head(), &[by_approver()]).await;
    assert!(ran.done.fetched && ran.done.scanned);

    let created = world.sandbox.created();
    let profiles: Vec<SandboxProfile> = created.iter().map(|c| c.profile).collect();
    assert_eq!(
        profiles,
        vec![SandboxProfile::FetchDeps, SandboxProfile::Verify]
    );
    assert!(matches!(
        created[0].network,
        NetworkAttachment::JobInternal { .. }
    ));
    assert_eq!(
        created[1].network,
        NetworkAttachment::None,
        "the verify sandbox has no network"
    );
    assert!(
        created.iter().all(|c| !c.job_token),
        "no job token reaches either sandbox"
    );
    assert!(!created[0].workspace_read_only && created[1].workspace_read_only);
    assert_eq!(world.sandbox.live(), 0, "every container is removed");

    // Exactly these commands, in the fetch profile, with the flag the command set adds.
    assert_eq!(
        world.tools.calls_at(Where::Fetch),
        vec![
            words(&["cargo", "--version"]),
            words(&["cargo", "fetch", "--locked"]),
            words(&["cargo", "metadata", "--format-version", "1", "--locked"]),
        ]
    );
    assert_eq!(
        world.tools.calls_at(Where::Verify),
        vec![
            words(&["cargo", "audit", "--version"]),
            words(&["cargo", "audit", "--json", "--no-fetch"]),
        ]
    );

    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Passed);
    let review = ran.report(gate::REVIEW);
    assert_eq!(
        review.environment.executor_kind,
        ExecutorKind::SandboxCommand
    );
    assert_eq!(
        review
            .environment
            .sandbox
            .as_ref()
            .expect("a sandbox")
            .network,
        SandboxNetwork::Allowlist
    );
    let advisories = ran.report(gate::ADVISORIES);
    assert_eq!(
        advisories
            .environment
            .sandbox
            .as_ref()
            .expect("a sandbox")
            .network,
        SandboxNetwork::None
    );
    assert!(
        advisories
            .environment
            .tool_versions
            .iter()
            .any(|v| v.tool.as_str() == "cargo-audit-audit"),
        "the version of the audit tool is recorded"
    );
}

#[tokio::test]
async fn the_decision_is_in_the_report_with_the_approver_the_policy_hash_and_the_reason() {
    let world = World::new();
    world.tools.set(clean());
    let ran = run(&world, &head(), &[by_approver()]).await;
    let text = ran.warning_text(gate::REVIEW);
    assert!(
        ran.warning_checks(gate::REVIEW)
            .contains(&"dependency-approved".to_owned())
    );
    assert!(text.contains(&format!("person {APPROVER}")), "{text}");
    assert!(text.contains(policy_hash().as_str()), "{text}");
    assert!(text.contains("Reviewed the package"), "{text}");
    let evidence = ran.done.evidence.as_ref().expect("evidence");
    assert_eq!(
        evidence["new_direct_dependencies"][0]["approval"]["approver_id"],
        APPROVER
    );
}

#[tokio::test]
async fn a_reason_that_looks_like_a_secret_is_withheld_from_the_report() {
    let world = World::new();
    world.tools.set(clean());
    let token = ["ghp", "_", &"a".repeat(36)].concat();
    let proof = authorized(decide(
        &human(APPROVER, "bob"),
        Designation::Approver,
        Some(REQUESTER),
    ));
    let approval = DependencyApproval::record(
        &proof,
        subject(),
        policy_hash(),
        &format!("The maintainer sent {token} for the review."),
    )
    .expect("recorded");
    let ran = run(&world, &head(), &[approval]).await;
    let text = ran.warning_text(gate::REVIEW);
    assert!(!text.contains(&token), "{text}");
    assert!(text.contains("withheld"), "{text}");
}

// ---------------------------------------------------------------------------------------------
// NT-SUP-02: build scripts and install scripts
// ---------------------------------------------------------------------------------------------

fn hostile() -> Script {
    Script {
        hostile: true,
        metadata: metadata(&[("some-crate", "0.1.0", Some("MIT"), true)]),
        ..Script::default()
    }
}

#[tokio::test]
async fn negative_nt_sup_02_a_build_script_and_an_install_script_never_run_in_the_fetch_profile() {
    let world = World::new();
    world.tools.set(hostile());
    // A security approver decided, so the fetch runs and reads a package that has a build script.
    let ran = run(&world, &head(), &[by_security()]).await;
    assert!(ran.done.fetched);
    assert!(
        world.tools.markers().is_empty(),
        "no build script and no install script wrote its marker: {:?}",
        world.tools.markers()
    );
    assert!(
        world.tools.attempts().is_empty(),
        "nothing tried the network"
    );
    // The only commands in the fetch profile are the three that read and download.
    let fetch_calls = world.tools.calls_at(Where::Fetch);
    assert_eq!(fetch_calls.len(), 3, "{fetch_calls:?}");
    for call in &fetch_calls {
        assert_eq!(call.first().map(String::as_str), Some("cargo"));
        assert!(
            matches!(
                call.get(1).map(String::as_str),
                Some("--version" | "fetch" | "metadata")
            ),
            "{call:?}"
        );
    }
    // The package does have a build script, and the gate says so.
    assert!(
        ran.warning_checks(gate::REVIEW)
            .contains(&"build-code-added".to_owned())
    );
}

#[test]
fn negative_nt_sup_02_the_policy_denies_repository_code_and_installs_in_the_fetch_profile() {
    let commands = &engine().commands;
    let in_fetch = |argv: &[&str]| commands.evaluate(&words(argv), SandboxProfileKind::FetchDeps);
    for argv in [
        &["cargo", "build"][..],
        &["cargo", "test"],
        &["cargo", "run"],
        &["cargo", "check"],
        &["cargo", "clippy"],
        &["cargo", "install", "evil"],
        &["rustc", "build.rs"],
        &["node", "postinstall.js"],
        &["npm", "install"],
        &["npm", "ci", "--ignore-scripts"],
        &["pip", "install", "evil"],
        &["python", "setup.py", "install"],
    ] {
        assert!(
            !in_fetch(argv).is_allowed(),
            "{argv:?} must not be allowed in fetch_deps"
        );
    }
    // What the gate asks for is allowed, and the policy adds `--locked`.
    for (asked, ran) in [
        (&["cargo", "fetch"][..], &["cargo", "fetch", "--locked"][..]),
        (
            &["cargo", "metadata", "--format-version", "1"],
            &["cargo", "metadata", "--format-version", "1", "--locked"],
        ),
    ] {
        match in_fetch(asked) {
            CommandVerdict::Allowed(allowed) => assert_eq!(allowed.argv, words(ran)),
            other => panic!("{asked:?} should be allowed, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn negative_nt_sup_02_a_build_script_runs_only_in_the_verify_sandbox_which_has_no_network() {
    let world = World::new();
    world.tools.set(hostile());
    let commit = world.push(&head()).await;

    // What the validation stage does with the build gate: `cargo build` in a verify sandbox made
    // exactly like the one this gate makes. The hostile build script runs, inside, and the
    // connection it tries does not leave, because the sandbox has no network.
    let (mut session, workspace) = world.open(&commit, SandboxProfile::Verify).await;
    World::exec(&mut *session, &world.cancel, &["cargo", "build"]).await;
    session
        .stop_and_remove(factory_ports::sandbox::TeardownReason::Completed)
        .await
        .expect("removed");
    workspace.dispose().await.expect("disposed");

    assert_eq!(
        world.tools.markers(),
        vec![Marker {
            at: Where::Verify,
            name: "build-rs"
        }]
    );
    assert_eq!(
        world.tools.attempts(),
        vec![Attempt {
            at: Where::Verify,
            host: "attacker.test",
            reached: false
        }]
    );
    let created = &world.sandbox.created()[0];
    assert_eq!(created.profile, SandboxProfile::Verify);
    assert_eq!(created.network, NetworkAttachment::None);
    assert!(!created.job_token, "no secret is mounted");
    assert_eq!(
        created.env_names,
        vec!["HOME".to_owned()],
        "the environment holds no secret"
    );
    assert!(created.workspace_read_only);
}

// ---------------------------------------------------------------------------------------------
// NT-SUP-03 through the whole gate
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_sup_03_a_tampered_lockfile_fails_the_gate_and_makes_no_container() {
    let world = World::new();
    let tampered = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.100", 'e').with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    let ran = world
        .gate(&base(), &tampered, &unknown_registry(), &[], false)
        .await
        .expect("the gate runs");
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Failed);
    assert!(
        ran.failure_checks(gate::INTEGRITY)
            .contains(&check::CHECKSUM_CHANGED.to_owned())
    );
    for later in [gate::REVIEW, gate::ADVISORIES, gate::SBOM] {
        assert_eq!(
            ran.outcome(later),
            GateOutcome::Blocked,
            "{later} did not run"
        );
    }
    assert!(
        world.sandbox.created().is_empty(),
        "a refused change never reaches a sandbox"
    );
}

#[tokio::test]
async fn negative_nt_sup_03_a_git_dependency_and_a_patch_section_fail_the_gate() {
    let world = World::new();
    let hostile = with(
        head(),
        "Cargo.toml",
        &manifest(
            "app",
            "[dependencies]\nserde = \"1\"\nsome-crate = { git = \"https://attacker.test/x\" }\n\n[patch.crates-io]\nserde = { path = \"evil\" }\n",
        ),
    );
    let ran = run(&world, &hostile, &[by_security()]).await;
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Failed);
    let checks = ran.failure_checks(gate::INTEGRITY);
    assert!(checks.contains(&check::GIT.to_owned()), "{checks:?}");
    assert!(checks.contains(&check::PATCH.to_owned()), "{checks:?}");
    assert!(world.sandbox.created().is_empty());
}

#[tokio::test]
async fn a_dependency_file_of_the_base_commit_that_cannot_be_read_blocks_every_gate() {
    let world = World::new();
    let broken = with(base(), "Cargo.lock", "[[package]\n");
    let ran = world
        .gate(&broken, &head(), &registry(), &[], false)
        .await
        .expect("the gate runs");
    for each in gate::ALL {
        assert_eq!(ran.outcome(each), GateOutcome::Blocked, "{each}");
    }
    assert!(ran.done.evidence.is_none());
    assert!(world.sandbox.created().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Scanners: absent is BLOCKED, never PASSED
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn scanner_absence_is_blocked() {
    let world = World::new();
    world.tools.set(Script {
        audit_present: false,
        ..clean()
    });
    let ran = run(&world, &head(), &[by_approver()]).await;
    assert_eq!(
        ran.outcome(gate::REVIEW),
        GateOutcome::Passed,
        "the review itself is fine"
    );
    let advisories = ran.report(gate::ADVISORIES);
    assert_eq!(advisories.outcome, GateOutcome::Blocked);
    assert_ne!(advisories.outcome, GateOutcome::Passed);
    let reason = advisories.blocked_reason.as_ref().expect("a reason");
    assert_eq!(reason.code, BlockedCode::ToolUnavailable);
    assert!(ran.missing(gate::ADVISORIES).contains("cargo audit"));
    // The audit itself was never run: only the probe asked for the version.
    assert_eq!(
        world.tools.calls_at(Where::Verify),
        vec![words(&["cargo", "audit", "--version"])]
    );
}

#[tokio::test]
async fn scanner_absence_is_blocked_when_the_audit_gives_no_usable_answer() {
    for audit in [AuditScript::Garbage, AuditScript::Error] {
        let world = World::new();
        world.tools.set(Script { audit, ..clean() });
        let ran = run(&world, &head(), &[by_approver()]).await;
        assert_eq!(
            ran.outcome(gate::ADVISORIES),
            GateOutcome::Blocked,
            "{audit:?}"
        );
    }
}

#[tokio::test]
async fn an_advisory_that_the_audit_finds_fails_the_gate() {
    let world = World::new();
    world.tools.set(Script {
        audit: AuditScript::Found,
        ..clean()
    });
    let ran = run(&world, &head(), &[by_approver()]).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Failed);
    assert_eq!(
        ran.failure_checks(gate::ADVISORIES),
        vec!["advisory-found".to_owned()]
    );
    let message = ran
        .report(gate::ADVISORIES)
        .failures
        .as_ref()
        .expect("failures")[0]
        .message
        .as_str()
        .to_owned();
    assert!(
        message.contains("RUSTSEC-2021-0003") && message.contains("smallvec"),
        "{message}"
    );
}

#[tokio::test]
async fn an_sbom_tool_that_is_not_there_is_not_applicable_unless_the_job_requires_one() {
    // The policy has no entry for an SBOM tool, so the tool cannot run at all.
    let world = World::new();
    world.tools.set(clean());
    let ran = run(&world, &head(), &[by_approver()]).await;
    assert_eq!(ran.outcome(gate::SBOM), GateOutcome::NotApplicable);
    let reason = ran
        .report(gate::SBOM)
        .not_applicable_reason
        .as_ref()
        .expect("a reason");
    assert!(reason.justification.as_str().contains("supply_chain.sbom"));

    let required = World::new();
    required.tools.set(clean());
    let ran = required
        .gate(&base(), &head(), &registry(), &[by_approver()], true)
        .await
        .expect("the gate runs");
    assert_eq!(ran.outcome(gate::SBOM), GateOutcome::Blocked);
    assert!(
        required
            .tools
            .calls_at(Where::Verify)
            .iter()
            .all(|call| call.get(1).map(String::as_str) != Some("sbom")),
        "a command the policy does not allow is not run"
    );
}

#[tokio::test]
async fn an_sbom_tool_that_the_policy_allows_but_the_image_lacks_is_blocked_when_required() {
    let mut world = World::new();
    world.sbom_subcommands = vec!["sbom"];
    world.tools.set(clean()); // sbom_present is false
    let optional = run(&world, &head(), &[by_approver()]).await;
    assert_eq!(optional.outcome(gate::SBOM), GateOutcome::NotApplicable);

    let mut world = World::new();
    world.sbom_subcommands = vec!["sbom"];
    world.tools.set(clean());
    let ran = world
        .gate(&base(), &head(), &registry(), &[by_approver()], true)
        .await
        .expect("the gate runs");
    assert_eq!(ran.outcome(gate::SBOM), GateOutcome::Blocked);
    assert_eq!(
        ran.report(gate::SBOM)
            .blocked_reason
            .as_ref()
            .expect("a reason")
            .code,
        BlockedCode::ToolUnavailable
    );
}

#[tokio::test]
async fn the_sbom_is_made_as_an_artifact_when_the_tool_exists() {
    let mut world = World::new();
    world.sbom_subcommands = vec!["sbom"];
    world.tools.set(Script {
        sbom_present: true,
        ..clean()
    });
    let ran = world
        .gate(&base(), &head(), &registry(), &[by_approver()], true)
        .await
        .expect("the gate runs");
    let report = ran.report(gate::SBOM);
    assert_eq!(report.outcome, GateOutcome::Passed);
    let command = report.commands.last().expect("the sbom command");
    assert_eq!(command.exit_code, Some(0));
    let bytes = world
        .artifacts
        .get(&TenantScope::new(world.tenant), &command.stdout)
        .await
        .expect("the document is stored");
    let document: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(document["bomFormat"], "CycloneDX");
    assert!(
        report
            .environment
            .tool_versions
            .iter()
            .any(|v| v.tool.as_str() == "cargo-sbom")
    );
}

// ---------------------------------------------------------------------------------------------
// Licenses, a refused fetch, and build code
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_license_off_the_list_in_the_fetched_metadata_fails_and_no_scan_runs() {
    let world = World::new();
    world.tools.set(Script {
        metadata: metadata(&[("some-crate", "0.1.0", Some("GPL-3.0-or-later"), false)]),
        ..Script::default()
    });
    let ran = run(&world, &head(), &[by_approver()]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Failed);
    assert_eq!(
        ran.failure_checks(gate::REVIEW),
        vec![check::LICENSE.to_owned()]
    );
    assert!(ran.done.fetched && !ran.done.scanned);
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
}

#[tokio::test]
async fn a_license_off_the_list_that_the_registry_shows_fails_before_anything_is_fetched() {
    let world = World::new();
    let copyleft = StaticRegistry::new().with(
        "some-crate",
        record(Some("2020-01-01T00:00:00Z"), Some("AGPL-3.0-only")),
    );
    let ran = world
        .gate(&base(), &head(), &copyleft, &[by_approver()], false)
        .await
        .expect("the gate runs");
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Failed);
    assert!(world.sandbox.created().is_empty());
}

#[tokio::test]
async fn a_fetch_that_the_lockfile_does_not_survive_fails_the_review() {
    let world = World::new();
    world.tools.set(Script {
        fetch_exit: 101,
        ..clean()
    });
    let ran = run(&world, &head(), &[by_approver()]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Failed);
    assert_eq!(
        ran.failure_checks(gate::REVIEW),
        vec!["fetch-refused".to_owned()]
    );
    assert!(!ran.done.scanned);
    assert_eq!(world.sandbox.live(), 0);
}

#[tokio::test]
async fn build_code_under_an_approver_decision_blocks_until_a_security_approver_decides() {
    let world = World::new();
    world.tools.set(hostile());
    let ran = run(&world, &head(), &[by_approver()]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    assert!(
        ran.missing(gate::REVIEW)
            .contains("security approver's decision"),
        "{}",
        ran.missing(gate::REVIEW)
    );
    assert!(!ran.done.scanned);
    assert!(world.tools.markers().is_empty());

    let cleared = World::new();
    cleared.tools.set(hostile());
    let ran = run(&cleared, &head(), &[by_approver(), by_security()]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert!(ran.done.scanned);
}

#[tokio::test]
async fn the_age_the_human_sees_is_the_age_at_the_time_of_the_run() {
    let world = World::new();
    let young = StaticRegistry::new().with(
        "some-crate",
        RegistryRecord {
            first_published: Some(at("2026-10-25T12:00:00Z")),
            ..old_and_licensed()
        },
    );
    let ran = world
        .gate(&base(), &head(), &young, &[], false)
        .await
        .expect("the gate runs");
    let evidence = ran.done.evidence.as_ref().expect("evidence");
    assert_eq!(
        evidence["new_direct_dependencies"][0]["registry"]["first_publish_age_days"],
        3
    );
    assert_eq!(
        evidence["new_direct_dependencies"][0]["needs"],
        "security_approver"
    );
}
