//! The dependency and supply chain gates inside the validation stage.
//!
//! The four reports (`dependency-integrity`, `dependency-review`, `dependency-advisories`,
//! `sbom`) are made on every run. These tests show the stage doing what the gate package says it
//! must: a change that adds no dependency costs nothing, a new direct dependency stops the stage
//! until a person has decided on exactly that package, a decision bound to the job and the policy
//! lets it through, and a scanner that is missing blocks.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::policy::decision::Designation;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::GateOutcome;
use factory_ports::paths::CommitSha;
use factory_workflow::gates::framework::{BlockCause, Resolution};
use factory_workflow::gates::supply_chain::approval::{DependencyApproval, Subject};
use factory_workflow::gates::supply_chain::facts::RegistryRecord;
use factory_workflow::gates::supply_chain::report::gate;
use factory_workflow::stages::validation::SUPPLY_CHAIN_GATES;

use crate::gates::{base_run, head_run, it_with_requirement_tests};
use crate::people::{
    APPROVER, REQUESTER, SECURITY, approve, authorized, decide, human, policy_hash, scope,
};
use crate::world::{World, base_files, policy_with};
use factory_workflow::stages::validation::RunSupplyChain;

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn sum() -> String {
    "c".repeat(64)
}

fn base_lock() -> String {
    "version = 4\n\n[[package]]\nname = \"word-count\"\nversion = \"0.1.0\"\n".to_owned()
}

fn head_lock() -> String {
    format!(
        "{}dependencies = [\n \"some-crate\",\n]\n\n[[package]]\nname = \"some-crate\"\nversion = \"0.1.0\"\nsource = \"{CRATES_IO}\"\nchecksum = \"{}\"\n",
        base_lock(),
        sum()
    )
}

fn manifest(extra: &str) -> String {
    let base = base_files()
        .into_iter()
        .find(|(path, _)| path == "Cargo.toml")
        .map(|(_, text)| text)
        .expect("the base has a manifest");
    format!("{base}{extra}")
}

fn subject() -> Subject {
    Subject {
        name: "some-crate".to_owned(),
        version: "0.1.0".to_owned(),
        checksum: sum(),
    }
}

fn old_and_licensed() -> RegistryRecord {
    RegistryRecord {
        exists: Some(true),
        first_published: Some(Timestamp::parse("2020-01-01T00:00:00Z").expect("a time")),
        license: Some("MIT".to_owned()),
        repository: None,
        downloads: Some(1_000),
    }
}

/// A project whose base commit has a lockfile, and whose candidate changes these files besides the
/// tests. The test runs are queued the way the passing world queues them.
async fn project(head: &[(&str, Option<&str>)]) -> (World, CommitSha, CommitSha) {
    let w = World::new();
    let lock = base_lock();
    let base = w
        .push(&crate::world::with(&[("Cargo.lock", Some(&lock))]))
        .await;
    let more = it_with_requirement_tests();
    let mut changes = vec![("tests/it.rs", Some(more.as_str()))];
    changes.extend_from_slice(head);
    let mut files = crate::world::with(&[("Cargo.lock", Some(&lock))]);
    for (path, text) in &changes {
        files.retain(|(existing, _)| existing != path);
        if let Some(text) = text {
            files.push(((*path).to_owned(), (*text).to_owned()));
        }
    }
    let head = w.push(&files).await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    (w, base, head)
}

/// A candidate that adds `some-crate` to the manifest and the lockfile.
async fn adding_a_dependency() -> (World, CommitSha, CommitSha) {
    let toml = manifest("\n[dependencies]\nsome-crate = \"0.1\"\n");
    let lock = head_lock();
    let (w, base, head) =
        project(&[("Cargo.toml", Some(&toml)), ("Cargo.lock", Some(&lock))]).await;
    w.packages.know("some-crate", old_and_licensed());
    w.cargo
        .metadata_of(&[("some-crate", "0.1.0", "MIT", false)]);
    (w, base, head)
}

fn decided(designation: Designation, number: u64, login: &str) -> DependencyApproval {
    approve(number, login, designation, &subject()).expect("recorded")
}

// ---------------------------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_contract_names_the_four_dependency_gates_and_every_one_has_a_report() {
    let (w, base, head) = project(&[]).await;
    let ran = w.run(&base, &head).await;
    let named: Vec<String> = ran
        .contract
        .evaluator
        .gate_ids
        .as_ref()
        .expect("gate ids")
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    for (id, _) in SUPPLY_CHAIN_GATES {
        assert!(named.contains(&id.to_owned()), "{id}");
        ran.report(id);
    }
    assert_eq!(
        factory_workflow::gates::framework::uncovered_criteria(&ran.contract, &ran.decision),
        0
    );
}

// ---------------------------------------------------------------------------------------------
// A change that adds no dependency
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_change_that_touches_no_dependency_file_passes_and_costs_nothing() {
    let (w, base, head) = project(&[]).await;
    let ran = w.run(&base, &head).await;
    for (id, _) in SUPPLY_CHAIN_GATES {
        assert_eq!(ran.outcome(id), GateOutcome::NotApplicable, "{id}");
    }
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(ran.problem, None);
    // Only the two containers of the command gates: no fetch, no scan.
    assert_eq!(w.sandbox.created(), 2);
    assert_eq!(w.cargo.ran("fetch"), 0);
    assert_eq!(w.cargo.ran("metadata"), 0);
    assert_eq!(w.cargo.ran("audit"), 0);
    assert!(ran.evidence.get("dependency_review").is_none());
}

/// RR-16. Source inside a directory of vendored crates is built and run, and no manifest shows a
/// change of it. The dependency gates run for such a change, the review is BLOCKED, and nothing is
/// fetched: there is no package for a person to decide on, so the change goes to a security review
/// outside the factory or the builder drops it.
#[tokio::test]
async fn a_change_inside_a_vendored_directory_blocks_the_review_and_runs_no_scan() {
    for path in [
        "vendor/serde/src/lib.rs",
        "vendor/serde/.cargo-checksum.json",
        "third_party/foo/src/lib.rs",
    ] {
        let (w, base, head) = project(&[(path, Some("pub fn edited() {}\n"))]).await;
        let ran = w.run(&base, &head).await;
        assert_eq!(
            ran.outcome(gate::REVIEW),
            GateOutcome::Blocked,
            "{path} did not block the review"
        );
        let reason = ran
            .report(gate::REVIEW)
            .blocked_reason
            .as_ref()
            .expect("a reason");
        assert_eq!(reason.code, BlockedCode::PolicyUnresolvable, "{path}");
        assert_eq!(w.cargo.ran("fetch"), 0, "{path}");
        assert_eq!(w.cargo.ran("audit"), 0, "{path}");
    }
}

#[tokio::test]
async fn a_manifest_edit_that_adds_no_dependency_passes_without_a_container() {
    let toml = manifest("\n# a note for the reader\n");
    let (w, base, head) = project(&[("Cargo.toml", Some(&toml))]).await;
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::NotApplicable);
    assert_eq!(ran.outcome(gate::SBOM), GateOutcome::NotApplicable);
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(w.sandbox.created(), 2, "no fetch and no scan container");
    assert_eq!(w.cargo.ran("fetch"), 0);
}

// ---------------------------------------------------------------------------------------------
// A new direct dependency
// ---------------------------------------------------------------------------------------------

/// The stage stops and waits for a person. The review is BLOCKED with the code
/// `policy_unresolvable` and names the package, the version and the designation that must decide;
/// the engine ends the stage run as blocked. The decision is the dependency approval
/// (`add_new_direct_dependency`) on exactly that subject, and the rerun is the operator's
/// `UnblockRerun`. Nothing is fetched meanwhile.
#[tokio::test]
async fn a_new_dependency_with_no_recorded_decision_stops_the_stage_for_a_person() {
    let (w, base, head) = adding_a_dependency().await;
    let ran = w.run(&base, &head).await;

    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    let reason = ran
        .report(gate::REVIEW)
        .blocked_reason
        .as_ref()
        .expect("a reason");
    assert_eq!(reason.code, BlockedCode::PolicyUnresolvable);
    let missing: Vec<String> = reason
        .missing
        .iter()
        .map(|item| item.as_str().to_owned())
        .collect();
    let missing = missing.join("; ");
    assert!(
        missing.contains("a recorded human decision")
            && missing.contains("some-crate 0.1.0")
            && missing.contains("approver"),
        "{missing}"
    );
    // The scanners did not run, and a gate that did not run is blocked, never passed.
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);

    // The engine stops the stage run at the block.
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::GateBlocked(
            factory_domain::values::Slug::parse(gate::REVIEW).expect("a slug")
        ))
    );
    // No fetch container, no dependency command.
    assert_eq!(w.sandbox.created(), 2);
    assert_eq!(w.cargo.ran("fetch"), 0);
    assert_eq!(w.cargo.ran("audit"), 0);

    // What a person is shown: the exact subject, who must decide, and what the registry said.
    let shown = &ran.evidence["dependency_review"]["new_direct_dependencies"][0];
    assert_eq!(shown["name"], "some-crate");
    assert_eq!(shown["version"], "0.1.0");
    assert_eq!(shown["checksum"], sum());
    assert_eq!(shown["needs"], "approver");
    assert_eq!(shown["approval"], serde_json::Value::Null);
}

/// A new direct dependency with no recorded decision blocks `dependency-review` with the code
/// `policy_unresolvable`. The facts of an override of that block are computed from the policy and
/// from the reports the stage made, and the policy says there is no override for it: a security
/// approver, who can waive other gates, cannot pass this one, and the domain guard the engine
/// evaluates for the override (`G_OVERRIDE_PERMITTED`) says no for the same facts.
#[tokio::test]
async fn nobody_overrides_the_block_of_a_dependency_that_waits_for_a_decision() {
    use factory_domain::machines::guards::OverrideFacts as GuardFacts;
    use factory_domain::machines::guards::stage_run::override_permitted;
    use factory_domain::vocabulary::HumanRole;
    use factory_workflow::commands::OverrideFacts;

    let (w, base, head) = adding_a_dependency().await;
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    assert_eq!(
        ran.report(gate::REVIEW)
            .blocked_reason
            .as_ref()
            .map(|reason| reason.code),
        Some(BlockedCode::PolicyUnresolvable)
    );

    // The facts come from the policy and the stage's reports. Nothing here is asserted.
    let facts = OverrideFacts::for_reports(&w.policy.authority, &ran.decision.reports, true, false);
    assert!(
        !facts.policy_permits,
        "the policy has no override for this block"
    );
    let roles = [HumanRole::SecurityApprover];
    let guard = override_permitted(&GuardFacts {
        policy_permits_override_for_block_code: facts.policy_permits,
        block_is_security_class: facts.security_class,
        principal_roles: &roles,
        role_required_by_policy: HumanRole::SecurityApprover,
        justification_recorded: true,
        blocked_gate_is_mandatory_of_active_profile: facts.mandatory_of_active_profile,
    });
    assert!(guard.is_err(), "the guard of S18 holds the override back");

    // The control: the same stage with the audit tool missing is blocked for another gate and
    // another code, and the policy does not hold that override back. The rule is the pair and not
    // every block.
    let (w, base, head) = adding_a_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    w.cargo.lacks("audit");
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
    let facts = OverrideFacts::for_reports(&w.policy.authority, &ran.decision.reports, true, false);
    assert!(facts.policy_permits);
}

/// Nothing that is not a block can be overridden: no report is blocked, so there is nothing the
/// policy could permit.
#[tokio::test]
async fn the_facts_of_an_override_with_no_block_to_pass_do_not_permit_it() {
    use factory_workflow::commands::OverrideFacts;
    let (w, base, head) = project(&[]).await;
    let ran = w.run(&base, &head).await;
    assert!(
        ran.decision
            .reports
            .iter()
            .all(|report| report.outcome != GateOutcome::Blocked)
    );
    let facts =
        OverrideFacts::for_reports(&w.policy.authority, &ran.decision.reports, false, false);
    assert!(!facts.policy_permits);
}

#[tokio::test]
async fn a_decision_bound_to_the_job_and_the_policy_lets_the_stage_pass() {
    let (w, base, head) = adding_a_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    let ran = w.run(&base, &head).await;

    for (id, _) in SUPPLY_CHAIN_GATES {
        let outcome = ran.outcome(id);
        assert!(
            outcome == GateOutcome::Passed
                || (id == gate::SBOM && outcome == GateOutcome::NotApplicable),
            "{id}: {outcome:?}"
        );
    }
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(ran.problem, None);
    // The two containers of the command gates, the fetch and the scan.
    assert_eq!(w.sandbox.created(), 4);
    assert_eq!(w.sandbox.live(), 0, "nothing is left running");
    assert_eq!(w.cargo.ran("fetch"), 1);
    assert_eq!(w.cargo.ran("metadata"), 1);
    assert_eq!(w.cargo.ran("audit"), 1);
    // The decision is part of what the stage records.
    let shown = &ran.evidence["dependency_review"]["new_direct_dependencies"][0];
    assert_eq!(shown["approval"]["approver_id"], APPROVER);
    assert_eq!(shown["approval"]["policy_hash"], policy_hash().as_str());
}

#[tokio::test]
async fn a_decision_taken_under_another_policy_or_for_another_job_does_not_count() {
    // Another policy bundle.
    let (w, base, head) = adding_a_dependency().await;
    let proof = authorized(decide(
        &human(APPROVER, "bob"),
        Designation::Approver,
        Some(REQUESTER),
    ));
    let older = DependencyApproval::record(
        &proof,
        subject(),
        Sha256Digest::of(b"an older policy bundle"),
        scope(),
        "Reviewed the package under the older rules.",
    )
    .expect("recorded");
    w.approvals.record(older);
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    assert_eq!(w.cargo.ran("fetch"), 0);

    // Another job.
    let (w, base, head) = adding_a_dependency().await;
    let elsewhere = factory_workflow::gates::supply_chain::approval::DecisionScope {
        job: factory_domain::ids::JobId::parse("018f3a00-0000-7000-8000-00000000d777")
            .expect("a job"),
        ..scope()
    };
    let proof = authorized(decide(
        &human(APPROVER, "bob"),
        Designation::Approver,
        Some(REQUESTER),
    ));
    let other_job = DependencyApproval::record(
        &proof,
        subject(),
        policy_hash(),
        elsewhere,
        "Reviewed the package for another job.",
    )
    .expect("recorded");
    w.approvals.record(other_job);
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    assert_eq!(w.cargo.ran("fetch"), 0);
}

/// Nothing is known about the package (the registry source knows nothing), so it needs a security
/// approver: an ordinary approver's decision does not lift the block, and a security approver's
/// does.
async fn adding_an_unknown_dependency() -> (World, CommitSha, CommitSha) {
    let toml = manifest("\n[dependencies]\nsome-crate = \"0.1\"\n");
    let lock = head_lock();
    let (w, base, head) =
        project(&[("Cargo.toml", Some(&toml)), ("Cargo.lock", Some(&lock))]).await;
    w.cargo
        .metadata_of(&[("some-crate", "0.1.0", "MIT", false)]);
    (w, base, head)
}

#[tokio::test]
async fn an_ordinary_approver_cannot_decide_what_needs_a_security_approver() {
    let (w, base, head) = adding_an_unknown_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    let missing = ran
        .report(gate::REVIEW)
        .blocked_reason
        .as_ref()
        .expect("a reason")
        .missing
        .iter()
        .map(|item| item.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(missing.contains("security_approver"), "{missing}");
    assert_eq!(w.cargo.ran("fetch"), 0);

    let (w, base, head) = adding_an_unknown_dependency().await;
    w.approvals
        .record(decided(Designation::SecurityApprover, SECURITY, "sam"));
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert_eq!(w.cargo.ran("fetch"), 1);
}

// ---------------------------------------------------------------------------------------------
// A scanner that is not there, and a database that is too old
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_audit_tool_is_blocked_and_never_passed() {
    let (w, base, head) = adding_a_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    w.cargo.lacks("audit");
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
    let reason = ran
        .report(gate::ADVISORIES)
        .blocked_reason
        .as_ref()
        .expect("a reason");
    assert_eq!(reason.code, BlockedCode::ToolUnavailable);
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::GateBlocked(
            factory_domain::values::Slug::parse(gate::ADVISORIES).expect("a slug")
        ))
    );
}

#[tokio::test]
async fn an_advisory_database_older_than_the_limit_blocks_the_advisory_gate() {
    let (w, base, head) = adding_a_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    // Longer ago than the fake clock minus the limit of seven days.
    w.database.updated(Some(
        Timestamp::parse("2026-10-01T00:00:00Z").expect("a time"),
    ));
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
    let unknown = adding_a_dependency().await;
    unknown
        .0
        .approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    unknown.0.database.updated(None);
    let ran = unknown.0.run(&unknown.1, &unknown.2).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
}

// ---------------------------------------------------------------------------------------------
// What the policy says, and what the composition root may change
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_stage_built_from_policy_takes_the_limit_and_the_run_rule_from_it() {
    let w = World::new();
    let settings = w.supply_settings();
    assert_eq!(settings.advisory_db_max_age_days, 7, "the policy's value");
    assert_eq!(settings.run, RunSupplyChain::WhenDependencyFilesChange);
    // A policy with another value gives another start; nothing is a constant of the stage.
    let mut w = World::new();
    w.policy = policy_with(|j| {
        j["supply_chain"]["advisory_database"]["max_age_days"] = 3.into();
        j["supply_chain"]["dependency_gates"]["run_when"] = "always".into();
    });
    let settings = w.supply_settings();
    assert_eq!(settings.advisory_db_max_age_days, 3);
    assert_eq!(settings.run, RunSupplyChain::Always);
}

#[tokio::test]
async fn the_composition_root_may_lower_the_database_age_limit_and_never_raise_it() {
    // The database is ten days old and the policy allows seven: BLOCKED. A configuration that
    // asks for thirty days is ignored, because policy is only tightened.
    let (w, base, head) = adding_a_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    w.database.updated(Some(
        Timestamp::parse("2026-10-18T00:00:00Z").expect("a time"),
    ));
    w.tweak_supply(|settings| settings.advisory_db_max_age_days = 30);
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);

    // The database is five days old, inside the policy's seven: PASSED. A configuration that asks
    // for three days is stricter, and it counts.
    let (w, base, head) = adding_a_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    w.database.updated(Some(
        Timestamp::parse("2026-10-23T00:00:00Z").expect("a time"),
    ));
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Passed);
    let (w, base, head) = adding_a_dependency().await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    w.database.updated(Some(
        Timestamp::parse("2026-10-23T00:00:00Z").expect("a time"),
    ));
    w.tweak_supply(|settings| settings.advisory_db_max_age_days = 3);
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
}

#[tokio::test]
async fn the_policys_limit_applies_even_when_the_stage_was_built_without_reading_the_policy() {
    // `SupplyChainSettings::new` does not read the policy and defaults to seven days. A policy
    // that says three days still wins.
    let (mut w, base, head) = adding_a_dependency().await;
    w.policy = policy_with(|j| {
        j["supply_chain"]["advisory_database"]["max_age_days"] = 3.into();
    });
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    w.database.updated(Some(
        Timestamp::parse("2026-10-23T00:00:00Z").expect("a time"),
    ));
    w.tweak_supply(|settings| settings.advisory_db_max_age_days = 7);
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::ADVISORIES), GateOutcome::Blocked);
}

#[tokio::test]
async fn the_policy_can_make_the_gates_run_on_every_change_and_the_configuration_cannot_undo_it() {
    // The control: with the policy as it is, a change that touches no dependency file costs
    // nothing (the test above in this file). With `always`, the same change goes through the
    // gate: the integrity check reads both lockfiles and says so.
    let (mut w, base, head) = project(&[]).await;
    w.policy = policy_with(|j| {
        j["supply_chain"]["dependency_gates"]["run_when"] = "always".into();
    });
    // The configuration asks for the lazy rule; the policy's `always` is not loosened by it.
    w.tweak_supply(|settings| settings.run = RunSupplyChain::WhenDependencyFilesChange);
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_ne!(ran.outcome(gate::INTEGRITY), GateOutcome::NotApplicable);
    assert!(ran.evidence.get("dependency_review").is_some());

    // The configuration may tighten a policy that says "only when a dependency file changes".
    let (w, base, head) = project(&[]).await;
    w.tweak_supply(|settings| settings.run = RunSupplyChain::Always);
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
}

// ---------------------------------------------------------------------------------------------
// A change the host refused
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_change_a_host_side_rule_refused_never_reaches_a_dependency_container() {
    let toml = manifest("\n[dependencies]\nsome-crate = \"0.1\"\n");
    let lock = head_lock();
    let (w, base, head) = project(&[
        ("Cargo.toml", Some(&toml)),
        ("Cargo.lock", Some(&lock)),
        (".github/workflows/ci.yml", Some("name: changed\n")),
    ])
    .await;
    w.approvals
        .record(decided(Designation::Approver, APPROVER, "bob"));
    let ran = w.run(&base, &head).await;
    assert_eq!(
        ran.outcome("protected-paths-unchanged"),
        GateOutcome::Failed
    );
    for (id, _) in SUPPLY_CHAIN_GATES {
        assert_eq!(ran.outcome(id), GateOutcome::Blocked, "{id}");
    }
    assert_eq!(w.sandbox.created(), 0);
    assert_eq!(w.cargo.ran("fetch"), 0);
}
