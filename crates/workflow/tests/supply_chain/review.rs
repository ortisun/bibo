//! The human decision on every new direct dependency (NT-SUP-01), what it is bound to, the
//! license rule, and the build code that comes in under a dependency.

use factory_domain::policy::authority::{ActionDenialReason, ActionVerdict, Actor, ActorKind};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::policy::dependency::DependencyFlag;
use factory_domain::values::Timestamp;
use factory_workflow::gates::supply_chain::approval::{ApprovalError, DependencyApproval, Subject};
use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::facts::RegistryRecord;
use factory_workflow::gates::supply_chain::integrity::{Context, inspect};
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::model::normalize;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::review::{Plan, RegistryTable, Settings, conclude};
use factory_workflow::gates::supply_chain::tools::PackageMeta;
use serde_json::json;

use super::files::{Files, base, files, head_adding, lock, manifest, member, reg, side, sum, with};
use super::people::{
    APPROVER, OPERATOR, REQUESTER, SECURITY, approve, authorized, decide, engine, human, now,
    policy_hash, scope,
};

pub fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("a time")
}

/// The registry's answer for a package that exists, was first published `published`, and has
/// `license`.
pub fn record(published: Option<&str>, license: Option<&str>) -> RegistryRecord {
    RegistryRecord {
        exists: Some(true),
        first_published: published.map(at),
        license: license.map(str::to_owned),
        repository: Some("https://example.test/repo".to_owned()),
        downloads: Some(1_000_000),
    }
}

pub fn old_and_licensed() -> RegistryRecord {
    record(Some("2020-01-01T00:00:00Z"), Some("MIT OR Apache-2.0"))
}

pub fn table(entries: &[(&str, RegistryRecord)]) -> RegistryTable {
    entries
        .iter()
        .map(|(name, record)| (normalize(name), record.clone()))
        .collect()
}

pub fn plan_with(
    head: &Files,
    registry: &RegistryTable,
    approvals: &[DependencyApproval],
    internal: &[String],
) -> Plan {
    let popular = PopularNames::bundled().expect("the bundled list");
    let cx = Context {
        internal_names: internal,
        popular: &popular,
    };
    let integrity = inspect(&CargoFormat, &side(&base()), &side(head), &cx).expect("readable");
    let licenses = LicensePolicy::owner_approved();
    Plan::new(
        integrity,
        registry,
        approvals,
        &Settings {
            dependency: &engine().dependency,
            licenses: &licenses,
            internal_names: internal,
            popular: &popular,
            now: now(),
            scope: scope(),
            policy_hash: &policy_hash(),
        },
    )
}

fn plan(head: &Files, registry: &RegistryTable) -> Plan {
    plan_with(head, registry, &[], &[])
}

fn subject(name: &str, version: &str, digit: char) -> Subject {
    Subject {
        name: name.to_owned(),
        version: version.to_owned(),
        checksum: sum(digit),
    }
}

fn only_need(plan: &Plan) -> &factory_workflow::gates::supply_chain::review::Need {
    assert_eq!(plan.needs.len(), 1, "{:?}", plan.findings);
    &plan.needs[0]
}

// ---------------------------------------------------------------------------------------------
// NT-SUP-01: every new name goes to a person; none is approved
// ---------------------------------------------------------------------------------------------

#[test]
fn negative_nt_sup_01_a_name_absent_from_the_registry_needs_a_security_approver() {
    let missing = RegistryRecord {
        exists: Some(false),
        ..RegistryRecord::default()
    };
    let plan = plan(
        &head_adding("zzqx-parser", "0.1.0", 'c'),
        &table(&[("zzqx-parser", missing)]),
    );
    let need = only_need(&plan);
    assert_eq!(need.designation, Designation::SecurityApprover);
    assert!(need.flags.contains(&DependencyFlag::NotInRegistry));
    assert!(need.awaiting());
    assert!(!plan.may_fetch(), "nothing is fetched before the decision");
}

#[test]
fn negative_nt_sup_01_a_package_first_published_three_days_ago_needs_a_security_approver() {
    let young = record(Some("2026-10-25T12:00:00Z"), Some("MIT"));
    let plan = plan(
        &head_adding("fresh-crate", "0.1.0", 'c'),
        &table(&[("fresh-crate", young)]),
    );
    let need = only_need(&plan);
    assert_eq!(need.age_days, Some(3));
    assert_eq!(need.designation, Designation::SecurityApprover);
    assert!(need.flags.contains(&DependencyFlag::FirstPublishTooRecent));
    assert!(need.awaiting() && !plan.may_fetch());
}

#[test]
fn negative_nt_sup_01_a_near_miss_of_a_popular_name_needs_a_security_approver() {
    let plan = plan(
        &head_adding("reqwset", "0.1.0", 'c'),
        &table(&[("reqwset", old_and_licensed())]),
    );
    let need = only_need(&plan);
    assert_eq!(need.designation, Designation::SecurityApprover);
    assert!(
        need.flags
            .contains(&DependencyFlag::NearPopularName("reqwest".to_owned())),
        "{:?}",
        need.flags
    );
    assert!(need.awaiting() && !plan.may_fetch());
}

#[test]
fn negative_nt_sup_01_a_name_equal_to_an_internal_package_needs_a_security_approver() {
    let internal = vec!["acme-billing-core".to_owned()];
    let plan = plan_with(
        &head_adding("acme-billing-core", "9.9.9", 'c'),
        &table(&[("acme-billing-core", old_and_licensed())]),
        &[],
        &internal,
    );
    let need = only_need(&plan);
    assert_eq!(need.designation, Designation::SecurityApprover);
    assert!(need.flags.contains(&DependencyFlag::InternalNameCollision));
    assert!(need.awaiting() && !plan.may_fetch());
}

#[test]
fn negative_nt_sup_01_unknown_registry_facts_are_treated_as_the_worst_case() {
    // Nothing is known about the package: no lookup was made.
    let plan = plan(
        &head_adding("some-crate", "0.1.0", 'c'),
        &RegistryTable::new(),
    );
    let need = only_need(&plan);
    assert_eq!(need.designation, Designation::SecurityApprover);
    assert!(need.flags.contains(&DependencyFlag::RegistryUnknown));
    assert!(need.flags.contains(&DependencyFlag::FirstPublishUnknown));
    assert_eq!(need.age_days, None);
}

#[test]
fn negative_nt_sup_01_an_ordinary_package_still_needs_a_human() {
    let plan = plan(
        &head_adding("some-crate", "0.1.0", 'c'),
        &table(&[("some-crate", old_and_licensed())]),
    );
    let need = only_need(&plan);
    assert_eq!(need.designation, Designation::Approver);
    assert!(need.flags.is_empty());
    assert!(
        need.awaiting() && !plan.may_fetch(),
        "no age, popularity or license approves"
    );
}

#[test]
fn negative_nt_sup_01_a_well_known_popular_package_new_to_the_repository_needs_a_human() {
    let plan = plan(
        &head_adding("rand", "0.8.5", 'c'),
        &table(&[("rand", old_and_licensed())]),
    );
    let need = only_need(&plan);
    assert_eq!(need.designation, Designation::Approver);
    assert!(need.awaiting() && !plan.may_fetch());
}

#[test]
fn negative_nt_sup_01_a_name_on_the_organization_list_but_absent_from_the_lockfile_is_new() {
    // There is no organization allowlist: the engine takes none, so a name that some other
    // project of the organization uses is as new here as any other.
    let plan = plan(
        &head_adding("tokio", "1.40.0", 'c'),
        &table(&[("tokio", old_and_licensed())]),
    );
    assert!(only_need(&plan).awaiting());
}

#[test]
fn negative_nt_sup_01_control_a_name_already_in_the_base_lockfile_asks_nobody() {
    // `serde_derive` is in the base lockfile as a transitive package; the lockfile still gets
    // checked, but no request for a person is made.
    let head = files(&[
        (
            "Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nserde = \"1\"\nserde_derive = \"1\"\n",
            ),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["serde", "serde_derive"]),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ]);
    let plan = plan(&head, &RegistryTable::new());
    assert!(plan.needs.is_empty());
    assert!(!plan.refused(), "{:?}", plan.integrity.findings);
}

#[test]
fn negative_nt_sup_01_no_registry_fact_approves_anything() {
    let published = [
        None,
        Some("2020-01-01T00:00:00Z"),
        Some("2026-10-27T00:00:00Z"),
    ];
    let exists = [None, Some(true), Some(false)];
    let licenses = [None, Some("MIT"), Some("Apache-2.0 OR MIT")];
    for first in published {
        for existence in exists {
            for license in licenses {
                let facts = RegistryRecord {
                    exists: existence,
                    first_published: first.map(at),
                    license: license.map(str::to_owned),
                    repository: Some("https://example.test".to_owned()),
                    downloads: Some(u64::MAX),
                };
                let plan = plan(
                    &head_adding("some-crate", "0.1.0", 'c'),
                    &table(&[("some-crate", facts)]),
                );
                let need = only_need(&plan);
                assert!(
                    need.awaiting() && !plan.may_fetch(),
                    "{first:?} {existence:?} {license:?}"
                );
            }
        }
    }
}

#[test]
fn negative_nt_sup_01_the_policy_has_no_automatic_approval_key() {
    let policy = include_str!("../../../domain/tests/fixtures/policy/security.json");
    assert!(!policy.contains("auto_approve_when"));
    assert!(!policy.contains("name_on_org_allowlist"));
}

#[test]
fn negative_nt_sup_01_the_facts_the_human_sees_are_recorded() {
    let young = record(Some("2026-10-25T12:00:00Z"), Some("MIT"));
    let plan = plan(
        &head_adding("fresh-crate", "0.1.0", 'c'),
        &table(&[("fresh-crate", young)]),
    );
    let evidence = plan.evidence();
    let entry = &evidence["new_direct_dependencies"][0];
    assert_eq!(entry["name"], "fresh-crate");
    assert_eq!(entry["version"], "0.1.0");
    assert_eq!(entry["checksum"], sum('c'));
    assert_eq!(entry["needs"], "security_approver");
    assert_eq!(entry["registry"]["first_publish_age_days"], 3);
    assert_eq!(entry["registry"]["license"], "MIT");
    assert_eq!(entry["registry"]["downloads"], 1_000_000);
    assert!(
        entry["flags"]
            .as_array()
            .expect("flags")
            .contains(&json!("first_publish_too_recent"))
    );
    assert_eq!(entry["approval"], json!(null));
}

// ---------------------------------------------------------------------------------------------
// The decision: who may make it, how it is recorded, what it is bound to
// ---------------------------------------------------------------------------------------------

#[test]
fn an_approver_who_is_not_the_requester_is_authorized_and_recorded_with_the_proof() {
    let subject = subject("some-crate", "0.1.0", 'c');
    let approval = approve(APPROVER, "bob", Designation::Approver, &subject).expect("recorded");
    assert_eq!(approval.approver.get(), APPROVER);
    assert_eq!(approval.designation, Designation::Approver);
    assert_eq!(approval.allowlist_version, "sha256:allowlist-v1");
    assert_eq!(approval.policy_hash, policy_hash());
    assert!(approval.reason.contains("Reviewed"));
    assert!(approval.covers(&subject));
}

#[test]
fn the_requester_cannot_approve_their_own_dependency() {
    let verdict = decide(
        &human(REQUESTER, "alice"),
        Designation::Approver,
        Some(REQUESTER),
    );
    assert!(
        matches!(&verdict, ActionVerdict::Denied(d) if d.reason == ActionDenialReason::SelfApproval),
        "{verdict:?}"
    );
}

#[test]
fn an_approver_cannot_decide_what_needs_a_security_approver() {
    let verdict = decide(
        &human(APPROVER, "bob"),
        Designation::SecurityApprover,
        Some(REQUESTER),
    );
    assert!(
        matches!(&verdict, ActionVerdict::Denied(d) if matches!(d.reason, ActionDenialReason::MissingDesignation { .. })),
        "{verdict:?}"
    );
    let operator = decide(
        &human(OPERATOR, "olga"),
        Designation::Approver,
        Some(REQUESTER),
    );
    assert!(matches!(operator, ActionVerdict::Denied(_)));
}

#[test]
fn a_security_approver_can_decide_a_security_case() {
    let subject = subject("fresh-crate", "0.1.0", 'c');
    let approval =
        approve(SECURITY, "sam", Designation::SecurityApprover, &subject).expect("recorded");
    assert_eq!(approval.designation, Designation::SecurityApprover);
    assert!(approval.satisfies(Designation::SecurityApprover));
    assert!(approval.satisfies(Designation::Approver));
}

#[test]
fn negative_nt_sup_01_a_login_is_not_an_identity() {
    // Another account has the login of a listed approver. The numeric id decides.
    let imposter = human(2000, "bob");
    let verdict = decide(&imposter, Designation::Approver, Some(REQUESTER));
    assert!(
        matches!(&verdict, ActionVerdict::Denied(d) if matches!(d.reason, ActionDenialReason::Authority(_))),
        "{verdict:?}"
    );
    // The listed id under another login is still that person.
    let renamed = authorized(decide(
        &human(APPROVER, "renamed-since"),
        Designation::Approver,
        Some(REQUESTER),
    ));
    assert_eq!(renamed.approver().get(), APPROVER);
}

#[test]
fn a_bot_cannot_decide() {
    let bot = Actor {
        kind: ActorKind::Bot,
        ..human(APPROVER, "bob")
    };
    assert!(matches!(
        decide(&bot, Designation::Approver, Some(REQUESTER)),
        ActionVerdict::Denied(_)
    ));
}

#[test]
fn negative_nt_sup_01_an_approval_is_bound_to_the_exact_name_version_and_checksum() {
    let approved = subject("some-crate", "0.1.0", 'c');
    let approval = approve(APPROVER, "bob", Designation::Approver, &approved).expect("recorded");

    let at_head = |version: &'static str, digit: char| {
        plan_with(
            &head_adding("some-crate", version, digit),
            &table(&[("some-crate", old_and_licensed())]),
            std::slice::from_ref(&approval),
            &[],
        )
    };
    // The exact thing approved: decided.
    let same = at_head("0.1.0", 'c');
    assert!(only_need(&same).approval.is_some());
    assert!(same.may_fetch());
    // A different version needs a new approval.
    let later = at_head("0.1.1", 'c');
    assert!(only_need(&later).awaiting() && !later.may_fetch());
    // The same version with another checksum is another package.
    let swapped = at_head("0.1.0", 'd');
    assert!(only_need(&swapped).awaiting() && !swapped.may_fetch());
    // Another name.
    let other = plan_with(
        &head_adding("other-crate", "0.1.0", 'c'),
        &table(&[("other-crate", old_and_licensed())]),
        std::slice::from_ref(&approval),
        &[],
    );
    assert!(only_need(&other).awaiting());
}

#[test]
fn an_approval_by_an_approver_does_not_cover_a_case_that_needs_a_security_approver() {
    let young = record(Some("2026-10-25T12:00:00Z"), Some("MIT"));
    let approver_only = approve(
        APPROVER,
        "bob",
        Designation::Approver,
        &subject("fresh-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let plan = plan_with(
        &head_adding("fresh-crate", "0.1.0", 'c'),
        &table(&[("fresh-crate", young.clone())]),
        &[approver_only],
        &[],
    );
    assert!(only_need(&plan).awaiting() && !plan.may_fetch());

    let security = approve(
        SECURITY,
        "sam",
        Designation::SecurityApprover,
        &subject("fresh-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let decided = plan_with(
        &head_adding("fresh-crate", "0.1.0", 'c'),
        &table(&[("fresh-crate", young)]),
        &[security],
        &[],
    );
    assert!(decided.awaiting().is_empty() && decided.may_fetch());
}

#[test]
fn the_decision_is_ledger_evidence_with_the_approver_the_policy_hash_and_the_reason() {
    let subject = subject("some-crate", "0.1.0", 'c');
    let approval = approve(APPROVER, "bob", Designation::Approver, &subject).expect("recorded");
    let json = approval.to_json();
    assert_eq!(json["approver_id"], APPROVER);
    assert_eq!(json["policy_hash"], policy_hash().as_str());
    assert_eq!(json["designation"], "approver");
    assert_eq!(json["name"], "some-crate");
    assert_eq!(json["checksum"], sum('c'));
    assert!(
        json["reason"]
            .as_str()
            .expect("a reason")
            .contains("license")
    );
    assert!(json.get("login").is_none(), "a login is never the key");
    assert_eq!(DependencyApproval::from_json(&json), Some(approval));
}

#[test]
fn a_stored_record_that_names_a_person_by_login_is_not_an_approval() {
    let subject = subject("some-crate", "0.1.0", 'c');
    let mut json = approve(APPROVER, "bob", Designation::Approver, &subject)
        .expect("recorded")
        .to_json();
    json.as_object_mut()
        .expect("an object")
        .remove("approver_id");
    json["approver_login"] = json!("bob");
    assert_eq!(DependencyApproval::from_json(&json), None);
    // A zero or a text id is no id either.
    for bad in [json!(0), json!("1004"), json!(-1)] {
        let mut changed = approve(APPROVER, "bob", Designation::Approver, &subject)
            .expect("recorded")
            .to_json();
        changed["approver_id"] = bad;
        assert_eq!(DependencyApproval::from_json(&changed), None);
    }
}

#[test]
fn a_decision_needs_a_reason_the_right_action_and_a_checksum() {
    let subject = subject("some-crate", "0.1.0", 'c');
    let proof = authorized(decide(
        &human(APPROVER, "bob"),
        Designation::Approver,
        Some(REQUESTER),
    ));
    assert_eq!(
        DependencyApproval::record(&proof, subject.clone(), policy_hash(), scope(), "ok").err(),
        Some(ApprovalError::NoReason)
    );
    let no_sum = Subject {
        checksum: String::new(),
        ..subject.clone()
    };
    assert_eq!(
        DependencyApproval::record(
            &proof,
            no_sum,
            policy_hash(),
            scope(),
            "A reason that is long enough."
        )
        .err(),
        Some(ApprovalError::NoChecksum)
    );
    // An authorization for another action is not a dependency decision.
    let tenant = super::people::tenant();
    let (allowlist, now) = (super::people::allowlist(), now());
    let actor = human(APPROVER, "bob");
    let other =
        engine()
            .authority
            .authorize_action(&factory_domain::policy::authority::ActionContext {
                action: "approve_pr",
                level: factory_domain::policy::authority::AutonomyLevel::L1,
                tenant: &tenant,
                repository: "example-org/app",
                actor: &actor,
                allowlist: &allowlist,
                now: &now,
                requester: GithubUserId::new(REQUESTER),
                change: factory_domain::policy::authority::ChangeFacts {
                    risk_tier: factory_domain::vocabulary::RiskTier::Low,
                    protected_path_change: false,
                    sensitive_file_change: false,
                    new_dependency: false,
                },
                require_designation: None,
                step_up_done: false,
            });
    let proof = authorized(other);
    assert_eq!(
        DependencyApproval::record(
            &proof,
            subject,
            policy_hash(),
            scope(),
            "A reason that is long enough."
        )
        .err(),
        Some(ApprovalError::WrongAction)
    );
}

// ---------------------------------------------------------------------------------------------
// Licenses
// ---------------------------------------------------------------------------------------------

#[test]
fn a_license_off_the_list_that_the_registry_shows_refuses_the_change_before_any_fetch() {
    for license in [
        "MPL-2.0",
        "GPL-3.0-only",
        "LGPL-2.1-or-later",
        "AGPL-3.0",
        "SSPL-1.0",
    ] {
        let plan = plan(
            &head_adding("some-crate", "0.1.0", 'c'),
            &table(&[(
                "some-crate",
                record(Some("2020-01-01T00:00:00Z"), Some(license)),
            )]),
        );
        assert!(
            plan.violations().any(|f| f.check == "license-not-allowed"),
            "{license}: {:?}",
            plan.findings
        );
        assert!(plan.refused() && !plan.may_fetch(), "{license}");
    }
}

fn meta(
    name: &str,
    version: &str,
    license: Option<&str>,
    build: bool,
    proc_macro: bool,
) -> PackageMeta {
    PackageMeta {
        name: name.to_owned(),
        version: version.to_owned(),
        license: license.map(str::to_owned),
        build_script: build,
        proc_macro,
    }
}

fn head_with_transitive() -> Files {
    files(&[
        (
            "Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nserde = \"1\"\nsome-crate = \"0.1\"\n",
            ),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["serde", "some-crate"]),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
                reg("some-crate", "0.1.0", 'c').with_deps(&["inner"]),
                reg("inner", "2.0.0", 'd'),
            ]),
        ),
    ])
}

fn decided_plan(head: &Files, approvals: &[DependencyApproval]) -> Plan {
    plan_with(
        head,
        &table(&[("some-crate", old_and_licensed())]),
        approvals,
        &[],
    )
}

#[test]
fn the_license_of_every_package_that_came_in_is_read_from_the_fetched_metadata() {
    let approval = approve(
        APPROVER,
        "bob",
        Designation::Approver,
        &subject("some-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let plan = decided_plan(&head_with_transitive(), &[approval]);
    assert!(plan.may_fetch());
    let licenses = LicensePolicy::owner_approved();

    let fine = [
        meta("some-crate", "0.1.0", Some("MIT"), false, false),
        meta("inner", "2.0.0", Some("Unicode-3.0 AND MIT"), false, false),
    ];
    assert!(!conclude(&plan, &fine, &licenses).has_violation());

    // A transitive package with a license off the list fails the gate.
    let copyleft = [
        meta("some-crate", "0.1.0", Some("MIT"), false, false),
        meta("inner", "2.0.0", Some("GPL-3.0-or-later"), false, false),
    ];
    let denied = conclude(&plan, &copyleft, &licenses);
    assert!(
        denied
            .findings
            .iter()
            .any(|f| f.check == "license-not-allowed" && f.message.contains("inner"))
    );

    // No metadata for a package, or no license in it, is an unknown license.
    let unknown = [meta("some-crate", "0.1.0", Some("MIT"), false, false)];
    assert!(conclude(&plan, &unknown, &licenses).has_violation());
    let silent = [
        meta("some-crate", "0.1.0", Some("MIT"), false, false),
        meta("inner", "2.0.0", None, false, false),
    ];
    assert!(conclude(&plan, &silent, &licenses).has_violation());
}

#[test]
fn a_package_licensed_under_an_or_expression_passes_only_through_a_listed_alternative() {
    let approval = approve(
        APPROVER,
        "bob",
        Designation::Approver,
        &subject("some-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let plan = decided_plan(&head_with_transitive(), &[approval]);
    let licenses = LicensePolicy::owner_approved();
    let ok = [
        meta(
            "some-crate",
            "0.1.0",
            Some("MIT OR Apache-2.0 OR LGPL-2.1-or-later"),
            false,
            false,
        ),
        meta("inner", "2.0.0", Some("MIT"), false, false),
    ];
    assert!(!conclude(&plan, &ok, &licenses).has_violation());
    let bad = [
        meta(
            "some-crate",
            "0.1.0",
            Some("LGPL-2.1-or-later OR GPL-2.0-only"),
            false,
            false,
        ),
        meta("inner", "2.0.0", Some("MIT"), false, false),
    ];
    assert!(conclude(&plan, &bad, &licenses).has_violation());
}

#[test]
fn the_license_allow_list_is_the_one_in_deny_toml() {
    let text = include_str!("../../../../deny.toml");
    let doc = factory_workflow::gates::supply_chain::toml::parse(text).expect("deny.toml parses");
    let allow: Vec<String> = doc["licenses"].as_table().expect("licenses")["allow"]
        .as_array()
        .expect("allow")
        .iter()
        .map(|v| v.as_str().expect("an identifier").to_owned())
        .collect();
    assert_eq!(allow, LicensePolicy::owner_approved().allowed());
}

// ---------------------------------------------------------------------------------------------
// Build code that comes in under a dependency
// ---------------------------------------------------------------------------------------------

#[test]
fn build_code_that_comes_in_under_an_approver_decision_asks_for_a_security_approver() {
    let by_approver = approve(
        APPROVER,
        "bob",
        Designation::Approver,
        &subject("some-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let plan = decided_plan(&head_with_transitive(), std::slice::from_ref(&by_approver));
    let licenses = LicensePolicy::owner_approved();
    let metadata = [
        meta("some-crate", "0.1.0", Some("MIT"), false, false),
        meta("inner", "2.0.0", Some("MIT"), true, false),
    ];
    let conclusion = conclude(&plan, &metadata, &licenses);
    assert!(
        !conclusion.has_violation(),
        "build code is flagged and does not fail the gate"
    );
    assert!(
        conclusion
            .findings
            .iter()
            .any(|f| f.check == "build-code-added" && f.message.contains("inner"))
    );
    assert_eq!(conclusion.escalated.len(), 1);
    assert_eq!(conclusion.escalated[0].name, "some-crate");

    // A security approver's decision clears it.
    let by_security = approve(
        SECURITY,
        "sam",
        Designation::SecurityApprover,
        &subject("some-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let cleared = decided_plan(&head_with_transitive(), &[by_approver, by_security]);
    assert!(
        conclude(&cleared, &metadata, &licenses)
            .escalated
            .is_empty()
    );
}

#[test]
fn a_procedural_macro_counts_as_build_code() {
    let approval = approve(
        APPROVER,
        "bob",
        Designation::Approver,
        &subject("some-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let plan = decided_plan(&head_with_transitive(), &[approval]);
    let metadata = [
        meta("some-crate", "0.1.0", Some("MIT"), false, true),
        meta("inner", "2.0.0", Some("MIT"), false, false),
    ];
    let conclusion = conclude(&plan, &metadata, &LicensePolicy::owner_approved());
    assert_eq!(conclusion.escalated.len(), 1);
}

#[test]
fn a_dependency_with_no_build_code_asks_for_nothing_more() {
    let approval = approve(
        APPROVER,
        "bob",
        Designation::Approver,
        &subject("some-crate", "0.1.0", 'c'),
    )
    .expect("recorded");
    let plan = decided_plan(&head_with_transitive(), &[approval]);
    let metadata = [
        meta("some-crate", "0.1.0", Some("MIT"), false, false),
        meta("inner", "2.0.0", Some("MIT"), false, false),
    ];
    let conclusion = conclude(&plan, &metadata, &LicensePolicy::owner_approved());
    assert!(conclusion.escalated.is_empty() && conclusion.findings.is_empty());
}

#[test]
fn a_refused_change_asks_no_person_anything() {
    // A git source in the lockfile is refused by the integrity checks; the plan does not ask
    // anybody to approve what cannot pass.
    let head = with(
        head_adding("some-crate", "0.1.0", 'c'),
        "Cargo.lock",
        &lock(&[
            member("app", &["some-crate", "serde"]),
            reg("some-crate", "0.1.0", 'c')
                .at_source("git+https://attacker.test/x#abc")
                .without_checksum(),
            reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    let plan = plan(&head, &RegistryTable::new());
    assert!(plan.refused());
    assert!(plan.needs.is_empty());
    assert!(!plan.may_fetch());
}
