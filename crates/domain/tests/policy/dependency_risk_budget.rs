//! New direct dependencies, risk tiers, budgets and the rework and repair caps.

use std::sync::LazyLock;

use factory_domain::machines::limits::{
    DEFAULT_REPAIR_CAP, DEFAULT_REWORK_CAP, ReworkLedger, ReworkTrack,
};
use factory_domain::policy::budget::{BudgetVerdict, CeilingRefusal, Metric, Reading, Scope};
use factory_domain::policy::decision::Designation;
use factory_domain::policy::dependency::{
    DECORATIONS, DependencyDecision, DependencyFlag, DependencyRefusal, DependencyRequest,
    RegistryFacts, RunWhen, is_decorated, within_one_edit,
};
use factory_domain::policy::risk::RiskFacts;
use factory_domain::policy::{BuildError, PolicyEngine};
use factory_domain::vocabulary::RiskTier;
use proptest::prelude::*;

use crate::support::{approval, security, security_from, security_json};

fn engine() -> &'static PolicyEngine {
    static ENGINE: LazyLock<PolicyEngine> =
        LazyLock::new(|| PolicyEngine::new(&security(), &approval()).expect("builds"));
    &ENGINE
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

// ---------------------------------------------------------------------------------------------
// New direct dependencies (ADR 0009)
// ---------------------------------------------------------------------------------------------

fn decide(
    ecosystem: &str,
    name: &str,
    lockfile: &[&str],
    facts: &RegistryFacts<'_>,
) -> DependencyDecision {
    engine().dependency.decide(
        &DependencyRequest {
            ecosystem,
            name,
            version_req: "^1.2",
        },
        &strings(lockfile),
        facts,
    )
}

fn needs_human(decision: &DependencyDecision) -> (Designation, &[DependencyFlag]) {
    match decision {
        DependencyDecision::NeedsHuman {
            designation, flags, ..
        } => (*designation, flags),
        other => panic!("expected a human, got {other:?}"),
    }
}

#[test]
fn override_and_dependency_rules_a_new_direct_dependency_always_needs_a_human() {
    let popular = strings(&["reqwest", "serde", "tokio", "lodash"]);
    let internal = strings(&["acme-billing-core"]);
    let facts = |exists, age| RegistryFacts {
        exists_in_registry: exists,
        first_publish_age_days: age,
        popular_names: &popular,
        internal_names: &internal,
    };

    // The best possible package: it exists, it is old, nothing about it looks odd. A human still
    // decides, an ordinary approver does.
    let best = decide(
        "cargo",
        "boring-lib",
        &["serde"],
        &facts(Some(true), Some(4000)),
    );
    assert_eq!(needs_human(&best), (Designation::Approver, &[][..]));

    // NT-SUP-01: each of these goes to a security approver and none is approved.
    let table: Vec<(&str, &str, RegistryFacts<'_>, DependencyFlag)> = vec![
        (
            "cargo",
            "no-such-crate",
            facts(Some(false), None),
            DependencyFlag::NotInRegistry,
        ),
        (
            "cargo",
            "fresh-crate",
            facts(Some(true), Some(3)),
            DependencyFlag::FirstPublishTooRecent,
        ),
        (
            "cargo",
            "reqwset",
            facts(Some(true), Some(900)),
            DependencyFlag::NearPopularName("reqwest".into()),
        ),
        (
            "cargo",
            "serd",
            facts(Some(true), Some(900)),
            DependencyFlag::NearPopularName("serde".into()),
        ),
        (
            "npm",
            "lodahs",
            facts(Some(true), Some(900)),
            DependencyFlag::NearPopularName("lodash".into()),
        ),
        (
            "cargo",
            "acme-billing-core",
            facts(Some(true), Some(900)),
            DependencyFlag::InternalNameCollision,
        ),
        (
            "cargo",
            "unknown-age",
            facts(Some(true), None),
            DependencyFlag::FirstPublishUnknown,
        ),
        (
            "cargo",
            "unknown-registry",
            facts(None, Some(900)),
            DependencyFlag::RegistryUnknown,
        ),
    ];
    for (ecosystem, name, facts, flag) in table {
        let decision = decide(ecosystem, name, &["serde"], &facts);
        let (designation, flags) = needs_human(&decision);
        assert_eq!(designation, Designation::SecurityApprover, "{name}");
        assert!(flags.contains(&flag), "{name}: {flags:?}");
    }
    // The 30-day line is the policy's: 29 days is young, 30 is not.
    assert_eq!(engine_min_age(), 30);
    assert_eq!(
        needs_human(&decide("cargo", "edge", &[], &facts(Some(true), Some(29)))).0,
        Designation::SecurityApprover
    );
    assert_eq!(
        needs_human(&decide("cargo", "edge", &[], &facts(Some(true), Some(30)))).0,
        Designation::Approver
    );

    // A well-known package that is new to this repository is still new.
    let known = decide("cargo", "tokio", &["serde"], &facts(Some(true), Some(3000)));
    assert_eq!(needs_human(&known).0, Designation::Approver);
    // Absent from the base lockfile is the whole definition of new: being on an organization list
    // or having been approved elsewhere does not change it (there is no such input).
    // The control: a name already in the base lockfile is not new, in the ecosystem's own
    // spelling of the name.
    assert_eq!(
        decide(
            "cargo",
            "serde",
            &["serde", "tokio"],
            &facts(Some(true), Some(3000))
        ),
        DependencyDecision::NotNew
    );
    assert_eq!(
        decide("cargo", "Serde-Json", &["serde_json"], &facts(None, None)),
        DependencyDecision::NotNew
    );
    assert_eq!(
        decide("pip", "Foo.Bar_baz", &["foo-bar-baz"], &facts(None, None)),
        DependencyDecision::NotNew
    );
    assert_eq!(
        decide("npm", "left-pad", &["left-pad"], &facts(None, None)),
        DependencyDecision::NotNew
    );
    // npm and Go names are exact, so a different case is a different (and invalid or new) name.
    assert_ne!(
        decide(
            "npm",
            "left-pad",
            &["Left-Pad"],
            &facts(Some(true), Some(900))
        ),
        DependencyDecision::NotNew
    );
    assert_ne!(
        decide(
            "go",
            "github.com/a/b",
            &["github.com/a/B"],
            &facts(Some(true), Some(900))
        ),
        DependencyDecision::NotNew
    );
}

#[test]
fn the_policy_gives_the_age_of_the_advisory_database_and_when_the_dependency_gates_run() {
    // SC-6: the limit is a policy value, the 7 days of `maximum-db-staleness` in deny.toml.
    assert_eq!(engine().dependency.advisory_database_max_age_days(), 7);
    // The decision about when the gates run is written in the policy: for a change that touches
    // a dependency file, because the gates judge the change and a scheduled scan of the base
    // branch judges the repository.
    assert_eq!(
        engine().dependency.run_when(),
        RunWhen::DependencyFilesChange
    );
}

#[test]
fn the_wording_of_new_excludes_the_members_of_the_project_and_the_old_wording_does_not_build() {
    // SC-3: a package whose name is only that of a member of the project is still new. The
    // engine reads one wording of the rule, and a policy that says the old one, which let an
    // internal name make a registry package "not new", does not build.
    let mut json = security_json();
    assert_eq!(
        json["supply_chain"]["new_direct_dependency"]["new_means"],
        "name_absent_from_base_commit_lockfile_as_anything_but_a_project_member"
    );
    json["supply_chain"]["new_direct_dependency"]["new_means"] =
        "name_absent_from_base_commit_lockfile".into();
    assert!(matches!(
        PolicyEngine::new(&security_from(json), &approval()),
        Err(BuildError::UnknownValue { .. })
    ));
}

#[test]
fn a_policy_with_a_value_for_the_age_or_for_when_the_gates_run_that_the_engine_does_not_know_does_not_build()
 {
    let with = |change: fn(&mut serde_json::Value)| {
        let mut json = security_json();
        change(&mut json);
        PolicyEngine::new(&security_from(json), &approval())
    };
    assert!(
        matches!(
            with(|j| j["supply_chain"]["dependency_gates"]["run_when"] = "sometimes".into()),
            Err(BuildError::UnknownValue { .. })
        ),
        "a run_when that is not one of the two"
    );
    assert!(
        with(|j| j["supply_chain"]["dependency_gates"]["run_when"] = "always".into()).is_ok(),
        "always is a value the engine reads"
    );
}

#[test]
fn the_edit_rule_and_the_decoration_rule_are_public_and_have_one_home() {
    // B-6: the gate used to keep its own copy of both. The rule lives here, and the gate calls it.
    assert!(within_one_edit("serde", "serdee"));
    assert!(within_one_edit("reqwest", "reqwset"));
    assert!(within_one_edit("serde", "serd"));
    assert!(
        !within_one_edit("serde", "serde"),
        "the same name is not an imitation"
    );
    assert!(!within_one_edit("serde", "serdeee"));
    assert!(is_decorated("reqwest", "reqwest_rs"));
    assert!(is_decorated("clap", "clap-derive-macros"));
    assert!(is_decorated("serde", "rust_serde"));
    assert!(
        !is_decorated("serde", "serde_json"),
        "`json` is not a decoration"
    );
    assert!(!is_decorated("serde", "serde"));
    assert!(!is_decorated("serde", "serde_one_two_three"));
    assert!(DECORATIONS.contains(&"rs") && DECORATIONS.contains(&"ext"));
}

#[test]
fn a_popular_name_with_a_decoration_goes_to_a_security_approver_like_one_edit_away() {
    // H-4: a squatter adds a word to a popular name. The human still decides; the scrutiny is the
    // security approver's.
    let popular = strings(&["reqwest", "serde", "clap", "anyhow", "tokio", "tokio_util"]);
    let facts = RegistryFacts {
        exists_in_registry: Some(true),
        first_publish_age_days: Some(900),
        popular_names: &popular,
        internal_names: &[],
    };
    for (name, imitated) in [
        ("reqwest-rs", "reqwest"),
        ("Reqwest_RS", "reqwest"),
        ("clap-derive-macros", "clap"),
        ("anyhow-ext", "anyhow"),
        ("rust-serde", "serde"),
    ] {
        let decision = decide("cargo", name, &["tokio"], &facts);
        let (designation, flags) = needs_human(&decision);
        assert_eq!(designation, Designation::SecurityApprover, "{name}");
        assert!(
            flags.contains(&DependencyFlag::NearPopularName(imitated.to_owned())),
            "{name}: {flags:?}"
        );
    }
    // A name that is on the list itself is not an imitation of the shorter name on it.
    let own = decide("cargo", "tokio-util", &["serde"], &facts);
    let (designation, flags) = needs_human(&own);
    assert_eq!(designation, Designation::Approver);
    assert!(flags.is_empty(), "{flags:?}");
    // The words of a real package are not decorations.
    let json = decide("cargo", "serde_json", &["tokio"], &facts);
    assert_eq!(needs_human(&json).0, Designation::Approver);
}

fn engine_min_age() -> u64 {
    security()
        .supply_chain
        .new_direct_dependency
        .min_first_publish_age_days
}

#[test]
fn override_and_dependency_rules_requests_that_could_name_a_source_other_than_the_registry_are_refused()
 {
    let facts = RegistryFacts::default();
    let bad_names = [
        ("cargo", ""),
        ("cargo", "git+https://github.com/x/y"),
        ("cargo", "../x"),
        ("cargo", "a b"),
        ("cargo", "1leading"),
        ("cargo", "x/y"),
        ("npm", "https://evil.test/p.tgz"),
        ("npm", "file:../x"),
        ("npm", "@scope"),
        ("npm", "@/x"),
        ("npm", "@a/b/c"),
        ("npm", "UpperCase"),
        ("npm", ".hidden"),
        ("pip", "-r"),
        ("pip", "git+ssh://x"),
        ("go", "nodots/x"),
        ("go", "github.com/a/../b"),
        ("go", "github.com//b"),
        ("go", "https://github.com/a/b"),
    ];
    for (ecosystem, name) in bad_names {
        let decision = decide(ecosystem, name, &[], &facts);
        assert!(
            matches!(
                decision,
                DependencyDecision::Refused {
                    reason: DependencyRefusal::InvalidName,
                    ..
                }
            ),
            "{ecosystem} {name:?}: {decision:?}"
        );
    }
    for req in [
        "git+https://x/y",
        "file:../x",
        "1.0 || http://x",
        "https://x/p.tgz",
        "workspace:*",
        "npm:other@1",
        "1.0\n",
        "1".repeat(65).as_str(),
    ] {
        let decision = engine().dependency.decide(
            &DependencyRequest {
                ecosystem: "cargo",
                name: "fine",
                version_req: req,
            },
            &[],
            &facts,
        );
        assert!(
            matches!(
                decision,
                DependencyDecision::Refused {
                    reason: DependencyRefusal::InvalidVersionRequirement,
                    ..
                }
            ),
            "{req:?}"
        );
    }
    let unknown = decide("maven", "x", &[], &facts);
    assert!(matches!(
        unknown,
        DependencyDecision::Refused {
            reason: DependencyRefusal::UnknownEcosystem,
            ..
        }
    ));
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 500, ..ProptestConfig::default() })]

    #[test]
    fn no_input_ever_approves_a_dependency(
        name in "[a-zA-Z0-9_.@/-]{0,40}",
        eco in prop::sample::select(vec!["cargo", "npm", "pip", "go", "other"]),
        exists in prop::option::of(any::<bool>()),
        age in prop::option::of(0u64..5000),
        locked in proptest::collection::vec("[a-z_-]{1,12}", 0..6),
    ) {
        let facts = RegistryFacts { exists_in_registry: exists, first_publish_age_days: age, popular_names: &[], internal_names: &[] };
        let decision = engine().dependency.decide(
            &DependencyRequest { ecosystem: eco, name: &name, version_req: "1" },
            &locked,
            &facts,
        );
        // The only way out without a person is that the name is already locked in; everything
        // else is a person or a refusal. (The enum has no approving variant: this match proves it.)
        match decision {
            DependencyDecision::NotNew => prop_assert!(!locked.is_empty()),
            DependencyDecision::NeedsHuman { designation, .. } => {
                prop_assert!(matches!(designation, Designation::Approver | Designation::SecurityApprover));
            }
            DependencyDecision::Refused { .. } => {}
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Risk tiers
// ---------------------------------------------------------------------------------------------

#[test]
fn a_design_decision_for_a_person_is_medium_and_no_new_dependency() {
    // ADR 0037: the policy names the fact at the medium tier, so it never matches by accident
    // of a missing name, and it lifts nothing to high on its own.
    let facts = RiskFacts {
        design_decision_needs_person: true,
        ..RiskFacts::default()
    };
    let assessment = engine().risk.assess(&facts, None);
    assert_eq!(assessment.tier, RiskTier::Medium);
    assert_eq!(assessment.matched, ["design_decision_needs_person"]);
    assert!(
        !assessment
            .required_reviews
            .iter()
            .any(|r| r == "security_reviewer")
    );
}

#[test]
fn negative_nt_pol_06_the_computed_tier_applies_and_an_agent_claim_only_raises() {
    let risk = &engine().risk;
    // The diff touches dependency manifests: sensitive files, so high, whatever the agent says.
    let facts = RiskFacts {
        sensitive_file_change: true,
        ..RiskFacts::default()
    };
    let assessment = risk.assess(&facts, Some(RiskTier::Low));
    assert_eq!(assessment.tier, RiskTier::High);
    assert_eq!(assessment.computed, RiskTier::High);
    assert_eq!(
        assessment.agent_claim,
        Some(RiskTier::Low),
        "kept as a claim"
    );
    assert!(
        assessment
            .required_reviews
            .iter()
            .any(|r| r == "security_reviewer")
    );
    assert!(
        assessment
            .matched
            .iter()
            .any(|m| m == "sensitive_file_change")
    );
    assert!(!assessment.unclassified);

    let table = [
        (
            RiskFacts {
                docs_only: true,
                ..RiskFacts::default()
            },
            RiskTier::Low,
        ),
        (
            RiskFacts {
                tests_only_new_files: true,
                ..RiskFacts::default()
            },
            RiskTier::Low,
        ),
        (
            RiskFacts {
                multi_module_change: true,
                ..RiskFacts::default()
            },
            RiskTier::Medium,
        ),
        (
            RiskFacts {
                public_api_change: true,
                docs_only: true,
                ..RiskFacts::default()
            },
            RiskTier::Medium,
        ),
        (
            RiskFacts {
                new_dependency: true,
                ..RiskFacts::default()
            },
            RiskTier::High,
        ),
        (
            RiskFacts {
                infra_change: true,
                multi_module_change: true,
                ..RiskFacts::default()
            },
            RiskTier::High,
        ),
        (
            RiskFacts {
                protected_path_change: true,
                docs_only: true,
                ..RiskFacts::default()
            },
            RiskTier::Critical,
        ),
        (
            RiskFacts {
                policy_or_sandbox_change: true,
                ..RiskFacts::default()
            },
            RiskTier::Critical,
        ),
        (
            RiskFacts {
                money_movement: true,
                ..RiskFacts::default()
            },
            RiskTier::Critical,
        ),
    ];
    for (facts, tier) in table {
        let a = risk.assess(&facts, None);
        assert_eq!(a.tier, tier, "{facts:?}");
    }
    assert_eq!(
        risk.assess(
            &RiskFacts {
                protected_path_change: true,
                ..RiskFacts::default()
            },
            None
        )
        .required_approvals,
        2
    );

    // An agent may raise the tier.
    let raised = risk.assess(
        &RiskFacts {
            docs_only: true,
            ..RiskFacts::default()
        },
        Some(RiskTier::Critical),
    );
    assert_eq!(raised.tier, RiskTier::Critical);
    assert_eq!(raised.computed, RiskTier::Low);

    // A change nobody classified is high, not low.
    let unknown = risk.assess(&RiskFacts::default(), Some(RiskTier::Low));
    assert!(unknown.unclassified);
    assert_eq!(unknown.tier, RiskTier::High);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 400, ..ProptestConfig::default() })]

    #[test]
    fn the_tier_never_goes_down_when_a_fact_is_added_or_an_agent_speaks(
        bits in proptest::collection::vec(any::<bool>(), 20),
        extra in 0usize..20,
        claim in prop::option::of(prop::sample::select(vec![RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical])),
    ) {
        let make = |b: &[bool]| RiskFacts {
            docs_only: b[0], tests_only_new_files: b[1],
            single_module_change_without_sensitive_or_protected_paths: b[2], multi_module_change: b[3],
            public_api_change: b[4], schema_migration_without_data_loss: b[5], authn_authz_change: b[6],
            secret_handling_change: b[7], new_dependency: b[8], sensitive_file_change: b[9],
            data_migration: b[10], concurrency_or_locking_change: b[11], infra_change: b[12],
            protected_path_change: b[13], policy_or_sandbox_change: b[14], money_movement: b[15],
            physical_actuation: b[16], regulated_workflow: b[17], production_data_access: b[18],
            design_decision_needs_person: b[19],
        };
        let risk = &engine().risk;
        let base = risk.assess(&make(&bits), None);
        let mut more = bits.clone();
        more[extra] = true;
        let after = risk.assess(&make(&more), None);
        // A fact can lift the tier. It can only lower it by being the first fact (an unclassified
        // change is high by default), and that is `High`, which `Low` or `Medium` can follow
        // only because a criterion now says what the change is.
        if !base.unclassified {
            prop_assert!(after.tier >= base.tier);
        }
        let claimed = risk.assess(&make(&bits), claim);
        prop_assert!(claimed.tier >= base.tier, "a claim lowered the tier");
        prop_assert_eq!(claimed.computed, base.computed);
    }
}

// ---------------------------------------------------------------------------------------------
// Budgets and caps
// ---------------------------------------------------------------------------------------------

#[test]
fn rework_cap_matches_the_default() {
    let policy = security();
    let per_job = &policy.budgets.hard_ceilings.per_job;
    assert!(
        per_job.max_rework_iterations <= u32::from(DEFAULT_REWORK_CAP),
        "{}",
        per_job.max_rework_iterations
    );
    assert!(per_job.max_specification_rework_iterations <= u32::from(DEFAULT_REWORK_CAP));
    assert!(per_job.max_design_rework_iterations <= u32::from(DEFAULT_REWORK_CAP));
    assert!(per_job.max_documentation_rework_iterations <= u32::from(DEFAULT_REWORK_CAP));
    assert!(policy.budgets.rework.default_rounds <= u32::from(DEFAULT_REWORK_CAP));
    let limits = engine().budget.rework_limits();
    for (track, configured) in [
        (
            ReworkTrack::Specification,
            per_job.max_specification_rework_iterations,
        ),
        (ReworkTrack::Design, per_job.max_design_rework_iterations),
        (ReworkTrack::Code, per_job.max_rework_iterations),
        (
            ReworkTrack::Documentation,
            per_job.max_documentation_rework_iterations,
        ),
    ] {
        assert_eq!(u32::from(limits.cap(track).get()), configured, "{track}");
    }
    // Two rounds are allowed, the third is not, for every count.
    for track in ReworkTrack::ALL {
        let one = ReworkLedger::default().with_used(*track, 1);
        let two = ReworkLedger::default().with_used(*track, 2);
        assert!(engine().budget.rework_allowed(one, *track), "{track}");
        assert!(!engine().budget.rework_allowed(two, *track), "{track}");
        // A full count leaves every other count its rounds.
        for other in ReworkTrack::ALL.iter().filter(|t| *t != track) {
            assert!(
                engine().budget.rework_allowed(two, *other),
                "{track} -> {other}"
            );
        }
    }
}

#[test]
fn repair_cap_matches_the_default() {
    let policy = security();
    let repairs = policy
        .untrusted_content
        .structured_output
        .bounded_repair_attempts;
    assert!(repairs <= u32::from(DEFAULT_REPAIR_CAP), "{repairs}");
    assert_eq!(u32::from(engine().budget.repair_cap().get()), repairs);
}

fn reading(metric: Metric, used: f64) -> Reading {
    Reading { metric, used }
}

#[test]
fn budget_checks_warn_at_eighty_percent_and_stop_at_the_ceiling() {
    let b = &engine().budget;
    assert_eq!(b.ceiling(Scope::Task, Metric::Usd), Some(8.0));
    assert_eq!(b.ceiling(Scope::OrgDay, Metric::Usd), Some(500.0));
    let check = |scope, used| b.check(scope, &[reading(Metric::Usd, used)]);
    assert_eq!(check(Scope::Task, 0.0), BudgetVerdict::Within);
    assert_eq!(check(Scope::Task, 6.39), BudgetVerdict::Within);
    assert_eq!(
        check(Scope::Task, 6.4),
        BudgetVerdict::Warn {
            metrics: vec![Metric::Usd]
        }
    );
    assert!(check(Scope::Task, 7.99).may_continue());
    for used in [8.0, 8.01, 1e9, f64::INFINITY, f64::NAN, -1.0] {
        let verdict = check(Scope::Task, used);
        assert!(!verdict.may_continue(), "{used}: {verdict:?}");
    }
    // Several metrics at once: the worst one decides, and every metric over the line is named.
    let verdict = b.check(
        Scope::Task,
        &[
            reading(Metric::Usd, 1.0),
            reading(Metric::ToolCalls, 1500.0),
            reading(Metric::Turns, 60.0),
            reading(Metric::InputTokens, 4_000_000.0 * 0.9),
        ],
    );
    let BudgetVerdict::Exhausted { metrics, rule } = verdict else {
        panic!("exhausted");
    };
    assert_eq!(metrics, [Metric::ToolCalls, Metric::Turns]);
    assert_eq!(rule.id(), "per_task");
    // A metric the scope does not limit is ignored.
    assert_eq!(
        b.check(Scope::OrgDay, &[reading(Metric::Turns, 1e12)]),
        BudgetVerdict::Within
    );
}

#[test]
fn negative_nt_bud_04_ceilings_can_be_lowered_and_never_raised() {
    let b = &engine().budget;
    let lowered = b
        .lowered(Scope::Task, &[(Metric::Usd, 4.0), (Metric::Turns, 30.0)])
        .expect("lowering is allowed");
    assert_eq!(lowered.ceiling(Scope::Task, Metric::Usd), Some(4.0));
    assert_eq!(
        lowered.ceiling(Scope::Task, Metric::ToolCalls),
        Some(1500.0),
        "untouched"
    );
    assert_eq!(
        b.lowered(Scope::Task, &[(Metric::Usd, 8.0)])
            .map(|p| p.ceiling(Scope::Task, Metric::Usd)),
        Ok(Some(8.0))
    );
    for requested in [8.01, 9.0, 1e9] {
        assert_eq!(
            b.lowered(Scope::Task, &[(Metric::Usd, requested)]).err(),
            Some(CeilingRefusal::Raises),
            "{requested}"
        );
    }
    for requested in [f64::NAN, f64::INFINITY, -0.5] {
        assert_eq!(
            b.lowered(Scope::Task, &[(Metric::Usd, requested)]).err(),
            Some(CeilingRefusal::Invalid),
            "{requested}"
        );
    }
    // A limit the scope does not have cannot be created.
    assert_eq!(
        b.lowered(Scope::OrgDay, &[(Metric::Turns, 5.0)]).err(),
        Some(CeilingRefusal::Raises)
    );
    // One bad value in a list changes nothing.
    assert!(
        b.lowered(Scope::Task, &[(Metric::Usd, 1.0), (Metric::Turns, 61.0)])
            .is_err()
    );
    assert_eq!(b.ceiling(Scope::Task, Metric::Usd), Some(8.0));
}

proptest! {
    #[test]
    fn a_lowered_budget_never_has_a_higher_ceiling(
        usd in 0.0f64..20.0, turns in 0.0f64..120.0, tools in 0.0f64..3000.0,
    ) {
        let b = &engine().budget;
        let requested = [(Metric::Usd, usd), (Metric::Turns, turns), (Metric::ToolCalls, tools)];
        match b.lowered(Scope::Task, &requested) {
            Ok(next) => {
                for metric in [Metric::Usd, Metric::Turns, Metric::ToolCalls, Metric::InputTokens, Metric::OutputTokens, Metric::WallClockSeconds] {
                    prop_assert!(next.ceiling(Scope::Task, metric) <= b.ceiling(Scope::Task, metric));
                }
            }
            Err(e) => prop_assert_eq!(e, CeilingRefusal::Raises),
        }
    }
}
