//! The ruleset reader: a response of the rules for a branch becomes a protection report, and the
//! report becomes a verdict. The responses are the fixtures in `tests/fixtures/`, written by hand
//! from the documented shape and not recorded (see the README there): these tests show that the
//! reader understands that shape, not that GitHub sends it.

use factory_domain::ids::PrincipalId;
use factory_domain::values::{Slug, Timestamp};
use factory_github::protection_from_rules;
use factory_ports::clock::Uuid;
use factory_ports::githost::{
    AppId, BypassAttestation, PreflightFailure, PreflightVerdict, ProtectionSource, RequiredCheck,
};
use factory_ports::paths::BranchName;
use serde_json::Value;

const APP: AppId = AppId(424_242);

fn fixture(text: &str) -> Value {
    serde_json::from_str(text).expect("a fixture is JSON")
}

fn report(text: &str) -> factory_ports::githost::ProtectionReport {
    protection_from_rules(BranchName::new("main").unwrap(), &fixture(text)).expect("a report")
}

fn checks() -> Vec<Slug> {
    vec![
        Slug::parse("factory-validation").unwrap(),
        Slug::parse("factory-review").unwrap(),
    ]
}

fn attestation() -> BypassAttestation {
    BypassAttestation {
        by: PrincipalId::from_uuid(Uuid::from_u128(9)),
        at: Timestamp::parse("2026-10-28T09:00:00Z").unwrap(),
    }
}

#[test]
fn a_strong_response_becomes_a_report_that_passes_with_an_attestation() {
    let strong = report(include_str!("fixtures/rules_branches_strong.json"));
    assert_eq!(strong.source, ProtectionSource::Rulesets);
    assert!(strong.requires_pull_request && strong.requires_code_owner_review);
    assert!(strong.dismisses_stale_approvals && strong.blocks_force_push && strong.blocks_deletion);
    assert!(strong.required_checks.contains(&RequiredCheck {
        context: "factory-validation".to_owned(),
        integration_id: Some(424_242),
    }));
    // The fixture asks for one approving review, which is what the policy needs (SF-07).
    assert_eq!(strong.required_approving_reviews, Some(1));
    assert_eq!(
        strong.evaluate(APP, &checks(), Some(&attestation()), 1),
        PreflightVerdict::Pass
    );
    // The same response is short of a policy that needs two.
    assert_eq!(
        strong.evaluate(APP, &checks(), Some(&attestation()), 2),
        PreflightVerdict::CapAtL0(vec![PreflightFailure::ApprovingReviewsBelowPolicy {
            found: 1,
            needed: 2,
        }])
    );
}

#[test]
fn a_missing_attestation_caps_a_strong_repository_and_says_why() {
    let strong = report(include_str!("fixtures/rules_branches_strong.json"));
    assert_eq!(
        strong.evaluate(APP, &checks(), None, 1),
        PreflightVerdict::CapAtL0(vec![PreflightFailure::BypassNotAttested])
    );
}

#[test]
fn a_repository_with_only_classic_protection_is_capped_at_l0_with_a_named_reason() {
    let classic = report(include_str!("fixtures/rules_branches_empty.json"));
    assert_eq!(classic.source, ProtectionSource::NoRulesetRules);
    assert_eq!(classic.required_approving_reviews, None);
    match classic.evaluate(APP, &checks(), Some(&attestation()), 1) {
        PreflightVerdict::CapAtL0(reasons) => {
            assert_eq!(reasons.first(), Some(&PreflightFailure::NoRulesetRules));
            assert!(reasons.contains(&PreflightFailure::PullRequestNotRequired));
        }
        PreflightVerdict::Pass => panic!("a repository without ruleset rules must not pass"),
    }
}

#[test]
fn checks_that_any_app_may_satisfy_or_that_another_app_owns_are_not_pinned() {
    let unpinned = report(include_str!("fixtures/rules_branches_unpinned.json"));
    assert_eq!(
        unpinned.evaluate(APP, &checks(), Some(&attestation()), 1),
        PreflightVerdict::CapAtL0(vec![
            PreflightFailure::FactoryCheckNotPinned("factory-validation".to_owned()),
            PreflightFailure::FactoryCheckNotPinned("factory-review".to_owned()),
        ])
    );
}
