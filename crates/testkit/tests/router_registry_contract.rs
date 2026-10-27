//! The static model router and the in-memory agent registry against their shared contract
//! suites, and against each deliberate defect.

use factory_testkit::contracts::{registry, router};
use factory_testkit::registry::{InMemoryRegistrySubject, RegistryDefect};
use factory_testkit::router::{RouterDefect, StaticRouterSubject};

#[tokio::test]
async fn the_static_router_passes_the_router_contract() {
    let report = router::run(|| async { StaticRouterSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), router::checks().len());
}

#[tokio::test]
async fn the_in_memory_registry_passes_the_registry_contract() {
    let report = registry::run(|| async { InMemoryRegistrySubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), registry::checks().len());
}

const ROUTER_DEFECTS: [(RouterDefect, &str); 4] = [
    (
        RouterDefect::ChoosesAtRandom,
        "the_same_need_always_gets_the_same_decision",
    ),
    (RouterDefect::WrongFlagSet, "the_flag_set_follows_the_stage"),
    (
        RouterDefect::RoutesAnything,
        "a_need_with_no_entry_has_no_route",
    ),
    (
        RouterDefect::IgnoresCapabilities,
        "a_missing_capability_is_reported_by_name",
    ),
];

#[tokio::test]
async fn the_router_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in ROUTER_DEFECTS {
        let report = router::run(|| async move { StaticRouterSubject::with_defect(defect) }).await;
        assert!(
            report.failed_check(must_fail),
            "the defect {defect:?} should fail {must_fail}, but the failed checks were {:?}",
            report.failed_names()
        );
    }
}

const REGISTRY_DEFECTS: [(RegistryDefect, &str); 4] = [
    (
        RegistryDefect::PicksLowestVersion,
        "any_version_picks_the_highest",
    ),
    (
        RegistryDefect::SkipsPromptHash,
        "a_changed_prompt_is_refused",
    ),
    (
        RegistryDefect::BlursMissingErrors,
        "an_unknown_agent_and_an_unmatched_requirement_are_different_errors",
    ),
    (
        RegistryDefect::UnstableProfileOrder,
        "profiles_come_back_for_a_tag_in_a_stable_order",
    ),
];

#[tokio::test]
async fn the_registry_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in REGISTRY_DEFECTS {
        let report =
            registry::run(|| async move { InMemoryRegistrySubject::with_defect(defect) }).await;
        assert!(
            report.failed_check(must_fail),
            "the defect {defect:?} should fail {must_fail}, but the failed checks were {:?}",
            report.failed_names()
        );
    }
}
