//! The static model router and the in-memory agent registry against their shared contract
//! suites, and against each deliberate defect. The tables live with the fakes
//! (`router::DEFECTS`, `registry::DEFECTS`).

use factory_testkit::contracts::{registry, router};
use factory_testkit::registry::{DEFECTS as REGISTRY_DEFECTS, InMemoryRegistrySubject};
use factory_testkit::router::{DEFECTS as ROUTER_DEFECTS, StaticRouterSubject};

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

#[tokio::test]
async fn the_router_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in ROUTER_DEFECTS {
        let defect = *defect;
        let report = router::run(|| async move { StaticRouterSubject::with_defect(defect) }).await;
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}

#[tokio::test]
async fn the_registry_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in REGISTRY_DEFECTS {
        let defect = *defect;
        let report =
            registry::run(|| async move { InMemoryRegistrySubject::with_defect(defect) }).await;
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}
