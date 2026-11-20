//! The fake project rules host against its contract suite, and against each deliberate defect. The
//! table of defects lives with the fake (`project_rules::PROJECT_RULES_DEFECTS`).

use factory_testkit::contracts::project_rules;
use factory_testkit::project_rules::{FakeProjectRulesHost, PROJECT_RULES_DEFECTS};

#[tokio::test]
async fn the_fake_project_rules_host_passes_its_contract() {
    let report = project_rules::run_project_rules(|| async {
        FakeProjectRulesHost::with_suite_repository()
    })
    .await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(
        report.passed.len(),
        project_rules::project_rules_checks().len()
    );
}

#[tokio::test]
async fn the_project_rules_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in PROJECT_RULES_DEFECTS {
        let defect = *defect;
        let report = project_rules::run_project_rules(|| async move {
            FakeProjectRulesHost::with_suite_repository_and_defect(defect)
        })
        .await;
        for name in *must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}

#[test]
fn the_fake_reports_that_it_is_a_fake() {
    use factory_domain::vocabulary::Fidelity;
    use factory_ports::project_rules::ProjectRulesHost;
    assert_eq!(FakeProjectRulesHost::new().fidelity(), Fidelity::Fake);
}
