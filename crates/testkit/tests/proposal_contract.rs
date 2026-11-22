//! The fake proposal host against its contract suite, and against each deliberate defect. The
//! table of defects lives with the fake (`proposal::PROPOSAL_DEFECTS`).

use factory_testkit::contracts::proposal;
use factory_testkit::proposal::{FakeProposalHost, PROPOSAL_DEFECTS};

#[tokio::test]
async fn the_fake_proposal_host_passes_its_contract() {
    let report =
        proposal::run_proposal(|| async { FakeProposalHost::with_suite_repository() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), proposal::proposal_checks().len());
}

#[tokio::test]
async fn the_proposal_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in PROPOSAL_DEFECTS {
        let defect = *defect;
        let report = proposal::run_proposal(|| async move {
            FakeProposalHost::with_suite_repository_and_defect(defect)
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
    use factory_ports::proposal::ProposalHost;
    assert_eq!(FakeProposalHost::new().fidelity(), Fidelity::Fake);
}
