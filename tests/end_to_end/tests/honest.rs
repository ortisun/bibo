//! The canned honest evidence passes every assertion, in production mode for the English and the
//! Portuguese request and in test mode with labelled fakes.

use factory_e2e::assertions::run_all;
use factory_e2e::canned::{Options, honest};
use factory_e2e::{Env, repository_root};

fn env() -> Env {
    Env::load(&repository_root()).expect("the state machine file loads")
}

fn assert_all_pass(options: Options) {
    let env = env();
    let evidence = honest(&env, options);
    let verdicts = run_all(&evidence, &env);
    assert_eq!(verdicts.len(), 14);
    let failures: Vec<String> = verdicts
        .iter()
        .filter(|verdict| !verdict.pass)
        .map(ToString::to_string)
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn the_honest_english_run_with_real_adapters_passes_all_fourteen() {
    assert_all_pass(Options::e1_production());
}

#[test]
fn the_honest_portuguese_run_with_real_adapters_passes_all_fourteen() {
    assert_all_pass(Options::e2_production());
}

#[test]
fn the_honest_english_run_in_test_mode_passes_all_fourteen() {
    assert_all_pass(Options::e1_test_mode());
}

#[test]
fn the_stage_list_comes_from_the_state_machine_file_and_is_not_counted_in_code() {
    let env = env();
    let kinds: Vec<&str> = env.stages.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds.first(), Some(&"INTAKE"));
    assert_eq!(kinds.last(), Some(&"APPROVAL"));
    assert!(!kinds.contains(&"MERGE"), "MERGE belongs to a later slice");
    let evidence = honest(&env, Options::e1_production());
    assert_eq!(evidence.stage_runs.len(), env.stages.len());
}

/// The owner works alone: the policy lets the approver be the requester for a low-risk change
/// (`policies/approval.yaml`, `approver_may_equal_requester_when_low_risk`). An honest run in which
/// the requester approves a low-risk request holds A9; the same approval of a request whose risk
/// is not known to be low does not, and neither does it when the policy says no.
#[test]
fn the_owner_may_approve_their_own_low_risk_request_when_the_policy_allows_it() {
    let env = env();
    assert!(
        env.self_approval_when_low_risk,
        "the repository policy allows it"
    );
    let mut evidence = honest(&env, Options::e1_production());
    let requester = evidence.job.requester.clone();
    let requester_id = requester.trim_start_matches("human:").to_owned();
    for record in evidence
        .audit
        .iter_mut()
        .filter(|r| r.action == "approval_granted_or_rejected.granted")
    {
        record.actor.clone_from(&requester);
    }
    for entry in &mut evidence.ledger {
        if let Some(items) = entry
            .pointer_mut("/evidence")
            .and_then(serde_json::Value::as_array_mut)
        {
            for item in items {
                if item
                    .pointer("/attestor/role")
                    .and_then(serde_json::Value::as_str)
                    == Some("approver")
                {
                    item["attestor"]["principal_id"] = serde_json::json!(requester_id);
                }
            }
        }
    }
    factory_e2e::mutations::reseal(&mut evidence);
    let a9 = |evidence: &factory_e2e::RunEvidence, env: &Env| {
        run_all(evidence, env)
            .into_iter()
            .find(|verdict| verdict.id == "A9")
            .expect("A9 runs")
    };
    let unknown_risk = a9(&evidence, &env);
    assert!(!unknown_risk.pass, "{unknown_risk}");
    evidence
        .facts
        .insert("risk_tier".to_owned(), serde_json::json!("low"));
    let low = a9(&evidence, &env);
    assert!(low.pass, "{low}");
    let strict = Env {
        self_approval_when_low_risk: false,
        ..env
    };
    let refused = a9(&evidence, &strict);
    assert!(!refused.pass, "{refused}");
}
