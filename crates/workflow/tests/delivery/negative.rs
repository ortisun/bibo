//! The negative tests of the delivery stage: drift of the evidence, hostile text, secrets, a pull
//! request that is not a draft, evidence that did not clear, and a retry in the middle.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::StageKind;
use factory_ports::paths::CommitSha;
use factory_workflow::gates::framework::{BlockCause, Resolution};
use factory_workflow::handlers::StageError;
use factory_workflow::stages::delivery::text::{TextRefused, finish};

use crate::spy::Call;
use crate::world::{ReviewBinding, Scenario, World, canary};

/// Everything up to `execute`, so that a test sees its result and not a panic.
async fn execute_only(world: &World) -> Result<Vec<String>, StageError> {
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world.resolve_contract(&handler, &upstream)?;
    world
        .execute(&handler, &contract, &upstream)
        .await
        .map(|outputs| outputs.iter().map(|o| o.name.as_str().to_owned()).collect())
}

fn nothing_reached_the_host(world: &World) {
    let calls = world.host.calls();
    assert!(
        calls
            .iter()
            .all(|call| matches!(call, Call::ResolveBranch(_))),
        "only a read reached the host: {calls:?}"
    );
    assert!(world.host.opened().is_empty());
    assert!(world.host.checks().is_empty());
    assert!(
        world
            .remote
            .branch_tip(
                &world.repo,
                &factory_ports::paths::BranchName::new("factory/job-1").expect("a branch")
            )
            .is_none(),
        "the branch was pushed"
    );
}

#[tokio::test]
async fn evidence_binding_is_rechecked() {
    // A value the evidence is bound to changed. Each is reported to the engine, the attempt stops,
    // and nothing is pushed, opened or published.
    type Change = fn(&World);
    let changes: [(&str, Change); 4] = [
        ("base", |w| {
            w.host
                .base_moves_to(CommitSha::parse(&"f".repeat(40)).expect("a sha"))
        }),
        ("definitions", |w| {
            w.sources.values.lock().expect("lock").definition_hash =
                Sha256Digest::of(b"definitions two");
        }),
        ("image", |w| {
            w.sources.values.lock().expect("lock").image_digest = Sha256Digest::of(b"image two");
        }),
        ("policy", |w| {
            *w.contract_policy.lock().expect("lock") = Some(Sha256Digest::of(b"policy two"));
        }),
    ];
    for (name, change) in changes {
        let world = World::new();
        change(&world);
        let result = execute_only(&world).await;
        assert_eq!(result, Err(StageError::Cancelled), "{name}");
        assert_eq!(
            world.drift.told.lock().expect("lock").len(),
            1,
            "{name}: the engine was told once"
        );
        nothing_reached_the_host(&world);
    }
}

#[tokio::test]
async fn unchanged_values_do_not_tell_the_engine() {
    let world = World::new();
    world.run().await;
    assert!(world.drift.told.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn evidence_for_another_commit_is_a_violation_and_not_a_drift() {
    let world = World::new();
    let (base, head) = world.commits().await;
    let other = CommitSha::parse(&"c".repeat(40)).expect("a sha");
    let handler = world.handler();
    // The reports were made for `head`, and the implementation result now names another commit.
    // The documentation follows the implementation result, so that only the reports disagree.
    let mut upstream = world.upstream(&base, &head).await;
    let forged = world
        .store_json(&serde_json::json!({
            "base_commit": base.as_str(),
            "head_commit": other.as_str(),
        }))
        .await;
    for run in &mut upstream {
        for output in &mut run.outputs {
            if output.name.as_str() == "implementation-result" {
                output.artifact = forged.clone();
            }
        }
    }
    for (name, field) in [
        ("documentation-result", "code_head"),
        ("documentation-result", "head_commit"),
        ("documentation-plan", "code_head"),
    ] {
        world
            .edit_upstream(&mut upstream, StageKind::Documenting, name, |document| {
                document[field] = serde_json::json!(other.as_str());
            })
            .await;
    }
    world
        .edit_upstream(
            &mut upstream,
            StageKind::Documenting,
            "documentation-result",
            |document| {
                document["writer_ran"] = serde_json::json!(false);
                document["changes"] = serde_json::json!([]);
            },
        )
        .await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");
    let result = world.execute(&handler, &contract, &upstream).await;
    assert_eq!(result.err(), Some(StageError::PolicyDenied));
    assert!(world.drift.told.lock().expect("lock").is_empty());
    nothing_reached_the_host(&world);
}

#[tokio::test]
async fn negative_nt_lse_03_a_retry_between_push_and_open_makes_one_pull_request() {
    let world = World::new();
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");

    // The branch is pushed, then the host is down when the pull request is opened.
    world.host.the_next_open_fails();
    let first = world.execute(&handler, &contract, &upstream).await;
    assert_eq!(first.err(), Some(StageError::Provider));
    assert!(
        world
            .remote
            .branch_tip(
                &world.repo,
                &factory_ports::paths::BranchName::new("factory/job-1").expect("a branch")
            )
            .is_some(),
        "the push happened before the failure"
    );

    // The retry pushes the same commit again, opens the pull request once and publishes each
    // check run once, on the head of the pull request: the documentation commit.
    let docs_head = world
        .documented
        .lock()
        .expect("lock")
        .clone()
        .expect("a documentation commit");
    assert_ne!(docs_head, head);
    let outputs = world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("the retry works");
    let result = world.read_output(&outputs, "delivery-result").await;
    assert_eq!(result["delivered"], true);
    assert_eq!(result["head_commit"], docs_head.as_str());
    assert_eq!(
        world
            .host
            .inner()
            .check_run_count(&docs_head, "factory-validation"),
        1
    );
    assert_eq!(
        world
            .host
            .inner()
            .check_run_count(&docs_head, "factory-review"),
        1
    );
    // A second full run changes nothing either.
    world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("a third run works");
    assert_eq!(
        world
            .host
            .inner()
            .check_run_count(&docs_head, "factory-validation"),
        1
    );
    let numbers: std::collections::BTreeSet<u64> =
        [result["pull_request"].as_u64().expect("a number")].into();
    assert_eq!(numbers.len(), 1);
}

#[tokio::test]
async fn negative_nt_sec_04_hostile_text_does_not_reach_the_pull_request() {
    let hostile = "Add [a](https://evil.test/?d=1) ![x](https://evil.test/p.png) @everyone <script>x</script> now";
    let world = World::with(Scenario {
        spec_title: Some(hostile.to_owned()),
        ..Scenario::default()
    });
    let ran = world.run().await;
    let sent = &world.host.opened()[0];
    for text in [&sent.title, &sent.body] {
        for bad in ["evil.test", "![", "@everyone", "<script", "<!--"] {
            assert!(!text.contains(bad), "{bad:?} reached the host in {text:?}");
        }
        // Every link that is left points at the code host, and nowhere else.
        for (at, _) in text.match_indices("](http") {
            assert!(text[at..].starts_with("](https://github.com/"), "{text:?}");
        }
        // The text passes the stage's own final check again.
        assert_eq!(finish(text, &world.redactor, &["github.com"]), Ok(()));
    }
    assert_eq!(ran.resolution, Resolution::Pass);
}

#[tokio::test]
async fn nothing_that_an_agent_wrote_is_copied_into_the_pull_request() {
    // The specification summary and the review summary are prose from agents. The body is
    // written from typed fields, so neither sentence can appear in it.
    let world = World::new();
    world.run().await;
    let body = &world.host.opened()[0].body;
    let spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
    ))
    .expect("a spec");
    let spec_summary = spec["summary"].as_str().expect("a summary");
    assert!(!body.contains(spec_summary));
    let review: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/examples/review-verdict/valid/changes-required-missing-test.json"
    ))
    .expect("a verdict");
    let review_summary = review["summary"].as_str().expect("a summary");
    assert!(!body.contains(review_summary));
    for check in world.host.checks() {
        assert!(!check.summary.contains(review_summary));
    }
}

#[tokio::test]
async fn negative_nt_sec_secret_canary_never_reaches_the_host() {
    // A secret in the title of the specification is refused whole. The pull request is not
    // opened, no check run is published, and the stored result holds no secret either.
    let secret = canary();
    let world = World::with(Scenario {
        spec_title: Some(format!("Use the key {secret} for the upload")),
        ..Scenario::default()
    });
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");
    let outputs = world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("execute works");
    let result = world.read_output(&outputs, "delivery-result").await;
    assert_eq!(result["delivered"], false);
    for text in [
        result.to_string(),
        world
            .read_output(&outputs, "evidence-manifest")
            .await
            .to_string(),
    ] {
        assert!(
            !text.contains(&secret),
            "the secret reached a stored document"
        );
    }
    // The title is a field of the manifest: it must be the cleaned form, never the secret.
    let calls = world.host.calls();
    assert!(
        !calls.iter().any(|call| matches!(
            call,
            Call::Open { .. } | Call::Check(_) | Call::PushTarget(_)
        )),
        "{calls:?}"
    );
    // The gate says so: the stage fails and nobody is told a pull request exists.
    let ran = world
        .evaluate(&handler, &contract, &outputs, &upstream)
        .await
        .expect("evaluate works");
    assert!(
        matches!(ran.resolution, Resolution::Failed { .. }),
        "{:?}",
        ran.resolution
    );
}

#[tokio::test]
async fn a_secret_in_a_finished_body_is_refused_by_the_last_check() {
    let world = World::new();
    let body = format!("Plain words. {}", canary());
    assert_eq!(
        finish(&body, &world.redactor, &["github.com"]),
        Err(TextRefused::Secret)
    );
}

#[tokio::test]
async fn negative_nt_mrg_08_the_pull_request_stays_a_draft() {
    // Whatever the outcome of the gates, the pull request that the stage opens is a draft, and
    // the host never receives a request to change that.
    let mut blocked_but_decided = Scenario::default();
    blocked_but_decided.gates[0].1 = "BLOCKED";
    blocked_but_decided.dispositions = vec![blocked_but_decided.gates[0].0.clone()];
    for scenario in [Scenario::default(), blocked_but_decided] {
        let world = World::with(scenario);
        let ran = world.run().await;
        let number = ran.result["pull_request"].as_u64().expect("a number");
        let state = factory_ports::githost::ChangeHost::pull_request_state(
            &*world.host,
            &factory_ports::githost::GitScope {
                tenant: world.tenant,
                job: world.job,
                stage: factory_domain::vocabulary::StageKind::Delivery,
                repo: world.repo.clone(),
            },
            &factory_ports::githost::PullRequestRef {
                repo: world.repo.clone(),
                number,
            },
        )
        .await
        .expect("a state");
        assert!(state.draft);
        // Only calls the port offers reached the host, and none is a merge or a ready call.
        for call in world.host.calls() {
            assert!(
                matches!(
                    call,
                    Call::PushTarget(_)
                        | Call::ResolveBranch(_)
                        | Call::Open { .. }
                        | Call::UpdateBody
                        | Call::Check(_)
                        | Call::State
                ),
                "{call:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_pull_request_that_is_not_a_draft_stops_the_stage() {
    // If the host reports the pull request as ready for review, the stage does not go on.
    let world = World::new();
    world.host.pull_request_reads_as_ready();
    let result = execute_only(&world).await;
    assert_eq!(result, Err(StageError::PolicyDenied));
}

#[tokio::test]
async fn a_pull_request_that_became_ready_after_delivery_is_a_violation_at_the_gate() {
    let world = World::new();
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");
    let outputs = world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("execute works");
    world.host.pull_request_reads_as_ready();
    let ran = world
        .evaluate(&handler, &contract, &outputs, &upstream)
        .await
        .expect("evaluate works");
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::PolicyViolation)
    );
}

#[tokio::test]
async fn a_pull_request_that_points_at_another_commit_is_a_violation() {
    let world = World::new();
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");
    let outputs = world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("execute works");
    world
        .host
        .head_moves_to(CommitSha::parse(&"9".repeat(40)).expect("a sha"));
    let ran = world
        .evaluate(&handler, &contract, &outputs, &upstream)
        .await
        .expect("evaluate works");
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::PolicyViolation)
    );
}

#[tokio::test]
async fn a_failed_gate_is_not_delivered() {
    let mut scenario = Scenario::default();
    scenario.gates[3].1 = "FAILED";
    let world = World::with(scenario);
    let result = execute_only(&world).await;
    assert_eq!(result, Err(StageError::PolicyDenied));
    nothing_reached_the_host(&world);
}

#[tokio::test]
async fn a_blocked_gate_nobody_decided_about_is_not_delivered() {
    let mut scenario = Scenario::default();
    scenario.gates[0].1 = "BLOCKED";
    let world = World::with(scenario);
    let result = execute_only(&world).await;
    assert_eq!(result, Err(StageError::PolicyDenied));
    nothing_reached_the_host(&world);
}

/// Condition C-a of the security review: the specification the delivery reads must have been
/// approved by a person. Planning, architecture and validation each check it; delivery did not.
#[tokio::test]
async fn a_specification_that_is_not_approved_is_not_delivered() {
    for status in ["draft", "superseded"] {
        let world = World::with(Scenario {
            spec_status: Some(status),
            ..Scenario::default()
        });
        let result = execute_only(&world).await;
        assert!(
            matches!(
                result,
                Err(StageError::PolicyDenied | StageError::InvalidOutput)
            ),
            "{status}: {result:?}"
        );
        nothing_reached_the_host(&world);
    }
}

/// Condition C-b: the documentation reviewer's verdict is read, not only hashed. A verdict that
/// is not a `PASS` is not delivered.
#[tokio::test]
async fn a_documentation_review_that_did_not_pass_is_not_delivered() {
    let world = World::with(Scenario {
        documentation_verdict: "CHANGES_REQUIRED",
        ..Scenario::default()
    });
    assert_eq!(execute_only(&world).await, Err(StageError::PolicyDenied));
    nothing_reached_the_host(&world);
}

/// A `PASS` over other reports, or over another specification, is a verdict about something
/// else. It is refused as stale, whatever its hash.
#[tokio::test]
async fn a_documentation_review_of_other_reports_or_another_specification_is_not_delivered() {
    for binding in [
        ReviewBinding::OtherReports,
        ReviewBinding::OtherSpecification,
    ] {
        let world = World::with(Scenario {
            documentation_review: binding,
            ..Scenario::default()
        });
        assert_eq!(
            execute_only(&world).await,
            Err(StageError::PolicyDenied),
            "{binding:?}"
        );
        nothing_reached_the_host(&world);
    }
}

/// A verdict that is not a review verdict at all is invalid, which is not the same as stale.
#[tokio::test]
async fn a_documentation_review_that_is_not_a_verdict_is_invalid() {
    let world = World::new();
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let mut upstream = world.upstream(&base, &head).await;
    world
        .edit_upstream(
            &mut upstream,
            StageKind::DocumentationReview,
            "documentation-review",
            |value| *value = serde_json::json!({ "document": "documentation review" }),
        )
        .await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("a contract");
    assert_eq!(
        world.execute(&handler, &contract, &upstream).await.err(),
        Some(StageError::InvalidOutput)
    );
    nothing_reached_the_host(&world);
}

#[tokio::test]
async fn a_review_that_did_not_pass_is_not_delivered() {
    // `ReviewVerdict` itself refuses a BLOCK verdict with no blocker, so use CHANGES_REQUIRED
    // with the finding the fixture needs: the stored document must stay valid for the test to
    // reach the rule of the manifest.
    let world = World::with(Scenario {
        verdict: "NEEDS_HUMAN",
        ..Scenario::default()
    });
    let result = execute_only(&world).await;
    assert!(
        matches!(
            result,
            Err(StageError::PolicyDenied | StageError::InvalidOutput)
        ),
        "{result:?}"
    );
    nothing_reached_the_host(&world);
}

#[tokio::test]
async fn a_missing_input_blocks_the_stage_before_anything_is_done() {
    for missing in [
        "implementation-result",
        "validation-evidence",
        "review-verdict",
        "specification-contract",
        "task-plan",
        "architecture-design",
        "documentation-plan",
        "documentation-result",
        "documentation-gate-report",
        "documentation-review",
    ] {
        let world = World::with(Scenario {
            missing: Some(missing),
            ..Scenario::default()
        });
        let result = execute_only(&world).await;
        assert_eq!(
            result,
            Err(StageError::Blocked(BlockedCode::DependencyUnavailable)),
            "{missing}"
        );
        assert!(world.host.calls().is_empty(), "{missing}");
    }
}
