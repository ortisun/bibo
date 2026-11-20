//! What a person reads before they decide, through the real pipeline: the specification draft they
//! approve, the gate reports of the evidence, and one report downloaded and checked against its hash.
//!
//! The rig is the one of the full run (`full/mod.rs`): the real engine on PostgreSQL, the real API
//! server, the real handlers of all thirteen stages. Scripted, and labelled in the rig: the agents,
//! the sandbox, the code host. The values the person reads are not scripted: the commit and the
//! ledger head are compared with what the worker's own seams read, and the reports with the
//! documents the engine stored.

#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/validation/cargo.rs"]
mod cargo;
mod full;
#[allow(dead_code)]
mod playbook;
mod support;

use factory_domain::ids::JobId;
use factory_domain::state::StageRunStatus;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::StageKind;
use full::{Options, Rig};
use serde_json::{Value, json};
use support::{Env, Req};

struct Journey {
    rig: Rig,
    job: JobId,
    approver: String,
}

async fn begin() -> Journey {
    let _ = support::captured();
    let env = Env::start().await;
    let requester = full::token_from_file(&env, "requester", &env.a.requester.token.clone());
    let approver = full::token_from_file(&env, "approver", &env.a.approver.token.clone());
    let rig = Rig::start(env, Options::default()).await;
    full::label_the_issue(&rig.env).await;
    let job = full::job_of(&rig.env, &requester).await;
    Journey { rig, job, approver }
}

fn get(journey: &Journey, token: &str, path: &str) -> Req {
    let _ = journey;
    Req::get(path).bearer(token)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_evidence_a_person_reads_before_deciding() {
    let journey = begin().await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    let rig = &journey.rig;

    // 1. The stage asks a person to approve its draft.
    let view = rig
        .drive(Some(journey.job), 120, |view| {
            full::status_of(view, StageKind::Specification) == Some(StageRunStatus::WaitingForHuman)
                || full::stopped(view)
        })
        .await
        .expect("a view of the job");
    assert_eq!(
        full::status_of(&view, StageKind::Specification),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    let run = full::stage_run_of(&view, StageKind::Specification);

    // 2. The endpoint gives the commit that holds the draft and the head of the ledger: the two
    // values an approval is bound to, and the ones the worker compares with.
    let path = format!("/v1/jobs/{}/specification-draft", journey.job);
    let reply = rig.env.send(get(&journey, &journey.approver, &path)).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let body = reply.json();
    let commit = rig.spec_draft_commit(journey.job, run).await;
    let head = rig
        .ledger_head(journey.job, StageKind::Specification, run)
        .await;
    assert_eq!(body["stage_run_id"], run.as_text());
    assert_eq!(body["status"], "WAITING_FOR_HUMAN");
    assert_eq!(body["draft"]["commit"], commit);
    assert_eq!(body["ledger_head"]["hash"], head.as_str());
    assert_eq!(body["approval"]["approvable"], true);
    assert_eq!(body["approval"]["window_hours"], 72);
    assert_eq!(body["approval"]["head"], commit);
    assert_eq!(body["approval"]["evidence"], head.as_str());
    // The run waits, so it takes an answer; the questions the stage asked are listed (this scripted
    // stage asks for an approval and has no question).
    assert_eq!(body["answerable"], true);
    assert!(body["questions"].is_array(), "{body}");
    let draft_hash = body["draft"]["artifact_sha256"]
        .as_str()
        .expect("the hash of the draft document")
        .to_owned();
    // The draft document itself is untrusted text, and is downloaded as such.
    let download = rig
        .env
        .send(get(
            &journey,
            &journey.approver,
            &format!(
                "/v1/jobs/{}/artifacts/{}",
                journey.job,
                draft_hash.trim_start_matches("sha256:")
            ),
        ))
        .await;
    assert_eq!(download.status, 200, "{}", download.text());
    assert_eq!(
        download.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(
        Sha256Digest::of(&download.body).as_str(),
        draft_hash,
        "the bytes are the document the hash names"
    );

    // 3. The same read, refused for the callers that may not have it.
    let outsider = rig
        .env
        .send(get(&journey, &rig.env.a.outsider.token, &path))
        .await;
    assert_eq!(outsider.status, 403);
    let other_tenant = rig
        .env
        .send(get(&journey, &rig.env.b.approver.token, &path))
        .await;
    assert_eq!(other_tenant.status, 404);
    let anonymous = rig.env.send(Req::get(&path)).await;
    assert_eq!(anonymous.status, 401);
    let bad = rig
        .env
        .send(get(
            &journey,
            &journey.approver,
            &format!("{path}?stage_run_id=not-an-id"),
        ))
        .await;
    assert_eq!(bad.status, 400, "{}", bad.text());
    let elsewhere = rig
        .env
        .send(get(
            &journey,
            &journey.approver,
            &format!(
                "/v1/jobs/{}/specification-draft",
                JobId::from_uuid(uuid::Uuid::from_u128(5))
            ),
        ))
        .await;
    assert_eq!(elsewhere.status, 404);

    // 4. The person approves what they read, with the values the endpoint gave.
    let decision = full::decide(
        &rig.env,
        &journey.approver,
        journey.job,
        "approve-what-i-read",
        json!({
            "verb": "approve",
            "stage_run_id": run.as_text(),
            "head": body["approval"]["head"],
            "evidence": body["approval"]["evidence"],
            "reason": "The specification says what the issue asked for.",
        }),
    )
    .await;
    assert_eq!(decision.status, 202, "{}", decision.text());
    let view = rig
        .drive(Some(journey.job), 240, |view| {
            full::status_of(view, StageKind::Approval) == Some(StageRunStatus::WaitingForHuman)
                || full::stopped(view)
        })
        .await
        .expect("a view of the job");
    assert_eq!(
        full::status_of(&view, StageKind::Approval),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    let after = rig
        .env
        .send(get(&journey, &journey.approver, &path))
        .await
        .json();
    assert_eq!(
        after["approval"]["approvable"], false,
        "the draft is not waiting for a person any more: {after}"
    );

    // 5. The gate reports of the evidence: the gate, the outcome, the code and the hash.
    let reports_path = format!("/v1/jobs/{}/gate-reports", journey.job);
    let reply = rig
        .env
        .send(get(&journey, &journey.approver, &reports_path))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let listing = reply.json();
    let reports = listing["reports"].as_array().expect("a list of reports");
    assert!(reports.len() >= 10, "{listing}");
    assert_eq!(listing["truncated"], false);
    for report in reports {
        assert_eq!(report["readable"], true, "{report}");
        assert!(
            report["report_sha256"]
                .as_str()
                .is_some_and(|hash| Sha256Digest::parse(hash).is_ok()),
            "{report}"
        );
    }
    let format = reports
        .iter()
        .find(|report| report["gate"] == "format" && report["stage"] == "VALIDATION")
        .expect("the format gate of the validation stage reported");
    assert_eq!(format["outcome"], "PASSED");
    assert_eq!(format["code"], Value::Null);

    // 6. One report, downloaded: the bytes are the document its hash names, and it says the same.
    let hash = format["report_sha256"].as_str().expect("a hash");
    let download = rig
        .env
        .send(get(
            &journey,
            &journey.approver,
            &format!(
                "/v1/jobs/{}/artifacts/{}",
                journey.job,
                hash.trim_start_matches("sha256:")
            ),
        ))
        .await;
    assert_eq!(download.status, 200, "{}", download.text());
    assert_eq!(Sha256Digest::of(&download.body).as_str(), hash);
    let document: Value = serde_json::from_slice(&download.body).expect("the report is JSON");
    assert_eq!(document["metadata"]["gate_id"], "format");
    assert_eq!(document["outcome"], "PASSED");

    // 7. The listing is refused to the callers that may not read, like the draft.
    for (token, status) in [
        (&rig.env.a.outsider.token, 403),
        (&rig.env.b.approver.token, 404),
    ] {
        let refused = rig.env.send(get(&journey, token, &reports_path)).await;
        assert_eq!(refused.status, status, "{}", refused.text());
    }
    rig.finish();
}
