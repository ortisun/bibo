//! A job in the rig of the full run, with the two people who decide, and the loop that drives it.
//!
//! The `Journey` of `full_run.rs` is private to that file, and the rules for this work package say
//! not to edit it. This is the part of it the scenarios need, and a drive loop that can also kill
//! a worker. If `full_run.rs` ever shares its `Journey`, this file goes away.

use std::time::{Duration, Instant};

use factory_domain::ids::JobId;
use factory_domain::state::{JobStatus, StageRunStatus, Status as _};
use factory_domain::vocabulary::StageKind;
use factory_workflow::engine::JobView;
use serde_json::{Value, json};

use crate::full::{self, Options, Rig};
use crate::support::{self, Env, Req};

/// A job that has been labelled, with the tokens of the two people who will decide.
pub struct Journey {
    pub rig: Rig,
    pub job: JobId,
    pub requester: String,
    pub approver: String,
}

/// The issue a scenario files, when it is not the rig's default.
pub struct Filed {
    pub title: String,
    pub body: String,
}

/// Starts the rig, files the issue (the rig's default, or `filed`), labels it through the signed
/// webhook and returns the job the requester sees.
pub async fn begin(options: Options, filed: Option<Filed>) -> Journey {
    let env = Env::start().await;
    let requester = full::token_from_file(&env, "requester", &env.a.requester.token.clone());
    let approver = full::token_from_file(&env, "approver", &env.a.approver.token.clone());
    let rig = Rig::start(env, options).await;
    if let Some(filed) = filed {
        refile(&rig, &filed).await;
    }
    full::label_the_issue(&rig.env).await;
    let job = full::job_of(&rig.env, &requester).await;
    Journey {
        rig,
        job,
        requester,
        approver,
    }
}

/// The signed-webhook body that says a person labelled the issue. It carries no text.
pub fn label_body(env: &Env, sender_id: u64, login: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "action": "labeled",
        "installation": {"id": env.a.installation},
        "repository": {"id": env.a.github_repository, "full_name": env.a.full_name},
        "sender": {"id": sender_id, "login": login, "type": "User"},
        "issue": {"number": full::ISSUE, "node_id": "I_12", "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": full::LABEL},
    }))
    .expect("json")
}

/// A rig where the issue was filed and labelled by a person who is not on the allowlist, with the
/// tokens of the requester and the approver. No job is looked for: the API may make none.
pub async fn file_as_outsider(options: Options) -> (Rig, String, String) {
    let env = Env::start().await;
    let requester = full::token_from_file(&env, "requester", &env.a.requester.token.clone());
    let approver = full::token_from_file(&env, "approver", &env.a.approver.token.clone());
    let rig = Rig::start(env, options).await;
    let reference = factory_ports::githost::IssueRef {
        repo: rig.repo.clone(),
        number: full::ISSUE,
    };
    let now = factory_domain::values::Timestamp::parse("2026-10-28T10:00:00Z").expect("a time");
    let outsider = factory_ports::githost::GithubActor {
        id: rig.env.a.outsider.github_id,
        login: factory_ports::githost::ActorLogin::new("outsider-one").expect("a login"),
    };
    rig.issues.put_issue(factory_ports::githost::Issue {
        reference,
        title: "Add a --json flag".to_owned(),
        body: "Please add a --json flag to the word count tool so other programs can read the counts."
            .to_owned(),
        author: outsider.clone(),
        labels: vec![full::LABEL.to_owned()],
        updated_at: now,
        fetched_at: now,
    });
    let body = label_body(&rig.env, rig.env.a.outsider.github_id, "outsider-one");
    let reply = rig
        .env
        .send(rig.env.delivery("issues", "0190a3b2-7c4d-4e5f-8a6b-0000000000e6", &body))
        .await;
    assert!(reply.status < 300, "{} {}", reply.status, reply.text());
    (rig, requester, approver)
}

/// Replaces the text of the issue the code host holds. The webhook carries no text, so this is
/// what the worker fetches.
async fn refile(rig: &Rig, filed: &Filed) {
    let reference = factory_ports::githost::IssueRef {
        repo: rig.repo.clone(),
        number: full::ISSUE,
    };
    let now = factory_domain::values::Timestamp::parse("2026-10-28T10:00:00Z").expect("a time");
    let author = factory_ports::githost::GithubActor {
        id: rig.env.a.requester.github_id,
        login: factory_ports::githost::ActorLogin::new("requester-one").expect("a login"),
    };
    rig.issues.put_issue(factory_ports::githost::Issue {
        reference,
        title: filed.title.clone(),
        body: filed.body.clone(),
        author,
        labels: vec![full::LABEL.to_owned()],
        updated_at: now,
        fetched_at: now,
    });
}

impl Journey {
    pub async fn until(&self, seconds: u64, done: impl Fn(&JobView) -> bool) -> JobView {
        self.rig
            .drive(Some(self.job), seconds, done)
            .await
            .expect("a view of the job")
    }

    /// Runs until the specification stage asks the person, or the job stops.
    pub async fn to_the_specification_question(&self) -> JobView {
        self.until(120, |view| {
            full::status_of(view, StageKind::Specification) == Some(StageRunStatus::WaitingForHuman)
                || full::stopped(view)
        })
        .await
    }

    /// The approver approves the specification draft, through the API.
    pub async fn approve_the_specification(&self, view: &JobView, key: &str) -> support::Reply {
        let run = full::stage_run_of(view, StageKind::Specification);
        let head = self.rig.spec_draft_commit(self.job, run).await;
        let evidence = self
            .rig
            .ledger_head(self.job, StageKind::Specification, run)
            .await;
        full::decide(
            &self.rig.env,
            &self.approver,
            self.job,
            key,
            json!({
                "verb": "approve",
                "stage_run_id": run.as_text(),
                "head": head,
                "evidence": evidence.as_str(),
                "reason": "The specification says what the issue asked for.",
            }),
        )
        .await
    }

    /// Runs until the approval stage asks the person, or the job stops.
    pub async fn to_the_pull_request_question(&self) -> JobView {
        self.until(240, |view| {
            full::status_of(view, StageKind::Approval) == Some(StageRunStatus::WaitingForHuman)
                || (full::stopped(view)
                    && full::status_of(view, StageKind::Specification)
                        != Some(StageRunStatus::WaitingForHuman))
        })
        .await
    }

    /// The approver approves the pull request, through the API, naming the head they saw.
    pub async fn approve_the_pull_request(&self, view: &JobView, key: &str) -> support::Reply {
        self.decide_on_the_pull_request(view, key, &self.approver, "approve")
            .await
    }

    /// Anyone decides on the pull request with the token given. Used by the hostile attempts.
    pub async fn decide_on_the_pull_request(
        &self,
        view: &JobView,
        key: &str,
        token: &str,
        verb: &str,
    ) -> support::Reply {
        use factory_workflow::stages::approval::ApprovalSources as _;
        let run = full::stage_run_of(view, StageKind::Approval);
        let request = self
            .rig
            .approvals
            .request(self.rig.tenant, run)
            .await
            .expect("the approval stage stored its request");
        let evidence = self
            .rig
            .ledger_head(self.job, StageKind::Approval, run)
            .await;
        full::decide(
            &self.rig.env,
            token,
            self.job,
            key,
            json!({
                "verb": verb,
                "stage_run_id": run.as_text(),
                "head": request.pr_head.as_str(),
                "evidence": evidence.as_str(),
                "reason": "The change does what the issue asked.",
            }),
        )
        .await
    }

    /// The honest journey to the end: approve the specification, then the pull request.
    pub async fn whole_job(&self) -> JobView {
        let view = self.to_the_specification_question().await;
        assert_eq!(
            full::status_of(&view, StageKind::Specification),
            Some(StageRunStatus::WaitingForHuman),
            "{view:#?}"
        );
        let reply = self.approve_the_specification(&view, "approve-specification-1").await;
        assert_eq!(reply.status, 202, "{}", reply.text());
        let view = self.to_the_pull_request_question().await;
        assert_eq!(
            full::status_of(&view, StageKind::Approval),
            Some(StageRunStatus::WaitingForHuman),
            "{view:#?}"
        );
        let reply = self.approve_the_pull_request(&view, "approve-pull-request-1").await;
        assert_eq!(reply.status, 202, "{}", reply.text());
        let view = self
            .until(120, |view| {
                view.status == JobStatus::Completed || view.status.is_terminal()
            })
            .await;
        assert_eq!(view.status, JobStatus::Completed, "{view:#?}");
        view
    }

    /// The timings the rig measured, as JSON.
    pub fn attempt_timings(&self) -> Vec<Value> {
        self.rig
            .timings
            .lock()
            .expect("the lock is never poisoned")
            .iter()
            .map(|timed| {
                json!({
                    "stage": timed.kind.as_str(),
                    "outcome": timed.outcome,
                    "milliseconds": u64::try_from(timed.took.as_millis()).unwrap_or(u64::MAX),
                })
            })
            .collect()
    }
}

/// The drive loop of `Rig::drive`, with one more thing it can do: a worker that dies.
///
/// For every stage kind in `kill_once`, the first attempt that is claimed is never run. The worker
/// has taken the lease and then is gone: no heartbeat, no result, nothing written. The passing of
/// time is the only part that is stood in for: the lease is moved into the past in the database,
/// as the superuser, instead of waiting out its 30 seconds, and the engine's own sweep then finds
/// an expired lease and makes the attempt `LEASE_LOST`, as it does for a real dead worker.
pub async fn drive_with_kills(
    rig: &Rig,
    job: JobId,
    seconds: u64,
    kill_once: &mut std::collections::BTreeSet<StageKind>,
    killed: &mut Vec<(StageKind, String)>,
    done: impl Fn(&JobView) -> bool,
) -> Option<JobView> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let worker = factory_ports::store::WorkerId::new("worker-e2e-kill").expect("a worker id");
    loop {
        let _ = rig.requests.refresh(&[rig.tenant]).await;
        rig.preflight.pass(rig.tenant).await;
        rig.hook.pass(rig.tenant).await;
        let _ = rig.engine.sweep().await;
        let claimed = rig.engine.claim_next(&worker).await.expect("a claim");
        for attempt in claimed.started {
            if kill_once.remove(&attempt.kind) {
                killed.push((attempt.kind, attempt.attempt.to_string()));
                rig.env
                    .db
                    .run(&format!(
                        "UPDATE attempts SET lease_expires_at = now() - interval '1 minute', version = version + 1 WHERE id = '{}'",
                        attempt.attempt.as_uuid()
                    ))
                    .await;
                continue;
            }
            let started = Instant::now();
            rig.jobs.enter(attempt.job, attempt.tenant);
            rig.jobs.enter_attempt(attempt.attempt, attempt.tenant);
            let outcome = {
                let attempt_run = rig.engine.run_attempt(&attempt);
                tokio::pin!(attempt_run);
                loop {
                    tokio::select! {
                        outcome = &mut attempt_run => break outcome,
                        _ = rig.pump.serve_next(&rig.engine) => {}
                    }
                }
            };
            rig.jobs.leave(attempt.job);
            rig.jobs.leave_attempt(attempt.attempt);
            rig.timings
                .lock()
                .expect("the lock is never poisoned")
                .push(full::Timed {
                    kind: attempt.kind,
                    outcome: format!("{outcome:?}"),
                    took: started.elapsed(),
                });
        }
        if let Ok(view) = rig.engine.job_view(rig.tenant, job).await
            && done(&view)
        {
            return Some(view);
        }
        if tokio::time::Instant::now() > deadline {
            return rig.engine.job_view(rig.tenant, job).await.ok();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// One request as a person's client would send it.
pub async fn get(rig: &Rig, token: &str, path: &str) -> support::Reply {
    rig.env.send(Req::get(path).bearer(token)).await
}
