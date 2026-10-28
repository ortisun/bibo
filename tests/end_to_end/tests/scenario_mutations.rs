//! Every scenario check fails on evidence that has been deliberately corrupted.
//!
//! The honest evidence comes from the scripted wiring (the real engine over the fakes). Each
//! mutation breaks one fact that the check exists to protect. Before a mutation is applied the
//! check must pass on the honest evidence, so a check that always fails cannot hide here.

use factory_e2e::evidence::RunEvidence;
use factory_e2e::runner::Wiring;
use factory_e2e::scenarios;
use factory_e2e::scripted::Scripted;
use factory_e2e::{Env, repository_root, scenario_checks};
use serde_json::json;

struct M {
    name: &'static str,
    check: &'static str,
    expect: &'static str,
    apply: fn(&mut RunEvidence),
}

fn honest(scenario: &str) -> (RunEvidence, Env) {
    let root = repository_root();
    let env = Env::load(&root).expect("env");
    let mut wiring = Scripted::new(&root).expect("wiring");
    let evidence = wiring
        .run(scenarios::by_id(scenario).expect("scenario"))
        .expect("the scenario runs");
    (evidence, env)
}

fn judge(scenario: &str, mutations: &[M]) {
    let (evidence, env) = honest(scenario);
    let mut problems = Vec::new();
    for m in mutations {
        let check = scenario_checks::by_id(m.check).expect("a scenario check");
        let before = check.apply(&evidence, &env);
        if !before.pass {
            problems.push(format!(
                "{}: the check fails on honest evidence: {}",
                m.name, before.reason
            ));
            continue;
        }
        let mut mutated = evidence.clone();
        (m.apply)(&mut mutated);
        if mutated == evidence {
            problems.push(format!("{}: the mutation changed nothing", m.name));
            continue;
        }
        let after = check.apply(&mutated, &env);
        if after.pass {
            problems.push(format!("{}: {} still passes", m.name, m.check));
        } else if !after.reason.contains(m.expect) {
            problems.push(format!(
                "{}: expected '{}', got '{}'",
                m.name, m.expect, after.reason
            ));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

fn started_run(kind: &str) -> factory_e2e::evidence::StageRunRecord {
    factory_e2e::evidence::StageRunRecord {
        id: "r".into(),
        kind: kind.into(),
        status: "RUNNING".into(),
        attempts: vec![factory_e2e::evidence::AttemptRecord {
            id: "a".into(),
            status: "RUNNING".into(),
        }],
        rework_round: 0,
    }
}

fn run_mut<'a>(
    ev: &'a mut RunEvidence,
    kind: &str,
) -> &'a mut factory_e2e::evidence::StageRunRecord {
    ev.stage_runs
        .iter_mut()
        .rev()
        .find(|r| r.kind == kind)
        .expect("a run")
}

#[test]
fn e3_checks_fail_on_corrupted_evidence() {
    judge(
        "E3",
        &[
            M {
                name: "one rework round",
                check: "E3.rework-cap-then-human",
                expect: "not 2",
                apply: |ev| {
                    ev.facts.insert("code_rework_rounds".into(), json!(1));
                },
            },
            M {
                name: "delivery started",
                check: "E3.rework-cap-then-human",
                expect: "DELIVERY started",
                apply: |ev| {
                    let r = run_mut(ev, "DELIVERY");
                    r.attempts.push(factory_e2e::evidence::AttemptRecord {
                        id: "a".into(),
                        status: "SUCCEEDED".into(),
                    });
                },
            },
            M {
                name: "a pull request exists",
                check: "E3.rework-cap-then-human",
                expect: "a pull request exists",
                apply: |ev| {
                    ev.github
                        .pull_requests
                        .push(factory_e2e::evidence::PullRequest {
                            number: 9,
                            draft: true,
                            merged: false,
                            state: "open".into(),
                            head_branch: "factory/x".into(),
                            head_sha: "x".into(),
                            title: "t".into(),
                            body: "b".into(),
                        });
                },
            },
            M {
                name: "job not waiting",
                check: "E3.rework-cap-then-human",
                expect: "not WAITING_FOR_HUMAN",
                apply: |ev| ev.job.status = "ACTIVE".into(),
            },
            M {
                name: "no failed gate report",
                check: "E3.rework-cap-then-human",
                expect: "no failed gate report",
                apply: |ev| ev.contracts.gate_reports.clear(),
            },
            M {
                name: "a third implementation run is missing",
                check: "E3.rework-cap-then-human",
                expect: "ran 2 times",
                apply: |ev| {
                    let at = ev
                        .stage_runs
                        .iter()
                        .rposition(|r| r.kind == "IMPLEMENTATION")
                        .expect("run");
                    ev.stage_runs.remove(at);
                },
            },
            M {
                name: "a ledger entry was edited",
                check: "X.ledger-chain",
                expect: "does not verify",
                apply: |ev| ev.ledger[1]["claim"]["statement"] = json!("edited afterwards"),
            },
            M {
                name: "the ledger is empty",
                check: "X.ledger-chain",
                expect: "ledger is empty",
                apply: |ev| ev.ledger.clear(),
            },
        ],
    );
}

#[test]
fn e4_checks_fail_on_corrupted_evidence() {
    judge(
        "E4",
        &[
            M {
                name: "an attempt was performed",
                check: "E4.no-effect",
                expect: "was not denied",
                apply: |ev| {
                    ev.hostile.as_mut().expect("h").attempts[0].outcome = "performed".into()
                },
            },
            M {
                name: "a canary leaked",
                check: "E4.no-effect",
                expect: "leaked into",
                apply: |ev| {
                    ev.hostile
                        .as_mut()
                        .expect("h")
                        .canary_leaks
                        .push("pull_request_text:pull request".into())
                },
            },
            M {
                name: "no canary planted",
                check: "E4.no-effect",
                expect: "no canary was planted",
                apply: |ev| ev.hostile.as_mut().expect("h").canaries_planted = 0,
            },
            M {
                name: "no hostile record",
                check: "E4.no-effect",
                expect: "no record of the hostile text",
                apply: |ev| ev.hostile = None,
            },
            M {
                name: "no attempts",
                check: "E4.no-effect",
                expect: "attempted nothing",
                apply: |ev| ev.hostile.as_mut().expect("h").attempts.clear(),
            },
            M {
                name: "a workflow file changed",
                check: "E4.no-effect",
                expect: "protected path",
                apply: |ev| {
                    ev.github
                        .changed_paths
                        .push(".github/workflows/ci.yml".into())
                },
            },
            M {
                name: "the denial is not in the audit stream",
                check: "E4.no-effect",
                expect: "denied tool calls",
                apply: |ev| {
                    ev.audit
                        .retain(|r| !r.action.starts_with("tool_call_denied"))
                },
            },
            M {
                name: "the pull request was merged",
                check: "E4.no-effect",
                expect: "was merged",
                apply: |ev| ev.github.pull_requests[0].merged = true,
            },
            M {
                name: "the base branch moved",
                check: "E4.no-effect",
                expect: "base branch moved",
                apply: |ev| ev.github.base_sha_after = "moved".into(),
            },
            M {
                name: "a demanded action was not recorded",
                check: "E4.no-effect",
                expect: "demanded actions",
                apply: |ev| {
                    ev.hostile.as_mut().expect("h").demanded.pop();
                },
            },
            M {
                name: "the original was changed",
                check: "X.original-kept",
                expect: "not the text as filed",
                apply: |ev| {
                    ev.facts.insert("stored_original_sha256".into(), json!("sha256:0000000000000000000000000000000000000000000000000000000000000000"));
                },
            },
            M {
                name: "the normalized request replaced the original",
                check: "X.original-kept",
                expect: "not kept apart",
                apply: |ev| {
                    let h = ev.facts["stored_original_sha256"].clone();
                    ev.facts.insert("normalized_request_sha256".into(), h);
                },
            },
        ],
    );
}

#[test]
fn e5_checks_fail_on_corrupted_evidence() {
    judge(
        "E5",
        &[
            M {
                name: "a stage never lost its lease",
                check: "E5.every-boundary",
                expect: "first must be a lost lease",
                apply: |ev| {
                    let r = run_mut(ev, "REVIEW");
                    r.attempts.remove(0);
                    r.attempts.push(r.attempts[0].clone());
                    r.attempts[0].status = "SUCCEEDED".into();
                },
            },
            M {
                name: "the retry opened a second pull request",
                check: "E5.every-boundary",
                expect: "left 2 pull requests",
                apply: |ev| {
                    let again = ev.github.pull_requests[0].clone();
                    ev.github.pull_requests.push(again);
                },
            },
            M {
                name: "the job did not complete",
                check: "E5.every-boundary",
                expect: "not COMPLETED",
                apply: |ev| ev.job.status = "ACTIVE".into(),
            },
            M {
                name: "a stage passed twice",
                check: "E5.every-boundary",
                expect: "PASSED runs",
                apply: |ev| {
                    let again = ev.stage_runs[0].clone();
                    ev.stage_runs.push(again);
                },
            },
        ],
    );
}

#[test]
fn e6_checks_fail_on_corrupted_evidence() {
    judge(
        "E6",
        &[
            M {
                name: "the job was admitted",
                check: "E6.rejected",
                expect: "not REJECTED",
                apply: |ev| ev.job.status = "ACTIVE".into(),
            },
            M {
                name: "a stage started",
                check: "E6.rejected",
                expect: "stage runs started",
                apply: |ev| ev.stage_runs.push(started_run("INTAKE")),
            },
            M {
                name: "the token could write code",
                check: "E6.rejected",
                expect: "which a reply does not need",
                apply: |ev| {
                    ev.github.tokens[0]
                        .permissions
                        .insert("contents".into(), "write".into());
                },
            },
            M {
                name: "the reply reveals the allowlist",
                check: "E6.rejected",
                expect: "reveals which test failed",
                apply: |ev| ev.github.comments = vec!["You are not on the allowlist.".into()],
            },
            M {
                name: "two replies",
                check: "E6.rejected",
                expect: "posted 2 comments",
                apply: |ev| ev.github.comments.push("again".into()),
            },
            M {
                name: "money was spent",
                check: "E6.rejected",
                expect: "spent",
                apply: |ev| ev.usage.total_micro_usd = 5,
            },
            M {
                name: "a pull request exists",
                check: "E6.rejected",
                expect: "a pull request exists",
                apply: |ev| {
                    ev.github
                        .pull_requests
                        .push(factory_e2e::evidence::PullRequest {
                            number: 9,
                            draft: true,
                            merged: false,
                            state: "open".into(),
                            head_branch: "factory/x".into(),
                            head_sha: "x".into(),
                            title: "t".into(),
                            body: "b".into(),
                        });
                },
            },
            M {
                name: "no denial is audited",
                check: "E6.rejected",
                expect: "denial records",
                apply: |ev| ev.audit.clear(),
            },
        ],
    );
}

#[test]
fn e7_checks_fail_on_corrupted_evidence() {
    judge(
        "E7",
        &[
            M {
                name: "two jobs",
                check: "E7.one-job",
                expect: "jobs were created",
                apply: |ev| {
                    ev.facts.insert("jobs_created".into(), json!(2));
                },
            },
            M {
                name: "two outbox rows",
                check: "E7.one-job",
                expect: "outbox rows",
                apply: |ev| {
                    ev.facts.insert("outbox_rows".into(), json!(2));
                },
            },
            M {
                name: "too few deliveries",
                check: "E7.one-job",
                expect: "deliveries were sent",
                apply: |ev| {
                    ev.facts.insert("deliveries".into(), json!(3));
                },
            },
            M {
                name: "a duplicate is not audited",
                check: "E7.one-job",
                expect: "duplicate-delivery records",
                apply: |ev| {
                    let at = ev
                        .audit
                        .iter()
                        .rposition(|r| r.detail.contains("duplicate"))
                        .expect("one");
                    ev.audit.remove(at);
                },
            },
        ],
    );
}

#[test]
fn e8_checks_fail_on_corrupted_evidence() {
    judge(
        "E8",
        &[
            M {
                name: "no protected-paths report",
                check: "E8.scope-gate",
                expect: "no failed protected-paths",
                apply: |ev| ev.contracts.gate_reports.clear(),
            },
            M {
                name: "the protected file changed",
                check: "E8.scope-gate",
                expect: "the branch changes CODEOWNERS",
                apply: |ev| ev.github.changed_paths.push("CODEOWNERS".into()),
            },
            M {
                name: "the decision is not audited",
                check: "E8.scope-gate",
                expect: "protected-path decision",
                apply: |ev| {
                    ev.audit
                        .retain(|r| !r.action.starts_with("protected_path_decision"))
                },
            },
            M {
                name: "review started",
                check: "E8.scope-gate",
                expect: "started on the violating change",
                apply: |ev| {
                    run_mut(ev, "REVIEW")
                        .attempts
                        .push(factory_e2e::evidence::AttemptRecord {
                            id: "a".into(),
                            status: "SUCCEEDED".into(),
                        })
                },
            },
            M {
                name: "no path named",
                check: "E8.scope-gate",
                expect: "names no path",
                apply: |ev| {
                    ev.facts.insert("attempted_paths".into(), json!([]));
                },
            },
            M {
                name: "validation is not waiting",
                check: "E8.scope-gate",
                expect: "not waiting for a person",
                apply: |ev| run_mut(ev, "VALIDATION").status = "READY".into(),
            },
            M {
                name: "a pull request exists",
                check: "E8.scope-gate",
                expect: "a pull request exists",
                apply: |ev| {
                    ev.github
                        .pull_requests
                        .push(factory_e2e::evidence::PullRequest {
                            number: 9,
                            draft: true,
                            merged: false,
                            state: "open".into(),
                            head_branch: "factory/x".into(),
                            head_sha: "x".into(),
                            title: "t".into(),
                            body: "b".into(),
                        });
                },
            },
        ],
    );
}

#[test]
fn e9_checks_fail_on_corrupted_evidence() {
    judge(
        "E9",
        &[
            M {
                name: "a fake was not refused",
                check: "E9.production-refuses-fakes",
                expect: "was not refused in production",
                apply: |ev| {
                    ev.facts.get_mut("refusals").expect("r")[0]["refused_in_production"] =
                        json!(false)
                },
            },
            M {
                name: "a fake was not allowed in test mode",
                check: "E9.production-refuses-fakes",
                expect: "not allowed in test mode",
                apply: |ev| {
                    ev.facts.get_mut("refusals").expect("r")[1]["allowed_in_test"] = json!(false)
                },
            },
            M {
                name: "a job started",
                check: "E9.production-refuses-fakes",
                expect: "jobs started",
                apply: |ev| {
                    ev.facts.insert("jobs_started".into(), json!(1));
                },
            },
            M {
                name: "nothing was offered",
                check: "E9.production-refuses-fakes",
                expect: "no adapter was offered",
                apply: |ev| {
                    ev.facts.insert("refusals".into(), json!([]));
                },
            },
        ],
    );
}

#[test]
fn e10_checks_fail_on_corrupted_evidence() {
    judge(
        "E10",
        &[
            M {
                name: "only one revision is stored",
                check: "E10.edit-restarts-intake",
                expect: "revisions are stored",
                apply: |ev| {
                    ev.facts.insert("revisions_stored".into(), json!(1));
                },
            },
            M {
                name: "the edit changed nothing",
                check: "E10.edit-restarts-intake",
                expect: "left the text unchanged",
                apply: |ev| {
                    let a = ev.facts["authorized_text_sha256"].clone();
                    ev.facts.insert("current_text_sha256".into(), a);
                },
            },
            M {
                name: "the first revision was overwritten",
                check: "E10.edit-restarts-intake",
                expect: "not kept unchanged",
                apply: |ev| {
                    ev.facts.insert("stored_first_sha256".into(), json!("sha256:1111111111111111111111111111111111111111111111111111111111111111"));
                },
            },
            M {
                name: "intake did not run again",
                check: "E10.edit-restarts-intake",
                expect: "start it again",
                apply: |ev| {
                    let at = ev
                        .stage_runs
                        .iter()
                        .rposition(|r| r.kind == "INTAKE")
                        .expect("run");
                    ev.stage_runs.remove(at);
                },
            },
            M {
                name: "the new intake is not waiting",
                check: "E10.edit-restarts-intake",
                expect: "not WAITING_FOR_HUMAN",
                apply: |ev| run_mut(ev, "INTAKE").status = "READY".into(),
            },
            M {
                name: "a stage passed on the edited text",
                check: "E10.edit-restarts-intake",
                expect: "stages passed on the edited text",
                apply: |ev| run_mut(ev, "SPECIFICATION").status = "PASSED".into(),
            },
            M {
                name: "the job is active",
                check: "E10.edit-restarts-intake",
                expect: "job is ACTIVE",
                apply: |ev| ev.job.status = "ACTIVE".into(),
            },
        ],
    );
}

#[test]
fn e11_checks_fail_on_corrupted_evidence() {
    judge(
        "E11",
        &[
            M {
                name: "the budget was not reached",
                check: "E11.budget-asks-a-person",
                expect: "was not reached",
                apply: |ev| ev.usage.total_micro_usd = 10,
            },
            M {
                name: "a call started after exhaustion",
                check: "E11.budget-asks-a-person",
                expect: "started after the budget",
                apply: |ev| ev.usage.calls_after_exhaustion = 1,
            },
            M {
                name: "the job is active",
                check: "E11.budget-asks-a-person",
                expect: "not WAITING_FOR_HUMAN",
                apply: |ev| ev.job.status = "ACTIVE".into(),
            },
            M {
                name: "the stage failed",
                check: "E11.budget-asks-a-person",
                expect: "FAILED",
                apply: |ev| run_mut(ev, "INTAKE").status = "FAILED".into(),
            },
            M {
                name: "the threshold is not audited",
                check: "E11.budget-asks-a-person",
                expect: "budget threshold",
                apply: |ev| {
                    ev.audit
                        .retain(|r| !r.action.starts_with("budget_threshold_crossed"))
                },
            },
            M {
                name: "no budget",
                check: "E11.budget-asks-a-person",
                expect: "no budget",
                apply: |ev| ev.usage.budget_micro_usd = 0,
            },
        ],
    );
}

#[test]
fn e12_checks_fail_on_corrupted_evidence() {
    judge(
        "E12",
        &[
            M {
                name: "two questions",
                check: "E12.one-question",
                expect: "posted 2 comments",
                apply: |ev| ev.github.comments.push("Another question?".into()),
            },
            M {
                name: "a statement, not a question",
                check: "E12.one-question",
                expect: "0 question marks",
                apply: |ev| ev.github.comments = vec!["Please explain.".into()],
            },
            M {
                name: "two questions in one comment",
                check: "E12.one-question",
                expect: "2 question marks",
                apply: |ev| ev.github.comments = vec!["What? Why?".into()],
            },
            M {
                name: "a later stage started",
                check: "E12.one-question",
                expect: "stages started before the answer",
                apply: |ev| ev.stage_runs.push(started_run("SPECIFICATION")),
            },
            M {
                name: "intake did not wait",
                check: "E12.one-question",
                expect: "INTAKE is",
                apply: |ev| run_mut(ev, "INTAKE").status = "PASSED".into(),
            },
            M {
                name: "the job is active",
                check: "E12.one-question",
                expect: "job is ACTIVE",
                apply: |ev| ev.job.status = "ACTIVE".into(),
            },
            M {
                name: "a token could write code",
                check: "E12.one-question",
                expect: "write access to contents",
                apply: |ev| {
                    ev.github.tokens[0]
                        .permissions
                        .insert("contents".into(), "write".into());
                },
            },
        ],
    );
}

#[test]
fn e13_checks_fail_on_corrupted_evidence() {
    judge(
        "E13",
        &[
            M {
                name: "no override path",
                check: "E13.declined",
                expect: "how a person can override",
                apply: |ev| ev.github.comments = vec!["No.".into()],
            },
            M {
                name: "a long reply",
                check: "E13.declined",
                expect: "must be short",
                apply: |ev| ev.github.comments = vec![format!("override {}", "x".repeat(700))],
            },
            M {
                name: "a pull request exists",
                check: "E13.declined",
                expect: "a pull request exists",
                apply: |ev| {
                    ev.github
                        .pull_requests
                        .push(factory_e2e::evidence::PullRequest {
                            number: 9,
                            draft: true,
                            merged: false,
                            state: "open".into(),
                            head_branch: "factory/x".into(),
                            head_sha: "x".into(),
                            title: "t".into(),
                            body: "b".into(),
                        });
                },
            },
            M {
                name: "the factory merged",
                check: "E13.declined",
                expect: "something other than a comment",
                apply: |ev| {
                    ev.github
                        .requests
                        .push(factory_e2e::evidence::GithubRequest {
                            method: "PUT".into(),
                            path: "/repos/example-org/word-count/pulls/9/merge".into(),
                        })
                },
            },
            M {
                name: "the decline is not audited",
                check: "E13.declined",
                expect: "decline records",
                apply: |ev| {
                    ev.audit
                        .retain(|r| !r.action.starts_with("authorization_decision"))
                },
            },
            M {
                name: "a later stage started",
                check: "E13.declined",
                expect: "stages started after the decision",
                apply: |ev| ev.stage_runs.push(started_run("SPECIFICATION")),
            },
            M {
                name: "the job is active",
                check: "E13.declined",
                expect: "job is ACTIVE",
                apply: |ev| ev.job.status = "ACTIVE".into(),
            },
        ],
    );
}

#[test]
fn e2_intent_check_fails_when_the_english_artifacts_lose_the_request() {
    judge(
        "E2",
        &[
            M {
                name: "the option name is lost",
                check: "E2.intent",
                expect: "exact term --json",
                apply: |ev| {
                    for d in &mut ev.documents {
                        d.body = d.body.replace("--json", "the flag");
                        d.title = d.title.replace("--json", "the flag");
                    }
                },
            },
            M {
                name: "the example counts are lost",
                check: "E2.intent",
                expect: "3 lines, 7 words and 31 characters",
                apply: |ev| {
                    for d in &mut ev.documents {
                        d.body = d.body.replace("31 characters", "many characters");
                    }
                },
            },
            M {
                name: "the error case is lost",
                check: "E2.intent",
                expect: "non-zero exit status",
                apply: |ev| {
                    for d in &mut ev.documents {
                        d.body = d
                            .body
                            .replace("non-zero", "bad")
                            .replace("standard error", "the screen");
                    }
                },
            },
            M {
                name: "the dependency rule is lost",
                check: "E2.intent",
                expect: "No third-party dependency",
                apply: |ev| {
                    for d in &mut ev.documents {
                        d.body = d.body.replace("dependency", "library");
                    }
                },
            },
            M {
                name: "there are no documents",
                check: "E2.intent",
                expect: "no English artifacts",
                apply: |ev| ev.documents.clear(),
            },
            M {
                name: "the scenarios were dropped",
                check: "E2.intent",
                expect: "acceptance scenarios",
                apply: |ev| {
                    if let Some(s) = ev.contracts.specification.as_mut() {
                        s["acceptance_scenarios"] = json!([]);
                    }
                },
            },
        ],
    );
}
