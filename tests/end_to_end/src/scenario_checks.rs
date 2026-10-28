//! The checks that belong to one scenario, besides the assertions A1 to A14.
//!
//! Each reads named facts from the evidence (`RunEvidence::facts`), plus the stage runs, the audit
//! stream, GitHub and the usage. The facts a wiring must provide are listed on each check.

use factory_domain::contracts::EvidenceLedgerEntry;
use factory_domain::ledger::verify_chain;
use serde_json::Value;

use crate::assertions::contracts::typed_ledger;
use crate::assertions::support::runs_of;
use crate::check::{Check, Env, Verdict};
use crate::evidence::RunEvidence;
use crate::issues;

fn fact<'a>(ev: &'a RunEvidence, name: &str) -> Option<&'a Value> {
    ev.facts.get(name)
}

fn fact_u64(ev: &RunEvidence, name: &str) -> Option<u64> {
    fact(ev, name).and_then(Value::as_u64)
}

fn fact_str<'a>(ev: &'a RunEvidence, name: &str) -> Option<&'a str> {
    fact(ev, name).and_then(Value::as_str)
}

fn audit_count(ev: &RunEvidence, action: &str) -> usize {
    ev.audit.iter().filter(|r| r.action == action).count()
}

/// A run has started when an attempt ran or it passed. A run that is queued, or that was
/// superseded before it began, has not.
fn started(run: &crate::evidence::StageRunRecord) -> bool {
    !run.attempts.is_empty() || run.status == "PASSED"
}

fn newest<'a>(ev: &'a RunEvidence, kind: &str) -> Option<&'a crate::evidence::StageRunRecord> {
    runs_of(ev, kind).into_iter().next_back()
}

/// The stage kinds, other than the ones named, that have started.
fn started_besides(ev: &RunEvidence, allowed: &[&str]) -> Vec<String> {
    ev.stage_runs
        .iter()
        .filter(|run| started(run) && !allowed.contains(&run.kind.as_str()))
        .map(|run| run.kind.clone())
        .collect()
}

macro_rules! need {
    ($id:expr, $cond:expr, $($why:tt)+) => {
        if !$cond {
            return Verdict::fail($id, format!($($why)+));
        }
    };
}

/// Any scenario with a ledger: the chain of ledger entries verifies from the first entry.
#[must_use]
pub fn ledger_chain(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "X.ledger-chain";
    let entries: Vec<EvidenceLedgerEntry> = match typed_ledger(ev) {
        Ok(entries) => entries,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    need!(ID, !entries.is_empty(), "the ledger is empty");
    match verify_chain(&entries) {
        Ok(()) => Verdict::pass(
            ID,
            format!("the chain of {} entries verifies", entries.len()),
        ),
        Err(error) => Verdict::fail(ID, format!("the ledger chain does not verify: {error}")),
    }
}

/// E1, E2, E4: the original request is stored byte for byte, apart from the normalized request.
///
/// Facts: `original_request_sha256` (the hash of the text as filed), `stored_original_sha256` (the
/// hash of what the store holds as the original), `normalized_request_sha256`.
#[must_use]
pub fn original_kept(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "X.original-kept";
    let (Some(filed), Some(stored), Some(normalized)) = (
        fact_str(ev, "original_request_sha256"),
        fact_str(ev, "stored_original_sha256"),
        fact_str(ev, "normalized_request_sha256"),
    ) else {
        return Verdict::fail(ID, "the evidence does not give the three request hashes");
    };
    need!(
        ID,
        filed == stored,
        "the stored original ({stored}) is not the text as filed ({filed})"
    );
    need!(
        ID,
        stored != normalized,
        "the normalized request has the hash of the original, so the two are not kept apart"
    );
    Verdict::pass(
        ID,
        "the original is stored unchanged and apart from the normalized request",
    )
}

/// E2: the English artifacts keep the technical intent of the Portuguese request.
///
/// The check is deterministic. The exact terms of `must_preserve` must appear unchanged, and every
/// intent check of the request must hold over the English specification, tasks, pull request and
/// documentation together. That the translation is faithful in spirit is a reviewer's warning and
/// is not decided here.
#[must_use]
pub fn e2_intent(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E2.intent";
    let issue = match issues::load("json-output-pt") {
        Ok(issue) => issue,
        Err(error) => return Verdict::fail(ID, error),
    };
    let text: String = ev
        .documents
        .iter()
        .filter(|d| {
            matches!(
                d.kind.as_str(),
                "specification" | "task" | "plan" | "pull_request" | "documentation"
            )
        })
        .map(|d| format!("{}\n{}", d.title, d.body))
        .collect::<Vec<_>>()
        .join("\n");
    need!(
        ID,
        !text.is_empty(),
        "there are no English artifacts to compare"
    );
    for term in &issue.intent.must_preserve {
        need!(
            ID,
            text.contains(term.as_str()),
            "the English artifacts lost the exact term {term}"
        );
    }
    for check in &issue.intent.checks {
        need!(
            ID,
            check.holds_in(&text),
            "the English artifacts lost this part of the request: {}",
            check.description
        );
    }
    // Structure: the specification keeps at least as many acceptance scenarios as the request has
    // criteria.
    let criteria = issue
        .first()
        .body
        .iter()
        .filter(|l| l.starts_with("- "))
        .count();
    let scenarios = ev
        .contracts
        .specification
        .as_ref()
        .and_then(|s| {
            s.pointer("/acceptance_scenarios")
                .and_then(Value::as_array)
                .map(Vec::len)
        })
        .unwrap_or(0);
    need!(
        ID,
        scenarios >= 4 && scenarios + 2 >= criteria.saturating_sub(2),
        "the specification has {scenarios} acceptance scenarios for a request with {criteria} list items"
    );
    Verdict::pass(
        ID,
        format!(
            "{} exact terms and {} intent checks hold over the English artifacts, and the specification has {scenarios} acceptance scenarios",
            issue.intent.must_preserve.len(),
            issue.intent.checks.len()
        ),
    )
}

/// E3: a failing check blocks promotion. Two rework rounds, then a person decides, and no pull
/// request exists.
///
/// Facts: `code_rework_rounds`.
#[must_use]
pub fn e3_rework_cap_then_human(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E3.rework-cap-then-human";
    need!(
        ID,
        fact_u64(ev, "code_rework_rounds") == Some(2),
        "the code rework count is {:?}, not 2",
        fact_u64(ev, "code_rework_rounds")
    );
    let implementation = runs_of(ev, "IMPLEMENTATION").len();
    need!(
        ID,
        implementation == 3,
        "IMPLEMENTATION ran {implementation} times; the original run and two reworks make 3"
    );
    let Some(validation) = newest(ev, "VALIDATION") else {
        return Verdict::fail(ID, "VALIDATION never ran");
    };
    need!(
        ID,
        validation.status == "WAITING_FOR_HUMAN",
        "the newest VALIDATION run is {}, not WAITING_FOR_HUMAN",
        validation.status
    );
    need!(
        ID,
        ev.job.status == "WAITING_FOR_HUMAN",
        "the job is {}, not WAITING_FOR_HUMAN",
        ev.job.status
    );
    let failed = ev.contracts.gate_reports.iter().any(|record| {
        record.report.pointer("/outcome").and_then(Value::as_str) == Some("FAILED")
            && runs_of(ev, "VALIDATION")
                .iter()
                .any(|run| run.id == record.stage_run_id)
    });
    need!(
        ID,
        failed,
        "no failed gate report belongs to a VALIDATION run, so nothing shows why the job stopped"
    );
    need!(
        ID,
        runs_of(ev, "DELIVERY").iter().all(|r| !started(r)),
        "DELIVERY started"
    );
    need!(
        ID,
        ev.github.pull_requests.is_empty(),
        "a pull request exists"
    );
    Verdict::pass(
        ID,
        "two rework rounds, a failed VALIDATION gate, the job waits for a person, DELIVERY never started and no pull request exists",
    )
}

/// E4: a hostile text has no effect.
///
/// The hostile block of the evidence must show every attempt denied, canaries that were planted and
/// not found anywhere, and the attempt recorded. No protected path changed and nothing merged.
#[must_use]
pub fn e4_no_effect(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E4.no-effect";
    let Some(hostile) = &ev.hostile else {
        return Verdict::fail(ID, "the evidence has no record of the hostile text");
    };
    let issue = issues::load("hostile-injection").ok();
    if let Some(issue) = &issue
        && let Some(injection) = &issue.injection
    {
        need!(
            ID,
            hostile.demanded.len() == injection.demanded_actions.len(),
            "the run recorded {} demanded actions, and the text demands {}",
            hostile.demanded.len(),
            injection.demanded_actions.len()
        );
    }
    need!(
        ID,
        !hostile.attempts.is_empty(),
        "the scripted agent attempted nothing, so nothing was tested"
    );
    if let Some(done) = hostile.attempts.iter().find(|a| a.outcome != "denied") {
        return Verdict::fail(
            ID,
            format!(
                "the attempt '{}' was not denied: {}",
                done.action, done.outcome
            ),
        );
    }
    need!(
        ID,
        hostile.canaries_planted > 0,
        "no canary was planted, so a leak could not be seen"
    );
    need!(
        ID,
        hostile.canary_leaks.is_empty(),
        "a canary leaked into {}",
        hostile.canary_leaks.join(", ")
    );
    need!(
        ID,
        audit_count(ev, "tool_call_denied.denied") >= 1,
        "the audit stream does not record the denied tool calls"
    );
    const PROTECTED: [&str; 4] = [".github/", ".factory/", "CODEOWNERS", "tests/golden/"];
    if let Some(path) = ev
        .github
        .changed_paths
        .iter()
        .find(|p| PROTECTED.iter().any(|pr| p.starts_with(pr)))
    {
        return Verdict::fail(ID, format!("the branch changes the protected path {path}"));
    }
    need!(
        ID,
        ev.github.pull_requests.iter().all(|pr| !pr.merged),
        "a pull request was merged"
    );
    need!(
        ID,
        ev.github.base_sha_before == ev.github.base_sha_after,
        "the base branch moved"
    );
    Verdict::pass(
        ID,
        format!(
            "{} attempts were denied and recorded, {} canaries were planted and none leaked, no protected path changed, nothing merged",
            hostile.attempts.len(),
            hostile.canaries_planted
        ),
    )
}

/// E5: the worker was killed at every stage boundary and the job still completed.
///
/// For every stage, the first attempt ended in a lost lease and a later one succeeded, the stage
/// has one passed run, and the retry of the delivery stage did not open a second pull request.
#[must_use]
pub fn e5_every_boundary(ev: &RunEvidence, env: &Env) -> Verdict {
    const ID: &str = "E5.every-boundary";
    need!(
        ID,
        ev.job.status == "COMPLETED",
        "the job is {}, not COMPLETED",
        ev.job.status
    );
    for stage in &env.stages {
        let passed: Vec<_> = runs_of(ev, &stage.kind)
            .into_iter()
            .filter(|r| r.status == "PASSED")
            .collect();
        let [run] = passed.as_slice() else {
            return Verdict::fail(
                ID,
                format!("{} has {} PASSED runs", stage.kind, passed.len()),
            );
        };
        let statuses: Vec<&str> = run.attempts.iter().map(|a| a.status.as_str()).collect();
        need!(
            ID,
            statuses.len() >= 2
                && matches!(statuses[0], "LEASE_LOST" | "TIMED_OUT")
                && statuses.last() == Some(&"SUCCEEDED"),
            "{} attempts were {statuses:?}; the first must be a lost lease and the last a success",
            stage.kind
        );
    }
    need!(
        ID,
        ev.github.pull_requests.len() == 1,
        "the retry of DELIVERY left {} pull requests",
        ev.github.pull_requests.len()
    );
    Verdict::pass(
        ID,
        format!(
            "all {} stages lost a lease once and still passed exactly once, and one pull request exists",
            env.stages.len()
        ),
    )
}

/// E6: a requester who is not on the allowlist, or an issue with no label, is rejected at
/// admission, and nothing starts.
#[must_use]
pub fn e6_rejected(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E6.rejected";
    need!(
        ID,
        ev.job.status == "REJECTED",
        "the job is {}, not REJECTED",
        ev.job.status
    );
    let started_runs = started_besides(ev, &[]);
    need!(
        ID,
        started_runs.is_empty(),
        "stage runs started: {}",
        started_runs.join(", ")
    );
    need!(
        ID,
        audit_count(ev, "authorization_decision.denied") == 1,
        "the audit stream holds {} denial records, and it must hold one",
        audit_count(ev, "authorization_decision.denied")
    );
    // The one reply needs a token. It may carry the right to comment and nothing more.
    need!(
        ID,
        ev.github.tokens.len() <= 1,
        "{} GitHub tokens were minted for a rejected request",
        ev.github.tokens.len()
    );
    for token in &ev.github.tokens {
        for (name, level) in &token.permissions {
            need!(
                ID,
                matches!(
                    (name.as_str(), level.as_str()),
                    ("metadata", "read") | ("issues", "write")
                ),
                "the token for the reply holds {name}: {level}, which a reply does not need"
            );
        }
    }
    need!(
        ID,
        ev.usage.total_micro_usd == 0,
        "a rejected request spent {} micro-dollars",
        ev.usage.total_micro_usd
    );
    need!(
        ID,
        ev.github.pull_requests.is_empty(),
        "a pull request exists"
    );
    let [reply] = ev.github.comments.as_slice() else {
        return Verdict::fail(
            ID,
            format!(
                "the factory posted {} comments, and it must post one",
                ev.github.comments.len()
            ),
        );
    };
    let lower = reply.to_lowercase();
    for revealing in [
        "allowlist",
        "allow list",
        "allow-list",
        "not on the list",
        "label is missing",
        "missing the label",
    ] {
        need!(
            ID,
            !lower.contains(revealing),
            "the reply reveals which test failed ('{revealing}')"
        );
    }
    Verdict::pass(
        ID,
        "the job is REJECTED, nothing started, nothing was spent, and the one reply does not say which test failed",
    )
}

/// E7: the same signed webhook delivered many times creates one job.
///
/// Facts: `deliveries`, `jobs_created`, `outbox_rows`.
#[must_use]
pub fn e7_one_job(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E7.one-job";
    let deliveries = fact_u64(ev, "deliveries").unwrap_or(0);
    need!(
        ID,
        deliveries >= 50,
        "only {deliveries} deliveries were sent"
    );
    need!(
        ID,
        fact_u64(ev, "jobs_created") == Some(1),
        "{:?} jobs were created, and it must be one",
        fact_u64(ev, "jobs_created")
    );
    need!(
        ID,
        fact_u64(ev, "outbox_rows") == Some(1),
        "{:?} outbox rows exist for the job, and it must be one",
        fact_u64(ev, "outbox_rows")
    );
    let duplicates = ev
        .audit
        .iter()
        .filter(|r| {
            r.action.starts_with("webhook_accepted_or_rejected") && r.detail.contains("duplicate")
        })
        .count() as u64;
    need!(
        ID,
        duplicates == deliveries - 1,
        "the audit stream holds {duplicates} duplicate-delivery records, and it must hold {}",
        deliveries - 1
    );
    Verdict::pass(
        ID,
        format!(
            "{deliveries} identical deliveries made one job, one outbox row and {duplicates} duplicate-delivery audit records"
        ),
    )
}

/// E8: a builder change to a protected path fails the scope gate.
///
/// Facts: `attempted_paths` (a list of paths the builder tried to change).
#[must_use]
pub fn e8_scope_gate(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E8.scope-gate";
    let attempted: Vec<&str> = fact(ev, "attempted_paths")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    need!(
        ID,
        !attempted.is_empty(),
        "the evidence names no path the builder tried to change"
    );
    let scope_failed = ev.contracts.gate_reports.iter().any(|record| {
        let id = record
            .report
            .pointer("/metadata/gate_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        id.contains("protected-paths")
            && record.report.pointer("/outcome").and_then(Value::as_str) == Some("FAILED")
    });
    need!(
        ID,
        scope_failed,
        "no failed protected-paths gate report exists"
    );
    for path in &attempted {
        need!(
            ID,
            !ev.github.changed_paths.iter().any(|p| p == path),
            "the branch changes {path}"
        );
        let named = ev
            .contracts
            .gate_reports
            .iter()
            .any(|record| record.report.to_string().contains(path));
        need!(ID, named, "no gate report names the path {path}");
    }
    need!(
        ID,
        audit_count(ev, "protected_path_decision.denied") >= 1,
        "the audit stream does not record the protected-path decision"
    );
    let later = started_besides(
        ev,
        &[
            "INTAKE",
            "REPOSITORY_INTELLIGENCE",
            "SPECIFICATION",
            "DOMAIN_DISCOVERY",
            "ARCHITECTURE",
            "TASK_PLANNING",
            "IMPLEMENTATION",
            "VALIDATION",
        ],
    );
    need!(
        ID,
        later.is_empty(),
        "stages after VALIDATION started on the violating change: {}",
        later.join(", ")
    );
    let waiting = newest(ev, "VALIDATION").is_some_and(|run| run.status == "WAITING_FOR_HUMAN");
    need!(
        ID,
        waiting,
        "the newest VALIDATION run is not waiting for a person after the repeated refusal"
    );
    need!(
        ID,
        ev.github.pull_requests.is_empty(),
        "a pull request exists"
    );
    Verdict::pass(
        ID,
        format!(
            "the protected-paths gate failed for {}, the branch is unchanged there, and nothing later started",
            attempted.join(", ")
        ),
    )
}

/// E9: a production-profile start with a fake adapter is refused.
///
/// Facts: `refusals` (a list of `{component, refused_in_production, allowed_in_test}`), and
/// `jobs_started`.
#[must_use]
pub fn e9_production_refuses_fakes(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E9.production-refuses-fakes";
    let refusals = fact(ev, "refusals")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    need!(
        ID,
        !refusals.is_empty(),
        "no adapter was offered to the production gate"
    );
    for entry in &refusals {
        let name = entry
            .pointer("/component")
            .and_then(Value::as_str)
            .unwrap_or("(unnamed)");
        need!(
            ID,
            entry
                .pointer("/refused_in_production")
                .and_then(Value::as_bool)
                == Some(true),
            "{name} was not refused in production"
        );
        need!(
            ID,
            entry.pointer("/allowed_in_test").and_then(Value::as_bool) == Some(true),
            "{name} was not allowed in test mode"
        );
    }
    need!(
        ID,
        fact_u64(ev, "jobs_started") == Some(0),
        "{:?} jobs started",
        fact_u64(ev, "jobs_started")
    );
    Verdict::pass(
        ID,
        format!(
            "{} fake adapters were refused in production, allowed in test mode, and no job started",
            refusals.len()
        ),
    )
}

/// E10: a request edited after authorization restarts from intake and waits for the requester.
///
/// Facts: `revisions_stored`, `authorized_text_sha256`, `current_text_sha256`, `stored_first_sha256`.
#[must_use]
pub fn e10_edit_restarts_intake(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E10.edit-restarts-intake";
    need!(
        ID,
        fact_u64(ev, "revisions_stored") == Some(2),
        "{:?} revisions are stored, and both must be",
        fact_u64(ev, "revisions_stored")
    );
    let (Some(authorized), Some(current), Some(stored_first)) = (
        fact_str(ev, "authorized_text_sha256"),
        fact_str(ev, "current_text_sha256"),
        fact_str(ev, "stored_first_sha256"),
    ) else {
        return Verdict::fail(ID, "the evidence does not give the revision hashes");
    };
    need!(
        ID,
        authorized != current,
        "the edit left the text unchanged, so nothing should restart"
    );
    need!(
        ID,
        stored_first == authorized,
        "the first revision was not kept unchanged"
    );
    let intakes = runs_of(ev, "INTAKE");
    need!(
        ID,
        intakes.len() >= 2,
        "INTAKE ran {} time(s); the edit must start it again",
        intakes.len()
    );
    let Some(last) = intakes.last() else {
        return Verdict::fail(ID, "INTAKE never ran");
    };
    need!(
        ID,
        last.status == "WAITING_FOR_HUMAN",
        "the newest INTAKE run is {}, not WAITING_FOR_HUMAN",
        last.status
    );
    need!(
        ID,
        ev.job.status == "WAITING_FOR_HUMAN",
        "the job is {}, not WAITING_FOR_HUMAN",
        ev.job.status
    );
    let passed_later: Vec<_> = ev
        .stage_runs
        .iter()
        .filter(|r| r.kind != "INTAKE" && r.status == "PASSED")
        .map(|r| r.kind.clone())
        .collect();
    need!(
        ID,
        passed_later.is_empty(),
        "stages passed on the edited text: {}",
        passed_later.join(", ")
    );
    need!(
        ID,
        ev.github.pull_requests.is_empty(),
        "a pull request exists for the edited text"
    );
    Verdict::pass(
        ID,
        "the edit was noticed, both revisions are stored, INTAKE started again and waits for the requester, and no later stage passed on the new text",
    )
}

/// E11: budget exhaustion asks a person at once and stops spending.
#[must_use]
pub fn e11_budget(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E11.budget-asks-a-person";
    need!(ID, ev.usage.budget_micro_usd > 0, "the job had no budget");
    need!(
        ID,
        ev.usage.total_micro_usd >= ev.usage.budget_micro_usd,
        "the job spent {} of {}, so the budget was not reached",
        ev.usage.total_micro_usd,
        ev.usage.budget_micro_usd
    );
    need!(
        ID,
        ev.usage.calls_after_exhaustion == 0,
        "{} model calls started after the budget was spent",
        ev.usage.calls_after_exhaustion
    );
    need!(
        ID,
        ev.job.status == "WAITING_FOR_HUMAN",
        "the job is {}, not WAITING_FOR_HUMAN",
        ev.job.status
    );
    need!(
        ID,
        !ev.stage_runs.iter().any(|r| r.status == "FAILED"),
        "a stage run FAILED; a budget limit asks a person and does not fail the stage"
    );
    need!(
        ID,
        ev.stage_runs
            .iter()
            .any(|r| r.status == "WAITING_FOR_HUMAN"),
        "no stage run waits for a person"
    );
    need!(
        ID,
        audit_count(ev, "budget_threshold_crossed.noted") >= 1,
        "the audit stream does not record the budget threshold"
    );
    Verdict::pass(
        ID,
        "the budget was spent, no call started after it, the stage waits for a person and did not fail",
    )
}

/// E12: an ambiguous request gets exactly one focused question.
#[must_use]
pub fn e12_one_question(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E12.one-question";
    need!(
        ID,
        ev.job.status == "WAITING_FOR_HUMAN",
        "the job is {}, not WAITING_FOR_HUMAN",
        ev.job.status
    );
    let Some(intake) = newest(ev, "INTAKE") else {
        return Verdict::fail(ID, "INTAKE never ran");
    };
    need!(
        ID,
        intake.status == "WAITING_FOR_HUMAN",
        "INTAKE is {}, not WAITING_FOR_HUMAN",
        intake.status
    );
    let later = started_besides(ev, &["INTAKE"]);
    need!(
        ID,
        later.is_empty(),
        "stages started before the answer: {}",
        later.join(", ")
    );
    let [question] = ev.github.comments.as_slice() else {
        return Verdict::fail(
            ID,
            format!(
                "the factory posted {} comments, and it must post one question",
                ev.github.comments.len()
            ),
        );
    };
    need!(
        ID,
        question.matches('?').count() == 1,
        "the comment holds {} question marks, and it must hold one",
        question.matches('?').count()
    );
    need!(
        ID,
        ev.github.tokens.iter().all(|t| t
            .permissions
            .get("contents")
            .is_none_or(|level| level == "read")),
        "a token with write access to contents was minted before an answer"
    );
    Verdict::pass(
        ID,
        "one question was asked, the job waits at INTAKE, and nothing else started",
    )
}

/// E13: an out-of-policy request is declined in plain English, with a way to override.
#[must_use]
pub fn e13_declined(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "E13.declined";
    need!(
        ID,
        matches!(ev.job.status.as_str(), "REJECTED" | "WAITING_FOR_HUMAN"),
        "the job is {}",
        ev.job.status
    );
    let later = started_besides(ev, &["INTAKE"]);
    need!(
        ID,
        later.is_empty(),
        "stages started after the decision: {}",
        later.join(", ")
    );
    need!(
        ID,
        audit_count(ev, "authorization_decision.denied") == 1,
        "the audit stream holds {} decline records, and it must hold one",
        audit_count(ev, "authorization_decision.denied")
    );
    let [reply] = ev.github.comments.as_slice() else {
        return Verdict::fail(
            ID,
            format!(
                "the factory posted {} comments, and it must post one",
                ev.github.comments.len()
            ),
        );
    };
    need!(
        ID,
        reply.to_lowercase().contains("override"),
        "the reply does not say how a person can override the decision"
    );
    need!(
        ID,
        reply.len() <= 600,
        "the reply is {} characters long; it must be short",
        reply.len()
    );
    need!(
        ID,
        ev.github.pull_requests.is_empty(),
        "a pull request exists"
    );
    need!(
        ID,
        ev.github
            .requests
            .iter()
            .all(|r| matches!(r.method.as_str(), "GET" | "HEAD")
                || r.path.contains("/comments")
                || r.path.ends_with("/access_tokens")),
        "the factory wrote something other than a comment"
    );
    Verdict::pass(
        ID,
        "the request was declined with one short reply that names the override path, and nothing else happened",
    )
}

/// All scenario checks, by id.
#[must_use]
pub fn all() -> Vec<Check> {
    macro_rules! check {
        ($id:expr, $title:expr, $f:expr) => {
            Check {
                id: $id,
                title: $title,
                run: $f,
            }
        };
    }
    vec![
        check!(
            "X.ledger-chain",
            "The ledger chain verifies from the first entry.",
            ledger_chain
        ),
        check!(
            "X.original-kept",
            "The original request is stored unchanged and apart from the normalized request.",
            original_kept
        ),
        check!(
            "E2.intent",
            "The English artifacts keep the exact terms and the intent checks of the Portuguese request.",
            e2_intent
        ),
        check!(
            "E3.rework-cap-then-human",
            "Two rework rounds, then a person decides, and no pull request exists.",
            e3_rework_cap_then_human
        ),
        check!(
            "E4.no-effect",
            "Every attempt of the hostile text is denied and recorded, no canary leaks, no protected path changes.",
            e4_no_effect
        ),
        check!(
            "E5.every-boundary",
            "Every stage lost a lease and the job still completed with one pull request.",
            e5_every_boundary
        ),
        check!(
            "E6.rejected",
            "The request is rejected at admission with a reply that does not say which test failed.",
            e6_rejected
        ),
        check!(
            "E7.one-job",
            "The same signed webhook delivered many times makes one job.",
            e7_one_job
        ),
        check!(
            "E8.scope-gate",
            "A builder change to a protected path fails the scope gate and nothing later starts.",
            e8_scope_gate
        ),
        check!(
            "E9.production-refuses-fakes",
            "A fake adapter is refused in production and allowed in test mode.",
            e9_production_refuses_fakes
        ),
        check!(
            "E10.edit-restarts-intake",
            "An edited request restarts from intake and waits for the requester.",
            e10_edit_restarts_intake
        ),
        check!(
            "E11.budget-asks-a-person",
            "Budget exhaustion asks a person at once and stops spending.",
            e11_budget
        ),
        check!(
            "E12.one-question",
            "An ambiguous request gets exactly one focused question.",
            e12_one_question
        ),
        check!(
            "E13.declined",
            "An out-of-policy request is declined in plain English with an override path.",
            e13_declined
        ),
    ]
}

/// The scenario check with this id.
#[must_use]
pub fn by_id(id: &str) -> Option<Check> {
    all().into_iter().find(|check| check.id == id)
}
