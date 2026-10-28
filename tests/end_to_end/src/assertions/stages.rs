//! Assertions about the stage runs and their order: A1, A2 and A13.

use crate::check::{Env, Verdict};
use crate::evidence::RunEvidence;

use super::support::{PASSED, ledger_sequences_for, passed_at, runs_of, the_passed_run};

/// A1: the job is `COMPLETED`. Every stage kind in scope has exactly one `PASSED` run that is not
/// superseded, and the order respects `requires`.
#[must_use]
pub fn a1(ev: &RunEvidence, env: &Env) -> Verdict {
    const ID: &str = "A1";
    if ev.job.status != "COMPLETED" {
        return Verdict::fail(ID, format!("the job is {}, not COMPLETED", ev.job.status));
    }
    // A completed job leaves no run in a state that still needs work.
    if let Some(open) = ev.stage_runs.iter().find(|run| {
        !matches!(
            run.status.as_str(),
            "PASSED" | "SUPERSEDED" | "REWORK_REQUESTED" | "SKIPPED" | "CANCELLED"
        )
    }) {
        return Verdict::fail(
            ID,
            format!(
                "the job is COMPLETED but the {} run {} is {}",
                open.kind, open.id, open.status
            ),
        );
    }
    for stage in &env.stages {
        let passed = runs_of(ev, &stage.kind)
            .into_iter()
            .filter(|run| run.status == PASSED)
            .count();
        if passed != 1 {
            return Verdict::fail(
                ID,
                format!(
                    "stage {} has {passed} PASSED runs, and it must have exactly one",
                    stage.kind
                ),
            );
        }
    }
    for stage in &env.stages {
        let Some(run) = the_passed_run(ev, &stage.kind) else {
            continue;
        };
        let Some(at) = passed_at(ev, run) else {
            return Verdict::fail(
                ID,
                format!(
                    "the timeline never shows the {} run {} passing",
                    stage.kind, run.id
                ),
            );
        };
        for required in &stage.requires {
            let before = the_passed_run(ev, required).and_then(|r| passed_at(ev, r));
            match before {
                Some(required_at) if required_at < at => {}
                Some(required_at) => {
                    return Verdict::fail(
                        ID,
                        format!(
                            "{} passed at position {at}, before {required} passed at position {required_at}, and it requires {required}",
                            stage.kind
                        ),
                    );
                }
                None => {
                    return Verdict::fail(
                        ID,
                        format!(
                            "{} requires {required}, which has no passing position",
                            stage.kind
                        ),
                    );
                }
            }
        }
    }
    Verdict::pass(
        ID,
        format!(
            "the job is COMPLETED, each of the {} stages has exactly one PASSED run, and every run passed after the stages it requires",
            env.stages.len()
        ),
    )
}

/// A2: `DOCUMENTING` and `DOCUMENTATION_REVIEW` both completed after `REVIEW` passed and before
/// `DELIVERY`, shown by ledger sequence.
#[must_use]
pub fn a2(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A2";
    let ledger_range = |kind: &str| -> Result<(u64, u64), String> {
        let run =
            the_passed_run(ev, kind).ok_or_else(|| format!("{kind} has no single PASSED run"))?;
        let sequences = ledger_sequences_for(ev, &run.id);
        match (sequences.first(), sequences.last()) {
            (Some(first), Some(last)) => Ok((*first, *last)),
            _ => Err(format!(
                "the {kind} run {} PASSED with no ledger entry",
                run.id
            )),
        }
    };
    let review = match ledger_range("REVIEW") {
        Ok(range) => range,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    let documenting = match ledger_range("DOCUMENTING") {
        Ok(range) => range,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    let doc_review = match ledger_range("DOCUMENTATION_REVIEW") {
        Ok(range) => range,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    let delivery = match ledger_range("DELIVERY") {
        Ok(range) => range,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    if documenting.0 <= review.1 {
        return Verdict::fail(
            ID,
            format!(
                "DOCUMENTING has a ledger entry at sequence {}, but REVIEW is not finished until sequence {}",
                documenting.0, review.1
            ),
        );
    }
    if doc_review.0 <= documenting.1 {
        return Verdict::fail(
            ID,
            format!(
                "DOCUMENTATION_REVIEW has a ledger entry at sequence {}, but DOCUMENTING is not finished until sequence {}",
                doc_review.0, documenting.1
            ),
        );
    }
    if delivery.0 <= doc_review.1 {
        return Verdict::fail(
            ID,
            format!(
                "DELIVERY has a ledger entry at sequence {}, but DOCUMENTATION_REVIEW is not finished until sequence {}",
                delivery.0, doc_review.1
            ),
        );
    }
    Verdict::pass(
        ID,
        format!(
            "REVIEW ends at ledger sequence {}, DOCUMENTING runs {} to {}, DOCUMENTATION_REVIEW {} to {}, and DELIVERY starts at {}",
            review.1, documenting.0, documenting.1, doc_review.0, doc_review.1, delivery.0
        ),
    )
}

/// A13: `DELIVERY` starts only when every stage before it has a current run that passed with a
/// gate report that passed. A failing check, as in E3, therefore keeps `DELIVERY` from starting.
#[must_use]
pub fn a13(ev: &RunEvidence, env: &Env) -> Verdict {
    const ID: &str = "A13";
    let delivery_runs = runs_of(ev, "DELIVERY");
    // A run that is only queued, or that was superseded before it began, has not started.
    let started = delivery_runs
        .iter()
        .any(|run| !run.attempts.is_empty() || run.status == PASSED);
    let mut blockers: Vec<String> = Vec::new();
    for stage in &env.stages {
        if stage.kind == "DELIVERY" {
            break;
        }
        let Some(newest) = runs_of(ev, &stage.kind).into_iter().next_back() else {
            blockers.push(format!("{} has no run", stage.kind));
            continue;
        };
        if newest.status != PASSED {
            blockers.push(format!(
                "the newest {} run is {}",
                stage.kind, newest.status
            ));
            continue;
        }
        for record in ev
            .contracts
            .gate_reports
            .iter()
            .filter(|record| record.stage_run_id == newest.id)
        {
            let outcome = record.report.pointer("/outcome").and_then(|v| v.as_str());
            if matches!(outcome, Some("FAILED" | "BLOCKED")) {
                blockers.push(format!(
                    "the {} run {} has a gate report with outcome {}",
                    stage.kind,
                    newest.id,
                    outcome.unwrap_or_default()
                ));
            }
        }
    }
    if started && !blockers.is_empty() {
        return Verdict::fail(
            ID,
            format!("DELIVERY started although {}", blockers.join("; ")),
        );
    }
    if !blockers.is_empty() && !ev.github.pull_requests.is_empty() {
        return Verdict::fail(
            ID,
            format!("a pull request exists although {}", blockers.join("; ")),
        );
    }
    if started {
        Verdict::pass(
            ID,
            "DELIVERY started, and every stage before it has a current PASSED run with passing gate reports",
        )
    } else if blockers.is_empty() {
        Verdict::pass(ID, "DELIVERY has not started, and nothing blocks it yet")
    } else {
        Verdict::pass(
            ID,
            format!("DELIVERY never started, because {}", blockers.join("; ")),
        )
    }
}
