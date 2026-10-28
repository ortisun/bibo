//! The facts the engine writes into the payload of the outbox event that announces a transition,
//! and the one place that names them.
//!
//! The outbox is a notification record, not the source of truth for what exists (ports-v1.1,
//! `OutboxOps`). The engine reads the stage runs, the attempts and what they produced from the
//! rows, through the listing operations of the `Store` (see [`timeline`](super::timeline)), so a
//! payload does not list them. A payload names the stage run an event is about, the guard that
//! held, a short machine code for why, and a few identifiers, counts and hashes for the consumers
//! of the event. It never carries a prompt, issue text, model output or a secret (ADR 0004), and
//! the database refuses a payload over 16 KiB.
//!
//! One key is still read back by the engine, because the store has no row for what it carries:
//! [`key::COST`]. The code that reads it says what is missing.

use factory_domain::ids::StageRunId;
use factory_domain::vocabulary::StageKind;
use serde_json::{Map, Value, json};

/// The key names. A reader and a writer both use these constants, so they cannot drift apart.
pub(crate) mod key {
    /// The stage kind of the stage run an event is about.
    pub const STAGE_KIND: &str = "stage_kind";
    /// The stage run an event is about, when the aggregate is an attempt or a job.
    pub const STAGE_RUN: &str = "stage_run_id";
    /// The attempt a `stage_run.started` event created. For the consumers of the event.
    pub const ATTEMPT: &str = "attempt_id";
    /// Which try the attempt is for its stage run. For the consumers of the event.
    pub const ATTEMPT_NUMBER: &str = "attempt_number";
    /// The failure class of an attempt that ended badly. For the consumers of the event.
    pub const FAILURE_CLASS: &str = "failure_class";
    /// What an attempt spent, in millionths of a US dollar, as the broker metered it.
    pub const COST: &str = "cost_micro_usd";
    /// A short machine code for why a move happened.
    pub const CAUSE: &str = "cause";
    /// The principal who took a human decision.
    pub const PRINCIPAL: &str = "principal_id";
    /// The guard that held for the move an event announces (ADR 0014, decision 3).
    pub const GUARD: &str = "guard";
    /// The SHA-256 of the facts that guard held on.
    pub const GUARD_FACTS: &str = "guard_facts_sha256";
}

/// A payload that starts with the stage kind and the stage run an event is about.
#[must_use]
pub(crate) fn for_run(kind: StageKind, run: StageRunId) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert(key::STAGE_KIND.to_owned(), json!(kind.as_str()));
    payload.insert(key::STAGE_RUN.to_owned(), json!(run.to_string()));
    payload
}

/// Adds one entry and returns the payload, so a builder reads as a chain.
#[must_use]
pub(crate) fn with(
    mut payload: Map<String, Value>,
    name: &str,
    value: Value,
) -> Map<String, Value> {
    payload.insert(name.to_owned(), value);
    payload
}

/// The payload of `stage_run.started`: the attempt that the move created. The deadline is not in
/// it: the store keeps it on the attempt (`Attempt::deadline_at`).
#[must_use]
pub(crate) fn attempt_started(
    kind: StageKind,
    run: StageRunId,
    attempt: factory_domain::ids::AttemptId,
    number: u32,
) -> Map<String, Value> {
    let payload = for_run(kind, run);
    let payload = with(payload, key::ATTEMPT, json!(attempt.to_string()));
    with(payload, key::ATTEMPT_NUMBER, json!(number))
}

/// The payload of an attempt event: the stage run it belongs to, which try it is, and, when it
/// ended badly, the failure class.
#[must_use]
pub(crate) fn attempt_event(
    kind: StageKind,
    run: StageRunId,
    number: u32,
    class: Option<factory_domain::machines::failure::FailureClass>,
) -> Map<String, Value> {
    let payload = for_run(kind, run);
    let payload = with(payload, key::ATTEMPT_NUMBER, json!(number));
    match class {
        Some(class) => with(payload, key::FAILURE_CLASS, json!(class.as_str())),
        None => payload,
    }
}
