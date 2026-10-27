//! The facts the engine writes into the payload of the outbox event that announces a transition,
//! and the one place that names them.
//!
//! The `Store` port holds the status of every aggregate, but it has no call that lists the stage
//! runs of a job or the attempts of a stage run, and no column for a retry back-off. The engine
//! therefore records what it needs later in the event that it writes in the same transaction as
//! the change, and [`timeline`](super::timeline) reads it back. A payload carries identifiers,
//! counts, failure classes, hashes and instants. It never carries a prompt, issue text, model
//! output or a secret (ADR 0004), and the database refuses a payload over 16 KiB, so a list in a
//! payload stays short.

use factory_domain::ids::StageRunId;
use factory_domain::vocabulary::StageKind;
use serde_json::{Map, Value, json};

/// The key names. A reader and a writer both use these constants, so they cannot drift apart.
pub(crate) mod key {
    /// The stage kind of the stage run an event is about.
    pub const STAGE_KIND: &str = "stage_kind";
    /// The stage run an event is about, when the aggregate is an attempt or a job.
    pub const STAGE_RUN: &str = "stage_run_id";
    /// `job.admitted`: every stage run created at admission, as `{id, kind}`.
    pub const STAGE_RUNS: &str = "stage_runs";
    /// The stage runs a rework or a supersession created, as `{id, kind}`.
    pub const CREATED: &str = "created_stage_runs";
    /// `stage_run.superseded`: the run that replaces it, as `{id, kind}`.
    pub const REPLACED_BY: &str = "replaced_by";
    /// The attempt a `stage_run.started` event created.
    pub const ATTEMPT: &str = "attempt_id";
    /// Which try the attempt is for its stage run.
    pub const ATTEMPT_NUMBER: &str = "attempt_number";
    /// The failure class of an attempt that ended badly.
    pub const FAILURE_CLASS: &str = "failure_class";
    /// `stage_run.retry_scheduled`: the earliest instant the run may start again.
    pub const NOT_BEFORE: &str = "not_before";
    /// `stage_run.started`: the instant the attempt times out.
    pub const DEADLINE: &str = "deadline_at";
    /// `stage_run.rework_requested`: the count the round is charged to.
    pub const REWORK_TRACK: &str = "rework_track";
    /// `stage_run.rework_requested`: digest of what failed, for the stagnation detector.
    pub const FAILING_SET: &str = "failing_set_sha256";
    /// `stage_run.gating`: what the attempt produced, as `{name, sha256, media_type}`.
    pub const OUTPUTS: &str = "outputs";
    /// `stage_run.ready` after an answer: the hash of the answer.
    pub const ANSWER: &str = "answer_sha256";
    /// `stage_run.ready` after an answer: the media type of the answer.
    pub const ANSWER_MEDIA_TYPE: &str = "answer_media_type";
    /// A short machine code for why a move happened.
    pub const CAUSE: &str = "cause";
    /// The principal who took a human decision.
    pub const PRINCIPAL: &str = "principal_id";
}

/// A stage run as the payload lists it.
#[must_use]
pub(crate) fn run_ref(id: StageRunId, kind: StageKind) -> Value {
    json!({ "id": id.to_string(), "kind": kind.as_str() })
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

/// The payload of `stage_run.started`: the attempt that the move created and when it times out.
#[must_use]
pub(crate) fn attempt_started(
    kind: StageKind,
    run: StageRunId,
    attempt: factory_domain::ids::AttemptId,
    number: u32,
    deadline: factory_domain::values::Timestamp,
) -> Map<String, Value> {
    let payload = for_run(kind, run);
    let payload = with(payload, key::ATTEMPT, json!(attempt.to_string()));
    let payload = with(payload, key::ATTEMPT_NUMBER, json!(number));
    with(payload, key::DEADLINE, json!(deadline.to_string()))
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
