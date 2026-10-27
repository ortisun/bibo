//! `schemas/domain-event.schema.json`: the envelope of one domain event.
//!
//! Domain events record facts about state changes, such as a stage run passing. They are not
//! diagnostic logs. Delivery is at least once, so a consumer treats `event_id` as its idempotency
//! key. Heartbeats are not domain events.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::common::{SchemaVersion, required_nullable};
use super::{Violations, contract};
use crate::ids::{AggregateId, CausationId, CorrelationId, EventId, JobId, TenantId};
use crate::macros::string_enum;
use crate::values::{EventType, PositiveInt, Slug, Timestamp, Traceparent, TransitionId};

string_enum! {
    /// The kind of aggregate an event is about.
    pub enum AggregateKind("aggregate type") {
        /// A job.
        Job = "job",
        /// A stage run.
        StageRun = "stage_run",
        /// An attempt.
        Attempt = "attempt",
        /// A task node.
        TaskNode = "task_node",
    }
}

/// The aggregate an event is about and its version after the change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aggregate {
    /// Which kind of aggregate.
    #[serde(rename = "type")]
    pub kind: AggregateKind,
    /// Which one.
    pub id: AggregateId,
    /// The aggregate version after the change. Lets a consumer detect reordering and gaps.
    pub version: PositiveInt,
}

/// The name and version of the schema a payload follows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSchema {
    /// The schema.
    pub name: Slug,
    /// Its version.
    pub version: PositiveInt,
}

/// The envelope of one domain event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, remote = "Self")]
pub struct DomainEvent {
    /// Always 1.
    pub schema_version: SchemaVersion,
    /// Unique per event. The stream message id and the consumer idempotency key.
    pub event_id: EventId,
    /// `aggregate.past_tense_verb`, from the emits column of `state-machine.json`.
    pub event_type: EventType,
    /// The version of the payload shape for this event type.
    pub event_version: PositiveInt,
    /// The tenant.
    pub tenant_id: TenantId,
    /// The job.
    pub job_id: JobId,
    /// The aggregate that changed.
    pub aggregate: Aggregate,
    /// The transition that produced the event. The machine-readable reason.
    pub transition_id: TransitionId,
    /// A finer reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<Slug>,
    /// Shared by every event and log line that belongs to one job.
    pub correlation_id: CorrelationId,
    /// The event or command that caused this one. `null` for the first event of a job.
    #[serde(deserialize_with = "required_nullable")]
    pub causation_id: Option<CausationId>,
    /// When the change happened.
    pub occurred_at: Timestamp,
    /// The component that produced it.
    pub producer: Slug,
    /// Lets a consumer continue the trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<Traceparent>,
    /// Event-specific data. Its shape is named by `payload_schema`.
    pub payload: Map<String, Value>,
    /// The schema the payload follows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_schema: Option<PayloadSchema>,
}

impl DomainEvent {
    fn check(&self, _found: &mut Violations) {
        // Every rule of this schema is a pattern, a closed set or a required field, so the field
        // types already enforce it. `EventType` refuses the heartbeat.
    }
}

contract!(DomainEvent, "domain-event");
