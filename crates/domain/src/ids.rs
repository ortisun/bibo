//! Typed identifiers.
//!
//! Each kind of identifier is its own type, so a job id cannot be passed where a tenant id is
//! expected. All of them are lowercase, hyphenated UUIDs on the wire. They are made by the
//! `IdGenerator` port (UUID version 7, as ADR 0007 says) and handed in through `from_uuid`, so
//! this crate never generates one.

use crate::macros::uuid_id;

uuid_id! {
    /// The organization that owns a row. Every query is scoped by one.
    pub struct TenantId("tenant id")
}
uuid_id! {
    /// One request to the factory.
    pub struct JobId("job id")
}
uuid_id! {
    /// One execution of one stage kind for a job.
    pub struct StageRunId("stage run id")
}
uuid_id! {
    /// One try at a stage run, owned by one worker through one lease.
    pub struct AttemptId("attempt id")
}
uuid_id! {
    /// One node of the planned task graph, as a state machine aggregate.
    pub struct TaskNodeId("task node id")
}
uuid_id! {
    /// A person or policy engine that took a recorded decision.
    pub struct PrincipalId("principal id")
}
uuid_id! {
    /// One domain event. The consumer idempotency key.
    pub struct EventId("event id")
}
uuid_id! {
    /// One entry of the evidence ledger.
    pub struct LedgerEntryId("ledger entry id")
}
uuid_id! {
    /// One specification contract.
    pub struct SpecId("specification id")
}
uuid_id! {
    /// One task plan.
    pub struct PlanId("plan id")
}
uuid_id! {
    /// One gate report.
    pub struct GateReportId("gate report id")
}
uuid_id! {
    /// One independent review.
    pub struct ReviewId("review id")
}
uuid_id! {
    /// One evidence manifest.
    pub struct ManifestId("manifest id")
}
uuid_id! {
    /// Shared by every event and log line that belongs to one job.
    pub struct CorrelationId("correlation id")
}
uuid_id! {
    /// The event or command that caused another event.
    pub struct CausationId("causation id")
}
uuid_id! {
    /// The identifier of an aggregate in a domain event. Which kind it is comes from the
    /// aggregate type next to it.
    pub struct AggregateId("aggregate id")
}
uuid_id! {
    /// One run of an experiment, cited as evidence.
    pub struct ExperimentRunId("experiment run id")
}
uuid_id! {
    /// A repository registered for a tenant.
    pub struct RepositoryId("repository id")
}
uuid_id! {
    /// One approver decision.
    pub struct ApprovalId("approval id")
}
uuid_id! {
    /// One recorded webhook delivery. This is the row, not the identifier GitHub puts in a header.
    pub struct WebhookDeliveryId("webhook delivery id")
}
uuid_id! {
    /// One audit record.
    pub struct AuditEventId("audit event id")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_new_identifiers_are_distinct_types_that_round_trip_as_text() {
        let uuid = uuid::Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0001);
        let repository = RepositoryId::from_uuid(uuid);
        let approval = ApprovalId::from_uuid(uuid);
        let delivery = WebhookDeliveryId::from_uuid(uuid);
        let audit = AuditEventId::from_uuid(uuid);
        assert_eq!(
            RepositoryId::parse(&repository.as_text()).unwrap(),
            repository
        );
        assert_eq!(ApprovalId::parse(&approval.as_text()).unwrap(), approval);
        assert_eq!(
            WebhookDeliveryId::parse(&delivery.as_text()).unwrap(),
            delivery
        );
        assert_eq!(AuditEventId::parse(&audit.as_text()).unwrap(), audit);
    }

    #[test]
    fn a_malformed_identifier_names_what_it_was_meant_to_be() {
        let message = RepositoryId::parse("not-a-uuid").unwrap_err().to_string();
        assert!(message.contains("repository id"), "{message}");
    }
}
