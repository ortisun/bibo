//! Names from the pipeline and assurance sections of `state-machine.json`.
//!
//! Written from the JSON file. The conformance test compares the stage
//! kinds (with the stages each one waits for), the assurance levels and the release states with
//! the file.

use crate::macros::string_enum;

string_enum! {
    /// The kind of a stage, in the order the pipeline runs them.
    pub enum StageKind("stage kind") {
        Intake = "INTAKE",
        RepositoryIntelligence = "REPOSITORY_INTELLIGENCE",
        Specification = "SPECIFICATION",
        DomainDiscovery = "DOMAIN_DISCOVERY",
        Architecture = "ARCHITECTURE",
        TaskPlanning = "TASK_PLANNING",
        Implementation = "IMPLEMENTATION",
        Validation = "VALIDATION",
        Review = "REVIEW",
        Documenting = "DOCUMENTING",
        DocumentationReview = "DOCUMENTATION_REVIEW",
        Delivery = "DELIVERY",
        Approval = "APPROVAL",
        Merge = "MERGE",
    }
}

impl StageKind {
    /// The stage kinds whose passed, non-superseded run must exist before a run of this kind can
    /// leave `PENDING`. Guard `G_UPSTREAM_PASSED` applies it.
    #[must_use]
    pub const fn requires(self) -> &'static [StageKind] {
        match self {
            StageKind::Intake => &[],
            StageKind::RepositoryIntelligence => &[StageKind::Intake],
            StageKind::Specification => &[StageKind::Intake, StageKind::RepositoryIntelligence],
            StageKind::DomainDiscovery => &[StageKind::Specification],
            StageKind::Architecture => &[StageKind::Specification, StageKind::DomainDiscovery],
            StageKind::TaskPlanning => &[StageKind::Architecture],
            StageKind::Implementation => &[StageKind::TaskPlanning],
            StageKind::Validation => &[StageKind::Implementation],
            StageKind::Review => &[StageKind::Validation],
            StageKind::Documenting => &[StageKind::Review],
            StageKind::DocumentationReview => &[StageKind::Documenting],
            StageKind::Delivery => &[StageKind::DocumentationReview],
            StageKind::Approval => &[StageKind::Delivery],
            StageKind::Merge => &[StageKind::Approval],
        }
    }
}

string_enum! {
    /// How far the work has been verified. These are claims backed by ledger entries. They are not
    /// job states and they are not ordered: `VERIFIED_ON_DEVICE` does not imply
    /// `VERIFIED_IN_SIMULATOR`.
    pub enum AssuranceLevel("assurance level") {
        Specified = "SPECIFIED",
        Implemented = "IMPLEMENTED",
        VerifiedInSandbox = "VERIFIED_IN_SANDBOX",
        VerifiedInSimulator = "VERIFIED_IN_SIMULATOR",
        VerifiedOnDevice = "VERIFIED_ON_DEVICE",
        PaperValidated = "PAPER_VALIDATED",
        ProductionReady = "PRODUCTION_READY",
    }
}

string_enum! {
    /// Where a change stands after approval. A second axis, independent of the job status. The
    /// factory stops at `APPROVED` in Slice 1 and a human merges.
    pub enum ReleaseState("release state") {
        NoRelease = "NONE",
        Approved = "APPROVED",
        Merged = "MERGED",
        Released = "RELEASED",
        Deployed = "DEPLOYED",
        Observed = "OBSERVED",
    }
}
