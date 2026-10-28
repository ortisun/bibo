//! The names of the deliverables the documentation stages read and write.
//!
//! The delivery stage reads `documentation-plan`, `documentation-gate-report` and
//! `documentation-review` by these exact names (`stages::delivery::input`). A package that names
//! them differently changes one constant there.

pub use crate::stages::implementation::input::{
    Candidate, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, input_artifact, parse_candidate,
    upstream_output,
};

/// The plan the `DOCUMENTING` stage derives. Read by the delivery stage.
pub const DOCUMENTATION_PLAN: &str = "documentation-plan";
/// What the `DOCUMENTING` stage did: the commits, the changed paths, the cited claims.
pub const DOCUMENTATION_RESULT: &str = "documentation-result";
/// The reports of the Documentation Quality Gate. Written by the `DOCUMENTATION_REVIEW` stage and
/// read by the delivery stage.
pub const DOCUMENTATION_GATE_REPORT: &str = "documentation-gate-report";
/// The independent documentation reviewer's verdict. Read by the delivery stage.
pub const DOCUMENTATION_REVIEW: &str = "documentation-review";
/// What the reviewer was given and what it returned.
pub const DOCUMENTATION_REVIEW_RECORD: &str = "documentation-review-record";
/// The domain profile written by the domain discovery stage. The documenting stage reads it when
/// it exists.
pub const DOMAIN_PROFILE: &str = "domain-profile";
