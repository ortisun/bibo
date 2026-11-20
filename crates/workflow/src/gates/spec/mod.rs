//! The deterministic specification gate.
//!
//! Work package `s1-spec-adapter-and-stage`. Spec Kit's own `analyze` needs a plan and tasks and
//! cannot validate a specification alone, so the factory has a gate of its own. It is pure: each
//! rule is a function of the typed [`SpecificationContract`] and plain values that the stage
//! hands in, with no port, no clock and no agent. The stage turns the findings into gate reports.
//! A language model never decides that a specification is sound.
//!
//! | Gate | Rules |
//! |---|---|
//! | `specification-structure` | The parse of the files, the scope boundary, the risks, a measurable criterion |
//! | `specification-identifiers` | Every identifier is unique |
//! | `specification-requirements` | Every requirement holds a requirement keyword, and names no technology |
//! | `specification-traceability` | Every requirement has a scenario, every scenario names a requirement, every reference resolves |
//! | `specification-clarity` | No marker, no placeholder and no open blocking question beyond what a person waived |
//! | `specification-contradictions` | Requirements that cannot both hold, found by fixed heuristics |
//! | `specification-safety` | A high risk has a mitigation or a safety constraint, and no requirement asks to bypass a control |
//! | `specification-authorization` | A draft carries no approval: authorization is a structured field written by a person |
//! | `specification-checklist` | Every checklist item is verified by an independent reviewer or waived by a person with a reason |
//! | `specification-artifacts` | The committed files are the recorded set and their hashes match |
//! | `stage_profile_check` | No skill outside the profile ran or was visible, no file of one appeared, and each skill run's transcript shows the fixed invocation and no other. It cannot be waived |
//!
//! # What counts as evidence for a checklist item
//!
//! Spec Kit's own ticks are self-assessed by the agent that wrote the specification. They are not
//! an input of this gate. An item counts only when the independent reviewer's verdict passed and
//! named no finding about the item, or when a person waived it and wrote a reason, in an answer
//! that the engine recorded with the person's identity.
//!
//! # Heuristics, and what they cannot do
//!
//! The contradiction rule finds a requirement that says MUST and another that says MUST NOT about
//! nearly the same words, two numeric bounds that cannot both hold, and the same sentence with two
//! priorities. It does not understand meaning. A finding goes to the writer to fix or to a person
//! to settle, and a miss is the independent reviewer's to catch.

pub mod checklist;
pub mod invocation;
pub mod profile;
pub mod rules;

pub use checklist::{ChecklistInput, Waiver, parse_waivers, resolve as resolve_checklist};
pub use invocation::InvocationRecord;
pub use profile::{ProfileEvidence, ProfileRules, SkillMention, scan_transcript};
pub use rules::Limits;

/// The gate for the parse of the files and the completeness of the sections.
pub const STRUCTURE: &str = "specification-structure";
/// The gate for unique identifiers.
pub const IDENTIFIERS: &str = "specification-identifiers";
/// The gate for requirement keywords and technology names.
pub const REQUIREMENTS: &str = "specification-requirements";
/// The gate for the links between requirements and scenarios.
pub const TRACEABILITY: &str = "specification-traceability";
/// The gate for markers, placeholders and open questions.
pub const CLARITY: &str = "specification-clarity";
/// The gate for requirements that conflict.
pub const CONTRADICTIONS: &str = "specification-contradictions";
/// The gate for safety constraints.
pub const SAFETY: &str = "specification-safety";
/// The gate for authorization.
pub const AUTHORIZATION: &str = "specification-authorization";
/// The gate for the checklist state.
pub const CHECKLIST: &str = "specification-checklist";
/// The gate for the committed artifact set and its hashes.
pub const ARTIFACTS: &str = "specification-artifacts";
/// The stage profile check. It is on the list of gates that cannot be waived
/// (`gate_integrity.nonwaivable_gates`).
pub const STAGE_PROFILE: &str = "stage_profile_check";

/// Every gate of the stage, in the order of its report.
pub const ALL: [&str; 11] = [
    STRUCTURE,
    IDENTIFIERS,
    REQUIREMENTS,
    TRACEABILITY,
    CLARITY,
    CONTRADICTIONS,
    SAFETY,
    AUTHORIZATION,
    CHECKLIST,
    ARTIFACTS,
    STAGE_PROFILE,
];

/// One thing a rule found: a code that tests and records use, and a sentence for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The code, such as `requirement-keyword-missing`.
    pub code: &'static str,
    /// What is wrong, in plain English, naming the item.
    pub message: String,
}

impl Finding {
    /// A finding.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// How the adapter's post-conditions are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// A violation of the stage profile or a leak into the arguments. The stage run is blocked and
    /// the output is discarded; nobody is asked to override it.
    Profile,
    /// The files are not what the skill should have left. The writer is asked to fix them.
    Structure,
    /// The links between requirements and scenarios are missing.
    Traceability,
}

/// The family of a post-condition the adapter reported. A name this table does not know is a
/// profile violation, so a new check of the adapter fails closed until someone classes it.
#[must_use]
pub fn family_of(name: &str) -> Family {
    match name {
        "feature-file-written"
        | "feature-pointer-valid"
        | "no-template-placeholder"
        | "checklist-present"
        | "custom-checklist-ticked" => Family::Structure,
        "requirement-without-scenario"
        | "scenario-without-requirement"
        | "scenario-identifier-duplicate"
        | "more-failures" => Family::Traceability,
        _ => Family::Profile,
    }
}
