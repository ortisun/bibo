//! The deterministic rules, one function for each, and the table that finds them by identifier.
//!
//! A rule function takes a [`Ctx`] and returns a [`Draft`] when the text breaks the rule, and
//! `None` otherwise. It never changes anything, never panics and does an amount of work
//! proportional to the text. The engine turns a draft into a finding: the severity and the
//! suggested fix come from the catalog, not from the function.

mod structure;
mod title;

use super::artifact::Artifact;
use super::catalog::{Catalog, RuleId};
use super::finding::Part;
use super::text::Body;

/// What a rule can see: the catalog, the artifact and its body split into lines.
pub(super) struct Ctx<'a> {
    pub(super) catalog: &'a Catalog,
    pub(super) artifact: &'a Artifact<'a>,
    pub(super) body: Body<'a>,
}

/// A rule's answer: where the problem is and what is wrong, in plain English.
pub(super) struct Draft {
    pub(super) part: Part,
    pub(super) line: Option<u32>,
    pub(super) message: String,
}

impl Draft {
    pub(super) const fn title(message: String) -> Self {
        Self {
            part: Part::Title,
            line: None,
            message,
        }
    }
}

/// Runs one rule.
pub(super) fn run(rule: RuleId, ctx: &Ctx<'_>) -> Option<Draft> {
    match rule {
        RuleId::TitleSchemaShape => title::schema_shape(ctx),
        RuleId::TitleOpaquePrefix => title::opaque_prefix(ctx),
        RuleId::TitleMachineLabel => title::machine_label(ctx),
        RuleId::TitleVague => title::vague(ctx),
        RuleId::TitleTypeTag => title::type_tag(ctx),
        RuleId::TitleNotSentenceCase => title::not_sentence_case(ctx),
        RuleId::TitleTooLong => title::too_long(ctx),
        RuleId::TitleTrailingPunctuation => title::trailing_punctuation(ctx),
        RuleId::TaskMissingSection => structure::task_missing_section(ctx),
        RuleId::BodyMetadataPrefix => structure::metadata_prefix(ctx),
        RuleId::BodyMetadataLines => structure::metadata_lines(ctx),
        RuleId::PrMissingEvidenceLink => structure::missing_evidence_link(ctx),
        RuleId::DocGuideMissingPart => structure::guide_missing_part(ctx),
        _ => None,
    }
}
