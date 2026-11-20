//! The pure function at the heart of the gate: artifacts in, findings out.

use super::artifact::Artifact;
use super::catalog::{Catalog, RuleId};
use super::finding::Finding;
use super::options::Options;
use super::rules::{self, Ctx};
use super::text::Body;

/// The most text the gate reads in one run, in bytes, titles and bodies together. A run over a
/// larger input does not check a prefix and pass. It refuses, and the gate report is `BLOCKED`.
pub const MAX_TOTAL_BYTES: usize = 1 << 20;

/// Why a run could not check the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    /// The artifacts hold more text than the gate reads in one run.
    #[error(
        "the artifacts hold {bytes} bytes of text, more than the {MAX_TOTAL_BYTES} the gate reads in one run"
    )]
    TooLarge {
        /// The size of the text handed over.
        bytes: usize,
    },
}

/// Checks every artifact against every deterministic rule that applies to it and that the
/// options leave on, and returns the findings in artifact order, then rule order.
///
/// The function is pure: the same input gives the same findings, and the text is only borrowed.
///
/// # Errors
/// [`CheckError::TooLarge`] when the text is larger than [`MAX_TOTAL_BYTES`]. Nothing is checked
/// in that case.
pub fn check(
    catalog: &Catalog,
    options: &Options,
    artifacts: &[Artifact<'_>],
) -> Result<Vec<Finding>, CheckError> {
    let bytes = artifacts.iter().fold(0_usize, |sum, artifact| {
        sum.saturating_add(artifact.title.len())
            .saturating_add(artifact.body.len())
    });
    if bytes > MAX_TOTAL_BYTES {
        return Err(CheckError::TooLarge { bytes });
    }
    let mut findings = Vec::new();
    for artifact in artifacts {
        let ctx = Ctx {
            catalog,
            artifact,
            body: Body::new(artifact.body),
        };
        for rule in RuleId::ALL.iter().copied() {
            let Some(spec) = catalog.rule(rule) else {
                continue;
            };
            if !spec.applies_to.contains(&artifact.kind) || options.is_disabled(catalog, rule) {
                continue;
            }
            if let Some(draft) = rules::run(rule, &ctx) {
                findings.push(Finding {
                    rule,
                    severity: spec.severity,
                    artifact: artifact.path.to_owned(),
                    part: draft.part,
                    line: draft.line,
                    message: draft.message,
                    suggested_fix: spec.suggested_fix.clone(),
                });
            }
        }
    }
    Ok(findings)
}
