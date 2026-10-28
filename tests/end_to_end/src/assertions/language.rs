//! A8: every human-facing artifact passes the readability gate, and a request in another language
//! gives English artifacts.

use factory_workflow::gates::readability::{Artifact, DocumentType, Options, Severity, check};

use crate::check::{Env, Verdict};
use crate::evidence::{Document, RunEvidence};

/// The kinds of document that every run must leave, so that a missing one is a finding and not a
/// silent pass.
pub const REQUIRED_KINDS: [&str; 4] = ["specification", "task", "pull_request", "documentation"];

fn artifact_of(document: &Document) -> Option<Artifact<'_>> {
    let artifact = match document.kind.as_str() {
        "specification" | "issue_reply" => Artifact::request(&document.title, &document.body),
        "task" | "plan" => Artifact::task(&document.title, &document.body),
        "pull_request" => Artifact::pull_request(&document.title, &document.body),
        "documentation" => {
            let doc_type = document
                .doc_type
                .as_deref()
                .and_then(DocumentType::parse)
                .unwrap_or(DocumentType::Reference);
            Artifact::documentation(&document.title, doc_type, &document.body)
        }
        _ => return None,
    };
    Some(artifact.at(&document.path))
}

/// A8: every human-facing artifact passes the readability gate. For E2 the specification, plan,
/// pull request and documentation are English.
///
/// The gate's `text-not-english` rule blocks Portuguese prose outside a marked quotation, so a
/// document that stayed in the language of the request fails here with that rule's name.
#[must_use]
pub fn a8(ev: &RunEvidence, env: &Env) -> Verdict {
    const ID: &str = "A8";
    for kind in REQUIRED_KINDS {
        if !ev.documents.iter().any(|document| document.kind == kind) {
            return Verdict::fail(ID, format!("the run left no {kind} to check"));
        }
    }
    let artifacts: Vec<Artifact<'_>> = ev.documents.iter().filter_map(artifact_of).collect();
    let findings = match check(&env.catalog, &Options::new(), &artifacts) {
        Ok(findings) => findings,
        Err(error) => {
            return Verdict::fail(ID, format!("the readability gate could not run: {error:?}"));
        }
    };
    if let Some(block) = findings
        .iter()
        .find(|finding| finding.severity == Severity::Block)
    {
        return Verdict::fail(
            ID,
            format!(
                "{} breaks the rule {} in its {}: {}",
                block.artifact,
                block.rule.as_str(),
                block.part.as_str(),
                block.message
            ),
        );
    }
    let warnings = findings.len();
    let language_note = if ev.source_language == "en" {
        String::new()
    } else {
        format!(
            "; the request was in {}, and the specification, plan, pull request and documentation passed the English rule",
            ev.source_language
        )
    };
    Verdict::pass(
        ID,
        format!(
            "{} artifact(s) pass the readability gate with {warnings} warning(s){language_note}",
            artifacts.len()
        ),
    )
}
