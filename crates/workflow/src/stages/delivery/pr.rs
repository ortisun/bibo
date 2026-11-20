//! The title and body of the draft pull request.
//!
//! Every sentence is written by this module from typed evidence: counts, outcomes, hashes, the
//! native number of the issue and the version of the specification. The two pieces of earlier
//! text that are placed in a sentence, the title of the frozen specification and the labels of the
//! linked documents, pass through [`fragment`](super::text::fragment) first. No summary, finding
//! text or explanation that an agent wrote is copied. The finished text is checked as a whole by
//! [`finish`](super::text::finish) before it can be sent.
//!
//! The body is English and plain: short sentences, a table of the checks, and a list of what was
//! not verified. It links the issue by its native number (`#12`), and the documents on the branch
//! by a link to the code host at the head commit, so a reader can follow every claim to its
//! evidence (rule `pr-missing-evidence-link`).

use factory_domain::contracts::EvidenceManifest;
use factory_domain::policy::risk::RiskAssessment;
use factory_domain::redaction::Redactor;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::GateOutcome;

use super::input::Dossier;
use super::manifest::{ChangeFacts, score_of};
use super::seams::DeliveryTarget;
use super::text::{TextRefused, ensure_no_secret, finish, fragment};

/// The hosts a link in the pull request may point to.
pub const LINK_HOSTS: [&str; 1] = ["github.com"];

/// What the text is made from.
#[derive(Debug, Clone, Copy)]
pub struct PrFacts<'a> {
    /// The stored evidence.
    pub dossier: &'a Dossier,
    /// The manifest the body points at.
    pub manifest: &'a EvidenceManifest,
    /// Its hash.
    pub manifest_hash: &'a Sha256Digest,
    /// Where and what the job delivers.
    pub target: &'a DeliveryTarget,
    /// The tier the policy computed.
    pub risk: &'a RiskAssessment,
    /// The size of the change.
    pub change: &'a ChangeFacts,
}

/// A title and a body that passed the checks of [`finish`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrText {
    /// One line.
    pub title: String,
    /// Markdown.
    pub body: String,
}

fn words(outcome: GateOutcome) -> &'static str {
    match outcome {
        GateOutcome::Passed => "passed",
        GateOutcome::Failed => "failed",
        GateOutcome::Blocked => "could not run",
        GateOutcome::NotApplicable => "does not apply",
    }
}

fn plural(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{count} {one}")
    } else {
        format!("{count} {many}")
    }
}

/// The title of the pull request and of the manifest: the title of the frozen specification with
/// everything that is not plain words removed. A title that holds a secret, or is too short after
/// cleaning, is replaced by a fixed sentence about the issue, and the answer says the original was
/// not clean, so the caller can refuse the text. The raw title is never returned.
#[must_use]
pub fn safe_title(raw: &str, issue: u64, redactor: &Redactor) -> (String, bool) {
    let fallback = || format!("Resolve issue {issue}");
    if ensure_no_secret(raw, redactor).is_err() {
        return (fallback(), false);
    }
    let cleaned = fragment(raw);
    if cleaned.chars().count() >= 3 {
        (cleaned, true)
    } else {
        (fallback(), true)
    }
}

/// Writes the title and the body, and checks them.
///
/// # Errors
/// [`TextRefused`] when the finished text holds a secret, markup, a link that is not allowed, or
/// is empty or too long.
pub fn compose(facts: &PrFacts<'_>, redactor: &Redactor) -> Result<PrText, TextRefused> {
    let d = facts.dossier;
    let issue = facts.target.issue.number;
    // The raw pieces of earlier text are scanned as they were written, before they are cleaned.
    ensure_no_secret(d.specification.title.as_str(), redactor)?;
    for link in &facts.target.links {
        ensure_no_secret(&link.label, redactor)?;
    }
    let (title, _) = safe_title(d.specification.title.as_str(), issue, redactor);
    let spec_title = title.clone();

    let mut body = String::new();
    body.push_str(&format!(
        "This change implements version {} of the frozen specification, \"{}\", for issue #{issue}. It changes {}: {} added and {} removed.\n\n",
        d.specification.metadata.spec_version.get(),
        spec_title,
        plural(facts.change.files_changed, "file", "files"),
        plural(facts.change.insertions, "line", "lines"),
        plural(facts.change.deletions, "line", "lines"),
    ));
    body.push_str(&format!("Closes #{issue}.\n\n"));

    body.push_str("What was checked\n\n| Check | Result |\n|---|---|\n");
    for report in &d.validation.reports {
        body.push_str(&format!(
            "| {} | {} |\n",
            fragment(report.metadata.gate_id.as_str()),
            words(report.outcome)
        ));
    }
    let findings = d.review.findings.len();
    body.push_str(&format!(
        "\nAn independent reviewer read the change and the gate reports and gave the verdict {} with {}.\n\n",
        d.review.verdict.as_str().to_lowercase(),
        plural(findings as u64, "finding", "findings"),
    ));

    body.push_str(&format!(
        "Risk\n\nThe policy computed the tier {} (score {} of 100). It needs {} before anyone merges.\n\n",
        facts.risk.tier.as_str(),
        score_of(facts.risk.tier),
        plural(u64::from(facts.risk.required_approvals), "approval", "approvals"),
    ));

    let repo = facts.target.repo.to_string();
    let head = facts.manifest.metadata.repository.head_commit.as_str();
    body.push_str("Evidence\n\n");
    body.push_str(&format!(
        "- Evidence manifest hash: `{}`\n",
        facts.manifest_hash.hex()
    ));
    body.push_str(&format!(
        "- Specification version {}: `{}`\n",
        d.specification.metadata.spec_version.get(),
        d.specification_sha256.hex()
    ));
    body.push_str(&format!(
        "- Task plan version {}: `{}`\n",
        d.plan.metadata.plan_version.get(),
        d.plan_sha256.hex()
    ));
    body.push_str(&format!(
        "- Architecture design: `{}`\n",
        d.architecture_sha256.hex()
    ));
    body.push_str(&format!(
        "- Documentation plan: `{}`\n",
        d.documentation_plan_sha256.hex()
    ));
    body.push_str(&format!(
        "- Ledger head, entry {}: `{}`\n",
        facts.manifest.ledger.head_sequence.get(),
        facts.manifest.ledger.head_hash.hex()
    ));
    for link in &facts.target.links {
        let label = fragment(&link.label);
        if label.is_empty() {
            continue;
        }
        body.push_str(&format!(
            "- {label}: [{path}](https://github.com/{repo}/blob/{head}/{path})\n",
            path = link.path.as_str()
        ));
    }

    body.push_str("\nWhat was not verified\n\n");
    for limitation in facts.manifest.limitations.as_slice() {
        body.push_str(&format!("- {}\n", fragment_sentence(limitation.as_str())));
    }

    body.push_str(
        "\nWhat happens next\n\nThis is a draft pull request. A person reads it, marks it ready for review and merges it on the code host. The factory does not merge and does not deploy.\n",
    );

    finish(&title, redactor, &LINK_HOSTS)?;
    finish(&body, redactor, &LINK_HOSTS)?;
    Ok(PrText { title, body })
}

/// A sentence the manifest wrote, kept as a sentence: the manifest limitations are made by this
/// stage from fixed templates and gate identifiers, so only hidden and markup characters are
/// removed.
fn fragment_sentence(sentence: &str) -> String {
    sentence
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | '[' | ']' | '`' | '@' | '|'))
        .collect()
}
