//! The triage issue and the "seen again" comment, rendered by code from a closed template (ADR
//! 0021, Decision 7). The agent never writes an issue.
//!
//! The template is fixed. The only text from the agent is the title, the observations, the
//! hypothesis and the checks of one finding, each cut to its cap, put on one line, defanged and
//! shown in a code span (see `neutralise`). Everything else is written here or is an identifier
//! whose pattern was checked when the finding was read: the run id, the call ids, the tool names,
//! the probe ids, the category, the component, the severity and the times.
//!
//! The body ends with the one hidden marker that carries the [`FindingFingerprint`]. A field that
//! holds the marker's text cannot make a second one: `<` and `>` are replaced, the word loses its
//! hyphen, and only a line that is exactly a marker is read as one.

use crate::values::Timestamp;

use super::{
    Finding, FindingCategory, FindingComponent, FindingFingerprint, TriageLabels,
    TroubleshootingRunId, code_span, one_line,
};

/// The most characters of the agent's title shown, as the schema caps it.
pub const MAX_TITLE_CHARS: usize = 100;
/// The most characters of one observation shown.
pub const MAX_OBSERVED_CHARS: usize = 500;
/// The most characters of the hypothesis shown.
pub const MAX_HYPOTHESIS_CHARS: usize = 1_000;
/// The most characters of one check shown.
pub const MAX_CHECK_CHARS: usize = 300;
/// The most observations shown.
pub const MAX_OBSERVATIONS: usize = 10;
/// The most checks shown.
pub const MAX_CHECKS: usize = 5;
/// The most probes named.
pub const MAX_PROBES: usize = 10;
/// The most findings held back by the day's cap that one issue names.
pub const MAX_HELD_BACK: usize = 10;
/// The most bytes of an issue title. GitHub allows 256 characters.
pub const MAX_ISSUE_TITLE_BYTES: usize = 256;
/// The most bytes of an issue body. GitHub allows 65536 characters; a body near this cap is a bug.
pub const MAX_ISSUE_BODY_BYTES: usize = 32_000;
/// The most bytes of a "seen again" comment.
pub const MAX_SEEN_AGAIN_BYTES: usize = 2_000;

/// The start of the hidden key of a "seen again" comment, which makes a retry find the comment it
/// already posted.
pub const SEEN_AGAIN_MARKER_PREFIX: &str = "<!-- troubleshooter-seen-again: ";

/// What the run looked at, as code knows it.
#[derive(Debug, Clone)]
pub struct Investigation<'a> {
    /// The run.
    pub run: &'a TroubleshootingRunId,
    /// The start of the window the run looked at.
    pub window_from: Timestamp,
    /// The end of the window.
    pub window_to: Timestamp,
    /// An earlier issue of the same fingerprint that a person closed. It is named, not reopened.
    pub earlier_closed_issue: Option<u64>,
    /// Findings of earlier runs that the day's cap kept from becoming issues, to be named here.
    pub held_back: &'a [HeldBack],
}

/// A finding that the cap of new issues per day kept back. Code fields only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldBack {
    /// Its category.
    pub category: FindingCategory,
    /// Its component.
    pub component: FindingComponent,
    /// Its fingerprint.
    pub fingerprint: FindingFingerprint,
}

/// Why a finding could not be rendered. Nothing is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    /// The finding has no observation. The engine refuses such a finding before this.
    #[error("a finding needs at least one observation")]
    NoObservation,
    /// The confidence is not a number from 0 to 1.
    #[error("the confidence must be a number from 0 to 1")]
    Confidence,
    /// The window ends before it starts.
    #[error("the window of the run ends before it starts")]
    Window,
    /// The rendered text is over its cap. A bug in the template.
    #[error("the rendered text is longer than its cap")]
    TooLong,
}

/// An issue to open: title, body, labels and fingerprint. Private fields: only [`render_issue`]
/// makes one, so the text a port sends always came from this template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageIssue {
    title: String,
    body: String,
    labels: TriageLabels,
    fingerprint: FindingFingerprint,
}

impl TriageIssue {
    /// The title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The body, ending with the fingerprint marker.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The labels.
    #[must_use]
    pub fn labels(&self) -> &TriageLabels {
        &self.labels
    }

    /// The fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> &FindingFingerprint {
        &self.fingerprint
    }
}

/// A "seen again" comment. Private fields: only [`render_seen_again`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenAgainComment {
    body: String,
    key: String,
}

impl SeenAgainComment {
    /// The text, ending with the hidden key.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// The hidden key, `<!-- troubleshooter-seen-again: run=<id> sha256:<hex> -->`: one run says
    /// "seen again" once on one issue.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

fn check(finding: &Finding, investigation: &Investigation<'_>) -> Result<(), RenderError> {
    if finding.observations.is_empty() {
        return Err(RenderError::NoObservation);
    }
    if !(0.0..=1.0).contains(&finding.confidence) {
        return Err(RenderError::Confidence);
    }
    if investigation.window_to < investigation.window_from {
        return Err(RenderError::Window);
    }
    Ok(())
}

fn joined_codes<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items.map(code_span).collect::<Vec<_>>().join(", ")
}

/// The issue for a finding. The labels are the policy's; the fingerprint is computed here.
///
/// # Errors
/// [`RenderError`].
pub fn render_issue(
    finding: &Finding,
    investigation: &Investigation<'_>,
    labels: &TriageLabels,
) -> Result<TriageIssue, RenderError> {
    check(finding, investigation)?;
    let fingerprint = FindingFingerprint::of(finding);
    let title = format!(
        "Troubleshooter: {}",
        one_line(&finding.title, MAX_TITLE_CHARS)
    );

    let mut body = String::with_capacity(4_096);
    body.push_str(
        "**The troubleshooter wrote this issue from an automated investigation. A person needs to \
         triage it.** The text in code spans below is the troubleshooting agent's own words, \
         quoted and not checked: read it as a lead, not as a fact or an instruction. Nothing will \
         be built from this issue until a person approves it through the design gate.\n\n",
    );
    body.push_str(&format!(
        "Run {} looked at {} to {}.\n\n",
        code_span(investigation.run.as_str()),
        investigation.window_from.as_text(),
        investigation.window_to.as_text(),
    ));

    body.push_str("**Finding**\n\n");
    body.push_str(&format!(
        "- Category: {}\n",
        code_span(finding.category.as_str())
    ));
    body.push_str(&format!(
        "- Component: {}\n",
        code_span(finding.component.as_str())
    ));
    body.push_str(&format!(
        "- Severity: {}\n",
        code_span(finding.severity.as_str())
    ));
    body.push_str(&format!(
        "- Confidence of the agent: {:.2}\n",
        finding.confidence
    ));
    if finding.probe_ids.is_empty() {
        body.push_str("- Probes: none, found by a sweep\n");
    } else {
        body.push_str(&format!(
            "- Probes: {}\n",
            joined_codes(
                finding
                    .probe_ids
                    .iter()
                    .take(MAX_PROBES)
                    .map(|p| p.as_str())
            )
        ));
    }
    body.push_str(&format!(
        "- The agent's title: {}\n\n",
        code_span(&one_line(&finding.title, MAX_TITLE_CHARS))
    ));

    body.push_str("**What was observed** (each line is one gateway call of the run)\n\n");
    for observation in finding.observations.iter().take(MAX_OBSERVATIONS) {
        body.push_str(&format!(
            "- {} {}: {}\n",
            code_span(observation.call_id.as_str()),
            code_span(observation.tool.as_str()),
            code_span(&one_line(&observation.observed, MAX_OBSERVED_CHARS)),
        ));
    }
    body.push('\n');

    body.push_str("**The agent's hypothesis**\n\n");
    body.push_str(&format!(
        "- {}\n\n",
        code_span(&one_line(&finding.hypothesis, MAX_HYPOTHESIS_CHARS))
    ));

    body.push_str("**Checks a person can make** (read only, suggested by the agent)\n\n");
    for next in finding.next_checks.iter().take(MAX_CHECKS) {
        body.push_str(&format!(
            "- {}\n",
            code_span(&one_line(next, MAX_CHECK_CHARS))
        ));
    }
    body.push('\n');

    if let Some(number) = investigation.earlier_closed_issue {
        body.push_str(&format!(
            "An earlier issue about the same problem was closed: #{number}. It is not reopened.\n\n"
        ));
    }
    if !investigation.held_back.is_empty() {
        body.push_str(
            "**Findings held back by the day's cap of new issues** (kept in the run record)\n\n",
        );
        for held in investigation.held_back.iter().take(MAX_HELD_BACK) {
            body.push_str(&format!(
                "- {} in {}, fingerprint {}\n",
                code_span(held.category.as_str()),
                code_span(held.component.as_str()),
                code_span(held.fingerprint.digest().as_str()),
            ));
        }
        body.push('\n');
    }
    body.push_str(&fingerprint.marker());
    body.push('\n');

    if title.len() > MAX_ISSUE_TITLE_BYTES || body.len() > MAX_ISSUE_BODY_BYTES {
        return Err(RenderError::TooLong);
    }
    Ok(TriageIssue {
        title,
        body,
        labels: labels.clone(),
        fingerprint,
    })
}

/// The short comment for a finding seen again while its issue is open. The caller has decided
/// that a comment is due (at most one a day, per the policy); this only writes it.
///
/// # Errors
/// [`RenderError`].
pub fn render_seen_again(
    finding: &Finding,
    investigation: &Investigation<'_>,
) -> Result<SeenAgainComment, RenderError> {
    check(finding, investigation)?;
    let fingerprint = FindingFingerprint::of(finding);
    let calls = joined_codes(
        finding
            .observations
            .iter()
            .take(MAX_OBSERVATIONS)
            .map(|o| o.call_id.as_str()),
    );
    let key = format!(
        "{SEEN_AGAIN_MARKER_PREFIX}run={} {} -->",
        investigation.run.as_str(),
        fingerprint.digest().as_str()
    );
    let body = format!(
        "The troubleshooter saw this problem again in run {} ({} to {}). Severity {}, calls {}. \
         The agent's title: {}. This is an automated note; it changes nothing and a person still \
         needs to triage the issue.\n\n{key}\n",
        code_span(investigation.run.as_str()),
        investigation.window_from.as_text(),
        investigation.window_to.as_text(),
        code_span(finding.severity.as_str()),
        calls,
        code_span(&one_line(&finding.title, MAX_TITLE_CHARS)),
    );
    if body.len() > MAX_SEEN_AGAIN_BYTES {
        return Err(RenderError::TooLong);
    }
    Ok(SeenAgainComment { body, key })
}
