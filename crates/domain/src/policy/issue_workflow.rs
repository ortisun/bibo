//! `policies/issue-workflow.yaml` as typed values, the rules that file must satisfy, and the one
//! type that may name a status label: [`StatusLabel`].
//!
//! # What the file decides
//!
//! The policy names the labels an issue carries (the trigger label, the `design:` track written by
//! people and the `factory:` track written by the factory's GitHub App) and maps each job state of
//! the engine to exactly one `factory:` label. The Python tool `scripts/lib/issue_workflow.py`
//! checks the same file and renders `onboarding/github/issue-workflow.json` for the installer and
//! the Action. The rules in [`IssueWorkflowPolicy::problems`] are the Rust side of that check, and
//! a test compares the two renderings, so the two languages cannot disagree about a label.
//!
//! # The label that cannot be wrong
//!
//! The factory writes the state of a job onto its issue as one `factory: <state>` label. A label
//! that is not in that namespace must never be written: not the trigger label `factory` (a label
//! alone never authorizes work), not a `design:` label (people write those), not any other label.
//! [`StatusLabel`] makes the wrong call impossible to write:
//!
//! * its fields are private and it has no `Deserialize`, no `Default` and no constructor from text;
//! * the only way to get one is [`StatusLabels::label_for`], and the only way to get
//!   [`StatusLabels`] is [`IssueWorkflowPolicy::status_labels`], which refuses a policy that breaks
//!   any rule of this module;
//! * [`check_status_label_name`] is the one pure test of a name, used here when the labels are built
//!   and again by every adapter before it sends a label (defense in depth).
//!
//! One function is meant for tests only: [`StatusLabel::forged_for_negative_tests`]. It exists so
//! that an adapter's own refusal can be shown to work. The architecture check ST-13 names the crates
//! that may call it.
//!
//! No policy type implements `Default`: a missing policy is an error, never an empty allow.

use std::collections::BTreeSet;
use std::fmt;

use super::common::{PolicyStatus, SchemaVersionOne, strict};
use super::decision::Designation;
use crate::state::JobStatus;

/// The prefix of every label the factory writes. The factory has this namespace to itself.
pub const STATUS_PREFIX: &str = "factory: ";

/// The prefix of the labels people write while a design is worked out.
pub const DESIGN_PREFIX: &str = "design: ";

/// The longest label name GitHub accepts, in characters.
pub const MAX_LABEL_NAME: usize = 50;

/// The longest label description GitHub accepts, in characters.
pub const MAX_LABEL_DESCRIPTION: usize = 100;

/// The key path of the list of factory states, for the messages of a broken policy. Written with
/// `concat!` because the telemetry name scan (ST-07) reads a string literal that starts with
/// `factory_` as a metric name.
const STATES_KEY: &str = concat!("factory", "_track.states");

strict! {
    /// The whole of `policies/issue-workflow.yaml`.
    pub struct IssueWorkflowPolicy {
        /// Always 1.
        pub schema_version: SchemaVersionOne,
        /// Identity and status of the policy.
        pub policy: WorkflowHeader,
        /// The label whose application by an authorized person starts a job.
        pub trigger: TriggerLabel,
        /// The two label namespaces and who writes each.
        pub namespaces: Namespaces,
        /// The design track, written by people.
        pub design_track: DesignTrack,
        /// The factory track, written by the factory.
        pub factory_track: FactoryTrack,
        /// What the engine must check when the trigger label is applied.
        pub intake_requirements: IntakeRequirements,
    }
}

strict! {
    /// Identity and status of the policy.
    pub struct WorkflowHeader {
        /// Always `issue-workflow`.
        pub id: String,
        /// Designed or enforced. Nothing switches on it.
        pub status: PolicyStatus,
    }
}

strict! {
    /// The trigger label.
    pub struct TriggerLabel {
        /// The label name, outside both namespaces.
        pub label: String,
        /// Six lower-case hex digits.
        pub color: String,
        /// One sentence.
        pub description: String,
    }
}

strict! {
    /// The two namespaces.
    pub struct Namespaces {
        /// The `design:` namespace, written by people.
        pub design: Namespace,
        /// The `factory:` namespace, written by the factory.
        pub factory: Namespace,
    }
}

strict! {
    /// One label namespace.
    pub struct Namespace {
        /// The prefix, such as `factory: `.
        pub prefix: String,
        /// `people` or `factory`.
        pub written_by: String,
    }
}

strict! {
    /// The design track.
    pub struct DesignTrack {
        /// The states an issue may take first.
        pub start_states: Vec<String>,
        /// The states.
        pub states: Vec<LabelState>,
        /// The legal moves.
        pub transitions: Vec<DesignMove>,
        /// What moving to `approved` needs.
        pub approval_requires: ApprovalRequires,
    }
}

strict! {
    /// A design state and its label.
    pub struct LabelState {
        /// The name after the prefix.
        pub name: String,
        /// Six lower-case hex digits.
        pub color: String,
        /// One sentence, at most 100 characters.
        pub description: String,
    }
}

strict! {
    /// A legal move between design states.
    pub struct DesignMove {
        /// The state the issue leaves.
        pub from: String,
        /// The state it enters.
        pub to: String,
    }
}

strict! {
    /// What approval of a design needs.
    pub struct ApprovalRequires {
        /// The design document.
        pub design_document: DesignDocument,
    }
}

strict! {
    /// Where the design document is named and where it must be.
    pub struct DesignDocument {
        /// The field of the issue body that names the document.
        pub issue_body_field: String,
        /// The glob the path must match.
        pub path_glob: String,
    }
}

strict! {
    /// The factory track.
    pub struct FactoryTrack {
        /// One entry for each job state.
        pub states: Vec<FactoryState>,
    }
}

strict! {
    /// A job state and the label that shows it.
    pub struct FactoryState {
        /// A job state of the engine, such as `WAITING_FOR_HUMAN`.
        pub job_state: String,
        /// The name after the prefix.
        pub name: String,
        /// Six lower-case hex digits.
        pub color: String,
        /// One sentence, at most 100 characters.
        pub description: String,
    }
}

strict! {
    /// What the engine checks when the trigger label is applied.
    pub struct IntakeRequirements {
        /// The design state an issue on the design track needs before a job may start.
        pub design_track_requires: String,
        /// The designation that the person who applied the label of that state must hold on the
        /// protected allowlist, such as `approver`. A designation by name, matched by numeric
        /// GitHub user id; never a GitHub role. Pending confirmation by the architect (ADR 0016).
        pub design_approved_by: String,
    }
}

/// What kind of rule a [`Problem`] breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    /// A name used twice.
    Duplicate,
    /// A name that nothing defines, or a job state the engine does not have.
    Unknown,
    /// A glob or field that has the wrong shape.
    Shape,
    /// Another rule of the policy.
    Constraint,
}

/// One rule the policy breaks: where, what kind and what to change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The key path, such as `factory_track.states[3].name`.
    pub path: String,
    /// The kind of rule.
    pub kind: ProblemKind,
    /// Plain English.
    pub message: String,
}

fn problem(path: impl Into<String>, kind: ProblemKind, message: impl Into<String>) -> Problem {
    Problem {
        path: path.into(),
        kind,
        message: message.into(),
    }
}

/// Why a name is not a status label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BadStatusLabel {
    /// The name does not start with `factory: `. This covers the trigger label, a `design:` label
    /// and every other label.
    #[error("a status label starts with `factory: `")]
    WrongNamespace,
    /// Nothing follows the prefix.
    #[error("a status label needs a name after `factory: `")]
    EmptyName,
    /// More than 50 characters.
    #[error("a label name is at most 50 characters")]
    TooLong,
    /// A character that is not printable ASCII.
    #[error("a label name is printable ASCII")]
    NotPrintable,
    /// A space or tab at either edge.
    #[error("a label name has no space at either edge")]
    EdgeSpace,
}

/// The one test of a status label name. Pure. The policy loader applies it to every name it builds,
/// and an adapter applies it again to every label it is about to send.
///
/// # Errors
/// [`BadStatusLabel`] for the first rule the name breaks.
pub fn check_status_label_name(name: &str) -> Result<(), BadStatusLabel> {
    let Some(rest) = name.strip_prefix(STATUS_PREFIX) else {
        return Err(BadStatusLabel::WrongNamespace);
    };
    if rest.is_empty() {
        return Err(BadStatusLabel::EmptyName);
    }
    if name.chars().count() > MAX_LABEL_NAME {
        return Err(BadStatusLabel::TooLong);
    }
    if !name.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(BadStatusLabel::NotPrintable);
    }
    if rest.starts_with([' ', '\t']) || rest.ends_with([' ', '\t']) {
        return Err(BadStatusLabel::EdgeSpace);
    }
    Ok(())
}

/// The label that shows one job state on an issue. See the module notes for why it cannot be
/// built from text.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StatusLabel {
    name: String,
    state: JobStatus,
}

impl StatusLabel {
    /// The full name, such as `factory: working`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The job state this label shows.
    #[must_use]
    pub fn job_state(&self) -> JobStatus {
        self.state
    }

    /// For the negative tests of an adapter, and for nothing else: a value that skips the policy,
    /// so that an adapter's own check can be shown to refuse a name that the type is built to keep
    /// out. The state is the first one, because a forged label does not show a state.
    ///
    /// **It does not exist in a production build** (finding STS-5). It is compiled only for this
    /// crate's own unit tests and when the feature `forge-status-labels` is on, and only the test
    /// kit turns that feature on; the test kit is a dev-dependency of every crate that uses it.
    /// The architecture check ST-13 adds a second barrier: it refuses any mention of the function
    /// outside the test kit, a call or a pointer to it alike.
    #[cfg(any(test, feature = "forge-status-labels"))]
    #[doc(hidden)]
    #[must_use]
    pub fn forged_for_negative_tests(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            state: JobStatus::Received,
        }
    }
}

impl fmt::Debug for StatusLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatusLabel({:?})", self.name)
    }
}

impl fmt::Display for StatusLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// The ten status labels of a policy that passed every rule, one for each job state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLabels {
    labels: Vec<StatusLabel>,
}

impl StatusLabels {
    /// The label for a job state. Every state has one, because the policy that built this value
    /// has no state without one.
    ///
    /// # Panics
    /// Never for a value built by [`IssueWorkflowPolicy::status_labels`].
    #[must_use]
    pub fn label_for(&self, state: JobStatus) -> &StatusLabel {
        self.labels
            .iter()
            .find(|label| label.state == state)
            .unwrap_or_else(|| unreachable!("the policy has a label for every job state"))
    }

    /// Every label, in the order of [`JobStatus::ALL`].
    pub fn iter(&self) -> impl Iterator<Item = &StatusLabel> {
        self.labels.iter()
    }
}

fn label_problems(name: &str, color: &str, description: &str) -> Vec<String> {
    let mut found = Vec::new();
    let printable = name.bytes().all(|b| (0x20..=0x7e).contains(&b));
    let length = name.chars().count();
    if !(1..=MAX_LABEL_NAME).contains(&length) || !printable || name != name.trim() {
        found.push(format!(
            "the label name {name:?} must be 1 to {MAX_LABEL_NAME} printable ASCII characters with no space at either edge"
        ));
    }
    let hex = color.len() == 6
        && color
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex {
        found.push(format!(
            "the color {color:?} must be six lower-case hex digits"
        ));
    }
    let words = description.chars().count();
    if !(1..=MAX_LABEL_DESCRIPTION).contains(&words) || description.chars().any(|c| c < ' ') {
        found.push(format!(
            "the description of {name:?} must be 1 to {MAX_LABEL_DESCRIPTION} characters with no control character"
        ));
    }
    found
}

fn glob_is_a_design_document(glob: &str) -> bool {
    let Some(rest) = glob.strip_prefix("docs/designs/") else {
        return false;
    };
    let Some(stem) = rest.strip_suffix(".md") else {
        return false;
    };
    !glob.contains("..")
        && (stem == "*"
            || (!stem.is_empty()
                && stem
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))))
}

/// The most design labels the audit record and the reply name.
const MAX_LABELS_SEEN: usize = 10;

/// The longest label name that is shown, in characters, after the cleaning.
const MAX_SHOWN_CHARS: usize = 60;

/// A label name as it is safe to show in an audit record: printable ASCII stays, every other
/// character (a control character, a character outside ASCII) becomes `?`, and a long name is cut.
/// A hostile name therefore shows that it is odd, and cannot change the line it is written in.
#[must_use]
pub fn printable_label(name: &str) -> String {
    let mut shown: String = name
        .chars()
        .take(MAX_SHOWN_CHARS)
        .map(|c| if (' '..='~').contains(&c) { c } else { '?' })
        .collect();
    if name.chars().count() > MAX_SHOWN_CHARS {
        shown.push_str("...");
    }
    shown
}

/// What the labels on an issue say about its design, before anybody checks who applied one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesignLabels {
    /// No label of the design track. A small, clear change: this rule does not touch it.
    NotOnTrack,
    /// The issue is on the design track and its only design label is the approved one. Who applied
    /// it is still to be checked.
    ApprovalLabelOnly,
    /// The issue is on the design track and does not carry the approved label.
    NotApproved {
        /// The design labels seen, cleaned for display (see [`printable_label`]).
        seen: Vec<String>,
    },
    /// The approved label is on the issue together with another design label, such as a design
    /// that was reopened and has not been cleaned up yet. The state is not clear, so it is not
    /// approved.
    Ambiguous {
        /// The design labels seen, cleaned for display.
        seen: Vec<String>,
    },
}

/// The design rule of the intake stage, made from a policy that passed every rule.
///
/// It is a pure value: it holds the three facts the rule needs (what makes a label a design label,
/// which label approves, and which designation must have applied it) and decides nothing about
/// people. The stage asks the allowlist about the person.
///
/// # What counts as a design label
///
/// A label is a design label when its name, ignoring leading white space and control characters
/// and the case of the letters, starts with the prefix of the design namespace up to and including
/// the colon (`design:`). That is wider than the namespace prefix itself (`design: `, with a
/// space) on purpose. `design:approved`, `Design: approved` and `design: approved ` are not the
/// label that approves, and an issue that carries one of them must not slip past the rule by being
/// "not on the track". They put the issue on the track, where they do not approve it. The
/// approving label is recognised by an exact, byte for byte, comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesignGate {
    track_key: String,
    approved_label: String,
    approved_by: Designation,
}

impl DesignGate {
    /// The exact name of the label that approves a design, such as `design: approved`.
    #[must_use]
    pub fn approved_label(&self) -> &str {
        &self.approved_label
    }

    /// The designation that the person who applied the approving label must hold.
    #[must_use]
    pub const fn approved_by(&self) -> Designation {
        self.approved_by
    }

    /// True when the name is a design label in the wide sense described on the type.
    #[must_use]
    pub fn is_design_label(&self, name: &str) -> bool {
        let trimmed = name.trim_start_matches(|c: char| c.is_whitespace() || c.is_control());
        trimmed
            .get(..self.track_key.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(&self.track_key))
    }

    /// Reads the labels on an issue, as the code host returned them now.
    #[must_use]
    pub fn classify(&self, labels: &[String]) -> DesignLabels {
        let design: Vec<&String> = labels
            .iter()
            .filter(|name| self.is_design_label(name))
            .collect();
        if design.is_empty() {
            return DesignLabels::NotOnTrack;
        }
        let approved = design
            .iter()
            .any(|name| name.as_str() == self.approved_label);
        let others = design
            .iter()
            .any(|name| name.as_str() != self.approved_label);
        let seen: Vec<String> = design
            .iter()
            .take(MAX_LABELS_SEEN)
            .map(|name| printable_label(name))
            .collect();
        match (approved, others) {
            (true, false) => DesignLabels::ApprovalLabelOnly,
            (true, true) => DesignLabels::Ambiguous { seen },
            (false, _) => DesignLabels::NotApproved { seen },
        }
    }
}

impl IssueWorkflowPolicy {
    /// Every rule the file breaks, or an empty list when it is sound. Pure. These are the rules of
    /// `scripts/lib/issue_workflow.py check` that concern the file alone, plus the two that tie it
    /// to the engine: every job state has exactly one label, and no label names a state the engine
    /// does not have.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn problems(&self) -> Vec<Problem> {
        let mut found = Vec::new();
        if self.policy.id != "issue-workflow" {
            found.push(problem(
                "policy.id",
                ProblemKind::Constraint,
                "this file must be the issue workflow policy, with `id: issue-workflow`",
            ));
        }

        // Namespaces: one writer each.
        for (key, namespace, prefix, writer) in [
            ("design", &self.namespaces.design, DESIGN_PREFIX, "people"),
            (
                "factory",
                &self.namespaces.factory,
                STATUS_PREFIX,
                "factory",
            ),
        ] {
            if namespace.prefix != prefix || namespace.written_by != writer {
                found.push(problem(
                    format!("namespaces.{key}"),
                    ProblemKind::Constraint,
                    format!("the {key} namespace must have the prefix {prefix:?} and be written by {writer}"),
                ));
            }
        }

        let mut seen: Vec<(String, String)> = Vec::new();
        let mut remember = |name: &str, place: String, found: &mut Vec<Problem>| {
            let folded = name.to_ascii_lowercase();
            if let Some((_, earlier)) = seen.iter().find(|(held, _)| *held == folded) {
                found.push(problem(
                    place.clone(),
                    ProblemKind::Duplicate,
                    format!("the label {name:?} is already used by {earlier}"),
                ));
            }
            seen.push((folded, place));
        };

        // The trigger label sits outside both namespaces.
        let trigger = &self.trigger;
        for message in label_problems(&trigger.label, &trigger.color, &trigger.description) {
            found.push(problem(
                "trigger",
                ProblemKind::Constraint,
                format!("trigger: {message}"),
            ));
        }
        if trigger.label.starts_with(DESIGN_PREFIX) || trigger.label.starts_with(STATUS_PREFIX) {
            found.push(problem(
                "trigger.label",
                ProblemKind::Constraint,
                "the trigger label must be outside both namespaces",
            ));
        }
        remember(&trigger.label, "the trigger".to_owned(), &mut found);

        // The design track.
        let design = &self.design_track;
        let mut design_names: Vec<&str> = Vec::new();
        for (index, state) in design.states.iter().enumerate() {
            let full = format!("{DESIGN_PREFIX}{}", state.name);
            for message in label_problems(&full, &state.color, &state.description) {
                found.push(problem(
                    format!("design_track.states[{index}]"),
                    ProblemKind::Constraint,
                    message,
                ));
            }
            remember(&full, format!("design state {}", state.name), &mut found);
            if design_names.contains(&state.name.as_str()) {
                found.push(problem(
                    format!("design_track.states[{index}].name"),
                    ProblemKind::Duplicate,
                    "design states must have unique names",
                ));
            }
            design_names.push(&state.name);
        }
        if design.start_states.is_empty() {
            found.push(problem(
                "design_track.start_states",
                ProblemKind::Constraint,
                "at least one start state is needed",
            ));
        }
        for name in &design.start_states {
            if !design_names.contains(&name.as_str()) {
                found.push(problem(
                    "design_track.start_states",
                    ProblemKind::Unknown,
                    format!("{name:?} is not a design state"),
                ));
            }
        }
        let mut edges: Vec<(&str, &str)> = Vec::new();
        for (index, edge) in design.transitions.iter().enumerate() {
            let at = format!("design_track.transitions[{index}]");
            let (from, to) = (edge.from.as_str(), edge.to.as_str());
            if !design_names.contains(&from) || !design_names.contains(&to) {
                found.push(problem(
                    at,
                    ProblemKind::Unknown,
                    format!("{from:?} to {to:?} names a state that does not exist"),
                ));
            } else if from == to {
                found.push(problem(
                    at,
                    ProblemKind::Constraint,
                    format!("{from:?} to {to:?} goes nowhere"),
                ));
            } else if edges.contains(&(from, to)) {
                found.push(problem(
                    at,
                    ProblemKind::Duplicate,
                    format!("{from:?} to {to:?} is listed twice"),
                ));
            }
            edges.push((from, to));
        }
        let mut reachable: BTreeSet<&str> = design
            .start_states
            .iter()
            .map(String::as_str)
            .filter(|name| design_names.contains(name))
            .collect();
        loop {
            let before = reachable.len();
            for (from, to) in &edges {
                if reachable.contains(from) {
                    reachable.insert(to);
                }
            }
            if reachable.len() == before {
                break;
            }
        }
        for name in &design_names {
            if !reachable.contains(name) {
                found.push(problem(
                    "design_track.transitions",
                    ProblemKind::Constraint,
                    format!("the design state {name:?} cannot be reached from a start state"),
                ));
            }
        }
        if !design_names.contains(&self.intake_requirements.design_track_requires.as_str()) {
            found.push(problem(
                "intake_requirements.design_track_requires",
                ProblemKind::Unknown,
                "this is not a design state",
            ));
        }
        match Designation::parse(&self.intake_requirements.design_approved_by) {
            None => found.push(problem(
                "intake_requirements.design_approved_by",
                ProblemKind::Unknown,
                format!(
                    "{:?} is not a designation of the allowlist",
                    self.intake_requirements.design_approved_by
                ),
            )),
            Some(Designation::Requester | Designation::Operator) => found.push(problem(
                "intake_requirements.design_approved_by",
                ProblemKind::Constraint,
                "the person whose label says a design is approved cannot be held to the requester or operator designation; the person who asks for work must not approve the design",
            )),
            Some(_) => {}
        }
        let document = &design.approval_requires.design_document;
        if !glob_is_a_design_document(&document.path_glob) {
            found.push(problem(
                "design_track.approval_requires.design_document.path_glob",
                ProblemKind::Shape,
                "the glob must look like docs/designs/*.md",
            ));
        }
        let field = &document.issue_body_field;
        if !(1..=40).contains(&field.len())
            || !field.bytes().all(|b| b.is_ascii_alphabetic() || b == b' ')
        {
            found.push(problem(
                "design_track.approval_requires.design_document.issue_body_field",
                ProblemKind::Shape,
                "the field is 1 to 40 letters and spaces",
            ));
        }

        // The factory track: one label for each job state, none left out, none invented.
        let mut mapped: Vec<&str> = Vec::new();
        for (index, state) in self.factory_track.states.iter().enumerate() {
            let at = format!("{STATES_KEY}[{index}]");
            let full = format!("{STATUS_PREFIX}{}", state.name);
            for message in label_problems(&full, &state.color, &state.description) {
                found.push(problem(at.clone(), ProblemKind::Constraint, message));
            }
            if let Err(why) = check_status_label_name(&full) {
                found.push(problem(
                    format!("{at}.name"),
                    ProblemKind::Constraint,
                    format!("{full:?} is not a status label: {why}"),
                ));
            }
            remember(&full, format!("factory state {}", state.name), &mut found);
            if JobStatus::parse(&state.job_state).is_err() {
                found.push(problem(
                    format!("{at}.job_state"),
                    ProblemKind::Unknown,
                    format!("{:?} is not a job state of the engine", state.job_state),
                ));
            }
            if mapped.contains(&state.job_state.as_str()) {
                found.push(problem(
                    format!("{at}.job_state"),
                    ProblemKind::Duplicate,
                    format!("the job state {} is mapped twice", state.job_state),
                ));
            }
            mapped.push(&state.job_state);
        }
        for status in JobStatus::ALL {
            if !mapped.contains(&status.as_str()) {
                found.push(problem(
                    STATES_KEY,
                    ProblemKind::Constraint,
                    format!(
                        "the engine job state {} has no factory label",
                        status.as_str()
                    ),
                ));
            }
        }
        found
    }

    /// The design rule of the intake stage, when the policy passes every rule.
    ///
    /// # Errors
    /// Every [`Problem`] of the policy. No rule exists after an error: a policy that cannot be
    /// judged gives the stage nothing to judge by, and the stage then refuses.
    pub fn design_gate(&self) -> Result<DesignGate, Vec<Problem>> {
        let found = self.problems();
        if !found.is_empty() {
            return Err(found);
        }
        let approved_by = Designation::parse(&self.intake_requirements.design_approved_by)
            .ok_or_else(|| {
                vec![problem(
                    "intake_requirements.design_approved_by",
                    ProblemKind::Unknown,
                    "this is not a designation of the allowlist",
                )]
            })?;
        let key = self.namespaces.design.prefix.trim().to_ascii_lowercase();
        Ok(DesignGate {
            track_key: key,
            approved_label: format!(
                "{}{}",
                self.namespaces.design.prefix, self.intake_requirements.design_track_requires
            ),
            approved_by,
        })
    }

    /// The status labels, when the policy passes every rule.
    ///
    /// # Errors
    /// Every [`Problem`] of the policy. No label exists after an error.
    pub fn status_labels(&self) -> Result<StatusLabels, Vec<Problem>> {
        let found = self.problems();
        if !found.is_empty() {
            return Err(found);
        }
        let mut labels = Vec::with_capacity(JobStatus::ALL.len());
        for status in JobStatus::ALL {
            let state = self
                .factory_track
                .states
                .iter()
                .find(|state| state.job_state == status.as_str())
                .ok_or_else(|| {
                    vec![problem(
                        STATES_KEY,
                        ProblemKind::Constraint,
                        format!(
                            "the engine job state {} has no factory label",
                            status.as_str()
                        ),
                    )]
                })?;
            let name = format!("{STATUS_PREFIX}{}", state.name);
            if let Err(why) = check_status_label_name(&name) {
                return Err(vec![problem(
                    STATES_KEY,
                    ProblemKind::Constraint,
                    format!("{name:?} is not a status label: {why}"),
                )]);
            }
            labels.push(StatusLabel {
                name,
                state: *status,
            });
        }
        Ok(StatusLabels { labels })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_label_name_must_be_in_the_factory_namespace() {
        for good in [
            "factory: working",
            "factory: waiting for a person",
            "factory: a",
        ] {
            assert_eq!(check_status_label_name(good), Ok(()), "{good}");
        }
        for (bad, why) in [
            ("factory", BadStatusLabel::WrongNamespace),
            ("design: approved", BadStatusLabel::WrongNamespace),
            ("bug", BadStatusLabel::WrongNamespace),
            ("Factory: working", BadStatusLabel::WrongNamespace),
            ("factory:working", BadStatusLabel::WrongNamespace),
            (" factory: working", BadStatusLabel::WrongNamespace),
            ("factory: ", BadStatusLabel::EmptyName),
            ("factory:  working", BadStatusLabel::EdgeSpace),
            ("factory: working ", BadStatusLabel::EdgeSpace),
            ("factory: wörking", BadStatusLabel::NotPrintable),
            ("factory: work\ning", BadStatusLabel::NotPrintable),
        ] {
            assert_eq!(check_status_label_name(bad), Err(why), "{bad:?}");
        }
        let long = format!(
            "{STATUS_PREFIX}{}",
            "x".repeat(MAX_LABEL_NAME - STATUS_PREFIX.len())
        );
        assert_eq!(long.chars().count(), MAX_LABEL_NAME);
        assert_eq!(check_status_label_name(&long), Ok(()));
        assert_eq!(
            check_status_label_name(&format!("{long}x")),
            Err(BadStatusLabel::TooLong)
        );
    }

    fn rule() -> DesignGate {
        DesignGate {
            track_key: "design:".to_owned(),
            approved_label: "design: approved".to_owned(),
            approved_by: Designation::Approver,
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn an_issue_with_no_design_label_is_not_on_the_track() {
        for labels in [
            &[][..],
            &["factory"][..],
            &["bug", "factory", "factory: working"][..],
            // Words that merely contain or resemble the prefix are not design labels.
            &["designer", "design-system", "my design: approved", "design"][..],
        ] {
            assert_eq!(rule().classify(&names(labels)), DesignLabels::NotOnTrack);
        }
    }

    #[test]
    fn only_the_exact_approving_label_alone_is_the_approval_label() {
        assert_eq!(
            rule().classify(&names(&["factory", "design: approved"])),
            DesignLabels::ApprovalLabelOnly
        );
        // Every other state of the track is not approved.
        for state in ["proposed", "in progress", "in review"] {
            let label = format!("design: {state}");
            assert_eq!(
                rule().classify(&names(&["factory", &label])),
                DesignLabels::NotApproved {
                    seen: names(&[&label])
                }
            );
        }
    }

    #[test]
    fn a_look_alike_of_the_approving_label_is_on_the_track_and_does_not_approve() {
        // The sibling of the test above: each of these must NOT be read as approved, and none may
        // slip past the rule by being read as "not on the track".
        for hostile in [
            "design:approved",
            "Design: approved",
            "DESIGN: APPROVED",
            "design: approved ",
            " design: approved",
            "\tdesign: approved",
            "design: Approved",
            "design: approved\n",
            "design: approved\u{0}",
            "design: appro\u{200b}ved",
            "design: approv\u{0435}d",
            "design:  approved",
        ] {
            match rule().classify(&names(&["factory", hostile])) {
                DesignLabels::NotApproved { seen } => assert_eq!(seen.len(), 1, "{hostile:?}"),
                other => panic!("{hostile:?} was read as {other:?}"),
            }
        }
    }

    #[test]
    fn the_approving_label_beside_another_design_label_is_not_clear_and_is_not_approved() {
        assert_eq!(
            rule().classify(&names(&["design: in progress", "design: approved"])),
            DesignLabels::Ambiguous {
                seen: names(&["design: in progress", "design: approved"])
            }
        );
        // A look-alike beside the real one is the same: the state is not clear.
        assert!(matches!(
            rule().classify(&names(&["design: approved", "Design: approved"])),
            DesignLabels::Ambiguous { .. }
        ));
    }

    #[test]
    fn what_is_shown_of_a_label_name_is_printable_ascii_and_short() {
        assert_eq!(printable_label("design: approved"), "design: approved");
        assert_eq!(printable_label("design:\n approved"), "design:? approved");
        assert_eq!(printable_label("design: \u{202e}x"), "design: ?x");
        let long = printable_label(&format!("design: {}", "a".repeat(200)));
        assert!(long.chars().count() <= MAX_SHOWN_CHARS + 3);
        assert!(long.ends_with("..."));
        let seen = match rule().classify(
            &(0..30)
                .map(|n| format!("design: x{n}"))
                .collect::<Vec<String>>(),
        ) {
            DesignLabels::NotApproved { seen } => seen,
            other => panic!("{other:?}"),
        };
        assert_eq!(seen.len(), MAX_LABELS_SEEN);
    }

    #[test]
    fn a_forged_label_keeps_the_name_it_was_given_and_shows_it_in_debug_output() {
        let forged = StatusLabel::forged_for_negative_tests("factory");
        assert_eq!(forged.as_str(), "factory");
        assert_eq!(format!("{forged:?}"), "StatusLabel(\"factory\")");
        assert!(check_status_label_name(forged.as_str()).is_err());
    }
}
