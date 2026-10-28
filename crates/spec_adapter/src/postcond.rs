//! The seven post-conditions of a skill run, and the check that nothing else leaked into the
//! arguments.
//!
//! The same skill writes different content on different runs, so the adapter never trusts what the
//! agent says it did. After a run it checks the files that the host read from the commit, and only
//! those. [`evaluate`] takes no parameter that holds the agent's report, so the report cannot be
//! believed by accident.
//!
//! | # | Post-condition | Name |
//! |---|---|---|
//! | 1 | The skill run ended normally, by the runtime's own outcome | `run-succeeded` |
//! | 2 | The installation is still the pinned one | the typed errors of [`crate::integrity`] |
//! | 3 | Nothing outside the known and allowed paths appeared | `unexpected-path` |
//! | 4 | The pointer is valid and the feature directory holds a specification | `feature-file-written`, `feature-pointer-valid` |
//! | 5 | No template placeholder remains | `no-template-placeholder` |
//! | 6 | No file of a skill the factory never runs appeared | `no-forbidden-artifact` |
//! | 7 | The checklist exists, and no custom item is ticked by its author | `checklist-present`, `custom-checklist-ticked` |
//!
//! The eighth check, `skill-arguments-fixed`, is the proof that nothing else leaked into the
//! arguments: the `Input` line of the specification, which Spec Kit fills from the arguments, must
//! be the fixed instruction and nothing more.

use std::sync::LazyLock;

use factory_domain::values::Slug;
use factory_ports::paths::RepoPath;
use factory_ports::spec::{FeatureDir, PostCondition, SpecError, SpecOperation};
use regex::Regex;

use crate::integrity::{FileView, check_installation, installation_paths};
use crate::invocation::{CUSTOM_CHECKLIST, FixedInstruction, Host};
use crate::parse::{feature_pointer, parse_checklist, parse_spec};

/// The constitution, written by one of the four operations.
pub const CONSTITUTION: &str = ".specify/memory/constitution.md";
/// The active-feature pointer.
pub const FEATURE_POINTER: &str = ".specify/feature.json";

/// What the host knows after a run.
#[derive(Debug, Clone, Copy)]
pub struct RunFacts<'a> {
    /// The operation that ran.
    pub op: SpecOperation,
    /// The feature directory the factory chose.
    pub feature: &'a FeatureDir,
    /// The host the skills ran on.
    pub host: Host,
    /// The files read from the commit.
    pub view: FileView<'a>,
    /// The instruction the specify skill was given. The `Input` line must be this text.
    pub specify_instruction: &'a FixedInstruction,
    /// Whether every skill run ended normally, by the runtime's outcome.
    pub run_succeeded: bool,
}

fn condition(name: &str, detail: impl Into<String>) -> PostCondition {
    PostCondition {
        name: Slug::parse(name).expect("the post-condition names are slugs"),
        detail: detail.into(),
    }
}

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\[FEATURE NAME\]|\$ARGUMENTS|\[###-feature-name\]|\[DATE\]|\[[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\]",
    )
    .expect("the placeholder pattern is valid")
});

/// The files whose text is checked for template placeholders: the specification, the checklists
/// and the constitution.
fn is_authored_text(path: &str, feature: &FeatureDir) -> bool {
    path == CONSTITUTION
        || path == format!("{}/spec.md", feature.as_str())
        || (path.starts_with(&format!("{}/checklists/", feature.as_str())) && path.ends_with(".md"))
}

fn is_forbidden_artifact(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("specs/") else {
        return false;
    };
    let mut parts = rest.splitn(2, '/');
    let (_, Some(inside)) = (parts.next(), parts.next()) else {
        return false;
    };
    matches!(
        inside,
        "plan.md" | "tasks.md" | "research.md" | "data-model.md" | "quickstart.md"
    ) || inside.starts_with("contracts/")
}

/// The paths the host reads for an operation, whether or not the run changed them.
#[must_use]
pub fn known_paths(feature: &FeatureDir, host: Host) -> Vec<String> {
    let dir = feature.as_str();
    let mut paths: Vec<String> = installation_paths(host)
        .into_iter()
        .map(str::to_owned)
        .collect();
    paths.extend([
        format!("{dir}/spec.md"),
        format!("{dir}/checklists/requirements.md"),
        format!("{dir}/checklists/{CUSTOM_CHECKLIST}"),
        FEATURE_POINTER.to_owned(),
        CONSTITUTION.to_owned(),
    ]);
    paths
}

/// The paths a skill may write, from the stage profile of the policy.
#[must_use]
pub fn allowed_writes(op: SpecOperation, feature: &FeatureDir) -> Vec<String> {
    let dir = feature.as_str();
    match op {
        SpecOperation::Constitution => vec![CONSTITUTION.to_owned()],
        SpecOperation::Specify => vec![
            format!("{dir}/spec.md"),
            format!("{dir}/checklists/requirements.md"),
            FEATURE_POINTER.to_owned(),
        ],
        SpecOperation::Clarify => vec![
            format!("{dir}/spec.md"),
            format!("{dir}/checklists/requirements.md"),
        ],
        SpecOperation::Checklist => vec![format!("{dir}/checklists/{CUSTOM_CHECKLIST}")],
    }
}

/// Post-condition 3 over a list of changed paths measured by the host. The stage runs the same
/// check with the globs of the policy; this is the adapter's own copy.
#[must_use]
pub fn check_changed_paths(
    op: SpecOperation,
    feature: &FeatureDir,
    changed: &[RepoPath],
) -> Vec<PostCondition> {
    let allowed = allowed_writes(op, feature);
    changed
        .iter()
        .filter(|path| !allowed.iter().any(|ok| ok == path.as_str()))
        .map(|path| {
            condition(
                "unexpected-path",
                format!("The run changed {path}, which this skill may not write."),
            )
        })
        .collect()
}

/// Checks post-conditions 1 and 3 to 8. The strongest failure comes first: a forbidden artifact
/// before anything else, because it means a skill the factory never runs ran.
#[must_use]
pub fn evaluate(facts: &RunFacts<'_>) -> Vec<PostCondition> {
    let mut failed = Vec::new();
    let dir = facts.feature.as_str();
    let spec_path = format!("{dir}/spec.md");

    for path in facts.view.paths() {
        if is_forbidden_artifact(path.as_str()) {
            failed.push(condition(
                "no-forbidden-artifact",
                format!("{path} exists, so a skill the factory never runs was run."),
            ));
        }
    }
    if !facts.run_succeeded {
        failed.push(condition(
            "run-succeeded",
            "A skill run did not end normally.",
        ));
    }
    let known = known_paths(facts.feature, facts.host);
    for path in facts.view.paths() {
        let text = path.as_str();
        if !known.iter().any(|k| k == text) && !is_forbidden_artifact(text) {
            failed.push(condition(
                "unexpected-path",
                format!("{path} appeared, and no skill of this stage writes it."),
            ));
        }
    }

    if facts.op != SpecOperation::Constitution {
        if facts.view.get(&spec_path).is_none() {
            failed.push(condition(
                "feature-file-written",
                format!("The feature directory {dir} holds no specification."),
            ));
        }
        if let Some(pointer) = facts.view.get(FEATURE_POINTER) {
            let ok = feature_pointer(pointer).as_deref() == Some(dir);
            if !ok {
                failed.push(condition(
                    "feature-pointer-valid",
                    "The active-feature pointer is not valid JSON that names the feature directory.",
                ));
            }
        }
    }

    for path in facts.view.paths() {
        if is_authored_text(path.as_str(), facts.feature)
            && let Some(bytes) = facts.view.get(path.as_str())
            && let Ok(text) = std::str::from_utf8(bytes)
            && PLACEHOLDER.is_match(text)
        {
            failed.push(condition(
                "no-template-placeholder",
                format!("{path} still holds template placeholder text."),
            ));
        }
    }

    if matches!(facts.op, SpecOperation::Specify | SpecOperation::Clarify)
        && facts
            .view
            .get(&format!("{dir}/checklists/requirements.md"))
            .is_none()
    {
        failed.push(condition(
            "checklist-present",
            "The built-in checklist of the specification is missing.",
        ));
    }
    if facts.op == SpecOperation::Checklist {
        let custom = format!("{dir}/checklists/{CUSTOM_CHECKLIST}");
        match facts.view.get(&custom).map(std::str::from_utf8) {
            None | Some(Err(_)) => failed.push(condition(
                "checklist-present",
                "The requirements-quality checklist is missing.",
            )),
            Some(Ok(text)) => {
                if parse_checklist(text).iter().any(|item| item.ticked) {
                    failed.push(condition(
                        "custom-checklist-ticked",
                        "An item of the custom checklist is ticked by the agent that wrote it.",
                    ));
                }
            }
        }
    }

    // Nothing else leaked into the arguments: the `Input` line is the fixed instruction.
    if let Some(bytes) = facts.view.get(&spec_path)
        && let Ok(text) = std::str::from_utf8(bytes)
        && let Ok(parsed) = parse_spec(text)
    {
        let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        if squash(&parsed.input) != squash(facts.specify_instruction.as_str()) {
            failed.push(condition(
                "skill-arguments-fixed",
                "The Input line of the specification is not the fixed instruction, so something else reached the arguments of the skill.",
            ));
        }
    }
    failed
}

/// Checks the installation, then the post-conditions. The installation comes first and returns
/// its own typed error.
///
/// # Errors
/// The typed errors of [`check_installation`], or [`SpecError::PostConditionFailed`] with every
/// post-condition that does not hold.
pub fn check_all(facts: &RunFacts<'_>) -> Result<(), SpecError> {
    check_installation(&facts.view, facts.host)?;
    let failed = evaluate(facts);
    if failed.is_empty() {
        Ok(())
    } else {
        Err(SpecError::PostConditionFailed(failed))
    }
}
