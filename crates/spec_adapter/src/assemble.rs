//! The typed `SpecificationContract` from the bytes of the committed files.
//!
//! Everything here is pure. The result is a **draft**: it carries the hash of the exact bytes of
//! each file, the provenance and the open questions, and it claims no approval. The factory
//! freezes it later, after the gate and a person, and a freeze cannot be written from here.
//!
//! # What Spec Kit does not give, and what is done about it
//!
//! * **Links between requirements and scenarios.** Spec Kit writes none. A requirement is linked
//!   to the scenarios that cite its identifier in their text, or whose story cites it. A
//!   requirement nothing cites has no scenario, and so does a scenario that cites nothing: that is
//!   `requirement-without-scenario` and `scenario-without-requirement`, never a guess.
//! * **Scenario identifiers.** `AS-` and ten digits taken from the SHA-256 of the story number and
//!   the normalised text, so inserting a scenario does not renumber the others.
//! * **Priorities.** A requirement takes the highest priority among the stories that cover it.
//! * **Risks and constraints.** Only the `Risk:` and `Constraint:` bullets under Assumptions, a
//!   local convention. A rating or a kind is read from an explicit parenthesis; without one the
//!   contract's required field is set to `medium` or `technical`, which is a normalisation and
//!   not a finding.
//! * **Checklist items.** Every item of every checklist becomes a blocking open question, ticked
//!   or not. A tick is a self-assessment and carries no weight, so it is not read.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use factory_domain::contracts::specification_contract::{ConstraintKind, Level};
use factory_domain::contracts::{Contract, SpecificationContract};
use factory_domain::ids::JobId;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::{ExecutionMode, Fidelity};
use factory_ports::paths::RepoPath;
use factory_ports::spec::{
    FeatureDir, ParseReason, PostCondition, SpecError, SpecFileSet, SpecOperation, SpecOutcome,
    SpecRequest, SpecificationDraft,
};
use regex::Regex;
use serde_json::{Value, json};

use crate::integrity::{FileView, INIT_OPTIONS};
use crate::invocation::{Host, skill_name};
use crate::parse::{ParsedSpec, StoryPriority, parse_checklist, parse_spec};
use crate::postcond::{CONSTITUTION, RunFacts, check_all};
use crate::question::{Origin, Question};

/// The file that holds the answers of people, written by the stage before the clarify skill runs.
pub const ANSWERS_FILE: &str = "inputs/answers.md";
/// The words every question made from a checklist item starts with. The gate reads them.
pub const CHECKLIST_PREFIX: &str = "Checklist item ";
/// The largest `spec.md` the parser reads.
pub const MAX_SPEC_BYTES: usize = 1024 * 1024;

/// What the adapter knows about itself and the run.
#[derive(Debug, Clone)]
pub struct AssembleConfig {
    /// The host the skills ran on.
    pub host: Host,
    /// Production or test.
    pub mode: ExecutionMode,
    /// The runtime adapter to record when no run was noted in this process.
    pub fallback_adapter: Slug,
    /// Its version, in the same case.
    pub fallback_adapter_version: String,
}

/// What `run` noted about the skill runs of a feature. The agent's report is not here: only the
/// runtime's own outcome, the skills that ran and the questions the detector found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunNotes {
    /// The operations that ran, in order.
    pub skills: Vec<SpecOperation>,
    /// Whether every run ended normally.
    pub run_succeeded: bool,
    /// The questions the detector found in the output of the skills.
    pub questions: Vec<Question>,
    /// The runtime adapter that ran the skills, as the runtime named itself.
    pub adapter: Option<String>,
    /// The version of the tool, when it reported one.
    pub adapter_version: Option<String>,
    /// Whether the runtime was real or scripted. Scripted until a run says otherwise.
    pub fidelity: Option<Fidelity>,
}

fn parse_error(path: &str, reason: ParseReason) -> SpecError {
    SpecError::ParseError {
        path: RepoPath::new(path).unwrap_or_else(|_| {
            RepoPath::new("specs/unknown/spec.md").expect("a fixed path is valid")
        }),
        reason,
    }
}

fn failure(name: &str, detail: String) -> PostCondition {
    PostCondition {
        name: Slug::parse(name).expect("the names are slugs"),
        detail,
    }
}

/// Text that fits a `HumanText`: at least ten characters and at most 4000.
fn human(text: &str) -> String {
    let mut text: String = text.trim().chars().take(4000).collect();
    if text.chars().count() < 10 {
        text.push_str(" (no further detail was given)");
    }
    text.trim().to_owned()
}

fn collapse(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The identifier of a scenario: stable when a scenario is inserted before it.
fn scenario_id(story: u32, given: &str, when: &str, then: &str) -> String {
    let seed = format!(
        "US{story}|{}|{}|{}",
        collapse(given),
        collapse(when),
        collapse(then)
    );
    let digest = Sha256Digest::of(seed.as_bytes());
    let number = u32::from_str_radix(&digest.hex()[..8], 16).unwrap_or(0);
    format!("AS-{number:010}")
}

/// The identifier of the specification: the same job and feature directory always give the same
/// one, so `assemble` is idempotent. It has the shape of a UUID version 7. The stage replaces it
/// with the identifier of the first revision when it freezes a later one.
#[must_use]
pub fn derive_spec_id(job: JobId, feature: &FeatureDir) -> String {
    let digest = Sha256Digest::of(format!("factory.spec|{job}|{}", feature.as_str()).as_bytes());
    let hex = digest.hex();
    let variant = ["8", "9", "a", "b"][usize::from(hex.as_bytes()[16] % 4)];
    format!(
        "{}-{}-7{}-{}{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[13..16],
        variant,
        &hex[17..20],
        &hex[20..32]
    )
}

static RATING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\s*\(likelihood (low|medium|high), impact (low|medium|high)\)")
        .expect("a valid pattern")
});
static KIND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Constraint(?: \((technical|legal|safety|platform|business)\))?:\s*(\S.*)$")
        .expect("a valid pattern")
});

fn level(name: &str) -> Level {
    match name {
        "low" => Level::Low,
        "high" => Level::High,
        _ => Level::Medium,
    }
}

fn kind(name: &str) -> ConstraintKind {
    match name {
        "legal" => ConstraintKind::Legal,
        "safety" => ConstraintKind::Safety,
        "platform" => ConstraintKind::Platform,
        "business" => ConstraintKind::Business,
        _ => ConstraintKind::Technical,
    }
}

fn level_text(level: Level) -> &'static str {
    match level {
        Level::Low => "low",
        Level::Medium => "medium",
        Level::High => "high",
    }
}

fn kind_text(kind: ConstraintKind) -> &'static str {
    match kind {
        ConstraintKind::Technical => "technical",
        ConstraintKind::Legal => "legal",
        ConstraintKind::Safety => "safety",
        ConstraintKind::Platform => "platform",
        ConstraintKind::Business => "business",
    }
}

struct Linked {
    scenarios: Vec<Value>,
    requirements: Vec<Value>,
}

/// Links requirements to scenarios by citation. Returns what failed to link.
fn link(spec: &ParsedSpec) -> Result<Linked, Vec<PostCondition>> {
    struct S {
        id: String,
        story: u32,
        priority: StoryPriority,
        cited: BTreeSet<String>,
        json: Value,
    }
    let mut scenarios: Vec<S> = Vec::new();
    let mut ids = BTreeSet::new();
    let mut problems = Vec::new();
    for story in &spec.stories {
        for scenario in &story.scenarios {
            let id = scenario_id(
                story.number,
                &scenario.given,
                &scenario.when,
                &scenario.then,
            );
            if !ids.insert(id.clone()) {
                problems.push(failure(
                    "scenario-identifier-duplicate",
                    format!(
                        "Two scenarios of story {} have the same text.",
                        story.number
                    ),
                ));
            }
            let mut cited = scenario.cited.clone();
            cited.extend(story.cited.iter().cloned());
            scenarios.push(S {
                json: json!({
                    "id": id,
                    "user_story_ref": format!("US{}", story.number),
                    "given": human(&scenario.given),
                    "when": human(&scenario.when),
                    "then": human(&scenario.then),
                }),
                id,
                story: story.number,
                priority: story.priority,
                cited,
            });
        }
    }
    let known: BTreeSet<&str> = spec.requirements.iter().map(|r| r.id.as_str()).collect();
    let mut requirements = Vec::new();
    for requirement in &spec.requirements {
        let covering: Vec<&S> = scenarios
            .iter()
            .filter(|s| s.cited.contains(&requirement.id))
            .collect();
        let Some(priority) = covering.iter().map(|s| s.priority).min() else {
            problems.push(failure(
                "requirement-without-scenario",
                format!(
                    "{} has no acceptance scenario that cites it.",
                    requirement.id
                ),
            ));
            continue;
        };
        let story = covering.iter().map(|s| s.story).min().unwrap_or(0);
        requirements.push(json!({
            "id": requirement.id,
            "statement": human(&requirement.text),
            "priority": priority.as_str(),
            "user_story_ref": format!("US{story}"),
            "acceptance_scenario_ids": covering.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        }));
    }
    let mut scenario_values = Vec::new();
    for scenario in &scenarios {
        let named: Vec<&String> = scenario
            .cited
            .iter()
            .filter(|id| known.contains(id.as_str()))
            .collect();
        if named.is_empty() {
            problems.push(failure(
                "scenario-without-requirement",
                format!(
                    "A scenario of story {} cites no requirement of the specification.",
                    scenario.story
                ),
            ));
            continue;
        }
        let mut json = scenario.json.clone();
        json["requirement_ids"] = json!(named);
        scenario_values.push(json);
    }
    if problems.is_empty() {
        Ok(Linked {
            scenarios: scenario_values,
            requirements,
        })
    } else {
        Err(problems)
    }
}

fn capped(problems: Vec<PostCondition>) -> SpecError {
    const PER_KIND: usize = 10;
    let mut kept: Vec<PostCondition> = Vec::new();
    let mut dropped = 0usize;
    for problem in problems {
        let same = kept.iter().filter(|k| k.name == problem.name).count();
        if same < PER_KIND {
            kept.push(problem);
        } else {
            dropped += 1;
        }
    }
    if dropped > 0 {
        kept.push(failure(
            "more-failures",
            format!("{dropped} more failures of the same kinds were not listed."),
        ));
    }
    SpecError::PostConditionFailed(kept)
}

fn question_json(
    number: usize,
    text: &str,
    blocking: bool,
    answer: Option<&str>,
    marker: bool,
) -> Value {
    let mut value = json!({
        "id": format!("Q-{number:03}"),
        "question": human(text),
        "blocking": blocking,
        "status": if answer.is_some() { "answered" } else { "open" },
    });
    if let Some(answer) = answer {
        value["answer"] = json!(human(answer));
    }
    if marker {
        value["source_marker"] = json!("NEEDS CLARIFICATION");
    }
    value
}

fn utf8<'a>(path: &str, bytes: &'a [u8]) -> Result<&'a str, SpecError> {
    std::str::from_utf8(bytes).map_err(|_| parse_error(path, ParseReason::NotText))
}

/// Builds the outcome from the committed files.
///
/// # Errors
/// * The typed errors of the installation check and [`SpecError::PostConditionFailed`] with the
///   post-conditions that do not hold.
/// * [`SpecError::ParseError`] when `spec.md` is missing, is not text, is too large or has a
///   structure the parser does not know.
/// * [`SpecError::PostConditionFailed`] with `requirement-without-scenario`,
///   `scenario-without-requirement` or `scenario-identifier-duplicate` when the links cannot be
///   made from the text.
pub fn assemble(
    config: &AssembleConfig,
    notes: &RunNotes,
    req: &SpecRequest,
    files: &SpecFileSet,
) -> Result<SpecOutcome, SpecError> {
    let dir = req.feature_directory.as_str();
    let view = FileView::new(&files.files);
    let spec_path = format!("{dir}/spec.md");

    // The request file is handed over for its hash only. It is not part of the commit, so the
    // post-conditions do not see it.
    let handed: Vec<_> = files
        .files
        .iter()
        .filter(|f| f.path != req.request_file && f.path.as_str() != ANSWERS_FILE)
        .cloned()
        .collect();
    let facts = RunFacts {
        op: req.op,
        feature: &req.feature_directory,
        host: config.host,
        view: FileView::new(&handed),
        run_succeeded: notes.run_succeeded,
    };
    check_all(&facts)?;

    let spec_bytes = view
        .get(&spec_path)
        .ok_or_else(|| parse_error(&spec_path, ParseReason::Missing))?;
    if spec_bytes.len() > MAX_SPEC_BYTES {
        return Err(parse_error(&spec_path, ParseReason::TooLarge));
    }
    let spec_text = utf8(&spec_path, spec_bytes)?;
    let spec = parse_spec(spec_text).map_err(|found| parse_error(&spec_path, found.reason))?;
    let linked = link(&spec).map_err(capped)?;

    // Questions: markers first, then what the detector heard, then answered ones, then checklists.
    let mut questions: Vec<Value> = Vec::new();
    let mut blocking_for_human: Vec<Value> = Vec::new();
    let mut number = 0usize;
    let mut next = || {
        number += 1;
        number
    };
    let mut seen_text = BTreeSet::new();
    for marker in &spec.markers {
        if seen_text.insert(collapse(&marker.question)) {
            let value = question_json(next(), &marker.question, true, None, true);
            blocking_for_human.push(value.clone());
            questions.push(value);
        }
    }
    for heard in notes
        .questions
        .iter()
        .filter(|q| q.origin == Origin::FreeText)
    {
        if seen_text.insert(collapse(&heard.text)) {
            let value = question_json(next(), &heard.text, true, None, false);
            blocking_for_human.push(value.clone());
            questions.push(value);
        }
    }
    for clarification in &spec.clarifications {
        questions.push(question_json(
            next(),
            &clarification.question,
            false,
            Some(&clarification.answer),
            false,
        ));
    }
    let mut checklist_paths: Vec<String> = view
        .paths()
        .map(|p| p.as_str().to_owned())
        .filter(|p| p.starts_with(&format!("{dir}/checklists/")) && p.ends_with(".md"))
        .collect();
    // The built-in checklist first, then the others by name.
    checklist_paths.sort_by_key(|p| (!p.ends_with("/requirements.md"), p.clone()));
    for path in &checklist_paths {
        let bytes = view.get(path).unwrap_or_default();
        for item in parse_checklist(utf8(path, bytes)?) {
            let label = item
                .id
                .clone()
                .unwrap_or_else(|| format!("on line {}", item.line));
            let base = path.rsplit('/').next().unwrap_or(path);
            questions.push(question_json(
                next(),
                &format!("{CHECKLIST_PREFIX}{label} of {base}: {}", item.text),
                true,
                None,
                false,
            ));
        }
    }
    if !blocking_for_human.is_empty() {
        let list = blocking_for_human
            .into_iter()
            .map(|value| {
                serde_json::from_value(value)
                    .map_err(|_| parse_error(&spec_path, ParseReason::BadId))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(SpecOutcome::NeedsHuman(list));
    }

    let artifact = |role: &str, path: &str, bytes: &[u8]| json!({ "role": role, "path": path, "sha256": Sha256Digest::of(bytes).as_str() });
    let mut artifacts = vec![artifact("specification", &spec_path, spec_bytes)];
    for path in &checklist_paths {
        let role = if path.ends_with("/requirements.md") {
            "requirements_checklist"
        } else {
            "custom_checklist"
        };
        artifacts.push(artifact(role, path, view.get(path).unwrap_or_default()));
    }
    if let Some(bytes) = view.get(CONSTITUTION) {
        artifacts.push(artifact("constitution", CONSTITUTION, bytes));
    }

    let request_bytes = files
        .files
        .iter()
        .find(|f| f.path == req.request_file)
        .map(|f| f.bytes.as_slice())
        .ok_or_else(|| parse_error(req.request_file.as_str(), ParseReason::Missing))?;
    let cli_version = view
        .get(INIT_OPTIONS)
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .and_then(|v| v["speckit_version"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut skills: Vec<&str> = Vec::new();
    for op in [
        SpecOperation::Constitution,
        SpecOperation::Specify,
        SpecOperation::Clarify,
        SpecOperation::Checklist,
    ] {
        if notes.skills.contains(&op) {
            skills.push(skill_name(op));
        }
    }
    let risks: Vec<Value> = spec
        .assumptions
        .iter()
        .filter_map(|a| a.strip_prefix("Risk:"))
        .enumerate()
        .map(|(index, body)| {
            let (likelihood, impact) = RATING.captures(body).map_or(("medium", "medium"), |c| {
                (
                    level_text(level(c.get(1).map_or("", |m| m.as_str()))),
                    level_text(level(c.get(2).map_or("", |m| m.as_str()))),
                )
            });
            json!({
                "id": format!("RISK-{:03}", index + 1),
                "description": human(&RATING.replace(body, "")),
                "likelihood": likelihood,
                "impact": impact,
            })
        })
        .collect();
    let constraints: Vec<Value> = spec
        .assumptions
        .iter()
        .filter_map(|a| KIND.captures(a))
        .enumerate()
        .map(|(index, c)| {
            json!({
                "id": format!("C-{:03}", index + 1),
                "kind": kind_text(kind(c.get(1).map_or("", |m| m.as_str()))),
                "description": human(c.get(2).map_or("", |m| m.as_str())),
            })
        })
        .collect();
    let out_of_scope: Vec<Value> = spec
        .edge_cases
        .first()
        .filter(|bullet| bullet.to_lowercase().contains("out of scope"))
        .map(|bullet| vec![json!(human(bullet))])
        .unwrap_or_default();

    let mut metadata = json!({
        "spec_id": derive_spec_id(req.job, &req.feature_directory),
        "spec_version": 1,
        "status": "draft",
        "job_id": req.job.to_string(),
        "execution_mode": config.mode.as_str(),
        "commit_sha": files.commit.as_str(),
        "created_at": format!("{}T00:00:00Z", spec.created),
    });
    let mut provenance = json!({
        "spec_kit": {
            "cli_version": cli_version,
            "integration": config.host.key(),
            "skills_invoked": skills,
        },
        "host_runtime": {
            "adapter": notes.adapter.as_deref().unwrap_or(config.fallback_adapter.as_str()),
            "adapter_version": notes
                .adapter_version
                .as_deref()
                .unwrap_or(&config.fallback_adapter_version),
            "fidelity": notes.fidelity.unwrap_or(Fidelity::Fake).as_str(),
        },
        "artifacts": artifacts,
        "source_request": {
            "sha256": Sha256Digest::of(request_bytes).as_str(),
            "language": "en",
        },
        "feature_directory": dir,
    });
    if req.revision.is_some() {
        // Provisional: the stage knows the real basis and replaces these three fields.
        metadata["spec_version"] = json!(2);
        metadata["supersedes_spec_version"] = json!(1);
        provenance["revision"] =
            json!({ "method": "new_feature_directory", "basis_spec_version": 1 });
    }
    let document = json!({
        "schema_version": 1,
        "metadata": metadata,
        "title": spec.title,
        "summary": human(&spec.stories.first().map(|s| s.narrative.clone()).unwrap_or_default()),
        "requirements": linked.requirements,
        "acceptance_scenarios": linked.scenarios,
        "nonfunctional_requirements": spec.success_criteria.iter().map(|c| json!({
            "id": c.id, "statement": human(&c.text),
        })).collect::<Vec<_>>(),
        "risks": risks,
        "open_questions": questions,
        "constraints": constraints,
        "out_of_scope": out_of_scope,
        "provenance": provenance,
    });
    let contract = SpecificationContract::from_json_value(document)
        .map_err(|_| parse_error(&spec_path, ParseReason::SectionMissing))?;
    contract
        .validate()
        .map_err(|_| parse_error(&spec_path, ParseReason::SectionMissing))?;
    Ok(SpecOutcome::Draft(Box::new(SpecificationDraft {
        contract,
        files: Vec::new(),
    })))
}
