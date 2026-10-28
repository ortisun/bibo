//! The parser: Spec Kit's `spec.md` and checklist files into typed values.
//!
//! The parser reads the structure that the Spec Kit template defines and the specify skill keeps
//! (the integration guide, section 9). It is strict. A structure it does not recognise is a
//! [`ParseFailure`], which becomes `SPEC_PARSE_ERROR`: the parser never guesses a priority, an
//! identifier or a section. It keys on identifiers and never on position, because the clarify
//! skill leaves requirement identifiers out of order on purpose.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use factory_ports::spec::ParseReason;
use regex::Regex;

/// Why a file was not understood, with the rule that failed and the line where it failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFailure {
    /// The reason in the words of the port.
    pub reason: ParseReason,
    /// The rule that failed, such as `required-section`.
    pub rule: &'static str,
    /// The line, counted from 1, or 0 when the rule is about the whole file.
    pub line: u32,
}

impl ParseFailure {
    const fn new(reason: ParseReason, rule: &'static str, line: usize) -> Self {
        Self {
            reason,
            rule,
            line: line as u32,
        }
    }
}

/// A priority Spec Kit gave a user story. Only the three the contract holds are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoryPriority {
    /// Most important.
    P1,
    /// Important.
    P2,
    /// Useful.
    P3,
}

impl StoryPriority {
    /// The text of the priority.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
        }
    }
}

/// A requirement or a success criterion: an identifier and the exact sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The identifier as Spec Kit wrote it.
    pub id: String,
    /// The sentence, unchanged.
    pub text: String,
}

/// An acceptance scenario. Spec Kit gives it no identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario {
    /// The starting situation.
    pub given: String,
    /// The action.
    pub when: String,
    /// The expected result.
    pub then: String,
    /// The requirement identifiers the scenario text cites.
    pub cited: BTreeSet<String>,
}

/// A user story with its scenarios.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Story {
    /// The number in the heading.
    pub number: u32,
    /// The title in the heading.
    pub title: String,
    /// The priority in the heading.
    pub priority: StoryPriority,
    /// The first paragraph of the story.
    pub narrative: String,
    /// The requirement identifiers the story text cites outside its scenarios.
    pub cited: BTreeSet<String>,
    /// The scenarios, in file order.
    pub scenarios: Vec<Scenario>,
}

/// A question and its answer from the clarifications section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clarification {
    /// The date of the session heading.
    pub session: String,
    /// The question.
    pub question: String,
    /// The answer.
    pub answer: String,
}

/// An open `[NEEDS CLARIFICATION: ...]` marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    /// The line, counted from 1.
    pub line: u32,
    /// The question inside the marker.
    pub question: String,
}

/// A specification read from `spec.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSpec {
    /// The name in the heading.
    pub title: String,
    /// The `Created` date, `YYYY-MM-DD`.
    pub created: String,
    /// The `Status` value. Spec Kit writes `Draft` and nothing moves it on.
    pub status: String,
    /// The text after `User description:` in the `Input` line, without the outer quotes.
    pub input: String,
    /// The answered questions.
    pub clarifications: Vec<Clarification>,
    /// The user stories.
    pub stories: Vec<Story>,
    /// The edge cases, in file order.
    pub edge_cases: Vec<String>,
    /// The functional requirements, in file order.
    pub requirements: Vec<Item>,
    /// The success criteria, in file order.
    pub success_criteria: Vec<Item>,
    /// The assumptions, in file order.
    pub assumptions: Vec<String>,
    /// The markers that are still open.
    pub markers: Vec<Marker>,
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("the pattern is a valid regular expression")
}

static H1: LazyLock<Regex> = LazyLock::new(|| re(r"^# Feature Specification:\s*(\S.*?)\s*$"));
static CREATED: LazyLock<Regex> = LazyLock::new(|| re(r"^\*\*Created\*\*:\s*(\S.*?)\s*$"));
static STATUS: LazyLock<Regex> = LazyLock::new(|| re(r"^\*\*Status\*\*:\s*(\S.*?)\s*$"));
static INPUT: LazyLock<Regex> = LazyLock::new(|| re(r"^\*\*Input\*\*:\s*(\S.*?)\s*$"));
static H2: LazyLock<Regex> = LazyLock::new(|| re(r"^## (\S.*?)\s*$"));
static H3: LazyLock<Regex> = LazyLock::new(|| re(r"^### (\S.*?)\s*$"));
static STORY: LazyLock<Regex> =
    LazyLock::new(|| re(r"^User Story ([0-9]+) - (.+?) \(Priority: (P[0-9]+)\)$"));
static SESSION: LazyLock<Regex> = LazyLock::new(|| re(r"^Session ([0-9]{4}-[0-9]{2}-[0-9]{2})$"));
static DATE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$"));
static SCENARIO: LazyLock<Regex> = LazyLock::new(|| {
    re(
        r"^[0-9]+\.\s+\*\*Given\*\*\s+(.+?)\s*,?\s+\*\*When\*\*\s+(.+?)\s*,?\s+\*\*Then\*\*\s+(.+?)\s*$",
    )
});
static NUMBERED: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9]+\.\s"));
static ITEM: LazyLock<Regex> = LazyLock::new(|| re(r"^- \*\*([A-Z]+-[0-9]+)\*\*:\s*(\S.*?)\s*$"));
static ANY_ITEM: LazyLock<Regex> = LazyLock::new(|| re(r"^- \*\*[A-Z]+-"));
static FR: LazyLock<Regex> = LazyLock::new(|| re(r"FR-[0-9]{3,}"));
static MARKER: LazyLock<Regex> =
    LazyLock::new(|| re(r"\[NEEDS CLARIFICATION:\s*([^\]]*[^\]\s])\s*\]"));
static QA: LazyLock<Regex> = LazyLock::new(|| re(r"^- Q:\s*(.+?)\s+(?:→|->)\s+A:\s*(\S.*?)\s*$"));
static GROUP_LABEL: LazyLock<Regex> = LazyLock::new(|| re(r"^\*\*[^*]+\*\*:?$"));

/// The value of the `Input` line without its `User description:` label and quotes.
fn input_value(raw: &str) -> String {
    let value = raw.strip_prefix("User description:").unwrap_or(raw).trim();
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
        .to_owned()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Header,
    Clarifications,
    Scenarios,
    Requirements,
    Success,
    Assumptions,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sub {
    None,
    Story,
    EdgeCases,
    Functional,
    Outcomes,
    Entities,
}

/// Joins the indented lines that continue a list item onto the item.
fn push_or_continue(list: &mut Vec<String>, line: &str, starts_item: bool, item: String) {
    if starts_item {
        list.push(item);
    } else if line.starts_with(char::is_whitespace)
        && let Some(last) = list.last_mut()
    {
        last.push(' ');
        last.push_str(line.trim());
    }
}

/// Reads a `spec.md`.
///
/// # Errors
/// A [`ParseFailure`] for the first structure that is not the one Spec Kit defines: a missing
/// heading field, a missing required section, a story without a priority or a scenario, a
/// scenario that is not Given, When and Then, a requirement line that is not `- **FR-nnn**:`, a
/// repeated identifier.
pub fn parse_spec(text: &str) -> Result<ParsedSpec, ParseFailure> {
    use ParseReason::{BadId, SectionMissing};
    let mut title = None;
    let mut created = None;
    let mut status = None;
    let mut input = None;
    let mut clarifications = Vec::new();
    let mut stories: Vec<Story> = Vec::new();
    let mut edge_cases: Vec<String> = Vec::new();
    let mut requirements: Vec<Item> = Vec::new();
    let mut success_criteria: Vec<Item> = Vec::new();
    let mut assumptions: Vec<String> = Vec::new();
    let mut markers = Vec::new();
    let mut seen = BTreeSet::new();
    let mut session = String::new();

    let mut section = Section::Header;
    let mut sub = Sub::None;
    let mut in_scenarios = false;
    let mut narrative_done = false;
    // The text of the current scenario while its continuation lines are read.
    let mut pending_scenario: Option<(usize, String)> = None;

    let finish_scenario = |stories: &mut Vec<Story>,
                           pending: &mut Option<(usize, String)>|
     -> Result<(), ParseFailure> {
        if let Some((line, joined)) = pending.take() {
            let caps = SCENARIO.captures(&joined).ok_or(ParseFailure::new(
                SectionMissing,
                "scenario-parts",
                line,
            ))?;
            let story = stories.last_mut().ok_or(ParseFailure::new(
                SectionMissing,
                "scenario-parts",
                line,
            ))?;
            story.scenarios.push(Scenario {
                given: caps[1].to_owned(),
                when: caps[2].to_owned(),
                then: caps[3].to_owned(),
                cited: FR
                    .find_iter(&joined)
                    .map(|m| m.as_str().to_owned())
                    .collect(),
            });
        }
        Ok(())
    };

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim_end();
        for found in MARKER.captures_iter(trimmed) {
            if section != Section::Clarifications {
                markers.push(Marker {
                    line: number as u32,
                    question: found[1].to_owned(),
                });
            }
        }
        if let Some(caps) = H2.captures(trimmed) {
            finish_scenario(&mut stories, &mut pending_scenario)?;
            let name = caps[1].split(" *(").next().unwrap_or("").trim().to_owned();
            section = match name.as_str() {
                "Clarifications" => Section::Clarifications,
                "User Scenarios & Testing" => Section::Scenarios,
                "Requirements" => Section::Requirements,
                "Success Criteria" => Section::Success,
                "Assumptions" => Section::Assumptions,
                _ => Section::Other,
            };
            sub = Sub::None;
            in_scenarios = false;
            continue;
        }
        if section == Section::Header {
            if let Some(caps) = H1.captures(trimmed) {
                title = Some(caps[1].to_owned());
            } else if let Some(caps) = CREATED.captures(trimmed) {
                created = Some((number, caps[1].to_owned()));
            } else if let Some(caps) = STATUS.captures(trimmed) {
                status = Some(caps[1].to_owned());
            } else if let Some(caps) = INPUT.captures(trimmed) {
                input = Some(input_value(&caps[1]));
            }
            continue;
        }
        if let Some(caps) = H3.captures(trimmed) {
            finish_scenario(&mut stories, &mut pending_scenario)?;
            let name = caps[1].to_owned();
            in_scenarios = false;
            narrative_done = false;
            sub = match section {
                Section::Scenarios if name.starts_with("User Story") => {
                    let story = STORY.captures(&name).ok_or(ParseFailure::new(
                        SectionMissing,
                        "story-heading",
                        number,
                    ))?;
                    let priority = match &story[3] {
                        "P1" => StoryPriority::P1,
                        "P2" => StoryPriority::P2,
                        "P3" => StoryPriority::P3,
                        _ => return Err(ParseFailure::new(BadId, "story-priority", number)),
                    };
                    stories.push(Story {
                        number: story[1].parse().unwrap_or(0),
                        title: story[2].to_owned(),
                        priority,
                        narrative: String::new(),
                        cited: BTreeSet::new(),
                        scenarios: Vec::new(),
                    });
                    Sub::Story
                }
                Section::Scenarios if name.starts_with("Edge Cases") => Sub::EdgeCases,
                Section::Requirements if name.starts_with("Functional Requirements") => {
                    Sub::Functional
                }
                Section::Requirements if name.starts_with("Key Entities") => Sub::Entities,
                Section::Success if name.starts_with("Measurable Outcomes") => Sub::Outcomes,
                Section::Clarifications => {
                    if let Some(found) = SESSION.captures(&name) {
                        session = found[1].to_owned();
                    }
                    Sub::None
                }
                _ => Sub::None,
            };
            continue;
        }
        match (section, sub) {
            (Section::Clarifications, _) => {
                if trimmed.starts_with("- Q:") {
                    let caps = QA.captures(trimmed).ok_or(ParseFailure::new(
                        SectionMissing,
                        "clarification-line",
                        number,
                    ))?;
                    clarifications.push(Clarification {
                        session: session.clone(),
                        question: caps[1].to_owned(),
                        answer: caps[2].to_owned(),
                    });
                }
            }
            (Section::Scenarios, Sub::Story) => {
                if trimmed.starts_with("**Acceptance Scenarios**") {
                    in_scenarios = true;
                    continue;
                }
                let story = stories.last_mut().expect("a story is open");
                if in_scenarios {
                    if NUMBERED.is_match(trimmed) {
                        finish_scenario(&mut stories, &mut pending_scenario)?;
                        pending_scenario = Some((number, trimmed.to_owned()));
                    } else if trimmed.starts_with(char::is_whitespace)
                        && !trimmed.trim().is_empty()
                        && let Some((_, joined)) = pending_scenario.as_mut()
                    {
                        joined.push(' ');
                        joined.push_str(trimmed.trim());
                    } else if trimmed.trim().is_empty() || trimmed.starts_with("---") {
                        finish_scenario(&mut stories, &mut pending_scenario)?;
                    }
                } else if !trimmed.trim().is_empty() && !trimmed.starts_with("---") {
                    if !narrative_done && !trimmed.starts_with("**") {
                        story.narrative = trimmed.trim().to_owned();
                        narrative_done = true;
                    }
                    story
                        .cited
                        .extend(FR.find_iter(trimmed).map(|m| m.as_str().to_owned()));
                }
            }
            (Section::Scenarios, Sub::EdgeCases) => {
                if let Some(bullet) = trimmed.strip_prefix("- ") {
                    edge_cases.push(bullet.trim().to_owned());
                } else if trimmed.starts_with(char::is_whitespace) && !trimmed.trim().is_empty() {
                    push_or_continue(&mut edge_cases, trimmed, false, String::new());
                }
            }
            (Section::Requirements, Sub::Functional) | (Section::Success, Sub::Outcomes) => {
                let target = if section == Section::Success {
                    &mut success_criteria
                } else {
                    &mut requirements
                };
                let prefix = if section == Section::Success {
                    "SC"
                } else {
                    "FR"
                };
                if ANY_ITEM.is_match(trimmed) {
                    let caps = ITEM.captures(trimmed).ok_or(ParseFailure::new(
                        BadId,
                        "item-line",
                        number,
                    ))?;
                    let id = caps[1].to_owned();
                    let well_formed = id
                        .strip_prefix(prefix)
                        .and_then(|rest| rest.strip_prefix('-'))
                        .is_some_and(|digits| {
                            digits.len() >= 3 && digits.bytes().all(|b| b.is_ascii_digit())
                        });
                    if !well_formed {
                        return Err(ParseFailure::new(BadId, "item-id", number));
                    }
                    if !seen.insert(id.clone()) {
                        return Err(ParseFailure::new(BadId, "item-id-duplicate", number));
                    }
                    target.push(Item {
                        id,
                        text: caps[2].to_owned(),
                    });
                } else if trimmed.starts_with(char::is_whitespace) && !trimmed.trim().is_empty() {
                    if let Some(last) = target.last_mut() {
                        last.text.push(' ');
                        last.text.push_str(trimmed.trim());
                    }
                } else if trimmed.starts_with("- ")
                    || (!trimmed.trim().is_empty() && !GROUP_LABEL.is_match(trimmed))
                {
                    return Err(ParseFailure::new(SectionMissing, "item-line", number));
                }
            }
            (Section::Assumptions, _) => {
                if let Some(bullet) = trimmed.strip_prefix("- ") {
                    assumptions.push(bullet.trim().to_owned());
                } else if trimmed.starts_with(char::is_whitespace) && !trimmed.trim().is_empty() {
                    push_or_continue(&mut assumptions, trimmed, false, String::new());
                }
            }
            _ => {}
        }
    }
    finish_scenario(&mut stories, &mut pending_scenario)?;

    let title = title.ok_or(ParseFailure::new(SectionMissing, "title", 0))?;
    let (created_line, created) = created.ok_or(ParseFailure::new(SectionMissing, "created", 0))?;
    if !DATE.is_match(&created) {
        return Err(ParseFailure::new(
            SectionMissing,
            "created-date",
            created_line,
        ));
    }
    let status = status.ok_or(ParseFailure::new(SectionMissing, "status", 0))?;
    let input = input.ok_or(ParseFailure::new(SectionMissing, "input", 0))?;
    for heading in [
        "User Scenarios & Testing",
        "Requirements",
        "Success Criteria",
        "Assumptions",
    ] {
        let present = text
            .lines()
            .filter_map(|line| H2.captures(line.trim_end()))
            .any(|caps| caps[1].split(" *(").next().unwrap_or("").trim() == heading);
        if !present {
            return Err(ParseFailure::new(SectionMissing, "required-section", 0));
        }
    }
    if stories.is_empty() {
        return Err(ParseFailure::new(SectionMissing, "stories", 0));
    }
    if let Some(story) = stories.iter().find(|story| story.scenarios.is_empty()) {
        return Err(ParseFailure::new(
            SectionMissing,
            "story-scenarios",
            story.number as usize,
        ));
    }
    if requirements.is_empty() {
        return Err(ParseFailure::new(SectionMissing, "requirements", 0));
    }
    Ok(ParsedSpec {
        title,
        created,
        status,
        input,
        clarifications,
        stories,
        edge_cases,
        requirements,
        success_criteria,
        assumptions,
        markers,
    })
}

/// One item of a checklist file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecklistItem {
    /// The identifier at the start of the item, such as `CHK001`, when it has one.
    pub id: Option<String>,
    /// The text of the item without the identifier.
    pub text: String,
    /// Whether the file shows the item ticked. A tick is a self-assessment and counts as nothing.
    pub ticked: bool,
    /// The line, counted from 1.
    pub line: u32,
}

static CHECK: LazyLock<Regex> = LazyLock::new(|| re(r"^- \[( |x|X)\]\s+(\S.*?)\s*$"));
static CHECK_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^([A-Z]{2,5}[0-9]{3,})\s+(\S.*)$"));

/// Reads the items of a checklist file. Lines that are not checkboxes (notes, headings, reviewer
/// notes under an item) are not items.
#[must_use]
pub fn parse_checklist(text: &str) -> Vec<ChecklistItem> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let caps = CHECK.captures(line.trim_end())?;
            let body = caps[2].to_owned();
            let (id, text) = match CHECK_ID.captures(&body) {
                Some(split) => (Some(split[1].to_owned()), split[2].to_owned()),
                None => (None, body),
            };
            Some(ChecklistItem {
                id,
                text,
                ticked: &caps[1] != " ",
                line: (index + 1) as u32,
            })
        })
        .collect()
}

/// The feature directory `.specify/feature.json` points at.
///
/// # Errors
/// `None` when the file is not JSON with a text `feature_directory`.
#[must_use]
pub fn feature_pointer(bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value
        .get("feature_directory")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "# Feature Specification: Word count\n\n**Feature Branch**: `x`\n\n**Created**: 2026-10-27\n\n**Status**: Draft\n\n**Input**: User description: \"Write it\"\n\n## User Scenarios & Testing *(mandatory)*\n\n### User Story 1 - Count words (Priority: P1)\n\nA person counts words.\n\n**Acceptance Scenarios**:\n\n1. **Given** a file with two words, **When** the tool runs, **Then** it prints 2.\n\n### Edge Cases\n\n- Out of scope: nothing else.\n\n## Requirements *(mandatory)*\n\n### Functional Requirements\n\n- **FR-001**: The tool MUST print the count.\n\n## Success Criteria *(mandatory)*\n\n### Measurable Outcomes\n\n- **SC-001**: 100% of runs print a count.\n\n## Assumptions\n\n- Risk: a file may be large.\n";

    #[test]
    fn a_minimal_specification_is_read() {
        let spec = parse_spec(MINIMAL).expect("the minimal specification parses");
        assert_eq!(spec.title, "Word count");
        assert_eq!(spec.input, "Write it");
        assert_eq!(spec.stories.len(), 1);
        assert_eq!(spec.stories[0].priority, StoryPriority::P1);
        assert_eq!(spec.stories[0].scenarios[0].when, "the tool runs");
        assert_eq!(spec.requirements[0].id, "FR-001");
        assert_eq!(spec.success_criteria[0].id, "SC-001");
        assert!(spec.markers.is_empty());
    }

    #[test]
    fn each_structure_the_parser_does_not_know_is_a_parse_failure() {
        let cases: [(&str, &str, &str); 9] = [
            ("# Feature Specification: Word count", "", "title"),
            (
                "**Created**: 2026-10-27",
                "**Created**: 27/10/2026",
                "created-date",
            ),
            ("**Status**: Draft\n", "", "status"),
            ("(Priority: P1)", "(Priority: P4)", "story-priority"),
            ("(Priority: P1)", "(Priority high)", "story-heading"),
            ("**Then** it prints 2.", "it prints 2.", "scenario-parts"),
            ("- **FR-001**:", "- **FR-1**:", "item-id"),
            ("## Assumptions", "## Notes", "required-section"),
            (
                "- **FR-001**: The tool MUST print the count.",
                "- **FR-001**: The tool MUST print the count.\n- **FR-001**: Again.",
                "item-id-duplicate",
            ),
        ];
        for (from, to, rule) in cases {
            let text = MINIMAL.replace(from, to);
            let failure = parse_spec(&text).expect_err(rule);
            assert_eq!(failure.rule, rule, "{rule}");
        }
    }

    #[test]
    fn a_story_without_a_scenario_is_a_parse_failure() {
        let text = MINIMAL.replace(
            "1. **Given** a file with two words, **When** the tool runs, **Then** it prints 2.\n",
            "",
        );
        assert_eq!(
            parse_spec(&text).expect_err("no scenario").rule,
            "story-scenarios"
        );
    }

    #[test]
    fn a_truncated_file_is_a_parse_failure_and_never_a_guess() {
        // Cut inside the header, inside a story, before each required section.
        for marker in [
            "**Status**",
            "**Acceptance Scenarios**",
            "### Edge Cases",
            "## Requirements",
            "## Success Criteria",
            "## Assumptions",
        ] {
            let at = MINIMAL.find(marker).expect("the marker is in the text");
            assert!(parse_spec(&MINIMAL[..at]).is_err(), "cut before {marker}");
        }
    }

    #[test]
    fn a_marker_is_found_with_its_question_and_a_bare_mention_is_not() {
        let text = MINIMAL.replace(
            "- Risk: a file may be large.",
            "- Risk: a file may be large.\n- Unknown limit [NEEDS CLARIFICATION: how large may a file be?]\n- No [NEEDS CLARIFICATION] markers remain.",
        );
        let spec = parse_spec(&text).expect("parses");
        assert_eq!(spec.markers.len(), 1);
        assert_eq!(spec.markers[0].question, "how large may a file be?");
    }

    #[test]
    fn a_checklist_tick_is_read_and_a_note_is_not_an_item() {
        let text = "# Checklist\n\n- [x] No implementation details\n- [ ] CHK001 Is the gate defined? [Gap]\n  - Reviewer note: Open.\n- [X] CHK002 Done\n";
        let items = parse_checklist(text);
        assert_eq!(items.len(), 3);
        assert!(items[0].ticked && items[0].id.is_none());
        assert_eq!(items[1].id.as_deref(), Some("CHK001"));
        assert!(!items[1].ticked);
        assert!(items[2].ticked);
    }

    #[test]
    fn the_feature_pointer_is_read() {
        assert_eq!(
            feature_pointer(br#"{"feature_directory":"specs/a"}"#).as_deref(),
            Some("specs/a")
        );
        assert_eq!(feature_pointer(b"{}"), None);
        assert_eq!(feature_pointer(b"no"), None);
    }
}
