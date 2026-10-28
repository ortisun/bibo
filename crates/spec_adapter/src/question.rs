//! Questions from the skills: the detector and the answer policy.
//!
//! Spec Kit gives no structured signal that a turn is a question. The clarify skill writes a
//! `**Question:**` block as free text and waits, and the specify skill leaves
//! `[NEEDS CLARIFICATION: ...]` markers in the file. The detector finds both. A skill that asked
//! something and a specification that still holds a marker are both routed to a person, and the
//! question reaches the person with its text unchanged.
//!
//! The answer policy is bounded. It counts the questions, stops at the skill's own limit, and
//! auto-accepts a recommended option only for a question it classes as routine, and only when the
//! policy switch for that is on. The switch is off by default.

use std::sync::LazyLock;

use regex::Regex;

/// Where a question came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A `[NEEDS CLARIFICATION: ...]` marker in a file.
    Marker,
    /// A `**Question:**` block in the free text of a skill.
    FreeText,
}

/// A question a skill left open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The question, unchanged.
    pub text: String,
    /// The letter of the option the skill recommends, when it recommends one.
    pub recommended: Option<char>,
    /// Where it came from.
    pub origin: Origin,
}

static BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\*\*Question:\*\*\s*(\S[^\n]*)").expect("a valid pattern"));
static RECOMMENDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\*\*Recommended:\*\*\s*Option\s+([A-Za-z])\b").expect("a valid pattern")
});
static MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[NEEDS CLARIFICATION:\s*([^\]]*[^\]\s])\s*\]").expect("a valid pattern")
});

/// Finds the questions in a piece of text: the `**Question:**` blocks and the markers.
#[must_use]
pub fn detect(text: &str) -> Vec<Question> {
    let mut found = Vec::new();
    let starts: Vec<usize> = BLOCK.find_iter(text).map(|m| m.start()).collect();
    for (index, caps) in BLOCK.captures_iter(text).enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(text.len());
        let start = starts[index];
        let block = &text[start..end];
        found.push(Question {
            text: caps[1].trim().to_owned(),
            recommended: RECOMMENDED
                .captures(block)
                .and_then(|r| r[1].chars().next())
                .map(|c| c.to_ascii_uppercase()),
            origin: Origin::FreeText,
        });
    }
    for caps in MARKER.captures_iter(text) {
        found.push(Question {
            text: caps[1].trim().to_owned(),
            recommended: None,
            origin: Origin::Marker,
        });
    }
    found
}

/// How much a question matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Wording, naming, ordering, formatting. The recommended option may be accepted.
    Routine,
    /// Anything that touches who may do what, data, cost, law, safety or scope. A person decides.
    Material,
}

const MATERIAL_WORDS: [&str; 22] = [
    "authoriz",
    "authoris",
    "permission",
    "access",
    "secur",
    "privacy",
    "personal data",
    "delete",
    "retention",
    "legal",
    "complian",
    "cost",
    "budget",
    "price",
    "scope",
    "credential",
    "secret",
    "who may",
    "who can",
    "approv",
    "production",
    "safety",
];

/// Classes a question by words that make it material. A question with none of them is routine.
#[must_use]
pub fn classify(question: &Question) -> Class {
    let lower = question.text.to_ascii_lowercase();
    if MATERIAL_WORDS.iter().any(|word| lower.contains(word)) {
        Class::Material
    } else {
        Class::Routine
    }
}

/// What to do with a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Put the question to a person, unchanged.
    AskHuman,
    /// Accept the option the skill recommends. The record says the answer was not a person's.
    AutoAccept(char),
    /// Stop: the limit of questions or of rounds is reached. A person is asked to decide how to go on.
    Stop,
}

/// The bounds of the question loop. They are part of the stage contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnswerPolicy {
    /// The most questions in all rounds. The clarify skill's own limit is five per run.
    pub max_questions: usize,
    /// The most rounds of clarification.
    pub max_rounds: u8,
    /// Whether a routine question with a recommended option is accepted without a person.
    pub auto_accept_routine: bool,
}

impl Default for AnswerPolicy {
    fn default() -> Self {
        Self {
            max_questions: 5,
            max_rounds: 2,
            auto_accept_routine: false,
        }
    }
}

impl AnswerPolicy {
    /// Where a question goes. `asked` is how many questions were put before this one, `round` is
    /// the round it belongs to, from 1.
    #[must_use]
    pub fn route(&self, question: &Question, asked: usize, round: u8) -> Route {
        if asked >= self.max_questions || round > self.max_rounds {
            return Route::Stop;
        }
        match (
            self.auto_accept_routine,
            classify(question),
            question.recommended,
        ) {
            (true, Class::Routine, Some(option)) => Route::AutoAccept(option),
            _ => Route::AskHuman,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TURN: &str = "**Question:** Who counts as an \"authorized person\" for filing an issue? (FR-001)\n\nWhy it matters: access.\n\n**Recommended:** Option A - a named allowlist\n\n| Option | Description |\n|--------|-------------|\n| A | allowlist |\n| Short | Provide a different short answer (<=5 words) |\n\nYou can reply with the option letter.";

    #[test]
    fn a_question_block_is_found_with_its_recommendation() {
        let found = detect(TURN);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].recommended, Some('A'));
        assert_eq!(found[0].origin, Origin::FreeText);
        assert!(found[0].text.starts_with("Who counts as"));
    }

    #[test]
    fn a_marker_is_a_question_and_a_completion_report_is_not() {
        let found = detect("The limit is [NEEDS CLARIFICATION: how large may a file be?] for now.");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].origin, Origin::Marker);
        assert!(detect("Clarification complete. 3 questions asked and answered.").is_empty());
    }

    #[test]
    fn a_material_question_always_goes_to_a_person() {
        let policy = AnswerPolicy {
            auto_accept_routine: true,
            ..AnswerPolicy::default()
        };
        let material = &detect(TURN)[0];
        assert_eq!(classify(material), Class::Material);
        assert_eq!(policy.route(material, 0, 1), Route::AskHuman);
    }

    #[test]
    fn a_routine_question_is_accepted_only_when_the_policy_says_so() {
        let routine = Question {
            text: "Should the heading be title case?".to_owned(),
            recommended: Some('B'),
            origin: Origin::FreeText,
        };
        assert_eq!(classify(&routine), Class::Routine);
        assert_eq!(
            AnswerPolicy::default().route(&routine, 0, 1),
            Route::AskHuman
        );
        let on = AnswerPolicy {
            auto_accept_routine: true,
            ..AnswerPolicy::default()
        };
        assert_eq!(on.route(&routine, 0, 1), Route::AutoAccept('B'));
    }

    #[test]
    fn the_loop_stops_at_the_limits() {
        let policy = AnswerPolicy::default();
        let question = &detect(TURN)[0];
        assert_eq!(policy.route(question, 5, 1), Route::Stop);
        assert_eq!(policy.route(question, 0, 3), Route::Stop);
        assert_eq!(policy.route(question, 4, 2), Route::AskHuman);
    }
}
