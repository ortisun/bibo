//! The title rules. Each is a pure function of the title and the word lists.
//!
//! The reference patterns in `rules.json` are written for a regular expression engine. This
//! crate may not depend on one (`workflow` is not allowed `regex` by
//! `docs/architecture/crate-dependency-rules.json`), so each pattern is a small scanner that
//! reads the title once from the start. None of them backtracks, and each one does an amount of
//! work proportional to the length of the title. The scanners follow the definition in the
//! catalog, and the test corpus decides the boundary cases.
//!
//! Characters: the shapes that the patterns spell with `[A-Z]` and `[0-9]` (identifier chains,
//! role stamps, type tags) are matched on ASCII letters. Whether a word is capitalised, and what
//! counts as a letter, use Unicode, because a title can be in any language and the rule about
//! capitals should hold for `Adicionar Salvamento De Progresso` as well.

use super::super::catalog::Lists;
use super::{Ctx, Draft};

const MIN_TITLE_CHARS: usize = 3;
const MAX_TITLE_CHARS: usize = 100;
/// The warning starts above this length (rule `title-too-long`).
const LONG_TITLE_CHARS: usize = 90;

/// White space as the schema pattern `\S` sees it: Unicode white space and the byte order mark.
pub(super) fn is_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `title-schema-shape`: the shape the contract schemas accept for a human title.
pub(super) fn schema_shape(ctx: &Ctx<'_>) -> Option<Draft> {
    let title = ctx.artifact.title;
    let chars = title.chars().count();
    let mut problems = Vec::new();
    if chars < MIN_TITLE_CHARS {
        problems.push(format!(
            "has {chars} characters, fewer than {MIN_TITLE_CHARS}"
        ));
    } else if chars > MAX_TITLE_CHARS {
        problems.push(format!(
            "has {chars} characters, more than {MAX_TITLE_CHARS}"
        ));
    }
    if title.chars().next().is_some_and(is_space) || title.chars().next_back().is_some_and(is_space)
    {
        problems.push("has white space at its start or its end".to_owned());
    }
    if title.chars().any(is_line_break) {
        problems.push("contains a line break".to_owned());
    }
    if problems.is_empty() {
        return None;
    }
    Some(Draft::title(format!(
        "The title {}, but a title is one line of {MIN_TITLE_CHARS} to {MAX_TITLE_CHARS} characters with no surrounding white space.",
        problems.join(" and ")
    )))
}

/// True when `text` starts with an identifier chain followed by a colon or a pipe, or with a
/// bracketed tag. The body rule `body-metadata-prefix` uses the same shape.
pub(super) fn has_opaque_prefix(text: &str) -> bool {
    let rest = text.trim_start_matches(char::is_whitespace);
    if let Some(inner) = rest.strip_prefix('[') {
        return inner.find(']').is_some_and(|end| end > 0);
    }
    identifier_chain_then_separator(rest) || code_then_separator(rest)
}

fn separator_follows(rest: &str) -> bool {
    rest.trim_start_matches(char::is_whitespace)
        .starts_with([':', '|'])
}

fn upper_or_digit(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

/// `[A-Z][A-Z0-9]*([-_][A-Z0-9]+)+` and then `\s*[:|]`.
fn identifier_chain_then_separator(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    let mut at = 1;
    while bytes.get(at).copied().is_some_and(upper_or_digit) {
        at += 1;
    }
    let mut groups = 0_usize;
    while bytes.get(at).is_some_and(|b| matches!(b, b'-' | b'_')) {
        let mut end = at + 1;
        while bytes.get(end).copied().is_some_and(upper_or_digit) {
            end += 1;
        }
        if end == at + 1 {
            break;
        }
        groups += 1;
        at = end;
    }
    groups >= 1 && rest.get(at..).is_some_and(separator_follows)
}

/// `[A-Z]{2,6}[0-9]{1,6}` and then `\s*[:|]`.
fn code_then_separator(rest: &str) -> bool {
    let bytes = rest.as_bytes();
    let letters = bytes.iter().take_while(|b| b.is_ascii_uppercase()).count();
    if !(2..=6).contains(&letters) {
        return false;
    }
    let digits = bytes[letters..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    (1..=6).contains(&digits) && rest.get(letters + digits..).is_some_and(separator_follows)
}

/// `title-opaque-prefix`.
pub(super) fn opaque_prefix(ctx: &Ctx<'_>) -> Option<Draft> {
    has_opaque_prefix(ctx.artifact.title).then(|| {
        Draft::title(
            "The title starts with an identifier, a code or a bracketed tag. Those belong in metadata, not in the title."
                .to_owned(),
        )
    })
}

/// A word that reads as ordinary language: letters and apostrophes only, three letters or more,
/// once the punctuation around it is stripped.
fn is_ordinary_word(token: &str) -> bool {
    let core = token.trim_matches(|c: char| !c.is_alphanumeric());
    let letters = core.chars().filter(|c| c.is_alphabetic()).count();
    letters >= 3
        && core
            .chars()
            .all(|c| c.is_alphabetic() || c == '\'' || c == '\u{2019}')
}

/// True when a bracket group that does not start the title holds a colon, or holds letters and
/// no lower-case letter.
fn has_late_machine_bracket(title: &str) -> bool {
    let start = title.len() - title.trim_start_matches(char::is_whitespace).len();
    let mut at = 0;
    while let Some(open) = title.get(at..).and_then(|rest| rest.find('[')) {
        let open = at + open;
        let Some(close) = title.get(open + 1..).and_then(|rest| rest.find(']')) else {
            return false;
        };
        let inner = title.get(open + 1..open + 1 + close).unwrap_or_default();
        if open > start {
            let letters = inner.chars().any(char::is_alphabetic);
            if inner.contains(':') || (letters && !inner.chars().any(char::is_lowercase)) {
                return true;
            }
        }
        at = open + 1 + close + 1;
    }
    false
}

/// True when the title holds an upper-case role stamp such as `AGENT:BACKEND` or `AGT-QNT`.
fn has_role_stamp(title: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        title.match_indices(prefix.as_str()).any(|(at, _)| {
            let before_ok = title
                .get(..at)
                .and_then(|head| head.chars().next_back())
                .is_none_or(|c| !is_word_char(c));
            let after = title
                .get(at + prefix.len()..)
                .unwrap_or_default()
                .as_bytes();
            let separator_ok = after
                .first()
                .is_some_and(|b| matches!(b, b'-' | b'_' | b':'));
            let name_ok = after
                .get(1)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
            before_ok && separator_ok && name_ok
        })
    })
}

/// `title-machine-label`.
pub(super) fn machine_label(ctx: &Ctx<'_>) -> Option<Draft> {
    let title = ctx.artifact.title;
    let lists = ctx.catalog.lists();
    let mut found = Vec::new();
    if title.contains('|') {
        found.push("a pipe");
    }
    if has_late_machine_bracket(title) {
        found.push("a bracketed tag that is not at the start");
    }
    if has_role_stamp(title, &lists.role_stamp_prefixes) {
        found.push("a role or agent stamp");
    }
    if title.chars().count() >= MIN_TITLE_CHARS && !title.split_whitespace().any(is_ordinary_word) {
        found.push("no ordinary word");
    }
    if found.is_empty() {
        return None;
    }
    Some(Draft::title(format!(
        "The title contains {}. Roles, stages, priorities and identifiers belong in metadata.",
        found.join(" and ")
    )))
}

fn all_generic(words: &[&str], lists: &Lists) -> bool {
    (1..=4).contains(&words.len()) && words.iter().all(|word| lists.generic_words.contains(*word))
}

/// "Edit file A", "Implement part 3": up to two plain words, a placeholder noun, then a single
/// letter or a number, and nothing else.
fn is_placeholder(words: &[&str], lists: &Lists) -> bool {
    let [leading @ .., noun, label] = words else {
        return false;
    };
    leading.len() <= 2
        && leading
            .iter()
            .all(|word| word.bytes().all(|b| b.is_ascii_lowercase()))
        && lists.placeholder_nouns.contains(*noun)
        && (label.len() == 1 && label.bytes().all(|b| b.is_ascii_lowercase())
            || label.bytes().all(|b| b.is_ascii_digit()))
}

/// "Agent task complete": a status subject, then the word item or another subject, then `is` or
/// `has been`, then a status phrase.
fn is_status_report(words: &[&str], lists: &Lists) -> bool {
    let Some((first, mut rest)) = words.split_first() else {
        return false;
    };
    if !lists.status_subjects.contains(*first) {
        return false;
    }
    if let Some((next, after)) = rest.split_first()
        && (lists.status_subjects.contains(*next) || *next == "item")
    {
        rest = after;
    }
    match rest {
        ["is", tail @ ..] | ["has", "been", tail @ ..] => rest = tail,
        _ => {}
    }
    !rest.is_empty() && lists.status_phrases.contains(&rest.join(" "))
}

/// `title-vague`.
pub(super) fn vague(ctx: &Ctx<'_>) -> Option<Draft> {
    let lists = ctx.catalog.lists();
    let lowered = ctx.artifact.title.to_lowercase();
    let cleaned = lowered
        .trim()
        .trim_end_matches(|c: char| c.is_ascii_punctuation() || c == '\u{2026}');
    let words: Vec<&str> = cleaned.split_whitespace().collect();
    (all_generic(&words, lists) || is_placeholder(&words, lists) || is_status_report(&words, lists))
        .then(|| {
            Draft::title(
                "The title names no concrete outcome. It uses only generic words, points at a placeholder, or reports a status."
                    .to_owned(),
            )
        })
}

/// `title-type-tag`: `feat(auth): `, `Fix: `, `URGENT: `.
pub(super) fn type_tag(ctx: &Ctx<'_>) -> Option<Draft> {
    let title = ctx.artifact.title;
    let bytes = title.as_bytes();
    let conventional = ctx
        .catalog
        .lists()
        .conventional_commit_types
        .iter()
        .any(|kind| {
            let Some(head) = bytes.get(..kind.len()) else {
                return false;
            };
            if !head.eq_ignore_ascii_case(kind.as_bytes()) {
                return false;
            }
            let mut rest = title.get(kind.len()..).unwrap_or_default();
            if rest.starts_with('(') {
                match rest.find(')') {
                    Some(close) => rest = rest.get(close + 1..).unwrap_or_default(),
                    None => return false,
                }
            }
            let rest = rest.strip_prefix('!').unwrap_or(rest);
            rest.strip_prefix(':')
                .and_then(|after| after.chars().next())
                .is_some_and(char::is_whitespace)
        });
    let capitals = bytes.iter().take_while(|b| b.is_ascii_uppercase()).count();
    let shouted = capitals >= 3
        && title
            .get(capitals..)
            .and_then(|rest| rest.strip_prefix(':'))
            .and_then(|after| after.chars().next())
            .is_some_and(char::is_whitespace);
    (conventional || shouted).then(|| {
        Draft::title(
            "The title starts with a type tag and a colon. The tag does not make the title clearer."
                .to_owned(),
        )
    })
}

fn letter_count(token: &str) -> usize {
    token.chars().filter(|c| c.is_alphabetic()).count()
}

/// `title-not-sentence-case`: all capitals, or Title Case.
pub(super) fn not_sentence_case(ctx: &Ctx<'_>) -> Option<Draft> {
    let tokens: Vec<&str> = ctx.artifact.title.split_whitespace().collect();
    let long: Vec<&&str> = tokens.iter().filter(|t| letter_count(t) >= 3).collect();
    let all_capitals = long.len() >= 2
        && long.iter().all(|token| {
            token
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(char::is_uppercase)
        });
    let after_first: Vec<&&str> = tokens
        .iter()
        .skip(1)
        .filter(|t| letter_count(t) >= 4)
        .collect();
    let title_case = tokens.len() >= 4
        && after_first.len() >= 3
        && after_first
            .iter()
            .all(|token| token.chars().next().is_some_and(char::is_uppercase));
    if !(all_capitals || title_case) {
        return None;
    }
    let shape = if all_capitals {
        "all capitals"
    } else {
        "Title Case"
    };
    Some(Draft::title(format!(
        "The title is in {shape}. Sentence case capitalises only the first word and proper names."
    )))
}

/// `title-too-long`: 91 to 100 characters. Longer titles break `title-schema-shape` instead.
pub(super) fn too_long(ctx: &Ctx<'_>) -> Option<Draft> {
    let chars = ctx.artifact.title.chars().count();
    (LONG_TITLE_CHARS < chars && chars <= MAX_TITLE_CHARS).then(|| {
        Draft::title(format!(
            "The title has {chars} characters. Aim for {LONG_TITLE_CHARS} or fewer so it reads at a glance."
        ))
    })
}

/// `title-trailing-punctuation`.
pub(super) fn trailing_punctuation(ctx: &Ctx<'_>) -> Option<Draft> {
    ctx.artifact
        .title
        .chars()
        .next_back()
        .filter(|c| matches!(c, '.' | ':' | ';' | ',' | '!' | '\u{2026}'))
        .map(|c| {
            Draft::title(format!(
                "The title ends with the character '{c}', which a title does not need."
            ))
        })
}
