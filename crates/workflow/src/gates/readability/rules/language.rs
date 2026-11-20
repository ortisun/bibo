//! The language rules: English prose, quotations, abbreviations, raw identifiers, filler and long
//! sentences.
//!
//! Prose is what is left of a line after fenced code, inline code, link targets, web addresses
//! and double-quoted spans are taken out, and blockquote lines are left aside (policy section
//! 2.2: a quotation is evidence, kept as written and explained in English next to it).
//!
//! Characters: the text is read as Unicode, because it is natural language. Abbreviations are
//! the exception. They are written in the ASCII capitals of the pattern in the catalog.

use std::collections::BTreeMap;

use super::super::artifact::DocumentType;
use super::super::catalog::{Language, Lists};
use super::super::lang::is_portuguese;
use super::super::text::{
    LineKind, Paragraph, blank_spans, count_words, heading_text, list_marker, paragraphs,
    prose_line, quote_spans, sentences, strip_brackets, strip_inline_code, strip_link_targets,
    strip_urls,
};
use super::{Ctx, Draft, Part};

/// The longest sentence, in words, that the rule `text-long-sentence` accepts.
const MAX_SENTENCE_WORDS: usize = 35;
/// The most abbreviations a message names.
const MAX_NAMED: usize = 5;

fn detects_portuguese(ctx: &Ctx<'_>) -> bool {
    ctx.catalog
        .lists()
        .languages
        .contains(&Language::Portuguese)
}

/// A unit that the detector may call non-English: at least four words, and Portuguese.
fn is_non_english(unit: &str) -> bool {
    count_words(unit) >= 4 && is_portuguese(unit)
}

/// `text-not-english`.
pub(super) fn not_english(ctx: &Ctx<'_>) -> Option<Draft> {
    if !detects_portuguese(ctx) {
        return None;
    }
    let title = prose_line(ctx.artifact.title);
    let in_title = sentences(&title)
        .into_iter()
        .filter(|sentence| is_non_english(sentence))
        .count();
    let mut in_body = 0_usize;
    let mut first_line = None;
    for Paragraph { line, text } in paragraphs(&ctx.body, true) {
        for sentence in sentences(&text) {
            if is_non_english(sentence) {
                in_body += 1;
                first_line.get_or_insert(line);
            }
        }
    }
    let total = in_title + in_body;
    if total == 0 {
        return None;
    }
    let message = format!(
        "{total} sentence(s) outside quotations and code appear to be written in Portuguese. Human-facing text is written in English, and the original wording is kept only as a marked quotation."
    );
    Some(if in_title > 0 {
        Draft::title(message)
    } else {
        Draft {
            part: Part::Body,
            line: first_line,
            message,
        }
    })
}

fn non_space(text: &str) -> usize {
    text.chars().filter(|c| !c.is_whitespace()).count()
}

/// `text-quotation-dominates`: more than half of the prose is non-English quotation.
pub(super) fn quotation_dominates(ctx: &Ctx<'_>) -> Option<Draft> {
    if !detects_portuguese(ctx) {
        return None;
    }
    let mut quoted = 0_usize;
    let mut prose = 0_usize;
    let mut block = String::new();
    let mut first_quote_line = None;
    let end_block = |block: &mut String, quoted: &mut usize| {
        if is_portuguese(block) {
            *quoted += non_space(block);
        }
        block.clear();
    };
    for line in &ctx.body.lines {
        let trimmed = line.trimmed();
        let text = match line.kind {
            LineKind::Quote => {
                first_quote_line.get_or_insert(line.number);
                block.push(' ');
                block.push_str(trimmed.trim_start_matches('>'));
                continue;
            }
            LineKind::Prose => trimmed,
            LineKind::Heading => heading_text(trimmed),
            LineKind::Item => {
                let (length, _) = list_marker(trimmed).unwrap_or_default();
                trimmed.get(length..).unwrap_or_default()
            }
            LineKind::Blank | LineKind::Code | LineKind::Table => "",
        };
        if !block.is_empty() {
            end_block(&mut block, &mut quoted);
        }
        let masked = strip_urls(&strip_link_targets(&strip_inline_code(text)));
        let spans = quote_spans(&masked);
        for (start, end) in &spans {
            let span = masked.get(*start..*end).unwrap_or_default();
            let inner = span.trim_matches(['"', '\u{201c}', '\u{201d}']);
            if is_portuguese(inner) {
                quoted += non_space(inner);
            }
        }
        prose += non_space(&blank_spans(&masked, &spans));
    }
    end_block(&mut block, &mut quoted);
    (quoted > prose).then(|| Draft {
        part: Part::Body,
        line: first_quote_line,
        message: format!(
            "Most of the prose is non-English quotation: {quoted} characters of quotation against {prose} characters of English explanation."
        ),
    })
}

/// Where an abbreviation was met and whether it was spelled out there.
#[derive(Clone, Copy)]
struct Mention {
    in_title: bool,
    line: Option<u32>,
    expanded: bool,
}

struct Tracked {
    order: usize,
    first: Mention,
    first_body: Option<Mention>,
}

fn touches_name(c: char) -> bool {
    c.is_alphanumeric() || c == '-' || c == '_'
}

/// True when the line has at least two words of three or more letters and all of them are upper
/// case. Such a line is a heading in capitals or a label, and every word in it would look like an
/// abbreviation.
fn is_shouting_line(text: &str) -> bool {
    let long: Vec<&str> = text
        .split_whitespace()
        .filter(|token| token.chars().filter(|c| c.is_alphabetic()).count() >= 3)
        .collect();
    long.len() >= 2
        && long.iter().all(|token| {
            token
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(char::is_uppercase)
        })
}

/// `(letters, start, end)` of each abbreviation candidate: two to five ASCII capitals and an
/// optional lower-case `s`, with no letter, digit, hyphen or underscore on either side.
fn candidates(text: &str) -> Vec<(&str, usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if !bytes.get(at).is_some_and(u8::is_ascii_uppercase) {
            at += 1;
            continue;
        }
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_uppercase) {
            at += 1;
        }
        let run = at - start;
        let before_ok = text
            .get(..start)
            .and_then(|head| head.chars().next_back())
            .is_none_or(|c| !touches_name(c));
        if !(2..=5).contains(&run) || !before_ok {
            continue;
        }
        let end = if bytes.get(at) == Some(&b's') {
            at + 1
        } else {
            at
        };
        let after_ok = text
            .get(end..)
            .and_then(|tail| tail.chars().next())
            .is_none_or(|c| !touches_name(c));
        if after_ok && let Some(letters) = text.get(start..at) {
            out.push((letters, start, end));
        }
    }
    out
}

fn words_in(text: &str) -> usize {
    text.split_whitespace()
        .filter(|token| token.chars().any(char::is_alphabetic))
        .count()
}

/// True when the abbreviation at `start..end` is spelled out: it is followed by a parenthesis of
/// two or more words, or it sits alone in parentheses after two or more words.
fn is_expanded(text: &str, start: usize, end: usize) -> bool {
    let after = text.get(end..).unwrap_or_default();
    if let Some(inner) = after.trim_start().strip_prefix('(') {
        let window: String = inner.chars().take(200).collect();
        if let Some(close) = window.find(')')
            && words_in(window.get(..close).unwrap_or_default()) >= 2
        {
            return true;
        }
    }
    let head = text.get(..start).unwrap_or_default();
    match head.strip_suffix('(') {
        Some(before) if after.starts_with(')') => {
            before
                .split_whitespace()
                .rev()
                .take(2)
                .filter(|token| token.chars().any(char::is_alphabetic))
                .count()
                == 2
        }
        _ => false,
    }
}

fn scan_line(
    text: &str,
    in_title: bool,
    line: Option<u32>,
    lists: &Lists,
    tracked: &mut BTreeMap<String, Tracked>,
) {
    if is_shouting_line(text) {
        return;
    }
    for (letters, start, end) in candidates(text) {
        if lists.acronym_allowlist.contains(letters)
            || lists.not_abbreviation_words.contains(letters)
        {
            continue;
        }
        let mention = Mention {
            in_title,
            line,
            expanded: is_expanded(text, start, end),
        };
        let next_order = tracked.len();
        let entry = tracked.entry(letters.to_owned()).or_insert(Tracked {
            order: next_order,
            first: mention,
            first_body: None,
        });
        if !in_title && entry.first_body.is_none() {
            entry.first_body = Some(mention);
        }
    }
}

/// `text-abbreviation-unexpanded`.
pub(super) fn abbreviation_unexpanded(ctx: &Ctx<'_>) -> Option<Draft> {
    let lists = ctx.catalog.lists();
    let mut tracked = BTreeMap::new();
    let title = strip_brackets(&prose_line(ctx.artifact.title));
    scan_line(&title, true, None, lists, &mut tracked);
    for line in &ctx.body.lines {
        if matches!(
            line.kind,
            LineKind::Prose | LineKind::Item | LineKind::Heading | LineKind::Table
        ) {
            let text = strip_brackets(&prose_line(line.trimmed()));
            scan_line(&text, false, Some(line.number), lists, &mut tracked);
        }
    }
    let mut flagged: Vec<(&String, &Tracked)> = tracked
        .iter()
        .filter(|(_, state)| {
            let excused = state.first_body.is_some_and(|body| body.expanded);
            !(state.first.expanded || (state.first.in_title && excused))
        })
        .collect();
    flagged.sort_by_key(|(_, state)| state.order);
    let (_, first) = flagged.first()?;
    let names: Vec<&str> = flagged
        .iter()
        .take(MAX_NAMED)
        .map(|(name, _)| name.as_str())
        .collect();
    let more = flagged.len().saturating_sub(MAX_NAMED);
    let mut list = names.join(", ");
    if more > 0 {
        list.push_str(&format!(" and {more} more"));
    }
    let message = format!(
        "The text uses {list} without spelling the abbreviation out at its first mention, for example \"discounted cash flow (DCF)\"."
    );
    Some(if first.first.in_title {
        Draft::title(message)
    } else {
        Draft {
            part: Part::Body,
            line: first.first.line,
            message,
        }
    })
}

/// True when `text` holds a UUID in its textual form, with no word character on either side.
fn has_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    (0..bytes.len().saturating_sub(35)).any(|at| {
        let shape = bytes.get(at..at + 36).is_some_and(|window| {
            window.iter().enumerate().all(|(i, b)| match i {
                8 | 13 | 18 | 23 => *b == b'-',
                _ => b.is_ascii_hexdigit(),
            })
        });
        shape
            && text
                .get(..at)
                .and_then(|head| head.chars().next_back())
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
            && text
                .get(at + 36..)
                .and_then(|tail| tail.chars().next())
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
    })
}

/// `text-raw-internal-id`.
pub(super) fn raw_internal_id(ctx: &Ctx<'_>) -> Option<Draft> {
    let clean = |text: &str| strip_urls(&strip_link_targets(&strip_inline_code(text)));
    let message = "A UUID appears in running text. Identifiers belong in metadata, in a link or in a code span.";
    if has_uuid(&clean(ctx.artifact.title)) {
        return Some(Draft::title(message.to_owned()));
    }
    ctx.body
        .text_lines()
        .find(|line| has_uuid(&clean(line.text)))
        .map(|line| Draft {
            part: Part::Body,
            line: Some(line.number),
            message: message.to_owned(),
        })
}

/// The phrases of the list that `text` contains, ignoring case and the curly apostrophe. Code,
/// links and quotations are taken out first.
fn filler_in<'p>(text: &str, phrases: &'p [String]) -> Vec<&'p str> {
    let lowered = prose_line(text).to_lowercase().replace('\u{2019}', "'");
    phrases
        .iter()
        .filter(|phrase| lowered.contains(phrase.as_str()))
        .map(String::as_str)
        .collect()
}

/// `text-filler-phrase`.
pub(super) fn filler_phrase(ctx: &Ctx<'_>) -> Option<Draft> {
    let phrases = &ctx.catalog.lists().filler_phrases;
    let mut first: Option<(Part, Option<u32>)> = None;
    let mut names: Vec<&str> = filler_in(ctx.artifact.title, phrases);
    if !names.is_empty() {
        first = Some((Part::Title, None));
    }
    for line in ctx
        .body
        .lines
        .iter()
        .filter(|line| !matches!(line.kind, LineKind::Code | LineKind::Quote))
    {
        for hit in filler_in(line.text, phrases) {
            first.get_or_insert((Part::Body, Some(line.number)));
            if !names.contains(&hit) {
                names.push(hit);
            }
        }
    }
    let (part, line) = first?;
    Some(Draft {
        part,
        line,
        message: format!(
            "The text contains chatbot filler or marketing phrasing: \"{}\". State the fact instead: what changed and how it was checked.",
            names.join("\", \"")
        ),
    })
}

/// `text-long-sentence`.
pub(super) fn long_sentence(ctx: &Ctx<'_>) -> Option<Draft> {
    if ctx.artifact.doc_type == Some(DocumentType::Reference) {
        return None;
    }
    let mut count = 0_usize;
    let mut longest = 0_usize;
    let mut first_line = None;
    for Paragraph { line, text } in paragraphs(&ctx.body, false) {
        for sentence in sentences(&text) {
            let words = count_words(sentence);
            if words > MAX_SENTENCE_WORDS {
                count += 1;
                longest = longest.max(words);
                first_line.get_or_insert(line);
            }
        }
    }
    (count > 0).then(|| Draft {
        part: Part::Body,
        line: first_line,
        message: format!(
            "{count} sentence(s) have more than {MAX_SENTENCE_WORDS} words; the longest has {longest}. Split a long sentence where a new idea starts."
        ),
    })
}
