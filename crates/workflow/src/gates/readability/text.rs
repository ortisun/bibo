//! Reading a body line by line, and taking code, quotations and links out of a line.
//!
//! Every function here makes one pass over its input, or two, and none of them searches again
//! from a place it has already searched. That keeps the work proportional to the length of the
//! text however hostile it is: ten thousand opening brackets with no closing one cost ten
//! thousand steps, not ten thousand times ten thousand. Positions are byte offsets, and every
//! slice is cut at the offset of an ASCII character or at a `char` boundary.

use std::collections::HashMap;

/// What a line of the body is, as far as the rules care.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LineKind {
    /// Nothing but white space.
    Blank,
    /// A fence line or a line inside a fenced code block.
    Code,
    /// A Markdown heading of level 1 to 6.
    Heading,
    /// A block quotation line (starts with `>`).
    Quote,
    /// A table row (starts with `|`).
    Table,
    /// A list item, bulleted or numbered.
    Item,
    /// Anything else: running prose.
    Prose,
}

/// One line of the body.
#[derive(Debug, Clone, Copy)]
pub(super) struct Line<'a> {
    /// The line number, from 1.
    pub(super) number: u32,
    /// The text without the line break.
    pub(super) text: &'a str,
    /// What the line is.
    pub(super) kind: LineKind,
}

impl Line<'_> {
    /// The text without its indentation.
    pub(super) fn trimmed(&self) -> &str {
        self.text.trim_start()
    }
}

/// A body split into classified lines. Fenced code is recognised across lines, so a heading or a
/// list item inside a fence is code.
#[derive(Debug, Clone, Default)]
pub(super) struct Body<'a> {
    pub(super) lines: Vec<Line<'a>>,
}

impl<'a> Body<'a> {
    pub(super) fn new(body: &'a str) -> Self {
        let mut fence: Option<(char, usize)> = None;
        let mut lines = Vec::new();
        for (index, raw) in body.split('\n').enumerate() {
            let text = raw.strip_suffix('\r').unwrap_or(raw);
            let trimmed = text.trim_start();
            let kind = if let Some((mark, length)) = fence {
                if closes_fence(trimmed, mark, length) {
                    fence = None;
                }
                LineKind::Code
            } else if let Some(opened) = opens_fence(trimmed) {
                fence = Some(opened);
                LineKind::Code
            } else if trimmed.is_empty() {
                LineKind::Blank
            } else if is_heading(trimmed) {
                LineKind::Heading
            } else if trimmed.starts_with('>') {
                LineKind::Quote
            } else if trimmed.starts_with('|') {
                LineKind::Table
            } else if list_marker(trimmed).is_some() {
                LineKind::Item
            } else {
                LineKind::Prose
            };
            lines.push(Line {
                number: u32::try_from(index + 1).unwrap_or(u32::MAX),
                text,
                kind,
            });
        }
        Self { lines }
    }

    /// The lines that are not code.
    pub(super) fn text_lines(&self) -> impl Iterator<Item = &Line<'a>> {
        self.lines.iter().filter(|line| line.kind != LineKind::Code)
    }
}

/// `(mark, length)` when `trimmed` opens a fenced code block: three or more backticks or tildes.
/// A backtick fence cannot have a backtick in its info string, or it is inline code.
fn opens_fence(trimmed: &str) -> Option<(char, usize)> {
    let mark = trimmed.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let length = trimmed.chars().take_while(|c| *c == mark).count();
    if length < 3 {
        return None;
    }
    let info = trimmed.get(length..).unwrap_or_default();
    (mark != '`' || !info.contains('`')).then_some((mark, length))
}

/// True when `trimmed` is a closing fence for a block opened with `length` of `mark`.
fn closes_fence(trimmed: &str, mark: char, length: usize) -> bool {
    let run = trimmed.chars().take_while(|c| *c == mark).count();
    run >= length
        && trimmed
            .get(run..)
            .is_some_and(|rest| rest.trim().is_empty())
}

fn is_heading(trimmed: &str) -> bool {
    let hashes = trimmed.chars().take_while(|c| *c == '#').count();
    (1..=6).contains(&hashes)
        && trimmed
            .get(hashes..)
            .and_then(|rest| rest.chars().next())
            .is_none_or(char::is_whitespace)
}

/// The text of a heading line without the `#` marks and without closing marks.
pub(super) fn heading_text(trimmed: &str) -> &str {
    trimmed
        .trim_start_matches('#')
        .trim()
        .trim_end_matches('#')
        .trim()
}

/// `(length, ordered)` when `trimmed` starts with a list marker: a bullet or a number, then a
/// space. The length covers the marker and the space.
pub(super) fn list_marker(trimmed: &str) -> Option<(usize, bool)> {
    let mut chars = trimmed.chars();
    let first = chars.next()?;
    if matches!(first, '-' | '*' | '+') {
        return chars
            .next()
            .filter(|c| matches!(c, ' ' | '\t'))
            .map(|_| (2, false));
    }
    if !first.is_ascii_digit() {
        return None;
    }
    let digits = trimmed.chars().take_while(char::is_ascii_digit).count();
    let mut after = trimmed.get(digits..)?.chars();
    let dot = after.next().filter(|c| matches!(c, '.' | ')'))?;
    after
        .next()
        .filter(|c| matches!(c, ' ' | '\t'))
        .map(|_| (digits + dot.len_utf8() + 1, true))
}

/// The label of a line that holds only a label in bold: `**Verification**`, `**Verification:**`
/// or `**Verification**:`.
pub(super) fn bold_label(trimmed: &str) -> Option<&str> {
    let line = trimmed.trim_end();
    ["**", "__"].into_iter().find_map(|marker| {
        let rest = line.strip_prefix(marker)?;
        let end = rest.find(marker)?;
        let tail = rest.get(end + marker.len()..)?;
        (tail.is_empty() || tail == ":").then(|| {
            rest.get(..end)
                .unwrap_or_default()
                .trim()
                .trim_end_matches(':')
                .trim()
        })
    })
}

/// The inline code spans of a line as `(start, end)` byte ranges that include the backticks. An
/// opening run of backticks pairs with the next run of the same length on the same line. A run
/// with no partner is ordinary text.
pub(super) fn code_spans(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes.get(at) == Some(&b'`') {
            let start = at;
            while bytes.get(at) == Some(&b'`') {
                at += 1;
            }
            runs.push((start, at - start));
        } else {
            at += 1;
        }
    }
    // For each run, the next run of the same length, found in one pass from the right.
    let mut next_same: Vec<Option<usize>> = vec![None; runs.len()];
    let mut latest: HashMap<usize, usize> = HashMap::new();
    for (index, (_, length)) in runs.iter().enumerate().rev() {
        if let Some(slot) = next_same.get_mut(index) {
            *slot = latest.get(length).copied();
        }
        latest.insert(*length, index);
    }
    let mut spans = Vec::new();
    let mut index = 0;
    while let Some((start, _)) = runs.get(index) {
        match next_same.get(index).copied().flatten() {
            Some(partner) => {
                let (close, length) = runs.get(partner).copied().unwrap_or_default();
                spans.push((*start, close + length));
                index = partner + 1;
            }
            None => index += 1,
        }
    }
    spans
}

/// `line` with each byte range in `spans` (sorted, not overlapping) replaced by one space.
pub(super) fn blank_spans(line: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(line.len());
    let mut at = 0;
    for (start, end) in spans {
        out.push_str(line.get(at..*start).unwrap_or_default());
        out.push(' ');
        at = *end;
    }
    out.push_str(line.get(at..).unwrap_or_default());
    out
}

/// `line` with its inline code taken out. Each span becomes one space.
pub(super) fn strip_inline_code(line: &str) -> String {
    if line.contains('`') {
        blank_spans(line, &code_spans(line))
    } else {
        line.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(body: &str) -> Vec<LineKind> {
        Body::new(body).lines.iter().map(|l| l.kind).collect()
    }

    #[test]
    fn lines_are_classified_and_fences_hide_what_is_inside() {
        let body = "# Title\n\n- item\n1. step\ntext\n> quote\n| a | b |\n```rust\n# not a heading\n```\nafter";
        assert_eq!(
            kinds(body),
            vec![
                LineKind::Heading,
                LineKind::Blank,
                LineKind::Item,
                LineKind::Item,
                LineKind::Prose,
                LineKind::Quote,
                LineKind::Table,
                LineKind::Code,
                LineKind::Code,
                LineKind::Code,
                LineKind::Prose,
            ]
        );
    }

    #[test]
    fn an_unclosed_fence_runs_to_the_end() {
        assert_eq!(
            kinds("```\n## Verification\nmore"),
            vec![LineKind::Code, LineKind::Code, LineKind::Code]
        );
    }

    #[test]
    fn inline_code_pairs_runs_of_the_same_length() {
        assert_eq!(strip_inline_code("a `b | c` d"), "a   d");
        assert_eq!(strip_inline_code("a ``b ` c`` d"), "a   d");
        assert_eq!(strip_inline_code("a ` b"), "a ` b");
    }

    #[test]
    fn bold_labels_allow_the_colon_inside_or_outside() {
        assert_eq!(bold_label("**Verification**"), Some("Verification"));
        assert_eq!(bold_label("**Verification:**"), Some("Verification"));
        assert_eq!(bold_label("**Verification**:"), Some("Verification"));
        assert_eq!(bold_label("**Verification** is next"), None);
    }

    #[test]
    fn list_markers_need_a_space() {
        assert_eq!(list_marker("- a"), Some((2, false)));
        assert_eq!(list_marker("12. a"), Some((4, true)));
        assert_eq!(list_marker("**bold**"), None);
        assert_eq!(list_marker("-a"), None);
    }
}
