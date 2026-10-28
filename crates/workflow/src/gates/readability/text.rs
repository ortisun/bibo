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

/// The longest double-quoted span, in characters, that counts as a quotation.
const MAX_QUOTED_CHARS: usize = 300;

/// The double-quoted spans of a line as `(start, end)` byte ranges that include the quote marks.
/// Straight quotes pair in order, and so do curly ones. A span of more than 300 characters is not
/// a quotation: its opening mark is ordinary text and the closing mark may open the next span.
pub(super) fn quote_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut open: Option<(usize, usize)> = None;
    for (count, (at, c)) in line.char_indices().enumerate() {
        match c {
            '"' => match open {
                Some((start, from)) if count - from <= MAX_QUOTED_CHARS + 1 => {
                    spans.push((start, at + 1));
                    open = None;
                }
                _ => open = Some((at, count)),
            },
            '\u{201c}' => open = Some((at, count)),
            '\u{201d}' => {
                if let Some((start, from)) = open.take()
                    && count - from <= MAX_QUOTED_CHARS + 1
                {
                    spans.push((start, at + c.len_utf8()));
                }
            }
            _ => {}
        }
    }
    spans
}

/// `line` with its double-quoted spans taken out.
pub(super) fn strip_quotes(line: &str) -> String {
    blank_spans(line, &quote_spans(line))
}

/// `line` with its square-bracket groups taken out.
pub(super) fn strip_brackets(line: &str) -> String {
    let mut spans = Vec::new();
    let mut open: Option<usize> = None;
    for (at, c) in line.char_indices() {
        match c {
            '[' if open.is_none() => open = Some(at),
            ']' => {
                if let Some(start) = open.take() {
                    spans.push((start, at + 1));
                }
            }
            _ => {}
        }
    }
    blank_spans(line, &spans)
}

/// `line` with each link target, `[text](target)`, taken out. The text stays.
pub(super) fn strip_link_targets(line: &str) -> String {
    if !line.contains("](") {
        return line.to_owned();
    }
    let bytes = line.as_bytes();
    // For each offset, the offset of the first `)` at or after it, found in one pass from the
    // right, so that a line of `](` with no `)` is not searched again at every `](`.
    let mut next_close = vec![usize::MAX; bytes.len() + 1];
    let mut latest = usize::MAX;
    for (at, byte) in bytes.iter().enumerate().rev() {
        if *byte == b')' {
            latest = at;
        }
        if let Some(slot) = next_close.get_mut(at) {
            *slot = latest;
        }
    }
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(found) = line.get(from..).and_then(|rest| rest.find("](")) {
        let open = from + found + 1;
        let close = next_close.get(open + 1).copied().unwrap_or(usize::MAX);
        if close == usize::MAX {
            break;
        }
        spans.push((open, close + 1));
        from = close + 1;
    }
    blank_spans(line, &spans)
}

/// `line` with each `http://` or `https://` address taken out. An address ends at white space or
/// at `<`, `>` or a double quote, and the punctuation that closes a sentence stays outside it.
pub(super) fn strip_urls(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    if !lowered.contains("http") {
        return line.to_owned();
    }
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(found) = lowered.get(from..).and_then(|rest| rest.find("http")) {
        let start = from + found;
        let after = lowered.get(start + 4..).unwrap_or_default();
        let scheme = if after.starts_with("://") {
            7
        } else if after.starts_with("s://") {
            8
        } else {
            from = start + 4;
            continue;
        };
        let tail = line.get(start + scheme..).unwrap_or_default();
        let length = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"'))
            .unwrap_or(tail.len());
        let address = tail.get(..length).unwrap_or_default();
        let kept = address
            .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '\''])
            .len();
        let end = start + scheme + kept;
        spans.push((start, end));
        from = end.max(start + 4);
    }
    blank_spans(line, &spans)
}

/// A line of running prose: inline code, link targets, web addresses and quotations taken out.
pub(super) fn prose_line(line: &str) -> String {
    strip_quotes(&strip_urls(&strip_link_targets(&strip_inline_code(line))))
}

/// A paragraph of prose: consecutive prose lines joined with spaces, already stripped by
/// [`prose_line`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Paragraph {
    /// The line the paragraph starts on.
    pub(super) line: u32,
    /// Its text.
    pub(super) text: String,
}

/// The paragraphs of a body. A blank line, a heading, a table row, a quotation line or a code
/// line ends one, and a list item starts a new one. With `headings`, each heading is a paragraph
/// of its own.
pub(super) fn paragraphs(body: &Body<'_>, headings: bool) -> Vec<Paragraph> {
    let mut out = Vec::new();
    let mut current: Option<Paragraph> = None;
    let flush = |current: &mut Option<Paragraph>, out: &mut Vec<Paragraph>| {
        if let Some(done) = current.take()
            && !done.text.trim().is_empty()
        {
            out.push(done);
        }
    };
    for line in &body.lines {
        let trimmed = line.trimmed();
        match line.kind {
            LineKind::Prose => {
                let text = prose_line(trimmed);
                match current.as_mut() {
                    Some(paragraph) => {
                        paragraph.text.push(' ');
                        paragraph.text.push_str(text.trim());
                    }
                    None => {
                        current = Some(Paragraph {
                            line: line.number,
                            text: text.trim().to_owned(),
                        });
                    }
                }
            }
            LineKind::Item => {
                flush(&mut current, &mut out);
                let (length, _) = list_marker(trimmed).unwrap_or_default();
                current = Some(Paragraph {
                    line: line.number,
                    text: prose_line(trimmed.get(length..).unwrap_or_default())
                        .trim()
                        .to_owned(),
                });
            }
            LineKind::Heading => {
                flush(&mut current, &mut out);
                if headings {
                    out.push(Paragraph {
                        line: line.number,
                        text: prose_line(heading_text(trimmed)).trim().to_owned(),
                    });
                }
            }
            LineKind::Blank | LineKind::Code | LineKind::Quote | LineKind::Table => {
                flush(&mut current, &mut out);
            }
        }
    }
    flush(&mut current, &mut out);
    out
}

/// The sentences of a text: it is cut after a period, an exclamation mark or a question mark
/// that is followed by white space or by the end.
pub(super) fn sentences(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if matches!(c, '.' | '!' | '?') && chars.peek().is_none_or(|(_, next)| next.is_whitespace())
        {
            let end = at + c.len_utf8();
            if let Some(sentence) = text.get(start..end) {
                out.push(sentence);
            }
            start = end;
        }
    }
    if let Some(rest) = text.get(start..)
        && !rest.trim().is_empty()
    {
        out.push(rest);
    }
    out
}

/// The number of whitespace-separated tokens that contain a letter or a digit.
pub(super) fn count_words(text: &str) -> usize {
    text.split_whitespace()
        .filter(|token| token.chars().any(char::is_alphanumeric))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotations_urls_and_link_targets_come_out_and_the_rest_stays() {
        assert_eq!(strip_quotes(r#"a "b c" d"#), "a   d");
        assert_eq!(strip_quotes("a \u{201c}b\u{201d} d"), "a   d");
        assert_eq!(strip_quotes("a \"b"), "a \"b");
        assert_eq!(
            strip_link_targets("see [the run](https://x.test/a) now"),
            "see [the run]  now"
        );
        assert_eq!(strip_urls("see https://x.test/a. Next"), "see  . Next");
        assert_eq!(strip_brackets("a [b c] d"), "a   d");
    }

    #[test]
    fn a_quotation_longer_than_three_hundred_characters_is_not_a_quotation() {
        let long = format!("x \"{}\" y", "w".repeat(310));
        assert_eq!(strip_quotes(&long), long);
        let short = format!("x \"{}\" y", "w".repeat(300));
        assert_eq!(strip_quotes(&short), "x   y");
    }

    #[test]
    fn sentences_split_after_terminators_followed_by_white_space() {
        assert_eq!(
            sentences("It is 0.1 s long. Is it? Yes!"),
            vec!["It is 0.1 s long.", " Is it?", " Yes!"]
        );
    }

    #[test]
    fn paragraphs_join_prose_lines_and_split_at_items() {
        let body = Body::new("one\ntwo\n\n- three\nfour\n- five\n> quoted");
        let texts: Vec<_> = paragraphs(&body, false)
            .into_iter()
            .map(|p| (p.line, p.text))
            .collect();
        assert_eq!(
            texts,
            vec![
                (1, "one two".to_owned()),
                (4, "three four".to_owned()),
                (6, "five".to_owned())
            ]
        );
    }

    #[test]
    fn hostile_lines_are_handled_in_one_pass() {
        let many = "](".repeat(200_000);
        assert_eq!(strip_link_targets(&many), many);
        let brackets = "[".repeat(200_000);
        assert_eq!(strip_brackets(&brackets), brackets);
        let quotes = "\"".repeat(200_000);
        assert!(strip_quotes(&quotes).len() <= quotes.len());
    }

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
