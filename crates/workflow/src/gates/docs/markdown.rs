//! A small Markdown reader for the documentation gate.
//!
//! It finds what the checks need and nothing else: headings (for anchors), links, fenced code
//! blocks and inline code spans. It never edits text, reads only what it is given, and does an
//! amount of work proportional to the size of the text. Text inside a fenced block is code, so a
//! link written inside one is not a link, and a heading written inside one is not a heading.

use std::collections::{BTreeMap, BTreeSet};

/// A heading, with the line it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heading {
    /// The line, from 1.
    pub line: usize,
    /// The text after the `#` marks.
    pub text: String,
}

/// A link or an image target, with the line it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The line, from 1.
    pub line: usize,
    /// The target as written, without the title.
    pub target: String,
}

/// A fenced code block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The line of the opening fence, from 1.
    pub line: usize,
    /// The first word after the fence, in lower case. Empty when there is none.
    pub lang: String,
    /// The lines between the fences, joined with a newline.
    pub body: String,
}

/// An inline code span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// The line, from 1.
    pub line: usize,
    /// The text between the backticks.
    pub text: String,
    /// The whole line the span is on, so a check can read the words around it.
    pub context: String,
}

/// What was found in one page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scan {
    /// The headings, in order.
    pub headings: Vec<Heading>,
    /// The links, in order.
    pub links: Vec<Link>,
    /// The fenced blocks, in order.
    pub blocks: Vec<Block>,
    /// The inline code spans, in order.
    pub spans: Vec<Span>,
}

/// Reads one page.
#[must_use]
pub fn scan(text: &str) -> Scan {
    let mut found = Scan::default();
    let mut fence: Option<(String, usize, String, Vec<&str>)> = None;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let trimmed = raw.trim_start();
        if let Some((marker, opened, lang, body)) = fence.as_mut() {
            if trimmed.starts_with(marker.as_str()) && trimmed.trim_end() == marker.as_str() {
                found.blocks.push(Block {
                    line: *opened,
                    lang: std::mem::take(lang),
                    body: body.join("\n"),
                });
                fence = None;
            } else {
                body.push(raw);
            }
            continue;
        }
        if let Some(marker) = fence_marker(trimmed) {
            let lang = trimmed[marker.len()..]
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|c| c == '{' || c == '}' || c == '.')
                .to_ascii_lowercase();
            fence = Some((marker, number, lang, Vec::new()));
            continue;
        }
        if let Some(text) = heading_text(trimmed) {
            found.headings.push(Heading {
                line: number,
                text: text.to_owned(),
            });
        }
        let prose = take_spans(raw, number, &mut found.spans);
        links_in(&prose, number, &mut found.links);
    }
    // A fence that is never closed still holds code up to the end of the page.
    if let Some((_, opened, lang, body)) = fence {
        found.blocks.push(Block {
            line: opened,
            lang,
            body: body.join("\n"),
        });
    }
    found
}

fn fence_marker(trimmed: &str) -> Option<String> {
    for mark in ['`', '~'] {
        let run = trimmed.chars().take_while(|c| *c == mark).count();
        if run >= 3 {
            return Some(mark.to_string().repeat(run));
        }
    }
    None
}

fn heading_text(trimmed: &str) -> Option<&str> {
    let hashes = trimmed.chars().take_while(|c| *c == '#').count();
    if (1..=6).contains(&hashes) {
        let rest = &trimmed[hashes..];
        if rest.starts_with(' ') || rest.starts_with('\t') {
            return Some(rest.trim().trim_end_matches('#').trim());
        }
    }
    None
}

/// Moves the code spans of a line into `spans` and returns the line without them.
fn take_spans(line: &str, number: usize, spans: &mut Vec<Span>) -> String {
    let mut prose = String::with_capacity(line.len());
    let mut chars = line.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if c != '`' {
            prose.push(c);
            continue;
        }
        let mut run = 1;
        while matches!(chars.peek(), Some((_, '`'))) {
            chars.next();
            run += 1;
        }
        let open = start + run;
        let ticks = "`".repeat(run);
        match line[open..].find(&ticks) {
            Some(length) => {
                spans.push(Span {
                    line: number,
                    text: line[open..open + length].trim().to_owned(),
                    context: line.to_owned(),
                });
                let end = open + length + run;
                while chars.peek().is_some_and(|(at, _)| *at < end) {
                    chars.next();
                }
            }
            None => prose.push_str(&ticks),
        }
    }
    prose
}

fn links_in(prose: &str, number: usize, links: &mut Vec<Link>) {
    let bytes = prose.as_bytes();
    let mut at = 0;
    while let Some(found) = prose[at..].find("](") {
        let open = at + found + 2;
        let mut depth = 1usize;
        let mut end = None;
        for (offset, byte) in bytes[open..].iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { break };
        let inner = prose[open..end].trim();
        let target = inner
            .strip_prefix('<')
            .and_then(|t| t.split('>').next())
            .map_or_else(
                || inner.split_whitespace().next().unwrap_or("").to_owned(),
                str::to_owned,
            );
        if !target.is_empty() {
            links.push(Link {
                line: number,
                target,
            });
        }
        at = end + 1;
    }
    // An autolink: `<https://example.test/page>`.
    let mut at = 0;
    while let Some(found) = prose[at..].find('<') {
        let open = at + found + 1;
        let Some(length) = prose[open..].find('>') else {
            break;
        };
        let inner = &prose[open..open + length];
        if inner.contains("://") && !inner.contains(char::is_whitespace) {
            links.push(Link {
                line: number,
                target: inner.to_owned(),
            });
        }
        at = open + length + 1;
    }
}

/// The anchor a heading gets on a code host: lower case, punctuation dropped, spaces to hyphens.
#[must_use]
pub fn anchor_of(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                Some(c)
            } else if c == ' ' {
                Some('-')
            } else {
                None
            }
        })
        .collect()
}

/// Every anchor of a page. A heading that repeats gets `-1`, `-2` and so on, as it does on a code
/// host.
#[must_use]
pub fn anchors(scan: &Scan) -> BTreeSet<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut found = BTreeSet::new();
    for heading in &scan.headings {
        let base = anchor_of(&heading.text);
        let count = seen.entry(base.clone()).or_insert(0);
        found.insert(if *count == 0 {
            base
        } else {
            format!("{base}-{count}")
        });
        *count += 1;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_in_a_code_block_is_not_a_link() {
        let page = "# Title\n\n```text\n[a](missing.md)\n```\n\nSee [b](real.md#part).\n";
        let found = scan(page);
        assert_eq!(found.links.len(), 1);
        assert_eq!(found.links[0].target, "real.md#part");
        assert_eq!(found.blocks.len(), 1);
    }

    #[test]
    fn a_link_in_a_code_span_is_not_a_link() {
        let found = scan("Write `[a](x.md)` to link. See [b](y.md).\n");
        assert_eq!(found.links.len(), 1);
        assert_eq!(found.spans[0].text, "[a](x.md)");
    }

    #[test]
    fn headings_make_anchors_and_repeats_are_numbered() {
        let found = scan("# Usage\n\n## Flags and `options`\n\n## Usage\n");
        let anchors = anchors(&found);
        assert!(anchors.contains("usage"));
        assert!(anchors.contains("usage-1"));
        assert!(anchors.contains("flags-and-options"));
    }

    #[test]
    fn a_target_with_a_title_or_angle_brackets_is_read() {
        let found = scan("[a](a.md \"A title\") and [b](<b c.md>) and <https://x.test/y>\n");
        let targets: Vec<&str> = found.links.iter().map(|l| l.target.as_str()).collect();
        assert_eq!(targets, ["a.md", "b c.md", "https://x.test/y"]);
    }

    #[test]
    fn a_block_that_is_never_closed_still_counts() {
        let found = scan("```mermaid\ngraph TD\n");
        assert_eq!(found.blocks.len(), 1);
        assert_eq!(found.blocks[0].lang, "mermaid");
    }
}
