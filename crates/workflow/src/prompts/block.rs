//! One data block.
//!
//! ```text
//! <<<DATA name=request class=issue_text bytes=120 sha256=sha256:... stripped=0 redacted=0 truncated=no omitted=0>>>
//! > first line of the text
//! > second line of the text
//! <<<END name=request>>>
//! ```
//!
//! # Why the text cannot end its own block
//!
//! The delimiter is not a secret and is not chosen to be unlikely. It does not need to be,
//! because the text is **encoded** so that it cannot contain a line that is not quoted:
//!
//! 1. The text has been through `sanitize::neutralize`, so `\n` is the only line break it holds.
//! 2. The text is split at `\n`, and every piece, empty ones included, gets the prefix `> `.
//!    A line of data therefore always starts with `> `, and the opening and closing lines of a
//!    block always start with `<<<`. No line of data starts with `<<<`, so none can pass for a
//!    delimiter, whatever the text says, whatever the name of the block is, and however many
//!    fake delimiters, headings or placeholders it holds.
//! 3. Nothing in the opening line comes from the text. The name and the class come from the
//!    template. The sizes and the hash are numbers and hex digits that the assembler computed.
//!
//! The text is decoded by taking the prefix off each line and joining the lines with `\n`, which
//! gives back exactly the neutralized text. `verify` does that on the finished prompt and refuses
//! to release one that does not decode to what the assembler meant to write.
//!
//! The encoding does not rely on the model understanding quoting. That part is the model's:
//! the fixed instruction in every prompt tells it that everything between the opening and the
//! closing line is data. See the module documentation of [`prompts`](super) for what that does
//! not defend against.

use factory_domain::values::Sha256Digest;

use super::class::ContentClass;

/// The start of an opening line.
pub(super) const OPEN: &str = "<<<DATA name=";
/// The start of a closing line.
pub(super) const CLOSE: &str = "<<<END name=";
/// The end of both.
pub(super) const TAIL: &str = ">>>";
/// The prefix of every line of data.
pub(super) const QUOTE: &str = "> ";

/// What the opening line states about a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Header<'a> {
    pub name: &'a str,
    pub class: ContentClass,
    /// The size of the original text in bytes, before anything was done to it.
    pub original_bytes: usize,
    /// The hash of the original text.
    pub original_sha256: &'a Sha256Digest,
    /// Hidden characters removed.
    pub stripped: usize,
    /// Secrets replaced.
    pub redacted: u64,
    /// Bytes of the cleaned text that are not in the block.
    pub omitted: usize,
}

impl Header<'_> {
    /// The opening line.
    #[must_use]
    pub(super) fn line(&self) -> String {
        format!(
            "{OPEN}{} class={} bytes={} sha256={} stripped={} redacted={} truncated={} omitted={}{TAIL}",
            self.name,
            self.class.as_str(),
            self.original_bytes,
            self.original_sha256.as_str(),
            self.stripped,
            self.redacted,
            if self.omitted > 0 { "yes" } else { "no" },
            self.omitted,
        )
    }
}

/// The closing line.
#[must_use]
pub(super) fn closing_line(name: &str) -> String {
    format!("{CLOSE}{name}{TAIL}")
}

/// The most bytes the opening line of an input with this name and class can have, whatever the
/// numbers in it are. Used to reserve room before the numbers are known.
#[must_use]
pub(super) fn header_reserve(name: &str, class: ContentClass) -> usize {
    let digest = Sha256Digest::of(b"");
    Header {
        name,
        class,
        original_bytes: usize::MAX,
        original_sha256: &digest,
        stripped: usize::MAX,
        redacted: u64::MAX,
        omitted: usize::MAX,
    }
    .line()
    .len()
}

/// The size of the lines between the opening and the closing line for `text`, with their line
/// breaks. `text` must already be neutralized. An empty text has no lines.
#[must_use]
pub(super) fn quoted_len(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    let lines = text.matches('\n').count().saturating_add(1);
    // Each line gets the prefix, the text keeps its own line breaks between lines, and the last
    // line is followed by the break that comes before the closing line.
    text.len()
        .saturating_add(lines.saturating_mul(QUOTE.len()))
        .saturating_add(1)
}

/// The longest start of `text` (ending at a character boundary) whose quoted size is at most
/// `allowance`.
#[must_use]
pub(super) fn longest_prefix(text: &str, allowance: usize) -> &str {
    // The empty text costs nothing. A non-empty prefix costs its length, a prefix for each line,
    // and the closing break.
    let mut cost = QUOTE.len().saturating_add(1);
    if cost > allowance {
        return "";
    }
    let mut end = 0usize;
    for (at, c) in text.char_indices() {
        let step = c
            .len_utf8()
            .saturating_add(if c == '\n' { QUOTE.len() } else { 0 });
        cost = cost.saturating_add(step);
        if cost > allowance {
            break;
        }
        end = at.saturating_add(c.len_utf8());
    }
    text.get(..end).unwrap_or_default()
}

/// The lines of a block: the opening line, the quoted lines of `text`, the closing line.
/// `text` must be neutralized.
#[must_use]
pub(super) fn render(header: &Header<'_>, text: &str) -> String {
    let mut out = header.line();
    if !text.is_empty() {
        for line in text.split('\n') {
            out.push('\n');
            out.push_str(QUOTE);
            out.push_str(line);
        }
    }
    out.push('\n');
    out.push_str(&closing_line(header.name));
    out
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    fn header<'a>(digest: &'a Sha256Digest, omitted: usize) -> Header<'a> {
        Header {
            name: "diff",
            class: ContentClass::ModelOutput,
            original_bytes: 12,
            original_sha256: digest,
            stripped: 1,
            redacted: 2,
            omitted,
        }
    }

    #[test]
    fn prompts_block_has_the_documented_shape() {
        let digest = Sha256Digest::of(b"x");
        let block = render(&header(&digest, 0), "one\ntwo");
        let lines: Vec<&str> = block.split('\n').collect();
        assert_eq!(lines.len(), 4);
        assert!(
            lines[0].starts_with("<<<DATA name=diff class=model_output bytes=12 sha256=sha256:")
        );
        assert!(lines[0].ends_with(" stripped=1 redacted=2 truncated=no omitted=0>>>"));
        assert_eq!(&lines[1..], ["> one", "> two", "<<<END name=diff>>>"]);
    }

    #[test]
    fn prompts_block_an_empty_text_has_no_lines_and_a_blank_line_is_quoted() {
        let digest = Sha256Digest::of(b"");
        assert_eq!(render(&header(&digest, 0), "").split('\n').count(), 2);
        let block = render(&header(&digest, 0), "a\n\nb\n");
        assert_eq!(
            block.split('\n').skip(1).collect::<Vec<_>>(),
            ["> a", "> ", "> b", "> ", "<<<END name=diff>>>"]
        );
    }

    #[test]
    fn prompts_block_says_so_in_the_opening_line_when_text_was_left_out() {
        let digest = Sha256Digest::of(b"x");
        assert!(
            header(&digest, 7)
                .line()
                .contains(" truncated=yes omitted=7>>>")
        );
    }

    #[test]
    fn prompts_block_quoted_len_is_exact_and_longest_prefix_fits() {
        for text in ["", "a", "ab\ncd", "\n\n", "caf\u{E9}\n\u{1F600}x", "a\n"] {
            let digest = Sha256Digest::of(text.as_bytes());
            let h = header(&digest, 0);
            let block = render(&h, text);
            let fixed = h.line().len() + 1 + closing_line("diff").len();
            // The fixed part (opening line, its break, closing line) plus the quoted lines.
            assert_eq!(block.len(), fixed + quoted_len(text), "{text:?}");
            for allowance in 0..quoted_len(text) + 3 {
                let cut = longest_prefix(text, allowance);
                assert!(text.starts_with(cut));
                assert!(quoted_len(cut) <= allowance, "{text:?} {allowance}");
                if cut.len() < text.len() {
                    let next = text[cut.len()..].chars().next().expect("a character");
                    let longer = &text[..cut.len() + next.len_utf8()];
                    assert!(quoted_len(longer) > allowance, "{text:?} {allowance}");
                }
            }
        }
    }

    #[test]
    fn prompts_block_the_header_reserve_is_never_exceeded() {
        let digest = Sha256Digest::of(b"x");
        let mut h = header(&digest, usize::MAX);
        h.stripped = usize::MAX;
        h.redacted = u64::MAX;
        h.original_bytes = usize::MAX;
        assert!(h.line().len() <= header_reserve("diff", ContentClass::ModelOutput));
        assert!(
            header(&digest, 0).line().len() <= header_reserve("diff", ContentClass::ModelOutput)
        );
    }
}
