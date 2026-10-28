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
}
