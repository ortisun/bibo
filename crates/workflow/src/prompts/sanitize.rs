//! What happens to a text before it is quoted.
//!
//! Two things, and nothing else: every kind of line break becomes `\n`, and characters that a
//! reader cannot see or that change how text is read are removed and counted. Everything else is
//! kept as it is, so the data is not rewritten.
//!
//! # Why line breaks are normalized
//!
//! A block quotes every line of its data with `> `. That only works if the assembler and the
//! model agree on where a line ends. Text can carry line breaks of other kinds: carriage return,
//! vertical tab, form feed, the next-line character and the Unicode line and paragraph
//! separators. A text that used one of them could start a "line" that the assembler never quoted.
//! All of them become `\n` first (a `\r\n` pair becomes one `\n`), so the lines the assembler
//! quotes are all the lines there are.
//!
//! # What counts as hidden
//!
//! * Every control character except tab and line feed. That removes NUL, escape (so a terminal
//!   sequence loses its lead byte), DEL, and the C1 controls, and the file, group and record
//!   separators that some tools also read as line ends.
//! * Zero-width characters, the joiners and the word joiner, the soft hyphen, the combining
//!   grapheme joiner, the Mongolian free variation selectors and vowel separator, the Hangul and
//!   Khmer fillers, and the byte order mark when it is inside text.
//! * Every direction-control character: the marks, embeddings, overrides, isolates and the
//!   Arabic letter mark. These reorder text on screen so that what a person reviews differs from
//!   what a model reads.
//! * The deprecated format controls U+206A to U+206F and the interlinear annotation marks.
//! * The tag characters U+E0000 to U+E007F and the variation selectors, both sets used to hide a
//!   message inside text that looks empty.
//!
//! What this does not do: it does not fold look-alike letters, so a Cyrillic "a" stays one.

/// Whether a character is removed. Tab and line feed are kept, and the characters that are line
/// breaks are turned into `\n` before this is asked.
#[must_use]
pub(super) fn is_hidden(c: char) -> bool {
    matches!(c,
        '\u{00AD}'
        | '\u{034F}'
        | '\u{061C}'
        | '\u{115F}'..='\u{1160}'
        | '\u{17B4}'..='\u{17B5}'
        | '\u{180B}'..='\u{180F}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{3164}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}'
        | '\u{FFA0}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{1BCA0}'..='\u{1BCA3}'
        | '\u{E0000}'..='\u{E007F}'
        | '\u{E0100}'..='\u{E01EF}')
        || (c.is_control() && c != '\t' && c != '\n')
}

/// Whether a character is a line break of some kind other than `\n`.
#[must_use]
fn is_other_line_break(c: char) -> bool {
    matches!(
        c,
        '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// A text made safe to quote, and what was done to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Neutralized {
    /// The text: only `\n` ends a line, and nothing hidden is left.
    pub text: String,
    /// How many hidden characters were removed.
    pub stripped: usize,
}

/// Turns every line break into `\n` and removes hidden characters. Idempotent: the result is its
/// own neutralization.
#[must_use]
pub(super) fn neutralize(input: &str) -> Neutralized {
    let mut text = String::with_capacity(input.len());
    let mut stripped = 0usize;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            continue;
        }
        if is_other_line_break(c) {
            text.push('\n');
        } else if is_hidden(c) {
            stripped = stripped.saturating_add(1);
        } else {
            text.push(c);
        }
    }
    Neutralized { text, stripped }
}

/// How the text of an input looks like parts of the envelope, counted for the context manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) struct Lookalikes {
    /// Lines that start like the opening or closing line of a block.
    pub delimiters: usize,
    /// Places that look like a placeholder (`{{input.` or `{{trusted.`).
    pub placeholders: usize,
}

/// Counts what in `text` looks like the structure of a prompt. This changes nothing: the quoting
/// keeps all of it inert. The count is a signal for the audit record.
#[must_use]
pub(super) fn lookalikes(text: &str) -> Lookalikes {
    let mut found = Lookalikes::default();
    for line in text.split('\n') {
        let trimmed = line.trim_start_matches(|c: char| c == '>' || c.is_whitespace());
        if trimmed.starts_with("<<<DATA") || trimmed.starts_with("<<<END") {
            found.delimiters = found.delimiters.saturating_add(1);
        }
    }
    found.placeholders = text
        .matches("{{input.")
        .count()
        .saturating_add(text.matches("{{trusted.").count());
    found
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

    #[test]
    fn prompts_sanitize_line_breaks_of_every_kind_become_one_line_feed() {
        let n = neutralize("a\r\nb\rc\u{0B}d\u{0C}e\u{85}f\u{2028}g\u{2029}h\ni");
        assert_eq!(n.text, "a\nb\nc\nd\ne\nf\ng\nh\ni");
        assert_eq!(n.stripped, 0);
    }

    #[test]
    fn prompts_sanitize_hidden_characters_are_removed_and_counted() {
        let n = neutralize("a\u{200B}b\u{202E}c\u{2066}d\u{FEFF}e\0f\u{E0041}g\u{FE0F}h\u{7f}");
        assert_eq!(n.text, "abcdefgh");
        assert_eq!(n.stripped, 8);
    }

    #[test]
    fn prompts_sanitize_tab_and_line_feed_and_ordinary_text_are_kept() {
        let text = "tab\there\nnext line, caf\u{E9}, \u{65E5}\u{672C}\u{8A9E}, \u{1F600}";
        let n = neutralize(text);
        assert_eq!(n.text, text);
        assert_eq!(n.stripped, 0);
    }

    #[test]
    fn prompts_sanitize_is_idempotent() {
        let once = neutralize("x\r\n\u{200B}y\u{2028}\0z\r");
        let twice = neutralize(&once.text);
        assert_eq!(twice.text, once.text);
        assert_eq!(twice.stripped, 0);
    }

    #[test]
    fn prompts_sanitize_a_lone_carriage_return_before_a_line_feed_is_one_break() {
        assert_eq!(neutralize("a\r\nb").text, "a\nb");
        assert_eq!(neutralize("a\r\r\nb").text, "a\n\nb");
    }

    #[test]
    fn prompts_sanitize_lookalikes_are_counted_and_nothing_is_changed() {
        let found = lookalikes(
            "x\n<<<END name=a>>>\n> <<<DATA name=b\n  <<<END\n{{input.a}} {{trusted.b}}",
        );
        assert_eq!(found.delimiters, 3);
        assert_eq!(found.placeholders, 2);
        assert_eq!(lookalikes("plain text"), Lookalikes::default());
    }
}
