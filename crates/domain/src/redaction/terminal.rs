//! The terminal view: the bytes a reader sees after terminal escape sequences and invisible
//! characters are taken out.
//!
//! Text can hold a secret that a person or a program reads whole and that a byte search does not
//! find: `gh`, then a colour code, then `p_...`; or the same token with a zero-width space between
//! every pair of letters. The redactor therefore looks at two views of every stream. The first is
//! the raw bytes. The second is this one. A match in either view is replaced, and the replaced
//! span runs from the first to the last byte of the match in the original text, so the noise
//! inside it goes too.
//!
//! This is the model the canary sweeper of the test kit uses to read output, on purpose: what
//! that sweeper cannot see, a leak cannot hide behind, and the other way round.
//!
//! * An escape sequence starts at the control byte `ESC` (0x1B). `ESC [` starts a control
//!   sequence that ends at the first byte from 0x40 to 0x7E. `ESC ]` starts an operating system
//!   command that ends at `BEL` (0x07) or at `ESC \`. `ESC`, some bytes from 0x20 to 0x2F, and one
//!   more byte make a short sequence. Any other `ESC x` is a two byte sequence. A sequence that
//!   never ends takes the rest of the stream. That is why the raw view exists as well.
//! * An invisible character is one of the Unicode characters that draw nothing and exist to
//!   change how text is joined, ordered or hidden: zero-width spaces and joiners, the word
//!   joiner, the byte order mark, the soft hyphen, the bidirectional controls, the variation
//!   selectors, the fillers and the tag characters. The list is longer than the one the sweeper
//!   uses, so a hidden character the sweeper does not know about is removed here as well.
//!
//! The view is built one byte at a time and keeps no more than three bytes of state, so a
//! sequence or a character cut in two by a chunk boundary is handled the same way as one that is
//! not.

/// What one input byte added to the view: up to four bytes, each with the offset in the original
/// stream it came from. Four, because three held back bytes of an incomplete character can be
/// released together with the byte that showed it was not invisible.
#[derive(Debug, Clone, Copy)]
pub(super) struct Visible {
    items: [(u8, u64); 4],
    len: usize,
}

impl Visible {
    const fn none() -> Self {
        Self {
            items: [(0, 0); 4],
            len: 0,
        }
    }

    fn push(&mut self, byte: u8, at: u64) {
        if let Some(slot) = self.items.get_mut(self.len) {
            *slot = (byte, at);
            self.len += 1;
        }
    }

    /// The visible bytes with their original offsets, in order.
    pub(super) fn iter(&self) -> impl Iterator<Item = (u8, u64)> + '_ {
        self.items.iter().take(self.len).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Text,
    /// After `ESC`.
    Escape,
    /// After `ESC` and some bytes from 0x20 to 0x2F, waiting for the byte that ends the sequence.
    EscapeIntermediate,
    /// Inside `ESC [`.
    Csi,
    /// Inside `ESC ]`.
    Osc,
    /// Inside an operating system command, just after an `ESC` that may start `ESC \`.
    OscEscape,
}

enum Class {
    Invisible,
    Visible,
    Incomplete,
}

/// Decides what the first bytes of a multi-byte character are. Every byte after the first is a
/// continuation byte (0x80 to 0xBF); the caller checks that.
fn classify(prefix: &[u8]) -> Class {
    match prefix {
        // U+00AD soft hyphen.
        [0xC2] => Class::Incomplete,
        [0xC2, 0xAD] => Class::Invisible,
        // U+034F combining grapheme joiner.
        [0xCD] => Class::Incomplete,
        [0xCD, 0x8F] => Class::Invisible,
        // U+061C Arabic letter mark.
        [0xD8] => Class::Incomplete,
        [0xD8, 0x9C] => Class::Invisible,
        // U+115F and U+1160 Hangul fillers, U+17B4 and U+17B5 Khmer vowel inherent, U+180B to
        // U+180F Mongolian selectors.
        [0xE1] | [0xE1, 0x85] | [0xE1, 0x9E] | [0xE1, 0xA0] => Class::Incomplete,
        [0xE1, 0x85, 0x9F | 0xA0] | [0xE1, 0x9E, 0xB4 | 0xB5] | [0xE1, 0xA0, 0x8B..=0x8F] => {
            Class::Invisible
        }
        // U+200B to U+200F zero-width and direction marks, U+202A to U+202E embeddings and
        // overrides, U+2060 to U+2064 word joiner and invisible operators, U+2066 to U+206F
        // isolates and deprecated format characters.
        [0xE2] | [0xE2, 0x80] | [0xE2, 0x81] => Class::Incomplete,
        [0xE2, 0x80, 0x8B..=0x8F | 0xAA..=0xAE] | [0xE2, 0x81, 0xA0..=0xA4 | 0xA6..=0xAF] => {
            Class::Invisible
        }
        // U+3164 Hangul filler.
        [0xE3] | [0xE3, 0x85] => Class::Incomplete,
        [0xE3, 0x85, 0xA4] => Class::Invisible,
        // U+FE00 to U+FE0F variation selectors, U+FEFF byte order mark, U+FFA0 halfwidth Hangul
        // filler, U+FFF0 to U+FFF8 specials.
        [0xEF] | [0xEF, 0xB8] | [0xEF, 0xBB] | [0xEF, 0xBE] | [0xEF, 0xBF] => Class::Incomplete,
        [0xEF, 0xB8, 0x80..=0x8F]
        | [0xEF, 0xBB, 0xBF]
        | [0xEF, 0xBE, 0xA0]
        | [0xEF, 0xBF, 0xB0..=0xB8] => Class::Invisible,
        // U+1BCA0 to U+1BCA3 shorthand format controls, U+1D173 to U+1D17A musical format
        // controls.
        [0xF0] | [0xF0, 0x9B] | [0xF0, 0x9B, 0xB2] | [0xF0, 0x9D] | [0xF0, 0x9D, 0x85] => {
            Class::Incomplete
        }
        [0xF0, 0x9B, 0xB2, 0xA0..=0xA3] | [0xF0, 0x9D, 0x85, 0xB3..=0xBA] => Class::Invisible,
        // U+E0000 to U+E0FFF tag characters and variation selectors supplement.
        [0xF3] | [0xF3, 0xA0] | [0xF3, 0xA0, 0x80..=0xBF] => Class::Incomplete,
        [0xF3, 0xA0, 0x80..=0xBF, 0x80..=0xBF] => Class::Invisible,
        _ => Class::Visible,
    }
}

/// True for a byte that can start a character on the list above.
fn starts_a_possibly_invisible_character(byte: u8) -> bool {
    matches!(
        byte,
        0xC2 | 0xCD | 0xD8 | 0xE1 | 0xE2 | 0xE3 | 0xEF | 0xF0 | 0xF3
    )
}

/// The reader of the terminal view. Feed it every byte of a stream in order.
#[derive(Debug, Clone)]
pub(super) struct Terminal {
    state: State,
    held: [(u8, u64); 3],
    held_len: usize,
}

impl Terminal {
    pub(super) const fn new() -> Self {
        Self {
            state: State::Text,
            held: [(0, 0); 3],
            held_len: 0,
        }
    }

    /// The offset of the oldest byte held back because it may start an invisible character.
    pub(super) fn first_held_offset(&self) -> Option<u64> {
        (self.held_len > 0).then(|| self.held.first().map_or(0, |h| h.1))
    }

    /// Takes the next byte of the stream, at offset `at`.
    pub(super) fn step(&mut self, byte: u8, at: u64) -> Visible {
        let mut out = Visible::none();
        match self.state {
            State::Text => self.step_text(byte, at, &mut out),
            State::Escape => {
                self.state = match byte {
                    b'[' => State::Csi,
                    b']' => State::Osc,
                    0x20..=0x2F => State::EscapeIntermediate,
                    // Any other byte ends a two byte sequence such as `ESC c`.
                    _ => State::Text,
                };
            }
            State::EscapeIntermediate => {
                if !(0x20..=0x2F).contains(&byte) {
                    self.state = State::Text;
                }
            }
            State::Csi => {
                if (0x40..=0x7E).contains(&byte) {
                    self.state = State::Text;
                }
            }
            State::Osc => match byte {
                0x07 => self.state = State::Text,
                0x1B => self.state = State::OscEscape,
                _ => {}
            },
            State::OscEscape => {
                // `ESC \` ends the command. Anything else was part of its text.
                self.state = if byte == b'\\' {
                    State::Text
                } else {
                    State::Osc
                };
            }
        }
        out
    }

    /// Ends the stream. The bytes of a character that never finished are visible: half a
    /// character is not an invisible one. A sequence that never finished is noise.
    pub(super) fn finish(&mut self) -> Visible {
        let mut out = Visible::none();
        self.release(&mut out);
        self.state = State::Text;
        out
    }

    fn release(&mut self, out: &mut Visible) {
        for &(byte, at) in self.held.iter().take(self.held_len) {
            out.push(byte, at);
        }
        self.held_len = 0;
    }

    fn step_text(&mut self, byte: u8, at: u64, out: &mut Visible) {
        if self.held_len > 0 {
            if (0x80..=0xBF).contains(&byte) {
                // The held bytes and this one are the start of a character. No character on the
                // list needs more than four bytes, so a prefix of four always gets an answer.
                let mut prefix = [0u8; 4];
                for (slot, held) in prefix.iter_mut().zip(self.held.iter().take(self.held_len)) {
                    *slot = held.0;
                }
                if let Some(slot) = prefix.get_mut(self.held_len) {
                    *slot = byte;
                }
                let prefix = prefix.get(..=self.held_len).unwrap_or(&[]);
                match classify(prefix) {
                    Class::Incomplete => {
                        // Cannot happen at four bytes. If it did, the bytes are visible.
                        if !self.hold(byte, at) {
                            self.release(out);
                            out.push(byte, at);
                        }
                    }
                    Class::Invisible => self.held_len = 0,
                    Class::Visible => {
                        self.release(out);
                        out.push(byte, at);
                    }
                }
                return;
            }
            // A lead byte that no continuation byte followed is not a character. It is visible,
            // and this byte is read as if nothing had been held.
            self.release(out);
        }
        match byte {
            0x1B => self.state = State::Escape,
            b if starts_a_possibly_invisible_character(b) => {
                if !self.hold(b, at) {
                    out.push(b, at);
                }
            }
            b => out.push(b, at),
        }
    }

    /// Holds a byte back. False when there is no room, which the callers treat as "visible".
    fn hold(&mut self, byte: u8, at: u64) -> bool {
        match self.held.get_mut(self.held_len) {
            Some(slot) => {
                *slot = (byte, at);
                self.held_len += 1;
                true
            }
            None => false,
        }
    }
}

/// The terminal view of a whole buffer, without offsets. Used to prepare the secrets that the
/// registry looks for in that view.
pub(super) fn strip(bytes: &[u8]) -> Vec<u8> {
    let mut terminal = Terminal::new();
    let mut out = Vec::with_capacity(bytes.len());
    for (at, &byte) in (0u64..).zip(bytes) {
        out.extend(terminal.step(byte, at).iter().map(|v| v.0));
    }
    out.extend(terminal.finish().iter().map(|v| v.0));
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// The view of a buffer, with the original offset of each byte.
    fn view(input: &[u8]) -> Vec<(u8, u64)> {
        let mut terminal = Terminal::new();
        let mut out = Vec::new();
        for (at, &byte) in (0u64..).zip(input) {
            out.extend(terminal.step(byte, at).iter());
        }
        out.extend(terminal.finish().iter());
        out
    }

    fn text(input: &[u8]) -> Vec<u8> {
        view(input).into_iter().map(|v| v.0).collect()
    }

    #[test]
    fn plain_text_is_untouched_and_keeps_its_offsets() {
        let v = view(b"plain text");
        assert_eq!(v.len(), 10);
        for (i, (byte, at)) in v.iter().enumerate() {
            assert_eq!(*at, i as u64);
            assert_eq!(*byte, b"plain text"[i]);
        }
    }

    #[test]
    fn a_colour_code_between_letters_disappears_and_the_offsets_skip_it() {
        let v = view(b"a\x1b[31;1mb\x1b[0mc");
        // `ESC [ 3 1 ; 1 m` is seven bytes, so `b` is at offset 8. `ESC [ 0 m` is four.
        assert_eq!(v, vec![(b'a', 0), (b'b', 8), (b'c', 13)]);
    }

    #[test]
    fn operating_system_commands_end_at_bell_or_string_terminator() {
        assert_eq!(text(b"a\x1b]0;window title\x07b"), b"ab");
        assert_eq!(text(b"a\x1b]8;;https://example.test\x1b\\b"), b"ab");
        // An escape inside the command that does not start the terminator is part of the text.
        assert_eq!(text(b"a\x1b]0;x\x1by\x07b"), b"ab");
    }

    #[test]
    fn short_and_two_byte_sequences_disappear() {
        assert_eq!(text(b"a\x1b(Bb"), b"ab");
        assert_eq!(text(b"a\x1bcb"), b"ab");
        assert_eq!(text(b"a\x1b=b"), b"ab");
    }

    #[test]
    fn a_sequence_that_never_ends_takes_the_rest_of_the_stream() {
        assert_eq!(text(b"a\x1b]0;never ends"), b"a");
        // A control sequence ends at the first byte from 0x40 to 0x7E, whatever it is.
        assert_eq!(text(b"a\x1b[12;\xc3\xa9m!"), b"a!");
    }

    #[test]
    fn invisible_characters_disappear() {
        for invisible in [
            "\u{200b}",
            "\u{200c}",
            "\u{200d}",
            "\u{200e}",
            "\u{200f}",
            "\u{2060}",
            "\u{feff}",
            "\u{ad}",
            "\u{202a}",
            "\u{202e}",
            "\u{2066}",
            "\u{2069}",
            "\u{34f}",
            "\u{61c}",
            "\u{115f}",
            "\u{180e}",
            "\u{3164}",
            "\u{fe0f}",
            "\u{ffa0}",
            "\u{e0041}",
            "\u{e0100}",
            "\u{1d173}",
        ] {
            let input = format!("a{invisible}b");
            assert_eq!(text(input.as_bytes()), b"ab", "{invisible:?}");
        }
    }

    #[test]
    fn visible_characters_that_share_a_lead_byte_stay() {
        for visible in [
            "\u{e9}",
            "\u{ae}",
            "\u{2013}",
            "\u{201c}",
            "\u{20ac}",
            "\u{3042}",
            "\u{65e5}",
            "\u{1f600}",
            "\u{fe30}",
            "\u{ff21}",
            "\u{1d11e}",
            "\u{e9f}",
        ] {
            let input = format!("a{visible}b");
            assert_eq!(text(input.as_bytes()), input.as_bytes(), "{visible:?}");
        }
    }

    #[test]
    fn a_lead_byte_with_no_continuation_is_visible_and_does_not_swallow_what_follows() {
        assert_eq!(text(b"a\xe2b"), b"a\xe2b");
        assert_eq!(text(b"a\xe2\x80b"), b"a\xe2\x80b");
        assert_eq!(text(b"a\xe2\x1b[0mb"), b"a\xe2b");
        // The bytes keep the offset they had.
        assert_eq!(view(b"a\xe2b"), vec![(b'a', 0), (0xe2, 1), (b'b', 2)]);
    }

    #[test]
    fn a_character_cut_off_by_the_end_of_the_stream_is_visible() {
        assert_eq!(text(b"a\xe2\x80"), b"a\xe2\x80");
    }

    #[test]
    fn invalid_utf8_never_stops_the_reader() {
        let bytes: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
        let _ = view(&bytes);
        assert_eq!(text(b"\xff\xfe\xfd"), b"\xff\xfe\xfd");
    }

    #[test]
    fn held_bytes_report_their_offset_until_they_are_decided() {
        let mut terminal = Terminal::new();
        assert_eq!(terminal.first_held_offset(), None);
        let _ = terminal.step(b'x', 0);
        let _ = terminal.step(0xe2, 1);
        assert_eq!(terminal.first_held_offset(), Some(1));
        let _ = terminal.step(0x80, 2);
        assert_eq!(terminal.first_held_offset(), Some(1));
        let _ = terminal.step(0x8b, 3);
        assert_eq!(terminal.first_held_offset(), None);
    }

    #[test]
    fn strip_is_the_view_without_offsets() {
        assert_eq!(strip(b"g\x1b[0mh\xe2\x80\x8bp"), b"ghp");
    }
}
