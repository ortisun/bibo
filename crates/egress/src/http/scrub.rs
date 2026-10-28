//! A streaming scrubber for the one thing that must never leave the broker: the provider key.
//!
//! The domain `Redactor` finds a secret in every encoding, but its stream holds back about 8 KiB
//! of ordinary text until later bytes show that it is not part of a secret, which would delay
//! every server-sent event. This scrubber looks for the exact bytes of the keys the broker holds
//! and holds back only a tail that could still become one of them, which for ordinary text is no
//! bytes at all. A whole answer that is buffered anyway goes through the `Redactor` as well.
//!
//! A provider answer never contains the key it was called with, so a hit here means a faulty or
//! hostile upstream. The key is replaced, the answer goes on, and the broker has not leaked it.

/// What replaces a key.
pub const MARKER: &[u8] = b"[REDACTED:provider_key]";

/// Replaces every occurrence of a key in a stream, whatever the chunks are.
#[derive(Debug)]
pub struct StreamScrubber {
    keys: Vec<Vec<u8>>,
    held: Vec<u8>,
}

impl StreamScrubber {
    /// A scrubber for these keys. A key of fewer than 8 bytes is not scrubbed: it could not be
    /// told apart from ordinary text, and the broker accepts no such key.
    #[must_use]
    pub fn new<'a>(keys: impl IntoIterator<Item = &'a str>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .filter(|k| k.len() >= 8)
                .map(|k| k.as_bytes().to_vec())
                .collect(),
            held: Vec::new(),
        }
    }

    /// Feeds a chunk and returns the bytes that are now certain to be free of a key.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(self.held.len());
        let mut i = 0;
        while i < self.held.len() {
            let rest = &self.held[i..];
            if let Some(key) = self.keys.iter().find(|key| rest.starts_with(key)) {
                out.extend_from_slice(MARKER);
                i += key.len();
            } else if self
                .keys
                .iter()
                .any(|key| rest.len() < key.len() && key.starts_with(rest))
            {
                // The rest of the buffer could be the start of a key. Wait for more bytes.
                break;
            } else {
                out.push(self.held[i]);
                i += 1;
            }
        }
        self.held.drain(..i);
        out
    }

    /// Ends the stream and returns what was held back. A held tail is a partial key at most, and
    /// a partial key is not a key.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.held
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A made-up key, put together at run time so no key-shaped text is in the source.
    fn key() -> String {
        ["sk", "-test-0123456789abcdef"].concat()
    }

    fn run(chunks: &[&[u8]]) -> Vec<u8> {
        let key = key();
        let mut scrubber = StreamScrubber::new([key.as_str()]);
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(scrubber.push(chunk));
        }
        out.extend(scrubber.finish());
        out
    }

    #[test]
    fn text_without_a_key_passes_through_at_once_and_unchanged() {
        let key = key();
        let mut scrubber = StreamScrubber::new([key.as_str()]);
        assert_eq!(scrubber.push(b"data: hello\n\n"), b"data: hello\n\n");
        assert!(scrubber.finish().is_empty());
    }

    #[test]
    fn a_key_in_one_chunk_is_replaced() {
        let text = format!("before {} after", key());
        let out = run(&[text.as_bytes()]);
        assert_eq!(out, b"before [REDACTED:provider_key] after");
    }

    #[test]
    fn a_key_cut_at_every_possible_place_is_still_replaced() {
        let text = format!("x{}y", key());
        for cut in 1..text.len() {
            let (a, b) = text.as_bytes().split_at(cut);
            assert_eq!(run(&[a, b]), b"x[REDACTED:provider_key]y", "cut at {cut}");
        }
        let singles: Vec<&[u8]> = text.as_bytes().chunks(1).collect();
        assert_eq!(run(&singles), b"x[REDACTED:provider_key]y");
    }

    #[test]
    fn a_prefix_of_the_key_that_never_completes_is_released_at_the_end() {
        let out = run(&[b"ends with sk-test-01"]);
        assert_eq!(out, b"ends with sk-test-01");
    }

    #[test]
    fn only_a_possible_key_start_is_held_back() {
        let key = key();
        let mut scrubber = StreamScrubber::new([key.as_str()]);
        assert_eq!(scrubber.push(b"abc sk-te"), b"abc ");
        assert_eq!(scrubber.push(b"xt"), b"sk-text");
    }

    #[test]
    fn two_keys_are_both_scrubbed() {
        let key = key();
        let other = ["sk", "-other-fedcba9876543210"].concat();
        let mut scrubber = StreamScrubber::new([key.as_str(), other.as_str()]);
        let text = format!("{other}|{key}");
        let mut out = scrubber.push(text.as_bytes());
        out.extend(scrubber.finish());
        assert_eq!(out, b"[REDACTED:provider_key]|[REDACTED:provider_key]");
    }
}
