//! Line arithmetic on file contents, on bytes, so a file that is not UTF-8 is still compared.
//!
//! The test-protection and secret-scan gates compare a file at the base commit with the same file
//! at the head commit, both read by the control plane from the job's object store. They never
//! look at a patch to learn which lines changed, because the patch is a rendering of this
//! comparison and a gate that trusts a rendering can be told a different story than the files
//! hold.

use std::collections::HashMap;

/// The lines of `data`, without their line feed. A final line feed does not make an empty line.
#[must_use]
pub fn split(data: &[u8]) -> Vec<&[u8]> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&[u8]> = data.split(|byte| *byte == b'\n').collect();
    if data.ends_with(b"\n") {
        lines.pop();
    }
    lines
}

/// True when `after` is `before` with lines inserted and nothing else: every line of `before`
/// appears in `after`, in the same order. A changed line is a removed line and an added line, so
/// it makes this false.
///
/// Greedy matching decides it: taking the earliest match for each line of `before` never hurts
/// a later one, so the work is linear.
#[must_use]
pub fn gained_lines_only(before: &[u8], after: &[u8]) -> bool {
    let wanted = split(before);
    let mut next = 0usize;
    for line in split(after) {
        if wanted.get(next) == Some(&line) {
            next += 1;
        }
    }
    next == wanted.len()
}

/// The lines of `after` that `before` does not account for, with their line number from 1. A
/// line counts as present before as many times as `before` holds it, so a second copy of a line
/// is new.
#[must_use]
pub fn added<'a>(before: &[u8], after: &'a [u8]) -> Vec<(u32, &'a [u8])> {
    let mut available: HashMap<&[u8], usize> = HashMap::new();
    for line in split(before) {
        *available.entry(line).or_insert(0) += 1;
    }
    let mut found = Vec::new();
    for (index, line) in split(after).into_iter().enumerate() {
        match available.get_mut(line) {
            Some(left) if *left > 0 => *left -= 1,
            _ => found.push((u32::try_from(index + 1).unwrap_or(u32::MAX), line)),
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_final_line_feed_does_not_make_an_empty_line() {
        assert_eq!(split(b"a\nb\n"), vec![&b"a"[..], b"b"]);
        assert_eq!(split(b"a\nb"), vec![&b"a"[..], b"b"]);
        assert_eq!(split(b"a\n\n"), vec![&b"a"[..], b""]);
        assert!(split(b"").is_empty());
    }

    #[test]
    fn inserted_lines_are_gained_lines_and_nothing_else_is() {
        let before = b"one\ntwo\nthree\n";
        assert!(gained_lines_only(before, b"one\ntwo\nthree\nfour\n"));
        assert!(gained_lines_only(before, b"zero\none\nnew\ntwo\nthree\n"));
        assert!(gained_lines_only(before, before));
        assert!(
            !gained_lines_only(before, b"one\nTWO\nthree\n"),
            "a changed line"
        );
        assert!(
            !gained_lines_only(before, b"one\nthree\n"),
            "a removed line"
        );
        assert!(
            !gained_lines_only(before, b"three\ntwo\none\n"),
            "a reordered file"
        );
        assert!(gained_lines_only(b"", b"anything\n"));
    }

    #[test]
    fn a_line_ending_change_is_a_changed_line() {
        assert!(!gained_lines_only(b"a\nb\n", b"a\r\nb\r\n"));
    }

    #[test]
    fn a_repeated_line_is_new_when_the_base_held_it_fewer_times() {
        let found = added(b"x\ny\n", b"x\nx\ny\nz\n");
        let lines: Vec<(u32, &[u8])> = vec![(2, b"x"), (4, b"z")];
        assert_eq!(found, lines);
    }

    #[test]
    fn a_file_that_is_not_text_is_still_compared() {
        assert!(gained_lines_only(
            &[0xff, b'\n', 0x00],
            &[0xff, b'\n', 0x00, b'\n', 0x01]
        ));
    }
}
