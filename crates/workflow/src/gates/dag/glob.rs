//! Path globs, for deciding whether two tasks might write the same file.
//!
//! The question is asked of two patterns, not of a pattern and a path, so the matcher answers
//! "could one path match both". The answer errs towards yes: two patterns that cannot be told
//! apart safely are reported as overlapping, because the cost of a false overlap is one extra
//! ordering edge in a plan, and the cost of a missed one is two builders changing the same file.

/// True when some path could match both patterns.
///
/// `*` and `?` stay inside one path segment, and `**` matches any number of segments, including
/// none. A pattern that ends with `/` stands for everything below that directory.
#[must_use]
pub fn may_overlap(left: &str, right: &str) -> bool {
    let left = segments(left);
    let right = segments(right);
    segments_overlap(&left, &right)
}

/// True when the pattern matches this literal path.
#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    let pattern = segments(pattern);
    let path: Vec<&str> = path
        .trim_start_matches("./")
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    segments_overlap(&pattern, &path)
}

/// True when the text has no wildcard, so it names exactly one path.
#[must_use]
pub fn is_literal(pattern: &str) -> bool {
    !pattern.contains(['*', '?', '[', '{'])
}

fn segments(pattern: &str) -> Vec<&str> {
    let trimmed = pattern.trim().trim_start_matches("./");
    let mut parts: Vec<&str> = trimmed.split('/').filter(|part| !part.is_empty()).collect();
    if trimmed.ends_with('/') {
        parts.push("**");
    }
    parts
}

fn segments_overlap(left: &[&str], right: &[&str]) -> bool {
    match (left.split_first(), right.split_first()) {
        (None, None) => true,
        (Some((&"**", rest)), _) => {
            segments_overlap(rest, right)
                || right
                    .split_first()
                    .is_some_and(|(_, tail)| segments_overlap(left, tail))
        }
        (_, Some((&"**", rest))) => {
            segments_overlap(left, rest)
                || left
                    .split_first()
                    .is_some_and(|(_, tail)| segments_overlap(tail, right))
        }
        (Some((a, left_rest)), Some((b, right_rest))) => {
            names_overlap(a, b) && segments_overlap(left_rest, right_rest)
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn has_wildcard(segment: &str) -> bool {
    segment.contains(['*', '?'])
}

fn names_overlap(a: &str, b: &str) -> bool {
    match (has_wildcard(a), has_wildcard(b)) {
        (false, false) => a == b,
        (true, false) => wild_match(a.as_bytes(), b.as_bytes()),
        (false, true) => wild_match(b.as_bytes(), a.as_bytes()),
        // Two wildcards: compatible if the fixed start and the fixed end of one agree with the
        // other. This can say yes for patterns that share no name, which is the safe direction.
        (true, true) => {
            let (a_head, a_tail) = fixed_ends(a);
            let (b_head, b_tail) = fixed_ends(b);
            (a_head.starts_with(b_head) || b_head.starts_with(a_head))
                && (a_tail.ends_with(b_tail) || b_tail.ends_with(a_tail))
        }
    }
}

fn fixed_ends(pattern: &str) -> (&str, &str) {
    let head_end = pattern.find(['*', '?']).unwrap_or(pattern.len());
    let tail_start = pattern.rfind(['*', '?']).map_or(0, |at| at + 1);
    (
        pattern.get(..head_end).unwrap_or(""),
        pattern.get(tail_start..).unwrap_or(""),
    )
}

fn wild_match(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => {
            wild_match(rest, text)
                || text
                    .split_first()
                    .is_some_and(|(_, tail)| wild_match(pattern, tail))
        }
        Some((b'?', rest)) => text
            .split_first()
            .is_some_and(|(_, tail)| wild_match(rest, tail)),
        Some((byte, rest)) => text
            .split_first()
            .is_some_and(|(head, tail)| head == byte && wild_match(rest, tail)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_file_overlaps_itself_and_a_different_file_does_not() {
        assert!(may_overlap("src/main.rs", "src/main.rs"));
        assert!(!may_overlap("src/main.rs", "src/output.rs"));
        assert!(!may_overlap("src/main.rs", "tests/main.rs"));
    }

    #[test]
    fn a_directory_pattern_overlaps_what_is_below_it() {
        assert!(may_overlap("src/**", "src/output.rs"));
        assert!(may_overlap("src/output.rs", "src/**"));
        assert!(may_overlap("src/", "src/deep/er/file.rs"));
        assert!(!may_overlap("src/**", "tests/it.rs"));
        assert!(may_overlap("**", "anything/at/all.txt"));
    }

    #[test]
    fn a_wildcard_in_a_name_overlaps_the_names_it_matches() {
        assert!(may_overlap("src/*.rs", "src/main.rs"));
        assert!(!may_overlap("src/*.rs", "src/main.py"));
        assert!(!may_overlap("src/*.rs", "src/deep/main.rs"));
        assert!(may_overlap("src/ma?n.rs", "src/main.rs"));
    }

    #[test]
    fn two_wildcard_names_overlap_unless_their_fixed_parts_disagree() {
        assert!(may_overlap("src/*.rs", "src/m*.rs"));
        assert!(!may_overlap("src/*.rs", "src/*.py"));
        assert!(!may_overlap("src/a*", "src/b*"));
    }

    #[test]
    fn a_pattern_matches_a_literal_path_by_the_same_rules() {
        assert!(matches("src/**", "src/a/b.rs"));
        assert!(matches("./src/*.rs", "src/main.rs"));
        assert!(!matches("src/*.rs", "src/a/main.rs"));
        assert!(is_literal("src/main.rs"));
        assert!(!is_literal("src/*.rs"));
    }
}
