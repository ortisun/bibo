//! Where a finding points: the lines a patch really shows.
//!
//! A finding of a verdict other than `PASS` cites a file and a line (FR-023, SC-008). The review
//! gate checks that the line is in the exported patch, so a reviewer cannot object to code it was
//! not shown, and a builder is never sent to fix a line that does not exist. The patch is the
//! host's own export from the job's object store, not anything the builder or the reviewer wrote.
//!
//! A line is in the patch when it falls in a hunk of the new file (context lines and added
//! lines), or, for a file that was deleted, in a hunk of the old file. A hunk that only removes
//! lines shows the line before the removal in the new file, and that line counts.

use std::collections::BTreeMap;

/// The lines each file of a patch shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchIndex {
    files: BTreeMap<String, Vec<(u32, u32)>>,
}

impl PatchIndex {
    /// Reads a unified patch.
    #[must_use]
    pub fn parse(patch: &[u8]) -> Self {
        let text = String::from_utf8_lossy(patch);
        let mut files: BTreeMap<String, Vec<(u32, u32)>> = BTreeMap::new();
        let mut old_path: Option<String> = None;
        let mut new_path: Option<String> = None;
        let mut current: Option<String> = None;
        let mut in_body = false;
        for line in text.lines() {
            if line.starts_with("diff --git ") {
                old_path = None;
                new_path = None;
                current = None;
                in_body = false;
                continue;
            }
            if !in_body {
                if let Some(rest) = line.strip_prefix("--- ") {
                    old_path = side(rest, "a/");
                } else if let Some(rest) = line.strip_prefix("+++ ") {
                    new_path = side(rest, "b/");
                }
            }
            if let Some(header) = line.strip_prefix("@@ ") {
                in_body = true;
                let deleted = new_path.is_none();
                let path = if deleted { &old_path } else { &new_path };
                current.clone_from(path);
                if let (Some(path), Some(range)) = (&current, hunk_range(header, deleted)) {
                    files.entry(path.clone()).or_default().push(range);
                }
            }
        }
        Self { files }
    }

    /// True when the patch shows every line from `start` to `end` (or just `start`) of `path`
    /// inside one hunk.
    #[must_use]
    pub fn shows(&self, path: &str, start: u32, end: Option<u32>) -> bool {
        let end = end.unwrap_or(start);
        if start == 0 || end < start {
            return false;
        }
        self.files.get(path).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|(first, last)| start >= *first && end <= *last)
        })
    }

    /// The paths the patch shows lines of, sorted.
    #[must_use]
    pub fn paths(&self) -> Vec<&str> {
        self.files.keys().map(String::as_str).collect()
    }
}

/// The path of one side of the patch: `None` for `/dev/null`.
fn side(rest: &str, prefix: &str) -> Option<String> {
    // A tab or a trailing timestamp can follow the path in some patch dialects.
    let rest = rest.split('\t').next().unwrap_or(rest);
    if rest == "/dev/null" {
        return None;
    }
    let path = if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
        unquote(&rest[1..rest.len() - 1])
    } else {
        rest.to_owned()
    };
    Some(path.strip_prefix(prefix).unwrap_or(&path).to_owned())
}

/// Undoes the quoting git applies to a path with unusual characters: `\"`, `\\`, `\t`, `\n` and
/// three-digit octal bytes.
fn unquote(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' || i + 1 >= bytes.len() {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b't' => out.push(b'\t'),
            b'n' => out.push(b'\n'),
            b'0'..=b'3' => {
                let octal = bytes
                    .get(i + 1..i + 4)
                    .and_then(|digits| std::str::from_utf8(digits).ok())
                    .and_then(|digits| u8::from_str_radix(digits, 8).ok());
                if let Some(byte) = octal {
                    out.push(byte);
                    i += 4;
                    continue;
                }
                out.push(bytes[i + 1]);
            }
            other => out.push(other),
        }
        i += 2;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The lines a hunk header covers: `-a[,b] +c[,d] @@ ...`.
fn hunk_range(header: &str, old_side: bool) -> Option<(u32, u32)> {
    let mut parts = header.split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let (start, length) = span(if old_side { old } else { new })?;
    if old_side {
        // A deleted file: every line of the old file is shown.
        return (length > 0).then_some((start, start + length - 1));
    }
    // A hunk that removes lines only has length 0 and names the line before the removal.
    Some((start.max(1), start.max(1) + length.max(1) - 1))
}

fn span(text: &str) -> Option<(u32, u32)> {
    match text.split_once(',') {
        Some((start, length)) => Some((start.parse().ok()?, length.parse().ok()?)),
        None => Some((text.parse().ok()?, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATCH: &str = "diff --git a/src/main.rs b/src/main.rs\nindex 1..2 100644\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -10,3 +10,5 @@ fn main() {\n context\n+added one\n+added two\n context\n context\n@@ -40,2 +42,1 @@\n keep\n-gone\ndiff --git a/old.txt b/old.txt\ndeleted file mode 100644\n--- a/old.txt\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-a\n-b\n-c\ndiff --git a/new.txt b/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1,2 @@\n+x\n+y\n";

    #[test]
    fn a_line_inside_a_hunk_of_the_new_file_is_shown() {
        let index = PatchIndex::parse(PATCH.as_bytes());
        assert!(index.shows("src/main.rs", 10, None));
        assert!(index.shows("src/main.rs", 11, Some(12)));
        assert!(index.shows("src/main.rs", 14, None));
        assert!(index.shows("new.txt", 2, None));
    }

    #[test]
    fn a_line_outside_every_hunk_is_not_shown() {
        let index = PatchIndex::parse(PATCH.as_bytes());
        assert!(!index.shows("src/main.rs", 9, None));
        assert!(!index.shows("src/main.rs", 15, None));
        // A range must sit inside one hunk, not straddle two.
        assert!(!index.shows("src/main.rs", 14, Some(42)));
        assert!(!index.shows("new.txt", 3, None));
    }

    #[test]
    fn a_file_the_patch_does_not_name_shows_nothing() {
        let index = PatchIndex::parse(PATCH.as_bytes());
        assert!(!index.shows("src/lib.rs", 1, None));
        assert!(!index.shows("", 1, None));
    }

    #[test]
    fn a_deleted_file_shows_its_old_lines() {
        let index = PatchIndex::parse(PATCH.as_bytes());
        assert!(index.shows("old.txt", 1, Some(3)));
        assert!(!index.shows("old.txt", 4, None));
    }

    #[test]
    fn a_removal_only_hunk_shows_the_line_before_it() {
        let index = PatchIndex::parse(PATCH.as_bytes());
        assert!(index.shows("src/main.rs", 42, None));
    }

    #[test]
    fn line_zero_and_a_backwards_range_are_never_shown() {
        let index = PatchIndex::parse(PATCH.as_bytes());
        assert!(!index.shows("src/main.rs", 0, None));
        assert!(!index.shows("src/main.rs", 12, Some(11)));
    }

    #[test]
    fn a_quoted_path_is_read_back() {
        let patch = "diff --git \"a/caf\\303\\251.txt\" \"b/caf\\303\\251.txt\"\n--- \"a/caf\\303\\251.txt\"\n+++ \"b/caf\\303\\251.txt\"\n@@ -1 +1 @@\n-a\n+b\n";
        let index = PatchIndex::parse(patch.as_bytes());
        assert_eq!(index.paths(), ["café.txt"]);
        assert!(index.shows("café.txt", 1, None));
    }

    #[test]
    fn text_inside_a_hunk_that_looks_like_a_header_is_not_a_header() {
        let patch = "diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1,2 +1,3 @@\n keep\n+--- a/other.txt\n++++ b/other.txt\n";
        let index = PatchIndex::parse(patch.as_bytes());
        assert_eq!(index.paths(), ["a.txt"]);
    }
}
