//! The extended headers of a git patch: the facts a list of changed paths does not carry.
//!
//! The list of changes says which paths were added, modified or deleted. A mode change, a file
//! that became a symbolic link, a symbolic link's target and a gitlink are visible only in the
//! patch. The workspace adapter exports the patch with `--no-renames`, `--binary` and a fixed
//! context, from the job's object store on the host, so the headers describe the committed
//! trees.
//!
//! The parser reads headers and nothing else. It does not decide whether a change is allowed. If
//! it meets a `diff --git` line it cannot split into two paths, it says the patch was not
//! understood, and the gate that needed the patch is `BLOCKED` instead of guessing.

/// A symbolic link has this file mode.
pub const SYMLINK_MODE: u32 = 0o120_000;
/// A gitlink (a submodule entry) has this file mode.
pub const GITLINK_MODE: u32 = 0o160_000;
/// The bits of a mode that say what kind of entry it is.
const KIND_MASK: u32 = 0o170_000;

/// What the headers of one file say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PatchFact {
    /// The path before the change.
    pub old_path: String,
    /// The path after the change.
    pub new_path: String,
    /// The mode before, when the headers say it.
    pub old_mode: Option<u32>,
    /// The mode after, when the headers say it.
    pub new_mode: Option<u32>,
    /// The source of a rename.
    pub renamed_from: Option<String>,
    /// The source of a copy.
    pub copied_from: Option<String>,
    /// The text of a symbolic link, when the file became or is a link.
    pub link_target: Option<String>,
}

impl PatchFact {
    /// What kind of entry a mode stands for.
    #[must_use]
    pub const fn kind_of(mode: u32) -> u32 {
        mode & KIND_MASK
    }
}

/// Every file the patch names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    files: Vec<PatchFact>,
    understood: bool,
}

impl Facts {
    /// The facts of the file at `path`, found by its new or its old name.
    #[must_use]
    pub fn find(&self, path: &str) -> Option<&PatchFact> {
        self.files
            .iter()
            .find(|fact| fact.new_path == path)
            .or_else(|| self.files.iter().find(|fact| fact.old_path == path))
    }

    /// Every file, in patch order.
    #[must_use]
    pub fn files(&self) -> &[PatchFact] {
        &self.files
    }

    /// False when a header could not be read. The facts are then not the whole story.
    #[must_use]
    pub const fn understood(&self) -> bool {
        self.understood
    }
}

/// Reads the headers of `patch`.
#[must_use]
pub fn parse(patch: &[u8]) -> Facts {
    let text = String::from_utf8_lossy(patch);
    let mut files: Vec<PatchFact> = Vec::new();
    let mut understood = true;
    let mut in_body = false;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            in_body = false;
            match header_paths(rest) {
                Some((old_path, new_path)) => files.push(PatchFact {
                    old_path,
                    new_path,
                    ..PatchFact::default()
                }),
                None => understood = false,
            }
            continue;
        }
        let Some(fact) = files.last_mut() else {
            continue;
        };
        if in_body {
            if fact.link_target.is_none()
                && fact.new_mode.map(PatchFact::kind_of) == Some(SYMLINK_MODE)
                && let Some(target) = line.strip_prefix('+')
            {
                fact.link_target = Some(target.to_owned());
            }
            continue;
        }
        if line.starts_with("@@") || line.starts_with("GIT binary patch") {
            in_body = true;
        } else if let Some(mode) = line.strip_prefix("old mode ") {
            fact.old_mode = octal(mode);
        } else if let Some(mode) = line.strip_prefix("new mode ") {
            fact.new_mode = octal(mode);
        } else if let Some(mode) = line.strip_prefix("new file mode ") {
            fact.new_mode = octal(mode);
        } else if let Some(mode) = line.strip_prefix("deleted file mode ") {
            fact.old_mode = octal(mode);
        } else if let Some(from) = line.strip_prefix("rename from ") {
            fact.renamed_from = Some(unquote(from));
        } else if let Some(from) = line.strip_prefix("copy from ") {
            fact.copied_from = Some(unquote(from));
        }
    }
    Facts { files, understood }
}

fn octal(text: &str) -> Option<u32> {
    u32::from_str_radix(text.trim(), 8).ok()
}

/// The two paths of `a/<old> b/<new>`, each quoted or not.
fn header_paths(rest: &str) -> Option<(String, String)> {
    if rest.starts_with('"') {
        let (first, tail) = take_quoted(rest)?;
        let second = tail.strip_prefix(' ')?;
        let second = if second.starts_with('"') {
            take_quoted(second).map(|(token, _)| token)?
        } else {
            second.to_owned()
        };
        return Some((strip_side(&first, "a/")?, strip_side(&second, "b/")?));
    }
    // Without quotes the two names are equal when nothing was renamed, which is the case for a
    // patch made with `--no-renames`. A name with a space in it is split at the middle.
    let middle = rest.len() / 2;
    if rest.is_char_boundary(middle)
        && rest.as_bytes().get(middle) == Some(&b' ')
        && let (Some(old), Some(new)) = (
            rest.get(..middle).and_then(|s| s.strip_prefix("a/")),
            rest.get(middle + 1..).and_then(|s| s.strip_prefix("b/")),
        )
        && old == new
    {
        return Some((old.to_owned(), new.to_owned()));
    }
    let (old, new) = rest.split_once(" b/")?;
    Some((old.strip_prefix("a/")?.to_owned(), new.to_owned()))
}

fn strip_side(token: &str, side: &str) -> Option<String> {
    token.strip_prefix(side).map(str::to_owned)
}

/// A C-style quoted token at the start of `text`, unquoted, and what follows it.
fn take_quoted(text: &str) -> Option<(String, &str)> {
    let body = text.strip_prefix('"')?;
    let bytes = body.as_bytes();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\\' => index += 2,
            b'"' => {
                let quoted = body.get(..index)?;
                return Some((unescape(quoted), body.get(index + 1..)?));
            }
            _ => index += 1,
        }
    }
    None
}

fn unquote(text: &str) -> String {
    text.strip_prefix('"')
        .and_then(|_| take_quoted(text))
        .map_or_else(|| text.to_owned(), |(token, _)| token)
}

/// Decodes the escapes git writes in a quoted name: `\\`, `\"`, `\n`, `\t` and three-digit octal.
fn unescape(quoted: &str) -> String {
    let bytes = quoted.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte != b'\\' {
            out.push(byte);
            index += 1;
            continue;
        }
        index += 1;
        match bytes.get(index) {
            Some(b'n') => out.push(b'\n'),
            Some(b't') => out.push(b'\t'),
            Some(b'r') => out.push(b'\r'),
            Some(digit @ b'0'..=b'7') => {
                let mut value = u32::from(digit - b'0');
                let mut taken = 1;
                while taken < 3
                    && let Some(next @ b'0'..=b'7') = bytes.get(index + 1)
                {
                    value = value * 8 + u32::from(next - b'0');
                    index += 1;
                    taken += 1;
                }
                out.push(u8::try_from(value & 0xff).unwrap_or(b'?'));
            }
            Some(other) => out.push(*other),
            None => {}
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODE_CHANGE: &str =
        "diff --git a/scripts/run.sh b/scripts/run.sh\nold mode 100644\nnew mode 100755\n";
    const NEW_SYMLINK: &str = "diff --git a/docs/link b/docs/link\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/docs/link\n@@ -0,0 +1 @@\n+../../etc/passwd\n\\ No newline at end of file\n";
    const GITLINK: &str = "diff --git a/vendor/x b/vendor/x\nnew file mode 160000\nindex 0000000..2222222\n--- /dev/null\n+++ b/vendor/x\n@@ -0,0 +1 @@\n+Subproject commit 3333333333333333333333333333333333333333\n";

    #[test]
    fn a_mode_change_is_read() {
        let facts = parse(MODE_CHANGE.as_bytes());
        assert!(facts.understood());
        let fact = facts.find("scripts/run.sh").expect("the file");
        assert_eq!(
            (fact.old_mode, fact.new_mode),
            (Some(0o100_644), Some(0o100_755))
        );
    }

    #[test]
    fn a_new_symbolic_link_and_its_target_are_read() {
        let facts = parse(NEW_SYMLINK.as_bytes());
        let fact = facts.find("docs/link").expect("the link");
        assert_eq!(fact.new_mode, Some(SYMLINK_MODE));
        assert_eq!(fact.link_target.as_deref(), Some("../../etc/passwd"));
    }

    #[test]
    fn a_gitlink_is_read() {
        let facts = parse(GITLINK.as_bytes());
        assert_eq!(
            facts.find("vendor/x").and_then(|f| f.new_mode),
            Some(GITLINK_MODE)
        );
    }

    #[test]
    fn a_body_line_that_looks_like_a_header_is_not_one() {
        let patch = "diff --git a/f b/f\nindex 1..2 100644\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-new file mode 120000\n+new mode 100755\n";
        let facts = parse(patch.as_bytes());
        let fact = facts.find("f").expect("the file");
        assert_eq!((fact.old_mode, fact.new_mode), (None, None));
        assert_eq!(facts.files().len(), 1);
    }

    #[test]
    fn a_quoted_name_with_octal_escapes_is_decoded() {
        // "e" + combining acute accent (NFD), as git quotes it.
        let patch = "diff --git \"a/caf\\145\\314\\201.rs\" \"b/caf\\145\\314\\201.rs\"\nold mode 100644\nnew mode 100755\n";
        let facts = parse(patch.as_bytes());
        assert!(facts.understood());
        assert!(facts.find("cafe\u{301}.rs").is_some());
    }

    #[test]
    fn a_name_with_a_space_is_found() {
        let patch =
            "diff --git a/my docs/a b.md b/my docs/a b.md\nold mode 100644\nnew mode 100755\n";
        assert!(parse(patch.as_bytes()).find("my docs/a b.md").is_some());
    }

    #[test]
    fn a_header_that_cannot_be_split_says_the_patch_was_not_understood() {
        assert!(!parse(b"diff --git nonsense\n").understood());
    }

    #[test]
    fn a_rename_names_its_source() {
        let patch = "diff --git a/old.txt b/new.txt\nsimilarity index 100%\nrename from old.txt\nrename to new.txt\n";
        let facts = parse(patch.as_bytes());
        assert_eq!(
            facts
                .find("new.txt")
                .and_then(|f| f.renamed_from.clone())
                .as_deref(),
            Some("old.txt")
        );
    }

    #[test]
    fn the_export_of_the_fake_without_headers_has_no_facts_and_is_understood() {
        let facts = parse(b"--- a/x\n+++ b/x\n-old\n+new\n");
        assert!(facts.understood());
        assert!(facts.files().is_empty());
    }
}
