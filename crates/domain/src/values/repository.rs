//! The shape of a repository's `owner/name` and of its default branch.
//!
//! The API checks these when a person registers a repository, and the worker checks them again when it
//! applies the signed request (finding RH-12): the worker is the trust anchor of that channel, so it
//! validates what it writes and does not rely on the API having done so. One definition, here, so the two
//! cannot disagree.

/// The longest `owner/name` a registration accepts, in bytes. GitHub allows 39 and 100 characters.
pub const MAX_FULL_NAME_BYTES: usize = 140;
/// The longest default branch name a registration accepts, in bytes (the column's own limit).
pub const MAX_BRANCH_BYTES: usize = 255;

/// `owner/name` as the table checks it, and no longer than GitHub allows: two parts of ASCII letters, digits,
/// `_`, `.` and `-`, neither empty, neither `.` nor `..`.
#[must_use]
pub fn is_repository_full_name(text: &str) -> bool {
    let word = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    };
    text.len() <= MAX_FULL_NAME_BYTES
        && text
            .split_once('/')
            .is_some_and(|(owner, name)| word(owner) && word(name))
}

/// A branch name as a registration accepts it: letters, digits and `. _ / -`, no empty part, no `..`, no leading
/// `-` or `/`, no trailing `/`.
#[must_use]
pub fn is_repository_branch(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_BRANCH_BYTES
        && !text.starts_with(['-', '/'])
        && !text.ends_with('/')
        && !text.contains("..")
        && !text.contains("//")
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_name_is_owner_slash_name_and_nothing_else() {
        for good in ["octo/hello", "a/b", "my-org/my.repo_1", "O/n"] {
            assert!(is_repository_full_name(good), "{good}");
        }
        for bad in [
            "", "octo", "octo/", "/hello", "a/b/c", "a b/c", "a/b c", "a/b\n", "../x", "a/..",
            "./x", "é/x", "a/b?x", "a/b#1", "a/b%2f",
        ] {
            assert!(!is_repository_full_name(bad), "{bad:?}");
        }
        assert!(!is_repository_full_name(&format!(
            "{}/x",
            "o".repeat(MAX_FULL_NAME_BYTES)
        )));
    }

    #[test]
    fn a_branch_is_a_plain_path_of_safe_characters() {
        for good in ["main", "release/1.2", "feature/a-b_c", "v1.0.0"] {
            assert!(is_repository_branch(good), "{good}");
        }
        for bad in [
            "", "/main", "main/", "a//b", "a..b", "-main", "a b", "a\tb", "a\nb", "é", "a:b",
            "a~b", "a^b", "a?b", "a*b", "a[b", "a\\b",
        ] {
            assert!(!is_repository_branch(bad), "{bad:?}");
        }
        assert!(!is_repository_branch(&"a".repeat(MAX_BRANCH_BYTES + 1)));
        assert!(is_repository_branch(&"a".repeat(MAX_BRANCH_BYTES)));
    }
}
