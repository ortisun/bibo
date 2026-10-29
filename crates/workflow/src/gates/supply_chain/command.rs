//! The words of a decision on a dependency, and how they find the subject the person was shown.
//!
//! A person decides on a dependency (or on its build code) from a comment on the pull request, from
//! the command line, or from the dashboard. The first two are text, and this module is the one
//! place that reads it. It is pure: it reads no file, opens no connection and knows no person. The
//! API and the command line call it and then hand the engine the **resolved subject**
//! (`Engine::record_dependency_decision`); the person is authorized by the policy engine and not
//! by anything written here.
//!
//! # The two verbs
//!
//! | Verb | Action of `approval.yaml` | Kind |
//! |---|---|---|
//! | `approve-dependency` | `add_new_direct_dependency` | [`ApprovalKind::NewDependency`] |
//! | `approve-build-code` | `approve_build_code` | [`ApprovalKind::BuildCode`] |
//!
//! ```text
//! /factory approve-dependency some-crate 0.1.0 6f1d2c9ab0e3 Read the maintainers and the licence.
//! approve-build-code helper 0.1.0 6f1d2c9ab0e3 Read the build script, it only sets cfg flags.
//! ```
//!
//! After the verb come the name, the version, an optional prefix of the checksum (12 to 64 lower
//! case hexadecimal digits, with or without `sha256:`), and the reason in the person's words. The
//! checksum is the part of the subject that a person copies from the evidence they were shown, and
//! it is how the person says "this one" when two packages share a name and a version. Without it,
//! the decision is for the only awaited package of that name and version, and a comment that
//! matches two is refused.
//!
//! # What is read
//!
//! * Only the first line. A second line, a quotation, a code fence and an HTML comment are not
//!   commands (`approval.yaml` `commands.github_comment`).
//! * The prefix `/factory ` is optional, so the same text serves the comment and the command line.
//! * The verb is matched exactly, in lower case. Anything else is [`ParsedLine::NotOurs`], which
//!   the caller passes on to the other command readers.
//! * A name that is not a cargo package name, and a version that is not a version, are refused
//!   with a reason, and so is a word that looks like a checksum and is not one.

use factory_domain::policy::dependency::Ecosystem;

use super::approval::{ApprovalKind, Subject};
use super::model::normalize;
use super::review::Awaited;
use super::version::Version;

/// The prefix of a command in a pull request comment.
pub const COMMENT_PREFIX: &str = "/factory ";

/// The shortest prefix of a checksum that selects a package.
pub const MIN_CHECKSUM_PREFIX: usize = 12;

/// The verb of a decision on a dependency.
pub const APPROVE_DEPENDENCY: &str = "approve-dependency";

/// The verb of a decision on build code.
pub const APPROVE_BUILD_CODE: &str = "approve-build-code";

/// A decision on a dependency, as the person wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyCommand {
    /// A decision on the dependency, or on its build code.
    pub kind: ApprovalKind,
    /// The package name as written.
    pub name: String,
    /// The version as written.
    pub version: String,
    /// The start of the checksum, lower case hexadecimal, when the person wrote one.
    pub checksum_prefix: Option<String>,
    /// The reason, in the person's words. It may be empty here; the record needs at least
    /// [`MIN_REASON_CHARS`](super::approval::MIN_REASON_CHARS) characters and refuses less.
    pub reason: String,
}

/// What a line is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLine {
    /// A decision on a dependency.
    Command(DependencyCommand),
    /// Not one of the two verbs. It may be a command for another reader, or no command at all.
    NotOurs,
}

/// Why a line that names one of the two verbs was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// The verb has no package name.
    #[error("the command needs a package name")]
    NoName,
    /// The name is not a name of a cargo package.
    #[error("the package name is not a name of a cargo package")]
    InvalidName,
    /// The command has no version.
    #[error("the command needs a version")]
    NoVersion,
    /// The version is not a version such as 1.2.3.
    #[error("the version is not a version such as 1.2.3")]
    InvalidVersion,
    /// A word that begins like a checksum is not one: it has to be 12 to 64 lower case
    /// hexadecimal digits.
    #[error("the checksum has to be 12 to 64 lower case hexadecimal digits")]
    InvalidChecksum,
}

/// Reads the first line of `text` as a decision on a dependency.
///
/// # Errors
/// [`CommandError`] when the line names one of the two verbs and the rest is wrong.
pub fn parse_dependency_command(text: &str) -> Result<ParsedLine, CommandError> {
    let line = text.lines().next().unwrap_or_default().trim();
    // A quotation, a code fence and an HTML comment are not commands.
    if line.starts_with(['>', '`', '<']) || line.starts_with("~~~") {
        return Ok(ParsedLine::NotOurs);
    }
    let line = line
        .strip_prefix(COMMENT_PREFIX)
        .unwrap_or(line)
        .trim_start();
    let (verb, rest) = split_word(line);
    let kind = match verb {
        APPROVE_DEPENDENCY => ApprovalKind::NewDependency,
        APPROVE_BUILD_CODE => ApprovalKind::BuildCode,
        _ => return Ok(ParsedLine::NotOurs),
    };
    let (name, rest) = split_word(rest);
    if name.is_empty() {
        return Err(CommandError::NoName);
    }
    if !Ecosystem::Cargo.valid_name(name) {
        return Err(CommandError::InvalidName);
    }
    let (version, rest) = split_word(rest);
    if version.is_empty() {
        return Err(CommandError::NoVersion);
    }
    if Version::parse(version).is_none() {
        return Err(CommandError::InvalidVersion);
    }
    let (next, after) = split_word(rest);
    let (checksum_prefix, reason) = match checksum_word(next)? {
        Some(prefix) => (Some(prefix), after),
        None => (None, rest),
    };
    Ok(ParsedLine::Command(DependencyCommand {
        kind,
        name: name.to_owned(),
        version: version.to_owned(),
        checksum_prefix,
        reason: reason.trim().to_owned(),
    }))
}

/// The first word and what follows it, without the space between.
fn split_word(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    text.split_once(char::is_whitespace)
        .map_or((text, ""), |(word, rest)| (word, rest.trim_start()))
}

/// A word that is a checksum prefix, `None` for a word that is not meant as one (the start of the
/// reason), and an error for a word that is meant as one and is wrong.
fn checksum_word(word: &str) -> Result<Option<String>, CommandError> {
    let Some(digits) = word.strip_prefix("sha256:").or_else(|| {
        // A bare word of hexadecimal digits long enough to be a prefix is a checksum.
        (word.len() >= MIN_CHECKSUM_PREFIX && word.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then_some(word)
    }) else {
        return Ok(None);
    };
    let lower_hex = digits
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if (MIN_CHECKSUM_PREFIX..=64).contains(&digits.len()) && lower_hex {
        Ok(Some(digits.to_owned()))
    } else {
        Err(CommandError::InvalidChecksum)
    }
}

/// Why a command did not select exactly one awaited decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// Nothing the person was shown matches. The stage run does not await this package, this
    /// version, this checksum or this kind of decision, and a decision on something that is not
    /// awaited is not recorded.
    #[error("no decision of this kind is awaited for that package")]
    NotAwaited,
    /// More than one awaited package matches. The checksum says which.
    #[error("more than one awaited package matches; add the start of the checksum")]
    Ambiguous,
}

/// The one awaited decision the command selects: the same kind, the same name as cargo compares
/// names, the same version, and a checksum that starts with the prefix when the person wrote one.
///
/// # Errors
/// [`ResolveError`] when none matches or more than one does.
pub fn resolve<'a>(
    awaited: &'a [Awaited],
    command: &DependencyCommand,
) -> Result<&'a Awaited, ResolveError> {
    let mut found = awaited.iter().filter(|candidate| {
        candidate.kind == command.kind
            && normalize(&candidate.subject.name) == normalize(&command.name)
            && candidate.subject.version == command.version
            && command
                .checksum_prefix
                .as_ref()
                .is_none_or(|prefix| candidate.subject.checksum.starts_with(prefix.as_str()))
    });
    match (found.next(), found.next()) {
        (Some(one), None) => Ok(one),
        (None, _) => Err(ResolveError::NotAwaited),
        (Some(_), Some(_)) => Err(ResolveError::Ambiguous),
    }
}

/// The subject a resolved command decides on.
#[must_use]
pub fn subject_of(awaited: &Awaited) -> Subject {
    awaited.subject.clone()
}

#[cfg(test)]
mod tests {
    use factory_domain::policy::decision::Designation;

    use super::*;

    fn command(text: &str) -> DependencyCommand {
        match parse_dependency_command(text) {
            Ok(ParsedLine::Command(command)) => command,
            other => panic!("{text}: expected a command, got {other:?}"),
        }
    }

    const SUM: &str = "6f1d2c9ab0e3aa11bb22cc33dd44ee55ff66778899aabbccddeeff0011223344";

    #[test]
    fn a_comment_and_a_command_line_read_the_same() {
        let reason = "Read the maintainers and the licence.";
        let from_comment = command(&format!(
            "/factory approve-dependency some-crate 0.1.0 6f1d2c9ab0e3 {reason}"
        ));
        let from_cli = command(&format!(
            "approve-dependency some-crate 0.1.0 6f1d2c9ab0e3 {reason}"
        ));
        assert_eq!(from_comment, from_cli);
        assert_eq!(from_comment.kind, ApprovalKind::NewDependency);
        assert_eq!(from_comment.name, "some-crate");
        assert_eq!(from_comment.version, "0.1.0");
        assert_eq!(
            from_comment.checksum_prefix.as_deref(),
            Some("6f1d2c9ab0e3")
        );
        assert_eq!(from_comment.reason, reason);
    }

    #[test]
    fn the_build_code_verb_is_the_other_kind() {
        let parsed = command("/factory approve-build-code helper 0.1.0 Looked at build.rs.");
        assert_eq!(parsed.kind, ApprovalKind::BuildCode);
        assert_eq!(parsed.checksum_prefix, None);
        assert_eq!(parsed.reason, "Looked at build.rs.");
    }

    #[test]
    fn a_checksum_may_be_written_in_full_with_its_prefix_and_a_reason_may_be_missing() {
        let parsed = command(&format!("approve-dependency a 1.2.3-rc.1 sha256:{SUM}"));
        assert_eq!(parsed.checksum_prefix.as_deref(), Some(SUM));
        assert_eq!(parsed.reason, "");
        // A short word is the start of the reason and not a checksum.
        let parsed = command("approve-dependency a 1.2.3 deadbeef looks fine to me");
        assert_eq!(parsed.checksum_prefix, None);
        assert_eq!(parsed.reason, "deadbeef looks fine to me");
    }

    #[test]
    fn only_the_first_line_counts_and_only_when_it_is_not_quoted_or_fenced() {
        let parsed = command(
            "/factory approve-dependency a 1.0.0 fine\n/factory approve-dependency b 2.0.0 also",
        );
        assert_eq!(parsed.name, "a");
        for not_a_command in [
            "> /factory approve-dependency a 1.0.0 fine",
            "```\n/factory approve-dependency a 1.0.0 fine\n```",
            "<!-- /factory approve-dependency a 1.0.0 fine -->",
            "Please /factory approve-dependency a 1.0.0",
            "\n/factory approve-dependency a 1.0.0 fine",
            "",
        ] {
            assert_eq!(
                parse_dependency_command(not_a_command),
                Ok(ParsedLine::NotOurs),
                "{not_a_command:?}"
            );
        }
    }

    #[test]
    fn another_verb_is_not_ours_and_the_match_is_exact() {
        for other in [
            "/factory approve",
            "/factory merge",
            "/factory approve-dependencies a 1.0.0",
            "/factory APPROVE-DEPENDENCY a 1.0.0",
            "/factory approve_dependency a 1.0.0",
            "/factory  approve-dependency",
        ] {
            let parsed = parse_dependency_command(other);
            // The last has two spaces after the prefix; it is read as the verb with no name.
            assert!(
                matches!(parsed, Ok(ParsedLine::NotOurs) | Err(CommandError::NoName)),
                "{other}: {parsed:?}"
            );
        }
        assert_eq!(
            parse_dependency_command("/factory approve-dependency"),
            Err(CommandError::NoName)
        );
    }

    #[test]
    fn a_name_a_version_or_a_checksum_that_is_wrong_is_refused_with_a_reason() {
        for (text, error) in [
            ("approve-dependency", CommandError::NoName),
            ("approve-dependency a", CommandError::NoVersion),
            ("approve-dependency ../x 1.0.0", CommandError::InvalidName),
            ("approve-dependency a?b=c 1.0.0", CommandError::InvalidName),
            ("approve-dependency 9lives 1.0.0", CommandError::InvalidName),
            ("approve-dependency a latest", CommandError::InvalidVersion),
            ("approve-dependency a 1.0", CommandError::InvalidVersion),
            (
                "approve-dependency a 1.0.0 sha256:abc",
                CommandError::InvalidChecksum,
            ),
            (
                "approve-dependency a 1.0.0 sha256:0123456789AB",
                CommandError::InvalidChecksum,
            ),
            (
                "approve-dependency a 1.0.0 0123456789ABCDEF",
                CommandError::InvalidChecksum,
            ),
        ] {
            assert_eq!(parse_dependency_command(text), Err(error), "{text}");
        }
    }

    fn awaited(kind: ApprovalKind, name: &str, version: &str, checksum: &str) -> Awaited {
        Awaited {
            kind,
            subject: Subject {
                name: name.to_owned(),
                version: version.to_owned(),
                checksum: checksum.to_owned(),
            },
            needs: Designation::Approver,
        }
    }

    #[test]
    fn a_command_selects_the_one_awaited_subject_it_names() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let list = vec![
            awaited(ApprovalKind::NewDependency, "some-crate", "0.1.0", &a),
            awaited(ApprovalKind::NewDependency, "some_crate", "0.1.0", &b),
            awaited(ApprovalKind::BuildCode, "helper", "0.1.0", &a),
            awaited(ApprovalKind::NewDependency, "other", "2.0.0", &b),
        ];
        let pick = |text: &str| resolve(&list, &command(text)).map(|found| found.subject.clone());
        // Two awaited packages share a name as cargo compares names and a version: the checksum
        // says which, and without it the command is refused.
        assert_eq!(
            pick("approve-dependency some-crate 0.1.0"),
            Err(ResolveError::Ambiguous)
        );
        assert_eq!(
            pick("approve-dependency some-crate 0.1.0 bbbbbbbbbbbb"),
            Ok(list[1].subject.clone())
        );
        assert_eq!(
            pick("approve-dependency some-crate 0.1.0 sha256:aaaaaaaaaaaa"),
            Ok(list[0].subject.clone())
        );
        // The kind has to match: build code is not decided with the dependency verb.
        assert_eq!(
            pick("approve-dependency helper 0.1.0"),
            Err(ResolveError::NotAwaited)
        );
        assert_eq!(
            pick("approve-build-code helper 0.1.0"),
            Ok(list[2].subject.clone())
        );
        // Another version, another checksum, a package nobody awaits.
        assert_eq!(
            pick("approve-dependency other 2.0.1"),
            Err(ResolveError::NotAwaited)
        );
        assert_eq!(
            pick("approve-dependency other 2.0.0 cccccccccccc"),
            Err(ResolveError::NotAwaited)
        );
        assert_eq!(
            pick("approve-dependency nothing 1.0.0"),
            Err(ResolveError::NotAwaited)
        );
        assert_eq!(
            resolve(&[], &command("approve-dependency a 1.0.0")),
            Err(ResolveError::NotAwaited)
        );
    }
}
