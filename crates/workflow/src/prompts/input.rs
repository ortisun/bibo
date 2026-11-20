//! The inputs of a prompt: what a piece of text is, where it came from, and whether it is
//! trusted.
//!
//! An input is built by the stage that fetched the text, with the constructor that says what it
//! is. There is no constructor that takes a trust tag as a parameter, so the tag always follows
//! from the way the input was made:
//!
//! * [`Input::untrusted`] is text from outside the factory: an issue, a repository file, command
//!   output, a web page, or anything a model wrote. This is the usual case.
//! * [`Input::trusted_identifier`] is a value the factory made, such as the id of a frozen
//!   specification. It must be a plain identifier. It is checked, not escaped.
//! * [`Input::self_assessment`] is what an agent said about its own work: a summary, notes,
//!   reasoning or a report. It is untrusted, and the type system keeps it away from reviewers
//!   (see [`IndependentInput`]).

use factory_domain::ids::TenantId;
use factory_domain::values::{GitSha, Timestamp};

use super::error::AssemblyError;

/// Whether the factory made the value or it came from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Trust {
    /// A plain identifier the factory made. It is the only kind that may fill a trusted slot.
    Trusted,
    /// Anything else. It goes inside a quoted block and nowhere else.
    Untrusted,
}

impl Trust {
    /// The name used in the context manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }
}

/// A range of lines of a file, counted from 1, both ends included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LineRange {
    /// The first line.
    pub start: u32,
    /// The last line.
    pub end: u32,
}

/// Where a text came from. The set is closed, and one member marks text that must not reach an
/// independent reviewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// An issue.
    Issue {
        /// The issue number.
        number: u64,
    },
    /// A comment on an issue.
    IssueComment {
        /// The issue number.
        issue: u64,
        /// The comment id.
        comment: u64,
    },
    /// A pull request.
    PullRequest {
        /// The pull request number.
        number: u64,
    },
    /// A file of the repository, or a part of one.
    RepoFile {
        /// The path, as the caller has it. The path policy decides whether the file may be read.
        path: String,
        /// The commit the file was read at.
        commit: Option<GitSha>,
        /// The lines taken, when not the whole file.
        lines: Option<LineRange>,
    },
    /// A commit message.
    CommitMessage {
        /// The commit.
        commit: GitSha,
    },
    /// Output of a command or a gate.
    ToolOutput {
        /// What produced it, such as a gate id.
        producer: String,
    },
    /// A fetched web page.
    WebPage {
        /// The address that was fetched.
        url: String,
    },
    /// A stored artifact that the factory computed or froze: a diff, a gate report, the frozen
    /// specification, the repository map.
    HostArtifact {
        /// The kind, such as `diff`.
        kind: String,
        /// The identifier or hash of the artifact.
        id: String,
    },
    /// An answer a person gave.
    HumanAnswer {
        /// Who gave it.
        principal: String,
    },
    /// What an agent said about its own work: a summary, notes, reasoning or a report.
    SelfAssessment {
        /// The agent.
        agent: String,
    },
}

impl Source {
    /// The repository paths this source is made of.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        match self {
            Self::RepoFile { path, .. } => vec![path.clone()],
            _ => Vec::new(),
        }
    }

    /// Whether this is an agent's account of its own work.
    #[must_use]
    pub const fn is_self_assessment(&self) -> bool {
        matches!(self, Self::SelfAssessment { .. })
    }
}

impl Source {
    /// The source as a JSON value for the audit record.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        match self {
            Self::Issue { number } => json!({"kind": "issue", "number": number}),
            Self::IssueComment { issue, comment } => {
                json!({"kind": "issue_comment", "issue": issue, "comment": comment})
            }
            Self::PullRequest { number } => json!({"kind": "pull_request", "number": number}),
            Self::RepoFile {
                path,
                commit,
                lines,
            } => json!({
                "kind": "repo_file",
                "path": path,
                "commit": commit.as_ref().map(ToString::to_string),
                "lines": lines.map(|r| [r.start, r.end]),
            }),
            Self::CommitMessage { commit } => {
                json!({"kind": "commit_message", "commit": commit.to_string()})
            }
            Self::ToolOutput { producer } => json!({"kind": "tool_output", "producer": producer}),
            Self::WebPage { url } => json!({"kind": "web_page", "url": url}),
            Self::HostArtifact { kind, id } => {
                json!({"kind": "host_artifact", "artifact_kind": kind, "id": id})
            }
            Self::HumanAnswer { principal } => {
                json!({"kind": "human_answer", "principal": principal})
            }
            Self::SelfAssessment { agent } => json!({"kind": "self_assessment", "agent": agent}),
        }
    }
}

impl std::fmt::Display for Source {
    /// A short form for the audit record. Text a person or a program chose is written with its
    /// special characters escaped, so a line of a log stays one line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Issue { number } => write!(f, "issue#{number}"),
            Self::IssueComment { issue, comment } => write!(f, "issue#{issue}/comment#{comment}"),
            Self::PullRequest { number } => write!(f, "pr#{number}"),
            Self::RepoFile {
                path,
                commit,
                lines,
            } => {
                write!(f, "file:{}", path.escape_debug())?;
                if let Some(commit) = commit {
                    write!(f, "@{commit}")?;
                }
                if let Some(range) = lines {
                    write!(f, "#L{}-{}", range.start, range.end)?;
                }
                Ok(())
            }
            Self::CommitMessage { commit } => write!(f, "commit:{commit}"),
            Self::ToolOutput { producer } => write!(f, "output:{}", producer.escape_debug()),
            Self::WebPage { url } => write!(f, "web:{}", url.escape_debug()),
            Self::HostArtifact { kind, id } => {
                write!(f, "artifact:{}:{}", kind.escape_debug(), id.escape_debug())
            }
            Self::HumanAnswer { principal } => write!(f, "answer:{}", principal.escape_debug()),
            Self::SelfAssessment { agent } => write!(f, "self-assessment:{}", agent.escape_debug()),
        }
    }
}

/// One input of a prompt.
///
/// `Debug` shows the name, the class, the trust, the source and the size, and never the text, so
/// a log line that prints an input cannot copy untrusted text or a secret into a log.
#[derive(Clone, PartialEq, Eq)]
pub struct Input {
    pub(super) name: String,
    pub(super) class: super::class::ContentClass,
    pub(super) trust: Trust,
    pub(super) source: Source,
    pub(super) tenant: TenantId,
    pub(super) bytes: Vec<u8>,
    pub(super) paths: Vec<String>,
    pub(super) fetched_at: Option<Timestamp>,
}

impl std::fmt::Debug for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Input")
            .field("name", &self.name)
            .field("class", &self.class)
            .field("trust", &self.trust)
            .field("source", &self.source.to_string())
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// The longest trusted value, in bytes.
const TRUSTED_MAX: usize = 256;

pub(super) fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= TRUSTED_MAX
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'@' | b'+' | b'-')
        })
}

impl Input {
    /// Text from outside the factory. `bytes` is the text as it was read; the assembler refuses
    /// it if it is not UTF-8.
    #[must_use]
    pub fn untrusted(
        name: &str,
        class: super::class::ContentClass,
        source: Source,
        tenant: TenantId,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        let paths = source.paths();
        Self {
            name: name.to_owned(),
            class,
            trust: Trust::Untrusted,
            source,
            tenant,
            bytes: bytes.into(),
            paths,
            fetched_at: None,
        }
    }

    /// What an agent said about its own work. It is untrusted text with a source that marks it,
    /// so that no independent reviewer receives it.
    #[must_use]
    pub fn self_assessment(
        name: &str,
        class: super::class::ContentClass,
        agent: &str,
        tenant: TenantId,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self::untrusted(
            name,
            class,
            Source::SelfAssessment {
                agent: agent.to_owned(),
            },
            tenant,
            bytes,
        )
    }

    /// A value the factory made, such as a specification id. It is 1 to 256 characters of
    /// letters, digits and `._:/@+-`, and nothing else, so it cannot hold a delimiter, a space,
    /// a line break or markup.
    ///
    /// # Errors
    /// [`AssemblyError::TrustedValueRefused`] for any other value.
    pub fn trusted_identifier(
        name: &str,
        class: super::class::ContentClass,
        source: Source,
        tenant: TenantId,
        value: &str,
    ) -> Result<Self, AssemblyError> {
        if !is_identifier(value) {
            return Err(AssemblyError::TrustedValueRefused);
        }
        let mut input = Self::untrusted(name, class, source, tenant, value.as_bytes());
        input.trust = Trust::Trusted;
        Ok(input)
    }

    /// Adds the repository paths that this text is made of, such as the files a diff touches. The
    /// path policy is asked about each of them, and an input that holds a hidden file is left out
    /// whole.
    #[must_use]
    pub fn touching<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.paths.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Records when the text was fetched, as the `Clock` port gave it. The time goes to the
    /// context manifest and never into the prompt, so the same text always gives the same prompt.
    #[must_use]
    pub fn fetched_at(mut self, at: Timestamp) -> Self {
        self.fetched_at = Some(at);
        self
    }

    /// The name of the input.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where the text came from.
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }

    /// Whether the factory made the value.
    #[must_use]
    pub const fn trust(&self) -> Trust {
        self.trust
    }

    /// Turns the input into one an independent reviewer may take.
    ///
    /// # Errors
    /// [`AssemblyError::SelfAssessmentRefused`] for an agent's account of its own work.
    pub fn into_independent(self) -> Result<IndependentInput, AssemblyError> {
        if self.source.is_self_assessment() {
            return Err(AssemblyError::SelfAssessmentRefused);
        }
        Ok(IndependentInput(self))
    }
}

/// An input that is not an agent's account of its own work.
///
/// Reviewers must judge a change by the specification, the diff and the gate reports, never by
/// what the builder or the writer says about it (`never_in_model_context:
/// builder_self_justification_for_reviewers`). The only way to assemble a prompt for a reviewer
/// is [`Assembler::assemble_independent`](super::Assembler::assemble_independent), and it takes
/// this type. The only way to make one is [`Input::into_independent`], which refuses a
/// [`Source::SelfAssessment`]. So a builder summary cannot be passed to a reviewer prompt
/// without the code saying, in the type of its source, that it is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndependentInput(pub(super) Input);
