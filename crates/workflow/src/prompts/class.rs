//! The classes of untrusted content.

/// What kind of text an input is. The set is `untrusted_content.classes` of
/// `policies/security.yaml`, in the same order; a test compares the two.
///
/// The class tells the model where the text came from. It never gives the text authority
/// (`untrusted_content.authority_from_content: never`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContentClass {
    /// The title and body of an issue.
    IssueText,
    /// A comment on an issue.
    IssueComment,
    /// The title and body of a pull request.
    PrText,
    /// A file of the repository.
    RepoFile,
    /// A commit message.
    CommitMessage,
    /// Output of a command or a gate.
    ToolOutput,
    /// A fetched web page.
    WebContent,
    /// Text that ships with a dependency.
    DependencyText,
    /// Text a model wrote, or a patch a model produced.
    ModelOutput,
    /// The text of a specification.
    SpecificationText,
    /// Text retrieved from memory.
    RetrievedMemory,
}

impl ContentClass {
    /// Every class, in the order of the policy.
    pub const ALL: [ContentClass; 11] = [
        ContentClass::IssueText,
        ContentClass::IssueComment,
        ContentClass::PrText,
        ContentClass::RepoFile,
        ContentClass::CommitMessage,
        ContentClass::ToolOutput,
        ContentClass::WebContent,
        ContentClass::DependencyText,
        ContentClass::ModelOutput,
        ContentClass::SpecificationText,
        ContentClass::RetrievedMemory,
    ];

    /// The name used in the policy and in the opening line of a block.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IssueText => "issue_text",
            Self::IssueComment => "issue_comment",
            Self::PrText => "pr_text",
            Self::RepoFile => "repo_file",
            Self::CommitMessage => "commit_message",
            Self::ToolOutput => "tool_output",
            Self::WebContent => "web_content",
            Self::DependencyText => "dependency_text",
            Self::ModelOutput => "model_output",
            Self::SpecificationText => "specification_text",
            Self::RetrievedMemory => "retrieved_memory",
        }
    }

    /// The class with this name, or `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == name)
    }
}
