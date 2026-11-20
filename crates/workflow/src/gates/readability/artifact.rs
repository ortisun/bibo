//! What the gate reads: one piece of human-facing text and the kind of artifact it belongs to.
//!
//! The gate only borrows the text. Nothing in this crate gives it a way to change it (the policy
//! says the gate never edits what it checks), so the same borrowed text is what every finding
//! points at.

/// The kinds of artifact the rules name in their `applies_to` list. A specification or an issue
/// that follows no template is a [`Request`](ArtifactKind::Request). An English rendering of a
/// translated request is checked as a request too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArtifactKind {
    /// A title on its own, such as the title of a metadata record.
    Title,
    /// A request, an issue or a specification: a title and a free-form body.
    Request,
    /// A task. The body must also have the four sections of the task template.
    Task,
    /// A pull request: a title and a body that links to its evidence.
    PullRequest,
    /// A documentation page, with a document type.
    Documentation,
}

impl ArtifactKind {
    /// Every kind, in the order of the catalog.
    pub const ALL: [Self; 5] = [
        Self::Title,
        Self::Request,
        Self::Task,
        Self::PullRequest,
        Self::Documentation,
    ];

    /// The spelling in `fixtures/readability/rules.json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Title => "title",
            Self::Request => "request",
            Self::Task => "task",
            Self::PullRequest => "pull_request",
            Self::Documentation => "documentation",
        }
    }

    /// The kind written as `text` in the catalog, or `None` for a kind the gate does not know.
    /// The `translation` and `identity_pair` kinds of the corpus are not kinds of artifact: the
    /// caller checks the rendering as a request and each version as a title.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }
}

/// The type of a documentation page (the four Diataxis forms, plus decision records and the
/// changelog). Only a how-to guide and a tutorial must have the parts of a guide, and a reference
/// page is exempt from the sentence-length rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DocumentType {
    /// A lesson that teaches.
    Tutorial,
    /// Steps for a goal.
    HowTo,
    /// Facts to look up.
    Reference,
    /// Background and reasons.
    Explanation,
    /// An architecture decision record.
    Adr,
    /// A list of changes by release.
    Changelog,
}

impl DocumentType {
    /// The spelling in the corpus (`how-to`, `adr`, ...).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tutorial => "tutorial",
            Self::HowTo => "how-to",
            Self::Reference => "reference",
            Self::Explanation => "explanation",
            Self::Adr => "adr",
            Self::Changelog => "changelog",
        }
    }

    /// The document type written as `text`, or `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Tutorial,
            Self::HowTo,
            Self::Reference,
            Self::Explanation,
            Self::Adr,
            Self::Changelog,
        ]
        .into_iter()
        .find(|doc_type| doc_type.as_str() == text)
    }

    /// True for the two types that must have prerequisites, steps, a result and troubleshooting.
    #[must_use]
    pub const fn is_guide(self) -> bool {
        matches!(self, Self::Tutorial | Self::HowTo)
    }
}

/// One artifact to check: borrowed text and where it came from.
///
/// `path` names the artifact inside the stage output (for example `tasks/12`). It is only used in
/// the location of a finding, so one gate report can cover many artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Artifact<'a> {
    pub(crate) kind: ArtifactKind,
    pub(crate) path: &'a str,
    pub(crate) title: &'a str,
    pub(crate) body: &'a str,
    pub(crate) doc_type: Option<DocumentType>,
}

impl<'a> Artifact<'a> {
    fn new(kind: ArtifactKind, title: &'a str, body: &'a str) -> Self {
        Self {
            kind,
            path: "",
            title,
            body,
            doc_type: None,
        }
    }

    /// A title on its own.
    #[must_use]
    pub fn title(title: &'a str) -> Self {
        Self::new(ArtifactKind::Title, title, "")
    }

    /// A request, an issue or a specification.
    #[must_use]
    pub fn request(title: &'a str, body: &'a str) -> Self {
        Self::new(ArtifactKind::Request, title, body)
    }

    /// A task.
    #[must_use]
    pub fn task(title: &'a str, body: &'a str) -> Self {
        Self::new(ArtifactKind::Task, title, body)
    }

    /// A pull request.
    #[must_use]
    pub fn pull_request(title: &'a str, body: &'a str) -> Self {
        Self::new(ArtifactKind::PullRequest, title, body)
    }

    /// A documentation page of the given type.
    #[must_use]
    pub fn documentation(title: &'a str, doc_type: DocumentType, body: &'a str) -> Self {
        Self {
            doc_type: Some(doc_type),
            ..Self::new(ArtifactKind::Documentation, title, body)
        }
    }

    /// Names the artifact inside the stage output, for the location of a finding.
    #[must_use]
    pub fn at(self, path: &'a str) -> Self {
        Self { path, ..self }
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// The title, exactly as it was handed over.
    #[must_use]
    pub const fn title_text(&self) -> &'a str {
        self.title
    }

    /// The body, exactly as it was handed over.
    #[must_use]
    pub const fn body_text(&self) -> &'a str {
        self.body
    }

    /// The document type, for documentation.
    #[must_use]
    pub const fn doc_type(&self) -> Option<DocumentType> {
        self.doc_type
    }
}
