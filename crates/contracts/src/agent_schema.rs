//! Placeholder: the signatures of the agent output validation, with no behavior yet. The tests in
//! `tests/agent_output_schemas.rs` fail against it; the next commit replaces it.

use std::path::PathBuf;

use factory_domain::contracts::{AgentManifest, SchemaRef, Violation};
use factory_domain::values::Sha256Digest;
use factory_ports::registry::ValidatedOutput;
use serde_json::Value;

use crate::validator::{Issue, OutputLimits};

/// What kind of problem a schema file has. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaFileErrorKind {
    /// The file cannot be read, is a symbolic link, or is not a regular file.
    Unreadable,
    /// No such schema file.
    Missing,
    /// The schema text is over the size limit.
    TooLarge,
    /// The schema text is not UTF-8.
    NotUtf8,
    /// The schema text is not JSON, or nests too deep.
    Syntax,
    /// An object in the schema repeats a key.
    DuplicateKey,
    /// The schema uses a keyword the engine does not implement.
    Unsupported,
    /// A `$ref` that is not a local definition.
    BadReference,
    /// A `pattern` that does not compile.
    BadPattern,
    /// A keyword with a value of the wrong shape.
    BadShape,
    /// The name or version would reach a path outside `agents/schemas`.
    UnsafePath,
    /// The hash of the file differs from the hash the manifest declares.
    HashMismatch,
    /// The `$id` inside the file names another schema than the one asked for.
    IdMismatch,
}

/// Why a schema could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{file}: {message}")]
pub struct SchemaFileError {
    /// The file or label.
    pub file: String,
    /// What kind of problem.
    pub kind: SchemaFileErrorKind,
    /// Plain English.
    pub message: String,
}

fn not_built() -> SchemaFileError {
    SchemaFileError {
        file: String::new(),
        kind: SchemaFileErrorKind::Unreadable,
        message: "not built yet".to_owned(),
    }
}

/// One compiled agent schema with the limits it enforces.
#[derive(Debug)]
pub struct AgentSchema {
    limits: OutputLimits,
    sha256: Sha256Digest,
}

impl AgentSchema {
    /// Compiles a schema from text.
    ///
    /// # Errors
    /// [`SchemaFileError`].
    pub fn from_text(_text: &str, _limits: OutputLimits) -> Result<Self, SchemaFileError> {
        Err(not_built())
    }

    /// Compiles a schema from bytes.
    ///
    /// # Errors
    /// [`SchemaFileError`].
    pub fn from_bytes(_bytes: &[u8], _limits: OutputLimits) -> Result<Self, SchemaFileError> {
        Err(not_built())
    }

    /// The hash of the schema bytes.
    #[must_use]
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> OutputLimits {
        self.limits
    }

    /// Parses and checks raw bytes.
    ///
    /// # Errors
    /// The issues found.
    pub fn parse_and_validate(&self, _bytes: &[u8]) -> Result<Value, Vec<Issue>> {
        Err(Vec::new())
    }

    /// The port-shaped form of [`AgentSchema::parse_and_validate`].
    ///
    /// # Errors
    /// The violations found.
    pub fn validate_bytes(&self, _bytes: &[u8]) -> Result<ValidatedOutput, Vec<Violation>> {
        Err(Vec::new())
    }

    /// Checks a value that was parsed already.
    ///
    /// # Errors
    /// The issues found.
    pub fn check(&self, _instance: &Value) -> Result<(), Vec<Issue>> {
        Err(Vec::new())
    }
}

/// The compiled input and output schemas of one agent.
#[derive(Debug)]
pub struct AgentSchemas {
    /// What the agent receives.
    pub inputs: AgentSchema,
    /// What the agent returns.
    pub outputs: AgentSchema,
}

/// Loads the schemas an agent manifest names.
#[derive(Debug, Clone)]
pub struct AgentSchemaLoader {
    root: PathBuf,
    output_limits: OutputLimits,
}

impl AgentSchemaLoader {
    /// A loader for the repository at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            output_limits: OutputLimits::AGENT_OUTPUT,
        }
    }

    /// Sets the limits that outputs are checked with.
    #[must_use]
    pub fn with_output_limits(mut self, limits: OutputLimits) -> Self {
        self.output_limits = limits;
        self
    }

    /// Loads the input and output schema of a manifest.
    ///
    /// # Errors
    /// [`SchemaFileError`].
    pub fn load(&self, _manifest: &AgentManifest) -> Result<AgentSchemas, SchemaFileError> {
        let _ = (&self.root, self.output_limits);
        Err(not_built())
    }

    /// Loads one schema by its reference.
    ///
    /// # Errors
    /// [`SchemaFileError`].
    pub fn load_ref(&self, _reference: &SchemaRef) -> Result<AgentSchema, SchemaFileError> {
        Err(not_built())
    }

    /// Loads one schema by name and version.
    ///
    /// # Errors
    /// [`SchemaFileError`].
    pub fn load_named(
        &self,
        _name: &str,
        _version: u32,
        _expected: Option<&Sha256Digest>,
    ) -> Result<AgentSchema, SchemaFileError> {
        Err(not_built())
    }
}
