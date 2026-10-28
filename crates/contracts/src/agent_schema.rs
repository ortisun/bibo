//! Checks the output of one agent against ITS OWN schema, the file in `agents/schemas/` that the
//! agent's manifest names.
//!
//! [`crate::validator::SchemaOutputValidator`] knows the eleven closed contract kinds. An agent
//! such as `intake-classifier` returns a document with a schema of its own
//! (`intake-classification.v1.schema.json`), which is not a contract kind, so a stage that ran
//! an agent had no way to validate what it got back. This module adds that, and changes nothing
//! about the existing validator.
//!
//! # The three pieces
//!
//! * [`AgentSchema`] is one compiled schema with the limits it enforces. It is built from text or
//!   bytes ([`AgentSchema::from_text`], [`AgentSchema::from_bytes`]) and checks raw output bytes
//!   with [`AgentSchema::parse_and_validate`] (the entry point for untrusted output) or
//!   [`AgentSchema::validate_bytes`] (the same, shaped like the `OutputValidator` port: it also
//!   returns the SHA-256 and the size of the exact bytes it checked).
//! * [`AgentSchemaLoader`] finds the schemas a manifest names ([`AgentSchemaLoader::load`]) and
//!   returns them compiled, as [`AgentSchemas`] (inputs and outputs).
//! * [`SchemaFileError`] is the closed error of loading.
//!
//! # What is the same as for the contract kinds
//!
//! The steps, the limits, the strict parse and the messages are the ones in
//! [`crate::validator`], because the code is shared. For output bytes the order is fixed: size,
//! UTF-8, nesting depth, strict parse (a repeated key and trailing data are refused), the schema,
//! then the path-safety rule for path-named properties. A step that fails ends the call. The
//! limits default to [`OutputLimits::AGENT_OUTPUT`] and cannot exceed [`OutputLimits::CEILING`].
//! A message says what rule was broken and what to change, and never repeats a value from the
//! document.
//!
//! # What is different, and why
//!
//! A schema is loaded at start-up and must be refused THEN if it cannot be trusted, not when the
//! first agent output meets it:
//!
//! * The schema text goes through the same strict parse, so a schema that repeats a key (a
//!   last-wins reader would silently drop an `additionalProperties: false`) is refused.
//! * The schema is compiled by the closed engine of [`crate::schema_engine`], which refuses any
//!   keyword it does not implement, any `$ref` that is not a local definition and any pattern the
//!   regex crate cannot compile. An ignored keyword would make a schema accept what it was
//!   written to refuse. That is [`SchemaFileErrorKind::Unsupported`] and its neighbours, raised
//!   by [`AgentSchema::from_text`], never by validation.
//! * The loader reads only `agents/schemas/<name>.v<version>.schema.json` below the repository
//!   root. The name must be a slug and the version a positive number, so no reference can name a
//!   path. The resolved file must still lie inside the root once links are resolved, the file
//!   itself must not be a link, its hash must equal the hash the manifest pins, and the `$id`
//!   inside must name the same schema as the file does. A schema that was changed after the
//!   manifest was written is refused, exactly as a prompt is.
//!
//! # Not covered
//!
//! The `planner-result` envelope holds a `plan` that follows the factory's `task-dag` contract.
//! This module checks the envelope. The planning stage validates `plan` with
//! [`crate::validator::SchemaOutputValidator`] (`ContractKind::TaskDag`).

use std::path::PathBuf;

use factory_domain::contracts::{AgentManifest, SchemaRef, Violation};
use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::paths::RepoPath;
use factory_ports::registry::ValidatedOutput;
use serde_json::Value;

use crate::loader::{
    LoadErrorKind, MAX_DEFINITION_BYTES, ResolveFailure, read_bounded, resolve_inside,
};
use crate::schema_engine::{Schema, SchemaLoadError};
use crate::validator::{
    Issue, IssueKind, OutputLimits, check_document, measure, parse_strict, prescan,
};

/// The directory below the repository root that holds the agent schemas.
pub const AGENT_SCHEMA_DIR: &str = "agents/schemas";

/// The most nesting a schema file may have. Real schemas nest about a dozen levels.
const SCHEMA_MAX_DEPTH: usize = 48;

/// The most values a schema file may hold.
const SCHEMA_MAX_NODES: usize = 100_000;

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
    /// The schema text is not JSON, or nests too deep, or holds too many values.
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

/// Why a schema could not be loaded: which file, what kind of problem and what to change.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{file}: {message}")]
pub struct SchemaFileError {
    /// The file, relative to the repository root, or `schema text` for text given directly. It
    /// never holds the location of the checkout on the host.
    pub file: String,
    /// What kind of problem.
    pub kind: SchemaFileErrorKind,
    /// Plain English: what is wrong and what to change.
    pub message: String,
}

impl SchemaFileError {
    fn new(file: &str, kind: SchemaFileErrorKind, message: impl Into<String>) -> Self {
        Self {
            file: file.to_owned(),
            kind,
            message: message.into(),
        }
    }
}

/// The label used when a schema comes from text and not from a file.
const TEXT_LABEL: &str = "schema text";

/// One compiled agent schema with the limits it enforces.
#[derive(Debug)]
pub struct AgentSchema {
    schema: Schema,
    limits: OutputLimits,
    sha256: Sha256Digest,
    id: Option<String>,
}

impl AgentSchema {
    /// Compiles a schema from JSON text. `limits` apply to the documents it later checks.
    ///
    /// # Errors
    /// [`SchemaFileError`] when the text is over the size limit, nests too deep, is not JSON,
    /// repeats a key, or uses a keyword, reference or pattern the engine does not support.
    pub fn from_text(text: &str, limits: OutputLimits) -> Result<Self, SchemaFileError> {
        Self::from_bytes(text.as_bytes(), limits)
    }

    /// Compiles a schema from bytes, with the same checks as [`AgentSchema::from_text`] and one
    /// more: the bytes must be UTF-8. The hash of the bytes is kept ([`AgentSchema::sha256`]).
    ///
    /// # Errors
    /// [`SchemaFileError`], as for [`AgentSchema::from_text`].
    pub fn from_bytes(bytes: &[u8], limits: OutputLimits) -> Result<Self, SchemaFileError> {
        Self::compile(TEXT_LABEL, bytes, limits)
    }

    fn compile(label: &str, bytes: &[u8], limits: OutputLimits) -> Result<Self, SchemaFileError> {
        let schema_limits =
            OutputLimits::new(MAX_DEFINITION_BYTES, SCHEMA_MAX_DEPTH, SCHEMA_MAX_NODES).map_err(
                |e| SchemaFileError::new(label, SchemaFileErrorKind::TooLarge, e.to_string()),
            )?;
        let text = prescan(bytes, schema_limits).map_err(|issue| from_issue(label, &issue))?;
        let value = parse_strict(text, schema_limits).map_err(|issue| from_issue(label, &issue))?;
        let id = value.get("$id").and_then(Value::as_str).map(str::to_owned);
        let schema = Schema::compile(value).map_err(|error| from_load_error(label, error))?;
        Ok(Self {
            schema,
            limits,
            sha256: Sha256Digest::of(bytes),
            id,
        })
    }

    /// The SHA-256 of the schema bytes. For a schema loaded from a manifest it equals the hash
    /// the manifest pins.
    #[must_use]
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    /// The `$id` the schema declares, when it has one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> OutputLimits {
        self.limits
    }

    /// Parses and checks the bytes of an untrusted document and returns the parsed value, so the
    /// caller does not parse twice.
    ///
    /// The order is fixed: size, UTF-8, nesting depth, strict parse, schema, path safety. A step
    /// that fails ends the call, so a 10 MB body is rejected for its size without being read and a
    /// body nested 10,000 deep is rejected for its depth without being parsed.
    ///
    /// # Errors
    /// The list of issues. A limit or syntax problem is a list of one.
    pub fn parse_and_validate(&self, bytes: &[u8]) -> Result<Value, Vec<Issue>> {
        let text = prescan(bytes, self.limits).map_err(|issue| vec![issue])?;
        let value = parse_strict(text, self.limits).map_err(|issue| vec![issue])?;
        check_document(Some(&self.schema), &value)?;
        Ok(value)
    }

    /// The same check, shaped like `OutputValidator::validate_bytes`: on success the value, the
    /// SHA-256 and the size of the exact bytes that were checked, so the artifact that stores
    /// them has that hash. On failure the violations, each with a path and a plain-English
    /// message.
    ///
    /// # Errors
    /// A non-empty list of [`Violation`]s.
    pub fn validate_bytes(&self, bytes: &[u8]) -> Result<ValidatedOutput, Vec<Violation>> {
        let value = self
            .parse_and_validate(bytes)
            .map_err(|issues| issues.iter().map(Issue::to_violation).collect::<Vec<_>>())?;
        Ok(ValidatedOutput {
            value,
            sha256: Sha256Digest::of(bytes),
            size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        })
    }

    /// Checks a value that was parsed already, with the same limits. It cannot see a repeated key,
    /// because the value no longer has one, so [`AgentSchema::parse_and_validate`] is the entry
    /// point for raw output. This is for values the factory built itself, such as the inputs it
    /// is about to hand to an agent.
    ///
    /// # Errors
    /// The list of issues.
    pub fn check(&self, instance: &Value) -> Result<(), Vec<Issue>> {
        measure(instance, self.limits).map_err(|issue| vec![issue])?;
        check_document(Some(&self.schema), instance)
    }
}

/// The compiled input and output schemas of one agent.
#[derive(Debug)]
pub struct AgentSchemas {
    /// What the agent receives. Checked with the loader's input limits.
    pub inputs: AgentSchema,
    /// What the agent returns. Checked with the loader's output limits.
    pub outputs: AgentSchema,
}

/// Loads the schemas an agent manifest names.
///
/// The references are by name and version, and the loader maps them to
/// `agents/schemas/<name>.v<version>.schema.json` below the repository root. See the module notes
/// for the checks.
#[derive(Debug, Clone)]
pub struct AgentSchemaLoader {
    root: PathBuf,
    output_limits: OutputLimits,
    input_limits: OutputLimits,
}

impl AgentSchemaLoader {
    /// A loader for the repository at `root`. Outputs are checked with
    /// [`OutputLimits::AGENT_OUTPUT`]. Inputs are built by the factory and may be larger than an
    /// output (a request can be a megabyte), so they use [`OutputLimits::CEILING`].
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            output_limits: OutputLimits::AGENT_OUTPUT,
            input_limits: OutputLimits::CEILING,
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
    /// The first [`SchemaFileError`].
    pub fn load(&self, manifest: &AgentManifest) -> Result<AgentSchemas, SchemaFileError> {
        Ok(AgentSchemas {
            inputs: self.load_with(&manifest.inputs_schema, self.input_limits)?,
            outputs: self.load_with(&manifest.outputs_schema, self.output_limits)?,
        })
    }

    /// Loads one schema by its reference, checking the hash the reference pins. The limits are the
    /// loader's output limits.
    ///
    /// # Errors
    /// [`SchemaFileError`].
    pub fn load_ref(&self, reference: &SchemaRef) -> Result<AgentSchema, SchemaFileError> {
        self.load_with(reference, self.output_limits)
    }

    fn load_with(
        &self,
        reference: &SchemaRef,
        limits: OutputLimits,
    ) -> Result<AgentSchema, SchemaFileError> {
        let version = u32::try_from(reference.version.get()).map_err(|_| {
            SchemaFileError::new(
                AGENT_SCHEMA_DIR,
                SchemaFileErrorKind::UnsafePath,
                "the schema version is not a number this build can name",
            )
        })?;
        self.load_checked(
            reference.name.as_str(),
            version,
            Some(&reference.sha256),
            limits,
        )
    }

    /// Loads one schema by name and version. When `expected` is given, the hash of the file must
    /// equal it. The limits are the loader's output limits.
    ///
    /// # Errors
    /// [`SchemaFileError`]: [`SchemaFileErrorKind::UnsafePath`] for a name that is not a slug or a
    /// version of zero, [`SchemaFileErrorKind::Missing`], [`SchemaFileErrorKind::HashMismatch`]
    /// and the compile errors of [`AgentSchema::from_bytes`].
    pub fn load_named(
        &self,
        name: &str,
        version: u32,
        expected: Option<&Sha256Digest>,
    ) -> Result<AgentSchema, SchemaFileError> {
        self.load_checked(name, version, expected, self.output_limits)
    }

    fn load_checked(
        &self,
        name: &str,
        version: u32,
        expected: Option<&Sha256Digest>,
        limits: OutputLimits,
    ) -> Result<AgentSchema, SchemaFileError> {
        // 1. The reference names a file by two parts. A slug has no separator, no dot-dot and no
        //    control character, so the file name cannot leave the directory.
        if Slug::parse(name).is_err() || version == 0 {
            return Err(SchemaFileError::new(
                AGENT_SCHEMA_DIR,
                SchemaFileErrorKind::UnsafePath,
                "a schema name must be a slug (lowercase letters, digits, dots, underscores and hyphens) and its version a positive number, so that it names a file inside agents/schemas",
            ));
        }
        let relative = format!("{AGENT_SCHEMA_DIR}/{name}.v{version}.schema.json");
        // 2. The same path rule that every repository path in the factory passes.
        RepoPath::new(&relative).map_err(|e| {
            SchemaFileError::new(
                &relative,
                SchemaFileErrorKind::UnsafePath,
                format!("the schema path is not allowed: {e}"),
            )
        })?;
        // 3. After links are resolved the file must still be inside the root.
        resolve_inside(&self.root, &relative).map_err(|failure| match failure {
            ResolveFailure::Missing => SchemaFileError::new(
                &relative,
                SchemaFileErrorKind::Missing,
                "the schema file does not exist under the repository root",
            ),
            ResolveFailure::Outside => SchemaFileError::new(
                &relative,
                SchemaFileErrorKind::UnsafePath,
                "the schema file resolves outside the repository root; keep the schema inside the repository",
            ),
            ResolveFailure::Unreadable => SchemaFileError::new(
                &relative,
                SchemaFileErrorKind::Unreadable,
                "the schema file cannot be read",
            ),
        })?;
        // 4. A pinned file is a plain file: a link is refused, and so is a file over the limit.
        let candidate = self.root.join(&relative);
        let bytes = read_bounded(&candidate, &relative).map_err(|e| {
            let kind = if e.kind == LoadErrorKind::Limits {
                SchemaFileErrorKind::TooLarge
            } else {
                SchemaFileErrorKind::Unreadable
            };
            SchemaFileError::new(&relative, kind, e.message)
        })?;
        // 5. The file is the one the manifest pinned.
        if let Some(expected) = expected {
            let actual = Sha256Digest::of(&bytes);
            if &actual != expected {
                return Err(SchemaFileError::new(
                    &relative,
                    SchemaFileErrorKind::HashMismatch,
                    format!(
                        "the hash of the schema file is {actual} but the manifest says {expected}; the schema changed after the manifest was written, so update the manifest in a reviewed change"
                    ),
                ));
            }
        }
        // 6. It compiles, and says it is the schema asked for.
        let compiled = AgentSchema::compile(&relative, &bytes, limits)?;
        let wanted = format!("urn:ortisun:factory:schema:agent:{name}:{version}");
        if compiled.id() != Some(wanted.as_str()) {
            return Err(SchemaFileError::new(
                &relative,
                SchemaFileErrorKind::IdMismatch,
                format!(
                    "the `$id` inside the file must be `{wanted}`; the file holds another schema or none"
                ),
            ));
        }
        Ok(compiled)
    }
}

fn from_issue(label: &str, issue: &Issue) -> SchemaFileError {
    let kind = match issue.kind {
        IssueKind::TooLarge => SchemaFileErrorKind::TooLarge,
        IssueKind::NotUtf8 => SchemaFileErrorKind::NotUtf8,
        IssueKind::DuplicateKey => SchemaFileErrorKind::DuplicateKey,
        _ => SchemaFileErrorKind::Syntax,
    };
    SchemaFileError::new(label, kind, issue.message.clone())
}

fn from_load_error(label: &str, error: SchemaLoadError) -> SchemaFileError {
    let kind = match &error {
        SchemaLoadError::NotJson(_) => SchemaFileErrorKind::Syntax,
        SchemaLoadError::UnsupportedKeyword { .. } => SchemaFileErrorKind::Unsupported,
        SchemaLoadError::BadReference { .. } => SchemaFileErrorKind::BadReference,
        SchemaLoadError::BadPattern { .. } => SchemaFileErrorKind::BadPattern,
        SchemaLoadError::BadShape { .. } => SchemaFileErrorKind::BadShape,
    };
    SchemaFileError::new(label, kind, error.to_string())
}
