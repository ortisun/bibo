//! Loads agent manifests, domain capability profiles and project manifests into typed values.
//!
//! One path serves all three. The text is read within a size limit, parsed (JSON strictly, YAML
//! through the restricted reader), checked against its schema, decoded into the typed contract
//! from `factory-domain`, and then checked for the rules a schema cannot state (see
//! `schemas/README.md`, "What a schema cannot check"). The first failure ends the load, and the
//! error names the file, the field and, for YAML, the line.
//!
//! The functions that take bytes read nothing from the file system, so the intake stage can hand
//! them the bytes of `.factory/project.yaml` that the workspace ingestion module read from the
//! protected base commit. The functions that take a path read exactly that file and refuse a
//! symbolic link.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use factory_domain::contracts::{
    AgentManifest, Contract, DomainCapabilityProfile, ProjectManifest,
};
use factory_domain::values::Sha256Digest;
use factory_ports::paths::RepoPath;
use factory_ports::registry::{ContractKind, LoadedPrompt};

use crate::schema_engine::SchemaLoadError;
use crate::schemas::SCHEMA_VERSION;
use crate::validator::{Issue, IssueKind, SchemaOutputValidator};
use crate::yaml::{self, Document, YamlError, YamlErrorKind, YamlLimits};

/// The largest definition file or prompt file that is read: 256 KiB.
pub const MAX_DEFINITION_BYTES: usize = 256 * 1024;

/// What kind of problem a load found. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadErrorKind {
    /// The file could not be read, or is a symbolic link.
    Unreadable,
    /// The file is over the size limit, or the document is over a nesting or size limit.
    Limits,
    /// The file is not UTF-8.
    NotUtf8,
    /// The extension is not `.json`, `.yaml` or `.yml`.
    UnsupportedFormat,
    /// The text is not valid JSON or YAML.
    Syntax,
    /// The document uses something the parser contract forbids: an anchor, an alias, a tag, a
    /// merge key, a duplicate key, a null or an ambiguous scalar.
    Forbidden,
    /// The document breaks a schema rule.
    Schema,
    /// The document does not fit the typed contract.
    Type,
    /// A path field would leave the repository.
    UnsafePath,
    /// The prompt file the manifest names does not exist.
    PromptMissing,
    /// The hash in the manifest differs from the hash of the prompt file.
    PromptHashMismatch,
    /// A rule the schema cannot state is broken, such as a profile whose probes and required
    /// tools differ.
    Consistency,
    /// Two definitions have the same identity.
    Duplicate,
    /// A directory the registry needs is missing.
    DirectoryMissing,
    /// A directory holds more files than the registry reads.
    TooManyFiles,
}

/// Why a definition could not be loaded: which file, which field and which line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    /// The file, as the caller named it (a path, or a label for bytes).
    pub file: String,
    /// The line, counting from 1, for YAML.
    pub line: Option<usize>,
    /// The field, written like `prompt.template_sha256` or `tools[2].name`.
    pub field: Option<String>,
    /// What kind of problem.
    pub kind: LoadErrorKind,
    /// Plain English: what is wrong and what to change.
    pub message: String,
    /// Further problems in the same file, when the load found several.
    pub others: Vec<String>,
}

impl LoadError {
    pub(crate) fn new(file: &str, kind: LoadErrorKind, message: impl Into<String>) -> Self {
        Self {
            file: file.to_owned(),
            line: None,
            field: None,
            kind,
            message: message.into(),
            others: Vec::new(),
        }
    }

    pub(crate) fn at_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    pub(crate) fn at_line(mut self, line: Option<usize>) -> Self {
        self.line = line;
        self
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.file)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        if let Some(field) = &self.field {
            write!(f, " (field `{field}`)")?;
        }
        write!(f, ": {}", self.message)?;
        if !self.others.is_empty() {
            write!(
                f,
                " ({} more: {})",
                self.others.len(),
                self.others.join("; ")
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for LoadError {}

/// How a definition is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinitionFormat {
    /// JSON.
    Json,
    /// The restricted YAML subset.
    Yaml,
}

impl DefinitionFormat {
    /// The format an extension means, or `None`.
    #[must_use]
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Some(Self::Json),
            Some("yaml" | "yml") => Some(Self::Yaml),
            _ => None,
        }
    }
}

/// An agent manifest with the prompt it names, whose hash was checked.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedAgent {
    /// The manifest.
    pub manifest: AgentManifest,
    /// The prompt text and its reference.
    pub prompt: LoadedPrompt,
    /// The manifest file, as named by the caller.
    pub file: String,
}

/// Loads definitions. Holds the compiled schemas, so build one and reuse it.
#[derive(Debug)]
pub struct DefinitionLoader {
    validator: SchemaOutputValidator,
}

impl DefinitionLoader {
    /// Compiles the embedded schemas.
    ///
    /// # Errors
    /// [`SchemaLoadError`] when an embedded schema does not compile.
    pub fn new() -> Result<Self, SchemaLoadError> {
        Ok(Self {
            validator: SchemaOutputValidator::new()?,
        })
    }

    /// Loads an agent manifest from bytes. `file` is the name shown in errors.
    ///
    /// # Errors
    /// A [`LoadError`] naming the file, the field and the line.
    pub fn agent_manifest(
        &self,
        file: &str,
        format: DefinitionFormat,
        bytes: &[u8],
    ) -> Result<AgentManifest, LoadError> {
        self.load(ContractKind::AgentManifest, file, format, bytes)
    }

    /// Loads a domain capability profile from bytes, and checks that its probes and its required
    /// tools name the same tools.
    ///
    /// # Errors
    /// A [`LoadError`] naming the file, the field and the line.
    pub fn capability_profile(
        &self,
        file: &str,
        format: DefinitionFormat,
        bytes: &[u8],
    ) -> Result<DomainCapabilityProfile, LoadError> {
        let (profile, located): (DomainCapabilityProfile, Located) =
            self.load_located(ContractKind::DomainCapabilityProfile, file, format, bytes)?;
        if let Some(probes) = &profile.tool_probes {
            let required: BTreeSet<&str> =
                profile.required_tools.iter().map(|t| t.as_str()).collect();
            let probed: BTreeSet<&str> = probes.iter().map(|p| p.tool.as_str()).collect();
            if required != probed {
                let missing: Vec<&str> = required.difference(&probed).copied().collect();
                let extra: Vec<&str> = probed.difference(&required).copied().collect();
                let mut parts = Vec::new();
                if !missing.is_empty() {
                    parts.push(format!(
                        "these required tools have no probe: {}",
                        missing.join(", ")
                    ));
                }
                if !extra.is_empty() {
                    parts.push(format!(
                        "these probes name tools that are not in required_tools: {}",
                        extra.join(", ")
                    ));
                }
                return Err(LoadError::new(
                    file,
                    LoadErrorKind::Consistency,
                    format!(
                        "required_tools and tool_probes must list the same tools; {}",
                        parts.join("; ")
                    ),
                )
                .at_field("tool_probes")
                .at_line(located.line_of("tool_probes")));
            }
        }
        Ok(profile)
    }

    /// Loads a project manifest from bytes.
    ///
    /// # Errors
    /// A [`LoadError`] naming the file, the field and the line.
    pub fn project_manifest(
        &self,
        file: &str,
        format: DefinitionFormat,
        bytes: &[u8],
    ) -> Result<ProjectManifest, LoadError> {
        self.load(ContractKind::ProjectManifest, file, format, bytes)
    }

    /// Loads an agent manifest file and the prompt it names, and checks the prompt's hash.
    ///
    /// `root` is the repository root: `prompt.template_path` is relative to it. The prompt must
    /// lie inside `root` after symbolic links are resolved.
    ///
    /// # Errors
    /// A [`LoadError`] naming the file and the field: `prompt.template_path` when the prompt is
    /// missing or outside the root, `prompt.template_sha256` when the hash differs.
    pub fn agent_with_prompt(
        &self,
        root: &Path,
        manifest_path: &Path,
    ) -> Result<LoadedAgent, LoadError> {
        let file = manifest_path.display().to_string();
        let format = DefinitionFormat::from_path(manifest_path).ok_or_else(|| {
            LoadError::new(
                &file,
                LoadErrorKind::UnsupportedFormat,
                "use the extension .json, .yaml or .yml",
            )
        })?;
        let bytes = read_bounded(manifest_path, &file)?;
        let (manifest, located): (AgentManifest, Located) =
            self.load_located(ContractKind::AgentManifest, &file, format, &bytes)?;
        let template = &manifest.prompt;
        let prompt_file = template.template_path.as_str();
        let line_of = |field: &str| located.line_of(field);
        let relative = RepoPath::new(prompt_file).map_err(|e| {
            LoadError::new(
                &file,
                LoadErrorKind::UnsafePath,
                format!("the prompt path is not allowed: {e}"),
            )
            .at_field("prompt.template_path")
            .at_line(line_of("prompt.template_path"))
        })?;
        let full = resolve_inside(root, relative.as_str()).map_err(|reason| {
            LoadError::new(
                &file,
                match reason {
                    ResolveFailure::Missing => LoadErrorKind::PromptMissing,
                    ResolveFailure::Outside => LoadErrorKind::UnsafePath,
                    ResolveFailure::Unreadable => LoadErrorKind::Unreadable,
                },
                match reason {
                    ResolveFailure::Missing => {
                        format!("the prompt file `{prompt_file}` does not exist under the registry root")
                    }
                    ResolveFailure::Outside => format!(
                        "the prompt file `{prompt_file}` resolves outside the registry root; use a file inside the repository"
                    ),
                    ResolveFailure::Unreadable => {
                        format!("the prompt file `{prompt_file}` cannot be read")
                    }
                },
            )
            .at_field("prompt.template_path")
            .at_line(line_of("prompt.template_path"))
        })?;
        let prompt_bytes = read_bounded(&full, prompt_file).map_err(|mut e| {
            e.field = Some("prompt.template_path".to_owned());
            e.line = line_of("prompt.template_path");
            e.file.clone_from(&file);
            e.message = format!("the prompt file `{prompt_file}`: {}", e.message);
            e
        })?;
        let actual = Sha256Digest::of(&prompt_bytes);
        if actual != template.template_sha256 {
            return Err(LoadError::new(
                &file,
                LoadErrorKind::PromptHashMismatch,
                format!(
                    "the hash of the prompt file `{prompt_file}` is {actual} but the manifest says {}; the prompt changed after the manifest was written, so update the manifest in a reviewed change",
                    template.template_sha256
                ),
            )
            .at_field("prompt.template_sha256")
            .at_line(line_of("prompt.template_sha256")));
        }
        let text = String::from_utf8(prompt_bytes).map_err(|_| {
            LoadError::new(
                &file,
                LoadErrorKind::NotUtf8,
                format!("the prompt file `{prompt_file}` is not UTF-8"),
            )
            .at_field("prompt.template_path")
            .at_line(line_of("prompt.template_path"))
        })?;
        Ok(LoadedAgent {
            prompt: LoadedPrompt {
                template: manifest.prompt.clone(),
                text,
            },
            manifest,
            file,
        })
    }

    // ---- shared path --------------------------------------------------------------------------

    fn load<T: Contract>(
        &self,
        kind: ContractKind,
        file: &str,
        format: DefinitionFormat,
        bytes: &[u8],
    ) -> Result<T, LoadError> {
        self.load_located(kind, file, format, bytes)
            .map(|(value, _)| value)
    }

    fn load_located<T: Contract>(
        &self,
        kind: ContractKind,
        file: &str,
        format: DefinitionFormat,
        bytes: &[u8],
    ) -> Result<(T, Located), LoadError> {
        if bytes.len() > MAX_DEFINITION_BYTES {
            return Err(LoadError::new(
                file,
                LoadErrorKind::Limits,
                format!(
                    "the file is {} bytes; the limit is {MAX_DEFINITION_BYTES} bytes",
                    bytes.len()
                ),
            ));
        }
        match format {
            DefinitionFormat::Json => {
                let value = self
                    .validator
                    .parse_and_validate(kind, SCHEMA_VERSION, bytes)
                    .map_err(|issues| from_issues(file, &issues, &Located::None))?;
                let typed = T::from_json_value(value)
                    .map_err(|e| LoadError::new(file, LoadErrorKind::Type, e.to_string()))?;
                Ok((typed, Located::None))
            }
            DefinitionFormat::Yaml => {
                let text = std::str::from_utf8(bytes).map_err(|e| {
                    LoadError::new(
                        file,
                        LoadErrorKind::NotUtf8,
                        format!(
                            "the file is not valid UTF-8 (first bad byte at offset {})",
                            e.valid_up_to()
                        ),
                    )
                })?;
                let document =
                    yaml::read(text, YamlLimits::DEFINITION).map_err(|e| from_yaml(file, &e))?;
                let json = document.to_json();
                let located = Located::Yaml(Box::new(document));
                self.validator
                    .check(kind, SCHEMA_VERSION, &json)
                    .map_err(|issues| from_issues(file, &issues, &located))?;
                let Located::Yaml(document) = &located else {
                    return Err(LoadError::new(
                        file,
                        LoadErrorKind::Type,
                        "internal: a YAML load lost its document",
                    ));
                };
                let typed: T = document.decode().map_err(|e| from_yaml(file, &e))?;
                Ok((typed, located))
            }
        }
    }
}

/// Where fields sit in the source, when the source was YAML.
enum Located {
    None,
    Yaml(Box<Document>),
}

impl Located {
    fn line_of(&self, field: &str) -> Option<usize> {
        match self {
            Self::None => None,
            Self::Yaml(document) => document.locate(field).map(|(line, _)| line),
        }
    }
}

fn from_yaml(file: &str, error: &YamlError) -> LoadError {
    let kind = match error.kind {
        YamlErrorKind::Syntax => LoadErrorKind::Syntax,
        YamlErrorKind::TooLarge
        | YamlErrorKind::TooDeep
        | YamlErrorKind::TooManyNodes
        | YamlErrorKind::ScalarTooLong => LoadErrorKind::Limits,
        YamlErrorKind::Decode => LoadErrorKind::Type,
        _ => LoadErrorKind::Forbidden,
    };
    let mut load = LoadError::new(file, kind, error.detail()).at_line(error.line);
    if let Some(key) = &error.key {
        load = load.at_field(key.clone());
    }
    load
}

fn from_issues(file: &str, issues: &[Issue], located: &Located) -> LoadError {
    let first = &issues[0];
    let kind = match first.kind {
        IssueKind::Schema(_) | IssueKind::UnknownVersion | IssueKind::MoreProblems => {
            LoadErrorKind::Schema
        }
        IssueKind::TooLarge | IssueKind::TooDeep | IssueKind::TooManyNodes => LoadErrorKind::Limits,
        IssueKind::NotUtf8 => LoadErrorKind::NotUtf8,
        IssueKind::NotJson => LoadErrorKind::Syntax,
        IssueKind::DuplicateKey => LoadErrorKind::Forbidden,
        IssueKind::UnsafePath => LoadErrorKind::UnsafePath,
    };
    let field = (first.path != "$").then(|| first.path.clone());
    let mut load = LoadError::new(file, kind, first.message.clone());
    if let Some(field) = field {
        load.line = located.line_of(&field);
        load.field = Some(field);
    } else {
        load.line = located.line_of("$");
    }
    load.others = issues
        .iter()
        .skip(1)
        .take(5)
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect();
    load
}

// ------------------------------------------------------------------------------------------
// Reading files
// ------------------------------------------------------------------------------------------

pub(crate) enum ResolveFailure {
    Missing,
    Outside,
    Unreadable,
}

/// Joins `relative` to `root`, resolves symbolic links, and requires the result to lie inside the
/// resolved root.
pub(crate) fn resolve_inside(root: &Path, relative: &str) -> Result<PathBuf, ResolveFailure> {
    let root = fs::canonicalize(root).map_err(|_| ResolveFailure::Unreadable)?;
    let candidate = root.join(relative);
    let resolved = match fs::canonicalize(&candidate) {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ResolveFailure::Missing),
        Err(_) => return Err(ResolveFailure::Unreadable),
    };
    if resolved.starts_with(&root) {
        Ok(resolved)
    } else {
        Err(ResolveFailure::Outside)
    }
}

/// Reads a file of at most [`MAX_DEFINITION_BYTES`]. A symbolic link is refused.
pub(crate) fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>, LoadError> {
    let unreadable =
        |reason: &str| LoadError::new(label, LoadErrorKind::Unreadable, reason.to_owned());
    let metadata = fs::symlink_metadata(path).map_err(|_| unreadable("the file cannot be read"))?;
    if metadata.file_type().is_symlink() {
        return Err(unreadable(
            "the file is a symbolic link, which is not followed",
        ));
    }
    if !metadata.is_file() {
        return Err(unreadable("the path is not a regular file"));
    }
    if metadata.len() > MAX_DEFINITION_BYTES as u64 {
        return Err(LoadError::new(
            label,
            LoadErrorKind::Limits,
            format!(
                "the file is {} bytes; the limit is {MAX_DEFINITION_BYTES} bytes",
                metadata.len()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)
        .map_err(|_| unreadable("the file cannot be opened"))?
        .take(MAX_DEFINITION_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable("the file cannot be read"))?;
    if bytes.len() > MAX_DEFINITION_BYTES {
        return Err(LoadError::new(
            label,
            LoadErrorKind::Limits,
            format!("the file is larger than {MAX_DEFINITION_BYTES} bytes"),
        ));
    }
    Ok(bytes)
}
