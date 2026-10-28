//! What the dependency files say, in a form that does not depend on the package manager.
//!
//! A [`DependencyFormat`] reads the three kinds of file that decide what a build fetches: the
//! **lockfile** (what was resolved), the **manifest** (what was asked for) and the **build
//! configuration** (where cargo-like tools look and what they run). The checks in
//! [`integrity`](super::integrity) work on these types only, so another ecosystem is added by
//! writing another format. Only [`CargoFormat`](super::cargo::CargoFormat) exists in this slice;
//! there is no npm, pip or Go reader, and a change in those ecosystems reaches no check here.

use std::collections::{BTreeMap, HashMap};

use factory_domain::policy::dependency::Ecosystem;

use super::toml::TomlError;

/// What kind of dependency file a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    /// The lockfile.
    Lockfile,
    /// A manifest.
    Manifest,
    /// A build configuration file.
    BuildConfig,
}

/// Why a dependency file was not read. The set is closed and holds no text of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// The file is not valid TOML (or whatever the format is written in).
    #[error("the file could not be parsed: {0}")]
    Syntax(TomlError),
    /// The file is valid but follows a layout this reader does not know (an old lockfile
    /// version, a dependency written in a form that is not a table or a string).
    #[error("the file has a layout this reader does not know")]
    Unsupported,
}

impl From<TomlError> for ParseError {
    fn from(error: TomlError) -> Self {
        Self::Syntax(error)
    }
}

/// Where a locked package comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    /// The default public registry (crates.io), the only source the policy allows.
    Registry,
    /// Another registry. The text is its host.
    OtherRegistry(String),
    /// A git repository. The text is its host.
    Git(String),
    /// A path: a workspace member, or a path dependency. The lockfile cannot tell them apart.
    Path,
    /// A source the reader does not know.
    Unknown,
}

impl Origin {
    /// True for the one source the policy allows for a package that is not part of the project.
    #[must_use]
    pub fn is_default_registry(&self) -> bool {
        matches!(self, Self::Registry)
    }

    /// A phrase for a message. It names the kind and the host and never a path or a credential.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Registry => "the default registry".to_owned(),
            Self::OtherRegistry(host) => format!("another registry ({host})"),
            Self::Git(host) => format!("a git repository ({host})"),
            Self::Path => "a path".to_owned(),
            Self::Unknown => "an unknown source".to_owned(),
        }
    }
}

/// A reference from one locked package to another.
///
/// Cargo writes `name`, `name version` or `name version (source)`: a part is added only when the
/// shorter form would name two packages. A package is therefore identified by its name, its
/// version **and its source**, and a reference that leaves a part out names the one package that
/// still matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedRef {
    /// The package name.
    pub name: String,
    /// The version, when the lockfile names one (it does when two versions of a name exist).
    pub version: Option<String>,
    /// The source, when the lockfile names one (it does when two sources have the same name and
    /// version, such as a workspace member and a registry package).
    pub origin: Option<Origin>,
}

/// What a reference resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved<'a> {
    /// Exactly one package matches.
    One(&'a LockedPackage),
    /// More than one package matches. Cargo never writes such a lockfile, so a candidate that has
    /// one is not a lockfile cargo wrote, and a gate must not pick one of the packages.
    Ambiguous,
    /// No package matches.
    Dangling,
}

/// One package of a lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    /// The package name.
    pub name: String,
    /// The version.
    pub version: String,
    /// The source.
    pub origin: Origin,
    /// The checksum of the package archive, 64 hexadecimal digits for a registry package.
    pub checksum: Option<String>,
    /// The packages it depends on.
    pub dependencies: Vec<LockedRef>,
}

/// A lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lockfile {
    /// Every package, in file order.
    pub packages: Vec<LockedPackage>,
}

/// A package name as the ecosystem compares it. Cargo treats `-` and `_` as one letter and
/// ignores case, like `DependencyPolicy` does.
#[must_use]
pub fn normalize(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

/// The packages of a lockfile by name, so that a reference is resolved without a scan of the
/// whole file. Build it once for a lockfile and resolve every reference through it: the cost is
/// then linear in the size of the lockfile, however many references it holds.
#[derive(Debug, Clone)]
pub struct LockIndex<'a> {
    by_name: HashMap<&'a str, Vec<&'a LockedPackage>>,
}

impl<'a> LockIndex<'a> {
    /// The package a reference names: exactly one, more than one, or none.
    #[must_use]
    pub fn resolve(&self, reference: &LockedRef) -> Resolved<'a> {
        let mut found = self
            .by_name
            .get(reference.name.as_str())
            .into_iter()
            .flatten()
            .copied()
            .filter(|package| {
                reference
                    .version
                    .as_ref()
                    .is_none_or(|version| *version == package.version)
                    && reference
                        .origin
                        .as_ref()
                        .is_none_or(|origin| *origin == package.origin)
            });
        match (found.next(), found.next()) {
            (None, _) => Resolved::Dangling,
            (Some(package), None) => Resolved::One(package),
            (Some(_), Some(_)) => Resolved::Ambiguous,
        }
    }
}

impl Lockfile {
    /// The packages that belong to the project itself or are path dependencies.
    pub fn members(&self) -> impl Iterator<Item = &LockedPackage> {
        self.packages
            .iter()
            .filter(|package| package.origin == Origin::Path)
    }

    /// The index to resolve references with.
    #[must_use]
    pub fn index(&self) -> LockIndex<'_> {
        let mut by_name: HashMap<&str, Vec<&LockedPackage>> = HashMap::new();
        for package in &self.packages {
            by_name
                .entry(package.name.as_str())
                .or_default()
                .push(package);
        }
        LockIndex { by_name }
    }

    /// What a reference names. This builds an index, so it is for a single lookup; resolve many
    /// references through [`index`](Self::index).
    #[must_use]
    pub fn resolve(&self, reference: &LockedRef) -> Resolved<'_> {
        self.index().resolve(reference)
    }

    /// The normalized names of every package.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.packages
            .iter()
            .map(|package| normalize(&package.name))
            .collect()
    }
}

/// How a dependency is declared in a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeclaredSource {
    /// From the default registry, by version.
    Registry,
    /// From another registry.
    AlternateRegistry,
    /// From a path.
    Path,
    /// From a git repository.
    Git,
    /// Inherited from the workspace table, which carries the real source.
    Workspace,
}

/// One dependency of a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    /// The table it is in, such as `dependencies` or `target.cfg(unix).dev-dependencies`.
    pub section: String,
    /// The key it is written under.
    pub key: String,
    /// The package it names: the `package` rename when there is one, else the key.
    pub name: String,
    /// Where it comes from.
    pub source: DeclaredSource,
    /// The whole declaration as one canonical line, to compare two versions of a manifest.
    pub canonical: String,
}

/// A manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    /// The package name, for a manifest that describes a package (a pure workspace root has none).
    pub name: Option<String>,
    /// Every dependency of the project and its targets.
    pub declared: Vec<Declared>,
    /// The entries of the workspace dependency table, which members inherit.
    pub workspace_declared: Vec<Declared>,
    /// The entries of `[patch]` and `[replace]`, as canonical lines.
    pub patches: Vec<String>,
    /// The manifest names a build script.
    pub build_script: bool,
    /// The manifest builds a procedural macro.
    pub proc_macro: bool,
}

/// How much a line of the build configuration can change what a fetch or a build does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigClass {
    /// Presentation and local choices that change neither the source nor the code that runs.
    Benign,
    /// Changes where packages come from or how the registry is reached.
    Redirect,
    /// Names a program that cargo would run, or an environment it would set.
    Execution,
    /// Not on the list of harmless keys, so it is not trusted.
    Unrecognized,
}

/// One line of a build configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEntry {
    /// The dotted key.
    pub key: String,
    /// The value as one canonical line.
    pub value: String,
    /// What the key can do.
    pub class: ConfigClass,
}

/// A build configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuildConfig {
    /// Every key with a value.
    pub entries: Vec<ConfigEntry>,
}

/// A package manager's way of writing dependency files. See the module notes.
pub trait DependencyFormat: Send + Sync {
    /// The ecosystem, as the policy names it.
    fn ecosystem(&self) -> Ecosystem;

    /// A phrase for the default registry, for messages.
    fn registry_label(&self) -> &'static str;

    /// What the file at `path` is, or `None` when it is not a dependency file.
    fn kind_of(&self, path: &str) -> Option<FileKind>;

    /// Reads a lockfile.
    ///
    /// # Errors
    /// [`ParseError`] when the file is not a lockfile of a layout this format knows.
    fn parse_lockfile(&self, text: &str) -> Result<Lockfile, ParseError>;

    /// Reads a manifest.
    ///
    /// # Errors
    /// [`ParseError`] as for the lockfile.
    fn parse_manifest(&self, text: &str) -> Result<Manifest, ParseError>;

    /// Reads a build configuration.
    ///
    /// # Errors
    /// [`ParseError`] as for the lockfile.
    fn parse_build_config(&self, text: &str) -> Result<BuildConfig, ParseError>;
}

/// The dependency files of one commit, by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Side(BTreeMap<String, String>);

impl Side {
    /// The files of `format` among `files` (path and text). Other files are dropped.
    #[must_use]
    pub fn of<'a>(
        format: &dyn DependencyFormat,
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        Self(
            files
                .into_iter()
                .filter(|(path, _)| format.kind_of(path).is_some())
                .map(|(path, text)| (path.to_owned(), text.to_owned()))
                .collect(),
        )
    }

    /// The paths and texts.
    pub fn files(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
    }

    /// True when there is no dependency file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A text from a file of the builder, cut to a safe length and with every character that is not
/// plain replaced by `?`. A message never carries the raw text of a dependency file.
#[must_use]
pub fn plain(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| {
            if c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '.' | '_' | '-' | ':' | '/' | '+' | '(' | ')' | '*' | '@' | ','
                )
            {
                c
            } else {
                '?'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_compared_as_cargo_compares_them() {
        assert_eq!(normalize("Serde-JSON"), normalize("serde_json"));
        assert_ne!(normalize("serde"), normalize("serde_json"));
    }

    #[test]
    fn plain_text_replaces_what_could_carry_a_secret_or_markup() {
        assert_eq!(plain("a b/c@d", 100), "a b/c@d");
        assert_eq!(plain("tok=abc\"<x>\n", 100), "tok?abc??x??");
        assert_eq!(plain("abcdef", 3), "abc");
    }
}
