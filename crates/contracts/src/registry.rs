//! `FileAgentRegistry`: the real implementation of the `AgentRegistry` port.
//!
//! It reads every agent manifest and capability profile under a repository root when it is built,
//! checks each manifest's prompt against the hash the manifest declares, and then answers lookups
//! from memory. After start-up it does no I/O, as the port requires, and a prompt that is changed
//! on disk afterwards is not picked up: a restart reloads it and checks it again.
//!
//! # Layout
//!
//! Nothing in the architecture documents fixes the file layout, so this crate chooses one and the
//! work package that writes the definitions (`s1-agent-definitions`) follows it or changes it here.
//!
//! * `agents/**/manifest.json`, `manifest.yaml` or `manifest.yml`: one agent manifest per file. The
//!   prompt path inside the manifest is relative to the repository root, as in the schema examples
//!   (`agents/builder/prompt.md`).
//! * `profiles/**/profile.json|yaml|yml` or `*.profile.json|yaml|yml`: one capability profile per
//!   file.
//!
//! Directories are walked in name order, symbolic links are refused, and the walk stops at 6 levels
//! and 1,000 files so a directory cannot hold the loader hostage.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use factory_domain::contracts::{AgentManifest, DomainCapabilityProfile};
use factory_domain::values::{SemanticVersion, Sha256Digest};
use factory_domain::vocabulary::Fidelity;
use factory_ports::registry::{
    AgentId, AgentRegistry, DomainTag, LoadedPrompt, RegistryError, VersionReq,
};

use crate::loader::{
    DefinitionFormat, DefinitionLoader, LoadError, LoadErrorKind, LoadedAgent, read_bounded,
};

/// How deep the directory walk goes below `agents/` or `profiles/`.
const MAX_WALK_DEPTH: usize = 6;
/// How many entries the directory walk visits before it stops.
const MAX_WALK_ENTRIES: usize = 1000;

/// A registry read from the definitions in a repository.
#[derive(Debug)]
pub struct FileAgentRegistry {
    agents: BTreeMap<(AgentId, SemanticVersion), LoadedAgent>,
    profiles: Vec<DomainCapabilityProfile>,
}

impl FileAgentRegistry {
    /// Reads `agents/` and `profiles/` under `root`.
    ///
    /// # Errors
    /// The first [`LoadError`]: an unreadable, malformed or forbidden file, a prompt whose hash
    /// differs from its manifest, a missing directory, or two definitions with the same identity.
    pub fn load(root: &Path) -> Result<Self, LoadError> {
        Self::load_from(root, "agents", "profiles")
    }

    /// Reads the given directories under `root`.
    ///
    /// # Errors
    /// As for [`FileAgentRegistry::load`].
    pub fn load_from(root: &Path, agents_dir: &str, profiles_dir: &str) -> Result<Self, LoadError> {
        let loader = DefinitionLoader::new().map_err(|e| {
            LoadError::new("embedded schemas", LoadErrorKind::Schema, e.to_string())
        })?;
        let mut agents = Vec::new();
        for path in discover(&root.join(agents_dir), agents_dir, |name| {
            matches!(name, "manifest.json" | "manifest.yaml" | "manifest.yml")
        })? {
            agents.push(loader.agent_with_prompt(root, &path)?);
        }
        let mut profiles = Vec::new();
        for path in discover(&root.join(profiles_dir), profiles_dir, is_profile_file)? {
            let label = path.display().to_string();
            let format = DefinitionFormat::from_path(&path).ok_or_else(|| {
                LoadError::new(
                    &label,
                    LoadErrorKind::UnsupportedFormat,
                    "use .json, .yaml or .yml",
                )
            })?;
            let bytes = read_bounded(&path, &label)?;
            profiles.push(loader.capability_profile(&label, format, &bytes)?);
        }
        Self::from_parts(agents, profiles)
    }

    /// Builds a registry from definitions that were loaded already.
    ///
    /// # Errors
    /// [`LoadErrorKind::Duplicate`] when two agents share an id and version, or two profiles share
    /// an id and version.
    pub fn from_parts(
        agents: Vec<LoadedAgent>,
        mut profiles: Vec<DomainCapabilityProfile>,
    ) -> Result<Self, LoadError> {
        let mut by_identity = BTreeMap::new();
        for agent in agents {
            let key = (agent.manifest.id.clone(), agent.manifest.version.clone());
            let file = agent.file.clone();
            if let Some(first) = by_identity.insert(key, agent) {
                return Err(LoadError::new(
                    &file,
                    LoadErrorKind::Duplicate,
                    format!(
                        "another manifest, {}, already defines this agent and version; each agent version is defined once",
                        first.file
                    ),
                )
                .at_field("version"));
            }
        }
        profiles.sort_by(|a, b| (&a.id, a.version).cmp(&(&b.id, b.version)));
        if let Some(pair) = profiles
            .windows(2)
            .find(|pair| pair[0].id == pair[1].id && pair[0].version == pair[1].version)
        {
            return Err(LoadError::new(
                "profiles",
                LoadErrorKind::Duplicate,
                format!(
                    "two capability profiles define `{}` version {}; each profile version is defined once",
                    pair[0].id, pair[0].version
                ),
            )
            .at_field("version"));
        }
        Ok(Self {
            agents: by_identity,
            profiles,
        })
    }

    /// How many agent versions the registry holds.
    #[must_use]
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// How many capability profiles the registry holds.
    #[must_use]
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}

fn is_profile_file(name: &str) -> bool {
    let stem = name
        .strip_suffix(".json")
        .or_else(|| name.strip_suffix(".yaml"))
        .or_else(|| name.strip_suffix(".yml"));
    stem.is_some_and(|stem| stem == "profile" || stem.ends_with(".profile"))
}

/// Finds the files in `dir` whose names `wanted` accepts. Walks in name order, refuses symbolic
/// links, and stops at the depth and entry limits.
fn discover(
    dir: &Path,
    label: &str,
    wanted: impl Fn(&str) -> bool,
) -> Result<Vec<PathBuf>, LoadError> {
    let metadata = fs::symlink_metadata(dir).map_err(|_| {
        LoadError::new(
            label,
            LoadErrorKind::DirectoryMissing,
            format!("the directory `{label}` does not exist under the registry root"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(LoadError::new(
            label,
            LoadErrorKind::DirectoryMissing,
            format!("`{label}` is not a directory"),
        ));
    }
    let mut found = Vec::new();
    let mut pending = vec![(dir.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((current, depth)) = pending.pop() {
        let mut entries: Vec<_> = fs::read_dir(&current)
            .map_err(|_| {
                LoadError::new(
                    &current.display().to_string(),
                    LoadErrorKind::Unreadable,
                    "the directory cannot be read",
                )
            })?
            .filter_map(Result::ok)
            .collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        // `pending` is a stack, so push subdirectories in reverse to visit them in name order.
        let mut subdirectories = Vec::new();
        for entry in entries {
            visited += 1;
            let path = entry.path();
            let shown = path.display().to_string();
            if visited > MAX_WALK_ENTRIES {
                return Err(LoadError::new(
                    label,
                    LoadErrorKind::TooManyFiles,
                    format!(
                        "`{label}` holds more than {MAX_WALK_ENTRIES} entries; the registry does not read that many"
                    ),
                ));
            }
            let file_type = entry.file_type().map_err(|_| {
                LoadError::new(
                    &shown,
                    LoadErrorKind::Unreadable,
                    "the entry cannot be inspected",
                )
            })?;
            if file_type.is_symlink() {
                return Err(LoadError::new(
                    &shown,
                    LoadErrorKind::Unreadable,
                    "a symbolic link is not followed; put the file here instead",
                ));
            }
            if file_type.is_dir() {
                if depth + 1 > MAX_WALK_DEPTH {
                    return Err(LoadError::new(
                        &shown,
                        LoadErrorKind::TooManyFiles,
                        format!(
                            "directories nest deeper than {MAX_WALK_DEPTH} levels under `{label}`"
                        ),
                    ));
                }
                subdirectories.push((path, depth + 1));
            } else if entry.file_name().to_str().is_some_and(&wanted) {
                found.push(path);
            }
        }
        pending.extend(subdirectories.into_iter().rev());
    }
    found.sort();
    Ok(found)
}

impl AgentRegistry for FileAgentRegistry {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn manifest(&self, id: &AgentId, req: &VersionReq) -> Result<AgentManifest, RegistryError> {
        let mut known = false;
        let mut best: Option<&LoadedAgent> = None;
        for ((agent, version), loaded) in &self.agents {
            if agent != id {
                continue;
            }
            known = true;
            if req.matches(version)
                && best.is_none_or(|current| current.manifest.version < *version)
            {
                best = Some(loaded);
            }
        }
        match best {
            Some(loaded) => Ok(loaded.manifest.clone()),
            None if known => Err(RegistryError::NoMatchingVersion),
            None => Err(RegistryError::UnknownAgent),
        }
    }

    fn prompt(&self, manifest: &AgentManifest) -> Result<LoadedPrompt, RegistryError> {
        let loaded = self
            .agents
            .get(&(manifest.id.clone(), manifest.version.clone()))
            .ok_or(RegistryError::PromptNotFound)?;
        let actual = Sha256Digest::of(loaded.prompt.text.as_bytes());
        if actual != manifest.prompt.template_sha256 {
            return Err(RegistryError::PromptHashMismatch {
                expected: manifest.prompt.template_sha256.clone(),
                actual,
            });
        }
        Ok(LoadedPrompt {
            template: manifest.prompt.clone(),
            text: loaded.prompt.text.clone(),
        })
    }

    fn profiles_matching(
        &self,
        tags: &[DomainTag],
    ) -> Result<Vec<DomainCapabilityProfile>, RegistryError> {
        Ok(self
            .profiles
            .iter()
            .filter(|profile| {
                tags.iter()
                    .any(|tag| profile.matches.as_slice().contains(tag))
            })
            .cloned()
            .collect())
    }
}
