//! The parameters of the source scans, read from the `source_scans` section of
//! `docs/architecture/crate-dependency-rules.json`.
//!
//! The rules file used to describe these in prose and the Rust sources kept them as constants.
//! A reviewer who wanted to add a shell to the list had to edit code. Now one reviewed file holds
//! them, and a test in `tests/source_scans.rs` fails when a list comes back into the sources.

use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct SourceScans {
    pub st_01: St01,
    pub dep_05: Dep05,
    pub dep_09: Dep09,
    pub dep_10: Dep10,
    pub st_04: St04,
    pub st_05: St05,
    pub st_07: St07,
    pub st_09: St09,
    pub st_13: Vec<Constructor>,
    pub st_14: St14,
    /// Every crate or binary named anywhere in the section, for the existence check.
    pub named_crates: BTreeSet<String>,
}

/// ST-01 walks the whole repository tree for `safe.directory`.
#[derive(Debug, Clone)]
pub struct St01 {
    pub skipped_directories: Vec<String>,
    /// Extensions of files that are prose, not code or configuration.
    pub prose_extensions: Vec<String>,
}

/// DEP-05: which crates carry the ban list, which lints may not be silenced, and which feature
/// sets of `time`, `uuid` and `tokio` the inner crates may resolve to.
#[derive(Debug, Clone)]
pub struct Dep05 {
    pub inner_crates: Vec<String>,
    pub forbidden_lint_allows: Vec<String>,
    pub resolved_features: Vec<ResolvedFeatureLimit>,
}

#[derive(Debug, Clone)]
pub struct ResolvedFeatureLimit {
    pub package: String,
    pub allowed: BTreeSet<String>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Dep09 {
    pub begin_system_function: String,
    pub begin_system_crate: String,
    pub spec_kit_crate: String,
    pub spec_kit_terms: Vec<String>,
    pub change_host_trait: String,
    pub forbidden_method_prefixes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Dep10 {
    /// The one file that may contain a process-spawning path, relative to the workspace root.
    pub spawn_file: String,
    /// Paths that start a process. A mention of one anywhere but `spawn_file` is a finding.
    pub spawn_paths: Vec<String>,
    pub shells: Vec<String>,
    pub programs: Vec<CrateRule>,
}

/// What one crate may do: the programs the crate may start.
#[derive(Debug, Clone)]
pub struct CrateRule {
    pub krate: String,
    pub programs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct St04 {
    pub verifier_crate: String,
    pub verifier_prefix: String,
    pub dangerous_strings: Vec<String>,
    pub host_namespace_flags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct St05 {
    pub verbs: Vec<String>,
    pub fragments: Vec<String>,
    pub route_segments: Vec<String>,
    pub workflow_file_words: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct St07 {
    /// The conventions page that holds the tables, relative to the workspace root.
    pub conventions: String,
    /// Crates whose sources are not scanned: they define the names.
    pub skip_crates: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct St09 {
    pub crates: Vec<String>,
    pub ingestion_crate: String,
    pub ingestion_dir: String,
    pub calls: Vec<String>,
    pub methods: Vec<String>,
}

/// ST-13: a constructor that only some crates may call.
#[derive(Debug, Clone)]
pub struct Constructor {
    /// `TenantScope::new` for a call, `ResolvedPrincipal` for a struct literal.
    pub name: String,
    pub allowed_crates: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct St14 {
    pub krate: String,
    pub names: Vec<String>,
}

fn object<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a Value, String> {
    value
        .get(key)
        .filter(|v| v.is_object())
        .ok_or_else(|| format!("rules file: {context} has no object `{key}`"))
}

fn text(value: &Value, key: &str, context: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("rules file: `{key}` in {context} must be a string"))
}

fn strings(value: &Value, key: &str, context: &str) -> Result<Vec<String>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("rules file: `{key}` in {context} must be a list"))?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("rules file: `{key}` in {context} must hold only strings"))
        })
        .collect()
}

impl SourceScans {
    pub fn parse(doc: &Value) -> Result<Self, String> {
        let scans = object(doc, "source_scans", "the document")?;
        let mut named = BTreeSet::new();
        let mut name = |krate: &str| {
            named.insert(krate.to_string());
            krate.to_string()
        };

        let d = object(scans, "st_01", "source_scans")?;
        let st_01 = St01 {
            skipped_directories: strings(d, "skipped_directories", "source_scans.st_01")?,
            prose_extensions: strings(d, "prose_extensions", "source_scans.st_01")?,
        };

        let d = object(scans, "dep_05", "source_scans")?;
        let mut resolved_features = Vec::new();
        for entry in d
            .get("resolved_features")
            .and_then(Value::as_array)
            .ok_or("rules file: `resolved_features` in source_scans.dep_05 must be a list")?
        {
            resolved_features.push(ResolvedFeatureLimit {
                package: text(entry, "package", "a resolved_features entry")?,
                allowed: strings(entry, "allowed", "a resolved_features entry")?
                    .into_iter()
                    .collect(),
                reason: text(entry, "reason", "a resolved_features entry")?,
            });
        }
        let dep_05 = Dep05 {
            inner_crates: strings(d, "inner_crates", "source_scans.dep_05")?
                .iter()
                .map(|c| name(c))
                .collect(),
            forbidden_lint_allows: strings(d, "forbidden_lint_allows", "source_scans.dep_05")?,
            resolved_features,
        };

        let d = object(scans, "dep_09", "source_scans")?;
        let dep_09 = Dep09 {
            begin_system_function: text(d, "begin_system_function", "source_scans.dep_09")?,
            begin_system_crate: name(&text(d, "begin_system_crate", "source_scans.dep_09")?),
            spec_kit_crate: name(&text(d, "spec_kit_crate", "source_scans.dep_09")?),
            spec_kit_terms: strings(d, "spec_kit_terms", "source_scans.dep_09")?,
            change_host_trait: text(d, "change_host_trait", "source_scans.dep_09")?,
            forbidden_method_prefixes: strings(
                d,
                "forbidden_method_prefixes",
                "source_scans.dep_09",
            )?,
        };

        let d = object(scans, "dep_10", "source_scans")?;
        let mut programs = Vec::new();
        for entry in d
            .get("programs")
            .and_then(Value::as_array)
            .ok_or("rules file: `programs` in source_scans.dep_10 must be a list")?
        {
            programs.push(CrateRule {
                krate: name(&text(entry, "crate", "a programs entry")?),
                programs: strings(entry, "programs", "a programs entry")?,
            });
        }
        let dep_10 = Dep10 {
            spawn_file: text(d, "spawn_file", "source_scans.dep_10")?,
            spawn_paths: strings(d, "spawn_paths", "source_scans.dep_10")?,
            shells: strings(d, "shells", "source_scans.dep_10")?,
            programs,
        };

        let d = object(scans, "st_04", "source_scans")?;
        let st_04 = St04 {
            verifier_crate: name(&text(d, "verifier_crate", "source_scans.st_04")?),
            verifier_prefix: text(d, "verifier_prefix", "source_scans.st_04")?,
            dangerous_strings: strings(d, "dangerous_strings", "source_scans.st_04")?,
            host_namespace_flags: strings(d, "host_namespace_flags", "source_scans.st_04")?,
        };

        let d = object(scans, "st_05", "source_scans")?;
        let st_05 = St05 {
            verbs: strings(d, "verbs", "source_scans.st_05")?,
            fragments: strings(d, "fragments", "source_scans.st_05")?,
            route_segments: strings(d, "route_segments", "source_scans.st_05")?,
            workflow_file_words: strings(d, "workflow_file_words", "source_scans.st_05")?,
        };

        let d = object(scans, "st_07", "source_scans")?;
        let st_07 = St07 {
            conventions: text(d, "conventions", "source_scans.st_07")?,
            skip_crates: strings(d, "skip_crates", "source_scans.st_07")?
                .iter()
                .map(|c| name(c))
                .collect(),
        };

        let d = object(scans, "st_09", "source_scans")?;
        let st_09 = St09 {
            crates: strings(d, "crates", "source_scans.st_09")?
                .iter()
                .map(|c| name(c))
                .collect(),
            ingestion_crate: name(&text(d, "ingestion_crate", "source_scans.st_09")?),
            ingestion_dir: text(d, "ingestion_dir", "source_scans.st_09")?,
            calls: strings(d, "calls", "source_scans.st_09")?,
            methods: strings(d, "methods", "source_scans.st_09")?,
        };

        let mut st_13 = Vec::new();
        for entry in scans
            .get("st_13")
            .and_then(Value::as_array)
            .ok_or("rules file: `st_13` in source_scans must be a list")?
        {
            st_13.push(Constructor {
                name: text(entry, "name", "an st_13 entry")?,
                allowed_crates: strings(entry, "allowed_crates", "an st_13 entry")?
                    .iter()
                    .map(|c| name(c))
                    .collect(),
            });
        }

        let d = object(scans, "st_14", "source_scans")?;
        let st_14 = St14 {
            krate: name(&text(d, "crate", "source_scans.st_14")?),
            names: strings(d, "names", "source_scans.st_14")?,
        };

        Ok(Self {
            st_01,
            dep_05,
            dep_09,
            dep_10,
            st_04,
            st_05,
            st_07,
            st_09,
            st_13,
            st_14,
            named_crates: named,
        })
    }
}
