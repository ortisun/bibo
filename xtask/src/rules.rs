//! Reads `docs/architecture/crate-dependency-rules.json`, the single source of truth for which
//! crate may depend on which. Nothing in this crate repeats those rules.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Rules {
    pub package_prefix: String,
    pub crates: Vec<CrateRule>,
    pub apps: Vec<AppRule>,
    pub tooling: Vec<ToolingRule>,
    /// The lint that DEP-06 relies on, read from that rule's `enforced_by` text, for example
    /// "workspace lint unsafe_code = forbid".
    pub workspace_lint: WorkspaceLint,
    statements: BTreeMap<String, String>,
}

/// A lint the root manifest sets under `[workspace.lints.<table>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceLint {
    /// `rust` or `clippy`.
    pub table: String,
    pub name: String,
    pub level: String,
}

impl WorkspaceLint {
    /// Reads "workspace lint NAME = LEVEL". A name written `clippy::x` is in the clippy table.
    fn parse(enforced_by: &str) -> Option<Self> {
        let rest = enforced_by.split("workspace lint ").nth(1)?;
        let (name, level) = rest.split_once('=')?;
        let level = level.split_whitespace().next()?;
        let name = name.trim();
        let (table, name) = name.split_once("::").unwrap_or(("rust", name));
        (!name.is_empty()).then(|| Self {
            table: table.to_string(),
            name: name.to_string(),
            level: level
                .trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CrateRule {
    pub name: String,
    pub ring: u64,
    /// `domain`, `ports`, `application`, `adapter` or `test-support`.
    pub layer: String,
    pub path: String,
    pub depends_on: Vec<String>,
    pub dev_depends_on: Vec<String>,
    pub external_allow: Vec<AllowEntry>,
}

#[derive(Debug, Clone)]
pub struct AppRule {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ToolingRule {
    pub name: String,
    pub path: String,
}

/// One entry of `external_allow`: a crate name, optionally with the only features it may enable,
/// written `tokio[sync,time]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    pub name: String,
    pub features: Option<BTreeSet<String>>,
}

#[derive(Clone, Copy)]
pub enum Role<'a> {
    Library(&'a CrateRule),
    App(&'a AppRule),
    Tooling(&'a ToolingRule),
}

impl Role<'_> {
    pub fn path(&self) -> &str {
        match self {
            Role::Library(c) => &c.path,
            Role::App(a) => &a.path,
            Role::Tooling(t) => &t.path,
        }
    }
}

/// Cargo treats `-` and `_` in a crate name as the same character.
pub fn normalize(name: &str) -> String {
    name.replace('-', "_")
}

impl AllowEntry {
    /// `None` for free text such as "a JWT signing crate chosen later", which allows no crate by
    /// name. An error for a bracket that is not closed.
    fn parse(entry: &str) -> Result<Option<Self>, String> {
        let entry = entry.trim();
        let (name, features) = match entry.split_once('[') {
            None => (entry, None),
            Some((name, rest)) => {
                let list = rest.strip_suffix(']').ok_or_else(|| {
                    format!("external_allow entry {entry:?} has an unclosed bracket")
                })?;
                let features: BTreeSet<String> = list
                    .split(',')
                    .map(str::trim)
                    .filter(|f| !f.is_empty())
                    .map(str::to_string)
                    .collect();
                (name, Some(features))
            }
        };
        let is_name = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !is_name {
            return Ok(None);
        }
        Ok(Some(Self {
            name: name.to_string(),
            features,
        }))
    }
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a Value, String> {
    value
        .get(key)
        .ok_or_else(|| format!("rules file: {context} has no `{key}`"))
}

fn text(value: &Value, key: &str, context: &str) -> Result<String, String> {
    field(value, key, context)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("rules file: `{key}` in {context} must be a string"))
}

fn list<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a Vec<Value>, String> {
    field(value, key, context)?
        .as_array()
        .ok_or_else(|| format!("rules file: `{key}` in {context} must be a list"))
}

fn strings(value: &Value, key: &str, context: &str) -> Result<Vec<String>, String> {
    list(value, key, context)?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("rules file: `{key}` in {context} must hold only strings"))
        })
        .collect()
}

impl Rules {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("cannot read the rules file {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(source: &str) -> Result<Self, String> {
        let doc: Value = serde_json::from_str(source)
            .map_err(|e| format!("rules file is not valid JSON: {e}"))?;
        let package_prefix = text(&doc, "package_prefix", "the document")?;

        let mut crates = Vec::new();
        for c in list(&doc, "crates", "the document")? {
            let name = text(c, "name", "a crate entry")?;
            let context = format!("crate {name}");
            let mut external_allow = Vec::new();
            for entry in strings(c, "external_allow", &context)? {
                if let Some(parsed) = AllowEntry::parse(&entry)? {
                    external_allow.push(parsed);
                }
            }
            crates.push(CrateRule {
                ring: field(c, "ring", &context)?
                    .as_u64()
                    .ok_or_else(|| format!("rules file: `ring` in {context} must be a number"))?,
                layer: text(c, "layer", &context)?,
                path: text(c, "path", &context)?,
                depends_on: strings(c, "depends_on", &context)?,
                dev_depends_on: strings(c, "dev_depends_on", &context)?,
                external_allow,
                name,
            });
        }

        let mut apps = Vec::new();
        for a in list(&doc, "apps", "the document")? {
            apps.push(AppRule {
                name: text(a, "name", "an app entry")?,
                path: text(a, "path", "an app entry")?,
            });
        }
        let mut tooling = Vec::new();
        for t in list(&doc, "tooling", "the document")? {
            tooling.push(ToolingRule {
                name: text(t, "name", "a tooling entry")?,
                path: text(t, "path", "a tooling entry")?,
            });
        }
        let mut statements = BTreeMap::new();
        let mut workspace_lint = None;
        for r in list(&doc, "rules", "the document")? {
            let id = text(r, "id", "a rule entry")?;
            if id == "DEP-06" {
                workspace_lint = WorkspaceLint::parse(&text(r, "enforced_by", "rule DEP-06")?);
            }
            statements.insert(id, text(r, "statement", "a rule entry")?);
        }
        let workspace_lint = workspace_lint.ok_or_else(|| {
            "rules file: rule DEP-06 must say \"workspace lint NAME = LEVEL\" in `enforced_by`"
                .to_string()
        })?;
        Ok(Self {
            package_prefix,
            crates,
            apps,
            tooling,
            workspace_lint,
            statements,
        })
    }

    /// The Cargo package name of a library crate or binary.
    pub fn package_name(&self, name: &str) -> String {
        format!("{}{name}", self.package_prefix)
    }

    pub fn crate_named(&self, name: &str) -> Option<&CrateRule> {
        self.crates.iter().find(|c| c.name == name)
    }

    /// What the rules file says a workspace package is, or `None` if it does not list it.
    pub fn role_of_package(&self, package: &str) -> Option<Role<'_>> {
        if let Some(c) = self
            .crates
            .iter()
            .find(|c| self.package_name(&c.name) == package)
        {
            return Some(Role::Library(c));
        }
        if let Some(a) = self
            .apps
            .iter()
            .find(|a| self.package_name(&a.name) == package)
        {
            return Some(Role::App(a));
        }
        self.tooling
            .iter()
            .find(|t| t.name == package)
            .map(Role::Tooling)
    }

    /// Binaries sit one ring above the highest library ring.
    pub fn app_ring(&self) -> u64 {
        self.crates
            .iter()
            .map(|c| c.ring)
            .max()
            .map_or(0, |r| r + 1)
    }

    /// The wording of a rule, to print next to a violation.
    pub fn statement(&self, rule_id: &str) -> Option<&str> {
        self.statements.get(rule_id).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_rules_text() -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/architecture/crate-dependency-rules.json");
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    fn the_real_rules_file_parses_with_twelve_libraries_four_binaries_and_xtask() {
        let rules = Rules::parse(&real_rules_text()).expect("the real rules file parses");
        assert_eq!(rules.crates.len(), 12);
        assert_eq!(rules.apps.len(), 4);
        assert_eq!(
            rules
                .tooling
                .iter()
                .map(|t| t.name.as_str())
                .collect::<Vec<_>>(),
            ["xtask"]
        );
        assert_eq!(rules.package_name("domain"), "factory-domain");
        assert!(rules.statement("DEP-01").is_some());
    }

    #[test]
    fn the_real_tokio_entry_in_workflow_keeps_its_feature_list() {
        let rules = Rules::parse(&real_rules_text()).expect("parse");
        let workflow = rules.crate_named("workflow").expect("workflow");
        let tokio = workflow
            .external_allow
            .iter()
            .find(|e| e.name == "tokio")
            .expect("tokio");
        let features: Vec<&str> = tokio
            .features
            .iter()
            .flatten()
            .map(String::as_str)
            .collect();
        assert_eq!(features, ["macros", "rt", "sync", "time"]);
    }

    #[test]
    fn binaries_sit_one_ring_above_the_libraries() {
        let rules = Rules::parse(&real_rules_text()).expect("parse");
        assert_eq!(rules.app_ring(), 3);
    }

    #[test]
    fn free_text_in_external_allow_allows_no_crate_by_name() {
        assert_eq!(
            AllowEntry::parse("a JWT signing crate and an HTTP client").unwrap(),
            None
        );
    }

    #[test]
    fn an_entry_without_brackets_allows_every_feature() {
        let entry = AllowEntry::parse("serde").unwrap().unwrap();
        assert_eq!(entry.name, "serde");
        assert_eq!(entry.features, None);
    }

    #[test]
    fn an_empty_bracket_allows_no_feature() {
        let entry = AllowEntry::parse("tokio[]").unwrap().unwrap();
        assert_eq!(entry.features, Some(BTreeSet::new()));
    }

    #[test]
    fn an_unclosed_bracket_is_an_error() {
        assert!(AllowEntry::parse("tokio[sync").is_err());
    }

    #[test]
    fn a_missing_key_names_the_key_and_the_place() {
        let error = Rules::parse(
            r#"{"package_prefix": "f-", "crates": [{"name": "a", "external_allow": []}]}"#,
        )
        .unwrap_err();
        assert!(
            error.contains("`ring`") && error.contains("crate a"),
            "{error}"
        );
    }

    #[test]
    fn dep_06_names_the_workspace_lint_it_relies_on() {
        let rules = Rules::parse(&real_rules_text()).expect("parse");
        assert_eq!(
            rules.workspace_lint,
            WorkspaceLint {
                table: "rust".into(),
                name: "unsafe_code".into(),
                level: "forbid".into()
            }
        );
    }

    #[test]
    fn a_clippy_lint_is_read_from_the_clippy_table() {
        let lint = WorkspaceLint::parse("workspace lint clippy::unwrap_used = deny").unwrap();
        assert_eq!(
            (lint.table.as_str(), lint.name.as_str(), lint.level.as_str()),
            ("clippy", "unwrap_used", "deny")
        );
    }

    #[test]
    fn text_without_a_workspace_lint_is_not_one() {
        assert_eq!(WorkspaceLint::parse("cargo deny check"), None);
        assert_eq!(WorkspaceLint::parse("workspace lint = forbid"), None);
    }

    #[test]
    fn a_rules_file_where_dep_06_names_no_lint_is_refused() {
        let broken =
            real_rules_text().replace("workspace lint unsafe_code = forbid", "a code review");
        let error = Rules::parse(&broken).unwrap_err();
        assert!(error.contains("DEP-06"), "{error}");
    }

    #[test]
    fn dashes_and_underscores_are_the_same_in_a_crate_name() {
        assert_eq!(normalize("diesel-async"), normalize("diesel_async"));
    }
}
