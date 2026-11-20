//! The documentation impact policy, as pure code.
//!
//! `docs/reference/documentation-policy.md` (section 8.2 and 8.3) says the factory writes the
//! smallest set of documents that covers what the change touches, and that nothing is forced on
//! every change. This module is that rule. It reads the facts of a change (the changed files
//! with their added and removed lines, which changed files an existing page names, which pages
//! exist, the domain profile) and returns the [`DocPlan`]: the pages, the audience, the sources,
//! the terms a page must contain and the acceptance criteria of each page.
//!
//! When nothing needs documenting the plan says so with the rule that led there. A rule is a
//! condition a program can evaluate. An agent's opinion is never a rule.
//!
//! What a diff cannot tell: a bug fix that changes behaviour without touching a flag, a variable
//! or a public item has no mark in the diff. If no page names a changed file, the plan is
//! `NOT_APPLICABLE` with the rule `refactor-no-interface-change`, and the independent reviewer,
//! who reads the specification next to the diff, is the check on that call.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

/// What happened to a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The file is new.
    Added,
    /// The file exists on both sides.
    Modified,
    /// The file is gone.
    Deleted,
}

/// One changed file with the lines that were added and removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    /// The path.
    pub path: String,
    /// What happened to it.
    pub kind: Kind,
    /// The added lines, without the `+`.
    pub added: Vec<String>,
    /// The removed lines, without the `-`.
    pub removed: Vec<String>,
}

/// Reads a patch in the form of `git diff --no-renames`.
#[must_use]
pub fn parse_patch(patch: &str) -> Vec<ChangedFile> {
    let mut files: Vec<ChangedFile> = Vec::new();
    let mut in_hunk = false;
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            // `a/PATH b/PATH`: the path of the new side follows the last ` b/`.
            let path = rest
                .rsplit_once(" b/")
                .map_or(rest, |(_, path)| path)
                .to_owned();
            files.push(ChangedFile {
                path,
                kind: Kind::Modified,
                added: Vec::new(),
                removed: Vec::new(),
            });
            in_hunk = false;
            continue;
        }
        let Some(file) = files.last_mut() else {
            continue;
        };
        if !in_hunk {
            if line.starts_with("new file mode") {
                file.kind = Kind::Added;
            } else if line.starts_with("deleted file mode") {
                file.kind = Kind::Deleted;
            } else if line.starts_with("@@") {
                in_hunk = true;
            }
            continue;
        }
        if let Some(text) = line.strip_prefix('+') {
            file.added.push(text.to_owned());
        } else if let Some(text) = line.strip_prefix('-') {
            file.removed.push(text.to_owned());
        }
    }
    files
}

/// Who a page is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Audience {
    /// People who run the product.
    EndUsers,
    /// People who change the code.
    Developers,
    /// People who run the system in production.
    Operators,
    /// People who build on an interface.
    Integrators,
}

impl Audience {
    /// The spelling in the plan.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EndUsers => "end-users",
            Self::Developers => "developers",
            Self::Operators => "operators",
            Self::Integrators => "integrators",
        }
    }
}

/// The form of a page (Diataxis, and the changelog).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// A guided lesson.
    Tutorial,
    /// Steps for a goal.
    HowTo,
    /// Facts to look up.
    Reference,
    /// Background and reasons.
    Explanation,
    /// A list of changes by release.
    Changelog,
}

impl Form {
    /// The spelling in the plan. It is the spelling of the readability gate's document types.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tutorial => "tutorial",
            Self::HowTo => "how-to",
            Self::Reference => "reference",
            Self::Explanation => "explanation",
            Self::Changelog => "changelog",
        }
    }
}

/// What the page is for. The gate treats the changelog and the upgrade page in their own ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// Usage text for a command, flag or screen.
    Usage,
    /// A reference page or entry.
    Reference,
    /// The changelog entry.
    Changelog,
    /// The upgrade note for a breaking change.
    Upgrade,
    /// Operating procedures, configuration, deployment.
    Operations,
    /// A page that already names a changed file and must stay true.
    Update,
    /// A changed document that only needs checking.
    Check,
    /// Content a domain adds (policy 8.4).
    Domain,
}

impl ItemKind {
    /// The spelling in the plan.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::Reference => "reference",
            Self::Changelog => "changelog",
            Self::Upgrade => "upgrade",
            Self::Operations => "operations",
            Self::Update => "update",
            Self::Check => "check",
            Self::Domain => "domain",
        }
    }
}

/// One page of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// A slug that names the item in the writer's coverage list.
    pub id: String,
    /// What it is for.
    pub kind: ItemKind,
    /// The page, relative to the repository root.
    pub page: String,
    /// The form of the page.
    pub form: Form,
    /// Who reads it.
    pub audience: Vec<Audience>,
    /// The files the claims on this page come from.
    pub sources: Vec<String>,
    /// Words the page must contain, such as the names of the new flags.
    pub terms: Vec<String>,
    /// What the page must do, in plain English.
    pub acceptance: Vec<String>,
}

/// The rule that says nothing needs documenting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotApplicable {
    /// The rule, a slug.
    pub rule: String,
    /// What the rule saw, in plain English.
    pub reason: String,
}

/// What the commits and the specification bind the plan to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The commit the change is relative to.
    pub base_commit: String,
    /// The commit the documentation was planned and written for.
    pub code_head: String,
    /// The hash of the frozen specification.
    pub specification_sha256: String,
}

/// The facts the policy reads.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// The changed files of the code change.
    pub changed: Vec<ChangedFile>,
    /// For each changed file that an existing page names, the pages that name it.
    pub documented: BTreeMap<String, BTreeSet<String>>,
    /// The Markdown pages of the repository at the base commit.
    pub existing_pages: BTreeSet<String>,
    /// The name of the command line program, when the repository builds one.
    pub program: Option<String>,
    /// The id of the domain profile.
    pub profile: String,
}

/// The interface names the diff adds and removes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Interface {
    /// Flags that are new.
    pub new_flags: BTreeSet<String>,
    /// Flags that are gone.
    pub removed_flags: BTreeSet<String>,
    /// Environment variables that are new.
    pub new_env: BTreeSet<String>,
    /// Environment variables that are gone.
    pub removed_env: BTreeSet<String>,
    /// Public items that are new, as `kind name`.
    pub new_api: BTreeSet<String>,
    /// Public items that are gone, as `kind name`.
    pub removed_api: BTreeSet<String>,
}

impl Interface {
    /// A change that removes something users or integrators could rely on.
    #[must_use]
    pub fn breaking(&self) -> bool {
        !(self.removed_flags.is_empty()
            && self.removed_env.is_empty()
            && self.removed_api.is_empty())
    }

    /// A change that adds or removes something users could see.
    #[must_use]
    pub fn user_visible(&self) -> bool {
        !(self.new_flags.is_empty()
            && self.removed_flags.is_empty()
            && self.new_env.is_empty()
            && self.removed_env.is_empty())
    }
}

/// True for a path that is documentation.
#[must_use]
pub fn is_doc(path: &str) -> bool {
    path.ends_with(".md") || path.starts_with("docs/")
}

/// True for a page the documentation writer may write: the README, the changelog or a Markdown
/// file under `docs/`.
#[must_use]
pub fn writable(page: &str) -> bool {
    page == "README.md"
        || page == "CHANGELOG.md"
        || (page.starts_with("docs/") && page.ends_with(".md") && !page.contains(".."))
}

/// True for a path that holds infrastructure: the `infra` directory, charts and container files.
fn is_infrastructure(path: &str) -> bool {
    path.starts_with("infra/") || path.starts_with("helm/") || path.contains("Dockerfile")
}

/// True for a path that is a test or a build script.
#[must_use]
pub fn is_test_or_build(path: &str) -> bool {
    path.starts_with("tests/")
        || path.contains("/tests/")
        || path.ends_with("_test.rs")
        || path == "build.rs"
        || path.starts_with("scripts/")
        || path.starts_with("benches/")
}

fn is_source(path: &str) -> bool {
    !is_doc(path) && !is_test_or_build(path) && !path.ends_with(".toml") && !path.ends_with(".lock")
}

fn quoted(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut parts = line.split('"');
    parts.next();
    while let (Some(inside), Some(_)) = (parts.next(), parts.next()) {
        found.push(inside);
    }
    found
}

fn flag_name(text: &str) -> Option<String> {
    let name = text.strip_prefix("--")?;
    let name = name.split('=').next().unwrap_or("");
    let valid = !name.is_empty()
        && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    valid.then(|| format!("--{name}"))
}

fn env_name(text: &str) -> Option<String> {
    let valid = text.len() >= 3
        && text.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && text
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    valid.then(|| text.to_owned())
}

/// The flags a line of source names: the string `"--name"` or an attribute `long = "name"`.
#[must_use]
pub fn flags_in(line: &str) -> Vec<String> {
    let mut found: Vec<String> = quoted(line).into_iter().filter_map(flag_name).collect();
    if let Some(at) = line.find("long = \"") {
        let rest = &line[at + 8..];
        if let Some(name) = rest.split('"').next().filter(|n| !n.is_empty()) {
            found.push(format!("--{name}"));
        }
    }
    found
}

/// The environment variables a line of source reads.
#[must_use]
pub fn env_in(line: &str) -> Vec<String> {
    if !line.contains("env") {
        return Vec::new();
    }
    quoted(line).into_iter().filter_map(env_name).collect()
}

fn api_in(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("pub ")?;
    for kind in ["fn", "struct", "enum", "trait", "const"] {
        if let Some(after) = rest.strip_prefix(kind).and_then(|r| r.strip_prefix(' ')) {
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(format!("{kind} {name}"));
            }
        }
    }
    None
}

/// What the diff adds to and takes from the interface of the program.
#[must_use]
pub fn interface_of(changed: &[ChangedFile]) -> Interface {
    let mut added = Interface::default();
    let mut gone = Interface::default();
    for file in changed.iter().filter(|file| is_source(&file.path)) {
        for line in &file.added {
            added.new_flags.extend(flags_in(line));
            added.new_env.extend(env_in(line));
            added.new_api.extend(api_in(line));
        }
        for line in &file.removed {
            gone.new_flags.extend(flags_in(line));
            gone.new_env.extend(env_in(line));
            gone.new_api.extend(api_in(line));
        }
    }
    Interface {
        new_flags: added
            .new_flags
            .difference(&gone.new_flags)
            .cloned()
            .collect(),
        removed_flags: gone
            .new_flags
            .difference(&added.new_flags)
            .cloned()
            .collect(),
        new_env: added.new_env.difference(&gone.new_env).cloned().collect(),
        removed_env: gone.new_env.difference(&added.new_env).cloned().collect(),
        new_api: added.new_api.difference(&gone.new_api).cloned().collect(),
        removed_api: gone.new_api.difference(&added.new_api).cloned().collect(),
    }
}

/// The documentation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocPlan {
    /// What the plan is bound to.
    pub binding: Binding,
    /// The names of the change types the rules recognised, such as `new-cli-flag`.
    pub change_types: Vec<String>,
    /// The interface names the change adds and removes.
    pub interface: Interface,
    /// The command line program, when there is one.
    pub program: Option<String>,
    /// Whether the change breaks something users rely on.
    pub breaking: bool,
    /// The pages. Empty when the plan is not applicable.
    pub items: Vec<Item>,
    /// Set when nothing needs documenting.
    pub not_applicable: Option<NotApplicable>,
}

impl DocPlan {
    /// True when the writer has something to write: at least one item that is not a check.
    #[must_use]
    pub fn needs_writing(&self) -> bool {
        self.items.iter().any(|item| item.kind != ItemKind::Check)
    }

    /// The pages of the plan, once each.
    #[must_use]
    pub fn pages(&self) -> BTreeSet<&str> {
        self.items.iter().map(|item| item.page.as_str()).collect()
    }
}

fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_owned()
}

fn first_page(existing: &BTreeSet<String>, wanted: &[&str], otherwise: &str) -> String {
    wanted
        .iter()
        .find(|page| existing.contains(**page))
        .map_or_else(|| otherwise.to_owned(), |page| (*page).to_owned())
}

/// The rules of section 8.3 of the policy, in order.
#[must_use]
pub fn derive(facts: &Facts, binding: Binding) -> DocPlan {
    let interface = interface_of(&facts.changed);
    let paths: Vec<&str> = facts
        .changed
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    let sources_of = |filter: &dyn Fn(&str) -> bool| -> Vec<String> {
        paths
            .iter()
            .filter(|path| filter(path))
            .map(|path| (*path).to_owned())
            .collect()
    };
    let code_sources = sources_of(&|path| is_source(path));
    let mut plan = DocPlan {
        binding,
        change_types: Vec::new(),
        breaking: interface.breaking(),
        program: facts.program.clone(),
        interface,
        items: Vec::new(),
        not_applicable: None,
    };
    let not_applicable = |rule: &str, reason: &str| NotApplicable {
        rule: rule.to_owned(),
        reason: reason.to_owned(),
    };

    // Documentation-only: the changed pages are checked. Never not applicable.
    if !paths.is_empty() && paths.iter().all(|path| is_doc(path)) {
        plan.change_types.push("documentation-only".to_owned());
        for path in &paths {
            plan.items.push(Item {
                id: format!("check-{}", slug(path)),
                kind: ItemKind::Check,
                page: (*path).to_owned(),
                form: if *path == "CHANGELOG.md" {
                    Form::Changelog
                } else {
                    Form::Explanation
                },
                audience: vec![Audience::EndUsers],
                sources: vec![(*path).to_owned()],
                terms: Vec::new(),
                acceptance: vec![
                    "The page has working links and examples and reads as clear English."
                        .to_owned(),
                ],
            });
        }
        return plan;
    }

    let visible = plan.interface.user_visible();
    let program = facts.program.as_deref().unwrap_or("the program");
    let usage_page = first_page(
        &facts.existing_pages,
        &["docs/usage.md", "docs/cli.md", "docs/reference/cli.md"],
        "README.md",
    );
    let config_page = first_page(
        &facts.existing_pages,
        &["docs/configuration.md", "docs/reference/configuration.md"],
        "README.md",
    );

    if !plan.interface.new_flags.is_empty() {
        plan.change_types.push("new-cli-flag".to_owned());
        let flags: Vec<String> = plan.interface.new_flags.iter().cloned().collect();
        plan.items.push(Item {
            id: format!("usage-{}", slug(&flags.join("-"))),
            kind: ItemKind::Usage,
            page: usage_page.clone(),
            form: Form::Reference,
            audience: vec![Audience::EndUsers],
            sources: code_sources.clone(),
            terms: flags.clone(),
            acceptance: vec![
                format!(
                    "Names {} and says what it does for {program}.",
                    flags.join(", ")
                ),
                "Has at least one example that a reader can run, with the output it prints."
                    .to_owned(),
                "Every command, flag and variable on the page exists in the program.".to_owned(),
            ],
        });
    }
    if !plan.interface.new_env.is_empty() {
        plan.change_types
            .push("new-environment-variable".to_owned());
        let names: Vec<String> = plan.interface.new_env.iter().cloned().collect();
        plan.items.push(Item {
            id: format!("configuration-{}", slug(&names.join("-"))),
            kind: ItemKind::Reference,
            page: config_page,
            form: Form::Reference,
            audience: vec![Audience::Operators, Audience::EndUsers],
            sources: code_sources.clone(),
            terms: names.clone(),
            acceptance: vec![format!(
                "Lists {} with its meaning, its default and who sets it.",
                names.join(", ")
            )],
        });
    }
    if plan.interface.breaking() {
        plan.change_types.push("breaking-change".to_owned());
        let mut removed: Vec<String> = plan.interface.removed_flags.iter().cloned().collect();
        removed.extend(plan.interface.removed_env.iter().cloned());
        plan.items.push(Item {
            id: "upgrade-note".to_owned(),
            kind: ItemKind::Upgrade,
            page: "docs/upgrading.md".to_owned(),
            form: Form::HowTo,
            audience: vec![Audience::EndUsers, Audience::Integrators],
            sources: code_sources.clone(),
            terms: removed,
            acceptance: vec![
                "Shows the steps before and after the change for everyone who used what was removed."
                    .to_owned(),
                "Has prerequisites, ordered steps, the expected result and a troubleshooting section."
                    .to_owned(),
            ],
        });
    }
    if !plan.interface.new_api.is_empty() && !plan.interface.new_flags.is_empty() {
        plan.change_types.push("new-public-interface".to_owned());
    } else if !plan.interface.new_api.is_empty() || !plan.interface.removed_api.is_empty() {
        plan.change_types
            .push("changed-public-interface".to_owned());
        let names: Vec<String> = plan
            .interface
            .new_api
            .iter()
            .map(|api| api.rsplit(' ').next().unwrap_or("").to_owned())
            .collect();
        plan.items.push(Item {
            id: "api-reference".to_owned(),
            kind: ItemKind::Reference,
            page: first_page(
                &facts.existing_pages,
                &["docs/api.md", "docs/reference/api.md"],
                "README.md",
            ),
            form: Form::Reference,
            audience: vec![Audience::Developers, Audience::Integrators],
            sources: code_sources.clone(),
            terms: names,
            acceptance: vec![
                "Describes each new public item and has one example that a reader can run."
                    .to_owned(),
            ],
        });
    }
    if paths.iter().any(|path| path.starts_with("migrations/")) {
        plan.change_types.push("data-migration".to_owned());
        plan.items.push(Item {
            id: "migration-runbook".to_owned(),
            kind: ItemKind::Operations,
            page: "docs/operations/migrations.md".to_owned(),
            form: Form::HowTo,
            audience: vec![Audience::Operators],
            sources: sources_of(&|path| path.starts_with("migrations/")),
            terms: Vec::new(),
            acceptance: vec![
                "Gives the steps to apply, verify and roll back the migration, and says what it does to downtime and data."
                    .to_owned(),
                "Has prerequisites, ordered steps, the expected result and a troubleshooting section."
                    .to_owned(),
            ],
        });
    }
    if paths.iter().any(|path| is_infrastructure(path)) {
        plan.change_types.push("infrastructure-change".to_owned());
        plan.items.push(Item {
            id: "operations-update".to_owned(),
            kind: ItemKind::Operations,
            page: first_page(
                &facts.existing_pages,
                &["docs/operations/deployment.md", "docs/deployment.md"],
                "docs/operations/deployment.md",
            ),
            form: Form::HowTo,
            audience: vec![Audience::Operators],
            sources: sources_of(&|path| {
                is_infrastructure(path)
            }),
            terms: Vec::new(),
            acceptance: vec![
                "Updates the deployment and configuration description and gives the rollback steps."
                    .to_owned(),
                "Has prerequisites, ordered steps, the expected result and a troubleshooting section."
                    .to_owned(),
            ],
        });
    }
    // Pages that already name a changed file must stay true, whatever else the change did.
    let mut named: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (file, pages) in &facts.documented {
        if paths.contains(&file.as_str()) {
            for page in pages.iter().filter(|page| writable(page)) {
                named.entry(page.as_str()).or_default().push(file.as_str());
            }
        }
    }
    for (page, files) in named {
        if plan.items.iter().any(|item| item.page == page) {
            continue;
        }
        plan.change_types.push("documented-file-changed".to_owned());
        plan.items.push(Item {
            id: format!("update-{}", slug(page)),
            kind: ItemKind::Update,
            page: page.to_owned(),
            form: Form::Explanation,
            audience: vec![Audience::Developers],
            sources: files.iter().map(|file| (*file).to_owned()).collect(),
            terms: Vec::new(),
            acceptance: vec![format!(
                "No sentence describes the old behaviour of {}.",
                files.join(", ")
            )],
        });
    }
    if let Some((page, acceptance)) = domain_addition(&facts.profile)
        && !code_sources.is_empty()
    {
        plan.change_types.push("domain-content".to_owned());
        plan.items.push(Item {
            id: format!("domain-{}", slug(&facts.profile)),
            kind: ItemKind::Domain,
            page: page.to_owned(),
            form: Form::Explanation,
            audience: vec![Audience::Developers, Audience::Operators],
            sources: code_sources.clone(),
            terms: Vec::new(),
            acceptance: vec![acceptance.to_owned()],
        });
    }
    // A change users can see, or one that breaks something, gets a changelog entry.
    if visible || plan.breaking {
        let mut terms: Vec<String> = plan.interface.new_flags.iter().cloned().collect();
        terms.extend(plan.interface.new_env.iter().cloned());
        terms.extend(plan.interface.removed_flags.iter().cloned());
        terms.extend(plan.interface.removed_env.iter().cloned());
        let mut acceptance = vec![
            "Has an entry for this change that names what users can now do or must now change."
                .to_owned(),
        ];
        if plan.breaking {
            acceptance.push("The entry is marked as breaking.".to_owned());
        }
        plan.items.push(Item {
            id: "changelog-entry".to_owned(),
            kind: ItemKind::Changelog,
            page: "CHANGELOG.md".to_owned(),
            form: Form::Changelog,
            audience: vec![Audience::EndUsers],
            sources: code_sources.clone(),
            terms,
            acceptance,
        });
    }

    if plan.items.is_empty() {
        plan.not_applicable = Some(if paths.iter().all(|path| is_test_or_build(path)) {
            not_applicable(
                "test-only-change",
                "Only tests or build scripts changed and no document names them.",
            )
        } else if paths
            .iter()
            .any(|path| path.ends_with("Cargo.toml") || path.ends_with("Cargo.lock"))
            && code_sources.is_empty()
        {
            not_applicable(
                "dependency-change-not-visible",
                "Only dependencies changed, no document names the manifest, and users cannot see the change.",
            )
        } else {
            not_applicable(
                "refactor-no-interface-change",
                "No command, flag, environment variable or public item changed and no document names a changed file.",
            )
        });
    }
    plan.change_types.sort();
    plan.change_types.dedup();
    plan
}

/// Content a domain adds to the documentation (policy 8.4): the page and what it must hold.
fn domain_addition(profile: &str) -> Option<(&'static str, &'static str)> {
    Some(match profile {
        "trading" => (
            "docs/explanation/trading.md",
            "States the instruments, the data lineage, the safeguards against look-ahead bias, the execution assumptions and the cost model.",
        ),
        "machine-learning" => (
            "docs/explanation/model.md",
            "States the dataset provenance, the split and leakage controls, the experiment configuration and seeds, and the known limits.",
        ),
        "valuation" => (
            "docs/explanation/valuation.md",
            "States the method, the sources with their dates, the assumptions and the limits of the result.",
        ),
        "games" => (
            "docs/explanation/game.md",
            "States the player controls, the gameplay systems and the supported hardware.",
        ),
        "workflow-engine" => (
            "docs/explanation/workflow.md",
            "States the state machine, the failure semantics, the retry rules and the recovery steps.",
        ),
        _ => return None,
    })
}

impl DocPlan {
    /// The plan as the typed document the stage stores under `documentation-plan`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let set = |values: &BTreeSet<String>| values.iter().cloned().collect::<Vec<_>>();
        let mut document = json!({
            "schema_version": 1,
            "kind": "documentation-plan",
            "base_commit": self.binding.base_commit,
            "code_head": self.binding.code_head,
            "specification_sha256": self.binding.specification_sha256,
            "applicable": self.not_applicable.is_none(),
            "change_types": self.change_types,
            "breaking": self.breaking,
            "program": self.program,
            "interface": {
                "new_flags": set(&self.interface.new_flags),
                "removed_flags": set(&self.interface.removed_flags),
                "new_env": set(&self.interface.new_env),
                "removed_env": set(&self.interface.removed_env),
                "new_api": set(&self.interface.new_api),
                "removed_api": set(&self.interface.removed_api),
            },
            "items": self.items.iter().map(|item| json!({
                "id": item.id,
                "kind": item.kind.as_str(),
                "page": item.page,
                "form": item.form.as_str(),
                "audience": item.audience.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
                "sources": item.sources,
                "terms": item.terms,
                "acceptance": item.acceptance,
                "owner": "documentation-writer",
            })).collect::<Vec<_>>(),
        });
        if let (Some(na), Some(map)) = (&self.not_applicable, document.as_object_mut()) {
            map.insert(
                "not_applicable".to_owned(),
                json!({ "rule": na.rule, "reason": na.reason }),
            );
        }
        document
    }
}

/// The schema of the stored plan, kept next to the code that writes it.
pub const SCHEMA: &str = include_str!("documentation-plan.v1.schema.json");

/// Why a plan document is refused. The path says where, and no document text is kept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the documentation plan breaks its schema at {0}")]
pub struct PlanError(pub String);

pub(crate) const ITEM_KINDS: [&str; 8] = [
    "usage",
    "reference",
    "changelog",
    "upgrade",
    "operations",
    "update",
    "check",
    "domain",
];
pub(crate) const FORMS: [&str; 5] = [
    "tutorial",
    "how-to",
    "reference",
    "explanation",
    "changelog",
];
pub(crate) const AUDIENCES: [&str; 4] = ["end-users", "developers", "operators", "integrators"];
pub(crate) const ROOT_REQUIRED: [&str; 11] = [
    "schema_version",
    "kind",
    "base_commit",
    "code_head",
    "specification_sha256",
    "applicable",
    "change_types",
    "breaking",
    "program",
    "interface",
    "items",
];
pub(crate) const ITEM_REQUIRED: [&str; 9] = [
    "id",
    "kind",
    "page",
    "form",
    "audience",
    "sources",
    "terms",
    "acceptance",
    "owner",
];

fn strings<'a>(value: &'a Value, at: &str) -> Result<Vec<&'a str>, PlanError> {
    let bad = || PlanError(at.to_owned());
    value
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|v| v.as_str().ok_or_else(bad))
        .collect()
}

fn commit(value: Option<&Value>, at: &str) -> Result<(), PlanError> {
    let ok = value
        .and_then(Value::as_str)
        .is_some_and(|c| c.len() == 40 && c.chars().all(|ch| ch.is_ascii_hexdigit()));
    ok.then_some(()).ok_or_else(|| PlanError(at.to_owned()))
}

impl DocPlan {
    /// Reads a stored plan.
    ///
    /// # Errors
    /// [`PlanError`] when the document breaks the schema.
    pub fn from_json(document: &Value) -> Result<Self, PlanError> {
        validate(document)?;
        let text = |value: &Value| value.as_str().unwrap_or("").to_owned();
        let list = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .map(|items| items.iter().map(&text).collect())
                .unwrap_or_default()
        };
        let set = |value: &Value| -> BTreeSet<String> { list(value).into_iter().collect() };
        let kind_of = |name: &str| {
            [
                ItemKind::Usage,
                ItemKind::Reference,
                ItemKind::Changelog,
                ItemKind::Upgrade,
                ItemKind::Operations,
                ItemKind::Update,
                ItemKind::Check,
                ItemKind::Domain,
            ]
            .into_iter()
            .find(|kind| kind.as_str() == name)
            .unwrap_or(ItemKind::Check)
        };
        let form_of = |name: &str| {
            [
                Form::Tutorial,
                Form::HowTo,
                Form::Reference,
                Form::Explanation,
                Form::Changelog,
            ]
            .into_iter()
            .find(|form| form.as_str() == name)
            .unwrap_or(Form::Explanation)
        };
        let audience_of = |name: &str| {
            [
                Audience::EndUsers,
                Audience::Developers,
                Audience::Operators,
                Audience::Integrators,
            ]
            .into_iter()
            .find(|audience| audience.as_str() == name)
            .unwrap_or(Audience::Developers)
        };
        let interface = &document["interface"];
        let items = document["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| Item {
                        id: text(&item["id"]),
                        kind: kind_of(item["kind"].as_str().unwrap_or("")),
                        page: text(&item["page"]),
                        form: form_of(item["form"].as_str().unwrap_or("")),
                        audience: list(&item["audience"])
                            .iter()
                            .map(|name| audience_of(name))
                            .collect(),
                        sources: list(&item["sources"]),
                        terms: list(&item["terms"]),
                        acceptance: list(&item["acceptance"]),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            binding: Binding {
                base_commit: text(&document["base_commit"]),
                code_head: text(&document["code_head"]),
                specification_sha256: text(&document["specification_sha256"]),
            },
            change_types: list(&document["change_types"]),
            interface: Interface {
                new_flags: set(&interface["new_flags"]),
                removed_flags: set(&interface["removed_flags"]),
                new_env: set(&interface["new_env"]),
                removed_env: set(&interface["removed_env"]),
                new_api: set(&interface["new_api"]),
                removed_api: set(&interface["removed_api"]),
            },
            program: document["program"].as_str().map(str::to_owned),
            breaking: document["breaking"].as_bool().unwrap_or(false),
            items,
            not_applicable: document.get("not_applicable").map(|rule| NotApplicable {
                rule: text(&rule["rule"]),
                reason: text(&rule["reason"]),
            }),
        })
    }
}

/// Checks a stored plan against its schema (`documentation-plan.v1.schema.json`).
///
/// # Errors
/// [`PlanError`] naming the first field that breaks the schema.
pub fn validate(document: &Value) -> Result<(), PlanError> {
    let root = document.as_object().ok_or_else(|| PlanError("/".into()))?;
    for name in ROOT_REQUIRED {
        if !root.contains_key(name) {
            return Err(PlanError(format!("/{name}")));
        }
    }
    if root.get("schema_version") != Some(&json!(1)) {
        return Err(PlanError("/schema_version".into()));
    }
    if root.get("kind") != Some(&json!("documentation-plan")) {
        return Err(PlanError("/kind".into()));
    }
    commit(root.get("base_commit"), "/base_commit")?;
    commit(root.get("code_head"), "/code_head")?;
    let spec_ok = root
        .get("specification_sha256")
        .and_then(Value::as_str)
        .is_some_and(|s| s.starts_with("sha256:") && s.len() == 71);
    if !spec_ok {
        return Err(PlanError("/specification_sha256".into()));
    }
    let applicable = root
        .get("applicable")
        .and_then(Value::as_bool)
        .ok_or_else(|| PlanError("/applicable".into()))?;
    if root.get("breaking").and_then(Value::as_bool).is_none() {
        return Err(PlanError("/breaking".into()));
    }
    strings(&root["change_types"], "/change_types")?;
    if !(root["program"].is_null() || root["program"].is_string()) {
        return Err(PlanError("/program".into()));
    }
    let interface = root["interface"]
        .as_object()
        .ok_or_else(|| PlanError("/interface".into()))?;
    for name in [
        "new_flags",
        "removed_flags",
        "new_env",
        "removed_env",
        "new_api",
        "removed_api",
    ] {
        strings(
            interface
                .get(name)
                .ok_or_else(|| PlanError(format!("/interface/{name}")))?,
            &format!("/interface/{name}"),
        )?;
    }
    let items = root["items"]
        .as_array()
        .ok_or_else(|| PlanError("/items".into()))?;
    for (index, item) in items.iter().enumerate() {
        let at = |name: &str| format!("/items/{index}/{name}");
        let object = item.as_object().ok_or_else(|| PlanError(at("")))?;
        for name in ITEM_REQUIRED {
            if !object.contains_key(name) {
                return Err(PlanError(at(name)));
            }
        }
        let one_of = |name: &str, allowed: &[&str]| -> Result<(), PlanError> {
            object[name]
                .as_str()
                .filter(|v| allowed.contains(v))
                .map(|_| ())
                .ok_or_else(|| PlanError(at(name)))
        };
        one_of("kind", &ITEM_KINDS)?;
        one_of("form", &FORMS)?;
        one_of("owner", &["documentation-writer"])?;
        if object["id"].as_str().is_none_or(str::is_empty) {
            return Err(PlanError(at("id")));
        }
        let page = object["page"].as_str().unwrap_or("");
        let shaped = page.ends_with(".md")
            && !page.starts_with('/')
            && !page.split('/').any(|part| part == ".." || part.is_empty())
            && page
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c));
        if !shaped || (object["kind"] != "check" && !writable(page)) {
            return Err(PlanError(at("page")));
        }
        for name in ["audience", "sources", "terms", "acceptance"] {
            strings(&object[name], &at(name))?;
        }
        let audience = strings(&object["audience"], &at("audience"))?;
        if audience.is_empty() || audience.iter().any(|a| !AUDIENCES.contains(a)) {
            return Err(PlanError(at("audience")));
        }
        if strings(&object["acceptance"], &at("acceptance"))?.is_empty() {
            return Err(PlanError(at("acceptance")));
        }
    }
    // A plan that is not applicable carries its rule and no pages. One that is carries pages.
    match (applicable, root.get("not_applicable")) {
        (false, Some(rule)) => {
            let rule_ok = rule
                .get("rule")
                .and_then(Value::as_str)
                .is_some_and(|r| !r.is_empty())
                && rule
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(|r| !r.is_empty());
            if !rule_ok || !items.is_empty() {
                return Err(PlanError("/not_applicable".into()));
            }
        }
        (true, None) if !items.is_empty() => {}
        _ => return Err(PlanError("/applicable".into())),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            base_commit: "a".repeat(40),
            code_head: "b".repeat(40),
            specification_sha256: format!("sha256:{}", "c".repeat(64)),
        }
    }

    fn file(path: &str, kind: Kind, added: &[&str], removed: &[&str]) -> ChangedFile {
        ChangedFile {
            path: path.to_owned(),
            kind,
            added: added.iter().map(|s| (*s).to_owned()).collect(),
            removed: removed.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn facts(changed: Vec<ChangedFile>) -> Facts {
        Facts {
            changed,
            existing_pages: ["README.md".to_owned()].into(),
            program: Some("wc-rs".to_owned()),
            profile: "rust-command-line-tool".to_owned(),
            ..Facts::default()
        }
    }

    #[test]
    fn a_patch_is_read_into_files_with_their_lines() {
        let patch = "diff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1,1 +1,2 @@\n-old\n+new\n+--not-a-header\ndiff --git a/README.md b/README.md\nnew file mode 100644\n--- /dev/null\n+++ b/README.md\n@@ -0,0 +1,1 @@\n+# Title\n";
        let files = parse_patch(patch);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].added, ["new", "--not-a-header"]);
        assert_eq!(files[0].removed, ["old"]);
        assert_eq!(files[1].kind, Kind::Added);
    }

    #[test]
    fn a_new_flag_needs_usage_text_and_a_changelog_entry_and_nothing_more() {
        let plan = derive(
            &facts(vec![file(
                "src/main.rs",
                Kind::Modified,
                &["    let json = args.any(|a| a == \"--json\");"],
                &[],
            )]),
            binding(),
        );
        assert_eq!(plan.not_applicable, None);
        let kinds: Vec<ItemKind> = plan.items.iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [ItemKind::Usage, ItemKind::Changelog]);
        assert_eq!(plan.items[0].terms, ["--json"]);
        assert_eq!(plan.items[0].page, "README.md");
        assert!(!plan.breaking);
        assert_eq!(plan.change_types, ["new-cli-flag"]);
    }

    #[test]
    fn a_pure_refactor_is_not_applicable_with_the_rule_recorded() {
        let plan = derive(
            &facts(vec![file(
                "src/output.rs",
                Kind::Modified,
                &["    let total = a + b;"],
                &["    let total = b + a;"],
            )]),
            binding(),
        );
        assert!(plan.items.is_empty());
        let na = plan.not_applicable.expect("a rule");
        assert_eq!(na.rule, "refactor-no-interface-change");
    }

    #[test]
    fn a_refactor_that_a_page_names_updates_that_page_only() {
        let mut facts = facts(vec![file("src/output.rs", Kind::Modified, &["x"], &["y"])]);
        facts.documented.insert(
            "src/output.rs".to_owned(),
            ["docs/layout.md".to_owned()].into(),
        );
        let plan = derive(&facts, binding());
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].page, "docs/layout.md");
        assert_eq!(plan.items[0].kind, ItemKind::Update);
    }

    #[test]
    fn a_removed_flag_is_breaking_and_needs_an_upgrade_note_and_a_marked_changelog_entry() {
        let plan = derive(
            &facts(vec![file(
                "src/main.rs",
                Kind::Modified,
                &[],
                &["    if a == \"--verbose\" {"],
            )]),
            binding(),
        );
        assert!(plan.breaking);
        let kinds: Vec<ItemKind> = plan.items.iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [ItemKind::Upgrade, ItemKind::Changelog]);
        assert!(
            plan.items[1]
                .acceptance
                .iter()
                .any(|a| a.contains("breaking"))
        );
    }

    #[test]
    fn an_environment_variable_needs_a_configuration_entry() {
        let plan = derive(
            &facts(vec![file(
                "src/main.rs",
                Kind::Modified,
                &["    let w = std::env::var(\"WC_WIDTH\");"],
                &[],
            )]),
            binding(),
        );
        assert!(plan.items.iter().any(|i| i.terms == ["WC_WIDTH"]));
    }

    #[test]
    fn a_test_only_change_is_not_applicable() {
        let plan = derive(
            &facts(vec![file("tests/a.rs", Kind::Added, &["fn t() {}"], &[])]),
            binding(),
        );
        assert_eq!(
            plan.not_applicable.map(|n| n.rule),
            Some("test-only-change".to_owned())
        );
    }

    #[test]
    fn a_documentation_only_change_checks_the_changed_pages() {
        let plan = derive(
            &facts(vec![file("docs/guide.md", Kind::Modified, &["x"], &[])]),
            binding(),
        );
        assert_eq!(plan.not_applicable, None);
        assert!(!plan.needs_writing());
        assert_eq!(plan.items[0].kind, ItemKind::Check);
    }

    #[test]
    fn a_migration_and_a_deployment_change_need_operations_pages() {
        let plan = derive(
            &facts(vec![
                file(
                    "migrations/001_add.sql",
                    Kind::Added,
                    &["create table t;"],
                    &[],
                ),
                file("infra/compose.yaml", Kind::Modified, &["x"], &[]),
            ]),
            binding(),
        );
        let pages = plan.pages();
        assert!(pages.contains("docs/operations/migrations.md"));
        assert!(pages.contains("docs/operations/deployment.md"));
    }

    #[test]
    fn every_derived_plan_matches_its_schema() {
        let cases = [
            vec![file("src/main.rs", Kind::Modified, &["\"--json\""], &[])],
            vec![file("src/output.rs", Kind::Modified, &["a"], &["b"])],
            vec![file("src/main.rs", Kind::Modified, &[], &["\"--old\""])],
            vec![file("docs/a.md", Kind::Modified, &["x"], &[])],
        ];
        for changed in cases {
            let plan = derive(&facts(changed), binding());
            validate(&plan.to_json()).expect("the plan follows its schema");
        }
    }

    #[test]
    fn the_validator_and_the_schema_file_name_the_same_fields() {
        let schema: Value = serde_json::from_str(SCHEMA).expect("the schema parses");
        let required = |value: &Value| -> Vec<String> {
            value["required"]
                .as_array()
                .expect("a list")
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        };
        assert_eq!(required(&schema), ROOT_REQUIRED);
        let item = &schema["$defs"]["item"];
        assert_eq!(required(item), ITEM_REQUIRED);
        let listed = |value: &Value| -> Vec<String> {
            value["enum"]
                .as_array()
                .expect("an enum")
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        };
        assert_eq!(listed(&item["properties"]["kind"]), ITEM_KINDS);
        assert_eq!(listed(&item["properties"]["form"]), FORMS);
        assert_eq!(listed(&schema["$defs"]["audience"]), AUDIENCES);
    }

    #[test]
    fn a_plan_survives_a_round_trip_through_its_document() {
        let plan = derive(
            &facts(vec![file(
                "src/main.rs",
                Kind::Modified,
                &["\"--json\""],
                &[],
            )]),
            binding(),
        );
        let again = DocPlan::from_json(&plan.to_json()).expect("it reads back");
        assert_eq!(again, plan);
    }

    #[test]
    fn a_plan_that_breaks_its_schema_is_refused() {
        let plan = derive(
            &facts(vec![file(
                "src/main.rs",
                Kind::Modified,
                &["\"--json\""],
                &[],
            )]),
            binding(),
        );
        let good = plan.to_json();
        let mut missing = good.clone();
        missing.as_object_mut().expect("an object").remove("items");
        assert!(validate(&missing).is_err());
        let mut wrong_kind = good.clone();
        wrong_kind["items"][0]["kind"] = json!("poem");
        assert!(validate(&wrong_kind).is_err());
        let mut outside = good.clone();
        outside["items"][0]["page"] = json!("src/main.rs");
        assert!(validate(&outside).is_err());
        let mut bad_commit = good;
        bad_commit["code_head"] = json!("not-a-commit");
        assert!(validate(&bad_commit).is_err());
    }
}
