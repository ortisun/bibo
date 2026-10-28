//! The checks that read the fixture as files. Each takes the fixture directory and returns the
//! findings, which are empty when the rule holds.

use std::fs;
use std::path::Path;

use factory_contracts::loader::{DefinitionFormat, DefinitionLoader};
use factory_domain::redaction::{PatternAction, Redactor};

use crate::Finding;
use crate::workdir::list_files;

/// The files the fixture must have.
pub const REQUIRED_FILES: [&str; 12] = [
    "Cargo.toml",
    "Cargo.lock",
    "README.md",
    "CHANGELOG.md",
    "CODEOWNERS",
    ".factory/project.yaml",
    "src/lib.rs",
    "src/main.rs",
    "tests/plain_output.rs",
    "tests/cli_usage.rs",
    "tests/golden/sample.txt",
    "tests/golden/sample.plain.txt",
];

/// Files and directories that must not exist: they would make the build depend on more than the
/// source (a build script, a cargo configuration that can redirect the build, a nested checkout).
pub const FORBIDDEN_FILES: [&str; 5] = [
    "build.rs",
    ".cargo/config.toml",
    ".cargo/config",
    "vendor/config.toml",
    "rust-project.json",
];

/// The gate identifiers the fixture declares, and which of them are mandatory.
pub const GATES: [(&str, bool); 4] = [
    ("format", false),
    ("lint", false),
    ("build", true),
    ("unit-tests", true),
];

/// The paths the manifest must protect.
pub const PROTECTED: [&str; 3] = [".factory/**", "CODEOWNERS", "tests/golden/**"];

fn read(dir: &Path, relative: &str) -> Result<String, Finding> {
    fs::read_to_string(dir.join(relative))
        .map_err(|error| Finding::new("layout", format!("cannot read {relative}: {error}")))
}

/// The files exist, and the things that must not exist do not.
#[must_use]
pub fn layout(dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for required in REQUIRED_FILES {
        if !dir.join(required).is_file() {
            findings.push(Finding::new("layout", format!("{required} is missing")));
        }
    }
    for forbidden in FORBIDDEN_FILES {
        if dir.join(forbidden).exists() {
            findings.push(Finding::new(
                "layout",
                format!("{forbidden} must not exist in the fixture"),
            ));
        }
    }
    if dir.join(".git").exists() {
        findings.push(Finding::new("layout", "the fixture holds a .git entry"));
    }
    findings
}

/// The project has no dependency of any kind, is its own workspace root, and its lock file lists
/// the project and nothing else. That is what lets it build with no network.
#[must_use]
pub fn no_dependencies(dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    match read(dir, "Cargo.toml") {
        Err(finding) => findings.push(finding),
        Ok(manifest) => {
            let mut section = String::new();
            let mut has_workspace_table = false;
            for line in manifest.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(header) = line.strip_prefix('[') {
                    section = header.trim_end_matches(']').trim().to_owned();
                    if section == "workspace" {
                        has_workspace_table = true;
                    }
                    continue;
                }
                let is_dependency_table = section == "dependencies"
                    || section == "dev-dependencies"
                    || section == "build-dependencies"
                    || (section.starts_with("target.") && section.ends_with("dependencies"))
                    || section.starts_with("dependencies.")
                    || section.starts_with("dev-dependencies.")
                    || section.starts_with("build-dependencies.");
                if is_dependency_table {
                    findings.push(Finding::new(
                        "no_dependencies",
                        format!("Cargo.toml lists a dependency under [{section}]: {line}"),
                    ));
                }
                if section == "package"
                    && (line.starts_with("build ") || line.starts_with("build="))
                {
                    findings.push(Finding::new(
                        "no_dependencies",
                        "Cargo.toml names a build script",
                    ));
                }
            }
            if !has_workspace_table {
                findings.push(Finding::new(
                    "no_dependencies",
                    "Cargo.toml has no [workspace] table, so Cargo looks upward for a workspace and finds the factory's",
                ));
            }
        }
    }
    match read(dir, "Cargo.lock") {
        Err(finding) => findings.push(finding),
        Ok(lock) => {
            let packages = lock.matches("[[package]]").count();
            if packages != 1 {
                findings.push(Finding::new(
                    "no_dependencies",
                    format!("Cargo.lock lists {packages} packages; it must list only the project"),
                ));
            }
            if lock.contains("source = ") || lock.contains("checksum = ") {
                findings.push(Finding::new(
                    "no_dependencies",
                    "Cargo.lock names a package from a registry or a repository",
                ));
            }
        }
    }
    findings
}

/// The package name in `Cargo.toml`.
fn package_name(dir: &Path) -> Option<String> {
    let manifest = fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let mut in_package = false;
    for line in manifest.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('[') {
            in_package = header.trim_end_matches(']').trim() == "package";
        } else if in_package && let Some(rest) = line.strip_prefix("name") {
            let value = rest.trim_start().strip_prefix('=')?.trim();
            return Some(value.trim_matches('"').to_owned());
        }
    }
    None
}

/// `.factory/project.yaml` loads through the same loader and schema the intake stage uses, and says
/// what the end-to-end run relies on: the gate commands, the protected paths, the documents.
#[must_use]
pub fn manifest(dir: &Path) -> Vec<Finding> {
    let bytes = match fs::read(dir.join(".factory/project.yaml")) {
        Ok(bytes) => bytes,
        Err(error) => {
            return vec![Finding::new(
                "manifest",
                format!("cannot read .factory/project.yaml: {error}"),
            )];
        }
    };
    let loader = match DefinitionLoader::new() {
        Ok(loader) => loader,
        Err(error) => {
            return vec![Finding::new(
                "manifest",
                format!("the schema engine did not start: {error:?}"),
            )];
        }
    };
    let loaded = loader.project_manifest(".factory/project.yaml", DefinitionFormat::Yaml, &bytes);
    let manifest = match loaded {
        Ok(manifest) => manifest,
        Err(error) => {
            return vec![Finding::new(
                "manifest",
                format!("the loader refused the manifest: {error}"),
            )];
        }
    };
    let mut findings = Vec::new();
    match package_name(dir) {
        Some(name) if name == manifest.project.name.as_str() => {}
        other => findings.push(Finding::new(
            "manifest",
            format!(
                "project.name is {}, but the Cargo package is {other:?}",
                manifest.project.name.as_str()
            ),
        )),
    }
    for (id, mandatory) in GATES {
        match manifest.gates.iter().find(|gate| gate.id.as_str() == id) {
            None => findings.push(Finding::new("manifest", format!("gate {id} is missing"))),
            Some(gate) => {
                if gate.mandatory != mandatory {
                    findings.push(Finding::new(
                        "manifest",
                        format!("gate {id} must have mandatory = {mandatory}"),
                    ));
                }
                if gate.argv.first().map(String::as_str) != Some("cargo") {
                    findings.push(Finding::new(
                        "manifest",
                        format!("gate {id} must run cargo"),
                    ));
                }
            }
        }
    }
    for gate in &manifest.gates {
        if !GATES.iter().any(|(id, _)| *id == gate.id.as_str()) {
            findings.push(Finding::new(
                "manifest",
                format!("gate {} is not one the fixture declares", gate.id.as_str()),
            ));
        }
    }
    for path in PROTECTED {
        if !manifest
            .protected_paths
            .iter()
            .any(|protected| protected.as_str() == path)
        {
            findings.push(Finding::new(
                "manifest",
                format!("{path} is not a protected path"),
            ));
        }
    }
    for document in &manifest.documentation.required_documents {
        if !dir.join(document.path.as_str()).is_file() {
            findings.push(Finding::new(
                "manifest",
                format!(
                    "the required document {} does not exist",
                    document.path.as_str()
                ),
            ));
        }
    }
    if !dir
        .join(manifest.documentation.changelog_path.as_str())
        .is_file()
    {
        findings.push(Finding::new("manifest", "the changelog does not exist"));
    }
    findings
}

/// `CODEOWNERS` has a catch-all rule and covers the paths the manifest protects.
#[must_use]
pub fn codeowners(dir: &Path) -> Vec<Finding> {
    let text = match read(dir, "CODEOWNERS") {
        Ok(text) => text,
        Err(finding) => return vec![finding],
    };
    let patterns: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let mut findings = Vec::new();
    for rule in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if rule.split_whitespace().count() < 2 {
            findings.push(Finding::new(
                "codeowners",
                format!("the rule '{rule}' names no owner"),
            ));
        }
    }
    for needed in ["*", "/.factory/", "/CODEOWNERS", "/tests/golden/"] {
        if !patterns.contains(&needed) {
            findings.push(Finding::new("codeowners", format!("no rule for {needed}")));
        }
    }
    findings
}

/// The patterns the secret scan looks for. They are written as regular expressions, not as
/// examples, so this file holds nothing that looks like a secret.
const SECRET_SHAPES: [(&str, &str); 8] = [
    ("github-token", "gh[pousr]_[A-Za-z0-9]{30,}"),
    ("github-fine-grained", "github_pat_[A-Za-z0-9_]{20,}"),
    ("aws-access-key", "AKIA[0-9A-Z]{16}"),
    ("private-key", "-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("provider-key", "sk-[A-Za-z0-9_-]{20,}"),
    ("slack-token", "xox[baprs]-[A-Za-z0-9-]{10,}"),
    (
        "bearer-jwt",
        "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
    ),
    (
        "assigned-credential",
        "(?i)(password|secret|api[_-]?key|token)[\"']?\\s*[:=]\\s*[\"'][A-Za-z0-9/+_=-]{16,}[\"']",
    ),
];

/// No file of the fixture holds text in the shape of a secret.
#[must_use]
pub fn no_secrets(dir: &Path) -> Vec<Finding> {
    let mut builder = Redactor::builder();
    for (id, regex) in SECRET_SHAPES {
        builder = builder.pattern(id, regex, PatternAction::Block);
    }
    let redactor = match builder.build() {
        Ok(redactor) => redactor,
        Err(error) => {
            return vec![Finding::new(
                "no_secrets",
                format!("the scanner did not build: {error:?}"),
            )];
        }
    };
    let files = match list_files(dir) {
        Ok(files) => files,
        Err(error) => {
            return vec![Finding::new(
                "no_secrets",
                format!("cannot list files: {error}"),
            )];
        }
    };
    let mut findings = Vec::new();
    for file in files {
        let Ok(bytes) = fs::read(dir.join(&file)) else {
            findings.push(Finding::new("no_secrets", format!("cannot read {file}")));
            continue;
        };
        match redactor.scan(&bytes) {
            Ok(report) => {
                for id in report.ids() {
                    findings.push(Finding::new(
                        "no_secrets",
                        format!("{file} has text in the shape of a secret ({id})"),
                    ));
                }
            }
            Err(error) => findings.push(Finding::new(
                "no_secrets",
                format!("{file} could not be scanned: {error:?}"),
            )),
        }
    }
    findings
}

/// What the README says, read from its Markdown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadmeFacts {
    /// Every command-line option in an options table, such as `--help`.
    pub options: Vec<String>,
    /// Every `cargo` subcommand in a `sh` block.
    pub cargo_subcommands: Vec<String>,
    /// Every line of a `text` block that is a row of counts (an example of the output).
    pub output_lines: Vec<String>,
}

/// Reads the facts out of the README text.
#[must_use]
pub fn readme_facts(readme: &str) -> ReadmeFacts {
    let mut facts = ReadmeFacts::default();
    let mut fence: Option<String> = None;
    for line in readme.lines() {
        if let Some(rest) = line.strip_prefix("```") {
            fence = match fence {
                Some(_) => None,
                None => Some(rest.trim().to_owned()),
            };
            continue;
        }
        match fence.as_deref() {
            Some("sh") => {
                let mut words = line.split_whitespace();
                if words.next() == Some("cargo")
                    && let Some(sub) = words.next()
                {
                    facts.cargo_subcommands.push(sub.to_owned());
                }
            }
            Some("text") => {
                let numbers = line
                    .split_whitespace()
                    .take(3)
                    .filter(|word| word.chars().all(|c| c.is_ascii_digit()))
                    .count();
                if numbers == 3 {
                    facts.output_lines.push(line.to_owned());
                }
            }
            Some(_) => {}
            None => {
                if line.starts_with('|') {
                    let first_cell = line.split('|').nth(1).unwrap_or_default();
                    for part in first_cell.split(',') {
                        let part = part.trim().trim_matches('`');
                        if part.starts_with('-') && !part.starts_with("---") {
                            facts.options.push(part.to_owned());
                        }
                    }
                }
            }
        }
    }
    facts
}

/// The options named in the help text of the tool.
#[must_use]
pub fn help_options(help: &str) -> Vec<String> {
    let mut options = Vec::new();
    for line in help.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('-') {
            continue;
        }
        let head = trimmed.split("  ").next().unwrap_or_default();
        for part in head.split(',') {
            let part = part.trim();
            if part.starts_with('-') {
                options.push(part.to_owned());
            }
        }
    }
    options
}

/// The README documents exactly the options the real tool has, uses only cargo subcommands that the
/// manifest's gates run, and every example output line is one the tool prints.
///
/// `help` is the output of `word-count --help`. `real_outputs` are the lines the real binary printed
/// for the inputs the README's examples use.
#[must_use]
pub fn readme_matches_reality(dir: &Path, help: &str, real_outputs: &[String]) -> Vec<Finding> {
    let readme = match read(dir, "README.md") {
        Ok(text) => text,
        Err(finding) => return vec![finding],
    };
    let facts = readme_facts(&readme);
    let real = help_options(help);
    let mut findings = Vec::new();
    for option in &facts.options {
        if !real.contains(option) {
            findings.push(Finding::new(
                "readme",
                format!("the README documents {option}, but the tool does not have it"),
            ));
        }
    }
    for option in &real {
        if !facts.options.contains(option) {
            findings.push(Finding::new(
                "readme",
                format!("the tool has {option}, but the README does not document it"),
            ));
        }
    }
    for sub in &facts.cargo_subcommands {
        if !["build", "test", "clippy", "fmt"].contains(&sub.as_str()) {
            findings.push(Finding::new(
                "readme",
                format!("the README runs `cargo {sub}`, which no gate of the manifest runs"),
            ));
        }
    }
    for line in &facts.output_lines {
        if !real_outputs.iter().any(|real| real == line) {
            findings.push(Finding::new(
                "readme",
                format!("the README shows the output '{line}', which the tool does not print"),
            ));
        }
    }
    if facts.output_lines.is_empty() {
        findings.push(Finding::new("readme", "the README shows no example output"));
    }
    findings
}

/// The deliberate gap is still there: the tool has no JSON output, and the files that the planned
/// change adds do not exist. (The run of `--json` itself is checked in [`crate::exec`].)
#[must_use]
pub fn gap_files(dir: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for file in ["src/output.rs", "tests/json_output.rs", "tests/errors.rs"] {
        if dir.join(file).exists() {
            findings.push(Finding::new(
                "gap",
                format!("{file} exists, so the planned change is already (partly) made"),
            ));
        }
    }
    for file in ["src/main.rs", "src/lib.rs", "README.md", "CHANGELOG.md"] {
        if let Ok(text) = fs::read_to_string(dir.join(file))
            && text.to_ascii_lowercase().contains("json")
        {
            findings.push(Finding::new(
                "gap",
                format!("{file} already mentions JSON, so the gap is not open"),
            ));
        }
    }
    findings
}

/// Runs every file-reading check and returns all findings, in a fixed order.
#[must_use]
pub fn all_static(dir: &Path) -> Vec<Finding> {
    let mut findings = layout(dir);
    findings.extend(no_dependencies(dir));
    findings.extend(manifest(dir));
    findings.extend(codeowners(dir));
    findings.extend(no_secrets(dir));
    findings.extend(gap_files(dir));
    findings
}
