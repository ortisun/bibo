//! Command line: argument parsing, the order of the checks, and the exit code.
//!
//! Exit codes: 0 when every rule holds, 1 when a rule is broken, 2 when the check could not run
//! (bad arguments, an unreadable rules file, or `cargo metadata` failing).

use crate::clippy_bans;
use crate::finding::Finding;
use crate::generated;
use crate::invariants;
use crate::links;
use crate::lints;
use crate::metadata;
use crate::rules::Rules;
use crate::static_checks;
use crate::topology;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const USAGE: &str = "usage:
  cargo xtask check-architecture [--manifest-path PATH] [--rules PATH]
  cargo xtask check-links [--root PATH] [--rules PATH]
  cargo xtask check-invariants [--root PATH] [--register PATH]
  cargo xtask check-generated [--root PATH] [--rules PATH]
  cargo xtask clippy-toml

check-links fails when a relative link in a Markdown file points at a file or heading that does
not exist. check-invariants fails when an invariant of docs/architecture/state-machine.json is
named by no test and no marker under crates/. check-generated runs the --check command of each
generated file listed in the rules file (python3 is needed). All three exit with 0, 1 (a
finding) or 2 (could not run).

check-architecture fails when the rules file lists a crate or binary that the workspace lacks.
Options:
  --manifest-path PATH    the workspace Cargo.toml to check (default: this repository)
  --rules PATH            the rules file (default: docs/architecture/crate-dependency-rules.json)
  --require-all-crates    the default, accepted so that older commands keep working
  --allow-missing-crates  do not fail on missing crates (for the tests of xtask itself)

clippy-toml prints the ban list (DEP-05) that domain, ports, workflow and spec_adapter keep in
their own clippy.toml, for example: cargo xtask clippy-toml > crates/domain/clippy.toml";

pub fn run(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("check-architecture") => match CheckArgs::parse(&args[1..]) {
            Ok(parsed) => check_architecture(&parsed),
            Err(message) => fail_to_run(&message),
        },
        Some("check-links") => with_tool_args(&args[1..], check_links),
        Some("check-invariants") => with_tool_args(&args[1..], check_invariants),
        Some("check-generated") => with_tool_args(&args[1..], check_generated),
        Some("clippy-toml") => {
            print!("{}", clippy_bans::render_clippy_toml());
            0
        }
        Some("help" | "--help" | "-h") | None => {
            println!("{USAGE}");
            0
        }
        Some(other) => fail_to_run(&format!("unknown command {other:?}")),
    }
}

fn fail_to_run(message: &str) -> i32 {
    eprintln!("error: {message}\n\n{USAGE}");
    2
}

/// The options of the three small commands.
struct ToolArgs {
    root: PathBuf,
    rules: PathBuf,
    register: PathBuf,
}

fn with_tool_args(args: &[String], command: fn(&ToolArgs) -> i32) -> i32 {
    let root = repository_root();
    let mut parsed = ToolArgs {
        rules: root.join("docs/architecture/crate-dependency-rules.json"),
        register: root.join("docs/architecture/state-machine.json"),
        root,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let target = match arg.as_str() {
            "--root" => &mut parsed.root,
            "--rules" => &mut parsed.rules,
            "--register" => &mut parsed.register,
            other => return fail_to_run(&format!("unknown option {other:?}")),
        };
        match value(&mut rest, arg) {
            Ok(path) => *target = path,
            Err(message) => return fail_to_run(&message),
        }
    }
    command(&parsed)
}

fn print_findings(findings: &[Finding]) {
    for finding in findings {
        eprintln!("{finding}");
    }
}

fn check_links(args: &ToolArgs) -> i32 {
    let rules = match Rules::load(&args.rules) {
        Ok(rules) => rules,
        Err(message) => return fail_to_run(&message),
    };
    match links::check(&args.root, &rules.source_scans.st_01.skipped_directories) {
        Err(message) => fail_to_run(&message),
        Ok((files, links, findings)) if findings.is_empty() => {
            println!(
                "link check passed: {links} link(s) in {files} Markdown file(s), every relative one resolves"
            );
            0
        }
        Ok((files, links, findings)) => {
            print_findings(&findings);
            eprintln!(
                "\n{} dead link(s) among {links} link(s) in {files} Markdown file(s)",
                findings.len()
            );
            1
        }
    }
}

fn check_invariants(args: &ToolArgs) -> i32 {
    match invariants::check(&args.root, &args.register) {
        Err(message) => fail_to_run(&message),
        Ok((ids, findings)) if findings.is_empty() => {
            println!(
                "invariant register check passed: all {} invariants are named",
                ids.len()
            );
            0
        }
        Ok((ids, findings)) => {
            print_findings(&findings);
            eprintln!(
                "\n{} of {} invariants have no test or marker that names them",
                findings.len(),
                ids.len()
            );
            1
        }
    }
}

fn check_generated(args: &ToolArgs) -> i32 {
    let rules = match Rules::load(&args.rules) {
        Ok(rules) => rules,
        Err(message) => return fail_to_run(&message),
    };
    let mut stale = Vec::new();
    let mut blocked = Vec::new();
    for artifact in &rules.source_scans.generated_artifacts {
        match generated::run(&args.root, artifact) {
            generated::Outcome::Current => println!("current: {}", artifact.name),
            generated::Outcome::Stale(finding) => stale.push(finding),
            generated::Outcome::Blocked(message) => blocked.push(message),
        }
    }
    print_findings(&stale);
    if let Some(message) = blocked.first() {
        return fail_to_run(&format!("BLOCKED, no evidence either way: {message}"));
    }
    i32::from(!stale.is_empty())
}

struct CheckArgs {
    manifest_path: PathBuf,
    rules_path: PathBuf,
    allow_missing_crates: bool,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

impl CheckArgs {
    fn parse(args: &[String]) -> Result<Self, String> {
        let root = repository_root();
        let mut parsed = Self {
            manifest_path: root.join("Cargo.toml"),
            rules_path: root.join("docs/architecture/crate-dependency-rules.json"),
            allow_missing_crates: false,
        };
        let mut explicitly_required = false;
        let mut rest = args.iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--manifest-path" => parsed.manifest_path = value(&mut rest, arg)?,
                "--rules" => parsed.rules_path = value(&mut rest, arg)?,
                "--require-all-crates" => explicitly_required = true,
                "--allow-missing-crates" => parsed.allow_missing_crates = true,
                other => return Err(format!("unknown option {other:?}")),
            }
        }
        if explicitly_required && parsed.allow_missing_crates {
            return Err(
                "--require-all-crates and --allow-missing-crates contradict each other".to_string(),
            );
        }
        Ok(parsed)
    }
}

fn value<'a>(rest: &mut impl Iterator<Item = &'a String>, option: &str) -> Result<PathBuf, String> {
    rest.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{option} needs a value"))
}

fn check_architecture(args: &CheckArgs) -> i32 {
    let rules = match Rules::load(&args.rules_path) {
        Ok(rules) => rules,
        Err(message) => return fail_to_run(&message),
    };
    let workspace = match metadata::load(&args.manifest_path) {
        Ok(workspace) => workspace,
        Err(message) => return fail_to_run(&message),
    };

    let mut findings = topology::check(
        &rules,
        &workspace,
        topology::Options {
            allow_missing_crates: args.allow_missing_crates,
        },
    );
    findings.extend(lints::check(&rules, &workspace));
    findings.extend(clippy_bans::check(&rules, &workspace));
    match clippy_bans::check_silencing(&rules, &workspace) {
        Ok(more) => findings.extend(more),
        Err(message) => return fail_to_run(&message),
    }
    match static_checks::check(&rules, &workspace) {
        Ok(more) => findings.extend(more),
        Err(message) => return fail_to_run(&message),
    }
    findings.sort_by(|a, b| {
        (&a.rule, &a.location, &a.message).cmp(&(&b.rule, &b.location, &b.message))
    });
    findings.dedup();

    if findings.is_empty() {
        let names: Vec<&str> = workspace.members.iter().map(|m| m.name.as_str()).collect();
        println!(
            "architecture check passed: {} workspace package(s): {}",
            names.len(),
            names.join(", ")
        );
        return 0;
    }
    report(&findings, &rules);
    1
}

fn report(findings: &[Finding], rules: &Rules) {
    for finding in findings {
        eprintln!("{finding}");
    }
    let broken: BTreeSet<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
    eprintln!(
        "\n{} violation(s) of {} rule(s):",
        findings.len(),
        broken.len()
    );
    for id in broken {
        match rules.statement(id) {
            Some(statement) => eprintln!("  {id}: {statement}"),
            None if id.starts_with("ST-") => {
                eprintln!("  {id}: static check {id} in docs/security/negative-test-catalog.md")
            }
            None => eprintln!("  {id}: the workspace does not match crate-dependency-rules.json"),
        }
    }
}
