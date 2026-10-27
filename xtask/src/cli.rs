//! Command line: argument parsing, the order of the checks, and the exit code.
//!
//! Exit codes: 0 when every rule holds, 1 when a rule is broken, 2 when the check could not run
//! (bad arguments, an unreadable rules file, or `cargo metadata` failing).

use crate::clippy_bans;
use crate::finding::Finding;
use crate::lints;
use crate::metadata;
use crate::rules::Rules;
use crate::static_checks;
use crate::topology;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const USAGE: &str = "usage:
  cargo xtask check-architecture [--manifest-path PATH] [--rules PATH]
  cargo xtask clippy-toml

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
