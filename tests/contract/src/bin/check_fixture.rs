//! `check-fixture`: runs the contract checks on the fixture and prints one line per result.
//!
//! ```text
//! check-fixture [--fixture DIR] [--host] [--image]
//! ```
//!
//! With no mode flag it runs the file checks only. `--host` also builds and tests a copy on the
//! host. `--image` runs the same commands in the pinned verify image.
//!
//! Exit codes: 0 every requested check passed, 1 a check failed, 2 wrong usage, 3 BLOCKED (the host
//! or Docker could not run what was asked, so there is no evidence either way).

use std::path::PathBuf;
use std::process::ExitCode;

use fixture_contract::exec::{self, CommandResult};
use fixture_contract::workdir::copy_fixture;
use fixture_contract::{Finding, checks, fixture_dir, repository_root};

fn print_results(results: &[CommandResult]) {
    for result in results {
        let verdict = if result.succeeded() {
            "PASSED"
        } else {
            "FAILED"
        };
        println!(
            "  {verdict} {} ({:.1}s): {}",
            result.label,
            result.seconds,
            result.argv.join(" ")
        );
        if !result.succeeded() {
            for line in result
                .stderr
                .lines()
                .rev()
                .take(5)
                .collect::<Vec<_>>()
                .iter()
                .rev()
            {
                println!("    {line}");
            }
        }
    }
}

fn main() -> ExitCode {
    let mut fixture = fixture_dir();
    let mut host = false;
    let mut image = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--fixture" => match args.next() {
                Some(path) => fixture = PathBuf::from(path),
                None => {
                    eprintln!("check-fixture: --fixture needs a directory");
                    return ExitCode::from(2);
                }
            },
            "--host" => host = true,
            "--image" => image = true,
            other => {
                eprintln!("check-fixture: unknown argument '{other}'");
                return ExitCode::from(2);
            }
        }
    }

    let mut failed = false;
    let mut blocked: Vec<String> = Vec::new();

    let findings: Vec<Finding> = checks::all_static(&fixture);
    if findings.is_empty() {
        println!("PASSED files: layout, dependencies, manifest, CODEOWNERS, secrets, open gap");
    } else {
        failed = true;
        println!("FAILED files:");
        for finding in &findings {
            println!("  {finding}");
        }
    }

    if host || image {
        let copy = match copy_fixture(&fixture, "check") {
            Ok(copy) => copy,
            Err(error) => {
                eprintln!("check-fixture: cannot copy the fixture: {error}");
                return ExitCode::from(1);
            }
        };
        if host {
            if exec::cargo_available() {
                let target_dir = match fixture_contract::workdir::TempDir::new("target") {
                    Ok(dir) => dir,
                    Err(error) => {
                        eprintln!("check-fixture: cannot make a build directory: {error}");
                        return ExitCode::from(1);
                    }
                };
                let target = target_dir.path().to_path_buf();
                let results = exec::run_on_host(copy.path(), &target);
                println!("host (cargo, offline):");
                print_results(&results);
                let mut problems = match exec::outcome_of(&results) {
                    fixture_contract::Outcome::Passed => Vec::new(),
                    fixture_contract::Outcome::Failed(findings) => findings,
                    fixture_contract::Outcome::Blocked(reason) => {
                        blocked.push(reason);
                        Vec::new()
                    }
                };
                if problems.is_empty() && blocked.is_empty() {
                    let behaviour = exec::probe_behaviour(copy.path(), &target);
                    problems.extend(checks::readme_matches_reality(
                        copy.path(),
                        &behaviour.help,
                        &behaviour.example_outputs,
                    ));
                    problems.extend(exec::gap_is_open(&behaviour));
                }
                drop(target_dir);
                if problems.is_empty() {
                    if blocked.is_empty() {
                        println!(
                            "PASSED host: the commands pass, the README matches, the gap is open"
                        );
                    }
                } else {
                    failed = true;
                    println!("FAILED host:");
                    for finding in &problems {
                        println!("  {finding}");
                    }
                }
            } else {
                blocked.push("cargo is not installed on this host".to_owned());
            }
        }
        if image {
            let images = repository_root().join("infra/sandbox-images/images.json");
            match exec::verify_image_reference(&images) {
                Err(reason) => blocked.push(reason),
                Ok(reference) => match exec::image_blocker(&reference) {
                    Some(reason) => blocked.push(reason),
                    None => {
                        let results = exec::run_in_image(copy.path(), &reference);
                        let removed = exec::remove_leftover_containers();
                        println!("image {reference} (no network):");
                        print_results(&results);
                        if removed > 0 {
                            println!("  removed {removed} leftover container(s)");
                        }
                        match exec::outcome_of(&results) {
                            fixture_contract::Outcome::Passed => {
                                println!(
                                    "PASSED image: every command passes in the pinned verify image"
                                );
                            }
                            fixture_contract::Outcome::Failed(findings) => {
                                failed = true;
                                println!("FAILED image:");
                                for finding in &findings {
                                    println!("  {finding}");
                                }
                            }
                            fixture_contract::Outcome::Blocked(reason) => blocked.push(reason),
                        }
                    }
                },
            }
        }
    }

    for reason in &blocked {
        println!("BLOCKED: {reason}");
    }
    if failed {
        ExitCode::from(1)
    } else if blocked.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}
