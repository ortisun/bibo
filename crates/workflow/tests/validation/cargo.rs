//! A scripted `cargo` and `rustc` for the fake verify image.
//!
//! The fake sandbox runs a program by name and hands it the argument vector. These programs
//! answer like the pinned image does (the version lines and the exit codes were observed in it),
//! and record every call, so a test can say which commands the stage ran and which it never ran.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use factory_testkit::sandbox::{FakeSandbox, ProgramOutput};

/// Standard output and standard error of a test command.
#[derive(Debug, Clone)]
pub struct TestRun {
    pub stdout: String,
    pub stderr: String,
    pub exit: i32,
}

/// What the scripted tools do.
#[derive(Default)]
pub struct CargoScript {
    calls: Mutex<Vec<Vec<String>>>,
    test_runs: Mutex<VecDeque<TestRun>>,
    exits: Mutex<BTreeMap<String, i32>>,
    missing: Mutex<BTreeSet<String>>,
}

impl CargoScript {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The next `cargo test` returns this. The head run is consumed first, then the baseline.
    pub fn queue_test_run(&self, run: TestRun) {
        self.test_runs
            .lock()
            .expect("the lock is never poisoned")
            .push_back(run);
    }

    /// `cargo <subcommand>` exits with this code.
    pub fn exit_of(&self, subcommand: &str, code: i32) {
        self.exits
            .lock()
            .expect("the lock is never poisoned")
            .insert(subcommand.to_owned(), code);
    }

    /// The image does not hold this subcommand (a component that was not installed).
    pub fn lacks(&self, subcommand: &str) {
        self.missing
            .lock()
            .expect("the lock is never poisoned")
            .insert(subcommand.to_owned());
    }

    /// Every command line the sandbox ran, in order.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls
            .lock()
            .expect("the lock is never poisoned")
            .clone()
    }

    /// How many times `cargo <subcommand>` ran, not counting version probes.
    pub fn ran(&self, subcommand: &str) -> usize {
        self.calls()
            .iter()
            .filter(|call| {
                call.first().map(String::as_str) == Some("cargo")
                    && call.get(1).map(String::as_str) == Some(subcommand)
                    && !call.iter().any(|word| word == "--version")
            })
            .count()
    }

    /// The command line of the most recent `cargo <subcommand>`.
    pub fn last(&self, subcommand: &str) -> Option<Vec<String>> {
        self.calls().into_iter().rev().find(|call| {
            call.first().map(String::as_str) == Some("cargo")
                && call.get(1).map(String::as_str) == Some(subcommand)
                && !call.iter().any(|word| word == "--version")
        })
    }

    fn answer(&self, argv: &[String]) -> ProgramOutput {
        self.calls
            .lock()
            .expect("the lock is never poisoned")
            .push(argv.to_vec());
        let sub = argv.get(1).map(String::as_str).unwrap_or_default();
        let word = |text: &str| ProgramOutput {
            exit_code: Some(0),
            stdout: text.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        if argv.first().map(String::as_str) == Some("rustc") {
            return word("rustc 1.98.0 (abcdef012 2026-08-05)\n");
        }
        if self
            .missing
            .lock()
            .expect("the lock is never poisoned")
            .contains(sub)
        {
            return ProgramOutput {
                exit_code: Some(101),
                stdout: Vec::new(),
                stderr: format!("error: no such command: `{sub}`\n").into_bytes(),
            };
        }
        if argv.iter().any(|word| word == "--version") {
            return match sub {
                "fmt" => word("rustfmt 1.8.0-stable (abcdef012 2026-08-05)\n"),
                "clippy" => word("clippy 0.1.98 (abcdef012 2026-08-05)\n"),
                _ => word("cargo 1.98.0 (797e8a9bc 2026-08-05)\n"),
            };
        }
        if sub == "test" {
            let run = self
                .test_runs
                .lock()
                .expect("the lock is never poisoned")
                .pop_front();
            return match run {
                Some(run) => ProgramOutput {
                    exit_code: Some(run.exit),
                    stdout: run.stdout.into_bytes(),
                    stderr: run.stderr.into_bytes(),
                },
                None => ProgramOutput {
                    exit_code: Some(101),
                    stdout: Vec::new(),
                    stderr: b"no scripted test run\n".to_vec(),
                },
            };
        }
        let code = self
            .exits
            .lock()
            .expect("the lock is never poisoned")
            .get(sub)
            .copied()
            .unwrap_or(0);
        ProgramOutput {
            exit_code: Some(code),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    /// Adds the programs to a fake sandbox.
    pub fn install(self: &Arc<Self>, sandbox: FakeSandbox) -> FakeSandbox {
        let cargo = Arc::clone(self);
        let rustc = Arc::clone(self);
        sandbox
            .with_program("cargo", move |argv, _| cargo.answer(argv))
            .with_program("rustc", move |argv, _| rustc.answer(argv))
    }
}

/// libtest output for the given binaries: the label cargo prints, and the tests with how each
/// ended (`ok`, `FAILED` or `ignored`). The numbers add up, as they do in real output.
pub fn libtest(binaries: &[(&str, &[(&str, &str)])], exit: i32) -> TestRun {
    let mut stdout = String::new();
    let mut stderr =
        String::from("    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s\n");
    for (label, tests) in binaries {
        if let Some(name) = label.strip_prefix("doc-tests ") {
            stderr.push_str(&format!("   Doc-tests {name}\n"));
        } else {
            stderr.push_str(&format!(
                "     Running {label} (/out/target/debug/deps/x-0123456789abcdef)\n"
            ));
        }
        let count = |status: &str| tests.iter().filter(|(_, s)| *s == status).count();
        stdout.push_str(&format!("\nrunning {} tests\n", tests.len()));
        for (name, status) in *tests {
            stdout.push_str(&format!("test {name} ... {status}\n"));
        }
        let verdict = if count("FAILED") > 0 { "FAILED" } else { "ok" };
        stdout.push_str(&format!(
            "\ntest result: {verdict}. {} passed; {} failed; {} ignored; 0 measured; 0 filtered out; finished in 0.00s\n\n",
            count("ok"),
            count("FAILED"),
            count("ignored"),
        ));
    }
    TestRun {
        stdout,
        stderr,
        exit,
    }
}
