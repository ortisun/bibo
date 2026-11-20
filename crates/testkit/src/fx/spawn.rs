//! FX-SPAWN: a record of every program the code under test starts.
//!
//! The control plane may start `docker` and `git`, and nothing else (rule DEP-10, check ST-03).
//! The static scan in `xtask` reads source text, so it cannot see a program name built at run
//! time. This recorder watches the other side: what actually got started.
//!
//! # How it works
//!
//! The recorder owns a private directory and puts a small executable shim in it for each program
//! name you install. The test gives the code under test a `PATH` that holds only that directory
//! ([`SpawnRecorder::path_env`]). When the code starts `docker`, the shim runs instead. It writes
//! the argument vector and the full environment it was given to a numbered record file, then
//! behaves as the test scripted: do nothing, print canned output and exit with a code, answer by
//! argument prefix, or hand over to the real program. Because the code under test never knows,
//! no change to it is needed, and this works for `std::process::Command` and for
//! `tokio::process::Command` alike.
//!
//! Shim files are written in POSIX `sh`. The kernel runs them through their `#!` line; the code
//! under test does not start a shell, and the records show only the program it asked for.
//!
//! # What it records
//!
//! For each start: a sequence number, the program name, the arguments (without the program), the
//! working directory, and the environment. The variables a POSIX shell adds when it starts
//! (`PWD`, `OLDPWD`, `SHLVL`, `_`) are removed from the environment, so what remains is what the
//! caller passed.
//!
//! # What it cannot see
//!
//! * A program started by absolute path (`/bin/sh`) does not use `PATH`, so no shim runs. The
//!   static scan covers that. A test in this module shows the case on purpose.
//! * A program that is neither shimmed nor trapped fails to start in the code under test, and the
//!   failure is the code's to report. Install traps for the programs that must never run
//!   ([`SpawnRecorder::install_shell_traps`]) so an attempt is recorded and not just an error.
//! * It does not stop the code under test from running the *real* docker when you install
//!   [`Behavior::Passthrough`]. That is the point of the mode.
//!
//! Unix only: the shims are shell scripts.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::tmpdir::FxTempDir;

/// Variables that a POSIX shell adds on its own when it starts. They are not in the record.
pub const SHELL_ADDED_VARIABLES: [&str; 4] = ["PWD", "OLDPWD", "SHLVL", "_"];

/// Program names a shell trap covers by default: the shells, the launchers that can start one,
/// and the network tools that must not run from the control plane.
pub const SHELLS: [&str; 12] = [
    "sh",
    "bash",
    "zsh",
    "dash",
    "ash",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "cmd",
    "powershell",
    "pwsh",
];

/// Programs that run another program given in their arguments.
pub const LAUNCHERS: [&str; 10] = [
    "env", "nice", "nohup", "timeout", "xargs", "sudo", "setsid", "exec", "command", "busybox",
];

/// What a shim does after it has made its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behavior {
    /// Record and exit with code 0, printing nothing.
    Record,
    /// Record, print the reply and exit with its code.
    Reply(Reply),
    /// Record, then answer with the first rule whose prefix starts the argument list (arguments
    /// joined by single spaces). Without a match, answer with `default`.
    ByArguments {
        /// `(prefix, reply)` pairs, tried in order.
        rules: Vec<(String, Reply)>,
        /// The answer when no prefix matches.
        default: Reply,
    },
    /// Record, then run the real program at this absolute path with the same arguments.
    Passthrough(PathBuf),
}

/// What a shim prints and the code it exits with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Exit code.
    pub exit_code: i32,
    /// Text for standard output.
    pub stdout: String,
    /// Text for standard error.
    pub stderr: String,
}

impl Reply {
    /// Exit 0 with this standard output.
    #[must_use]
    pub fn ok(stdout: &str) -> Self {
        Self {
            exit_code: 0,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// Exit with a code and a message on standard error.
    #[must_use]
    pub fn fail(exit_code: i32, stderr: &str) -> Self {
        Self {
            exit_code,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }
    }
}

/// One program start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRecord {
    /// 1 for the first start, counting up. The order the shims ran in.
    pub seq: u64,
    /// The program name the caller used (the shim's name).
    pub program: String,
    /// The arguments, without the program.
    pub argv: Vec<String>,
    /// The environment the caller passed, without the variables a shell adds.
    pub env: BTreeMap<String, String>,
    /// The working directory.
    pub cwd: String,
}

impl SpawnRecord {
    /// The program and its arguments, each shortened to 60 characters, for messages. A secret in
    /// an argument is cut off by the shortening only by accident, so a failing test may still show
    /// part of one: only fake secrets belong in a test run.
    #[must_use]
    pub fn summary(&self) -> String {
        let shorten = |text: &str| -> String {
            if text.chars().count() > 60 {
                format!("{}...", text.chars().take(57).collect::<String>())
            } else {
                text.to_owned()
            }
        };
        std::iter::once(self.program.as_str())
            .chain(self.argv.iter().map(String::as_str))
            .map(shorten)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The same record as JSON, with the fidelity label. Environment values are left out; names
    /// and counts are enough to read it, and the values go to the sink collector.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fidelity": "fake",
            "seq": self.seq,
            "program": self.program,
            "argv": self.argv,
            "cwd": self.cwd,
            "env_names": self.env.keys().collect::<Vec<_>>(),
        })
    }

    /// The indexes of arguments that hold a URL with a user name and a password in it, which is
    /// how a token ends up in a process listing (NT-SEC-09).
    #[must_use]
    pub fn arguments_with_url_credentials(&self) -> Vec<usize> {
        self.argv
            .iter()
            .enumerate()
            .filter(|(_, argument)| has_url_credentials(argument))
            .map(|(index, _)| index)
            .collect()
    }

    /// What this record lacks of the fixed environment host-side git must run with
    /// (`docs/security/sandbox-policy.md` section 6.2). Empty for a record that is not `git`
    /// or that has all of it.
    #[must_use]
    pub fn missing_git_hardening(&self) -> Vec<String> {
        if self.program != "git" {
            return Vec::new();
        }
        let mut missing = Vec::new();
        for (name, wanted) in [
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ] {
            if self.env.get(name).map(String::as_str) != Some(wanted) {
                missing.push(format!("{name}={wanted}"));
            }
        }
        for (key, wanted) in [("core.hooksPath", "/dev/null"), ("core.fsmonitor", "false")] {
            if !self.git_config_value_is(key, wanted) {
                missing.push(format!("-c {key}={wanted}"));
            }
        }
        missing
    }

    /// True when `-c key=value` is among the arguments, or the same pair is set through
    /// `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_n` and `GIT_CONFIG_VALUE_n`.
    fn git_config_value_is(&self, key: &str, value: &str) -> bool {
        let wanted = format!("{key}={value}");
        let by_flag = self
            .argv
            .windows(2)
            .any(|pair| pair[0] == "-c" && pair[1] == wanted);
        let by_env = self
            .env
            .get("GIT_CONFIG_COUNT")
            .and_then(|count| count.parse::<usize>().ok())
            .is_some_and(|count| {
                (0..count).any(|n| {
                    self.env
                        .get(&format!("GIT_CONFIG_KEY_{n}"))
                        .map(String::as_str)
                        == Some(key)
                        && self
                            .env
                            .get(&format!("GIT_CONFIG_VALUE_{n}"))
                            .map(String::as_str)
                            == Some(value)
                })
            });
        by_flag || by_env
    }
}

/// True when a URL in the text has both a user name and a password before its host.
fn has_url_credentials(text: &str) -> bool {
    text.match_indices("://").any(|(at, _)| {
        let rest = &text[at + 3..];
        let authority = rest.split(['/', '?', '#', ' ']).next().unwrap_or_default();
        authority.rsplit_once('@').is_some_and(|(userinfo, _)| {
            userinfo
                .split_once(':')
                .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty())
        })
    })
}

/// A start that the policy forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnViolation {
    /// The program is a shell.
    Shell {
        /// The record's sequence number.
        seq: u64,
        /// The program name.
        program: String,
    },
    /// A launcher such as `env` was given a shell to run.
    ShellThroughLauncher {
        /// The record's sequence number.
        seq: u64,
        /// The launcher.
        program: String,
        /// The shell named in its arguments.
        shell: String,
    },
    /// The program is not in the allowed set.
    NotAllowed {
        /// The record's sequence number.
        seq: u64,
        /// The program name.
        program: String,
    },
}

impl fmt::Display for SpawnViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnViolation::Shell { seq, program } => {
                write!(f, "start #{seq}: the shell {program} was started")
            }
            SpawnViolation::ShellThroughLauncher {
                seq,
                program,
                shell,
            } => write!(
                f,
                "start #{seq}: {program} was asked to run the shell {shell}"
            ),
            SpawnViolation::NotAllowed { seq, program } => write!(
                f,
                "start #{seq}: {program} is not an allowed program for the control plane"
            ),
        }
    }
}

/// Which programs the control plane may start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnPolicy {
    allowed: BTreeSet<String>,
}

impl SpawnPolicy {
    /// The policy of rule DEP-10: `docker` and `git`.
    #[must_use]
    pub fn docker_and_git() -> Self {
        Self::allowing(&["docker", "git"])
    }

    /// A policy that allows exactly these programs.
    #[must_use]
    pub fn allowing(programs: &[&str]) -> Self {
        Self {
            allowed: programs.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    /// Everything wrong with one start.
    #[must_use]
    pub fn evaluate(&self, record: &SpawnRecord) -> Vec<SpawnViolation> {
        let name = base_name(&record.program);
        if SHELLS.contains(&name.as_str()) {
            return vec![SpawnViolation::Shell {
                seq: record.seq,
                program: record.program.clone(),
            }];
        }
        if LAUNCHERS.contains(&name.as_str())
            && let Some(shell) = record
                .argv
                .iter()
                .map(|argument| base_name(argument))
                .find(|argument| SHELLS.contains(&argument.as_str()))
        {
            return vec![SpawnViolation::ShellThroughLauncher {
                seq: record.seq,
                program: record.program.clone(),
                shell,
            }];
        }
        if self.allowed.contains(&name) {
            Vec::new()
        } else {
            vec![SpawnViolation::NotAllowed {
                seq: record.seq,
                program: record.program.clone(),
            }]
        }
    }
}

fn base_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase()
}

/// Records the programs a test starts. See the module documentation.
///
/// When the recorder is dropped it checks the policy once more and panics if a start was
/// forbidden, unless the thread is already panicking or [`disarm`](Self::disarm) was called. This
/// is the trap that NT-SBX-14 asks for: a test cannot forget to look.
#[derive(Debug)]
pub struct SpawnRecorder {
    dir: FxTempDir,
    policy: SpawnPolicy,
    installed: BTreeSet<String>,
    armed: bool,
}

impl SpawnRecorder {
    /// Creates the recorder and its private directory.
    ///
    /// # Errors
    /// Returns the I/O error when the directory cannot be made, or when its path holds a
    /// character that the shims cannot quote safely.
    pub fn new(policy: SpawnPolicy) -> io::Result<Self> {
        let dir = FxTempDir::new("fx-spawn")?;
        ensure_shell_safe(dir.path())?;
        fs::create_dir(dir.join("bin"))?;
        fs::create_dir(dir.join("rules"))?;
        fs::create_dir(dir.join("log"))?;
        Ok(Self {
            dir,
            policy,
            installed: BTreeSet::new(),
            armed: true,
        })
    }

    /// The directory that holds the shims. Give the code under test a `PATH` with only this.
    #[must_use]
    pub fn path_env(&self) -> OsString {
        self.dir.join("bin").into_os_string()
    }

    /// The directory that holds the shims.
    #[must_use]
    pub fn bin_dir(&self) -> PathBuf {
        self.dir.join("bin")
    }

    /// Installs a shim named `program`.
    ///
    /// # Errors
    /// Returns an error for a name that is not a plain program name, a path that cannot be quoted
    /// safely, or when the files cannot be written.
    pub fn install(&mut self, program: &str, behavior: &Behavior) -> io::Result<()> {
        validate_program_name(program)?;
        let rules = self.dir.join("rules");
        let mut tail = String::new();
        match behavior {
            Behavior::Record => tail.push_str("exit 0\n"),
            Behavior::Reply(reply) => {
                write_reply(&rules, &format!("{program}.default"), None, reply)?;
                tail.push_str(&reply_block(program));
            }
            Behavior::ByArguments {
                rules: pairs,
                default,
            } => {
                for (index, (prefix, reply)) in pairs.iter().enumerate() {
                    if prefix.contains('\n') {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "a rule prefix must be one line",
                        ));
                    }
                    write_reply(
                        &rules,
                        &format!("{program}.{index:03}"),
                        Some(prefix),
                        reply,
                    )?;
                }
                write_reply(&rules, &format!("{program}.default"), None, default)?;
                tail.push_str(&rule_block(program));
            }
            Behavior::Passthrough(real) => {
                ensure_shell_safe(real)?;
                tail.push_str(&format!("exec '{}' \"$@\"\n", real.display()));
            }
        }
        let script = shim_script(self.dir.path(), program, &tail);
        let shim = self.dir.join("bin").join(program);
        fs::write(&shim, script)?;
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755))?;
        self.installed.insert(program.to_owned());
        Ok(())
    }

    /// Installs a trap for every shell, every launcher and the network tools `curl`, `wget`, `nc`
    /// and `ssh`. A trap records the attempt, prints a message on standard error and exits 127,
    /// so the code under test sees a failure and the test sees the start.
    ///
    /// # Errors
    /// The same as [`install`](Self::install).
    pub fn install_shell_traps(&mut self) -> io::Result<()> {
        let trap = Behavior::Reply(Reply::fail(
            127,
            "FX-SPAWN: this program must not be started by the control plane\n",
        ));
        for name in SHELLS
            .iter()
            .chain(LAUNCHERS.iter())
            .chain(["curl", "wget", "nc", "ssh"].iter())
        {
            if !self.installed.contains(*name) {
                self.install(name, &trap)?;
            }
        }
        Ok(())
    }

    /// Records a start that the code under test made through its own process seam, as if a shim
    /// had run. An adapter that routes spawns through a trait of its own can feed this.
    ///
    /// # Errors
    /// Returns the I/O error when the record cannot be written.
    pub fn record_direct(
        &self,
        program: &str,
        argv: &[&str],
        env: &[(&str, &str)],
    ) -> io::Result<u64> {
        let log = self.dir.join("log");
        let seq = fs::read_dir(&log)?
            .flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_prefix("rec-")?
                    .strip_suffix(".meta")?
                    .parse::<u64>()
                    .ok()
            })
            .max()
            .unwrap_or(0)
            + 1;
        let nul_joined = |items: &mut dyn Iterator<Item = String>| -> Vec<u8> {
            let mut bytes = Vec::new();
            for item in items {
                bytes.extend_from_slice(item.as_bytes());
                bytes.push(0);
            }
            bytes
        };
        fs::write(
            log.join(format!("rec-{seq}.argv")),
            nul_joined(&mut argv.iter().map(|a| (*a).to_owned())),
        )?;
        fs::write(
            log.join(format!("rec-{seq}.env")),
            nul_joined(&mut env.iter().map(|(k, v)| format!("{k}={v}"))),
        )?;
        let cwd = std::env::current_dir()
            .map(|dir| dir.display().to_string())
            .unwrap_or_default();
        fs::write(
            log.join(format!("rec-{seq}.meta")),
            nul_joined(&mut [program.to_owned(), cwd].into_iter()),
        )?;
        Ok(seq)
    }

    /// Every start so far, in the order the shims ran.
    ///
    /// # Errors
    /// Returns the I/O error when the log directory cannot be read.
    pub fn records(&self) -> io::Result<Vec<SpawnRecord>> {
        let log = self.dir.join("log");
        let mut sequences: Vec<u64> = fs::read_dir(&log)?
            .flatten()
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_prefix("rec-")?
                    .strip_suffix(".meta")?
                    .parse()
                    .ok()
            })
            .collect();
        sequences.sort_unstable();
        sequences
            .into_iter()
            .map(|seq| {
                let read = |extension: &str| fs::read(log.join(format!("rec-{seq}.{extension}")));
                let meta = split_nul(&read("meta")?);
                let argv = split_nul(&read("argv")?);
                let env = split_nul(&read("env")?)
                    .into_iter()
                    .filter_map(|line| {
                        let (name, value) = line.split_once('=')?;
                        (!SHELL_ADDED_VARIABLES.contains(&name))
                            .then(|| (name.to_owned(), value.to_owned()))
                    })
                    .collect();
                Ok(SpawnRecord {
                    seq,
                    program: meta.first().cloned().unwrap_or_default(),
                    argv,
                    env,
                    cwd: meta.get(1).cloned().unwrap_or_default(),
                })
            })
            .collect()
    }

    /// The starts the policy forbids.
    #[must_use]
    pub fn violations(&self) -> Vec<SpawnViolation> {
        self.records()
            .unwrap_or_default()
            .iter()
            .flat_map(|record| self.policy.evaluate(record))
            .collect()
    }

    /// Fails the test when the code under test started anything the policy forbids.
    ///
    /// # Panics
    /// Panics, naming each forbidden start, when there is one. Also panics when the log cannot be read.
    pub fn assert_clean(&self) {
        let records = self.records().expect("the spawn log can be read");
        let violations: Vec<String> = records
            .iter()
            .flat_map(|record| {
                self.policy
                    .evaluate(record)
                    .into_iter()
                    .map(move |v| format!("{v}: {}", record.summary()))
            })
            .collect();
        assert!(
            violations.is_empty(),
            "FX-SPAWN: the code under test started a forbidden program:\n  {}",
            violations.join("\n  ")
        );
    }

    /// Turns off the check at drop. A test that provokes a violation on purpose calls this.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// All records as JSON, with the fidelity label.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fidelity": "fake",
            "records": self.records().unwrap_or_default().iter().map(SpawnRecord::to_json).collect::<Vec<_>>(),
        })
    }
}

impl Drop for SpawnRecorder {
    fn drop(&mut self) {
        if self.armed && !std::thread::panicking() {
            self.assert_clean();
        }
    }
}

fn validate_program_name(program: &str) -> io::Result<()> {
    let ok = !program.is_empty()
        && !program.starts_with('.')
        && program
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{program:?} is not a plain program name"),
        ))
    }
}

/// A path that goes inside single quotes in a shim must not hold a quote or a line break.
fn ensure_shell_safe(path: &Path) -> io::Result<()> {
    let text = path.to_string_lossy();
    if text.contains('\'') || text.contains('\n') || !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the path {text:?} cannot be quoted safely for a shim"),
        ));
    }
    Ok(())
}

fn split_nul(bytes: &[u8]) -> Vec<String> {
    let mut parts: Vec<String> = bytes
        .split(|b| *b == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    // Every item ends with a NUL, so the last piece is empty.
    if parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    parts
}

fn write_reply(rules: &Path, stem: &str, prefix: Option<&str>, reply: &Reply) -> io::Result<()> {
    if let Some(prefix) = prefix {
        fs::write(rules.join(format!("{stem}.prefix")), format!("{prefix}\n"))?;
    }
    fs::write(rules.join(format!("{stem}.out")), &reply.stdout)?;
    fs::write(rules.join(format!("{stem}.err")), &reply.stderr)?;
    fs::write(
        rules.join(format!("{stem}.code")),
        format!("{}\n", reply.exit_code),
    )
}

/// Shell text that answers with the default reply of `program`.
fn reply_block(program: &str) -> String {
    format!(
        "b=\"$DIR/rules/{program}.default\"\n\
         /bin/cat \"$b.out\"\n\
         /bin/cat \"$b.err\" >&2\n\
         IFS= read -r code < \"$b.code\"\n\
         exit \"$code\"\n"
    )
}

/// Shell text that tries the numbered prefix rules and then the default reply.
fn rule_block(program: &str) -> String {
    format!(
        "for p in \"$DIR\"/rules/{program}.[0-9]*.prefix; do\n\
         \x20 [ -e \"$p\" ] || continue\n\
         \x20 IFS= read -r prefix < \"$p\"\n\
         \x20 case \"$*\" in\n\
         \x20   \"$prefix\"*)\n\
         \x20     b=${{p%.prefix}}\n\
         \x20     /bin/cat \"$b.out\"\n\
         \x20     /bin/cat \"$b.err\" >&2\n\
         \x20     IFS= read -r code < \"$b.code\"\n\
         \x20     exit \"$code\"\n\
         \x20     ;;\n\
         \x20 esac\n\
         done\n{}",
        reply_block(program)
    )
}

fn shim_script(dir: &Path, program: &str, tail: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # FX-SPAWN shim for '{program}'. FAKE: test machinery from factory-testkit, not the real program.\n\
         DIR='{dir}'\n\
         PROGRAM='{program}'\n\
         n=0\n\
         i=0\n\
         until /bin/mkdir \"$DIR/lock\" 2>/dev/null; do\n\
         \x20 i=$((i + 1))\n\
         \x20 if [ \"$i\" -gt 20000 ]; then break; fi\n\
         done\n\
         if [ -r \"$DIR/seq\" ]; then IFS= read -r n < \"$DIR/seq\"; fi\n\
         n=$((n + 1))\n\
         echo \"$n\" > \"$DIR/seq\"\n\
         /bin/rmdir \"$DIR/lock\" 2>/dev/null\n\
         rec=\"$DIR/log/rec-$n\"\n\
         if [ \"$#\" -gt 0 ]; then printf '%s\\0' \"$@\" > \"$rec.argv\"; else : > \"$rec.argv\"; fi\n\
         /usr/bin/env -0 > \"$rec.env\"\n\
         printf '%s\\0%s\\0' \"$PROGRAM\" \"$PWD\" > \"$rec.meta\"\n\
         {tail}",
        dir = dir.display()
    )
}

#[cfg(test)]
mod tests;
