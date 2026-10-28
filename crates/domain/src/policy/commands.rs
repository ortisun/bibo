//! Command classification (`forbidden_command_classes` and `command_sets` of
//! `policies/security.yaml`).
//!
//! A command is an argument vector, never a shell string. [`CommandPolicy::evaluate`] answers in
//! two steps, and a deny in the first step is final (deny overrides):
//!
//! 1. **Forbidden classes.** Each class that does not except the sandbox profile matches when any
//!    of three things holds: the basename of `argv[0]` (lower-cased, so `SH` and `/bin/sh` are
//!    `sh`) is one of the class's `executables`; any argument equals one of its `argv_any`; or one
//!    of its `argv_regex` matches the argument vector joined with single spaces. The three tests
//!    are alternatives, because `credential_access` lists executables and also expressions that
//!    must catch `cat /proc/self/environ`, where `cat` is not listed. A matching `deny` class
//!    denies. If only `require_human` classes match, a human decides.
//! 2. **Command sets.** `argv[0]` must be a bare name (no `/`) that a command set lists. If the
//!    set names `allowed_subcommands`, `argv[1]` must be one of them, so `cargo +nightly test`
//!    and `cargo --config x test` are refused. No argument may match `forbidden_args`: exactly,
//!    as `--flag=value`, with one dash or two (Go accepts both), as a short flag with its value
//!    attached or inside a cluster (`-Cfoo`, `-vC`), or, for an entry with a space such as
//!    `-m pip`, as those two arguments in a row. The `forced_args` of the profile
//!    are inserted before the first `--`, so that they reach the program and not the test binary
//!    behind it.
//!
//! An empty `allowed_subcommands` list means the program has no subcommand to check (`node`
//! takes a script, `rustc` takes a source file); its safety rests on `forbidden_args`.
//!
//! The work is bounded: at most 512 arguments, 64 KiB each, 256 KiB in total, and no NUL byte.

use std::collections::{BTreeMap, BTreeSet};

use super::security::{CommandAction, SecurityPolicy};
use super::{BuildError, RuleRef, SandboxProfileKind};

/// The most arguments one command may have.
pub const MAX_ARGS: usize = 512;
/// The longest single argument, in bytes.
pub const MAX_ARG_BYTES: usize = 64 * 1024;
/// The longest argument vector, in bytes.
pub const MAX_TOTAL_BYTES: usize = 256 * 1024;

/// Why an argument vector was refused before any class looked at it. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MalformedArgv {
    /// There is no argument, or `argv[0]` is empty.
    #[error("the command has no program")]
    NoProgram,
    /// More than 512 arguments.
    #[error("the command has more than {MAX_ARGS} arguments")]
    TooManyArguments,
    /// An argument is longer than 64 KiB.
    #[error("an argument is longer than {MAX_ARG_BYTES} bytes")]
    ArgumentTooLong,
    /// The arguments together are longer than 256 KiB.
    #[error("the arguments are longer than {MAX_TOTAL_BYTES} bytes in total")]
    TooLong,
    /// An argument contains a NUL byte, which no program can receive.
    #[error("an argument contains a NUL byte")]
    NulByte,
}

/// Why a command was refused. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandDenialReason {
    /// The argument vector is malformed.
    Malformed(MalformedArgv),
    /// A forbidden command class matched.
    ForbiddenClass,
    /// `argv[0]` is not a bare name, so the wrapper cannot resolve it from its fixed `PATH`.
    ExecutableNotBare,
    /// No command set lists the program, or the program name is not a plain name (a shell string
    /// such as `cargo test` as one argument ends here).
    NotInCommandSet,
    /// The program has a list of subcommands and `argv[1]` is not on it.
    SubcommandNotAllowed,
    /// An argument matches a `forbidden_args` entry. The entry is named, not the argument.
    ForbiddenArgument(String),
}

/// A refused command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandDenial {
    /// Why.
    pub reason: CommandDenialReason,
    /// The rule: a forbidden class, a command set or a program.
    pub rule: RuleRef,
    /// Every class that matched, in policy order, for the audit event.
    pub matched_classes: Vec<String>,
}

/// A command that may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedCommand {
    /// The argument vector to run: the request with the profile's forced arguments inserted.
    pub argv: Vec<String>,
    /// The environment the supervisor sets. The caller cannot add to it.
    pub env: BTreeMap<String, String>,
    /// The command set that allowed it.
    pub rule: RuleRef,
}

/// The answer for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandVerdict {
    /// The command may run as given.
    Allowed(AllowedCommand),
    /// Only `require_human` classes matched: a human decides.
    RequireHuman {
        /// The classes.
        classes: Vec<String>,
    },
    /// The command is refused.
    Denied(CommandDenial),
}

impl CommandVerdict {
    /// True when the command may run.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }
}

#[derive(Debug)]
struct Class {
    id: String,
    action: CommandAction,
    executables: BTreeSet<String>,
    argv_any: BTreeSet<String>,
    regexes: Vec<regex::bytes::Regex>,
    except_profiles: BTreeSet<SandboxProfileKind>,
}

#[derive(Debug)]
struct Program {
    set_id: String,
    subcommands: Vec<String>,
    forbidden_args: Vec<String>,
    forced: BTreeMap<SandboxProfileKind, Vec<String>>,
    env: BTreeMap<String, String>,
}

/// The command rules of one security policy, compiled once.
#[derive(Debug)]
pub struct CommandPolicy {
    classes: Vec<Class>,
    programs: BTreeMap<String, Program>,
}

fn basename_folded(program: &str) -> String {
    let base = program.rsplit('/').next().unwrap_or(program);
    base.to_lowercase()
}

fn matches_forbidden_arg(forbidden: &str, tail: &[String]) -> bool {
    if let Some((flag, value)) = forbidden.split_once(' ') {
        let attached = format!("{flag}{value}");
        let with_equals = format!("{flag}={value}");
        return tail.iter().enumerate().any(|(i, token)| {
            *token == attached
                || *token == with_equals
                || (token == flag && tail.get(i + 1).is_some_and(|next| next == value))
        });
    }
    let name = forbidden.trim_start_matches('-');
    if name.len() == forbidden.len() {
        // Not a flag: a word, matched exactly.
        return tail.iter().any(|token| token == forbidden);
    }
    let mut chars = name.chars();
    let single_letter = matches!((chars.next(), chars.next()), (Some(_), None));
    let name_equals = format!("{name}=");
    tail.iter().any(|token| {
        let Some(token_name) = token.strip_prefix('-') else {
            return false;
        };
        if single_letter {
            // `-C`, `-Copt-level=3` and a cluster such as `-vC` all carry the letter. A long
            // option (`--c...`) is a different option.
            return !token_name.starts_with('-') && token_name.contains(name);
        }
        // `--config`, `--config=x`, `-config` (Go accepts one dash or two), and an entry that
        // carries a value, such as `--manifest-path=/`, matched as a prefix.
        let token_name = token_name.trim_start_matches('-');
        token_name == name
            || token_name.starts_with(&name_equals)
            || (name.contains('=') && token_name.starts_with(name))
    })
}

fn profile_of(key: &'static str, name: &str) -> Result<SandboxProfileKind, BuildError> {
    SandboxProfileKind::parse(name).ok_or_else(|| BuildError::UnknownValue {
        key,
        found: name.to_owned(),
    })
}

impl CommandPolicy {
    /// Compiles the command rules of `policy`.
    ///
    /// # Errors
    /// A [`BuildError`] when an expression does not compile, a profile name is unknown, a program
    /// is listed twice, or `executable_match` is not `basename_only`.
    pub fn from_policy(policy: &SecurityPolicy) -> Result<Self, BuildError> {
        if policy.command_sets.executable_match != "basename_only" {
            return Err(BuildError::UnknownValue {
                key: "command_sets.executable_match",
                found: policy.command_sets.executable_match.clone(),
            });
        }
        let mut classes = Vec::new();
        let mut seen = BTreeSet::new();
        for class in &policy.forbidden_command_classes {
            if !seen.insert(class.id.clone()) {
                return Err(BuildError::Duplicate {
                    what: "forbidden command class",
                    name: class.id.clone(),
                });
            }
            let mut regexes = Vec::new();
            for (n, regex) in class.matches.argv_regex.iter().flatten().enumerate() {
                regexes.push(regex.compile().map_err(|message| BuildError::Regex {
                    place: format!(
                        "forbidden_command_classes[{}].match.argv_regex[{n}]",
                        class.id
                    ),
                    message,
                })?);
            }
            let mut except_profiles = BTreeSet::new();
            for name in class.except_profiles.iter().flatten() {
                except_profiles.insert(profile_of(
                    "forbidden_command_classes.except_profiles",
                    name,
                )?);
            }
            classes.push(Class {
                id: class.id.clone(),
                action: class.action,
                executables: class
                    .matches
                    .executables
                    .iter()
                    .flatten()
                    .map(|e| e.to_lowercase())
                    .collect(),
                argv_any: class.matches.argv_any.iter().flatten().cloned().collect(),
                regexes,
                except_profiles,
            });
        }

        let mut programs = BTreeMap::new();
        for set in &policy.command_sets.sets {
            for (name, executable) in &set.executables {
                if name.contains('/') || name.is_empty() {
                    return Err(BuildError::UnknownValue {
                        key: "command_sets.sets.executables",
                        found: name.clone(),
                    });
                }
                let mut forced = BTreeMap::new();
                for (profile, args) in executable.forced_args.iter().flatten() {
                    forced.insert(
                        profile_of("command_sets.sets.executables.forced_args", profile)?,
                        args.clone(),
                    );
                }
                let program = Program {
                    set_id: set.id.clone(),
                    subcommands: executable.allowed_subcommands.clone().unwrap_or_default(),
                    forbidden_args: executable.forbidden_args.clone().unwrap_or_default(),
                    forced,
                    env: set.env.clone(),
                };
                if programs.insert(name.clone(), program).is_some() {
                    return Err(BuildError::Duplicate {
                        what: "command set program",
                        name: name.clone(),
                    });
                }
            }
        }
        Ok(Self { classes, programs })
    }

    /// The ids of the forbidden classes, in policy order.
    pub fn class_ids(&self) -> impl Iterator<Item = &str> {
        self.classes.iter().map(|c| c.id.as_str())
    }

    /// The programs the command sets list.
    pub fn programs(&self) -> impl Iterator<Item = &str> {
        self.programs.keys().map(String::as_str)
    }

    fn validate(argv: &[String]) -> Result<(), MalformedArgv> {
        let program = argv.first().ok_or(MalformedArgv::NoProgram)?;
        if program.is_empty() {
            return Err(MalformedArgv::NoProgram);
        }
        if argv.len() > MAX_ARGS {
            return Err(MalformedArgv::TooManyArguments);
        }
        let mut total = 0usize;
        for arg in argv {
            if arg.len() > MAX_ARG_BYTES {
                return Err(MalformedArgv::ArgumentTooLong);
            }
            if arg.contains('\0') {
                return Err(MalformedArgv::NulByte);
            }
            total = total.saturating_add(arg.len() + 1);
        }
        if total > MAX_TOTAL_BYTES {
            return Err(MalformedArgv::TooLong);
        }
        Ok(())
    }

    /// The ids of the classes that match, in policy order.
    fn matching_classes(&self, argv: &[String], profile: SandboxProfileKind) -> Vec<&Class> {
        let base = argv.first().map(|p| basename_folded(p)).unwrap_or_default();
        let joined = argv.join(" ");
        self.classes
            .iter()
            .filter(|c| !c.except_profiles.contains(&profile))
            .filter(|c| {
                c.executables.contains(&base)
                    || argv.iter().any(|a| c.argv_any.contains(a))
                    || c.regexes.iter().any(|r| r.is_match(joined.as_bytes()))
            })
            .collect()
    }

    /// Decides one command under a sandbox profile.
    #[must_use]
    pub fn evaluate(&self, argv: &[String], profile: SandboxProfileKind) -> CommandVerdict {
        let denied = |reason, rule: RuleRef, matched: Vec<String>| {
            CommandVerdict::Denied(CommandDenial {
                reason,
                rule,
                matched_classes: matched,
            })
        };
        if let Err(malformed) = Self::validate(argv) {
            return denied(
                CommandDenialReason::Malformed(malformed),
                RuleRef::new("command_sets", "argv_array"),
                Vec::new(),
            );
        }

        let matched = self.matching_classes(argv, profile);
        let matched_ids: Vec<String> = matched.iter().map(|c| c.id.clone()).collect();
        if let Some(hard) = matched.iter().find(|c| c.action == CommandAction::Deny) {
            return denied(
                CommandDenialReason::ForbiddenClass,
                RuleRef::new("forbidden_command_classes", hard.id.clone()),
                matched_ids,
            );
        }
        if !matched.is_empty() {
            return CommandVerdict::RequireHuman {
                classes: matched_ids,
            };
        }

        let Some(program_name) = argv.first() else {
            return denied(
                CommandDenialReason::Malformed(MalformedArgv::NoProgram),
                RuleRef::new("command_sets", "argv_array"),
                Vec::new(),
            );
        };
        if program_name.contains('/') {
            return denied(
                CommandDenialReason::ExecutableNotBare,
                RuleRef::new("command_sets", "executable_match"),
                Vec::new(),
            );
        }
        let Some(program) = self.programs.get(program_name) else {
            return denied(
                CommandDenialReason::NotInCommandSet,
                RuleRef::new("command_sets", "default_action"),
                Vec::new(),
            );
        };
        let rule = RuleRef::new("command_sets", format!("{}:{program_name}", program.set_id));
        let tail = argv.get(1..).unwrap_or_default();
        if !program.subcommands.is_empty()
            && !tail
                .first()
                .is_some_and(|sub| program.subcommands.contains(sub))
        {
            return denied(CommandDenialReason::SubcommandNotAllowed, rule, Vec::new());
        }
        if let Some(entry) = program
            .forbidden_args
            .iter()
            .find(|f| matches_forbidden_arg(f, tail))
        {
            return denied(
                CommandDenialReason::ForbiddenArgument(entry.clone()),
                rule,
                Vec::new(),
            );
        }

        let mut final_argv: Vec<String> = argv.to_vec();
        if let Some(forced) = program.forced.get(&profile) {
            let at = final_argv
                .iter()
                .skip(1)
                .position(|a| a == "--")
                .map_or(final_argv.len(), |p| p + 1);
            for (offset, arg) in forced.iter().enumerate() {
                final_argv.insert(at + offset, arg.clone());
            }
        }
        CommandVerdict::Allowed(AllowedCommand {
            argv: final_argv,
            env: program.env.clone(),
            rule,
        })
    }
}
