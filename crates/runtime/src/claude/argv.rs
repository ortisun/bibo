//! The Claude Code command line, built from a closed allow list.
//!
//! Every flag the adapter ever writes is a variant of [`Flag`]. The builder is a pure function
//! from the run's parameters to a vector, and it needs a [`VerifiedTarget`]: the vector always
//! carries `--dangerously-skip-permissions`, which is acceptable only because the container is the
//! boundary (spike section 4.8), so the builder refuses any sandbox whose posture was not checked.
//!
//! The set follows the spike (section 6.1), `claude-factory-profile` and `claude-factory-profile-spec`:
//!
//! * `--setting-sources=user` and `--strict-mcp-config` in every stage. `--bare` is **not** used: it
//!   neither stops the `env` block of a repository `settings.json` nor loads any skill.
//! * `--disable-slash-commands` in every stage except specification.
//! * `--no-session-persistence`, so the tool writes no transcript of its own.
//! * `apiKeyHelper` in a `--settings` document: the credential is a file that a helper prints, never
//!   a variable.
//! * An explicit `--model`: the default is the most expensive model.
//! * `--max-turns` (hidden, behavior-probed) and `--max-budget-usd` as second lines of defense behind
//!   the broker.
//! * `--tools=` with exactly the built-in tools the granted access levels need.
//!
//! Values are written in the `--flag=value` form, so that a value can never be read as another
//! flag, and the variadic options cannot swallow the prompt (the prompt travels on standard input).

use factory_domain::contracts::agent_manifest::{AllowedTool, ToolAccess};
use factory_ports::agent::FlagSet;
use factory_ports::sandbox::JOB_TOKEN_TARGET;

use crate::target::VerifiedTarget;

/// The built-in tools the adapter can grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaudeTool {
    /// Reads a file.
    Read,
    /// Finds files by name.
    Glob,
    /// Searches file contents.
    Grep,
    /// Edits a file.
    Edit,
    /// Writes a file.
    Write,
    /// Runs a command.
    Bash,
    /// Invokes a skill. Only the specification stage gets it.
    Skill,
}

impl ClaudeTool {
    /// The tool's name in `--tools`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Glob => "Glob",
            Self::Grep => "Grep",
            Self::Edit => "Edit",
            Self::Write => "Write",
            Self::Bash => "Bash",
            Self::Skill => "Skill",
        }
    }

    /// The built-in tools an access level needs.
    const fn for_access(access: ToolAccess) -> &'static [ClaudeTool] {
        match access {
            ToolAccess::Read => &[Self::Read, Self::Glob, Self::Grep],
            ToolAccess::Write => &[Self::Edit, Self::Write],
            ToolAccess::ExecuteSandboxed => &[Self::Bash],
        }
    }
}

/// The tools for the granted access levels. The specification stage also gets `Skill`. The result is
/// sorted and has no repeat.
#[must_use]
pub fn tools_for(granted: &[AllowedTool], flag_set: FlagSet) -> Vec<ClaudeTool> {
    let mut tools: Vec<ClaudeTool> = granted
        .iter()
        .flat_map(|tool| ClaudeTool::for_access(tool.access).iter().copied())
        .collect();
    if flag_set == FlagSet::Specification {
        tools.push(ClaudeTool::Skill);
    }
    tools.sort();
    tools.dedup();
    tools
}

/// Every flag the adapter may write. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// `-p`: print mode, no person at the keyboard.
    Print,
    /// `--output-format=stream-json`.
    OutputFormat,
    /// `--verbose`: stream-json needs it.
    Verbose,
    /// `--no-session-persistence`.
    NoSessionPersistence,
    /// `--setting-sources=user`.
    SettingSources,
    /// `--strict-mcp-config`.
    StrictMcpConfig,
    /// `--settings=<json>` with the credential helper.
    Settings,
    /// `--model=<name>`.
    Model,
    /// `--max-turns=<n>`.
    MaxTurns,
    /// `--max-budget-usd=<x>`.
    MaxBudgetUsd,
    /// `--tools=<list>`.
    Tools,
    /// `--disable-slash-commands`. Every stage except specification.
    DisableSlashCommands,
    /// `--dangerously-skip-permissions`. Only inside a verified sandbox.
    DangerouslySkipPermissions,
}

impl Flag {
    /// Every flag.
    pub const ALL: [Flag; 13] = [
        Flag::Print,
        Flag::OutputFormat,
        Flag::Verbose,
        Flag::NoSessionPersistence,
        Flag::SettingSources,
        Flag::StrictMcpConfig,
        Flag::Settings,
        Flag::Model,
        Flag::MaxTurns,
        Flag::MaxBudgetUsd,
        Flag::Tools,
        Flag::DisableSlashCommands,
        Flag::DangerouslySkipPermissions,
    ];

    /// The flag's name, without a value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Print => "-p",
            Self::OutputFormat => "--output-format",
            Self::Verbose => "--verbose",
            Self::NoSessionPersistence => "--no-session-persistence",
            Self::SettingSources => "--setting-sources",
            Self::StrictMcpConfig => "--strict-mcp-config",
            Self::Settings => "--settings",
            Self::Model => "--model",
            Self::MaxTurns => "--max-turns",
            Self::MaxBudgetUsd => "--max-budget-usd",
            Self::Tools => "--tools",
            Self::DisableSlashCommands => "--disable-slash-commands",
            Self::DangerouslySkipPermissions => "--dangerously-skip-permissions",
        }
    }

    /// True for the flags that take the permission checks away. They need a verified target.
    #[must_use]
    pub const fn is_bypass(self) -> bool {
        matches!(self, Self::DangerouslySkipPermissions)
    }
}

/// Why an argument vector was not built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgvRefused {
    /// The model name has characters a model name does not have.
    #[error("the model name is not a plain model name")]
    BadModel,
    /// The budget is not a positive number of dollars.
    #[error("the budget is not a positive number")]
    BadBudget,
}

/// What a Claude Code run needs to know to build its command line.
#[derive(Debug, Clone)]
pub struct Plan<'a> {
    /// The stage's flag set.
    pub flag_set: FlagSet,
    /// The model, as the provider spells it.
    pub model: &'a str,
    /// The most turns the tool may take.
    pub max_turns: u32,
    /// The most dollars the tool may spend by its own count.
    pub max_budget_usd: f64,
    /// The built-in tools granted.
    pub tools: Vec<ClaudeTool>,
}

/// The arguments of one Claude Code run. The target is the proof that the bypass flag is safe.
///
/// # Errors
/// [`ArgvRefused`] for a model name or a budget that cannot be written.
pub fn build(plan: &Plan<'_>, target: &VerifiedTarget) -> Result<Vec<String>, ArgvRefused> {
    let _proof: &VerifiedTarget = target;
    if !is_plain_model_name(plan.model) {
        return Err(ArgvRefused::BadModel);
    }
    if !(plan.max_budget_usd.is_finite() && plan.max_budget_usd > 0.0) {
        return Err(ArgvRefused::BadBudget);
    }
    let helper = format!("/usr/bin/cat {JOB_TOKEN_TARGET}");
    let settings = serde_json::json!({ "apiKeyHelper": helper }).to_string();
    let tools = plan
        .tools
        .iter()
        .map(|t| t.name())
        .collect::<Vec<_>>()
        .join(",");
    let mut args = vec![
        Flag::Print.name().to_owned(),
        format!("{}=stream-json", Flag::OutputFormat.name()),
        Flag::Verbose.name().to_owned(),
        Flag::NoSessionPersistence.name().to_owned(),
        format!("{}=user", Flag::SettingSources.name()),
        Flag::StrictMcpConfig.name().to_owned(),
        format!("{}={settings}", Flag::Settings.name()),
        format!("{}={}", Flag::Model.name(), plan.model),
        format!("{}={}", Flag::MaxTurns.name(), plan.max_turns.max(1)),
        format!("{}={:.4}", Flag::MaxBudgetUsd.name(), plan.max_budget_usd),
        format!("{}={tools}", Flag::Tools.name()),
    ];
    if plan.flag_set == FlagSet::Standard {
        args.push(Flag::DisableSlashCommands.name().to_owned());
    }
    args.push(Flag::DangerouslySkipPermissions.name().to_owned());
    Ok(args)
}

/// A model name is letters, digits and `. _ - : / @ [ ]`, starts with a letter or digit, and is
/// short. Nothing here can hold a space, so a name cannot become a second argument.
fn is_plain_model_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '@' | '[' | ']'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_names_cannot_carry_a_second_argument() {
        assert!(is_plain_model_name("claude-sonnet-5-5"));
        assert!(is_plain_model_name("anthropic/claude-sonnet-5-5@2026"));
        for bad in ["", "x y", "--model", "a;b", "a\nb", "-x", "a=b"] {
            assert!(!is_plain_model_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_names_of_all_flags_are_distinct() {
        let mut names: Vec<&str> = Flag::ALL.iter().map(|f| f.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Flag::ALL.len());
    }
}
