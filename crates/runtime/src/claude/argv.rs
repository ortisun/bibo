//! The Claude Code command line, built from a closed allow list.
//!
//! Every flag the adapter ever writes is a variant of [`Flag`]. The builder is a pure function
//! from the run's parameters to a vector, and it needs a [`VerifiedTarget`]: the vector of every
//! pipeline stage carries `--dangerously-skip-permissions`, which is acceptable only because the
//! container is the boundary (spike section 4.8), so the builder refuses any sandbox whose posture
//! was not checked. The troubleshooter's vector carries `--permission-mode=dontAsk` instead.
//!
//! The set follows the spike (section 6.1), `claude-factory-profile` and `claude-factory-profile-spec`:
//!
//! * `--setting-sources=user` and `--strict-mcp-config` in every stage. `--bare` is **not** used: it
//!   neither stops the `env` block of a repository `settings.json` nor loads any skill.
//! * `--disable-slash-commands` in every stage except specification.
//! * In the specification stage only, `--input-format=stream-json` and `--replay-user-messages`,
//!   with the prompt sent as one stream-json user message ([`stdin_for`]). Claude Code writes a
//!   typed command into its event stream only when it replays the prompt: the replayed `user` event
//!   holds `<command-name>` and `<command-args>`, and it is the only place the invocation of the
//!   skill and its arguments appear. The stage's check of what reached the arguments
//!   (`skill-arguments-fixed`) reads that event and fails closed without it. The other stages run
//!   no command, so their prompt stays plain text.
//! * `--no-session-persistence`, so the tool writes no transcript of its own.
//! * The credential (ADR 0020). In API-key mode, `apiKeyHelper` in a `--settings` document: the
//!   credential is a file that a helper prints, never a variable. In subscription mode (the
//!   default), no `--settings`: the job token reaches the tool as `CLAUDE_CODE_OAUTH_TOKEN`, read
//!   from its file by the launcher line of `crate::command`, and never written into this vector.
//! * An explicit `--model`: the default is the most expensive model.
//! * `--max-turns` (hidden, behavior-probed) and `--max-budget-usd` as second lines of defense behind
//!   the broker.
//! * `--tools=` with exactly the built-in tools the granted access levels need.
//! * The troubleshooter (`FlagSet::Troubleshooting`, ADR 0021 Decision 6) differs: `--tools=` is
//!   empty, `--mcp-config=<json>` names the one MCP server, `factory` (the gateway, reached through
//!   the sidecar's second relay), `--allowedTools=` lists exactly the gateway tools granted, and
//!   `--permission-mode=dontAsk` refuses any other tool call. It carries **no**
//!   `--dangerously-skip-permissions`: with no built-in tool there is nothing to bypass, and
//!   `dontAsk` makes the allow list a filter (a call to an unlisted gateway tool is denied and
//!   reported in `permission_denials`; observed with 2.1.329 on 2026-11-20). The bearer token is
//!   not in the vector: the configuration names `${FACTORY_MCP_TOKEN}`, which the launcher line
//!   reads from the token file inside the sandbox. `--strict-mcp-config` stays on.
//!
//! Values are written in the `--flag=value` form, so that a value can never be read as another
//! flag, and the variadic options cannot swallow the prompt (the prompt travels on standard input).

use std::borrow::Cow;

use factory_domain::contracts::agent_manifest::{AllowedTool, ToolAccess};
use factory_ports::agent::{FlagSet, McpToolName};
use factory_ports::sandbox::JOB_TOKEN_TARGET;

use crate::command::MCP_TOKEN_VARIABLE;
use crate::target::VerifiedTarget;

/// The name of the one MCP server a troubleshooting run has. Claude Code names its tools
/// `mcp__factory__<tool>`.
pub const MCP_SERVER: &str = "factory";

/// The prefix of a gateway tool's name as Claude Code writes it.
const MCP_PREFIX: &str = "mcp__factory__";

/// The tools the adapter can grant: the built-in ones, and the gateway's tools for the
/// troubleshooter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
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
    /// One tool of the MCP gateway, `mcp__factory__<tool>`. Only the troubleshooter gets these,
    /// and it gets nothing else.
    Mcp(McpToolName),
}

impl ClaudeTool {
    /// Every built-in tool the adapter can grant.
    pub const ALL: [ClaudeTool; 7] = [
        Self::Read,
        Self::Glob,
        Self::Grep,
        Self::Edit,
        Self::Write,
        Self::Bash,
        Self::Skill,
    ];

    /// The tool with this name, when the adapter knows it: a built-in tool, or a gateway tool
    /// whose name is `mcp__factory__` and a valid [`McpToolName`]. Used to turn a name read from
    /// the tool's event stream into one of the fixed words, so that a name the model chose is never
    /// recorded as it is.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        if let Some(tool) = name.strip_prefix(MCP_PREFIX) {
            return McpToolName::new(tool).ok().map(Self::Mcp);
        }
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    /// The tool's name: in `--tools` for a built-in tool, in `--allowedTools` for a gateway tool.
    #[must_use]
    pub fn name(&self) -> Cow<'static, str> {
        match self {
            Self::Mcp(tool) => Cow::Owned(format!("{MCP_PREFIX}{tool}")),
            built_in => Cow::Borrowed(built_in.fixed_word()),
        }
    }

    /// A fixed word for the tool, for telemetry: the built-in tool's name, or `mcp` for any gateway
    /// tool. The gateway records which of its tools was called.
    #[must_use]
    pub const fn fixed_word(&self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Glob => "Glob",
            Self::Grep => "Grep",
            Self::Edit => "Edit",
            Self::Write => "Write",
            Self::Bash => "Bash",
            Self::Skill => "Skill",
            Self::Mcp(_) => "mcp",
        }
    }

    /// True for a built-in tool, false for a gateway tool.
    #[must_use]
    pub const fn is_built_in(&self) -> bool {
        !matches!(self, Self::Mcp(_))
    }

    /// The built-in tools an access level needs.
    fn for_access(access: ToolAccess) -> Vec<ClaudeTool> {
        match access {
            ToolAccess::Read => vec![Self::Read, Self::Glob, Self::Grep],
            ToolAccess::Write => vec![Self::Edit, Self::Write],
            ToolAccess::ExecuteSandboxed => vec![Self::Bash],
        }
    }
}

/// The tools for the granted access levels. The specification stage also gets `Skill`; the
/// troubleshooter gets the gateway's tools. The result is sorted and has no repeat.
///
/// The troubleshooter's built-in tools are computed like any other stage's and **not** dropped
/// here: a manifest that grants it one makes [`build`] refuse the run, so a wrong grant is found
/// and not silently narrowed.
#[must_use]
pub fn tools_for(
    granted: &[AllowedTool],
    flag_set: FlagSet,
    gateway: &[McpToolName],
) -> Vec<ClaudeTool> {
    let mut tools: Vec<ClaudeTool> = granted
        .iter()
        .flat_map(|tool| ClaudeTool::for_access(tool.access))
        .collect();
    if flag_set == FlagSet::Specification {
        tools.push(ClaudeTool::Skill);
    }
    tools.extend(gateway.iter().cloned().map(ClaudeTool::Mcp));
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
    /// `--input-format=stream-json`. Specification only: standard input is one user message.
    InputFormat,
    /// `--replay-user-messages`. Specification only: the tool writes the prompt back into its
    /// stream, with a typed command as `<command-name>` and `<command-args>`.
    ReplayUserMessages,
    /// `--dangerously-skip-permissions`. Only inside a verified sandbox, and never for the
    /// troubleshooter.
    DangerouslySkipPermissions,
    /// `--mcp-config=<json>`: the one MCP server of a troubleshooting run. Troubleshooting only.
    McpConfig,
    /// `--allowedTools=<list>`: the gateway tools the run may call. Troubleshooting only.
    AllowedTools,
    /// `--permission-mode=dontAsk`: a call that no allow rule covers is denied, never asked about.
    /// Troubleshooting only.
    PermissionMode,
}

impl Flag {
    /// Every flag.
    pub const ALL: [Flag; 18] = [
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
        Flag::InputFormat,
        Flag::ReplayUserMessages,
        Flag::DangerouslySkipPermissions,
        Flag::McpConfig,
        Flag::AllowedTools,
        Flag::PermissionMode,
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
            Self::InputFormat => "--input-format",
            Self::ReplayUserMessages => "--replay-user-messages",
            Self::DangerouslySkipPermissions => "--dangerously-skip-permissions",
            Self::McpConfig => "--mcp-config",
            Self::AllowedTools => "--allowedTools",
            Self::PermissionMode => "--permission-mode",
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
    /// A gateway address with a flag set other than troubleshooting, or troubleshooting without
    /// one.
    #[error("only the troubleshooting flag set has an MCP gateway, and it always has one")]
    GatewayMismatch,
    /// The gateway address is not a plain `http://host:port/path` URL.
    #[error("the MCP gateway address is not a plain http URL")]
    BadGatewayUrl,
    /// A built-in tool for the troubleshooter, a gateway tool for any other flag set, or a
    /// troubleshooter with no gateway tool at all.
    #[error("a tool does not belong to this flag set")]
    ToolNotAllowed,
}

/// How the job token reaches Claude Code. The broker swaps it for the real credential either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClaudeCredential {
    /// API-key mode: an `apiKeyHelper` in `--settings` prints the token file.
    #[default]
    ApiKeyHelper,
    /// Subscription mode (ADR 0020): the token is the tool's OAuth token, `CLAUDE_CODE_OAUTH_TOKEN`,
    /// set by the launcher line from the token file. No `--settings` document is written.
    OauthToken,
}

/// What a Claude Code run needs to know to build its command line.
#[derive(Debug, Clone)]
pub struct Plan<'a> {
    /// How the job token reaches the tool.
    pub credential: ClaudeCredential,
    /// The stage's flag set.
    pub flag_set: FlagSet,
    /// The model, as the provider spells it.
    pub model: &'a str,
    /// The most turns the tool may take.
    pub max_turns: u32,
    /// The most dollars the tool may spend by its own count.
    pub max_budget_usd: f64,
    /// The tools granted.
    pub tools: Vec<ClaudeTool>,
    /// The MCP gateway's address as the sandbox reaches it. Troubleshooting only, and required
    /// there.
    pub mcp_url: Option<&'a str>,
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
    let troubleshooting = plan.flag_set == FlagSet::Troubleshooting;
    if troubleshooting != plan.mcp_url.is_some() {
        return Err(ArgvRefused::GatewayMismatch);
    }
    let (built_in, gateway): (Vec<&ClaudeTool>, Vec<&ClaudeTool>) =
        plan.tools.iter().partition(|t| t.is_built_in());
    let tools_fit = if troubleshooting {
        built_in.is_empty() && !gateway.is_empty()
    } else {
        gateway.is_empty()
    };
    if !tools_fit {
        return Err(ArgvRefused::ToolNotAllowed);
    }
    let helper = format!("/usr/bin/cat {JOB_TOKEN_TARGET}");
    let settings = serde_json::json!({ "apiKeyHelper": helper }).to_string();
    let tools = built_in
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
    ];
    if plan.credential == ClaudeCredential::ApiKeyHelper {
        args.push(format!("{}={settings}", Flag::Settings.name()));
    }
    args.extend([
        format!("{}={}", Flag::Model.name(), plan.model),
        format!("{}={}", Flag::MaxTurns.name(), plan.max_turns.max(1)),
        format!("{}={:.4}", Flag::MaxBudgetUsd.name(), plan.max_budget_usd),
        format!("{}={tools}", Flag::Tools.name()),
    ]);
    if let Some(url) = plan.mcp_url {
        if !is_plain_gateway_url(url) {
            return Err(ArgvRefused::BadGatewayUrl);
        }
        let allowed = gateway
            .iter()
            .map(|t| t.name())
            .collect::<Vec<_>>()
            .join(",");
        args.extend([
            format!("{}={}", Flag::McpConfig.name(), mcp_config(url)),
            format!("{}={allowed}", Flag::AllowedTools.name()),
            format!("{}=dontAsk", Flag::PermissionMode.name()),
        ]);
    }
    if plan.flag_set != FlagSet::Specification {
        args.push(Flag::DisableSlashCommands.name().to_owned());
    }
    if replays_prompt(plan.flag_set) {
        args.push(format!("{}=stream-json", Flag::InputFormat.name()));
        args.push(Flag::ReplayUserMessages.name().to_owned());
    }
    if !troubleshooting {
        args.push(Flag::DangerouslySkipPermissions.name().to_owned());
    }
    Ok(args)
}

/// The MCP configuration of a troubleshooting run: one server, `factory`, over Streamable HTTP
/// at the gateway's address, with the run's bearer token as a reference to
/// [`MCP_TOKEN_VARIABLE`], never its value. Written inline in `--mcp-config=` (the form the spike
/// used, section 4.9), so no file in the run's home could be changed between writing and reading.
#[must_use]
pub fn mcp_config(url: &str) -> String {
    serde_json::json!({
        "mcpServers": {
            MCP_SERVER: {
                "type": "http",
                "url": url,
                "headers": {
                    "Authorization": format!("Bearer ${{{MCP_TOKEN_VARIABLE}}}"),
                },
            },
        },
    })
    .to_string()
}

/// A gateway address is `http://<host>:<port><path>`: a host of lower-case letters, digits, `.`
/// and `-`, a port, and a path of letters, digits, `/`, `_` and `-` that starts with `/`. No user
/// information, query, fragment, space or `$`, so nothing in it can be expanded or read as another
/// part of the configuration.
fn is_plain_gateway_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let Some((authority, path)) = rest.find('/').map(|at| rest.split_at(at)) else {
        return false;
    };
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p != 0);
    let path_ok = path.len() <= 128
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-'));
    host_ok && port_ok && path_ok
}

/// True for the flag set whose prompt is sent as a stream-json message and replayed: the
/// specification stage, the only one that runs a typed command. [`build`] writes the two flags and
/// [`stdin_for`] encodes the prompt from this one answer, so the flags and the encoding of standard
/// input cannot differ.
#[must_use]
pub const fn replays_prompt(flag_set: FlagSet) -> bool {
    matches!(flag_set, FlagSet::Specification)
}

/// The bytes the tool reads on standard input. For a flag set that replays the prompt: one
/// stream-json user message and a newline, the shape Claude Code 2.1.325 accepts with
/// `--input-format=stream-json`, `{"type":"user","message":{"role":"user","content":"<prompt>"}}`.
/// The prompt is a JSON string, so no text in it can end the message or start another. Otherwise
/// the prompt as it is. Standard input is closed after it either way, and the tool ends its run
/// there.
#[must_use]
pub fn stdin_for(flag_set: FlagSet, prompt: &str) -> Vec<u8> {
    if replays_prompt(flag_set) {
        let message = serde_json::json!({
            "type": "user",
            "message": {"role": "user", "content": prompt},
        });
        let mut bytes = message.to_string().into_bytes();
        bytes.push(b'\n');
        bytes
    } else {
        prompt.as_bytes().to_vec()
    }
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
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '@' | '[' | ']')
        })
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
    fn a_replayed_prompt_is_one_json_user_message_and_a_plain_one_is_the_text() {
        let prompt = "/speckit-specify Write it. \"quoted\"\n}\n{\"type\":\"user\"}";
        let bytes = stdin_for(FlagSet::Specification, prompt);
        assert_eq!(bytes.last(), Some(&b'\n'));
        let text = std::str::from_utf8(&bytes).expect("utf-8");
        assert_eq!(
            text.lines().count(),
            1,
            "one line, whatever the prompt holds"
        );
        let value: serde_json::Value = serde_json::from_str(text.trim_end()).expect("json");
        assert_eq!(
            value,
            serde_json::json!({"type": "user", "message": {"role": "user", "content": prompt}})
        );
        assert_eq!(stdin_for(FlagSet::Standard, prompt), prompt.as_bytes());
        assert!(replays_prompt(FlagSet::Specification));
        assert!(!replays_prompt(FlagSet::Standard));
    }

    #[test]
    fn a_gateway_address_is_a_plain_http_url() {
        for good in [
            "http://egress:8444/mcp",
            "http://10.0.0.5:1/mcp/v1",
            "http://a-b.c:65535/",
        ] {
            assert!(is_plain_gateway_url(good), "{good:?}");
        }
        for bad in [
            "",
            "https://egress:8444/mcp",
            "http://egress/mcp",
            "http://egress:8444",
            "http://egress:0/mcp",
            "http://egress:99999/mcp",
            "http://user@egress:8444/mcp",
            "http://egress:8444/mcp?x=1",
            "http://egress:8444/mcp#f",
            "http://egress:8444/${FACTORY_MCP_TOKEN}",
            "http://EGRESS:8444/mcp",
            "http://egress:8444/m cp",
            "http://[::1]:8444/mcp",
        ] {
            assert!(!is_plain_gateway_url(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_gateway_tool_is_named_for_the_factory_server_and_read_back() {
        let tool = ClaudeTool::Mcp(McpToolName::new("vm_query").expect("a name"));
        assert_eq!(tool.name(), "mcp__factory__vm_query");
        assert_eq!(ClaudeTool::from_name("mcp__factory__vm_query"), Some(tool));
        assert_eq!(ClaudeTool::from_name("mcp__other__vm_query"), None);
        assert_eq!(ClaudeTool::from_name("mcp__factory__Bad-Name"), None);
        assert_eq!(ClaudeTool::from_name("Bash"), Some(ClaudeTool::Bash));
        assert_eq!(
            ClaudeTool::from_name("mcp__factory__vm_query").map(|t| t.fixed_word()),
            Some("mcp")
        );
    }

    #[test]
    fn the_mcp_configuration_names_the_token_variable_and_never_a_value() {
        let config: serde_json::Value =
            serde_json::from_str(&mcp_config("http://egress:8444/mcp")).expect("json");
        assert_eq!(
            config,
            serde_json::json!({"mcpServers": {"factory": {
                "type": "http",
                "url": "http://egress:8444/mcp",
                "headers": {"Authorization": "Bearer ${FACTORY_MCP_TOKEN}"},
            }}})
        );
    }

    #[test]
    fn the_names_of_all_flags_are_distinct() {
        let mut names: Vec<&str> = Flag::ALL.iter().map(|f| f.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Flag::ALL.len());
    }
}
