//! The Codex command line, built from a closed allow list.
//!
//! The set follows the spike (section 6.1) and the recorded `codex-factory-profile` runs:
//!
//! * A **custom model provider** named `broker`. Codex ignores `OPENAI_BASE_URL`, and its built-in
//!   provider tries a WebSocket first. The entry points at the broker, reads the credential from
//!   the job token file with an `auth` command (never a variable), turns the WebSocket off, and
//!   caps both retry counts.
//! * `--disable unbounded_connection_retries`, because Codex otherwise retries a lost connection
//!   forever.
//! * `--disable plugins` and `-c analytics.enabled=false` (and the other switches the spike
//!   recorded): together they leave the broker as the only host the tool contacts.
//! * `-c project_doc_max_bytes=0`: Codex loads `AGENTS.md` by default, and `--ignore-user-config`
//!   and `--ignore-rules` do not stop it.
//! * `-c skills.bundled.enabled=false`: the tool's own skills are not the factory's to offer.
//! * `-c web_search="disabled"`: Codex 0.163.0 puts `{"type": "web_search", "external_web_access":
//!   true}` in the tool list of every request by default, a search the **provider** runs from its
//!   own network. The broker refuses a request that names a provider-side tool (finding EGR-1 of
//!   the isolation core review, `crates/egress/src/broker/shape`), so without this setting every
//!   Codex run would be refused; with it the tool list holds only tools Codex runs itself.
//! * An explicit model with `-m`: the default is the most expensive one.
//! * The prompt is read from standard input (`-`).
//!
//! **`--dangerously-bypass-approvals-and-sandbox` is always written, and only for a verified
//! target.** Codex's own sandbox needs user namespaces that the container's seccomp profile refuses,
//! so without the flag every command fails (spike section 4.8). The flag is acceptable here
//! because the container is the boundary: non-root, no capabilities, read-only root, `no-new-privileges`,
//! seccomp, and a network that reaches only the broker. The builder takes a [`VerifiedTarget`] so a
//! container that was not checked cannot get the flag.
//!
//! **Tool bridge.** Nothing here claims more than the spike verified. When no shell access is
//! granted, `--disable shell_tool` and `--disable unified_exec` remove the shell from the tools the
//! model sees. `apply_patch` stays: Codex 0.163.0 has no switch for it (spike section 4.9).

use factory_domain::contracts::agent_manifest::{AllowedTool, ToolAccess};
use factory_ports::sandbox::{JOB_TOKEN_TARGET, WORKSPACE_TARGET};

use crate::target::VerifiedTarget;

/// The name of the provider entry.
pub const PROVIDER_NAME: &str = "broker";

/// A Codex feature the adapter switches off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Retry a lost connection without end.
    UnboundedConnectionRetries,
    /// Plugin synchronisation with GitHub.
    Plugins,
    /// The apps catalogue.
    Apps,
    /// Remote plugins.
    RemotePlugin,
    /// Tool suggestions.
    ToolSuggest,
    /// Image generation.
    ImageGeneration,
    /// Plugin sharing.
    PluginSharing,
    /// The shell tool.
    ShellTool,
    /// The unified exec tool.
    UnifiedExec,
}

impl Feature {
    /// The features every run switches off.
    pub const ALWAYS_OFF: [Feature; 7] = [
        Feature::UnboundedConnectionRetries,
        Feature::Plugins,
        Feature::Apps,
        Feature::RemotePlugin,
        Feature::ToolSuggest,
        Feature::ImageGeneration,
        Feature::PluginSharing,
    ];

    /// The features a run without shell access also switches off.
    pub const NO_SHELL: [Feature; 2] = [Feature::ShellTool, Feature::UnifiedExec];

    /// The name `--disable` takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnboundedConnectionRetries => "unbounded_connection_retries",
            Self::Plugins => "plugins",
            Self::Apps => "apps",
            Self::RemotePlugin => "remote_plugin",
            Self::ToolSuggest => "tool_suggest",
            Self::ImageGeneration => "image_generation",
            Self::PluginSharing => "plugin_sharing",
            Self::ShellTool => "shell_tool",
            Self::UnifiedExec => "unified_exec",
        }
    }

    /// The names of every feature the adapter ever switches off, for the probe.
    #[must_use]
    pub fn all_names() -> Vec<&'static str> {
        Self::ALWAYS_OFF
            .iter()
            .chain(Self::NO_SHELL.iter())
            .map(|f| f.name())
            .collect()
    }
}

/// Every flag the adapter may write, other than `-c` settings and `--disable` features.
pub const ALLOWED_FLAGS: &[&str] = &[
    "exec",
    "--json",
    "--ephemeral",
    "--skip-git-repo-check",
    "-C",
    "--ignore-user-config",
    "--ignore-rules",
    "--disable",
    "-c",
    "-m",
    "--dangerously-bypass-approvals-and-sandbox",
    "-",
];

/// Every `-c` key the adapter may write.
pub const ALLOWED_CONFIG_KEYS: &[&str] = &[
    "project_doc_max_bytes",
    "skills.bundled.enabled",
    "web_search",
    "analytics.enabled",
    "feedback.enabled",
    "check_for_update_on_startup",
    "model_provider",
    "model_providers.broker",
];

/// The built-in tools that the access levels need. Codex has one shell tool; only the absence of
/// shell access changes the command line.
#[must_use]
pub fn grants_shell(granted: &[AllowedTool]) -> bool {
    granted
        .iter()
        .any(|tool| tool.access == ToolAccess::ExecuteSandboxed)
}

/// Why an argument vector was not built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgvRefused {
    /// The model name has characters a model name does not have.
    #[error("the model name is not a plain model name")]
    BadModel,
    /// The broker origin has characters that do not belong in a URL.
    #[error("the broker address is not a plain origin")]
    BadBroker,
}

/// What a Codex run needs to know to build its command line.
#[derive(Debug, Clone)]
pub struct Plan<'a> {
    /// The model, as the provider spells it.
    pub model: &'a str,
    /// The broker's origin, such as `http://egress:8080`.
    pub broker_origin: &'a str,
    /// Whether the run may use the shell tool.
    pub shell: bool,
    /// How many times a failed request and a dropped stream are retried.
    pub retries: u32,
}

/// A TOML basic string, with the characters that need it escaped.
fn toml_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A model name is letters, digits and `. _ - : / @ [ ]`, starts with a letter or digit, and is
/// short.
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

/// The arguments of one Codex run. The target is the proof that the bypass flag is safe.
///
/// # Errors
/// [`ArgvRefused`] for a model name or a broker address that cannot be written.
pub fn build(plan: &Plan<'_>, target: &VerifiedTarget) -> Result<Vec<String>, ArgvRefused> {
    let _proof: &VerifiedTarget = target;
    if !is_plain_model_name(plan.model) {
        return Err(ArgvRefused::BadModel);
    }
    if crate::command::broker_origin(plan.broker_origin).is_err() {
        return Err(ArgvRefused::BadBroker);
    }
    let base = format!("{}/v1", plan.broker_origin.trim_end_matches('/'));
    let entry = format!(
        "model_providers.{PROVIDER_NAME}={{name={}, base_url={}, auth={{command={}, args=[{}]}}, wire_api=\"responses\", supports_websockets=false, request_max_retries={r}, stream_max_retries={r}}}",
        toml_string("Broker"),
        toml_string(&base),
        toml_string("/usr/bin/cat"),
        toml_string(JOB_TOKEN_TARGET),
        r = plan.retries,
    );
    let mut args: Vec<String> = [
        "exec",
        "--json",
        "--ephemeral",
        "--skip-git-repo-check",
        "-C",
    ]
    .map(String::from)
    .to_vec();
    args.push(WORKSPACE_TARGET.to_owned());
    args.extend(["--ignore-user-config", "--ignore-rules"].map(String::from));
    for feature in Feature::ALWAYS_OFF {
        args.extend(["--disable".to_owned(), feature.name().to_owned()]);
    }
    if !plan.shell {
        for feature in Feature::NO_SHELL {
            args.extend(["--disable".to_owned(), feature.name().to_owned()]);
        }
    }
    for setting in [
        "project_doc_max_bytes=0",
        "skills.bundled.enabled=false",
        "web_search=\"disabled\"",
        "analytics.enabled=false",
        "feedback.enabled=false",
        "check_for_update_on_startup=false",
    ] {
        args.extend(["-c".to_owned(), setting.to_owned()]);
    }
    args.extend(["-m".to_owned(), plan.model.to_owned()]);
    args.extend([
        "-c".to_owned(),
        format!("model_provider={}", toml_string(PROVIDER_NAME)),
        "-c".to_owned(),
        entry,
    ]);
    args.push("--dangerously-bypass-approvals-and-sandbox".to_owned());
    args.push("-".to_owned());
    Ok(args)
}

/// The arguments of the free skill listing, `codex debug prompt-input`, with the settings that
/// decide which skills the tool finds.
#[must_use]
pub fn skill_listing_args() -> Vec<String> {
    let mut args = vec!["debug".to_owned(), "prompt-input".to_owned()];
    for setting in ["project_doc_max_bytes=0", "skills.bundled.enabled=false"] {
        args.extend(["-c".to_owned(), setting.to_owned()]);
    }
    args.extend(["--disable".to_owned(), Feature::Plugins.name().to_owned()]);
    args.push("list the skills".to_owned());
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_strings_escape_quotes_and_backslashes_and_control_characters() {
        assert_eq!(toml_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(toml_string("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn feature_names_are_distinct() {
        let mut names = Feature::all_names();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }
}
