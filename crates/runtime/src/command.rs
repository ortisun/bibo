//! The command line of a tool run, and the clean environment it starts with.
//!
//! `SandboxSession::exec` takes an argument vector and nothing else: no environment and no shell.
//! The adapter therefore builds a vector that starts `env -i` and names every variable the tool
//! gets, from the closed set [`EnvName`]. Nothing the agent, the repository, the prompt or the
//! request wrote can add a name or reach the vector as anything but a value (negative test
//! NT-TOOL-06). A credential is never one of the names: the job token is a file that the tool reads
//! through a helper (spike section 4.5).
//!
//! The vector also wraps the tool in `timeout -s INT`. At the soft deadline the tool is asked to
//! stop, so it can still report what it used (Claude Code answers an interrupt with a clean result
//! event). The hard deadline is the exec timeout, which ends the whole sandbox session.

/// The program that clears the environment.
pub const ENV_PROGRAM: &str = "/usr/bin/env";

/// The program that sends the soft-deadline interrupt.
pub const TIMEOUT_PROGRAM: &str = "/usr/bin/timeout";

/// Seconds the tool gets between the interrupt and the kill signal of `timeout`.
pub const KILL_AFTER_SECONDS: u32 = 10;

/// Seconds added to the soft deadline for the hard deadline of the exec call, so that the soft
/// path (interrupt, then kill) always finishes before the sandbox kills the container.
pub const HARD_DEADLINE_MARGIN_SECONDS: u32 = KILL_AFTER_SECONDS + 15;

/// The environment variables a tool run may have. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EnvName {
    /// The tool's home directory, which holds its state. A fresh directory for every run.
    Home,
    /// Where the tool finds the programs it starts.
    Path,
    /// Claude Code: where model traffic goes. The broker.
    AnthropicBaseUrl,
    /// Claude Code: `1` stops telemetry, the update check and the other background traffic.
    ClaudeDisableNonessentialTraffic,
    /// Claude Code: how many times a failed request is retried.
    ClaudeMaxRetries,
    /// Claude Code: `1` hides the tool's own bundled skills, so that the skills a stage sees are the
    /// pinned ones and nothing else.
    ClaudeDisableBundledSkills,
}

impl EnvName {
    /// Every name, in the order they are written.
    pub const ALL: [EnvName; 6] = [
        EnvName::Home,
        EnvName::Path,
        EnvName::AnthropicBaseUrl,
        EnvName::ClaudeDisableNonessentialTraffic,
        EnvName::ClaudeMaxRetries,
        EnvName::ClaudeDisableBundledSkills,
    ];

    /// The variable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Home => "HOME",
            Self::Path => "PATH",
            Self::AnthropicBaseUrl => "ANTHROPIC_BASE_URL",
            Self::ClaudeDisableNonessentialTraffic => "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
            Self::ClaudeMaxRetries => "CLAUDE_CODE_MAX_RETRIES",
            Self::ClaudeDisableBundledSkills => "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS",
        }
    }
}

/// A value that cannot be an environment variable value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("an environment value is one line of printable text with no NUL byte")]
pub struct BadEnvValue;

/// The environment of one tool run: only names from [`EnvName`], each at most once.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolEnv(Vec<(EnvName, String)>);

impl ToolEnv {
    /// An empty environment.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Sets a variable, replacing an earlier value of the same name.
    ///
    /// # Errors
    /// [`BadEnvValue`] for a value with a control character.
    pub fn set(mut self, name: EnvName, value: impl Into<String>) -> Result<Self, BadEnvValue> {
        let value = value.into();
        if value.chars().any(char::is_control) {
            return Err(BadEnvValue);
        }
        self.0.retain(|(existing, _)| *existing != name);
        self.0.push((name, value));
        self.0.sort_by_key(|(name, _)| *name);
        Ok(self)
    }

    /// The pairs, in the order they are written.
    #[must_use]
    pub fn pairs(&self) -> &[(EnvName, String)] {
        &self.0
    }

    /// The value of a variable.
    #[must_use]
    pub fn get(&self, name: EnvName) -> Option<&str> {
        self.0
            .iter()
            .find(|(existing, _)| *existing == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The broker address cannot be given to a tool.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the broker address must be an http or https URL with no path, query or whitespace")]
pub struct BadBrokerUrl;

/// The broker's origin: `scheme://host[:port]`, with no trailing slash. The tools add their own
/// paths (`/v1/messages`, `/v1/responses`). An address with a path, a query, a fragment or a
/// character that does not belong in a URL is refused, so a value cannot carry anything but an
/// address.
///
/// # Errors
/// [`BadBrokerUrl`].
pub fn broker_origin(base_url: &str) -> Result<String, BadBrokerUrl> {
    let trimmed = base_url.trim_end_matches('/');
    let rest = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .ok_or(BadBrokerUrl)?;
    let host_ok = !rest.is_empty()
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if host_ok {
        Ok(trimmed.to_owned())
    } else {
        Err(BadBrokerUrl)
    }
}

/// A tool run: its environment, its soft deadline, the program and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCommand {
    /// The environment.
    pub env: ToolEnv,
    /// Seconds until the tool is interrupted.
    pub soft_deadline_seconds: u32,
    /// The tool's path inside the image.
    pub program: String,
    /// The arguments, built from a closed allow list.
    pub args: Vec<String>,
}

impl ToolCommand {
    /// The argument vector for `SandboxSession::exec`:
    /// `env -i NAME=value ... timeout -s INT -k <n> <seconds> <program> <args>`.
    #[must_use]
    pub fn into_argv(self) -> Vec<String> {
        let mut argv = vec![ENV_PROGRAM.to_owned(), "-i".to_owned()];
        argv.extend(
            self.env
                .pairs()
                .iter()
                .map(|(name, value)| format!("{}={value}", name.as_str())),
        );
        argv.extend([
            TIMEOUT_PROGRAM.to_owned(),
            "-s".to_owned(),
            "INT".to_owned(),
            "-k".to_owned(),
            KILL_AFTER_SECONDS.to_string(),
            self.soft_deadline_seconds.to_string(),
            self.program,
        ]);
        argv.extend(self.args);
        argv
    }

    /// The same command without the soft deadline, for the short probe commands. They are bounded
    /// by the exec timeout alone.
    #[must_use]
    pub fn into_probe_argv(self) -> Vec<String> {
        let mut argv = vec![ENV_PROGRAM.to_owned(), "-i".to_owned()];
        argv.extend(
            self.env
                .pairs()
                .iter()
                .map(|(name, value)| format!("{}={value}", name.as_str())),
        );
        argv.push(self.program);
        argv.extend(self.args);
        argv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(env: ToolEnv) -> ToolCommand {
        ToolCommand {
            env,
            soft_deadline_seconds: 60,
            program: "/usr/local/bin/tool".to_owned(),
            args: vec!["--flag".to_owned()],
        }
    }

    #[test]
    fn the_vector_clears_the_environment_and_names_each_variable_once() {
        let env = ToolEnv::new()
            .set(EnvName::Path, "/usr/bin")
            .expect("a path")
            .set(EnvName::Home, "/tmp/h")
            .expect("a home")
            .set(EnvName::Home, "/tmp/other")
            .expect("a second home replaces the first");
        let argv = command(env).into_argv();
        assert_eq!(&argv[..2], ["/usr/bin/env", "-i"]);
        assert_eq!(argv[2], "HOME=/tmp/other");
        assert_eq!(argv[3], "PATH=/usr/bin");
        assert_eq!(argv[4], TIMEOUT_PROGRAM);
        assert_eq!(&argv[5..8], ["-s", "INT", "-k"]);
        assert_eq!(argv[9], "60");
        assert_eq!(argv[10], "/usr/local/bin/tool");
        assert_eq!(argv[11], "--flag");
    }

    #[test]
    fn a_value_with_a_control_character_is_refused() {
        assert_eq!(
            ToolEnv::new().set(EnvName::Home, "/tmp\nLD_PRELOAD=/x"),
            Err(BadEnvValue)
        );
    }

    #[test]
    fn the_broker_address_is_an_origin_and_nothing_more() {
        assert_eq!(
            broker_origin("http://egress:8080/").as_deref(),
            Ok("http://egress:8080")
        );
        assert_eq!(
            broker_origin("https://broker.internal").as_deref(),
            Ok("https://broker.internal")
        );
        for bad in [
            "http://egress:8080/v1",
            "http://egress:8080?x=1",
            "http://user:pw@egress",
            "http://egress#frag",
            "ftp://egress",
            "egress:8080",
            "http://",
            "http://a b",
            "http://a\nb",
        ] {
            assert_eq!(broker_origin(bad), Err(BadBrokerUrl), "{bad:?}");
        }
    }

    #[test]
    fn the_closed_set_has_no_credential_and_no_loader_variable() {
        for name in EnvName::ALL {
            let text = name.as_str();
            assert!(!text.contains("KEY") && !text.contains("TOKEN") && !text.contains("SECRET"));
            assert!(!text.starts_with("LD_") && text != "RUSTFLAGS" && text != "NODE_OPTIONS");
        }
    }
}
