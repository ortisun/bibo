//! The model providers the broker can forward to, and which agent runtime uses which.

use factory_ports::agent::RuntimeId;

/// A model provider. The set is closed: a provider is added here, in a reviewed change, together
/// with its routes, its credential header and its way of reading usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Provider {
    /// Anthropic, the Messages API. Claude Code uses it.
    Anthropic,
    /// OpenAI, the Responses and Chat Completions APIs. Codex uses it.
    OpenAi,
}

impl Provider {
    /// The name used in audit lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    /// The provider that an agent runtime talks to, or `None` for a runtime that talks to no
    /// provider through this broker (the fake runtime). A token whose models name only such
    /// runtimes is valid at no route.
    #[must_use]
    pub fn for_runtime(runtime: &RuntimeId) -> Option<Self> {
        match runtime.as_str() {
            "claude-code-cli" => Some(Self::Anthropic),
            "codex-cli" => Some(Self::OpenAi),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_accepted_tool_maps_to_one_provider_and_anything_else_to_none() {
        let id = |name: &str| RuntimeId::new(name).expect("a slug");
        assert_eq!(
            Provider::for_runtime(&id("claude-code-cli")),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            Provider::for_runtime(&id("codex-cli")),
            Some(Provider::OpenAi)
        );
        assert_eq!(Provider::for_runtime(&id("fake")), None);
    }
}
