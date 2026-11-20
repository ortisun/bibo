//! The request headers and the query that cross to the provider, and the response headers that
//! come back, each from a closed set.

use super::Violation;
use crate::broker::Provider;

/// The `anthropic-beta` values the recorded sessions of Claude Code 2.1.311 send, all of which
/// change how the model is driven and none of which makes the provider call out for the caller.
const ANTHROPIC_BETAS: &[&str] = &[
    "claude-code-20250219",
    "interleaved-thinking-2025-05-14",
    "context-management-2025-06-27",
    "per-turn-control-2026-07-01",
    "mid-conversation-tool-changes-2026-07-01",
    "thinking-token-count-2026-05-13",
    "advanced-tool-use-2025-11-20",
    "effort-2025-11-24",
    "thinking-display-updates-2026-08-18",
];

/// The beta that tells the provider the credential is an OAuth (subscription) token. Allowed, and
/// always sent, only when the broker relays the owner's subscription (ADR 0020). Claude Code
/// 2.1.323 sends it, with `claude-code-20250219`, when it runs on `CLAUDE_CODE_OAUTH_TOKEN`, and
/// the provider accepts a subscription token only with it (both VERIFIED by the owner on
/// 2026-11-12).
pub const OAUTH_BETA: &str = "oauth-2025-04-20";

/// Beta families that switch on a tool the provider runs for the caller, or a way to reach a
/// remote server, or a file store. A request that asks for one is refused, not trimmed: a
/// sandbox that asks for them is not a Claude Code run.
const ANTHROPIC_FORBIDDEN_BETAS: &[&str] = &[
    "mcp",
    "web-fetch",
    "web-search",
    "code-execution",
    "computer-use",
    "files-api",
    "skills",
    "tool-search",
    "memory",
    "container",
    "agent",
];

/// The `anthropic-beta` header the broker forwards, from the one the sandbox sent.
///
/// The header is a comma-separated list. Every value must be a plain lowercase token. A value of
/// a forbidden family refuses the request. A value that is well formed but not on the list of
/// `ANTHROPIC_BETAS` is dropped. The OpenAI header is dropped whole: no runtime sends one.
///
/// # Errors
/// [`Violation::BetaHeader`] for a malformed list or a forbidden family.
pub fn beta_header(provider: Provider, value: Option<&str>) -> Result<Option<String>, Violation> {
    filter_betas(provider, value, false)
}

/// The `anthropic-beta` header the broker forwards when it relays the owner's subscription: the
/// list of [`beta_header`], with [`OAUTH_BETA`] allowed and always present, because the provider
/// takes a subscription token only with it.
///
/// # Errors
/// [`Violation::BetaHeader`], as for [`beta_header`].
pub fn subscription_beta_header(
    provider: Provider,
    value: Option<&str>,
) -> Result<Option<String>, Violation> {
    if provider != Provider::Anthropic {
        return Ok(None);
    }
    let kept = filter_betas(provider, value, true)?;
    Ok(Some(match kept {
        Some(list) if list.split(',').any(|b| b == OAUTH_BETA) => list,
        Some(list) => format!("{list},{OAUTH_BETA}"),
        None => OAUTH_BETA.to_owned(),
    }))
}

fn filter_betas(
    provider: Provider,
    value: Option<&str>,
    subscription: bool,
) -> Result<Option<String>, Violation> {
    let Some(value) = value else {
        return Ok(None);
    };
    if provider != Provider::Anthropic {
        return Ok(None);
    }
    let allowed =
        |token: &str| ANTHROPIC_BETAS.contains(&token) || (subscription && token == OAUTH_BETA);
    let mut kept: Vec<&str> = Vec::new();
    for token in value.split(',').map(str::trim) {
        let well_formed = !token.is_empty()
            && token.len() <= 64
            && token
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b));
        if !well_formed {
            return Err(Violation::BetaHeader);
        }
        if ANTHROPIC_FORBIDDEN_BETAS
            .iter()
            .any(|family| token.starts_with(family))
        {
            return Err(Violation::BetaHeader);
        }
        if allowed(token) && !kept.contains(&token) {
            kept.push(token);
        }
    }
    Ok((!kept.is_empty()).then(|| kept.join(",")))
}

/// The query string the broker forwards. Claude Code sends `beta=true`; nothing else is forwarded,
/// because the query of a model route has no other use.
#[must_use]
pub fn upstream_query(provider: Provider, query: Option<&str>) -> Option<&'static str> {
    (provider == Provider::Anthropic && query == Some("beta=true")).then_some("beta=true")
}

/// The media types of an answer the sandbox gets as they are. Any other type is passed as opaque
/// bytes.
#[must_use]
pub fn response_content_type(value: &str) -> &'static str {
    let media = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match media.as_str() {
        "application/json" => "application/json",
        "text/event-stream" => "text/event-stream",
        "text/plain" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// The retry delay of an answer, in whole seconds, when the provider gave one in that form. A date
/// form, a fraction or a very long delay is not passed.
#[must_use]
pub fn response_retry_after(value: &str) -> Option<u32> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 6 && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse::<u32>().ok())
        .flatten()
        .filter(|seconds| *seconds <= 3600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorded_betas_pass_and_unknown_well_formed_ones_are_dropped() {
        let sent = "claude-code-20250219,effort-2025-11-24, some-new-feature-2030-01-01 ,effort-2025-11-24";
        assert_eq!(
            beta_header(Provider::Anthropic, Some(sent)),
            Ok(Some("claude-code-20250219,effort-2025-11-24".to_owned()))
        );
        assert_eq!(
            beta_header(Provider::Anthropic, Some("something-else-2030-01-01")),
            Ok(None)
        );
        assert_eq!(beta_header(Provider::Anthropic, None), Ok(None));
        assert_eq!(
            beta_header(Provider::OpenAi, Some("assistants=v2")),
            Ok(None),
            "the OpenAI header is dropped whole"
        );
    }

    #[test]
    fn a_beta_that_switches_on_a_provider_side_tool_refuses_the_request() {
        for bad in [
            "web-fetch-2025-09-10",
            "claude-code-20250219,mcp-client-2025-04-04",
            "mcp-client-2025-11-20",
            "code-execution-2025-05-22",
            "computer-use-2025-01-24",
            "files-api-2025-04-14",
            "skills-2025-10-02",
            "web-search-2025-03-05",
            "tool-search-tool-2025-10-19",
            "WEB-FETCH-2025-09-10",
            "web fetch",
            "",
            ",",
            "a,,b",
            "mcp-client-2025-04-04\n",
        ] {
            assert_eq!(
                beta_header(Provider::Anthropic, Some(bad)),
                Err(Violation::BetaHeader),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_oauth_beta_passes_and_is_added_only_when_the_subscription_is_relayed() {
        let sent = "claude-code-20250219,oauth-2025-04-20,effort-2025-11-24";
        assert_eq!(
            beta_header(Provider::Anthropic, Some(sent)),
            Ok(Some("claude-code-20250219,effort-2025-11-24".to_owned())),
            "an API key run does not forward the OAuth beta"
        );
        assert_eq!(
            subscription_beta_header(Provider::Anthropic, Some(sent)),
            Ok(Some(sent.to_owned()))
        );
        assert_eq!(
            subscription_beta_header(Provider::Anthropic, Some("claude-code-20250219")),
            Ok(Some("claude-code-20250219,oauth-2025-04-20".to_owned()))
        );
        assert_eq!(
            subscription_beta_header(Provider::Anthropic, None),
            Ok(Some(OAUTH_BETA.to_owned()))
        );
        assert_eq!(
            subscription_beta_header(Provider::Anthropic, Some("web-fetch-2025-09-10")),
            Err(Violation::BetaHeader),
            "a forbidden family still refuses the request"
        );
        assert_eq!(
            subscription_beta_header(Provider::OpenAi, Some(sent)),
            Ok(None)
        );
    }

    #[test]
    fn only_the_beta_query_is_forwarded() {
        assert_eq!(
            upstream_query(Provider::Anthropic, Some("beta=true")),
            Some("beta=true")
        );
        assert_eq!(
            upstream_query(Provider::Anthropic, Some("beta=true&x=1")),
            None
        );
        assert_eq!(upstream_query(Provider::Anthropic, Some("x=1")), None);
        assert_eq!(upstream_query(Provider::Anthropic, None), None);
        assert_eq!(upstream_query(Provider::OpenAi, Some("beta=true")), None);
    }

    #[test]
    fn answer_headers_are_reduced_to_a_type_and_a_delay_in_seconds() {
        assert_eq!(
            response_content_type("application/json; charset=utf-8"),
            "application/json"
        );
        assert_eq!(
            response_content_type("Text/Event-Stream"),
            "text/event-stream"
        );
        assert_eq!(
            response_content_type("text/html"),
            "application/octet-stream"
        );
        assert_eq!(response_retry_after("30"), Some(30));
        assert_eq!(response_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(response_retry_after("1.5"), None);
        assert_eq!(response_retry_after("99999"), None);
        assert_eq!(response_retry_after(""), None);
    }
}
