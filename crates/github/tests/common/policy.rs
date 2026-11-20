//! The redactor and the App permission lists, read from `policies/security.yaml` itself, so a
//! test cannot drift from the policy it claims to check.

use factory_domain::redaction::{EntropySpec, PatternAction, PatternSpec, Redactor};
use factory_github::{AppPolicy, Level};

const POLICY: &str = include_str!("../../../../policies/security.yaml");

fn single_quoted(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                out.push('\'');
            } else {
                return out;
            }
        } else {
            out.push(c);
        }
    }
    panic!("a quoted scalar in the policy does not end");
}

fn policy_patterns() -> Vec<PatternSpec> {
    let secrets = POLICY
        .split("\nsecrets:\n")
        .nth(1)
        .expect("the policy has a secrets section");
    let block = secrets
        .split("  patterns:\n")
        .nth(1)
        .and_then(|rest| rest.split("  entropy_heuristic:").next())
        .expect("the secrets section lists patterns");
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("- { id: "))
        .map(|line| {
            let id = line
                .split("id: ")
                .nth(1)
                .and_then(|rest| rest.split(',').next())
                .expect("an id")
                .trim();
            let regex = single_quoted(line.split("regex: '").nth(1).expect("a regex"));
            let action = match line
                .rsplit("action: ")
                .next()
                .and_then(|rest| rest.split([',', ' ', '}']).next())
            {
                Some("block") => PatternAction::Block,
                _ => PatternAction::Flag,
            };
            PatternSpec::new(id, regex, action)
        })
        .collect()
}

/// A redactor with the patterns of the policy.
pub fn redactor() -> Redactor {
    Redactor::builder()
        .patterns(policy_patterns())
        .entropy(EntropySpec {
            min_length: 32,
            min_bits_per_char: 4.2,
            action: PatternAction::Flag,
        })
        .build()
        .expect("the policy patterns compile")
}

/// The `credentials.github_app` lists of the policy as the adapter takes them.
pub fn app_policy() -> AppPolicy {
    let section = POLICY
        .split("  github_app:\n")
        .nth(1)
        .expect("the policy has a github_app section");
    let required_block = section
        .split("    permissions_required:\n")
        .nth(1)
        .and_then(|rest| rest.split("    permissions_forbidden:").next())
        .expect("required permissions");
    let required: Vec<(String, Level)> = required_block
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter_map(|line| line.split_once(": "))
        .map(|(name, level)| {
            (
                name.to_owned(),
                Level::parse(level.trim()).expect("a known level"),
            )
        })
        .collect();
    let forbidden_block = section
        .split("    permissions_forbidden:\n")
        .nth(1)
        .and_then(|rest| rest.split("    installation_token:").next())
        .expect("forbidden permissions");
    let forbidden: Vec<String> = forbidden_block
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("- "))
        .map(|rest| rest.split('#').next().unwrap_or("").trim().to_owned())
        .collect();
    let required_refs: Vec<(&str, Level)> =
        required.iter().map(|(n, l)| (n.as_str(), *l)).collect();
    let forbidden_refs: Vec<&str> = forbidden.iter().map(String::as_str).collect();
    AppPolicy::new(&required_refs, &forbidden_refs)
}
