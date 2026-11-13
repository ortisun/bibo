//! Checks that the types cannot make by themselves: that every regular expression and glob
//! compiles in the dialect the policy names, that identifiers are unique, and that a name used in
//! one place is defined in another.
//!
//! Each check records a [`Problem`] with the path of the field, written like
//! `secrets.patterns[3].regex`, so the loader can add the line from the YAML source.

use std::collections::BTreeSet;

use factory_domain::vocabulary::RiskTier;

use super::approval::ApprovalPolicy;
use super::common::{GlobText, RegexText};
use super::security::SecurityPolicy;

/// What kind of rule a [`Problem`] breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    /// A regex that does not compile.
    InvalidRegex,
    /// A glob that does not compile.
    InvalidGlob,
    /// Two entries share an identifier.
    DuplicateId,
    /// A name that nothing defines.
    UnknownReference,
    /// Another rule of the policy.
    Constraint,
}

/// One broken rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The field.
    pub path: String,
    /// The kind of rule.
    pub kind: ProblemKind,
    /// Plain English: what is wrong and what to change.
    pub message: String,
}

#[derive(Default)]
struct Problems(Vec<Problem>);

/// The least and the most seconds a blocked job may keep its installation tokens (LB-04).
const MIN_BLOCKED_REVOKE_S: u64 = 60;
const MAX_BLOCKED_REVOKE_S: u64 = 86_400;

impl Problems {
    fn add(&mut self, path: impl Into<String>, kind: ProblemKind, message: impl Into<String>) {
        self.0.push(Problem {
            path: path.into(),
            kind,
            message: message.into(),
        });
    }

    fn regex(&mut self, path: &str, regex: &RegexText) {
        if let Err(reason) = regex.compile() {
            self.add(
                path,
                ProblemKind::InvalidRegex,
                format!(
                    "this regular expression does not compile in the Rust `regex` dialect (no look-around, no back-references): {}",
                    first_line(&reason)
                ),
            );
        }
    }

    fn glob(&mut self, path: &str, glob: &GlobText) {
        if glob.pattern().is_empty() {
            self.add(path, ProblemKind::InvalidGlob, "a glob must not be empty");
        } else if let Err(reason) = glob.compile() {
            self.add(
                path,
                ProblemKind::InvalidGlob,
                format!(
                    "this glob does not compile in the `globset` dialect: {}",
                    first_line(&reason)
                ),
            );
        }
    }

    /// Records a duplicate for every id that appears more than once. `ids` is in file order.
    fn unique<'a>(&mut self, list: &str, ids: impl Iterator<Item = &'a str>) {
        let mut seen = BTreeSet::new();
        for (index, id) in ids.enumerate() {
            if !seen.insert(id) {
                self.add(
                    format!("{list}[{index}].id"),
                    ProblemKind::DuplicateId,
                    format!("the id `{id}` is used twice in `{list}`; each id is defined once"),
                );
            }
        }
    }

    fn defined(&mut self, path: &str, name: &str, known: &BTreeSet<&str>, what: &str) {
        if !known.contains(name) {
            self.add(
                path,
                ProblemKind::UnknownReference,
                format!(
                    "`{name}` is not a defined {what}; it must be one of: {}",
                    join(known)
                ),
            );
        }
    }
}

fn first_line(text: &str) -> String {
    text.lines().last().unwrap_or(text).trim().to_owned()
}

fn join(set: &BTreeSet<&str>) -> String {
    set.iter().copied().collect::<Vec<_>>().join(", ")
}

/// All problems in a security policy, in a stable order.
#[must_use]
pub fn security_problems(policy: &SecurityPolicy) -> Vec<Problem> {
    let mut found = Problems::default();

    if policy.policy.id != "security" {
        found.add(
            "policy.id",
            ProblemKind::Constraint,
            "this file must be the security policy, with `id: security`",
        );
    }
    if policy.policy.version == 0 {
        found.add(
            "policy.version",
            ProblemKind::Constraint,
            "the version starts at 1",
        );
    }

    // LB-04: a blocked job gives up its installation tokens after this long. Zero would revoke at
    // the first pass, which is not a wait, and a bound above a day is no bound.
    let blocked_after = policy
        .credentials
        .github_app
        .installation_token
        .revoke_when_blocked_after_s;
    if !(MIN_BLOCKED_REVOKE_S..=MAX_BLOCKED_REVOKE_S).contains(&blocked_after) {
        found.add(
            "credentials.github_app.installation_token.revoke_when_blocked_after_s",
            ProblemKind::Constraint,
            format!(
                "the seconds a blocked job keeps its tokens must be between {MIN_BLOCKED_REVOKE_S} and {MAX_BLOCKED_REVOKE_S}"
            ),
        );
    }

    // The App's permissions. A required level is both what the App must hold and the most it may
    // hold (`audit_app`), so it must be a level GitHub grants, and a permission cannot be required
    // and forbidden at once. `administration: read` is required since the owner's decision of
    // 2026-11-12; `administration: write` stays refused because `read` is its ceiling.
    let app = &policy.credentials.github_app;
    for (name, level) in &app.permissions_required {
        let key = format!("credentials.github_app.permissions_required.{name}");
        if level != "read" && level != "write" {
            found.add(
                key.clone(),
                ProblemKind::Constraint,
                "a required permission is `read` or `write`",
            );
        }
        if app.permissions_forbidden.iter().any(|f| f == name) {
            found.add(
                key,
                ProblemKind::Constraint,
                "a permission cannot be both required and forbidden",
            );
        }
    }

    // ADR 0020: the subscription token is the owner's own login. Only the broker holds it, it never
    // reaches a sandbox, only Anthropic's subscription is relayed, and the redactor knows it by an
    // exact value.
    let subscription = &policy.credentials.model_providers.subscription_token;
    let sub = "credentials.model_providers.subscription_token";
    if !subscription.never_in_sandbox {
        found.add(
            format!("{sub}.never_in_sandbox"),
            ProblemKind::Constraint,
            "the subscription token never reaches a sandbox; this must be true",
        );
    }
    if subscription.held_by != ["model_broker"] {
        found.add(
            format!("{sub}.held_by"),
            ProblemKind::Constraint,
            "only the model broker holds the subscription token: `[model_broker]`",
        );
    }
    if subscription.providers != ["anthropic"] {
        found.add(
            format!("{sub}.providers"),
            ProblemKind::Constraint,
            "only the Anthropic subscription can be relayed by the broker: `[anthropic]`",
        );
    }
    if !policy
        .secrets
        .exact_values
        .register_from
        .contains(&subscription.registered_for_redaction_as)
    {
        found.add(
            format!("{sub}.registered_for_redaction_as"),
            ProblemKind::UnknownReference,
            "the kind the subscription token is registered under must be listed in secrets.exact_values.register_from",
        );
    }

    // Regular expressions.
    for (i, pattern) in policy.secrets.patterns.iter().enumerate() {
        found.regex(&format!("secrets.patterns[{i}].regex"), &pattern.regex);
    }
    for (i, class) in policy.forbidden_command_classes.iter().enumerate() {
        for (j, regex) in class.matches.argv_regex.iter().flatten().enumerate() {
            found.regex(
                &format!("forbidden_command_classes[{i}].match.argv_regex[{j}]"),
                regex,
            );
        }
    }

    // Globs.
    for (i, group) in policy.protected_paths.groups.iter().enumerate() {
        for (j, glob) in group.globs.iter().enumerate() {
            found.glob(&format!("protected_paths.groups[{i}].globs[{j}]"), glob);
        }
    }
    for (i, group) in policy.protected_paths.sensitive_files.iter().enumerate() {
        for (j, glob) in group.globs.iter().enumerate() {
            found.glob(
                &format!("protected_paths.sensitive_files[{i}].globs[{j}]"),
                glob,
            );
        }
    }
    for (i, glob) in policy.path_access.write_allow.iter().enumerate() {
        found.glob(&format!("path_access.write_allow[{i}]"), glob);
    }
    for (i, profile) in policy.agent_stage_profiles.profiles.iter().enumerate() {
        for (j, skill) in profile.skills.iter().flat_map(|s| &s.allowed).enumerate() {
            for (k, glob) in skill.writes.iter().enumerate() {
                found.glob(
                    &format!("agent_stage_profiles.profiles[{i}].skills.allowed[{j}].writes[{k}]"),
                    glob,
                );
            }
        }
        for (j, glob) in profile
            .forbidden_artifacts_after_run
            .iter()
            .flatten()
            .enumerate()
        {
            found.glob(
                &format!("agent_stage_profiles.profiles[{i}].forbidden_artifacts_after_run[{j}]"),
                glob,
            );
        }
    }

    // Unique identifiers.
    found.unique(
        "protected_paths.groups",
        policy.protected_paths.groups.iter().map(|g| g.id.as_str()),
    );
    found.unique(
        "protected_paths.sensitive_files",
        policy
            .protected_paths
            .sensitive_files
            .iter()
            .map(|g| g.id.as_str()),
    );
    found.unique(
        "forbidden_command_classes",
        policy
            .forbidden_command_classes
            .iter()
            .map(|c| c.id.as_str()),
    );
    found.unique(
        "tools.entries",
        policy.tools.entries.iter().map(|t| t.id.as_str()),
    );
    found.unique(
        "command_sets.sets",
        policy.command_sets.sets.iter().map(|s| s.id.as_str()),
    );
    found.unique(
        "secrets.patterns",
        policy.secrets.patterns.iter().map(|p| p.id.as_str()),
    );
    found.unique(
        "gate_integrity.semantic_checks",
        policy
            .gate_integrity
            .semantic_checks
            .iter()
            .map(|c| c.id.as_str()),
    );
    found.unique(
        "agent_stage_profiles.profiles",
        policy
            .agent_stage_profiles
            .profiles
            .iter()
            .map(|p| p.id.as_str()),
    );
    found.unique(
        "egress.broker_upstreams",
        policy.egress.broker_upstreams.iter().map(|u| u.id.as_str()),
    );

    // References.
    let sandbox_profiles: BTreeSet<&str> = ["agent", "fetch_deps", "verify"].into_iter().collect();
    let egress_profiles: BTreeSet<&str> = ["agent", "fetch_deps", "none"].into_iter().collect();
    let checks: BTreeSet<&str> = policy
        .gate_integrity
        .semantic_checks
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    let tool_ids: BTreeSet<&str> = policy.tools.entries.iter().map(|t| t.id.as_str()).collect();
    let stage_profiles: BTreeSet<&str> = policy
        .agent_stage_profiles
        .profiles
        .iter()
        .map(|p| p.id.as_str())
        .collect();

    for (i, group) in policy.protected_paths.sensitive_files.iter().enumerate() {
        for (j, check) in group.checks.iter().enumerate() {
            found.defined(
                &format!("protected_paths.sensitive_files[{i}].checks[{j}]"),
                check,
                &checks,
                "semantic check in gate_integrity.semantic_checks",
            );
        }
    }
    for (i, tool) in policy.tools.entries.iter().enumerate() {
        for (j, profile) in tool.profiles.iter().enumerate() {
            found.defined(
                &format!("tools.entries[{i}].profiles[{j}]"),
                profile,
                &sandbox_profiles,
                "sandbox profile",
            );
        }
    }
    for (i, class) in policy.forbidden_command_classes.iter().enumerate() {
        for (j, profile) in class.except_profiles.iter().flatten().enumerate() {
            found.defined(
                &format!("forbidden_command_classes[{i}].except_profiles[{j}]"),
                profile,
                &sandbox_profiles,
                "sandbox profile",
            );
        }
        if let Some(tool) = &class.breakglass_tool {
            found.defined(
                &format!("forbidden_command_classes[{i}].breakglass_tool"),
                tool,
                &tool_ids,
                "tool in tools.entries",
            );
        }
    }
    found.defined(
        "agent_stage_profiles.default_profile",
        &policy.agent_stage_profiles.default_profile,
        &stage_profiles,
        "profile in agent_stage_profiles.profiles",
    );
    for (name, profile) in [
        ("fetch_deps", &policy.sandbox.profiles.fetch_deps),
        ("agent", &policy.sandbox.profiles.agent),
        ("verify", &policy.sandbox.profiles.verify),
    ] {
        found.defined(
            &format!("sandbox.profiles.{name}.egress_profile"),
            &profile.egress_profile,
            &egress_profiles,
            "egress profile",
        );
    }

    // Egress entries carry a review date and a usable port.
    let mut egress_ids = BTreeSet::new();
    for (profile, allow) in [
        ("fetch_deps", &policy.egress.profiles.fetch_deps.allow),
        ("agent", &policy.egress.profiles.agent.allow),
        ("none", &policy.egress.profiles.none.allow),
    ] {
        for (i, entry) in allow.iter().enumerate() {
            let at = format!("egress.profiles.{profile}.allow[{i}]");
            if !egress_ids.insert(entry.id.as_str()) {
                found.add(
                    format!("{at}.id"),
                    ProblemKind::DuplicateId,
                    format!("the egress entry `{}` is defined twice", entry.id),
                );
            }
            if !is_iso_date(&entry.review_by) {
                found.add(
                    format!("{at}.review_by"),
                    ProblemKind::Constraint,
                    "write the review date as YYYY-MM-DD in quotes",
                );
            }
            if entry.ports.is_empty() || entry.ports.contains(&0) {
                found.add(
                    format!("{at}.ports"),
                    ProblemKind::Constraint,
                    "list at least one port, and no port 0",
                );
            }
            if entry.host.contains('*') {
                found.add(
                    format!("{at}.host"),
                    ProblemKind::Constraint,
                    "a host is written out in full; wildcards are not allowed",
                );
            }
        }
    }
    for (i, upstream) in policy.egress.broker_upstreams.iter().enumerate() {
        if !is_iso_date(&upstream.review_by) {
            found.add(
                format!("egress.broker_upstreams[{i}].review_by"),
                ProblemKind::Constraint,
                "write the review date as YYYY-MM-DD in quotes",
            );
        }
    }

    // Budgets.
    let thresholds = &policy.budgets.thresholds;
    if !(thresholds.warn_at_fraction > 0.0
        && thresholds.warn_at_fraction <= thresholds.stop_at_fraction
        && thresholds.stop_at_fraction <= 1.0)
    {
        found.add(
            "budgets.thresholds",
            ProblemKind::Constraint,
            "the warning fraction must be above 0 and not above the stop fraction, and the stop fraction must be at most 1",
        );
    }

    found.0
}

/// All problems in an approval policy, in a stable order.
#[must_use]
pub fn approval_problems(policy: &ApprovalPolicy) -> Vec<Problem> {
    let mut found = Problems::default();

    if policy.policy.id != "approval" {
        found.add(
            "policy.id",
            ProblemKind::Constraint,
            "this file must be the approval policy, with `id: approval`",
        );
    }
    if policy.policy.version == 0 {
        found.add(
            "policy.version",
            ProblemKind::Constraint,
            "the version starts at 1",
        );
    }

    found.unique(
        "autonomy.levels",
        policy.autonomy.levels.iter().map(|l| l.id.as_str()),
    );
    found.unique("roles", policy.roles.iter().map(|r| r.id.as_str()));
    found.unique("actions", policy.actions.iter().map(|a| a.id.as_str()));

    let levels: BTreeSet<&str> = policy
        .autonomy
        .levels
        .iter()
        .map(|l| l.id.as_str())
        .collect();
    let roles: BTreeSet<&str> = policy.roles.iter().map(|r| r.id.as_str()).collect();
    found.defined(
        "autonomy.default_level",
        &policy.autonomy.default_level,
        &levels,
        "level in autonomy.levels",
    );
    for (j, role) in policy.autonomy.deploy.approver_roles.iter().enumerate() {
        found.defined(
            &format!("autonomy.deploy.approver_roles[{j}]"),
            role,
            &roles,
            "role",
        );
    }

    for (i, action) in policy.actions.iter().enumerate() {
        let at = format!("actions[{i}]");
        match (&action.requires, &action.requires_by_level) {
            (Some(_), None) | (None, Some(_)) => {}
            (None, None) => found.add(
                &at,
                ProblemKind::Constraint,
                "an action needs exactly one of `requires` and `requires_by_level`; this has neither",
            ),
            (Some(_), Some(_)) => found.add(
                &at,
                ProblemKind::Constraint,
                "an action needs exactly one of `requires` and `requires_by_level`; this has both",
            ),
        }
        found.defined(
            &format!("{at}.min_level"),
            &action.min_level,
            &levels,
            "level in autonomy.levels",
        );
        for level in action.requires_by_level.iter().flat_map(|m| m.keys()) {
            found.defined(
                &format!("{at}.requires_by_level.{level}"),
                level,
                &levels,
                "level in autonomy.levels",
            );
        }
        for (j, role) in action.approver_roles.iter().flatten().enumerate() {
            found.defined(&format!("{at}.approver_roles[{j}]"), role, &roles, "role");
        }
    }

    // Every risk tier is defined exactly once.
    for tier in RiskTier::ALL {
        let count = policy.risk_tiers.iter().filter(|t| t.id == *tier).count();
        if count != 1 {
            found.add(
                "risk_tiers",
                ProblemKind::Constraint,
                format!(
                    "the risk tier `{}` must be defined exactly once but is defined {count} times",
                    tier.as_str()
                ),
            );
        }
    }
    for (i, tier) in policy.risk_tiers.iter().enumerate() {
        if tier.required_approvals == 0 {
            found.add(
                format!("risk_tiers[{i}].required_approvals"),
                ProblemKind::Constraint,
                "every tier needs at least one approval",
            );
        }
        for (j, role) in tier.approver_roles.iter().flatten().enumerate() {
            found.defined(
                &format!("risk_tiers[{i}].approver_roles[{j}]"),
                role,
                &roles,
                "role",
            );
        }
    }

    found.unique_strings(
        "always_human",
        policy.always_human.iter().map(String::as_str),
    );
    found.0
}

impl Problems {
    /// Duplicate plain strings in a list of strings (no `.id` suffix).
    fn unique_strings<'a>(&mut self, list: &str, items: impl Iterator<Item = &'a str>) {
        let mut seen = BTreeSet::new();
        for (index, item) in items.enumerate() {
            if !seen.insert(item) {
                self.add(
                    format!("{list}[{index}]"),
                    ProblemKind::DuplicateId,
                    format!("`{item}` is listed twice in `{list}`"),
                );
            }
        }
    }
}

/// True for `YYYY-MM-DD` with a month from 1 to 12 and a day from 1 to 31.
fn is_iso_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 10
        && bytes.iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        });
    if !shaped {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> { text.get(range)?.parse().ok() };
    let (Some(year), Some(month), Some(day)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    year >= 2000 && (1..=12).contains(&month) && (1..=31).contains(&day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_checked_for_shape_and_range() {
        for good in ["2027-01-31", "2026-12-01"] {
            assert!(is_iso_date(good), "{good}");
        }
        for bad in [
            "2027-1-31",
            "2027-13-01",
            "2027-00-10",
            "2027-01-32",
            "27-01-31",
            "2027/01/31",
            "tomorrow",
            "",
        ] {
            assert!(!is_iso_date(bad), "{bad}");
        }
    }
}
