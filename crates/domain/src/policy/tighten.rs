//! Project policy may only tighten the central policy (NT-POL-02).
//!
//! A project's policy (`.factory/` in a target repository, read from the protected base commit)
//! is a candidate document with the same shape as the central one. [`check_security`] and
//! [`check_approval`] compare the two key by key and report every key where the candidate is
//! looser, by its path in the document. [`tighten_security`] and [`tighten_approval`] return the
//! candidate as the merged policy only when that list is empty, so a merged policy is never looser
//! than the central one, and the merged value is what gets hashed and used.
//!
//! # How a key is compared
//!
//! The comparison reads both documents as JSON values. **A key that is not in the table below
//! must stay equal.** A key added to a policy file in the future is therefore frozen for projects
//! until someone writes down which direction is tighter, instead of being loose by accident. The
//! table gives the direction for the keys a project may move:
//!
//! * a **ceiling** (`budgets`, `limits`, sizes, counts, ages) may go down, never up;
//! * a **floor** (the minimum age of a first publication, the distinct administrators an
//!   allowlist change needs, the approvals a tier needs) may go up, never down;
//! * a **switch** may move only toward its protective value, so `reject_dotdot` stays `true` and
//!   `allow_wildcards` stays `false`;
//! * a **denylist** (protected globs, forbidden classes, forbidden arguments, never-grantable
//!   tools, non-waivable gates, always-human actions, rejected address ranges) may grow, never
//!   shrink, and a glob that starts with `!` (a re-inclusion) may not be added;
//! * an **allowlist** (egress hosts, ports, methods, tool profiles and roles, skills, GitHub
//!   writes of a level, approver roles) may shrink, never grow, and an entry may not be added;
//! * a **ranked value** (a protection mode, a command action, the autonomy level, a tool's human
//!   gate, an action's requirement) may move only toward the stricter end of its order;
//! * a **placement list** (a tool's sandbox `profiles`, where an empty list means the tool runs
//!   outside every sandbox): it may shrink to a non-empty subset, and an empty one stays empty;
//! * a **restrictive list** (`allowed_subcommands`, `approver_roles`) where an empty or missing
//!   list means no restriction: it may be added to, or narrowed to a non-empty subset;
//! * a **set of named entries** (protected groups, forbidden classes, secret patterns, semantic
//!   checks) may gain entries and never lose one; for entries that grant something (tools,
//!   egress hosts, command-set programs, skills, action rows) adding one is refused and removing
//!   one is allowed;
//! * prose (`description`, `reason`, `notes`, `threats`, `justification`, `when`, `review_by`)
//!   is free.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::approval::ApprovalPolicy;
use super::security::SecurityPolicy;

/// Why a key is looser in the project policy than in the central one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WideningReason {
    /// A ceiling is higher.
    CeilingRaised,
    /// A floor is lower.
    FloorLowered,
    /// A switch moved away from its protective value.
    SwitchRelaxed,
    /// Entries of a denylist or a required list are missing.
    EntriesRemoved(Vec<String>),
    /// Entries were added to an allowlist, or a re-inclusion was added to a denylist.
    EntriesAdded(Vec<String>),
    /// A ranked value moved toward the looser end, or is not a value of its order.
    ValueLoosened,
    /// A named entry that must stay was removed.
    NamedEntryRemoved(String),
    /// A named entry that would grant something was added.
    NamedEntryAdded(String),
    /// A key the table does not let a project change was changed.
    Changed,
    /// A key that the central policy has is missing.
    Missing,
    /// A key that the central policy does not have is present.
    Unexpected,
    /// The two documents do not have the same shape at this key.
    ShapeChanged,
}

/// One key where the project policy is looser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Widening {
    /// The key, such as `egress.profiles.fetch_deps.allow[extra_registry]`.
    pub key: String,
    /// How it is looser.
    pub reason: WideningReason,
}

/// Every key where a project policy is looser. Never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TightenReport {
    /// The keys, sorted by key.
    pub widenings: Vec<Widening>,
}

impl TightenReport {
    /// The keys, for an error message.
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.widenings.iter().map(|w| w.key.as_str()).collect()
    }
}

impl std::fmt::Display for TightenReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the project policy widens the central policy at: {}",
            self.keys().join(", ")
        )
    }
}

impl std::error::Error for TightenReport {}

/// Whether an entry can be added or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Entries {
    Allowed,
    Forbidden,
}

#[derive(Debug, Clone, Copy)]
enum Rule {
    Equal,
    AtMost,
    AtLeast,
    /// A switch whose protective value is `tight`; `default` is what a missing key means.
    Switch {
        tight: bool,
        default: bool,
    },
    Superset,
    SupersetNoReinclude,
    Subset,
    SubsetUnlessBaseHas(&'static str),
    Restrictive,
    /// A list that places something (sandbox profiles): empty means "outside every sandbox", so
    /// it may be narrowed to a non-empty subset, and an empty list must stay empty.
    Placement,
    /// Later values are stricter. `default` is what a missing key means.
    Rank {
        order: &'static [&'static str],
        default: Option<&'static str>,
    },
    /// The project must apply to at least the repositories the central entry applies to.
    AppliesTo,
    ById {
        key: &'static str,
        added: Entries,
        removed: Entries,
    },
    MapKeys {
        added: Entries,
        removed: Entries,
    },
}

const MODES: &[&str] = &["additions_only", "append_only", "deny_write", "hidden"];
const LEVELS_STRICT_LAST: &[&str] = &["L3", "L2", "L1", "L0"];
const LEVELS_LOW_FIRST: &[&str] = &["L0", "L1", "L2", "L3"];
const GATES: &[&str] = &["none", "per_task", "per_call"];
const RUN_WHEN: &[&str] = &["dependency_files_change", "always"];
const RISK: &[&str] = &["low", "medium", "high"];
const ACTIONS: &[&str] = &["require_human", "deny"];
const SECRET_ACTIONS: &[&str] = &["flag", "block"];
const SINK_ACTIONS: &[&str] = &["redact", "block"];
const REQUIRES: &[&str] = &["none", "human", "human_and_policy"];
const REQUIRES_BY_LEVEL: &[&str] = &["none", "policy", "human", "human_and_policy", "forbidden"];
const PERMISSIONS: &[&str] = &["none", "read", "triage", "write", "maintain", "admin"];

const ALLOW_ADD: Entries = Entries::Allowed;
const FORBID: Entries = Entries::Forbidden;

const fn by_id(added: Entries, removed: Entries) -> Rule {
    Rule::ById {
        key: "id",
        added,
        removed,
    }
}

const fn on() -> Rule {
    Rule::Switch {
        tight: true,
        default: false,
    }
}

const fn off() -> Rule {
    Rule::Switch {
        tight: false,
        default: false,
    }
}

/// The names of keys that hold prose. They never decide anything.
const PROSE: [&str; 7] = [
    "description",
    "reason",
    "notes",
    "threats",
    "justification",
    "review_by",
    "when",
];

/// The direction of each key a project may move. A path segment `*` matches any one key and `[]`
/// stands for an element of a list of named entries. A key that matches nothing must stay equal.
#[allow(clippy::too_many_lines)]
fn table() -> Vec<(&'static str, Rule)> {
    use Rule::{
        AppliesTo, AtLeast, AtMost, Equal, Restrictive, Subset, Superset, SupersetNoReinclude,
    };
    vec![
        // security.yaml: path matching and protected paths
        ("matching.case_insensitive", on()),
        ("matching.reject_dotdot", on()),
        ("matching.reject_absolute", on()),
        ("matching.reject_nul_and_backslash", on()),
        ("matching.count_rename_source_and_destination", on()),
        ("matching.mode_and_type_changes_are_modifications", on()),
        ("matching.reject_dot_git_components", on()),
        ("matching.reject_gitlinks", on()),
        ("protected_paths.default_change_requires", Superset),
        ("protected_paths.groups", by_id(ALLOW_ADD, FORBID)),
        (
            "protected_paths.groups.[].mode",
            Rule::Rank {
                order: MODES,
                default: None,
            },
        ),
        ("protected_paths.groups.[].applies_to", AppliesTo),
        ("protected_paths.groups.[].globs", SupersetNoReinclude),
        ("protected_paths.sensitive_files", by_id(ALLOW_ADD, FORBID)),
        (
            "protected_paths.sensitive_files.[].globs",
            SupersetNoReinclude,
        ),
        ("protected_paths.sensitive_files.[].checks", Superset),
        ("protected_paths.sensitive_files.[].extra_review", Superset),
        ("protected_paths.sensitive_files.[].applies_to", AppliesTo),
        // path_access
        ("path_access.write_allow", Rule::SubsetUnlessBaseHas("**")),
        ("path_access.follow_symlinks_on_host", off()),
        ("path_access.max_file_bytes", AtMost),
        ("path_access.max_files_changed_per_task", AtMost),
        ("path_access.max_diff_bytes", AtMost),
        ("path_access.workspace_audit.reject_any_of", Superset),
        // forbidden command classes
        ("forbidden_command_classes", by_id(ALLOW_ADD, FORBID)),
        ("forbidden_command_classes.[].match.executables", Superset),
        ("forbidden_command_classes.[].match.argv_any", Superset),
        ("forbidden_command_classes.[].match.argv_regex", Superset),
        (
            "forbidden_command_classes.[].action",
            Rule::Rank {
                order: ACTIONS,
                default: None,
            },
        ),
        ("forbidden_command_classes.[].except_profiles", Subset),
        // tools
        ("tools.agents_may_self_grant", off()),
        ("tools.never_grantable", Superset),
        ("tools.entries", by_id(FORBID, ALLOW_ADD)),
        (
            "tools.entries.[].risk",
            Rule::Rank {
                order: RISK,
                default: None,
            },
        ),
        (
            "tools.entries.[].enabled",
            Rule::Switch {
                tight: false,
                default: true,
            },
        ),
        ("tools.entries.[].profiles", Rule::Placement),
        ("tools.entries.[].roles", Rule::SubsetUnlessBaseHas("*")),
        (
            "tools.entries.[].human_gate",
            Rule::Rank {
                order: GATES,
                default: None,
            },
        ),
        (
            "tools.entries.[].args",
            Rule::MapKeys {
                added: FORBID,
                removed: FORBID,
            },
        ),
        ("tools.entries.[].args.*.max_len", AtMost),
        ("tools.entries.[].limits.max_calls_per_task", AtMost),
        ("tools.entries.[].limits.max_result_bytes", AtMost),
        ("tools.entries.[].limits.timeout_s", AtMost),
        ("tools.entries.[].limits.kill_process_group", on()),
        // command sets
        ("command_sets.sets", by_id(FORBID, ALLOW_ADD)),
        (
            "command_sets.sets.[].executables",
            Rule::MapKeys {
                added: FORBID,
                removed: ALLOW_ADD,
            },
        ),
        (
            "command_sets.sets.[].executables.*.allowed_subcommands",
            Restrictive,
        ),
        (
            "command_sets.sets.[].executables.*.forbidden_args",
            Superset,
        ),
        (
            "command_sets.sets.[].executables.*.forced_args",
            Rule::MapKeys {
                added: ALLOW_ADD,
                removed: FORBID,
            },
        ),
        ("command_sets.sets.[].executables.*.forced_args.*", Superset),
        // sandbox
        ("sandbox.required.cap_drop", Superset),
        ("sandbox.required.cap_add", Subset),
        ("sandbox.required.devices", Subset),
        ("sandbox.forbidden_mount_sources", Superset),
        ("sandbox.profiles.*.limits.*", AtMost),
        ("sandbox.watchdog.disk_poll_interval_s", AtMost),
        ("sandbox.watchdog.max_log_bytes", AtMost),
        // egress
        ("egress.allow_wildcards", off()),
        ("egress.resolve_in_proxy_only", on()),
        ("egress.proxy_rules.reject_resolved_ip_ranges", Superset),
        ("egress.proxy_rules.methods_default", Subset),
        ("egress.proxy_rules.max_bytes_per_job", AtMost),
        ("egress.proxy_rules.log_every_request", on()),
        (
            "egress.never_allow_from_sandbox",
            Rule::ById {
                key: "host",
                added: ALLOW_ADD,
                removed: FORBID,
            },
        ),
        ("egress.profiles.*.allow", by_id(FORBID, ALLOW_ADD)),
        ("egress.profiles.*.allow.[].ports", Subset),
        ("egress.profiles.*.allow.[].methods", Subset),
        ("egress.broker_upstreams", by_id(FORBID, ALLOW_ADD)),
        ("egress.broker_upstreams.[].paths", Subset),
        ("egress.widening_requires", Superset),
        // secrets
        ("secrets.patterns", by_id(ALLOW_ADD, FORBID)),
        (
            "secrets.patterns.[].action",
            Rule::Rank {
                order: SECRET_ACTIONS,
                default: None,
            },
        ),
        ("secrets.entropy_heuristic.enabled", on()),
        ("secrets.entropy_heuristic.min_length", AtMost),
        (
            "secrets.entropy_heuristic.min_shannon_bits_per_char",
            AtMost,
        ),
        (
            "secrets.entropy_heuristic.action",
            Rule::Rank {
                order: SECRET_ACTIONS,
                default: None,
            },
        ),
        ("secrets.exact_values.register_from", Superset),
        ("secrets.exact_values.min_length", AtMost),
        ("secrets.exact_values.encodings", Superset),
        (
            "secrets.sinks.*.on_match",
            Rule::Rank {
                order: SINK_ACTIONS,
                default: None,
            },
        ),
        ("secrets.sinks.*.applies_to", Superset),
        ("secrets.never_in_model_context", Superset),
        // budgets
        ("budgets.enforced_by", Superset),
        ("budgets.hard_ceilings.*.*", AtMost),
        ("budgets.rework.default_rounds", AtMost),
        ("budgets.concurrency.*", AtMost),
        ("budgets.stagnation.window_iterations", AtMost),
        ("budgets.thresholds.warn_at_fraction", AtMost),
        ("budgets.thresholds.stop_at_fraction", AtMost),
        ("budgets.per_request_caps.*", AtMost),
        // gate integrity
        ("gate_integrity.nonwaivable_gates", Superset),
        ("gate_integrity.test_regression.forbid_removed_tests", on()),
        (
            "gate_integrity.test_regression.forbid_newly_ignored_tests",
            on(),
        ),
        (
            "gate_integrity.test_regression.forbid_newly_skipped_tests",
            on(),
        ),
        (
            "gate_integrity.test_regression.forbid_assertion_count_drop",
            on(),
        ),
        ("gate_integrity.flaky_tests.retries_allowed", AtMost),
        ("gate_integrity.semantic_checks", by_id(ALLOW_ADD, FORBID)),
        ("gate_integrity.merge.require_expected_head_sha", on()),
        ("gate_integrity.merge.rerun_critical_gates_after_sync", on()),
        (
            "gate_integrity.merge.required_checks_pinned_to_app_id",
            on(),
        ),
        // untrusted content, output hygiene
        (
            "untrusted_content.structured_output.bounded_repair_attempts",
            AtMost,
        ),
        (
            "untrusted_content.structured_output.max_output_bytes",
            AtMost,
        ),
        ("untrusted_content.web_fetch.max_redirects", AtMost),
        ("untrusted_content.web_fetch.max_bytes", AtMost),
        ("output_hygiene.max_body_bytes", AtMost),
        ("output_hygiene.allow_raw_html", off()),
        ("output_hygiene.allow_images_from_domains", Subset),
        // agent stage profiles
        ("agent_stage_profiles.profiles", by_id(FORBID, FORBID)),
        ("agent_stage_profiles.profiles.[].skills_allowed", Subset),
        (
            "agent_stage_profiles.profiles.[].skills.allowed",
            by_id(FORBID, ALLOW_ADD),
        ),
        ("agent_stage_profiles.profiles.[].skills.denied", Superset),
        (
            "agent_stage_profiles.profiles.[].skills.deny_wins_over_allow",
            on(),
        ),
        (
            "agent_stage_profiles.profiles.[].skills.allowed.[].writes",
            Subset,
        ),
        (
            "agent_stage_profiles.profiles.[].skills.allowed.[].protected_path_exception_required",
            on(),
        ),
        (
            "agent_stage_profiles.profiles.[].hide_denied_skills_in_sandbox",
            on(),
        ),
        (
            "agent_stage_profiles.profiles.[].forbidden_artifacts_after_run",
            Superset,
        ),
        // supply chain
        ("supply_chain.lockfiles.required", on()),
        ("supply_chain.lockfiles.frozen_in_gates", on()),
        ("supply_chain.licenses.always_denied", Superset),
        (
            "supply_chain.new_direct_dependency.min_first_publish_age_days",
            AtLeast,
        ),
        // The advisory database may be at most this old: a ceiling, lowered by a project and
        // never raised.
        ("supply_chain.advisory_database.max_age_days", AtMost),
        // `always` is the stricter value, so a project may move to it and never back.
        (
            "supply_chain.dependency_gates.run_when",
            Rule::Rank {
                order: RUN_WHEN,
                default: None,
            },
        ),
        ("supply_chain.scanners", Superset),
        ("supply_chain.images.pinned_by_digest", on()),
        ("supply_chain.images.built_from_source_by_factory", on()),
        ("supply_chain.images.rebuild_interval_days", AtMost),
        ("supply_chain.ci_actions_pinned_to_commit_sha", on()),
        // approval.yaml: autonomy
        (
            "autonomy.default_level",
            Rule::Rank {
                order: LEVELS_STRICT_LAST,
                default: None,
            },
        ),
        ("autonomy.levels", by_id(FORBID, FORBID)),
        (
            "autonomy.levels.[].enabled",
            Rule::Switch {
                tight: false,
                default: true,
            },
        ),
        ("autonomy.levels.[].github_writes", Subset),
        ("autonomy.levels.[].human_required_for", Superset),
        ("autonomy.levels.[].preconditions", Superset),
        ("autonomy.levels.[].eligibility_all_of", Superset),
        ("autonomy.levels.[].opt_in_requires", Superset),
        ("autonomy.levels.[].revoke_automatically_on", Superset),
        ("autonomy.deploy.enabled", off()),
        ("autonomy.auto_merge.enabled", off()),
        ("autonomy.auto_merge.per_repo_opt_in_only", on()),
        // authority and separation of duties
        (
            "authority.github_permission.additional_condition.enabled",
            on(),
        ),
        (
            "authority.github_permission.additional_condition.at_least",
            Rule::Rank {
                order: PERMISSIONS,
                default: None,
            },
        ),
        (
            "authority.allowlist_changes.requires_distinct_org_admins",
            AtLeast,
        ),
        ("roles", by_id(FORBID, FORBID)),
        (
            "separation_of_duties.approver_must_differ_from_requester_when",
            Superset,
        ),
        (
            "separation_of_duties.approver_may_equal_requester_when_low_risk",
            off(),
        ),
        ("separation_of_duties.factory_app_may_approve", off()),
        (
            "separation_of_duties.security_approver_must_differ_from_requester",
            on(),
        ),
        // risk tiers
        ("risk_tiers", by_id(FORBID, FORBID)),
        ("risk_tiers.[].required_reviews", Superset),
        ("risk_tiers.[].required_approvals", AtLeast),
        ("risk_tiers.[].approver_must_differ_from_requester", on()),
        ("risk_tiers.[].approver_roles", Restrictive),
        ("risk_classification.agent_may_lower_tier", off()),
        // actions
        ("actions", by_id(FORBID, FORBID)),
        (
            "actions.[].min_level",
            Rule::Rank {
                order: LEVELS_LOW_FIRST,
                default: None,
            },
        ),
        (
            "actions.[].requires",
            Rule::Rank {
                order: REQUIRES,
                default: None,
            },
        ),
        (
            "actions.[].requires_by_level",
            Rule::MapKeys {
                added: FORBID,
                removed: FORBID,
            },
        ),
        (
            "actions.[].requires_by_level.*",
            Rule::Rank {
                order: REQUIRES_BY_LEVEL,
                default: None,
            },
        ),
        ("actions.[].approver_roles", Restrictive),
        ("always_human", Superset),
        ("never_allowed_even_with_human_via_the_factory", Superset),
        // approval binding, commands, intake
        ("approval_binding.binds_to", Superset),
        ("approval_binding.expires_after_hours", AtMost),
        ("approval_binding.invalidated_by", Superset),
        (
            "approval_binding.step_up_authentication_required_for",
            Superset,
        ),
        ("approval_binding.record_fields", Superset),
        (
            "approval_binding.github_merge_must_pass_expected_head_sha",
            on(),
        ),
        ("commands.verbs", Subset),
        ("commands.channels", Subset),
        ("commands.github_comment.ignore_inside", Superset),
        ("commands.github_comment.ignore_senders", Superset),
        ("commands.github_comment.first_line_only", on()),
        ("commands.github_comment.one_command_per_comment", on()),
        ("commands.rate_limit.per_user_per_minute", AtMost),
        ("intake.snapshot_content_hash_at_authorization", on()),
        (
            "intake.reauthorize_on_edit_by_actor_other_than_authorizer",
            on(),
        ),
        // anything below is spelled out to show it is deliberate: these are deep-equal
        ("command_sets.sets.[].env", Equal),
        ("sandbox.required.extra_sysctls", Equal),
    ]
}

/// What `applies_to` says; a missing key means both repositories.
fn applies_to_of(value: Option<&Value>) -> Option<&str> {
    match value {
        None => Some("both"),
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => None,
    }
}

/// A list of named entries by the value of `key`, or `None` when it is not one: an element
/// without the key, or a repeated name, would make "the same entry" ambiguous.
fn index_by<'a>(value: Option<&'a Value>, key: &str) -> Option<BTreeMap<String, &'a Value>> {
    let list = match value {
        None | Some(Value::Null) => return Some(BTreeMap::new()),
        Some(Value::Array(list)) => list,
        Some(_) => return None,
    };
    let mut map = BTreeMap::new();
    for item in list {
        let id = item.get(key)?.as_str()?.to_owned();
        if map.insert(id, item).is_some() {
            return None;
        }
    }
    Some(map)
}

struct Walker<'t> {
    rules: &'t [(&'static str, Rule)],
    out: Vec<Widening>,
}

#[derive(Clone)]
struct Seg {
    /// What the rule table sees: the key, `[]` for an element, `*` is only in patterns.
    pattern: String,
    /// What the report shows.
    shown: String,
}

fn shown_path(segments: &[Seg]) -> String {
    let mut out = String::new();
    for seg in segments {
        if seg.shown.starts_with('[') {
            out.push_str(&seg.shown);
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(&seg.shown);
        }
    }
    out
}

fn pattern_matches(pattern: &str, segments: &[Seg]) -> bool {
    let parts: Vec<&str> = pattern.split('.').collect();
    parts.len() == segments.len()
        && parts
            .iter()
            .zip(segments)
            .all(|(p, s)| *p == "*" || *p == s.pattern)
}

fn items(value: Option<&Value>) -> Option<Vec<&Value>> {
    match value {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(list)) => Some(list.iter().collect()),
        Some(_) => None,
    }
}

fn text_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn as_set(value: Option<&Value>) -> Option<BTreeSet<String>> {
    items(value).map(|list| list.into_iter().map(text_of).collect())
}

impl Walker<'_> {
    fn report(&mut self, path: &[Seg], reason: WideningReason) {
        self.out.push(Widening {
            key: shown_path(path),
            reason,
        });
    }

    fn rule_for(&self, path: &[Seg]) -> Option<Rule> {
        self.rules
            .iter()
            .find(|(pattern, _)| pattern_matches(pattern, path))
            .map(|(_, rule)| *rule)
    }

    fn walk(&mut self, path: &mut Vec<Seg>, base: Option<&Value>, project: Option<&Value>) {
        let is_prose = path
            .last()
            .is_some_and(|s| PROSE.contains(&s.pattern.as_str()))
            && !matches!(base, Some(Value::Object(_)))
            && !matches!(project, Some(Value::Object(_)));
        if is_prose {
            return;
        }
        if let Some(rule) = self.rule_for(path) {
            self.apply(rule, path, base, project);
            return;
        }
        match (base, project) {
            (None, None) => {}
            (Some(Value::Object(b)), Some(Value::Object(p))) => {
                self.walk_object(path, Some(b), Some(p))
            }
            (Some(Value::Object(b)), None) => self.walk_object(path, Some(b), None),
            (None, Some(Value::Object(p))) => self.walk_object(path, None, Some(p)),
            (b, p) => {
                if b != p {
                    let reason = match (b, p) {
                        (Some(_), None) => WideningReason::Missing,
                        (None, Some(_)) => WideningReason::Unexpected,
                        _ => WideningReason::Changed,
                    };
                    self.report(path, reason);
                }
            }
        }
    }

    fn walk_object(
        &mut self,
        path: &mut Vec<Seg>,
        base: Option<&serde_json::Map<String, Value>>,
        project: Option<&serde_json::Map<String, Value>>,
    ) {
        let keys: BTreeSet<&String> = base
            .into_iter()
            .chain(project)
            .flat_map(serde_json::Map::keys)
            .collect();
        for key in keys {
            path.push(Seg {
                pattern: key.clone(),
                shown: key.clone(),
            });
            self.walk(
                path,
                base.and_then(|m| m.get(key)),
                project.and_then(|m| m.get(key)),
            );
            path.pop();
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply(
        &mut self,
        rule: Rule,
        path: &mut Vec<Seg>,
        base: Option<&Value>,
        project: Option<&Value>,
    ) {
        use WideningReason as W;
        if base == project {
            return; // nothing moved, so nothing is looser
        }
        match rule {
            Rule::Equal => {
                if base != project {
                    self.report(path, W::Changed);
                }
            }
            Rule::AtMost | Rule::AtLeast => {
                let at_most = matches!(rule, Rule::AtMost);
                let number = |v: Option<&Value>| v.map(Value::as_f64);
                match (number(base), number(project)) {
                    (_, Some(None)) | (Some(None), _) => self.report(path, W::ShapeChanged),
                    (None, None) => {}
                    (Some(_), None) => self.report(path, W::Missing),
                    (None, Some(_)) => {}
                    (Some(Some(b)), Some(Some(p))) => {
                        if at_most && p > b {
                            self.report(path, W::CeilingRaised);
                        } else if !at_most && p < b {
                            self.report(path, W::FloorLowered);
                        }
                    }
                }
            }
            Rule::Switch { tight, default } => {
                let value = |v: Option<&Value>| match v {
                    None => Some(default),
                    Some(Value::Bool(b)) => Some(*b),
                    Some(_) => None,
                };
                match (value(base), value(project)) {
                    (Some(b), Some(p)) => {
                        if p != b && p != tight {
                            self.report(path, W::SwitchRelaxed);
                        }
                    }
                    _ => self.report(path, W::ShapeChanged),
                }
            }
            Rule::Superset | Rule::SupersetNoReinclude => {
                let (Some(b), Some(p)) = (as_set(base), as_set(project)) else {
                    self.report(path, W::ShapeChanged);
                    return;
                };
                let missing: Vec<String> = b.difference(&p).cloned().collect();
                if !missing.is_empty() {
                    self.report(path, W::EntriesRemoved(missing));
                }
                if matches!(rule, Rule::SupersetNoReinclude) {
                    let reinclusions: Vec<String> = p
                        .difference(&b)
                        .filter(|g| g.starts_with('!'))
                        .cloned()
                        .collect();
                    if !reinclusions.is_empty() {
                        self.report(path, W::EntriesAdded(reinclusions));
                    }
                }
            }
            Rule::Subset | Rule::SubsetUnlessBaseHas(_) => {
                let (Some(b), Some(p)) = (as_set(base), as_set(project)) else {
                    self.report(path, W::ShapeChanged);
                    return;
                };
                if let Rule::SubsetUnlessBaseHas(wildcard) = rule
                    && b.contains(wildcard)
                {
                    return;
                }
                let added: Vec<String> = p.difference(&b).cloned().collect();
                if !added.is_empty() {
                    self.report(path, W::EntriesAdded(added));
                }
            }
            Rule::Restrictive => {
                let (Some(b), Some(p)) = (as_set(base), as_set(project)) else {
                    self.report(path, W::ShapeChanged);
                    return;
                };
                if b.is_empty() {
                    return; // no restriction in force, so any restriction is tighter
                }
                let added: Vec<String> = p.difference(&b).cloned().collect();
                if p.is_empty() {
                    self.report(path, W::EntriesRemoved(b.into_iter().collect()));
                } else if !added.is_empty() {
                    self.report(path, W::EntriesAdded(added));
                }
            }
            Rule::Placement => {
                let (Some(b), Some(p)) = (as_set(base), as_set(project)) else {
                    self.report(path, W::ShapeChanged);
                    return;
                };
                let added: Vec<String> = p.difference(&b).cloned().collect();
                if b.is_empty() {
                    if !p.is_empty() {
                        self.report(path, W::EntriesAdded(added));
                    }
                } else if p.is_empty() {
                    // Emptying the list would move the tool out of every sandbox.
                    self.report(path, W::EntriesRemoved(b.into_iter().collect()));
                } else if !added.is_empty() {
                    self.report(path, W::EntriesAdded(added));
                }
            }
            Rule::Rank { order, default } => {
                let rank = |v: Option<&Value>| match v {
                    None => default.and_then(|d| order.iter().position(|o| *o == d)),
                    Some(Value::String(s)) => order.iter().position(|o| *o == s),
                    Some(_) => None,
                };
                match (base, project, rank(base), rank(project)) {
                    (None, None, ..) => {}
                    (_, _, Some(b), Some(p)) => {
                        if p < b {
                            self.report(path, W::ValueLoosened);
                        }
                    }
                    (Some(_), None, ..) => self.report(path, W::Missing),
                    _ => self.report(path, W::ValueLoosened),
                }
            }
            Rule::AppliesTo => match (applies_to_of(base), applies_to_of(project)) {
                (Some(b), Some(p)) => {
                    if p != b && p != "both" {
                        self.report(path, W::ValueLoosened);
                    }
                }
                _ => self.report(path, W::ShapeChanged),
            },
            Rule::ById {
                key,
                added,
                removed,
            } => self.by_id(path, base, project, key, added, removed),
            Rule::MapKeys { added, removed } => {
                let (b, p) = match (base, project) {
                    (None | Some(Value::Null), None | Some(Value::Null)) => return,
                    (Some(Value::Object(b)), Some(Value::Object(p))) => (Some(b), Some(p)),
                    (Some(Value::Object(b)), None) => (Some(b), None),
                    (None, Some(Value::Object(p))) => (None, Some(p)),
                    _ => {
                        self.report(path, W::ShapeChanged);
                        return;
                    }
                };
                let keys: BTreeSet<&String> = b
                    .into_iter()
                    .chain(p)
                    .flat_map(serde_json::Map::keys)
                    .collect();
                for k in keys {
                    let (bv, pv) = (b.and_then(|m| m.get(k)), p.and_then(|m| m.get(k)));
                    path.push(Seg {
                        pattern: k.clone(),
                        shown: format!("[{k}]"),
                    });
                    match (bv, pv) {
                        (Some(_), None) if removed == Entries::Forbidden => {
                            self.report(path, W::NamedEntryRemoved(k.clone()));
                        }
                        (None, Some(_)) if added == Entries::Forbidden => {
                            self.report(path, W::NamedEntryAdded(k.clone()));
                        }
                        (Some(_), None) => {}
                        _ => self.walk_children(path, bv, pv),
                    }
                    path.pop();
                }
            }
        }
    }

    /// Compares what lies under an entry whose own presence was settled by its parent rule.
    fn walk_children(
        &mut self,
        path: &mut Vec<Seg>,
        base: Option<&Value>,
        project: Option<&Value>,
    ) {
        // A rule for the entry itself (`…executables.*.forced_args.*`) comes first, then its keys.
        if let Some(rule) = self.rule_for(path) {
            self.apply(rule, path, base, project);
            return;
        }
        match (base, project) {
            (Some(Value::Object(b)), Some(Value::Object(p))) => {
                self.walk_object(path, Some(b), Some(p))
            }
            (Some(Value::Object(b)), None) => self.walk_object(path, Some(b), None),
            (None, Some(Value::Object(p))) => self.walk_object(path, None, Some(p)),
            (b, p) => {
                if b != p {
                    self.report(path, WideningReason::Changed);
                }
            }
        }
    }

    fn by_id(
        &mut self,
        path: &mut Vec<Seg>,
        base: Option<&Value>,
        project: Option<&Value>,
        key: &str,
        added: Entries,
        removed: Entries,
    ) {
        use WideningReason as W;
        let (Some(b), Some(p)) = (index_by(base, key), index_by(project, key)) else {
            self.report(path, W::ShapeChanged);
            return;
        };
        let ids: BTreeSet<&String> = b.keys().chain(p.keys()).collect();
        for id in ids {
            path.push(Seg {
                pattern: "[]".to_owned(),
                shown: format!("[{id}]"),
            });
            match (b.get(id), p.get(id)) {
                (Some(_), None) => {
                    if removed == Entries::Forbidden {
                        self.report(path, W::NamedEntryRemoved(id.clone()));
                    }
                }
                (None, Some(_)) => {
                    if added == Entries::Forbidden {
                        self.report(path, W::NamedEntryAdded(id.clone()));
                    }
                }
                (Some(bv), Some(pv)) => self.walk_children(path, Some(bv), Some(pv)),
                (None, None) => {}
            }
            path.pop();
        }
    }
}

fn compare(base: &Value, project: &Value) -> Result<(), TightenReport> {
    let rules = table();
    let mut walker = Walker {
        rules: &rules,
        out: Vec::new(),
    };
    walker.walk(&mut Vec::new(), Some(base), Some(project));
    if walker.out.is_empty() {
        Ok(())
    } else {
        Err(TightenReport {
            widenings: walker.out,
        })
    }
}

fn json_of<T: serde::Serialize>(policy: &T) -> Result<Value, TightenReport> {
    serde_json::to_value(policy).map_err(|_| TightenReport {
        widenings: vec![Widening {
            key: String::new(),
            reason: WideningReason::ShapeChanged,
        }],
    })
}

/// Checks that a project security policy only tightens the central one.
///
/// # Errors
/// A [`TightenReport`] naming every key where the project is looser.
pub fn check_security(
    base: &SecurityPolicy,
    project: &SecurityPolicy,
) -> Result<(), TightenReport> {
    compare(&json_of(base)?, &json_of(project)?)
}

/// Checks that a project approval policy only tightens the central one.
///
/// # Errors
/// A [`TightenReport`] naming every key where the project is looser.
pub fn check_approval(
    base: &ApprovalPolicy,
    project: &ApprovalPolicy,
) -> Result<(), TightenReport> {
    compare(&json_of(base)?, &json_of(project)?)
}

/// The merged security policy: the project's, once it is shown to be no looser than the central
/// one. The merged policy is the one to hash and to run.
///
/// # Errors
/// A [`TightenReport`] naming every key where the project is looser. No merged policy exists then.
pub fn tighten_security(
    base: &SecurityPolicy,
    project: &SecurityPolicy,
) -> Result<SecurityPolicy, TightenReport> {
    check_security(base, project)?;
    Ok(project.clone())
}

/// The merged approval policy. See [`tighten_security`].
///
/// # Errors
/// A [`TightenReport`] naming every key where the project is looser.
pub fn tighten_approval(
    base: &ApprovalPolicy,
    project: &ApprovalPolicy,
) -> Result<ApprovalPolicy, TightenReport> {
    check_approval(base, project)?;
    Ok(project.clone())
}
