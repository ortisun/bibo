//! A project policy may only tighten the central one (NT-POL-02): a table of named changes, each
//! of which must be refused naming its key, or accepted. The property over random changes is in
//! `tighten_property.rs`.

use factory_domain::policy::PolicyEngine;
use factory_domain::policy::tighten::{
    TightenReport, WideningReason, check_approval, check_security, tighten_approval,
    tighten_security,
};
use serde_json::{Value, json};

use crate::support::{
    approval, approval_from, approval_json, security, security_from, security_json,
};

/// A named change that must be refused, with the key it must be refused at.
type Widening = (&'static str, &'static str, Box<dyn FnOnce(&mut Value)>);
/// A named change that must be accepted.
type Tightening = (&'static str, Box<dyn FnOnce(&mut Value)>);

fn keys_of(result: Result<(), TightenReport>) -> Vec<String> {
    match result {
        Ok(()) => Vec::new(),
        Err(report) => report.keys().into_iter().map(str::to_owned).collect(),
    }
}

fn sec(change: impl FnOnce(&mut Value)) -> Result<(), TightenReport> {
    let mut json = security_json();
    change(&mut json);
    check_security(&security(), &security_from(json))
}

fn app(change: impl FnOnce(&mut Value)) -> Result<(), TightenReport> {
    let mut json = approval_json();
    change(&mut json);
    check_approval(&approval(), &approval_from(json))
}

fn group_index(json: &Value, id: &str) -> usize {
    json["protected_paths"]["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .position(|g| g["id"] == id)
        .expect("the group exists")
}

fn row_index(json: &Value, list: &str, id: &str) -> usize {
    json[list]
        .as_array()
        .expect("list")
        .iter()
        .position(|g| g["id"] == id)
        .expect("the row exists")
}

#[test]
fn a_project_cannot_move_the_dependency_gates_back_from_always_to_only_when_a_file_changes() {
    // The central policy here says `always`. The real central policy says the other value, so the
    // reverse move is made against a central policy that is changed for this test.
    let mut central = security_json();
    central["supply_chain"]["dependency_gates"]["run_when"] = "always".into();
    let central = security_from(central);
    assert_eq!(
        keys_of(check_security(&central, &security())),
        ["supply_chain.dependency_gates.run_when"]
    );
    // The same value is no change.
    assert_eq!(check_security(&central, &central), Ok(()));
}

#[test]
fn a_policy_equal_to_the_central_one_is_a_tightening_of_it() {
    assert_eq!(check_security(&security(), &security()), Ok(()));
    assert_eq!(check_approval(&approval(), &approval()), Ok(()));
    assert_eq!(
        tighten_security(&security(), &security()).expect("merges"),
        security()
    );
    assert_eq!(
        tighten_approval(&approval(), &approval()).expect("merges"),
        approval()
    );
}

#[test]
fn negative_nt_pol_02_each_widening_is_refused_and_names_its_key() {
    let table: Vec<Widening> = vec![
        (
            "adds an egress host",
            "egress.profiles.fetch_deps.allow[extra_registry]",
            Box::new(|j| {
                j["egress"]["profiles"]["fetch_deps"]["allow"].as_array_mut().expect("list").push(json!({
                    "id": "extra_registry", "host": "registry.example.org", "ports": [443], "methods": ["GET"],
                    "justification": "x", "review_by": "2027-01-01"
                }));
            }),
        ),
        (
            "adds a port to an egress host",
            "egress.profiles.fetch_deps.allow[crates_index].ports",
            Box::new(|j| {
                j["egress"]["profiles"]["fetch_deps"]["allow"][0]["ports"]
                    .as_array_mut()
                    .expect("list")
                    .push(80.into());
            }),
        ),
        (
            "adds POST to an egress host",
            "egress.profiles.fetch_deps.allow[crates_index].methods",
            Box::new(|j| {
                j["egress"]["profiles"]["fetch_deps"]["allow"][0]["methods"]
                    .as_array_mut()
                    .expect("list")
                    .push("POST".into());
            }),
        ),
        (
            "gives the none profile a host",
            "egress.profiles.none.allow[x]",
            Box::new(|j| {
                j["egress"]["profiles"]["none"]["allow"] = json!([{
                    "id": "x", "host": "example.org", "ports": [443], "methods": ["GET"],
                    "justification": "x", "review_by": "2027-01-01"
                }]);
            }),
        ),
        (
            "allows wildcards",
            "egress.allow_wildcards",
            Box::new(|j| j["egress"]["allow_wildcards"] = true.into()),
        ),
        (
            "removes a never-allowed host",
            "egress.never_allow_from_sandbox[github.com]",
            Box::new(|j| {
                j["egress"]["never_allow_from_sandbox"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "removes a rejected address range",
            "egress.proxy_rules.reject_resolved_ip_ranges",
            Box::new(|j| {
                j["egress"]["proxy_rules"]["reject_resolved_ip_ranges"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "removes a protected group",
            "protected_paths.groups[ci_workflows]",
            Box::new(|j| {
                let at = group_index(j, "ci_workflows");
                j["protected_paths"]["groups"]
                    .as_array_mut()
                    .expect("list")
                    .remove(at);
            }),
        ),
        (
            "removes a glob from a group",
            "protected_paths.groups[ci_workflows].globs",
            Box::new(|j| {
                let at = group_index(j, "ci_workflows");
                j["protected_paths"]["groups"][at]["globs"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "adds a re-inclusion to a group",
            "protected_paths.groups[ci_workflows].globs",
            Box::new(|j| {
                let at = group_index(j, "ci_workflows");
                j["protected_paths"]["groups"][at]["globs"]
                    .as_array_mut()
                    .expect("list")
                    .push("!.github/workflows/**".into());
            }),
        ),
        (
            "weakens a mode",
            "protected_paths.groups[ci_workflows].mode",
            Box::new(|j| {
                let at = group_index(j, "ci_workflows");
                j["protected_paths"]["groups"][at]["mode"] = "additions_only".into();
            }),
        ),
        (
            "narrows where a group applies",
            "protected_paths.groups[ci_workflows].applies_to",
            Box::new(|j| {
                let at = group_index(j, "ci_workflows");
                j["protected_paths"]["groups"][at]["applies_to"] = "factory_repo".into();
            }),
        ),
        (
            "empties the change requirements",
            "protected_paths.default_change_requires",
            Box::new(|j| {
                j["protected_paths"]["default_change_requires"] = json!(["human_approval"])
            }),
        ),
        (
            "switches off dotdot rejection",
            "matching.reject_dotdot",
            Box::new(|j| j["matching"]["reject_dotdot"] = false.into()),
        ),
        (
            "raises a memory limit",
            "sandbox.profiles.agent.limits.memory_mb",
            Box::new(|j| {
                let now = j["sandbox"]["profiles"]["agent"]["limits"]["memory_mb"]
                    .as_u64()
                    .expect("number");
                j["sandbox"]["profiles"]["agent"]["limits"]["memory_mb"] = (now * 2).into();
            }),
        ),
        (
            "raises a budget",
            "budgets.hard_ceilings.per_task.max_usd",
            Box::new(|j| {
                j["budgets"]["hard_ceilings"]["per_task"]["max_usd"] = 80.0.into();
            }),
        ),
        (
            "raises the rework cap",
            "budgets.hard_ceilings.per_job.max_rework_iterations",
            Box::new(|j| {
                j["budgets"]["hard_ceilings"]["per_job"]["max_rework_iterations"] = 3.into();
            }),
        ),
        (
            "adds a tool grant",
            "tools.entries[net.shell]",
            Box::new(|j| {
                j["tools"]["entries"].as_array_mut().expect("list").push(json!({
                    "id": "net.shell", "risk": "high", "profiles": ["agent"], "roles": ["builder"], "human_gate": "none"
                }));
            }),
        ),
        (
            "adds a role to a tool",
            "tools.entries[fs.write].roles",
            Box::new(|j| {
                let at = j["tools"]["entries"]
                    .as_array()
                    .expect("list")
                    .iter()
                    .position(|e| e["id"] == "fs.write")
                    .expect("fs.write");
                j["tools"]["entries"][at]["roles"]
                    .as_array_mut()
                    .expect("list")
                    .push("qa".into());
            }),
        ),
        (
            "empties the sandbox profiles of a tool, which would move it to the control plane",
            "tools.entries[vcs.commit].profiles",
            Box::new(|j| {
                let at = j["tools"]["entries"]
                    .as_array()
                    .expect("list")
                    .iter()
                    .position(|e| e["id"] == "vcs.commit")
                    .expect("vcs.commit");
                j["tools"]["entries"][at]["profiles"] = json!([]);
            }),
        ),
        (
            "removes a never-grantable tool",
            "tools.never_grantable",
            Box::new(|j| {
                j["tools"]["never_grantable"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "lets agents self-grant",
            "tools.agents_may_self_grant",
            Box::new(|j| j["tools"]["agents_may_self_grant"] = true.into()),
        ),
        (
            "removes a forbidden command class",
            "forbidden_command_classes[shell_interpreters]",
            Box::new(|j| {
                j["forbidden_command_classes"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "removes an executable from a class",
            "forbidden_command_classes[shell_interpreters].match.executables",
            Box::new(|j| {
                j["forbidden_command_classes"][0]["match"]["executables"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "turns a deny into a human question",
            "forbidden_command_classes[shell_interpreters].action",
            Box::new(|j| j["forbidden_command_classes"][0]["action"] = "require_human".into()),
        ),
        (
            "excepts a profile from a class",
            "forbidden_command_classes[shell_interpreters].except_profiles",
            Box::new(|j| j["forbidden_command_classes"][0]["except_profiles"] = json!(["agent"])),
        ),
        (
            "allows another program",
            "command_sets.sets[rust].executables[make]",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["make"] = json!({"forbidden_args": []});
            }),
        ),
        (
            "allows another cargo subcommand",
            "command_sets.sets[rust].executables[cargo].allowed_subcommands",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]["allowed_subcommands"]
                    .as_array_mut()
                    .expect("list")
                    .push("install".into());
            }),
        ),
        (
            "drops a forbidden argument",
            "command_sets.sets[rust].executables[cargo].forbidden_args",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]["forbidden_args"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "drops a forced argument",
            "command_sets.sets[rust].executables[cargo].forced_args[agent]",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]["forced_args"]
                    .as_object_mut()
                    .expect("map")
                    .remove("agent");
            }),
        ),
        (
            "takes a subcommand out of the scope of a forced argument",
            "command_sets.sets[rust].executables[cargo].forced_arg_subcommands.--offline",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]["forced_arg_subcommands"]["--offline"]
                    .as_array_mut()
                    .expect("list")
                    .retain(|sub| sub != "test");
            }),
        ),
        (
            "drops the scope of a forced argument so that it reaches every subcommand",
            "command_sets.sets[rust].executables[cargo].forced_arg_subcommands.--locked",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]
                    .as_object_mut()
                    .expect("map")
                    .remove("forced_arg_subcommands");
            }),
        ),
        (
            "turns the network on for the agent profile",
            "command_sets.sets[rust].env_by_profile.agent.CARGO_NET_OFFLINE",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["env_by_profile"]["agent"] =
                    json!({ "CARGO_NET_OFFLINE": "false" });
            }),
        ),
        (
            "turns the network on for every profile of the set",
            "command_sets.sets[rust].env",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["env"]["CARGO_NET_OFFLINE"] = "false".into();
            }),
        ),
        (
            "removes a non-waivable gate",
            "gate_integrity.nonwaivable_gates",
            Box::new(|j| {
                j["gate_integrity"]["nonwaivable_gates"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "lowers the minimum age of a first publication",
            "supply_chain.new_direct_dependency.min_first_publish_age_days",
            Box::new(|j| {
                j["supply_chain"]["new_direct_dependency"]["min_first_publish_age_days"] = 1.into()
            }),
        ),
        (
            "removes the block nobody may override",
            "gate_integrity.non_overridable_blocks[dependency-review-policy-unresolvable]",
            Box::new(|j| {
                j["gate_integrity"]["non_overridable_blocks"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "points the block nobody may override at another code",
            "gate_integrity.non_overridable_blocks[dependency-review-policy-unresolvable].code",
            Box::new(|j| {
                j["gate_integrity"]["non_overridable_blocks"][0]["code"] =
                    "tool_unavailable".into();
            }),
        ),
        (
            "raises the age the advisory database may have",
            "supply_chain.advisory_database.max_age_days",
            Box::new(|j| {
                j["supply_chain"]["advisory_database"]["max_age_days"] = 30.into();
            }),
        ),
        (
            "makes the dependency gates run never",
            "supply_chain.dependency_gates.run_when",
            Box::new(|j| {
                // A value that is not one of the two, so it is not on the way to stricter.
                j["supply_chain"]["dependency_gates"]["run_when"] = "never".into();
            }),
        ),
        (
            "adds a skill to the specification stage",
            "agent_stage_profiles.profiles[specification].skills.allowed[speckit.plan]",
            Box::new(|j| {
                j["agent_stage_profiles"]["profiles"][1]["skills"]["allowed"]
                    .as_array_mut()
                    .expect("list")
                    .push(json!({"id": "speckit.plan", "writes": ["specs/*/plan.md"]}));
            }),
        ),
        (
            "removes a denied skill",
            "agent_stage_profiles.profiles[specification].skills.denied",
            Box::new(|j| {
                j["agent_stage_profiles"]["profiles"][1]["skills"]["denied"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "changes a key the table does not let a project change",
            "tenancy.tenant_id_on_every_row",
            Box::new(|j| j["tenancy"]["tenant_id_on_every_row"] = false.into()),
        ),
        (
            "changes the status",
            "policy.status",
            Box::new(|j| j["policy"]["status"] = "enforced".into()),
        ),
    ];
    for (name, key, change) in table {
        let keys = keys_of(sec(change));
        assert!(
            keys.iter().any(|k| k == key),
            "{name}: expected a widening at {key}, got {keys:?}"
        );
    }
}

#[test]
fn negative_nt_pol_02_widenings_of_the_approval_policy_are_refused_too() {
    let table: Vec<Widening> = vec![
        (
            "sets autonomy L3",
            "autonomy.default_level",
            Box::new(|j| j["autonomy"]["default_level"] = "L3".into()),
        ),
        (
            "sets autonomy L2",
            "autonomy.default_level",
            Box::new(|j| j["autonomy"]["default_level"] = "L2".into()),
        ),
        (
            "enables auto merge",
            "autonomy.auto_merge.enabled",
            Box::new(|j| j["autonomy"]["auto_merge"]["enabled"] = true.into()),
        ),
        (
            "enables deploy",
            "autonomy.deploy.enabled",
            Box::new(|j| j["autonomy"]["deploy"]["enabled"] = true.into()),
        ),
        (
            "lets a GitHub role grant authority",
            "authority.github_permission.can_grant_authority",
            Box::new(|j| j["authority"]["github_permission"]["can_grant_authority"] = true.into()),
        ),
        (
            "lets bots be listed",
            "authority.bots_may_be_listed",
            Box::new(|j| j["authority"]["bots_may_be_listed"] = true.into()),
        ),
        (
            "lets an administrator add themselves",
            "authority.allowlist_changes.self_grant_allowed",
            Box::new(|j| j["authority"]["allowlist_changes"]["self_grant_allowed"] = true.into()),
        ),
        (
            "needs one org admin where two were needed",
            "authority.allowlist_changes.requires_distinct_org_admins",
            Box::new(|j| {
                j["authority"]["allowlist_changes"]["requires_distinct_org_admins"] = 1.into()
            }),
        ),
        (
            "lets the app approve",
            "separation_of_duties.factory_app_may_approve",
            Box::new(|j| j["separation_of_duties"]["factory_app_may_approve"] = true.into()),
        ),
        (
            "drops a separation condition",
            "separation_of_duties.approver_must_differ_from_requester_when",
            Box::new(|j| {
                j["separation_of_duties"]["approver_must_differ_from_requester_when"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "lets an agent lower its tier",
            "risk_classification.agent_may_lower_tier",
            Box::new(|j| j["risk_classification"]["agent_may_lower_tier"] = true.into()),
        ),
        (
            "needs one approval for a critical change",
            "risk_tiers[critical].required_approvals",
            Box::new(|j| {
                let at = row_index(j, "risk_tiers", "critical");
                j["risk_tiers"][at]["required_approvals"] = 1.into();
            }),
        ),
        (
            "drops a review",
            "risk_tiers[high].required_reviews",
            Box::new(|j| {
                let at = row_index(j, "risk_tiers", "high");
                j["risk_tiers"][at]["required_reviews"]
                    .as_array_mut()
                    .expect("list")
                    .pop();
            }),
        ),
        (
            "moves a criterion",
            "risk_tiers[high].criteria_any",
            Box::new(|j| {
                let at = row_index(j, "risk_tiers", "high");
                j["risk_tiers"][at]["criteria_any"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "needs no human to merge",
            "actions[merge_pr].requires_by_level[L1]",
            Box::new(|j| {
                let at = row_index(j, "actions", "merge_pr");
                j["actions"][at]["requires_by_level"]["L1"] = "none".into();
            }),
        ),
        (
            "needs no human for a new dependency",
            "actions[add_new_direct_dependency].requires",
            Box::new(|j| {
                let at = row_index(j, "actions", "add_new_direct_dependency");
                j["actions"][at]["requires"] = "none".into();
            }),
        ),
        (
            "lets any approver change a protected path",
            "actions[change_protected_path].approver_roles",
            Box::new(|j| {
                let at = row_index(j, "actions", "change_protected_path");
                j["actions"][at]["approver_roles"]
                    .as_array_mut()
                    .expect("list")
                    .push("approver".into());
            }),
        ),
        (
            "makes an action available earlier",
            "actions[merge_pr].min_level",
            Box::new(|j| {
                let at = row_index(j, "actions", "merge_pr");
                j["actions"][at]["min_level"] = "L0".into();
            }),
        ),
        (
            "adds an action row",
            "actions[ship_it]",
            Box::new(|j| {
                j["actions"]
                    .as_array_mut()
                    .expect("list")
                    .push(json!({"id": "ship_it", "min_level": "L1", "requires": "none"}));
            }),
        ),
        (
            "removes an always-human action",
            "always_human",
            Box::new(|j| {
                j["always_human"].as_array_mut().expect("list").remove(0);
            }),
        ),
        (
            "removes a never-allowed action",
            "never_allowed_even_with_human_via_the_factory",
            Box::new(|j| {
                j["never_allowed_even_with_human_via_the_factory"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "approvals live longer",
            "approval_binding.expires_after_hours",
            Box::new(|j| j["approval_binding"]["expires_after_hours"] = 200.into()),
        ),
        (
            "stops invalidating on a new commit",
            "approval_binding.invalidated_by",
            Box::new(|j| {
                j["approval_binding"]["invalidated_by"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "drops a step-up requirement",
            "approval_binding.step_up_authentication_required_for",
            Box::new(|j| {
                j["approval_binding"]["step_up_authentication_required_for"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "raises the rate limit",
            "commands.rate_limit.per_user_per_minute",
            Box::new(|j| j["commands"]["rate_limit"]["per_user_per_minute"] = 200.into()),
        ),
        (
            "lets a label alone authorize",
            "intake.label_presence_alone_is_authorization",
            Box::new(|j| j["intake"]["label_presence_alone_is_authorization"] = true.into()),
        ),
        (
            "lets GitHub permission authorize",
            "intake.github_permission_is_authorization",
            Box::new(|j| j["intake"]["github_permission_is_authorization"] = true.into()),
        ),
        (
            "changes the identity key",
            "authority.identity_key",
            Box::new(|j| j["authority"]["identity_key"] = "github_login".into()),
        ),
    ];
    for (name, key, change) in table {
        let keys = keys_of(app(change));
        assert!(
            keys.iter().any(|k| k == key),
            "{name}: expected a widening at {key}, got {keys:?}"
        );
    }
    // Enabling L3 by key, written out because the level rows have no helper.
    let keys = keys_of(app(|j| {
        let at = j["autonomy"]["levels"]
            .as_array()
            .expect("levels")
            .iter()
            .position(|l| l["id"] == "L3")
            .expect("L3");
        j["autonomy"]["levels"][at]["enabled"] = true.into();
    }));
    assert!(
        keys.iter().any(|k| k == "autonomy.levels[L3].enabled"),
        "{keys:?}"
    );
}

#[test]
fn negative_nt_pol_02_tightenings_are_accepted() {
    let accepted: Vec<Tightening> = vec![
        (
            "lowers a budget",
            Box::new(|j| j["budgets"]["hard_ceilings"]["per_task"]["max_usd"] = 4.0.into()),
        ),
        (
            "lowers the rework cap to one",
            Box::new(|j| {
                j["budgets"]["hard_ceilings"]["per_job"]["max_rework_iterations"] = 1.into();
                j["budgets"]["rework"]["default_rounds"] = 1.into();
            }),
        ),
        (
            "lowers the rework cap to zero",
            Box::new(|j| {
                j["budgets"]["hard_ceilings"]["per_job"]["max_rework_iterations"] = 0.into()
            }),
        ),
        (
            "lowers a memory limit",
            Box::new(|j| j["sandbox"]["profiles"]["agent"]["limits"]["memory_mb"] = 512.into()),
        ),
        (
            "lowers the repair cap",
            Box::new(|j| {
                j["untrusted_content"]["structured_output"]["bounded_repair_attempts"] = 1.into()
            }),
        ),
        (
            "lowers a tool cap",
            Box::new(|j| j["tools"]["entries"][0]["limits"]["max_calls_per_task"] = 10.into()),
        ),
        (
            "adds a protected path to a group",
            Box::new(|j| {
                let at = group_index(j, "ci_workflows");
                j["protected_paths"]["groups"][at]["globs"]
                    .as_array_mut()
                    .expect("list")
                    .push("release/**".into());
            }),
        ),
        (
            "adds a protected group",
            Box::new(|j| {
                j["protected_paths"]["groups"].as_array_mut().expect("list").push(json!({"id": "project_docs", "mode": "deny_write", "applies_to": "both", "globs": ["docs/adr/**"], "reason": "decisions", "threats": ["T-12"]}));
            }),
        ),
        (
            "makes a group stricter",
            Box::new(|j| {
                let at = group_index(j, "test_code");
                j["protected_paths"]["groups"][at]["mode"] = "append_only".into();
            }),
        ),
        (
            "widens where a group applies",
            Box::new(|j| {
                let at = group_index(j, "factory_self_protection");
                j["protected_paths"]["groups"][at]["applies_to"] = "both".into();
            }),
        ),
        (
            "adds a forbidden command class",
            Box::new(|j| {
                j["forbidden_command_classes"].as_array_mut().expect("list").push(json!({"id": "project_make", "match": {"executables": ["make"]}, "action": "deny"}));
            }),
        ),
        (
            "adds an executable to a class",
            Box::new(|j| {
                j["forbidden_command_classes"][0]["match"]["executables"]
                    .as_array_mut()
                    .expect("list")
                    .push("xonsh".into())
            }),
        ),
        (
            "removes an egress host",
            Box::new(|j| {
                j["egress"]["profiles"]["fetch_deps"]["allow"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "narrows the ports of a host",
            Box::new(|j| j["egress"]["profiles"]["fetch_deps"]["allow"][0]["ports"] = json!([])),
        ),
        (
            "adds a never-allowed host",
            Box::new(|j| {
                j["egress"]["never_allow_from_sandbox"]
                    .as_array_mut()
                    .expect("list")
                    .push(json!({"host": "evil.example", "reason": "x"}));
            }),
        ),
        (
            "removes a role from a tool",
            Box::new(|j| {
                j["tools"]["entries"][0]["roles"]
                    .as_array_mut()
                    .expect("list")
                    .pop();
            }),
        ),
        (
            "removes a tool",
            Box::new(|j| {
                j["tools"]["entries"]
                    .as_array_mut()
                    .expect("list")
                    .remove(0);
            }),
        ),
        (
            "adds a never-grantable tool",
            Box::new(|j| {
                j["tools"]["never_grantable"]
                    .as_array_mut()
                    .expect("list")
                    .push("fs.write".into())
            }),
        ),
        (
            "asks for a human on every call",
            Box::new(|j| j["tools"]["entries"][0]["human_gate"] = "per_call".into()),
        ),
        (
            "adds a forbidden argument",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]["forbidden_args"]
                    .as_array_mut()
                    .expect("list")
                    .push("--target-dir".into())
            }),
        ),
        (
            "removes a cargo subcommand",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]["allowed_subcommands"]
                    .as_array_mut()
                    .expect("list")
                    .pop();
            }),
        ),
        (
            "narrows an unrestricted program to subcommands",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["rustc"]["allowed_subcommands"] =
                    json!(["--version"])
            }),
        ),
        (
            "removes a program",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]
                    .as_object_mut()
                    .expect("map")
                    .remove("rustfmt");
            }),
        ),
        (
            "adds a forced argument",
            Box::new(|j| {
                j["command_sets"]["sets"][0]["executables"]["cargo"]["forced_args"]["agent"]
                    .as_array_mut()
                    .expect("list")
                    .push("--frozen".into())
            }),
        ),
        (
            "adds a non-waivable gate",
            Box::new(|j| {
                j["gate_integrity"]["nonwaivable_gates"]
                    .as_array_mut()
                    .expect("list")
                    .push("lint_gate".into())
            }),
        ),
        (
            "raises the minimum age",
            Box::new(|j| {
                j["supply_chain"]["new_direct_dependency"]["min_first_publish_age_days"] = 90.into()
            }),
        ),
        (
            "adds a block nobody may override",
            Box::new(|j| {
                j["gate_integrity"]["non_overridable_blocks"]
                    .as_array_mut()
                    .expect("list")
                    .push(json!({
                        "id": "advisories-unavailable",
                        "gate": "dependency-advisories",
                        "code": "dependency_unavailable",
                        "reason": "a project that wants it stricter"
                    }));
            }),
        ),
        (
            "lowers the age the advisory database may have",
            Box::new(|j| {
                j["supply_chain"]["advisory_database"]["max_age_days"] = 1.into();
            }),
        ),
        (
            "runs the dependency gates on every change",
            Box::new(|j| {
                j["supply_chain"]["dependency_gates"]["run_when"] = "always".into();
            }),
        ),
        (
            "adds a scanner",
            Box::new(|j| {
                j["supply_chain"]["scanners"]
                    .as_array_mut()
                    .expect("list")
                    .push("trivy".into())
            }),
        ),
        (
            "narrows the writable paths",
            Box::new(|j| j["path_access"]["write_allow"] = json!(["src/**", "tests/**"])),
        ),
        (
            "removes a skill",
            Box::new(|j| {
                j["agent_stage_profiles"]["profiles"][1]["skills"]["allowed"]
                    .as_array_mut()
                    .expect("list")
                    .pop();
            }),
        ),
        (
            "adds a denied skill",
            Box::new(|j| {
                j["agent_stage_profiles"]["profiles"][1]["skills"]["denied"]
                    .as_array_mut()
                    .expect("list")
                    .push("speckit.checklist".into())
            }),
        ),
        (
            "adds a secret pattern",
            Box::new(|j| {
                let first = j["secrets"]["patterns"][0].clone();
                let mut extra = first;
                extra["id"] = "project-token".into();
                j["secrets"]["patterns"]
                    .as_array_mut()
                    .expect("list")
                    .push(extra);
            }),
        ),
    ];
    for (name, change) in accepted {
        let keys = keys_of(sec(change));
        assert!(keys.is_empty(), "{name} must be accepted, got {keys:?}");
    }

    // The merged policy is the central one plus the tightening, and the widening it replaces is
    // reported in one list.
    let mut json = security_json();
    json["budgets"]["hard_ceilings"]["per_task"]["max_usd"] = 4.0.into();
    json["sandbox"]["profiles"]["agent"]["limits"]["memory_mb"] = 512.into();
    let project = security_from(json);
    let merged = tighten_security(&security(), &project).expect("a tightening merges");
    assert_eq!(merged, project);
    assert_eq!(
        merged.budgets.hard_ceilings.per_task.max_usd.to_bits(),
        4.0f64.to_bits()
    );
    assert!(
        PolicyEngine::new(&merged, &approval()).is_ok(),
        "the merged policy builds"
    );

    let mut json = security_json();
    json["budgets"]["hard_ceilings"]["per_task"]["max_usd"] = 4.0.into();
    json["budgets"]["hard_ceilings"]["per_job"]["max_usd"] = 100.0.into();
    json["egress"]["allow_wildcards"] = true.into();
    let both = tighten_security(&security(), &security_from(json)).expect_err("two widenings");
    assert_eq!(
        both.keys(),
        [
            "budgets.hard_ceilings.per_job.max_usd",
            "egress.allow_wildcards"
        ]
    );
    assert!(
        both.widenings
            .iter()
            .any(|w| w.reason == WideningReason::CeilingRaised)
    );
}

#[test]
fn negative_nt_pol_02_approval_tightenings_are_accepted() {
    let accepted: Vec<Tightening> = vec![
        (
            "lowers the default level",
            Box::new(|j| j["autonomy"]["default_level"] = "L0".into()),
        ),
        (
            "requires a human for mark_pr_ready at L2",
            Box::new(|j| {
                let at = row_index(j, "actions", "mark_pr_ready");
                j["actions"][at]["requires_by_level"]["L2"] = "human".into();
            }),
        ),
        (
            "moves an action to a higher minimum level",
            Box::new(|j| {
                let at = row_index(j, "actions", "approve_pr");
                j["actions"][at]["min_level"] = "L2".into();
            }),
        ),
        (
            "makes the new-dependency check also need a policy pass",
            Box::new(|j| {
                let at = row_index(j, "actions", "add_new_direct_dependency");
                j["actions"][at]["requires"] = "human_and_policy".into();
            }),
        ),
        (
            "needs three approvals for a critical change",
            Box::new(|j| {
                let at = row_index(j, "risk_tiers", "critical");
                j["risk_tiers"][at]["required_approvals"] = 3.into();
            }),
        ),
        (
            "adds a required review",
            Box::new(|j| {
                let at = row_index(j, "risk_tiers", "low");
                j["risk_tiers"][at]["required_reviews"]
                    .as_array_mut()
                    .expect("list")
                    .push("qa".into());
            }),
        ),
        (
            "adds an always-human action",
            Box::new(|j| {
                j["always_human"]
                    .as_array_mut()
                    .expect("list")
                    .push("deploy_docs".into())
            }),
        ),
        (
            "shortens the approval lifetime",
            Box::new(|j| j["approval_binding"]["expires_after_hours"] = 24.into()),
        ),
        (
            "narrows the commands",
            Box::new(|j| j["commands"]["verbs"] = json!(["approve", "reject"])),
        ),
        (
            "lowers the rate limit",
            Box::new(|j| j["commands"]["rate_limit"]["per_user_per_minute"] = 5.into()),
        ),
        (
            "turns on the GitHub permission condition",
            Box::new(|j| {
                j["authority"]["github_permission"]["additional_condition"]["enabled"] = true.into()
            }),
        ),
        (
            "narrows the approvers of an action",
            Box::new(|j| {
                let at = row_index(j, "actions", "lower_autonomy_level");
                j["actions"][at]["approver_roles"] = json!(["org_admin"]);
            }),
        ),
        (
            "needs more distinct org admins",
            Box::new(|j| {
                j["authority"]["allowlist_changes"]["requires_distinct_org_admins"] = 3.into()
            }),
        ),
    ];
    for (name, change) in accepted {
        let keys = keys_of(app(change));
        assert!(keys.is_empty(), "{name} must be accepted, got {keys:?}");
    }
}
