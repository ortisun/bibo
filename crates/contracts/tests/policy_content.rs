//! What the real policy files say about the things other parts of the factory depend on, checked
//! against the code that enforces them: the tool grants of the specification roles, the command
//! sets, the budgets, the protected paths and the approval rows.
//!
//! These tests read `policies/security.yaml` and `policies/approval.yaml` through the loader, build
//! the same evaluators the engine builds, and ask them questions. They do not repeat the YAML as
//! expected values where an evaluator can answer the question instead.

mod support;

use std::collections::BTreeSet;
use std::sync::LazyLock;

use factory_contracts::policy::{
    ApprovalPolicy, PolicyLoader, ProtectedPolicySource, SecurityPolicy,
};
use factory_domain::policy::SandboxProfileKind;
use factory_domain::policy::commands::{CommandDenialReason, CommandPolicy, CommandVerdict};
use factory_domain::policy::tools::{GrantRequest, ToolDenial, ToolPolicy};
use serde_json::Value;
use support::{read_text, repo_root};

fn source() -> ProtectedPolicySource {
    ProtectedPolicySource::protected_default_branch(&repo_root(), &[])
        .expect("the repository root exists")
}

fn security() -> &'static SecurityPolicy {
    static POLICY: LazyLock<SecurityPolicy> = LazyLock::new(|| {
        PolicyLoader::load_security(&source())
            .expect("the security policy loads")
            .document
    });
    &POLICY
}

fn approval() -> &'static ApprovalPolicy {
    static POLICY: LazyLock<ApprovalPolicy> = LazyLock::new(|| {
        PolicyLoader::load_approval(&source())
            .expect("the approval policy loads")
            .document
    });
    &POLICY
}

fn manifest(agent: &str) -> Value {
    let path = repo_root().join("agents").join(agent).join("manifest.json");
    serde_json::from_str(&read_text(&path)).expect("a manifest is JSON")
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

/// The tools a manifest requests, in order.
fn manifest_tools(manifest: &Value) -> Vec<String> {
    manifest["allowed_tools"]
        .as_array()
        .expect("allowed_tools")
        .iter()
        .map(|t| t["name"].as_str().expect("a tool name").to_owned())
        .collect()
}

/// The path scopes a manifest gives one tool.
fn manifest_scopes(manifest: &Value, tool: &str) -> Vec<String> {
    manifest["allowed_tools"]
        .as_array()
        .expect("allowed_tools")
        .iter()
        .find(|t| t["name"] == tool)
        .and_then(|t| t["path_scope"].as_array())
        .map(|scopes| {
            scopes
                .iter()
                .map(|s| s.as_str().expect("a scope").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn entry<'a>(
    policy: &'a SecurityPolicy,
    tool: &str,
) -> &'a factory_contracts::policy::security::ToolEntry {
    policy
        .tools
        .entries
        .iter()
        .find(|e| e.id == tool)
        .unwrap_or_else(|| panic!("the policy has no tool {tool}"))
}

fn grants(role: &str, manifest_tools: &[String]) -> factory_domain::policy::tools::GrantSet {
    let tools = ToolPolicy::from_policy(security()).expect("the tool rules build");
    tools.grant(&GrantRequest {
        manifest_allowed: manifest_tools,
        stage_needs: manifest_tools,
        role,
        profile: Some(SandboxProfileKind::Agent),
    })
}

fn run(profile: SandboxProfileKind, argv: &[&str]) -> CommandVerdict {
    let commands = CommandPolicy::from_policy(security()).expect("the command rules build");
    commands.evaluate(&strings(argv), profile)
}

// ---------------------------------------------------------------------------------------------
// The specification roles (A2)
// ---------------------------------------------------------------------------------------------

#[test]
fn the_specification_writer_holds_every_tool_its_manifest_requests() {
    let manifest = manifest("specification-writer");
    let requested = manifest_tools(&manifest);
    assert_eq!(
        requested,
        [
            "fs.read",
            "fs.list",
            "fs.write",
            "exec.run",
            "report.submit"
        ]
    );
    let set = grants("specification_writer", &requested);
    for tool in &requested {
        assert!(
            set.holds(tool),
            "the policy does not grant `{tool}` to specification_writer: {:?}",
            set.denied()
        );
    }
    assert!(set.denied().is_empty(), "{:?}", set.denied());
}

#[test]
fn the_specification_reviewer_reads_and_reports_and_nothing_more() {
    let manifest = manifest("specification-reviewer");
    let requested = manifest_tools(&manifest);
    assert_eq!(requested, ["fs.read", "fs.list", "report.submit"]);
    let set = grants("specification_reviewer", &requested);
    assert!(set.denied().is_empty(), "{:?}", set.denied());

    // Even if its manifest asked for more, the policy would not give it a write, a command, a
    // delete, a commit or a dependency request.
    let greedy = strings(&[
        "fs.read",
        "fs.write",
        "fs.delete",
        "exec.run",
        "vcs.commit",
        "deps.request",
    ]);
    let set = grants("specification_reviewer", &greedy);
    assert!(set.holds("fs.read"));
    for tool in [
        "fs.write",
        "fs.delete",
        "exec.run",
        "vcs.commit",
        "deps.request",
    ] {
        assert!(
            set.denied()
                .contains(&(tool.to_owned(), ToolDenial::RoleNotAllowed)),
            "{tool}: {:?}",
            set.denied()
        );
    }
}

#[test]
fn the_writer_may_write_only_the_files_the_spec_kit_skills_write() {
    let policy = security();
    let writer = manifest("specification-writer");
    let scopes: Vec<String> = entry(policy, "fs.write")
        .role_scopes
        .as_ref()
        .and_then(|m| m.get("specification_writer"))
        .and_then(|s| s.paths.as_ref())
        .expect("fs.write has a path scope for specification_writer")
        .iter()
        .map(|g| g.pattern().to_owned())
        .collect();

    // The scope is exactly what the manifest asks for.
    let mut asked = manifest_scopes(&writer, "fs.write");
    asked.sort();
    let mut given = scopes.clone();
    given.sort();
    assert_eq!(
        given, asked,
        "the policy scope and the manifest scope differ"
    );

    // Every path in it is a write of a skill the stage profile allows.
    let profile = policy
        .agent_stage_profiles
        .profiles
        .iter()
        .find(|p| {
            p.applies_to_stage_kinds
                .iter()
                .any(|k| k == "SPECIFICATION")
        })
        .expect("the specification profile");
    let skill_writes: BTreeSet<String> = profile
        .skills
        .as_ref()
        .expect("skills")
        .allowed
        .iter()
        .flat_map(|a| a.writes.iter().map(|g| g.pattern().to_owned()))
        .collect();
    for scope in &scopes {
        assert!(
            skill_writes.contains(scope),
            "the write scope `{scope}` is not a write of an allowed skill: {skill_writes:?}"
        );
    }

    // The constitution is written once per repository with a human approval of a protected-path
    // exception. The writer is never given it.
    assert!(
        !scopes.iter().any(|s| s.contains("constitution")),
        "{scopes:?}"
    );
}

#[test]
fn the_read_scopes_of_the_specification_roles_equal_what_their_manifests_ask_for() {
    let policy = security();
    for (agent, role) in [
        ("specification-writer", "specification_writer"),
        ("specification-reviewer", "specification_reviewer"),
    ] {
        let manifest = manifest(agent);
        for tool in ["fs.read", "fs.list"] {
            let mut given: Vec<String> = entry(policy, tool)
                .role_scopes
                .as_ref()
                .and_then(|m| m.get(role))
                .and_then(|s| s.paths.as_ref())
                .unwrap_or_else(|| panic!("{tool} has no path scope for {role}"))
                .iter()
                .map(|g| g.pattern().to_owned())
                .collect();
            let mut asked = manifest_scopes(&manifest, tool);
            given.sort();
            asked.sort();
            assert_eq!(given, asked, "{agent}: {tool}");
        }
    }
}

#[test]
fn the_writers_commands_are_limited_to_the_spec_kit_helper_scripts() {
    let policy = security();
    let scope = entry(policy, "exec.run")
        .role_scopes
        .as_ref()
        .and_then(|m| m.get("specification_writer"))
        .expect("exec.run has a scope for specification_writer");
    assert_eq!(
        scope.command_sets.as_deref(),
        Some(&strings(&["spec_kit_helpers"])[..])
    );
    assert!(scope.paths.is_none());

    let set = policy
        .command_sets
        .sets
        .iter()
        .find(|s| s.id == "spec_kit_helpers")
        .expect("the helper command set exists");
    let programs: BTreeSet<&str> = set.executables.keys().map(String::as_str).collect();
    assert_eq!(
        programs,
        BTreeSet::from(["check-prerequisites.sh", "resolve-template.sh"])
    );
    // The scripts of the denied skills are not in it, nor is the script that makes branches.
    for forbidden in [
        "setup-plan.sh",
        "setup-tasks.sh",
        "create-new-feature.sh",
        "common.sh",
    ] {
        assert!(!programs.contains(forbidden), "{forbidden}");
    }

    use SandboxProfileKind::Agent;
    for good in [
        &["check-prerequisites.sh", "--json", "--paths-only"][..],
        &["resolve-template.sh", "spec-template", "--json"][..],
        &["resolve-template.sh", "checklist-template", "--json"][..],
    ] {
        let verdict = run(Agent, good);
        assert!(verdict.is_allowed(), "{good:?}: {verdict:?}");
    }
    // The other scripts, a path to a script, and an interpreter running a script are refused.
    for (bad, reason) in [
        (
            &["setup-plan.sh", "--json"][..],
            CommandDenialReason::NotInCommandSet,
        ),
        (
            &["setup-tasks.sh"][..],
            CommandDenialReason::NotInCommandSet,
        ),
        (
            &["create-new-feature.sh", "--json", "x"][..],
            CommandDenialReason::NotInCommandSet,
        ),
        (
            &[".specify/scripts/bash/setup-plan.sh"][..],
            CommandDenialReason::ForbiddenClass,
        ),
    ] {
        match run(Agent, bad) {
            CommandVerdict::Denied(d) if d.reason == reason => {}
            CommandVerdict::Denied(d)
                if d.reason == CommandDenialReason::ExecutableNotBare
                    && reason == CommandDenialReason::ForbiddenClass => {}
            other => panic!("{bad:?} must be refused with {reason:?}, got {other:?}"),
        }
    }
    assert!(
        matches!(
            run(Agent, &["bash", ".specify/scripts/bash/check-prerequisites.sh"]),
            CommandVerdict::Denied(d) if d.reason == CommandDenialReason::ForbiddenClass
        ),
        "an interpreter is a forbidden class, whatever script it runs"
    );
}

#[test]
fn every_role_scope_names_a_role_of_its_tool_and_a_command_set_that_exists() {
    let policy = security();
    let sets: BTreeSet<&str> = policy
        .command_sets
        .sets
        .iter()
        .map(|s| s.id.as_str())
        .collect();
    let mut seen = 0;
    for tool in &policy.tools.entries {
        for (role, scope) in tool.role_scopes.iter().flatten() {
            seen += 1;
            assert!(
                tool.roles.iter().any(|r| r == role),
                "{}: the scope names `{role}`, which does not hold the tool",
                tool.id
            );
            assert!(
                scope.paths.is_some() || scope.command_sets.is_some(),
                "{}: the scope of `{role}` limits nothing",
                tool.id
            );
            for id in scope.command_sets.iter().flatten() {
                assert!(
                    sets.contains(id.as_str()),
                    "{}: `{role}` names the unknown command set `{id}`",
                    tool.id
                );
            }
            for glob in scope.paths.iter().flatten() {
                glob.compile()
                    .unwrap_or_else(|e| panic!("{}: `{}` does not compile: {e}", tool.id, glob.0));
            }
        }
    }
    assert!(seen >= 2, "the specification writer has two scopes");
}

#[test]
fn the_specification_stage_allows_exactly_four_skills_and_denies_the_rest() {
    let profile = security()
        .agent_stage_profiles
        .profiles
        .iter()
        .find(|p| {
            p.applies_to_stage_kinds
                .iter()
                .any(|k| k == "SPECIFICATION")
        })
        .expect("the specification profile");
    let skills = profile.skills.as_ref().expect("skills");
    let allowed: BTreeSet<&str> = skills.allowed.iter().map(|a| a.id.as_str()).collect();
    let denied: BTreeSet<&str> = skills.denied.iter().map(String::as_str).collect();
    assert_eq!(
        allowed,
        BTreeSet::from([
            "speckit.checklist",
            "speckit.clarify",
            "speckit.constitution",
            "speckit.specify",
        ])
    );
    assert_eq!(
        denied,
        BTreeSet::from([
            "speckit.analyze",
            "speckit.converge",
            "speckit.implement",
            "speckit.plan",
            "speckit.tasks",
            "speckit.taskstoissues",
        ])
    );
    assert!(skills.deny_wins_over_allow);
    // Every skill a specification manifest names is one of the four.
    for agent in ["specification-writer", "specification-reviewer"] {
        for skill in manifest(agent)["skills"].as_array().expect("skills") {
            let id = skill["id"].as_str().expect("a skill id");
            assert!(allowed.contains(id), "{agent}: {id}");
        }
    }
    // The reviewer runs with no skill at all.
    assert!(
        manifest("specification-reviewer")["skills"]
            .as_array()
            .expect("skills")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------------------------
// The fetch profile (A3)
// ---------------------------------------------------------------------------------------------

fn class_of(verdict: &CommandVerdict) -> Option<&str> {
    match verdict {
        CommandVerdict::Denied(d) if d.reason == CommandDenialReason::ForbiddenClass => {
            d.matched_classes.first().map(String::as_str)
        }
        _ => None,
    }
}

#[test]
fn the_fetch_profile_can_run_cargo_fetch_and_the_wrapper_adds_locked() {
    use SandboxProfileKind::FetchDeps;
    // The supervisor writes `cargo fetch`; the wrapper adds `--locked`. Passing `--locked` as well
    // would repeat it, and cargo refuses a repeated flag, so the supervisor leaves it to the wrapper.
    let CommandVerdict::Allowed(a) = run(FetchDeps, &["cargo", "fetch"]) else {
        panic!("cargo fetch must be allowed in the fetch profile");
    };
    assert_eq!(a.argv, ["cargo", "fetch", "--locked"]);
    // The metadata of a dependency-free command-line tool fixture is allowed too.
    assert!(run(FetchDeps, &["cargo", "metadata"]).is_allowed());
}

#[test]
fn cargo_fetch_is_denied_outside_the_fetch_profile_by_the_install_class() {
    for profile in [SandboxProfileKind::Agent, SandboxProfileKind::Verify] {
        let verdict = run(profile, &["cargo", "fetch"]);
        assert_eq!(
            class_of(&verdict),
            Some("install_scripts_outside_fetch"),
            "{profile:?}: {verdict:?}"
        );
    }
}

#[test]
fn the_fetch_profile_runs_no_install_no_update_and_no_repository_code() {
    use SandboxProfileKind::FetchDeps;
    // No install, add, update or vendor: the command set lists none of them.
    for words in [
        &["cargo", "install", "ripgrep"][..],
        &["cargo", "add", "serde"][..],
        &["cargo", "update"][..],
        &["cargo", "vendor"][..],
        &["npm", "install", "left-pad"][..],
        &["npm", "ci"][..],
    ] {
        let verdict = run(FetchDeps, words);
        assert!(
            matches!(&verdict, CommandVerdict::Denied(d) if d.reason == CommandDenialReason::SubcommandNotAllowed),
            "{words:?}: {verdict:?}"
        );
    }
    // The fetch profile runs no code of the repository: a build script, a procedural macro, a test
    // binary or a project script would run with the network switched on.
    for words in [
        &["cargo", "build"][..],
        &["cargo", "check"][..],
        &["cargo", "test"][..],
        &["cargo", "clippy"][..],
        &["cargo", "doc"][..],
        &["cargo", "nextest", "run"][..],
        &["npm", "run", "build"][..],
        &["npm", "test"][..],
        &["rustc", "src/main.rs"][..],
        &["node", "script.js"][..],
        &["python", "setup.py"][..],
        &["go", "test"][..],
    ] {
        let verdict = run(FetchDeps, words);
        assert_eq!(
            class_of(&verdict),
            Some("repository_code_in_fetch_deps"),
            "{words:?}: {verdict:?}"
        );
    }
    // The same commands still run where they belong.
    for profile in [SandboxProfileKind::Agent, SandboxProfileKind::Verify] {
        for words in [&["cargo", "build"][..], &["cargo", "test"][..]] {
            assert!(run(profile, words).is_allowed(), "{profile:?} {words:?}");
        }
    }
}

#[test]
fn the_arguments_that_could_redirect_a_fetch_stay_forbidden_in_the_fetch_profile() {
    use SandboxProfileKind::FetchDeps;
    for words in [
        &[
            "cargo",
            "fetch",
            "--config",
            "source.crates-io.replace-with=x",
        ][..],
        &["cargo", "fetch", "--registry", "evil"][..],
        &["cargo", "fetch", "--index", "http://evil.test"][..],
        &["cargo", "fetch", "-Z", "unstable-options"][..],
        &["cargo", "fetch", "--manifest-path=/etc/x/Cargo.toml"][..],
    ] {
        let verdict = run(FetchDeps, words);
        assert!(
            matches!(&verdict, CommandVerdict::Denied(d) if matches!(d.reason, CommandDenialReason::ForbiddenArgument(_))),
            "{words:?}: {verdict:?}"
        );
    }
}

#[test]
fn only_the_fetch_profile_may_use_the_network_and_the_others_stay_offline() {
    let rust = security()
        .command_sets
        .sets
        .iter()
        .find(|s| s.id == "rust")
        .expect("the rust command set");
    // The set is offline by default, and `--offline` is forced where the network is off.
    assert_eq!(
        rust.env.get("CARGO_NET_OFFLINE").map(String::as_str),
        Some("true")
    );
    let cargo = &rust.executables["cargo"];
    let forced = cargo.forced_args.as_ref().expect("forced arguments");
    for profile in ["agent", "verify"] {
        assert!(
            forced[profile].iter().any(|a| a == "--offline"),
            "{profile} must force --offline"
        );
    }
    assert!(
        !forced["fetch_deps"].iter().any(|a| a == "--offline"),
        "the fetch profile reaches the registries through the proxy"
    );
    // Only the fetch profile may override the offline default.
    let overrides = rust
        .env_by_profile
        .as_ref()
        .expect("per-profile environment");
    assert_eq!(
        overrides.keys().map(String::as_str).collect::<Vec<_>>(),
        ["fetch_deps"]
    );
    assert_eq!(
        overrides["fetch_deps"]
            .get("CARGO_NET_OFFLINE")
            .map(String::as_str),
        Some("false")
    );
    for profile in [SandboxProfileKind::Agent, SandboxProfileKind::Verify] {
        let CommandVerdict::Allowed(a) = run(profile, &["cargo", "build"]) else {
            panic!("cargo build is allowed in {profile:?}");
        };
        assert_eq!(
            a.env.get("CARGO_NET_OFFLINE").map(String::as_str),
            Some("true")
        );
        assert!(a.argv.iter().any(|x| x == "--offline"), "{:?}", a.argv);
    }
}

// ---------------------------------------------------------------------------------------------
// Budget exhaustion goes to a person (A4)
// ---------------------------------------------------------------------------------------------

#[test]
fn budget_exhaustion_stops_the_job_revokes_the_token_and_waits_for_a_human() {
    let policy = security();
    // ADR 0010: exhaustion is escalated, not failed and not blocked. BLOCKED is for gates that
    // cannot run and for violations a deterministic check finds.
    assert_eq!(
        policy.budgets.on_exhaustion,
        "stop_job_revoke_job_token_wait_for_human"
    );
    assert!(!policy.budgets.on_exhaustion.contains("BLOCKED"));
    // The token is revoked on exhaustion, and an org_admin, not the policy, raises a ceiling.
    assert!(
        policy
            .credentials
            .model_providers
            .job_token
            .revoked_on
            .iter()
            .any(|r| r == "budget_exhausted")
    );
    let raise = approval()
        .actions
        .iter()
        .find(|a| a.id == "raise_budget_ceiling")
        .expect("the action that raises a ceiling has a row");
    assert_eq!(
        raise.approver_roles.as_deref(),
        Some(&strings(&["org_admin"])[..])
    );
    assert_eq!(
        raise.requires,
        Some(factory_contracts::policy::approval::Requirement::Human)
    );
}

#[test]
fn the_rework_and_repair_caps_are_two_and_a_project_can_only_lower_them() {
    let policy = security();
    let per_job = &policy.budgets.hard_ceilings.per_job;
    assert_eq!(per_job.max_rework_iterations, 2);
    assert_eq!(per_job.max_documentation_rework_iterations, 2);
    assert_eq!(policy.budgets.rework.default_rounds, 2);
    assert_eq!(policy.budgets.rework.project_override, "lower_only");
    assert_eq!(policy.budgets.rework.on_cap_reached, "human_decides");
    assert_eq!(
        policy
            .untrusted_content
            .structured_output
            .bounded_repair_attempts,
        2
    );

    // The engine builds from the real pair, so it accepts these values and would refuse a third.
    let engine = factory_domain::policy::PolicyEngine::new(policy, approval())
        .expect("the real pair builds");
    assert_eq!(engine.budget.repair_cap().get(), 2);
}

// ---------------------------------------------------------------------------------------------
// Protected paths of the factory's own tooling (A5)
// ---------------------------------------------------------------------------------------------

use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::{
    ChangeEvidence, Operation, PathDenialReason, PathPolicy, PathVerdict,
};

const MODIFY: Operation = Operation::Modify {
    gained_lines_only: false,
};

fn path_policy() -> PathPolicy {
    PathPolicy::from_policy(security()).expect("the path rules build")
}

fn check(paths: &PathPolicy, repo: RepoKind, path: &str, op: Operation) -> PathVerdict {
    paths.check(repo, path, op, None, &ChangeEvidence::default())
}

/// The reason and the rule that denied, or `None` when the path is allowed.
fn denied_by(verdict: &PathVerdict) -> Option<(PathDenialReason, String)> {
    match verdict {
        PathVerdict::Denied(d) => Some((d.reason.clone(), d.rule.id().to_owned())),
        PathVerdict::Allowed(_) => None,
    }
}

/// The sensitive groups an allowed change touches.
fn sensitive_groups(paths: &PathPolicy, repo: RepoKind, path: &str) -> Vec<String> {
    match check(paths, repo, path, MODIFY) {
        PathVerdict::Allowed(a) => a.sensitive.iter().map(|h| h.group.clone()).collect(),
        PathVerdict::Denied(d) => panic!("{path} is denied: {d:?}"),
    }
}

/// The directory or file a glob starts with, before its first wildcard.
fn literal_prefix(glob: &str) -> String {
    let end = glob.find(['*', '?', '{', '[']).unwrap_or(glob.len());
    glob[..end].trim_end_matches('/').to_owned()
}

#[test]
fn the_tooling_that_decides_what_a_pass_means_is_write_protected_in_the_factory_repository() {
    let paths = path_policy();
    for path in [
        "xtask/src/main.rs",
        "xtask/Cargo.toml",
        "xtask/tests/review_bypasses.rs",
        "schemas/validate.sh",
        "docs/architecture/crate-dependency-rules.json",
        "docs/architecture/tools/check_work_packages.py",
        "fixtures/readability/rules.json",
        "fixtures/readability/cases/translations.json",
        "crates/domain/tests/oracle/expected.rs",
        "crates/domain/tests/tools/support.rs",
    ] {
        for op in [
            MODIFY,
            Operation::Add,
            Operation::Delete,
            Operation::RenameFrom,
            Operation::ModeChange,
        ] {
            let verdict = check(&paths, RepoKind::Factory, path, op);
            assert_eq!(
                denied_by(&verdict),
                Some((
                    PathDenialReason::DenyWrite,
                    "factory_gate_tooling".to_owned()
                )),
                "{path} {op:?}: {verdict:?}"
            );
        }
        // Reading is fine: only a change is refused.
        assert!(check(&paths, RepoKind::Factory, path, Operation::Read).is_allowed());
    }
}

#[test]
fn a_target_repository_is_not_covered_by_the_factory_tooling_group() {
    let paths = path_policy();
    // The group names the factory's own files. A tenant's repository may have a directory with
    // one of these names, and the factory has no business forbidding it there.
    for path in [
        "xtask/src/main.rs",
        "schemas/validate.sh",
        "docs/architecture/crate-dependency-rules.json",
        "docs/architecture/tools/check.py",
        "fixtures/readability/rules.json",
    ] {
        let verdict = check(&paths, RepoKind::Target, path, MODIFY);
        assert!(verdict.is_allowed(), "{path}: {verdict:?}");
    }
    // The test directories are additions-only in a target (the test_code group), so a new file is
    // fine there and an edit is not. In the factory repository both are refused.
    for path in [
        "crates/domain/tests/oracle/new.rs",
        "crates/domain/tests/tools/new.rs",
    ] {
        assert!(check(&paths, RepoKind::Target, path, Operation::Add).is_allowed());
        assert!(!check(&paths, RepoKind::Target, path, MODIFY).is_allowed());
        assert!(!check(&paths, RepoKind::Factory, path, Operation::Add).is_allowed());
    }
}

#[test]
fn the_dev_script_and_the_example_environment_file_are_sensitive_infrastructure() {
    let paths = path_policy();
    for repo in [RepoKind::Factory, RepoKind::Target] {
        for path in ["scripts/dev-up.sh", ".env.example"] {
            let groups = sensitive_groups(&paths, repo, path);
            assert!(
                groups.iter().any(|g| g == "container_and_infrastructure"),
                "{repo:?} {path}: {groups:?}"
            );
        }
    }
    // The example file stays readable: it is a template, not a secret.
    assert!(check(&paths, RepoKind::Factory, ".env.example", Operation::Read).is_allowed());
}

#[test]
fn security_critical_code_lists_paths_that_exist() {
    let policy = security();
    let group = policy
        .protected_paths
        .sensitive_files
        .iter()
        .find(|g| g.id == "security_critical_code")
        .expect("the security-critical group");
    let globs: Vec<&str> = group.globs.iter().map(|g| g.pattern()).collect();
    for expected in [
        "crates/domain/src/policy/**",
        "crates/domain/src/redaction/**",
        "crates/contracts/**",
        "crates/egress/**",
        "crates/sandbox/**",
    ] {
        assert!(
            globs.contains(&expected),
            "{expected} is missing: {globs:?}"
        );
    }
    // Every entry points at something in the repository, so none of them is a name that guards
    // nothing (the old `crates/policy/**` did not exist).
    for glob in &globs {
        let prefix = literal_prefix(glob);
        assert!(
            repo_root().join(&prefix).exists(),
            "`{glob}` names `{prefix}`, which does not exist"
        );
    }
    assert!(!globs.iter().any(|g| g.starts_with("crates/policy")));

    let paths = path_policy();
    for path in [
        "crates/domain/src/policy/paths.rs",
        "crates/domain/src/redaction/scan.rs",
        "crates/contracts/src/policy/check.rs",
        "crates/egress/src/lib.rs",
        "crates/sandbox/src/lib.rs",
        "crates/runtime/src/lib.rs",
    ] {
        let groups = sensitive_groups(&paths, RepoKind::Factory, path);
        assert!(
            groups.iter().any(|g| g == "security_critical_code"),
            "{path}: {groups:?}"
        );
        // The group is for the factory's own crates. A target repository's `crates/sandbox` is not
        // the factory's.
        let target = sensitive_groups(&paths, RepoKind::Target, path);
        assert!(
            !target.iter().any(|g| g == "security_critical_code"),
            "{path}: {target:?}"
        );
    }
}

#[test]
fn the_new_group_lists_real_paths() {
    use factory_contracts::policy::security::{AppliesTo, ProtectionMode};
    let policy = security();
    let group = policy
        .protected_paths
        .groups
        .iter()
        .find(|g| g.id == "factory_gate_tooling")
        .expect("the factory tooling group");
    assert_eq!(group.mode, ProtectionMode::DenyWrite);
    assert_eq!(group.applies_to, AppliesTo::FactoryRepo);
    for glob in &group.globs {
        let prefix = literal_prefix(glob.pattern());
        assert!(
            repo_root().join(&prefix).exists(),
            "`{}` names `{prefix}`, which does not exist",
            glob.0
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Agent runtime flags (A6), from docs/spikes/agent-runtime.md sections 4 to 7
// ---------------------------------------------------------------------------------------------

fn has_flag(flags: &[String], start: &str) -> bool {
    flags
        .iter()
        .any(|f| f == start || f.starts_with(&format!("{start} ")))
}

#[test]
fn claude_code_runs_with_the_flags_the_spike_proved_and_does_not_rely_on_bare() {
    let runtime = &security().untrusted_content.agent_runtimes.claude_code;
    let flags = &runtime.required_flags;
    // An explicit model (the tool's own default is the most expensive), a turn cap, the one
    // source of settings, no repository MCP configuration, no session on disk.
    assert!(has_flag(flags, "--model"), "{flags:?}");
    assert!(has_flag(flags, "--max-turns"), "{flags:?}");
    assert!(
        flags.iter().any(|f| f == "--setting-sources user"),
        "{flags:?}"
    );
    assert!(has_flag(flags, "--strict-mcp-config"), "{flags:?}");
    assert!(has_flag(flags, "--no-session-persistence"), "{flags:?}");
    // The credential comes from a helper that reads the token file, at the path the ports crate
    // fixes, and never from an environment variable.
    let settings = flags
        .iter()
        .find(|f| f.starts_with("--settings"))
        .unwrap_or_else(|| panic!("no --settings flag: {flags:?}"));
    assert!(settings.contains("apiKeyHelper"), "{settings}");
    assert!(
        settings.contains(factory_ports::sandbox::JOB_TOKEN_TARGET),
        "{settings}"
    );
    // `--bare` neither loads the skills nor stops the `env` block of a repository settings file
    // (spike 4.6), so it is not what neutralizes anything and is not required.
    assert!(
        !flags.iter().any(|f| f.contains("--bare")),
        "--bare must not be relied on: {flags:?}"
    );
    // The switch that stops background traffic is an environment setting, and the credential is
    // not.
    let env = runtime
        .required_environment
        .as_ref()
        .expect("required_environment");
    assert!(
        env.iter()
            .any(|e| e == "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"),
        "{env:?}"
    );
    assert!(env.iter().any(|e| e == "HOME=/tmp"), "{env:?}");
    for credential in ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"] {
        assert!(
            !env.iter().any(|e| e.starts_with(credential)),
            "the credential is delivered by the helper: {env:?}"
        );
    }
    assert!(runtime.auth.contains("apiKeyHelper"), "{}", runtime.auth);
    assert!(runtime.per_run_budget_flag.contains("--max-turns"));
    // The permission bypass is acceptable only in a container that passed the posture check.
    for flag in [
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
    ] {
        assert!(
            runtime
                .forbidden_flags_outside_verified_sandbox
                .iter()
                .any(|f| f == flag),
            "{flag}"
        );
    }
}

#[test]
fn codex_runs_with_the_flags_the_spike_proved_and_its_own_sandbox_is_not_a_control() {
    let runtime = &security().untrusted_content.agent_runtimes.codex_cli;
    let flags = &runtime.required_flags;
    assert!(has_flag(flags, "-m"), "an explicit model: {flags:?}");
    // A custom provider entry, because the tool ignores OPENAI_BASE_URL.
    assert!(
        flags.iter().any(|f| f.starts_with("-c model_provider=")),
        "{flags:?}"
    );
    assert!(
        flags.iter().any(|f| f.starts_with("-c model_providers.")),
        "{flags:?}"
    );
    // The two switches that stop the traffic to other hosts, and the bound on retries.
    assert!(flags.iter().any(|f| f == "--disable plugins"), "{flags:?}");
    assert!(
        flags.iter().any(|f| f == "-c analytics.enabled=false"),
        "{flags:?}"
    );
    assert!(
        flags
            .iter()
            .any(|f| f == "--disable unbounded_connection_retries"),
        "{flags:?}"
    );
    // `--ignore-user-config` and `--ignore-rules` do not stop AGENTS.md; this setting does.
    assert!(
        flags.iter().any(|f| f == "-c project_doc_max_bytes=0"),
        "{flags:?}"
    );
    assert!(flags.iter().any(|f| f == "--ephemeral"), "{flags:?}");
    // The tool's own sandbox cannot start in the container, so a `--sandbox` mode is not a
    // control; the bypass flag is used because the container is the boundary.
    assert!(
        !flags.iter().any(|f| f.starts_with("--sandbox")),
        "a --sandbox mode fails in the hardened container: {flags:?}"
    );
    assert!(
        flags
            .iter()
            .any(|f| f == "--dangerously-bypass-approvals-and-sandbox")
    );
    assert!(
        runtime
            .forbidden_flags_outside_verified_sandbox
            .iter()
            .any(|f| f == "--dangerously-bypass-approvals-and-sandbox")
    );
    // The key stays out of the environment the model's shell sees.
    assert!(
        runtime.env_policy.contains("job-token"),
        "{}",
        runtime.env_policy
    );
    assert!(
        runtime.env_policy.contains("never"),
        "{}",
        runtime.env_policy
    );
}

#[test]
fn the_runtime_notes_no_longer_say_what_the_spike_disproved() {
    let text = read_text(&repo_root().join("policies/security.yaml"));
    for stale in [
        "has no `--max-turns`",
        "Codex has no verified skill-disable flag",
        "key exists per --help example; exact syntax to confirm",
        "--bare, --strict-mcp-config, --no-session-persistence",
        "--sandbox read-only|workspace-write",
        "skill_permission_rule: unverified",
        "ANTHROPIC_API_KEY_or_apiKeyHelper",
        "Whether each one fully neutralizes",
        "The agent-runtime spike decides",
    ] {
        assert!(!text.contains(stale), "stale claim: {stale}");
    }
    // The answers the spike gave are in the file.
    let profile = security()
        .agent_stage_profiles
        .profiles
        .iter()
        .find(|p| p.id == "specification")
        .expect("the specification profile");
    assert_eq!(
        profile.claude_code.skill_permission_rule.as_deref(),
        Some("supported_for_the_Skill_tool_not_for_a_typed_slash_command")
    );
    assert!(
        profile
            .codex_cli
            .skill_visibility
            .contains("skills.bundled.enabled=false")
    );
}

#[test]
fn repeated_refused_tool_requests_send_the_stage_to_a_person() {
    // NT-TOOL-03: "after N attempts the stage is NEEDS_HUMAN". N is a number in the policy.
    let threshold = security()
        .tools
        .misuse_threshold
        .as_ref()
        .expect("tools.misuse_threshold");
    assert_eq!(threshold.max_denied_requests_per_task, 3);
    assert_eq!(threshold.on_threshold, "needs_human");
}

// ---------------------------------------------------------------------------------------------
// Approval rows, always-human names and invalidation reasons (A7, B)
// ---------------------------------------------------------------------------------------------

use factory_domain::ids::TenantId;
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::authority::{
    ActionContext, ActionDenialReason, ActionVerdict, Actor, ActorKind, Allowlist, AllowlistEntry,
    AutonomyLevel, ChangeFacts,
};
use factory_domain::policy::decision::{Designation, GithubUserId};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::RiskTier;
use factory_ports::store::ApprovalInvalidation;

const REPO: &str = "acme/widgets";
const ORG_ADMIN: u64 = 11;
const REPO_ADMIN: u64 = 12;
const APPROVER: u64 = 13;
const SECURITY_APPROVER: u64 = 14;
const OPERATOR: u64 = 15;
const REQUESTER: u64 = 16;

fn user_id(n: u64) -> GithubUserId {
    GithubUserId::new(n).expect("a GitHub id")
}

fn tenant() -> TenantId {
    TenantId::parse("018f3a00-0000-7000-8000-00000000c001").expect("a tenant id")
}

fn allowlist() -> Allowlist {
    let person = |id: u64, login: &str, designation: Designation| AllowlistEntry {
        tenant: tenant(),
        github_user_id: user_id(id),
        login: login.to_owned(),
        designations: std::iter::once(designation).collect(),
        repositories: None,
        expires_at: None,
    };
    Allowlist::new(
        "sha256:test-allowlist",
        vec![
            person(ORG_ADMIN, "gina", Designation::OrgAdmin),
            person(REPO_ADMIN, "rita", Designation::RepoAdmin),
            person(APPROVER, "mallory", Designation::Approver),
            person(SECURITY_APPROVER, "sam", Designation::SecurityApprover),
            person(OPERATOR, "olga", Designation::Operator),
            person(REQUESTER, "alice", Designation::Requester),
        ],
    )
    .expect("no person is listed twice")
}

fn engine() -> PolicyEngine {
    PolicyEngine::new(security(), approval()).expect("the real pair builds")
}

/// Asks the engine whether a person may take an action at a level.
fn decide(engine: &PolicyEngine, who: u64, action: &str, level: AutonomyLevel) -> ActionVerdict {
    let list = allowlist();
    let (tenant, now) = (
        tenant(),
        Timestamp::parse("2026-10-27T12:00:00Z").expect("a time"),
    );
    let login = "someone";
    let actor = Actor {
        github_user_id: user_id(who),
        login,
        kind: ActorKind::User,
        github_permission: None,
        author_association: None,
    };
    engine.authority.authorize_action(&ActionContext {
        action,
        level,
        tenant: &tenant,
        repository: REPO,
        actor: &actor,
        allowlist: &list,
        now: &now,
        requester: Some(user_id(REQUESTER)),
        change: ChangeFacts {
            risk_tier: RiskTier::Low,
            protected_path_change: false,
            sensitive_file_change: false,
            new_dependency: false,
        },
        require_designation: None,
        step_up_done: true,
    })
}

/// Asks the engine whether a person may move a repository between two levels.
fn decide_change(
    engine: &PolicyEngine,
    who: u64,
    from: AutonomyLevel,
    to: AutonomyLevel,
) -> ActionVerdict {
    let list = allowlist();
    let (tenant, now) = (
        tenant(),
        Timestamp::parse("2026-10-27T12:00:00Z").expect("a time"),
    );
    let actor = Actor {
        github_user_id: user_id(who),
        login: "someone",
        kind: ActorKind::User,
        github_permission: None,
        author_association: None,
    };
    engine.authority.authorize_autonomy_change(
        &ActionContext {
            action: "raise_autonomy_level",
            level: from,
            tenant: &tenant,
            repository: REPO,
            actor: &actor,
            allowlist: &list,
            now: &now,
            requester: Some(user_id(REQUESTER)),
            change: ChangeFacts {
                risk_tier: RiskTier::Low,
                protected_path_change: false,
                sensitive_file_change: false,
                new_dependency: false,
            },
            require_designation: None,
            step_up_done: true,
        },
        from,
        to,
    )
}

fn authorized(verdict: &ActionVerdict) -> bool {
    matches!(verdict, ActionVerdict::Authorized(_))
}

fn row<'a>(
    policy: &'a ApprovalPolicy,
    id: &str,
) -> &'a factory_contracts::policy::approval::ActionRule {
    policy
        .actions
        .iter()
        .find(|a| a.id == id)
        .unwrap_or_else(|| panic!("approval.yaml has no row for `{id}`"))
}

#[test]
fn raising_and_lowering_autonomy_have_rows_that_agree_with_the_engine() {
    use AutonomyLevel::{L0, L1, L2};
    use factory_contracts::policy::approval::Requirement;
    let policy = approval();
    let raise = row(policy, "raise_autonomy_level");
    let lower = row(policy, "lower_autonomy_level");
    for r in [raise, lower] {
        assert_eq!(r.requires, Some(Requirement::Human));
        // A repository capped at L0 can be raised, so the action exists from L0.
        assert_eq!(r.min_level, "L0");
    }
    assert_eq!(
        raise.approver_roles.as_deref(),
        Some(&strings(&["org_admin"])[..])
    );
    // The engine lets a repo_admin lower, and an org_admin too.
    assert_eq!(
        lower.approver_roles.as_deref(),
        Some(&strings(&["repo_admin", "org_admin"])[..])
    );
    assert!(
        policy
            .always_human
            .iter()
            .any(|a| a == "raise_autonomy_level")
    );
    assert!(
        policy
            .approval_binding
            .step_up_authentication_required_for
            .iter()
            .any(|a| a == "raise_autonomy_level")
    );

    // The row and the engine's own check say the same thing for every designation.
    let engine = engine();
    for (who, may_raise, may_lower) in [
        (ORG_ADMIN, true, true),
        (REPO_ADMIN, false, true),
        (APPROVER, false, false),
        (SECURITY_APPROVER, false, false),
        (OPERATOR, false, false),
        (REQUESTER, false, false),
    ] {
        let by_row_raise = decide(&engine, who, "raise_autonomy_level", L1);
        let by_engine_raise = decide_change(&engine, who, L1, L2);
        assert_eq!(authorized(&by_row_raise), may_raise, "row, raise, {who}");
        assert_eq!(
            authorized(&by_engine_raise),
            may_raise,
            "engine, raise, {who}"
        );
        let by_row_lower = decide(&engine, who, "lower_autonomy_level", L2);
        let by_engine_lower = decide_change(&engine, who, L2, L0);
        assert_eq!(authorized(&by_row_lower), may_lower, "row, lower, {who}");
        assert_eq!(
            authorized(&by_engine_lower),
            may_lower,
            "engine, lower, {who}"
        );
    }
}

#[test]
fn every_open_translation_warning_needs_an_approvers_decision() {
    use AutonomyLevel::{L1, L2};
    use factory_contracts::policy::approval::Requirement;
    let policy = approval();
    let r = row(policy, "acknowledge_documentation_warning");
    assert_eq!(r.requires, Some(Requirement::Human));
    assert_eq!(
        r.approver_roles.as_deref(),
        Some(&strings(&["approver"])[..])
    );
    assert!(
        r.when
            .as_deref()
            .is_some_and(|w| w.contains("translation-unfaithful")),
        "{:?}",
        r.when
    );
    // It is a human decision at every level, and no setting can turn it into none.
    assert!(
        policy
            .always_human
            .iter()
            .any(|a| a == "acknowledge_documentation_warning")
    );
    let engine = engine();
    assert!(
        engine
            .authority
            .always_needs_human("acknowledge_documentation_warning")
    );
    for level in [L1, L2] {
        assert!(authorized(&decide(
            &engine,
            APPROVER,
            "acknowledge_documentation_warning",
            level
        )));
        for who in [OPERATOR, REQUESTER, REPO_ADMIN] {
            let verdict = decide(&engine, who, "acknowledge_documentation_warning", level);
            assert!(
                matches!(
                    &verdict,
                    ActionVerdict::Denied(d) if matches!(d.reason, ActionDenialReason::MissingDesignation { .. })
                ),
                "{who} {level:?}: {verdict:?}"
            );
        }
    }
}

#[test]
fn letting_a_blocked_stage_run_go_again_is_an_operators_human_decision_at_every_level() {
    use AutonomyLevel::{L1, L2};
    use factory_contracts::policy::approval::Requirement;
    let policy = approval();
    let r = row(policy, "unblock_blocked_stage_run");
    assert_eq!(r.requires, Some(Requirement::Human));
    assert_eq!(
        r.approver_roles.as_deref(),
        Some(&strings(&["operator"])[..])
    );
    assert!(
        r.threats
            .iter()
            .flatten()
            .any(|threat| format!("{threat:?}").contains("23")),
        "{:?}",
        r.threats
    );
    // The verb is one of the words of the command set, and the action is a human decision that no
    // setting can turn into none.
    for word in [
        "unblock",
        "approve-project-build-code",
        "ack-translation-warning",
    ] {
        assert!(
            policy.commands.verbs.iter().any(|verb| verb == word),
            "commands.verbs lacks {word}"
        );
    }
    assert!(
        policy
            .always_human
            .iter()
            .any(|a| a == "unblock_blocked_stage_run")
    );
    let engine = engine();
    assert!(
        engine
            .authority
            .always_needs_human("unblock_blocked_stage_run")
    );
    for level in [L1, L2] {
        assert!(authorized(&decide(
            &engine,
            OPERATOR,
            "unblock_blocked_stage_run",
            level
        )));
        // An approver, a security approver, a requester and an administrator hold other
        // designations. None of them holds this one.
        for who in [APPROVER, SECURITY_APPROVER, REQUESTER, REPO_ADMIN] {
            let verdict = decide(&engine, who, "unblock_blocked_stage_run", level);
            assert!(
                matches!(
                    &verdict,
                    ActionVerdict::Denied(d) if matches!(d.reason, ActionDenialReason::MissingDesignation { .. })
                ),
                "{who} {level:?}: {verdict:?}"
            );
        }
    }
}

#[test]
fn the_loader_gives_the_age_of_the_advisory_database_and_when_the_dependency_gates_run() {
    // SC-6. The value is a typed field of the loaded policy, and it is the staleness limit that
    // `deny.toml` holds the factory's own CI to, so the two cannot drift: P7D is 7 days.
    let supply = &security().supply_chain;
    assert_eq!(supply.advisory_database.max_age_days, 7);
    let deny = read_text(&repo_root().join("deny.toml"));
    assert!(
        deny.lines()
            .any(|line| line.trim() == r#"maximum-db-staleness = "P7D""#),
        "deny.toml no longer says P7D; the policy and deny.toml must agree"
    );
    // The decision about when the gates run is the policy's, and the engine reads it.
    assert_eq!(supply.dependency_gates.run_when, "dependency_files_change");
    assert_eq!(
        engine().dependency.advisory_database_max_age_days(),
        supply.advisory_database.max_age_days
    );
    // "New" is read with the wording that excludes the members of the project.
    assert_eq!(
        supply.new_direct_dependency.new_means,
        factory_domain::policy::dependency::NEW_MEANS
    );
}

#[test]
fn build_code_of_a_new_package_is_a_security_approvers_own_decision() {
    // B-2 and SC-10. `build_script_added` blocks until a security review, and the action that
    // lifts it has its own row: a person with the designation security_approver, never an
    // ordinary approver, never the person who asked for the change, at every level.
    use AutonomyLevel::{L1, L2};
    use factory_contracts::policy::approval::Requirement;
    let policy = approval();
    let r = row(policy, "approve_build_code");
    assert_eq!(r.requires, Some(Requirement::Human));
    assert_eq!(
        r.approver_roles.as_deref(),
        Some(&strings(&["security_approver"])[..])
    );
    let threats: Vec<&str> = r.threats.iter().flatten().map(|t| t.as_str()).collect();
    assert_eq!(threats, ["T-29", "T-30"]);
    let when = r.when.as_deref().unwrap_or_default();
    for word in ["name", "version", "checksum", "build script"] {
        assert!(
            when.contains(word),
            "the `when` text must say `{word}`: {when}"
        );
    }
    assert!(
        policy
            .always_human
            .iter()
            .any(|a| a == "approve_build_code")
    );

    // The dependency row says that it does not cover the build code, so a person reading either
    // row learns that two decisions are needed.
    let dependency = row(policy, "add_new_direct_dependency");
    let text = dependency.when.as_deref().unwrap_or_default();
    assert!(
        text.contains("build code") && text.contains("approve_build_code"),
        "{text}"
    );

    let engine = engine();
    assert!(engine.authority.always_needs_human("approve_build_code"));
    for level in [L1, L2] {
        assert!(authorized(&decide(
            &engine,
            SECURITY_APPROVER,
            "approve_build_code",
            level
        )));
        for who in [APPROVER, OPERATOR, REQUESTER, REPO_ADMIN, ORG_ADMIN] {
            let verdict = decide(&engine, who, "approve_build_code", level);
            assert!(
                matches!(
                    &verdict,
                    ActionVerdict::Denied(d) if matches!(d.reason, ActionDenialReason::MissingDesignation { .. })
                ),
                "{who} {level:?}: {verdict:?}"
            );
        }
    }
}

#[test]
fn the_always_human_list_uses_the_real_action_ids() {
    let policy = approval();
    let engine = engine();
    let ids: BTreeSet<&str> = policy.actions.iter().map(|a| a.id.as_str()).collect();
    // The descriptive names that stood for an action with a row, and the id each one meant. A name
    // that is not an id is not checked against its row, so the engine would not notice a row that
    // lets the action happen with no human.
    for (old, id) in [
        ("waive_any_gate", "waive_failed_gate"),
        (
            "grant_tool_outside_agent_manifest",
            "grant_tool_outside_manifest",
        ),
        ("enable_exec_shell_breakglass", "use_exec_shell_breakglass"),
        (
            "access_additional_repository_or_organization",
            "write_to_additional_repository",
        ),
        (
            "send_code_to_additional_model_provider",
            "send_code_to_new_model_provider",
        ),
        (
            "install_or_update_spec_kit_or_other_tooling",
            "install_spec_kit_or_tooling",
        ),
    ] {
        assert!(
            !policy.always_human.iter().any(|a| a == old),
            "`{old}` is a descriptive name; the action is `{id}`"
        );
        assert!(
            policy.always_human.iter().any(|a| a == id),
            "`{id}` is missing from always_human"
        );
        assert!(ids.contains(id), "{id}");
        assert!(
            engine.authority.always_needs_human(id),
            "`{id}` must need a human at every level"
        );
    }
    // Every step-up action is an action with a row.
    for action in &policy.approval_binding.step_up_authentication_required_for {
        assert!(
            ids.contains(action.as_str()),
            "step-up names `{action}`, which has no row"
        );
    }
    // The actions the other evaluators rely on are on the list under their real ids.
    for id in [
        "change_protected_path",
        "add_new_direct_dependency",
        "approve_build_code",
        "waive_failed_gate",
    ] {
        assert!(policy.always_human.iter().any(|a| a == id), "{id}");
    }
}

#[test]
fn an_approval_stops_counting_for_the_five_reasons_of_the_store_port() {
    // An exhaustive match: a sixth reason in the port stops this file from compiling, and
    // whoever adds it has to say what the policy does with it.
    fn name(reason: ApprovalInvalidation) -> &'static str {
        match reason {
            ApprovalInvalidation::NewCommit => "new_commit",
            ApprovalInvalidation::BaseMoved => "base_moved",
            ApprovalInvalidation::PolicyChange => "policy_change",
            ApprovalInvalidation::ImageChange => "image_change",
            ApprovalInvalidation::SpecRevision => "spec_revision",
        }
    }
    let port: BTreeSet<&str> = [
        ApprovalInvalidation::NewCommit,
        ApprovalInvalidation::BaseMoved,
        ApprovalInvalidation::PolicyChange,
        ApprovalInvalidation::ImageChange,
        ApprovalInvalidation::SpecRevision,
    ]
    .into_iter()
    .map(name)
    .collect();
    let listed: BTreeSet<&str> = approval()
        .approval_binding
        .invalidated_by
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(
        listed, port,
        "approval.yaml and the store port list different reasons"
    );
    assert_eq!(approval().approval_binding.invalidated_by.len(), 5);

    // The gate evidence list uses the same names, and `rebase` is a new commit.
    let gates: BTreeSet<&str> = security()
        .gate_integrity
        .invalidated_by
        .iter()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = port.iter().copied().chain(["rebase"]).collect();
    assert_eq!(gates, expected);

    // The two conditions the old list had are checks made when an approval is used, not stored
    // reasons, and the policy still lists them.
    let checked = approval()
        .approval_binding
        .checked_when_used
        .as_ref()
        .expect("approval_binding.checked_when_used");
    for condition in [
        "evidence_manifest_hash_differs_from_the_one_the_approver_saw",
        "approver_removed_from_allowlist_or_entry_expired",
    ] {
        assert!(
            checked.iter().any(|c| c == condition),
            "{condition}: {checked:?}"
        );
    }
}

#[test]
fn row_level_security_is_required_from_slice_one() {
    // ADR 0012. The value is `required`; the file says the first pass is in Slice 1, not Slice 4.
    assert_eq!(security().tenancy.database_row_level_security, "required");
    let text = read_text(&repo_root().join("policies/security.yaml"));
    let tenancy = &text[text.find("\ntenancy:").expect("the tenancy section")..];
    assert!(tenancy.contains("ADR 0012"), "tenancy must cite ADR 0012");
    assert!(
        tenancy.contains("Slice 1"),
        "tenancy must say RLS is Slice 1"
    );
    assert!(
        !tenancy[..tenancy.find("\naudit:").unwrap_or(tenancy.len())].contains("Slice 4"),
        "tenancy no longer defers RLS to Slice 4"
    );
}

#[test]
fn gate_evidence_invalidation_points_at_the_state_machine_mapping() {
    let text = read_text(&repo_root().join("policies/security.yaml"));
    let at = text
        .find("  invalidated_by: [new_commit")
        .expect("the list");
    let before = &text[..at];
    let comment: Vec<&str> = before.lines().rev().take(4).collect();
    assert!(
        comment
            .iter()
            .any(|l| l.contains("docs/architecture/state-machine.md")),
        "the comment above invalidated_by must point at the mapping: {comment:?}"
    );
}
