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

use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource, SecurityPolicy};
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
