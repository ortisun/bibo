//! Argument safety (work package done criterion 2, ADR 0005 "Argument safety"): bypass flags only
//! for a sandbox whose posture was checked, only allow-listed flags, a flag set that differs per
//! stage, an explicit model, and no credential in any argument.

mod support;

use factory_domain::contracts::agent_manifest::AllowedTool;
use factory_ports::agent::{AgentRunError, AgentRuntime, FlagSet};
use factory_ports::sandbox::{
    Confinement, JOB_TOKEN_TARGET, Namespace, NetworkAttachment, PostureReport,
};
use factory_runtime::claude::argv::{self as claude_argv, ClaudeTool, Flag};
use factory_runtime::codex::argv as codex_argv;
use factory_runtime::command::EnvName;
use factory_runtime::probe::NeverCancelled;
use factory_runtime::{
    ClaudeCodeConfig, ClaudeCodeRuntime, CodexConfig, CodexRuntime, TargetRefusal, VerifiedTarget,
};
use support::scripted::{ScriptedSession, Step, Tool, posture};
use support::{Harness, request};

fn tool(access: &str) -> AllowedTool {
    serde_json::from_value(serde_json::json!({
        "name": format!("{access}-tool"),
        "access": access,
    }))
    .expect("an allowed tool")
}

fn verified() -> VerifiedTarget {
    VerifiedTarget::check(&posture(|_| {})).expect("a hardened posture")
}

fn claude_args(flag_set: FlagSet, granted: &[AllowedTool]) -> Vec<String> {
    claude_argv::build(
        &claude_argv::Plan {
            flag_set,
            model: "claude-sonnet-5-5",
            max_turns: 7,
            max_budget_usd: 2.5,
            tools: claude_argv::tools_for(granted, flag_set),
        },
        &verified(),
    )
    .expect("arguments")
}

fn codex_args(granted: &[AllowedTool]) -> Vec<String> {
    codex_argv::build(
        &codex_argv::Plan {
            model: "gpt-fake",
            broker_origin: "http://egress:8080",
            shell: codex_argv::grants_shell(granted),
            retries: 1,
        },
        &verified(),
    )
    .expect("arguments")
}

fn flag_name(arg: &str) -> &str {
    arg.split_once('=').map_or(arg, |(name, _)| name)
}

#[test]
fn argument_safety_claude_writes_only_flags_from_the_allow_list() {
    let allowed: Vec<&str> = Flag::ALL.iter().map(|f| f.name()).collect();
    for flag_set in [FlagSet::Standard, FlagSet::Specification] {
        let args = claude_args(
            flag_set,
            &[tool("read"), tool("write"), tool("execute_sandboxed")],
        );
        for arg in args.iter().filter(|a| a.starts_with('-')) {
            assert!(
                allowed.contains(&flag_name(arg)),
                "{arg} is not allow-listed"
            );
        }
        // Every flag the stage needs is there.
        for needed in [
            "-p",
            "--output-format=stream-json",
            "--verbose",
            "--no-session-persistence",
            "--setting-sources=user",
            "--strict-mcp-config",
            "--model=claude-sonnet-5-5",
            "--max-turns=7",
            "--max-budget-usd=2.5000",
            "--dangerously-skip-permissions",
        ] {
            assert!(
                args.iter().any(|a| a == needed),
                "{needed} missing in {args:?}"
            );
        }
        // The flags the spike found unsafe or useless are never written.
        for never in [
            "--bare",
            "--add-dir",
            "--mcp-config",
            "--allowedTools",
            "--permission-mode",
            "--json-schema",
            "--input-format",
            "--plugin-dir",
            "--safe-mode",
        ] {
            assert!(
                !args.iter().any(|a| flag_name(a) == never),
                "{never} must not appear"
            );
        }
    }
}

#[test]
fn argument_safety_the_flag_set_differs_per_stage() {
    let granted = [tool("read")];
    let standard = claude_args(FlagSet::Standard, &granted);
    let specification = claude_args(FlagSet::Specification, &granted);
    assert!(standard.iter().any(|a| a == "--disable-slash-commands"));
    assert!(
        !specification
            .iter()
            .any(|a| a == "--disable-slash-commands"),
        "the specification stage must keep slash commands, or its skills cannot resolve"
    );
    // That one flag, and the Skill tool, are the whole difference.
    let strip = |args: &[String]| -> Vec<String> {
        args.iter()
            .filter(|a| *a != "--disable-slash-commands" && !a.starts_with("--tools="))
            .cloned()
            .collect()
    };
    assert_eq!(strip(&standard), strip(&specification));
    assert!(standard.iter().any(|a| a == "--tools=Read,Glob,Grep"));
    assert!(
        specification
            .iter()
            .any(|a| a == "--tools=Read,Glob,Grep,Skill")
    );
}

#[test]
fn argument_safety_tools_follow_the_granted_access_and_nothing_more() {
    let none = claude_args(FlagSet::Standard, &[]);
    assert!(
        none.iter().any(|a| a == "--tools="),
        "no grant means no built-in tool"
    );
    let shell = claude_args(FlagSet::Standard, &[tool("execute_sandboxed")]);
    assert!(shell.iter().any(|a| a == "--tools=Bash"));
    let all = claude_argv::tools_for(
        &[tool("read"), tool("write"), tool("execute_sandboxed")],
        FlagSet::Standard,
    );
    assert_eq!(
        all,
        vec![
            ClaudeTool::Read,
            ClaudeTool::Glob,
            ClaudeTool::Grep,
            ClaudeTool::Edit,
            ClaudeTool::Write,
            ClaudeTool::Bash
        ]
    );
}

#[test]
fn argument_safety_the_model_is_always_explicit_and_cannot_carry_a_second_argument() {
    let args = claude_args(FlagSet::Standard, &[]);
    assert!(
        args.iter()
            .any(|a| a.starts_with("--model=") && a.len() > "--model=".len())
    );
    let codex = codex_args(&[]);
    let at = codex.iter().position(|a| a == "-m").expect("-m");
    assert_eq!(codex[at + 1], "gpt-fake");
    for bad in [
        "",
        "x --dangerously-skip-permissions",
        "-x",
        "a b",
        "a\nb",
        "a=b",
    ] {
        let refused = claude_argv::build(
            &claude_argv::Plan {
                flag_set: FlagSet::Standard,
                model: bad,
                max_turns: 3,
                max_budget_usd: 1.0,
                tools: Vec::new(),
            },
            &verified(),
        );
        assert_eq!(refused, Err(claude_argv::ArgvRefused::BadModel), "{bad:?}");
        let refused = codex_argv::build(
            &codex_argv::Plan {
                model: bad,
                broker_origin: "http://egress:8080",
                shell: true,
                retries: 1,
            },
            &verified(),
        );
        assert_eq!(refused, Err(codex_argv::ArgvRefused::BadModel), "{bad:?}");
    }
}

#[test]
fn argument_safety_the_credential_is_a_file_read_by_a_helper_never_an_argument() {
    let claude = claude_args(FlagSet::Standard, &[]);
    let settings = claude
        .iter()
        .find(|a| a.starts_with("--settings="))
        .expect("--settings");
    assert!(settings.contains("apiKeyHelper"));
    assert!(settings.contains(JOB_TOKEN_TARGET));
    let codex = codex_args(&[]).join(" ");
    assert!(codex.contains("auth={command=\"/usr/bin/cat\""));
    assert!(codex.contains(&format!("args=[\"{JOB_TOKEN_TARGET}\"]")));
    for text in [claude.join(" "), codex] {
        for forbidden in ["API_KEY", "AUTH_TOKEN", "env_key", "Bearer", "x-api-key"] {
            assert!(!text.contains(forbidden), "{forbidden} in {text}");
        }
    }
}

#[test]
fn argument_safety_codex_writes_the_spike_flag_set() {
    let args = codex_args(&[tool("read")]);
    let joined = args.join(" ");
    for needed in [
        "exec --json --ephemeral --skip-git-repo-check -C /workspace",
        "--ignore-user-config",
        "--ignore-rules",
        "--disable unbounded_connection_retries",
        "--disable plugins",
        "-c analytics.enabled=false",
        "-c project_doc_max_bytes=0",
        "-c skills.bundled.enabled=false",
        "-c model_provider=\"broker\"",
        "base_url=\"http://egress:8080/v1\"",
        "supports_websockets=false",
        "request_max_retries=1",
        "stream_max_retries=1",
        "--dangerously-bypass-approvals-and-sandbox -",
    ] {
        assert!(joined.contains(needed), "{needed} missing in {joined}");
    }
    // No shell access was granted, so the shell tools are switched off.
    assert!(joined.contains("--disable shell_tool"));
    assert!(joined.contains("--disable unified_exec"));
    let with_shell = codex_args(&[tool("execute_sandboxed")]).join(" ");
    assert!(!with_shell.contains("--disable shell_tool"));
    // Every `-c` key and every flag comes from the allow lists.
    for (i, arg) in args.iter().enumerate() {
        if arg == "-c" {
            let key = args[i + 1].split('=').next().expect("a key");
            assert!(codex_argv::ALLOWED_CONFIG_KEYS.contains(&key), "{key}");
        }
        if arg.starts_with('-') && arg != "-" {
            assert!(codex_argv::ALLOWED_FLAGS.contains(&arg.as_str()), "{arg}");
        }
    }
}

type Weakening = (&'static str, Box<dyn Fn(&mut PostureReport)>);

fn weakenings() -> Vec<Weakening> {
    vec![
        ("privileged", Box::new(|p| p.observed.privileged = true)),
        ("root", Box::new(|p| p.observed.uid = 0)),
        ("low uid", Box::new(|p| p.observed.uid = 5000)),
        (
            "cap_add",
            Box::new(|p| p.observed.cap_add = vec!["SYS_ADMIN".into()]),
        ),
        ("caps kept", Box::new(|p| p.observed.cap_drop_all = false)),
        (
            "new privileges",
            Box::new(|p| p.observed.no_new_privileges = false),
        ),
        (
            "writable root",
            Box::new(|p| p.observed.read_only_rootfs = false),
        ),
        (
            "seccomp off",
            Box::new(|p| p.observed.seccomp = Confinement::Unconfined),
        ),
        (
            "seccomp missing",
            Box::new(|p| p.observed.seccomp = Confinement::NotAvailable),
        ),
        (
            "apparmor off",
            Box::new(|p| p.observed.apparmor = Confinement::Unconfined),
        ),
        ("host pid", Box::new(|p| p.observed.pid = Namespace::Host)),
        ("host ipc", Box::new(|p| p.observed.ipc = Namespace::Host)),
        (
            "a device",
            Box::new(|p| p.observed.devices = vec!["/dev/kvm".into()]),
        ),
        (
            "a sysctl",
            Box::new(|p| p.observed.sysctls = vec!["net.x=1".into()]),
        ),
        ("no init", Box::new(|p| p.observed.init = false)),
        (
            "self-check failed",
            Box::new(|p| p.self_check_passed = false),
        ),
        (
            "no job network",
            Box::new(|p| p.network = NetworkAttachment::None),
        ),
    ]
}

#[test]
fn argument_safety_a_sandbox_that_was_not_checked_is_refused_with_its_reason() {
    for (name, weaken) in weakenings() {
        let refusal = VerifiedTarget::check(&posture(|p| weaken(p)));
        assert!(refusal.is_err(), "{name} must be refused");
    }
    assert!(matches!(
        VerifiedTarget::check(&posture(|p| p.observed.privileged = true)),
        Err(TargetRefusal::NotHardened(names)) if names.contains(&"privileged")
    ));
    assert_eq!(
        VerifiedTarget::check(&posture(|p| p.self_check_passed = false)),
        Err(TargetRefusal::SelfCheckFailed)
    );
    assert_eq!(
        VerifiedTarget::check(&posture(|p| p.network = NetworkAttachment::None)),
        Err(TargetRefusal::NoBrokerNetwork)
    );
    // AppArmor may be missing on a development daemon; that is not a weaker setting.
    assert!(
        VerifiedTarget::check(&posture(|p| p.observed.apparmor = Confinement::NotAvailable))
            .is_ok()
    );
}

#[tokio::test]
async fn argument_safety_a_run_on_an_unchecked_sandbox_starts_nothing_with_a_bypass_flag() {
    let h = Harness::new();
    for (name, weaken) in weakenings() {
        for tool_kind in [Tool::Claude, Tool::Codex] {
            let mut s = ScriptedSession::new(&h, tool_kind, Step::exits(0, ""))
                .with_posture(posture(|p| weaken(p)));
            let watch = s.watch();
            let (runtime, model): (Box<dyn AgentRuntime>, &str) = match tool_kind {
                Tool::Claude => (
                    Box::new(ClaudeCodeRuntime::new(
                        ClaudeCodeConfig::default(),
                        h.io.clone(),
                    )),
                    "claude-code-cli",
                ),
                Tool::Codex => (
                    Box::new(CodexRuntime::new(CodexConfig::default(), h.io.clone())),
                    "codex-cli",
                ),
            };
            let req = request(&h, model, "some-model", "http://egress:8080");
            let report = runtime.run(&mut s, req, &NeverCancelled).await;
            assert!(report.outcome.is_err(), "{name}");
            assert_eq!(report.exit, None, "{name}: the tool must not have started");
            let argv: Vec<String> = watch.seen().into_iter().flat_map(|c| c.argv).collect();
            assert!(
                !argv.iter().any(|a| a.contains("dangerously")),
                "{name}: a bypass flag was written for an unchecked sandbox"
            );
            assert!(watch.tool_run().is_none(), "{name}");
        }
    }
}

#[tokio::test]
async fn argument_safety_the_prompt_travels_on_standard_input_and_the_vector_names_only_known_variables()
 {
    let h = Harness::new();
    let mut s = ScriptedSession::new(&h, Tool::Claude, Step::exits(0, ""));
    let watch = s.watch();
    let mut req = request(
        &h,
        "claude-code-cli",
        "claude-sonnet-5-5",
        "http://egress:8080/",
    );
    req.prompt.instructions =
        "PROMPT-TEXT with LD_PRELOAD=/evil.so and --dangerously-flag".to_owned();
    let runtime = ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone());
    let _ = runtime.run(&mut s, req, &NeverCancelled).await;
    let run = watch.tool_run().expect("the tool ran");
    let stdin = String::from_utf8(run.stdin.clone().expect("a prompt on stdin")).expect("text");
    assert!(stdin.contains("PROMPT-TEXT with LD_PRELOAD=/evil.so"));
    assert!(!run.argv.iter().any(|a| a.contains("PROMPT-TEXT")));
    // `env -i NAME=value ...` then `timeout`: every name is from the closed set.
    assert_eq!(&run.argv[..2], ["/usr/bin/env", "-i"]);
    let end = run
        .argv
        .iter()
        .position(|a| a == "/usr/bin/timeout")
        .expect("the soft deadline wrapper");
    let known: Vec<&str> = EnvName::ALL.iter().map(|n| n.as_str()).collect();
    for pair in &run.argv[2..end] {
        let (name, _) = pair.split_once('=').expect("NAME=value");
        assert!(known.contains(&name), "{name} is not an allowed variable");
    }
    // Trailing slash on the broker address is dropped, and the tool gets the origin.
    assert!(
        run.argv
            .iter()
            .any(|a| a == "ANTHROPIC_BASE_URL=http://egress:8080")
    );
    assert!(
        run.argv
            .iter()
            .any(|a| a == "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1")
    );
    assert!(run.argv.iter().any(|a| a == "CLAUDE_CODE_MAX_RETRIES=2"));
}

#[tokio::test]
async fn argument_safety_a_broker_address_with_more_than_an_origin_is_refused() {
    let h = Harness::new();
    for bad in [
        "http://egress:8080/path",
        "http://egress:8080?x=LD_PRELOAD=/evil",
        "ftp://egress:8080",
        "http://a b",
    ] {
        let mut s = ScriptedSession::new(&h, Tool::Claude, Step::exits(0, ""));
        let watch = s.watch();
        // `Uri` rejects whitespace itself; the others reach the adapter.
        let Ok(uri) = factory_domain::values::Uri::parse(bad) else {
            continue;
        };
        let mut req = request(
            &h,
            "claude-code-cli",
            "claude-sonnet-5-5",
            "http://egress:8080",
        );
        req.broker.base_url = uri;
        let runtime = ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone());
        let report = runtime.run(&mut s, req, &NeverCancelled).await;
        assert!(
            matches!(report.outcome, Err(AgentRunError::ProcessFailed(_))),
            "{bad}"
        );
        assert!(watch.tool_run().is_none(), "{bad}");
    }
}
