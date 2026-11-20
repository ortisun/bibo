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
            credential: claude_argv::ClaudeCredential::ApiKeyHelper,
            flag_set,
            model: "claude-sonnet-5-5",
            max_turns: 7,
            max_budget_usd: 2.5,
            tools: claude_argv::tools_for(granted, flag_set, &[]),
            mcp_url: None,
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
            "--plugin-dir",
            "--safe-mode",
        ] {
            assert!(
                !args.iter().any(|a| flag_name(a) == never),
                "{never} must not appear"
            );
        }
        // The prompt is replayed only where a skill is invoked; elsewhere standard input is text.
        let replay = ["--input-format=stream-json", "--replay-user-messages"];
        for flag in replay {
            assert_eq!(
                args.iter().any(|a| a == flag),
                flag_set == FlagSet::Specification,
                "{flag} in {flag_set:?}: {args:?}"
            );
        }
        assert!(
            !args
                .iter()
                .any(|a| flag_name(a) == "--input-format" && a != "--input-format=stream-json"),
            "{args:?}"
        );
    }
}

#[test]
fn argument_safety_the_stdin_encoding_follows_the_replay_flags() {
    // The two flags and the encoding of standard input come from one decision, so a replayed run
    // always gets a stream-json message and a plain run always gets the text.
    let prompt =
        "/speckit-specify Write the specification. The request is in the file inputs/request.md.";
    for flag_set in [FlagSet::Standard, FlagSet::Specification] {
        let args = claude_args(flag_set, &[tool("read")]);
        let replays = args.iter().any(|a| a == "--replay-user-messages");
        assert_eq!(replays, claude_argv::replays_prompt(flag_set));
        let stdin = claude_argv::stdin_for(flag_set, prompt);
        if replays {
            let line = std::str::from_utf8(&stdin).expect("utf-8");
            assert!(line.ends_with('\n') && line.lines().count() == 1, "{line}");
            let value: serde_json::Value = serde_json::from_str(line).expect("a JSON message");
            assert_eq!(value["type"], "user");
            assert_eq!(value["message"]["role"], "user");
            assert_eq!(value["message"]["content"], prompt);
        } else {
            assert_eq!(stdin, prompt.as_bytes());
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
    // That one flag, the two flags that replay the prompt, and the Skill tool are the whole
    // difference.
    let strip = |args: &[String]| -> Vec<String> {
        args.iter()
            .filter(|a| {
                *a != "--disable-slash-commands"
                    && *a != "--input-format=stream-json"
                    && *a != "--replay-user-messages"
                    && !a.starts_with("--tools=")
            })
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
        &[],
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
                credential: claude_argv::ClaudeCredential::ApiKeyHelper,
                flag_set: FlagSet::Standard,
                model: bad,
                max_turns: 3,
                max_budget_usd: 1.0,
                tools: Vec::new(),
                mcp_url: None,
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
        // The provider must not run a web search for the tool (EGR-1): the broker refuses a
        // request that names a provider-side tool, and Codex names one by default.
        "-c web_search=\"disabled\"",
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
                        h.attestation(),
                    )),
                    "claude-code-cli",
                ),
                Tool::Codex => (
                    Box::new(CodexRuntime::new(
                        CodexConfig::default(),
                        h.io.clone(),
                        h.attestation(),
                    )),
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
    let runtime =
        ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone(), h.attestation());
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

/// ADR 0020, subscription mode: no `--settings` document, the job token reaches the tool as
/// `CLAUDE_CODE_OAUTH_TOKEN` through the fixed launcher line, and the token value, a credential
/// variable name or the repository's settings are never in the vector. The hostile-workspace flags
/// stay.
#[tokio::test]
async fn argument_safety_in_subscription_mode_the_token_is_read_by_the_launcher_never_an_argument()
{
    use factory_runtime::command::{LAUNCHER_SHELL, OAUTH_TOKEN_LAUNCHER};
    let h = Harness::new();
    let mut s = ScriptedSession::new(&h, Tool::Claude, Step::exits(0, ""));
    let watch = s.watch();
    let req = request(
        &h,
        "claude-code-cli",
        "claude-sonnet-5-5",
        "http://egress:8080",
    );
    let config = ClaudeCodeConfig {
        credential: claude_argv::ClaudeCredential::OauthToken,
        ..ClaudeCodeConfig::default()
    };
    let runtime = ClaudeCodeRuntime::new(config.clone(), h.io.clone(), h.attestation());
    let _ = runtime.run(&mut s, req, &NeverCancelled).await;
    let run = watch.tool_run().expect("the tool ran");
    let argv = &run.argv;
    // env -i NAME=value ... timeout ... /bin/sh -c <line> <tool> <flags>
    let known: Vec<&str> = EnvName::ALL.iter().map(|n| n.as_str()).collect();
    let end = argv
        .iter()
        .position(|a| a == "/usr/bin/timeout")
        .expect("the soft deadline wrapper");
    for pair in &argv[2..end] {
        let (name, _) = pair.split_once('=').expect("NAME=value");
        assert!(known.contains(&name), "{name} is not an allowed variable");
    }
    assert!(argv.iter().any(|a| a == "CLAUDE_CODE_PROMPT_CACHE_TTL=5m"));
    let shell = argv
        .iter()
        .position(|a| a == LAUNCHER_SHELL)
        .expect("the launcher");
    assert_eq!(argv[shell + 1], "-c");
    assert_eq!(argv[shell + 2], OAUTH_TOKEN_LAUNCHER);
    assert_eq!(
        argv[shell + 3],
        config.binary,
        "the tool is a positional parameter"
    );
    assert!(OAUTH_TOKEN_LAUNCHER.contains(JOB_TOKEN_TARGET));
    assert!(OAUTH_TOKEN_LAUNCHER.ends_with("exec \"$0\" \"$@\""));
    let flags = &argv[shell + 4..];
    assert!(
        !flags.iter().any(|a| a.starts_with("--settings")),
        "{flags:?}"
    );
    assert!(flags.iter().any(|a| a == "--setting-sources=user"));
    assert!(flags.iter().any(|a| a == "--strict-mcp-config"));
    assert!(flags.iter().any(|a| a == "--disable-slash-commands"));
    for a in argv.iter().filter(|a| *a != OAUTH_TOKEN_LAUNCHER) {
        for forbidden in ["OAUTH", "API_KEY", "Bearer", "x-api-key", "sfjt_"] {
            assert!(!a.contains(forbidden), "{forbidden} in {a}");
        }
    }
}

#[test]
fn argument_safety_the_api_key_mode_keeps_its_helper_and_the_subscription_mode_drops_it() {
    let plan = |credential| claude_argv::Plan {
        credential,
        flag_set: FlagSet::Standard,
        model: "claude-sonnet-5-5",
        max_turns: 3,
        max_budget_usd: 1.0,
        tools: Vec::new(),
        mcp_url: None,
    };
    let helper = claude_argv::build(
        &plan(claude_argv::ClaudeCredential::ApiKeyHelper),
        &verified(),
    )
    .expect("arguments");
    assert!(helper.iter().any(|a| a.starts_with("--settings=")));
    let oauth = claude_argv::build(
        &plan(claude_argv::ClaudeCredential::OauthToken),
        &verified(),
    )
    .expect("arguments");
    assert!(!oauth.iter().any(|a| a.starts_with("--settings")));
    assert_eq!(
        helper.len(),
        oauth.len() + 1,
        "only the settings document differs"
    );
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
        let runtime =
            ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone(), h.attestation());
        let report = runtime.run(&mut s, req, &NeverCancelled).await;
        assert!(
            matches!(report.outcome, Err(AgentRunError::ProcessFailed(_))),
            "{bad}"
        );
        assert!(watch.tool_run().is_none(), "{bad}");
    }
}

// ---- the troubleshooter (ADR 0021, Decision 6) ------------------------------------------------

fn gateway_tools() -> Vec<factory_ports::agent::McpToolName> {
    ["vm_query", "pg_activity"]
        .iter()
        .map(|n| factory_ports::agent::McpToolName::new(n).expect("a gateway tool name"))
        .collect()
}

const GATEWAY_URL: &str = "http://egress:8444/mcp";

fn troubleshooting_plan(
    credential: claude_argv::ClaudeCredential,
    tools: Vec<ClaudeTool>,
    mcp_url: Option<&str>,
) -> claude_argv::Plan<'_> {
    claude_argv::Plan {
        credential,
        flag_set: FlagSet::Troubleshooting,
        model: "claude-sonnet-5-5",
        max_turns: 7,
        max_budget_usd: 2.5,
        tools,
        mcp_url,
    }
}

fn troubleshooting_request(h: &Harness) -> factory_ports::agent::AgentRunRequest {
    let mut req = request(
        h,
        "claude-code-cli",
        "claude-sonnet-5-5",
        "http://egress:8080",
    );
    req.flag_set = FlagSet::Troubleshooting;
    req.tools = Vec::new();
    req.mcp_gateway = Some(factory_ports::agent::McpGateway {
        url: factory_domain::values::Uri::parse(GATEWAY_URL).expect("a URI"),
        tools: gateway_tools(),
    });
    req
}

#[test]
fn argument_safety_troubleshooting_gets_the_gateway_tools_only_and_no_bypass() {
    let tools = claude_argv::tools_for(&[], FlagSet::Troubleshooting, &gateway_tools());
    let args = claude_argv::build(
        &troubleshooting_plan(
            claude_argv::ClaudeCredential::OauthToken,
            tools,
            Some(GATEWAY_URL),
        ),
        &verified(),
    )
    .expect("arguments");
    let allowed: Vec<&str> = Flag::ALL.iter().map(|f| f.name()).collect();
    for arg in &args {
        assert!(
            allowed.contains(&flag_name(arg)),
            "{arg} is not allow-listed"
        );
    }
    for expected in [
        "--tools=",
        "--strict-mcp-config",
        "--setting-sources=user",
        "--disable-slash-commands",
        "--permission-mode=dontAsk",
        "--allowedTools=mcp__factory__pg_activity,mcp__factory__vm_query",
    ] {
        assert!(args.iter().any(|a| a == expected), "{expected} in {args:?}");
    }
    assert!(
        !args.iter().any(|a| a == "--dangerously-skip-permissions"),
        "the troubleshooter's permission mode is dontAsk, never the bypass"
    );
    let config = args
        .iter()
        .find_map(|a| a.strip_prefix("--mcp-config="))
        .expect("--mcp-config");
    let config: serde_json::Value = serde_json::from_str(config).expect("json");
    let servers = config["mcpServers"].as_object().expect("servers");
    assert_eq!(servers.len(), 1, "one MCP server and no other");
    assert_eq!(servers["factory"]["url"], GATEWAY_URL);
    assert_eq!(
        servers["factory"]["headers"]["Authorization"],
        "Bearer ${FACTORY_MCP_TOKEN}"
    );
}

#[test]
fn argument_safety_troubleshooting_refuses_a_tool_that_is_not_a_gateway_tool() {
    for granted in [
        vec![tool("read")],
        vec![tool("write")],
        vec![tool("execute_sandboxed")],
    ] {
        let tools = claude_argv::tools_for(&granted, FlagSet::Troubleshooting, &gateway_tools());
        assert!(tools.iter().any(ClaudeTool::is_built_in));
        let refused = claude_argv::build(
            &troubleshooting_plan(
                claude_argv::ClaudeCredential::ApiKeyHelper,
                tools,
                Some(GATEWAY_URL),
            ),
            &verified(),
        );
        assert_eq!(refused, Err(claude_argv::ArgvRefused::ToolNotAllowed));
    }
    for built_in in ClaudeTool::ALL {
        let mut tools = vec![built_in];
        tools.extend(gateway_tools().into_iter().map(ClaudeTool::Mcp));
        let refused = claude_argv::build(
            &troubleshooting_plan(
                claude_argv::ClaudeCredential::ApiKeyHelper,
                tools,
                Some(GATEWAY_URL),
            ),
            &verified(),
        );
        assert_eq!(refused, Err(claude_argv::ArgvRefused::ToolNotAllowed));
    }
    // A troubleshooter with no gateway tool has nothing to do: refused, not run empty.
    let refused = claude_argv::build(
        &troubleshooting_plan(
            claude_argv::ClaudeCredential::ApiKeyHelper,
            Vec::new(),
            Some(GATEWAY_URL),
        ),
        &verified(),
    );
    assert_eq!(refused, Err(claude_argv::ArgvRefused::ToolNotAllowed));
    // Without a gateway address the flag set is refused, and a bad address too.
    let gateway: Vec<ClaudeTool> = gateway_tools().into_iter().map(ClaudeTool::Mcp).collect();
    let refused = claude_argv::build(
        &troubleshooting_plan(
            claude_argv::ClaudeCredential::ApiKeyHelper,
            gateway.clone(),
            None,
        ),
        &verified(),
    );
    assert_eq!(refused, Err(claude_argv::ArgvRefused::GatewayMismatch));
    let refused = claude_argv::build(
        &troubleshooting_plan(
            claude_argv::ClaudeCredential::ApiKeyHelper,
            gateway,
            Some("http://egress:8444/mcp?token=x"),
        ),
        &verified(),
    );
    assert_eq!(refused, Err(claude_argv::ArgvRefused::BadGatewayUrl));
}

#[test]
fn argument_safety_other_flag_sets_refuse_a_gateway_and_its_tools() {
    for flag_set in [FlagSet::Standard, FlagSet::Specification] {
        let plan = |tools, mcp_url| claude_argv::Plan {
            credential: claude_argv::ClaudeCredential::ApiKeyHelper,
            flag_set,
            model: "claude-sonnet-5-5",
            max_turns: 3,
            max_budget_usd: 1.0,
            tools,
            mcp_url,
        };
        let refused = claude_argv::build(&plan(Vec::new(), Some(GATEWAY_URL)), &verified());
        assert_eq!(refused, Err(claude_argv::ArgvRefused::GatewayMismatch));
        let gateway: Vec<ClaudeTool> = gateway_tools().into_iter().map(ClaudeTool::Mcp).collect();
        let refused = claude_argv::build(&plan(gateway, None), &verified());
        assert_eq!(refused, Err(claude_argv::ArgvRefused::ToolNotAllowed));
        // And the flags of the troubleshooter never reach them.
        let args = claude_args(flag_set, &[tool("read")]);
        for name in ["--mcp-config", "--allowedTools", "--permission-mode"] {
            assert!(
                !args.iter().any(|a| flag_name(a) == name),
                "{name} for {flag_set:?}"
            );
        }
        assert!(args.iter().any(|a| a == "--strict-mcp-config"));
    }
}

#[tokio::test]
async fn argument_safety_a_request_whose_flag_set_and_gateway_disagree_never_starts_the_tool() {
    let h = Harness::new();
    // A pipeline stage with a gateway.
    let mut with_gateway = troubleshooting_request(&h);
    with_gateway.flag_set = FlagSet::Standard;
    // The troubleshooter without one.
    let mut without_gateway = troubleshooting_request(&h);
    without_gateway.mcp_gateway = None;
    // The troubleshooter with a built-in tool granted.
    let mut with_read = troubleshooting_request(&h);
    with_read.tools = vec![tool("read")];
    for req in [with_gateway, without_gateway, with_read] {
        let mut s = ScriptedSession::new(&h, Tool::Claude, Step::exits(0, ""));
        let watch = s.watch();
        let runtime =
            ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone(), h.attestation());
        let report = runtime.run(&mut s, req, &NeverCancelled).await;
        assert!(watch.tool_run().is_none(), "the tool was started");
        assert!(matches!(
            report.outcome,
            Err(AgentRunError::ProcessFailed(_))
        ));
    }
    // Codex never runs the troubleshooter.
    let mut s = ScriptedSession::new(&h, Tool::Codex, Step::exits(0, ""));
    let watch = s.watch();
    let mut req = troubleshooting_request(&h);
    req.model.runtime = factory_ports::agent::RuntimeId::new("codex-cli").expect("an id");
    let codex = CodexRuntime::new(CodexConfig::default(), h.io.clone(), h.attestation());
    let report = codex.run(&mut s, req, &NeverCancelled).await;
    assert!(watch.tool_run().is_none(), "Codex was started");
    assert!(matches!(
        report.outcome,
        Err(AgentRunError::ProcessFailed(_))
    ));
}

/// The gateway's run token is a file the launcher line reads inside the sandbox. Neither its value
/// nor a variable carrying it is in the recorded command line, in either credential mode.
#[tokio::test]
async fn argument_safety_the_gateway_token_never_appears_in_the_argv_or_the_recorded_command() {
    use factory_ports::sandbox::MCP_TOKEN_TARGET;
    use factory_runtime::command::{
        LAUNCHER_SHELL, MCP_TOKEN_LAUNCHER, MCP_TOKEN_VARIABLE, OAUTH_AND_MCP_TOKEN_LAUNCHER,
    };
    // Stands in for the token the sandbox mounts; the runtime is never given it.
    let token = support::runtime_secret("mcp-run-token");
    for (credential, line) in [
        (
            claude_argv::ClaudeCredential::ApiKeyHelper,
            MCP_TOKEN_LAUNCHER,
        ),
        (
            claude_argv::ClaudeCredential::OauthToken,
            OAUTH_AND_MCP_TOKEN_LAUNCHER,
        ),
    ] {
        let h = Harness::new();
        h.register_secret("mcp-run-token", &token);
        let mut s = ScriptedSession::new(&h, Tool::Claude, Step::exits(0, ""));
        let watch = s.watch();
        let config = ClaudeCodeConfig {
            credential,
            ..ClaudeCodeConfig::default()
        };
        let runtime = ClaudeCodeRuntime::new(config.clone(), h.io.clone(), h.attestation());
        let _ = runtime
            .run(&mut s, troubleshooting_request(&h), &NeverCancelled)
            .await;
        let run = watch.tool_run().expect("the tool ran");
        let argv = &run.argv;
        let shell = argv
            .iter()
            .position(|a| a == LAUNCHER_SHELL)
            .expect("the launcher");
        assert_eq!(argv[shell + 1], "-c");
        assert_eq!(argv[shell + 2], line);
        assert_eq!(argv[shell + 3], config.binary);
        assert!(line.contains(MCP_TOKEN_TARGET));
        assert!(line.contains(MCP_TOKEN_VARIABLE));
        // No variable of the clean environment carries the token.
        let end = argv
            .iter()
            .position(|a| a == "/usr/bin/timeout")
            .expect("the soft deadline wrapper");
        for pair in &argv[2..end] {
            assert!(!pair.starts_with(MCP_TOKEN_VARIABLE), "{pair}");
        }
        let flags = &argv[shell + 4..];
        assert!(!flags.iter().any(|a| a == "--dangerously-skip-permissions"));
        assert!(flags.iter().any(|a| a == "--strict-mcp-config"));
        for seen in watch.seen() {
            let text = seen.argv.join(" ");
            assert!(!text.contains(&token), "the token value is in a command");
            if let Some(stdin) = &seen.stdin {
                assert!(!String::from_utf8_lossy(stdin).contains(&token));
            }
            // The only bearer the command line names is the variable reference.
            for (at, _) in text.match_indices("Bearer ") {
                assert!(
                    text[at + "Bearer ".len()..].starts_with("${FACTORY_MCP_TOKEN}"),
                    "a bearer value is in a command: {text}"
                );
            }
        }
    }
}
