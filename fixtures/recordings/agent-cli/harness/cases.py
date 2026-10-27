"""The recorded cases of the agent runtime spike (work package s0-agent-runtime-spike).

Every case runs a tool (or a probe command) inside the hardened container profile. See spike.py for the
profile and model.py for the fields. Cases are grouped by the question of the spike they answer. A
directive such as FAKE:TOOL in a prompt tells the labelled fake provider (fake/fake_provider.py) what to
answer; the tools never talk to a real model.
"""

from __future__ import annotations

import json
from pathlib import Path

from model import Case

REPO = Path(__file__).resolve().parents[4]
CLAUDE = "/usr/local/bin/claude"
CODEX = "/opt/codex/bin/codex"
CLAUDE_STREAM = ["-p", "--output-format", "stream-json", "--verbose", "--no-session-persistence"]
CODEX_EXEC = ["exec", "--json", "--ephemeral", "--skip-git-repo-check", "-C", "/workspace"]
SPEC_STAGE_DENIED = ["plan", "tasks", "analyze", "implement", "converge", "taskstoissues"]
POSTURE_SCRIPT = (
    "id; grep -E 'CapEff|CapPrm|CapBnd|NoNewPrivs|Seccomp:' /proc/self/status; "
    "echo '--- apparmor'; cat /proc/self/attr/current 2>&1; "
    "echo '--- mounts'; grep -E ' / | /workspace| /home/agent| /tmp | /out | /run/secrets' /proc/mounts; "
    "echo '--- masked git'; ls -la /workspace/.git; wc -c < /workspace/.git; "
    "echo '--- write tests'; touch /usr/x 2>&1; touch /etc/x 2>&1; touch /workspace/ok && echo workspace-writable; "
    "touch /home/agent/ok && echo home-writable; touch /tmp/ok && echo tmp-writable; "
    "echo '--- tools present'; for t in git bash sh python3 node rg curl wget ps ldd; do command -v $t || echo \"$t: absent\"; done; "
    "echo '--- binaries'; ls -l /usr/local/bin/claude /opt/codex/bin/* /opt/codex/codex-path/* /opt/codex/codex-resources/* 2>&1; "
    "sha256sum /usr/local/bin/claude /opt/codex/bin/codex 2>&1; "
    "echo '--- shared libraries'; ldd /usr/local/bin/claude 2>&1; ldd /opt/codex/bin/codex 2>&1"
)


def gate_report_schema(strip_dialect: bool = False) -> str:
    """The real gate-report schema, compact, as the argument of --json-schema. Optionally without the $schema key."""
    schema = json.loads((REPO / "schemas" / "gate-report.schema.json").read_text(encoding="utf-8"))
    if strip_dialect:
        schema.pop("$schema", None)
    return json.dumps(schema, separators=(",", ":"))


def build_cases(provider_url: str) -> list[Case]:
    cases: list[Case] = []
    add = cases.append
    bridge_url = "http://bridge:8081/mcp"
    claude_env = {"ANTHROPIC_BASE_URL": provider_url}
    quiet = {**claude_env, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}
    bridge_mcp = json.dumps({"mcpServers": {"bridge": {"type": "http", "url": bridge_url}}})

    def codex_provider(auth: str = 'env_key="FAKE_PROVIDER_KEY"', extra: str = "") -> list[str]:
        return [
            "-c", 'model_provider="fake"',
            "-c", f'model_providers.fake={{name="Fake", base_url="{provider_url}/v1", {auth}, wire_api="responses", supports_websockets=false{extra}}}',
        ]

    codex_quiet_features = ["--disable", "plugins", "--disable", "apps", "--disable", "remote_plugin", "--disable", "tool_suggest", "--disable", "image_generation", "--disable", "plugin_sharing"]
    codex_quiet_config = ["-c", "analytics.enabled=false", "-c", "feedback.enabled=false", "-c", "check_for_update_on_startup=false"]
    codex_quiet = [*codex_quiet_features, *codex_quiet_config]

    # ------------------------------------------------------------------ questions 1 and 2: install, start, footprint
    add(Case("claude-version", "claude --version under the hardened profile, no network", [1, 2], "claude", ["--version"], net="none"))
    add(Case("codex-version", "codex --version under the hardened profile, no network", [1, 2], "codex", ["--version"], net="none"))
    add(Case("claude-help", "claude --help from the image", [1, 7], "claude", ["--help"], net="none"))
    add(Case("codex-help", "codex --help from the image", [1, 7], "codex", ["--help"], net="none"))
    add(Case("codex-exec-help", "codex exec --help from the image", [1, 7], "codex", ["exec", "--help"], net="none"))
    add(Case("codex-features-list", "codex features list, offline", [4, 6], "codex", ["features", "list"], net="none"))
    add(Case("claude-posture", "Process posture seen from inside the Claude Code image", [1, 2], "claude", ["-c", POSTURE_SCRIPT], net="none", entrypoint=["/bin/sh"], wrap=False))
    add(Case("codex-posture", "Process posture seen from inside the Codex image", [1, 2], "codex", ["-c", POSTURE_SCRIPT], net="none", entrypoint=["/bin/sh"], wrap=False))
    add(Case("claude-ro-home", "Claude Code turn with no writable home", [2], "claude", [*CLAUDE_STREAM, "say hello"], env=quiet, key_env="ANTHROPIC_API_KEY", home="readonly", timeout_s=40))
    add(Case("codex-ro-home", "Codex turn with no writable home", [2], "codex", [*CODEX_EXEC, *codex_provider(), *codex_quiet, "say hello"], key_env="FAKE_PROVIDER_KEY", home="readonly", timeout_s=40))
    add(Case("codex-git-check-default", "Codex without --skip-git-repo-check in a workspace whose .git is masked", [2],
             "codex", ["exec", "--json", "--ephemeral", "-C", "/workspace", *codex_provider(), *codex_quiet, "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=40))
    add(Case("claude-git-masked", "Claude Code asked to inspect the masked .git and look for a git binary", [2], "claude",
             [*CLAUDE_STREAM, "--dangerously-skip-permissions",
              'FAKE:TOOL Bash {"command":"ls -la /workspace/.git; wc -c < /workspace/.git; command -v git || echo no-git-binary","description":"inspect"}'],
             env=quiet, key_env="ANTHROPIC_API_KEY"))

    # The tools on a bare Alpine image (no bash, no libgcc, no libstdc++, no ca-certificates): which packages does each really need?
    bare = "alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"
    add(Case("claude-bare-image-version", "claude --version on a bare Alpine image with only the binary mounted", [1], "claude", ["--version"], net="none", image=bare, entrypoint=[CLAUDE], wrap=False,
             mounts=["type=bind,src={run}/bin/claude,dst=/usr/local/bin/claude,readonly"]))
    add(Case("claude-bare-image-turn", "Claude Code turn on a bare Alpine image with only the binary mounted", [1, 2], "claude", [*CLAUDE_STREAM, "say hello"], env=quiet, key_env="ANTHROPIC_API_KEY", image=bare, entrypoint=[CLAUDE], wrap=False,
             mounts=["type=bind,src={run}/bin/claude,dst=/usr/local/bin/claude,readonly"]))
    proxy_mount = ["type=bind,src={run}/bin/codex-responses-api-proxy,dst=/opt/proxy/codex-responses-api-proxy,readonly"]
    add(Case("codex-responses-proxy-help", "The vendor codex-responses-api-proxy release asset: --help (a possible broker building block, offline)", [3, 5], "codex", ["--help"], net="none",
             image=bare, entrypoint=["/opt/proxy/codex-responses-api-proxy"], wrap=False, mounts=proxy_mount))
    add(Case("codex-bare-image-version", "codex --version on a bare Alpine image with only the files mounted", [1], "codex", ["--version"], net="none", image=bare, entrypoint=[CODEX], wrap=False,
             mounts=["type=bind,src={run}/bin/codex,dst=/opt/codex,readonly"]))
    add(Case("codex-bare-image-turn", "Codex turn on a bare Alpine image with only the files mounted", [1, 2], "codex", [*CODEX_EXEC, *codex_provider(), *codex_quiet, "say hello"], key_env="FAKE_PROVIDER_KEY", image=bare, entrypoint=[CODEX], wrap=False,
             mounts=["type=bind,src={run}/bin/codex,dst=/opt/codex,readonly"], timeout_s=40))

    # ------------------------------------------------------------------ question 3 and 5: base URL and credentials
    add(Case("claude-turn-env", "Claude Code turn: base URL and key from environment variables", [2, 3, 5, 7], "claude",
             [*CLAUDE_STREAM, "say hello"], env=claude_env, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-baseurl-settings", "Claude Code: base URL from --settings, key from the environment", [3], "claude",
             [*CLAUDE_STREAM, "--settings", json.dumps({"env": {"ANTHROPIC_BASE_URL": provider_url}}), "say hello"],
             env={"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-auth-helper", "Claude Code: key from an apiKeyHelper that reads the secret file", [5], "claude",
             [*CLAUDE_STREAM, "--settings", json.dumps({"apiKeyHelper": "cat /run/secrets/job_token"}), "say hello"], env=quiet))
    add(Case("claude-auth-helper-bare", "Claude Code --bare: key from an apiKeyHelper that reads the secret file", [5, 6], "claude",
             [*CLAUDE_STREAM, "--bare", "--settings", json.dumps({"apiKeyHelper": "cat /run/secrets/job_token"}), "say hello"], env=quiet))
    add(Case("claude-auth-fd", "Claude Code: key from an inherited file descriptor", [5], "claude",
             ["-c", 'exec 3</run/secrets/job_token; CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR=3 exec /usr/local/bin/claude "$@"', "sh", *CLAUDE_STREAM, "say hello"],
             env=quiet, entrypoint=["/bin/sh"], wrap=False))
    add(Case("claude-auth-token-env", "Claude Code: bearer token from ANTHROPIC_AUTH_TOKEN", [5], "claude",
             [*CLAUDE_STREAM, "say hello"], env=quiet, key_env="ANTHROPIC_AUTH_TOKEN"))
    add(Case("claude-auth-none", "Claude Code with no credential at all", [5, 7], "claude", [*CLAUDE_STREAM, "say hello"], env=quiet, timeout_s=40))
    add(Case("claude-auth-wrong", "Claude Code with a key the provider rejects", [5, 7], "claude", [*CLAUDE_STREAM, "say hello"],
             env={**quiet, "ANTHROPIC_API_KEY": "wrong-key-made-up-for-the-spike"}, timeout_s=40))
    add(Case("claude-bare-turn", "Claude Code --bare turn: base URL and key from the environment", [3, 4, 6], "claude",
             [*CLAUDE_STREAM, "--bare", "say hello"], env=claude_env, key_env="ANTHROPIC_API_KEY"))
    add(Case("codex-baseurl-env-ignored", "Codex with OPENAI_BASE_URL and OPENAI_API_KEY set", [3, 5], "codex",
             [*CODEX_EXEC, "say hello"], env={"OPENAI_BASE_URL": provider_url + "/v1"}, key_env="OPENAI_API_KEY", timeout_s=20))
    add(Case("codex-baseurl-builtin-openai-key", "Codex built-in provider with -c openai_base_url and OPENAI_API_KEY", [3, 5], "codex",
             [*CODEX_EXEC, "-c", f'openai_base_url="{provider_url}/v1"', "say hello"], key_env="OPENAI_API_KEY", timeout_s=30))
    add(Case("codex-baseurl-builtin-codex-key", "Codex built-in provider with -c openai_base_url and CODEX_API_KEY", [3, 5], "codex",
             [*CODEX_EXEC, "-c", f'openai_base_url="{provider_url}/v1"', "say hello"], key_env="CODEX_API_KEY", timeout_s=30))
    add(Case("codex-turn-custom-provider", "Codex turn through a custom model provider, key from an environment variable", [2, 3, 5, 7], "codex",
             [*CODEX_EXEC, *codex_provider(), "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=30))
    add(Case("codex-auth-command", "Codex: key from a provider auth command that reads the secret file", [5], "codex",
             [*CODEX_EXEC, *codex_provider('auth={command="cat", args=["/run/secrets/job_token"]}'), *codex_quiet, "say hello"], timeout_s=30))
    add(Case("codex-auth-json", "Codex: key stored by codex login --with-api-key in auth.json under the home directory", [5], "codex",
             ["-c", 'cat /run/secrets/job_token | /opt/codex/bin/codex login --with-api-key; echo "--- auth.json keys"; sed "s/\\"OPENAI_API_KEY\\": *\\"[^\\"]*\\"/OPENAI_API_KEY=<hidden>/" /home/agent/.codex/auth.json; echo; '
              f'exec /opt/codex/bin/codex exec --json --ephemeral --skip-git-repo-check -C /workspace -c openai_base_url="{provider_url}/v1" {" ".join(codex_quiet_features)} {" ".join(codex_quiet_config)} "say hello"'],
             entrypoint=["/bin/sh"], wrap=False, timeout_s=40))
    add(Case("codex-auth-none", "Codex with no credential for a provider that needs one", [5, 7], "codex",
             [*CODEX_EXEC, *codex_provider(), *codex_quiet, "say hello"], timeout_s=30))
    add(Case("codex-auth-wrong", "Codex with a key the provider rejects", [5, 7], "codex",
             [*CODEX_EXEC, *codex_provider(), *codex_quiet, "say hello"], env={"FAKE_PROVIDER_KEY": "wrong-key-made-up-for-the-spike"}, timeout_s=40))

    # ------------------------------------------------------------------ question 4: egress
    add(Case("claude-egress-minimal", "Claude Code turn with CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", [4], "claude",
             [*CLAUDE_STREAM, "say hello"], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-unreachable", "Claude Code when the provider cannot be reached (no network), retries bounded to 2", [4, 7], "claude",
             [*CLAUDE_STREAM, "say hello"], env={**quiet, "CLAUDE_CODE_MAX_RETRIES": "2"}, key_env="ANTHROPIC_API_KEY", net="none", timeout_s=60))
    add(Case("codex-egress-features-only", "Codex turn with only the network-related features switched off", [4], "codex",
             [*CODEX_EXEC, *codex_provider(), *codex_quiet_features, "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=30))
    add(Case("codex-egress-config-only", "Codex turn with only analytics, feedback and update-check settings switched off", [4], "codex",
             [*CODEX_EXEC, *codex_provider(), *codex_quiet_config, "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=30))
    add(Case("codex-egress-minimal", "Codex turn with network-related features and settings switched off", [4], "codex",
             [*CODEX_EXEC, *codex_provider(), *codex_quiet, "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=30))
    add(Case("claude-egress-disable-telemetry", "Claude Code turn with DISABLE_TELEMETRY, DISABLE_ERROR_REPORTING and DISABLE_AUTOUPDATER only", [4], "claude",
             [*CLAUDE_STREAM, "say hello"], env={**claude_env, "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1", "DISABLE_AUTOUPDATER": "1"}, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-telemetry-file-keys", "Key names (not values) in the telemetry file Claude Code leaves in its home directory", [4, 7], "claude",
             ["-c", '/usr/local/bin/claude -p --no-session-persistence --output-format json "say hello" >/dev/null 2>&1; '
              'for f in /home/agent/.claude/telemetry/*.json; do echo "file: $f"; wc -c < "$f"; grep -o \'"[A-Za-z_]*":\' "$f" | sort | uniq -c | sort -rn | head -60; done'],
             env=claude_env, key_env="ANTHROPIC_API_KEY", entrypoint=["/bin/sh"], wrap=False))
    switches = [("feature", name) for name in ("plugins", "apps", "remote_plugin", "tool_suggest", "image_generation", "plugin_sharing")]
    switches += [("config", name) for name in ("analytics.enabled=false", "feedback.enabled=false", "check_for_update_on_startup=false")]
    for kind, name in switches:
        flag = ["--disable", name] if kind == "feature" else ["-c", name]
        slug = name.split("=")[0].split(".")[0].replace("_", "-")
        add(Case(f"codex-egress-only-{slug}", f"Codex turn with only {name} switched off", [4], "codex",
                 [*CODEX_EXEC, *codex_provider(), *flag, "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=30))
    env_probe = r"env | grep -c -E '^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|FAKE_PROVIDER_KEY)='; tr '\0' '\n' < /proc/$PPID/environ | grep -c -E '^(ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|FAKE_PROVIDER_KEY)='; true"
    claude_env_probe = "FAKE:TOOL Bash " + json.dumps({"command": env_probe, "description": "count key variables"})
    add(Case("claude-toolenv-default", "Does the Bash tool of Claude Code see the key in its environment and in its parent's environment (key given as a variable)", [5, 8], "claude",
             [*CLAUDE_STREAM, "--dangerously-skip-permissions", claude_env_probe], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-toolenv-scrub", "Same with CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1", [5, 8], "claude",
             [*CLAUDE_STREAM, "--dangerously-skip-permissions", claude_env_probe], env={**quiet, "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1"}, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-toolenv-helper", "Same when the key comes from an apiKeyHelper and is in no variable", [5, 8], "claude",
             [*CLAUDE_STREAM, "--dangerously-skip-permissions", "--settings", json.dumps({"apiKeyHelper": "cat /run/secrets/job_token"}), claude_env_probe], env=quiet))
    codex_env_probe = "FAKE:TOOL exec text(JSON.stringify(await tools.exec_command({cmd: " + json.dumps(env_probe) + "})))"
    add(Case("codex-toolenv-default", "Does the shell tool of Codex see the key in its environment and in its parent's environment (key given as a variable)", [5, 8], "codex",
             [*CODEX_EXEC, "--dangerously-bypass-approvals-and-sandbox", *codex_provider(), *codex_quiet, codex_env_probe], key_env="FAKE_PROVIDER_KEY", timeout_s=60))
    add(Case("codex-toolenv-command-auth", "Same when the key comes from a provider auth command and is in no variable", [5, 8], "codex",
             [*CODEX_EXEC, "--dangerously-bypass-approvals-and-sandbox", *codex_provider('auth={command="cat", args=["/run/secrets/job_token"]}'), *codex_quiet, codex_env_probe], timeout_s=60))
    add(Case("codex-unreachable", "Codex when the provider cannot be reached (no network)", [4, 7], "codex",
             [*CODEX_EXEC, *codex_provider('env_key="FAKE_PROVIDER_KEY", request_max_retries=1, stream_max_retries=1'), *codex_quiet, "say hello"],
             key_env="FAKE_PROVIDER_KEY", net="none", timeout_s=60))

    # ------------------------------------------------------------------ question 6: skills and slash commands
    speckit = "speckit"

    def overlays(prefix: str, names: list[str]) -> list[str]:
        return [f"type=bind,src={{run}}/empty,dst=/workspace/{prefix}/speckit-{n},readonly" for n in names]

    def claude_skill_case(case_id: str, title: str, extra: list[str], mounts: list[str] | None = None, prompt: str = "say hello") -> Case:
        return Case(case_id, title, [6], "claude", [*CLAUDE_STREAM, *extra, prompt], env=quiet, key_env="ANTHROPIC_API_KEY", ws=speckit, mounts=mounts or [])

    add(claude_skill_case("claude-skills-baseline", "Claude Code skill list in a Spec Kit project, default flags", []))
    add(claude_skill_case("claude-skills-bare", "Claude Code skill list with --bare", ["--bare"]))
    add(claude_skill_case("claude-skills-disabled", "Claude Code skill list with --disable-slash-commands", ["--disable-slash-commands"]))
    add(Case("claude-skills-no-bundled", "Claude Code skill list with CLAUDE_CODE_DISABLE_BUNDLED_SKILLS=1", [6], "claude", [*CLAUDE_STREAM, "say hello"],
             env={**quiet, "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS": "1"}, key_env="ANTHROPIC_API_KEY", ws=speckit))
    add(claude_skill_case("claude-skills-overlay-spec-stage", "Claude Code skill list with the six denied Spec Kit skills hidden by read-only empty overlays", [], overlays(".claude/skills", SPEC_STAGE_DENIED)))
    add(claude_skill_case("claude-skills-bare-overlay-spec-stage", "Claude Code --bare with the six denied skills hidden by overlays", ["--bare"], overlays(".claude/skills", SPEC_STAGE_DENIED)))
    plugin_mount = ["type=bind,src={run}/plugin,dst=/factory/plugin,readonly"]
    add(claude_skill_case("claude-skills-bare-plugin", "Claude Code --bare with the four allowed skills supplied by a factory plugin directory", ["--bare", "--plugin-dir=/factory/plugin"], plugin_mount))
    add(claude_skill_case("claude-skills-bare-plugin-hidden-project", "Claude Code --bare, factory plugin, and the project skill roots hidden by overlays", ["--bare", "--plugin-dir=/factory/plugin"],
                          [*plugin_mount, "type=bind,src={run}/empty,dst=/workspace/.claude/skills,readonly"]))
    add(claude_skill_case("claude-skills-overlay-all", "Claude Code skill list with .claude/skills and .claude/commands hidden by read-only empty overlays", [],
                          ["type=bind,src={run}/empty,dst=/workspace/.claude/skills,readonly", "type=bind,src={run}/empty,dst=/workspace/.claude/commands,readonly"]))
    add(claude_skill_case("claude-skills-slash-direct", "Claude Code single-shot: the prompt starts with /speckit-specify", [], prompt="/speckit-specify Add a tiny login page"))
    add(claude_skill_case("claude-skills-slash-disabled", "Claude Code with --disable-slash-commands: the prompt starts with /speckit-specify", ["--disable-slash-commands"], prompt="/speckit-specify Add a tiny login page"))
    add(claude_skill_case("claude-skills-slash-overlay-denied", "Claude Code: the prompt starts with /speckit-plan while its directory is hidden by an overlay", [],
                          overlays(".claude/skills", SPEC_STAGE_DENIED), prompt="/speckit-plan Make a plan"))
    add(claude_skill_case("claude-skills-slash-rule-denied", "Claude Code: the prompt starts with /speckit-plan while Skill(speckit-plan) is a deny rule", ["--disallowedTools=Skill(speckit-plan)"], prompt="/speckit-plan Make a plan"))
    add(claude_skill_case("claude-skills-tool-rule-denied", "Claude Code: the model calls the Skill tool for speckit-plan while Skill(speckit-plan) is a deny rule", ["--disallowedTools=Skill(speckit-plan)"],
                          prompt='FAKE:TOOL Skill {"skill":"speckit-plan"}'))
    add(claude_skill_case("claude-skills-tool-no-rule", "Claude Code: the model calls the Skill tool for speckit-plan with no deny rule (control)", [], prompt='FAKE:TOOL Skill {"skill":"speckit-plan"}'))
    add(claude_skill_case("claude-skills-tool-overlay", "Claude Code: the model calls the Skill tool for a skill hidden by an overlay", [], overlays(".claude/skills", SPEC_STAGE_DENIED), prompt='FAKE:TOOL Skill {"skill":"speckit-plan"}'))

    codex_skill_base = ["-C", "/workspace", *codex_quiet]

    def codex_skill_case(case_id: str, title: str, extra: list[str], mounts: list[str] | None = None) -> Case:
        return Case(case_id, title, [6], "codex", [*extra, *codex_skill_base, "debug", "prompt-input", "test"], ws=speckit, mounts=mounts or [], net="none", timeout_s=40)

    add(codex_skill_case("codex-skills-baseline", "Codex skill list in a Spec Kit project (debug prompt-input, no model call)", []))
    add(codex_skill_case("codex-skills-overlay-spec-stage", "Codex skill list with the six denied skills hidden by overlays", [], overlays(".agents/skills", SPEC_STAGE_DENIED)))
    add(codex_skill_case("codex-skills-overlay-all", "Codex skill list with .agents/skills hidden by an overlay", [], ["type=bind,src={run}/empty,dst=/workspace/.agents/skills,readonly"]))
    add(codex_skill_case("codex-skills-config-disable", "Codex skill list with skills.config entries that disable two skills", ["-c", 'skills.config=[{path="/workspace/.agents/skills/speckit-plan/SKILL.md", enabled=false},{path="/workspace/.agents/skills/speckit-tasks/SKILL.md", enabled=false}]']))
    add(codex_skill_case("codex-skills-bundled-off", "Codex skill list with skills.bundled.enabled=false", ["-c", "skills.bundled.enabled=false"]))
    add(codex_skill_case("codex-skills-ignore-user-config", "Codex skill list with --ignore-user-config", ["--ignore-user-config"]))

    # ------------------------------------------------------------------ question 7: the headless contract
    read_loop = 'FAKE:LOOP {n} Read {{"file_path":"/workspace/README.md"}}'
    add(Case("claude-fmt-text", "Claude Code -p with the default text output", [7], "claude", ["-p", "--no-session-persistence", "say hello"], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-fmt-json", "Claude Code -p --output-format json", [7], "claude", ["-p", "--no-session-persistence", "--output-format", "json", "say hello"], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-fmt-stream-partial", "Claude Code stream-json with --include-partial-messages", [7], "claude", [*CLAUDE_STREAM, "--include-partial-messages", "say hello"], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-stdin-stream-json", "Claude Code with --input-format stream-json and one user message on standard input", [7], "claude",
             ["-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--no-session-persistence"], env=quiet, key_env="ANTHROPIC_API_KEY",
             stdin=json.dumps({"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": "say hello"}]}}) + "\n"))
    add(Case("claude-tool-turns", "Claude Code: one tool call and a final answer (two model requests)", [7, 8], "claude",
             [*CLAUDE_STREAM, "--allowedTools=Read", 'FAKE:TOOL Read {"file_path":"/workspace/README.md"}'], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-max-turns-flag", "Claude Code with the hidden --max-turns 2 flag against a model that never stops calling tools", [7], "claude",
             [*CLAUDE_STREAM, "--max-turns", "2", "--allowedTools=Read", read_loop.format(n=9)], env=quiet, key_env="ANTHROPIC_API_KEY", timeout_s=40))
    add(Case("claude-max-turns-env", "Claude Code with CLAUDE_CODE_MAX_TURNS=2", [7], "claude",
             [*CLAUDE_STREAM, "--allowedTools=Read", read_loop.format(n=9)], env={**quiet, "CLAUDE_CODE_MAX_TURNS": "2"}, key_env="ANTHROPIC_API_KEY", timeout_s=40))
    add(Case("claude-max-budget", "Claude Code with --max-budget-usd 0.01 against a model that never stops calling tools", [7], "claude",
             [*CLAUDE_STREAM, "--max-budget-usd", "0.01", "--allowedTools=Read", read_loop.format(n=9)], env=quiet, key_env="ANTHROPIC_API_KEY", timeout_s=40))
    add(Case("claude-loop-revoked", "Claude Code when the broker revokes the token after three tool results", [7], "claude",
             [*CLAUDE_STREAM, "--allowedTools=Read", read_loop.format(n=3)], env=quiet, key_env="ANTHROPIC_API_KEY", timeout_s=40))
    add(Case("claude-struct-valid", "Claude Code --json-schema with the real gate-report schema, valid answer", [7], "claude",
             ["-p", "--no-session-persistence", "--output-format", "json", "--json-schema", gate_report_schema(), "FAKE:STRUCT"], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-struct-invalid", "Claude Code --json-schema with the real gate-report schema, answer breaks the schema", [7], "claude",
             ["-p", "--no-session-persistence", "--output-format", "json", "--json-schema", gate_report_schema(), "FAKE:STRUCT_BAD"], env=quiet, key_env="ANTHROPIC_API_KEY", timeout_s=60))
    add(Case("claude-struct-nodialect-valid", "Claude Code --json-schema with the gate-report schema minus its $schema key, valid answer", [7], "claude",
             ["-p", "--no-session-persistence", "--output-format", "json", "--json-schema", gate_report_schema(True), "FAKE:STRUCT"], env=quiet, key_env="ANTHROPIC_API_KEY"))
    add(Case("claude-struct-nodialect-invalid", "Claude Code --json-schema with the gate-report schema minus its $schema key, answer breaks the schema", [7], "claude",
             ["-p", "--no-session-persistence", "--output-format", "json", "--json-schema", gate_report_schema(True), "FAKE:STRUCT_BAD"], env=quiet, key_env="ANTHROPIC_API_KEY", timeout_s=60))
    claude_matrix = (
        "for f in /schemas/*.schema.json; do b=$(basename \"$f\" .schema.json); "
        "for variant in as-is without-dialect-key; do "
        "if [ \"$variant\" = as-is ]; then cp \"$f\" /tmp/s.json; else grep -v '\"[$]schema\"' \"$f\" > /tmp/s.json; fi; "
        "out=$(timeout 20 /usr/local/bin/claude -p --no-session-persistence --output-format json --json-schema \"$(cat /tmp/s.json)\" 'say hello' 2>&1 | head -c 260 | tr '\\n' ' '); "
        "echo \"$b | $variant | $out\"; done; done"
    )
    add(Case("claude-schema-matrix", "Which factory schemas Claude Code accepts as --json-schema, as they are and without the $schema key", [7], "claude", ["-c", claude_matrix],
             env=quiet, key_env="ANTHROPIC_API_KEY", entrypoint=["/bin/sh"], wrap=False, mounts=["type=bind,src={run}/schemas,dst=/schemas,readonly"], timeout_s=240))
    codex_matrix = (
        "for f in /schemas/*.schema.json; do b=$(basename \"$f\" .schema.json); "
        "out=$(timeout 20 /opt/codex/bin/codex exec --json --ephemeral --skip-git-repo-check -C /workspace --output-schema \"$f\" "
        + " ".join(f"'{part}'" if " " in part or "{" in part or '"' in part else part for part in [*codex_provider(), *codex_quiet])
        + " 'say hello' 2>&1 | head -c 260 | tr '\\n' ' '); echo \"$b | $out\"; done"
    )
    add(Case("codex-schema-matrix", "Which factory schemas Codex accepts as --output-schema", [7], "codex", ["-c", codex_matrix],
             key_env="FAKE_PROVIDER_KEY", entrypoint=["/bin/sh"], wrap=False, mounts=["type=bind,src={run}/schemas,dst=/schemas,readonly"], timeout_s=300))
    for status, retries in (("429", None), ("500", "1"), ("529", "1")):
        env = {**quiet, "CLAUDE_CODE_MAX_RETRIES": retries} if retries else quiet
        add(Case(f"claude-http-{status}", f"Claude Code when the provider answers {status}" + (f", retries bounded to {retries}" if retries else ", default retries"), [7], "claude",
                 [*CLAUDE_STREAM, f"FAKE:HTTP {status}"], env=env, key_env="ANTHROPIC_API_KEY", timeout_s=25 if not retries else 40))
    add(Case("claude-cancel-term", "Claude Code receives SIGTERM while waiting for the model", [7], "claude", [*CLAUDE_STREAM, "FAKE:SLEEP 60"], env=quiet, key_env="ANTHROPIC_API_KEY", kill_after=(4, "TERM"), wrap=False, timeout_s=30))
    add(Case("claude-cancel-int", "Claude Code receives SIGINT while waiting for the model", [7], "claude", [*CLAUDE_STREAM, "FAKE:SLEEP 60"], env=quiet, key_env="ANTHROPIC_API_KEY", kill_after=(4, "INT"), wrap=False, timeout_s=30))

    add(Case("codex-fmt-text", "Codex exec with the default human output", [7], "codex", ["exec", "--ephemeral", "--skip-git-repo-check", "-C", "/workspace", *codex_provider(), *codex_quiet, "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=30))
    add(Case("codex-last-message", "Codex exec --json with -o for the last message", [7], "codex",
             [*CODEX_EXEC, "-o", "/out/last-message.txt", *codex_provider(), *codex_quiet, "say hello"], key_env="FAKE_PROVIDER_KEY", timeout_s=30, keep_out=["last-message.txt"]))
    add(Case("codex-tool-turns", "Codex: one tool call and a final answer", [7, 8], "codex",
             [*CODEX_EXEC, "-s", "workspace-write", *codex_provider(), *codex_quiet,
              'FAKE:TOOL exec text(JSON.stringify(await tools.exec_command({cmd: "cat /workspace/README.md"})))'], key_env="FAKE_PROVIDER_KEY", timeout_s=40))
    add(Case("codex-loop-no-cap", "Codex against a model that never stops calling tools, until the broker revokes the token after nine results", [7], "codex",
             [*CODEX_EXEC, "-s", "workspace-write", *codex_provider(), *codex_quiet,
              'FAKE:LOOP 9 exec text(JSON.stringify(await tools.exec_command({cmd: "cat /workspace/README.md"})))'], key_env="FAKE_PROVIDER_KEY", timeout_s=60))
    add(Case("codex-struct-valid", "Codex --output-schema with the real gate-report schema, valid answer", [7], "codex",
             [*CODEX_EXEC, "--output-schema", "/fixture/gate-report.schema.json", "-o", "/out/last-message.json", *codex_provider(), *codex_quiet, "FAKE:STRUCT"],
             key_env="FAKE_PROVIDER_KEY", mounts=["type=bind,src={run}/fake/gate-report.schema.json,dst=/fixture/gate-report.schema.json,readonly"], keep_out=["last-message.json"], timeout_s=40))
    add(Case("codex-struct-invalid", "Codex --output-schema with the real gate-report schema, answer breaks the schema", [7], "codex",
             [*CODEX_EXEC, "--output-schema", "/fixture/gate-report.schema.json", "-o", "/out/last-message.json", *codex_provider(), *codex_quiet, "FAKE:STRUCT_BAD"],
             key_env="FAKE_PROVIDER_KEY", mounts=["type=bind,src={run}/fake/gate-report.schema.json,dst=/fixture/gate-report.schema.json,readonly"], keep_out=["last-message.json"], timeout_s=40))
    for status in ("429", "500"):
        add(Case(f"codex-http-{status}", f"Codex when the provider answers {status}", [7], "codex", [*CODEX_EXEC, *codex_provider(), *codex_quiet, f"FAKE:HTTP {status}"], key_env="FAKE_PROVIDER_KEY", timeout_s=60))
    add(Case("codex-unreachable-bounded", "Codex when the provider cannot be reached, with unbounded_connection_retries disabled", [4, 7], "codex",
             [*CODEX_EXEC, *codex_provider('env_key="FAKE_PROVIDER_KEY", request_max_retries=1, stream_max_retries=1'), *codex_quiet, "--disable", "unbounded_connection_retries", "say hello"],
             key_env="FAKE_PROVIDER_KEY", net="none", timeout_s=60))
    add(Case("codex-cancel-term", "Codex receives SIGTERM while waiting for the model", [7], "codex", [*CODEX_EXEC, *codex_provider(), *codex_quiet, "FAKE:SLEEP 60"], key_env="FAKE_PROVIDER_KEY", kill_after=(4, "TERM"), wrap=False, timeout_s=30))
    add(Case("codex-cancel-int", "Codex receives SIGINT while waiting for the model", [7], "codex", [*CODEX_EXEC, *codex_provider(), *codex_quiet, "FAKE:SLEEP 60"], key_env="FAKE_PROVIDER_KEY", kill_after=(4, "INT"), wrap=False, timeout_s=30))

    # ------------------------------------------------------------------ question 8: what the permission model enforces
    probe = "id; touch /workspace/created-by-tool && echo wrote-workspace; touch /etc/created-by-tool; echo etc-rc=$?; wc -c < /workspace/.env"
    bash_probe = "FAKE:TOOL Bash " + json.dumps({"command": probe, "description": "probe"})
    chained = "FAKE:TOOL Bash " + json.dumps({"command": "touch /workspace/first.txt && echo SECOND-COMMAND-RAN > /workspace/second.txt", "description": "chained"})
    read_env = 'FAKE:TOOL Read {"file_path":"/workspace/.env"}'
    codex_probe = "FAKE:TOOL exec text(JSON.stringify(await tools.exec_command({cmd: " + json.dumps(probe) + "})))"

    def claude_perm(case_id: str, title: str, extra: list[str], prompt: str) -> Case:
        return Case(case_id, title, [8], "claude", [*CLAUDE_STREAM, *extra, prompt], env=quiet, key_env="ANTHROPIC_API_KEY")

    add(claude_perm("claude-perm-bash-default", "Claude Code, default mode, no one to answer prompts: the model asks to run Bash", ["--permission-prompts", "none"], bash_probe))
    add(claude_perm("claude-perm-read-default", "Claude Code, default mode: the model reads a file in the workspace", ["--permission-prompts", "none"], 'FAKE:TOOL Read {"file_path":"/workspace/README.md"}'))
    add(claude_perm("claude-perm-bash-dontask", "Claude Code, permission mode dontAsk: the model asks to run Bash", ["--permission-mode", "dontAsk"], bash_probe))
    add(claude_perm("claude-perm-allow-prefix-chain", "Claude Code with --allowedTools Bash(touch:*): a chained command", ["--permission-prompts", "none", "--allowedTools=Bash(touch:*)"], chained))
    add(claude_perm("claude-perm-write-inside-acceptedits", "Claude Code acceptEdits: Write inside the workspace", ["--permission-mode", "acceptEdits", "--permission-prompts", "none"],
                    'FAKE:TOOL Write {"file_path":"/workspace/new-file.txt","content":"written by the tool"}'))
    add(claude_perm("claude-perm-write-outside-acceptedits", "Claude Code acceptEdits: Write outside the workspace", ["--permission-mode", "acceptEdits", "--permission-prompts", "none"],
                    'FAKE:TOOL Write {"file_path":"/tmp/outside-file.txt","content":"written by the tool"}'))
    add(claude_perm("claude-perm-bypass-flag", "Claude Code --dangerously-skip-permissions: the model runs the probe command", ["--dangerously-skip-permissions"], bash_probe))
    add(claude_perm("claude-perm-bypass-mode", "Claude Code --permission-mode bypassPermissions: the model runs the probe command", ["--permission-mode", "bypassPermissions"], bash_probe))
    deny_flags = ["--permission-prompts", "none"]
    add(claude_perm("claude-perm-deny-read-rule", "Claude Code with a Read(./.env) deny rule: the Read tool", [*deny_flags, "--disallowedTools=Read(./.env)"], read_env))
    add(claude_perm("claude-perm-deny-read-rule-abs", "Claude Code with a Read(//workspace/.env) deny rule: the Read tool", [*deny_flags, "--disallowedTools=Read(//workspace/.env)"], read_env))
    add(claude_perm("claude-perm-deny-read-rule-slash", "Claude Code with a Read(/workspace/.env) deny rule, one leading slash: the Read tool", [*deny_flags, "--disallowedTools=Read(/workspace/.env)"], read_env))
    add(claude_perm("claude-perm-deny-read-rule-bash", "Claude Code with a Read(./.env) deny rule: Bash reads the same file",
                    [*deny_flags, "--allowedTools=Bash", "--disallowedTools=Read(./.env)"],
                    "FAKE:TOOL Bash " + json.dumps({"command": "wc -c < /workspace/.env", "description": "size of .env"})))

    for variant, command in (("cat", "cat /workspace/.env | wc -c"), ("sh-c", "sh -c 'cat /workspace/.env' | wc -c"), ("awk", "awk 1 /workspace/.env | wc -c")):
        add(claude_perm(f"claude-perm-deny-read-rule-bash-{variant}", f"Claude Code with a Read(./.env) deny rule: Bash reads the same file with {variant}",
                        [*deny_flags, "--allowedTools=Bash", "--disallowedTools=Read(./.env)"], "FAKE:TOOL Bash " + json.dumps({"command": command, "description": "size of .env"})))

    def codex_perm(case_id: str, title: str, extra: list[str]) -> Case:
        return Case(case_id, title, [8], "codex", [*CODEX_EXEC, *extra, *codex_provider(), *codex_quiet, codex_probe], key_env="FAKE_PROVIDER_KEY", timeout_s=60)

    add(codex_perm("codex-perm-default", "Codex exec with no sandbox flag: the model runs the probe command", []))
    add(codex_perm("codex-perm-read-only", "Codex exec -s read-only: the model runs the probe command", ["-s", "read-only"]))
    add(codex_perm("codex-perm-workspace-write", "Codex exec -s workspace-write: the model runs the probe command", ["-s", "workspace-write"]))
    add(codex_perm("codex-perm-bypass", "Codex exec --dangerously-bypass-approvals-and-sandbox: the model runs the probe command", ["--dangerously-bypass-approvals-and-sandbox"]))

    # ------------------------------------------------------------------ the host tool bridge as hardening target
    bridge_flags = ["--tools=", "--strict-mcp-config", f"--mcp-config={bridge_mcp}", "--allowedTools=mcp__bridge__factory_exec"]
    add(claude_perm("claude-bridge-tools-empty", "Claude Code --tools empty with only the bridge: the model asks for Bash anyway", bridge_flags, bash_probe))
    add(claude_perm("claude-bridge-call", "Claude Code --tools empty with only the bridge: the model calls the bridge tool", bridge_flags, 'FAKE:TOOL mcp__bridge__factory_exec {"argv":["echo","hello"]}'))
    add(claude_perm("claude-bridge-bypass-attempt", "Claude Code --tools empty plus --dangerously-skip-permissions: the model asks for Bash anyway", [*bridge_flags, "--dangerously-skip-permissions"], bash_probe))
    add(claude_perm("claude-bridge-restricted", "Claude Code --restricted with only the bridge: the model asks for Bash", ["--restricted", "--strict-mcp-config", f"--mcp-config={bridge_mcp}", "--allowedTools=mcp__bridge__factory_exec"], bash_probe))
    add(claude_perm("claude-bridge-no-flags", "Claude Code with the bridge added but no tool restriction (control)", ["--strict-mcp-config", f"--mcp-config={bridge_mcp}"], "say hello"))

    codex_bridge_mcp = ["-c", f'mcp_servers.bridge={{url="{bridge_url}", default_tools_approval_mode="approve", enabled_tools=["factory_exec"]}}']
    codex_bridge_mcp_plain = ["-c", f'mcp_servers.bridge={{url="{bridge_url}"}}']
    codex_no_shell = ["--disable", "shell_tool", "--disable", "unified_exec"]
    bridge_call_js = 'FAKE:TOOL exec text(JSON.stringify(await tools.mcp__bridge__factory_exec({argv: ["echo", "hello"]})))'

    def codex_bridge(case_id: str, title: str, extra: list[str], prompt: str, mcp: list[str] | None = None) -> Case:
        return Case(case_id, title, [8], "codex", [*CODEX_EXEC, *extra, *(mcp or codex_bridge_mcp), *codex_provider(), *codex_quiet, prompt], key_env="FAKE_PROVIDER_KEY", timeout_s=60)

    add(codex_bridge("codex-bridge-no-patch-config", "Codex bridge case with include_apply_patch_tool=false added", [*codex_no_shell, "-c", "include_apply_patch_tool=false"], "say hello"))
    add(codex_bridge("codex-bridge-no-patch-feature", "Codex bridge case with the apply_patch_freeform feature disabled", [*codex_no_shell, "--disable", "apply_patch_freeform"], "say hello"))
    add(codex_bridge("codex-bridge-call-unapproved", "Codex bridge tool call without an approval setting for the MCP server", codex_no_shell, bridge_call_js, codex_bridge_mcp_plain))

    add(codex_bridge("codex-bridge-default", "Codex with the bridge added and nothing disabled (control): which tools does the model see", [], "say hello"))
    add(codex_bridge("codex-bridge-shell-off", "Codex with shell_tool and unified_exec disabled and the bridge added: the model asks for exec_command anyway", codex_no_shell, codex_probe))
    add(codex_bridge("codex-bridge-call", "Codex with shell_tool and unified_exec disabled: the model calls the bridge tool", codex_no_shell, bridge_call_js))
    add(codex_bridge("codex-bridge-bypass-attempt", "Codex with shell_tool and unified_exec disabled plus the sandbox bypass flag: the model asks for exec_command", [*codex_no_shell, "--dangerously-bypass-approvals-and-sandbox"], codex_probe))

    # ------------------------------------------------------------------ repository-resident configuration (hostile workspace)
    def claude_hostile(case_id: str, title: str, extra: list[str]) -> Case:
        return Case(case_id, title, [6], "claude", [*CLAUDE_STREAM, *extra, "say hello"], env=claude_env, key_env="ANTHROPIC_API_KEY", ws="hostile", timeout_s=40)

    add(claude_hostile("claude-hostile-default", "Claude Code in a hostile workspace, default flags", []))
    add(claude_hostile("claude-hostile-bare", "Claude Code in a hostile workspace, --bare", ["--bare"]))
    add(claude_hostile("claude-hostile-sources-user", "Claude Code in a hostile workspace, --setting-sources user", ["--setting-sources", "user"]))
    add(claude_hostile("claude-hostile-safe-mode", "Claude Code in a hostile workspace, --safe-mode", ["--safe-mode"]))
    add(claude_hostile("claude-hostile-factory-flags", "Claude Code in a hostile workspace, --bare --setting-sources user --strict-mcp-config", ["--bare", "--setting-sources", "user", "--strict-mcp-config"]))
    for suffix, extra in (("default", []), ("bare", ["--bare"]), ("sources-user", ["--setting-sources", "user"])):
        add(Case(f"claude-docs-{suffix}", f"Claude Code with repository CLAUDE.md and AGENTS.md files only ({suffix})", [6], "claude", [*CLAUDE_STREAM, *extra, "say hello"], env=quiet, key_env="ANTHROPIC_API_KEY", ws="docs"))
    add(Case("codex-docs-default", "Codex with repository CLAUDE.md and AGENTS.md files only, default flags", [6], "codex", [*CODEX_EXEC, *codex_provider(), *codex_quiet, "say hello"], key_env="FAKE_PROVIDER_KEY", ws="docs", timeout_s=40))
    add(Case("codex-docs-no-project-doc", "Codex with repository AGENTS.md and project_doc_max_bytes=0", [6], "codex", [*CODEX_EXEC, *codex_provider(), *codex_quiet, "-c", "project_doc_max_bytes=0", "say hello"], key_env="FAKE_PROVIDER_KEY", ws="docs", timeout_s=40))
    hostile_codex = [*CODEX_EXEC, "-c", f'openai_base_url="{provider_url}/v1"', *codex_quiet]
    add(Case("codex-hostile-default", "Codex in a hostile workspace, default flags", [6], "codex", [*hostile_codex, "say hello"], key_env="CODEX_API_KEY", ws="hostile", timeout_s=40))
    add(Case("codex-hostile-ignore-flags", "Codex in a hostile workspace, --ignore-user-config --ignore-rules", [6], "codex",
             [*hostile_codex, "--ignore-user-config", "--ignore-rules", "say hello"], key_env="CODEX_API_KEY", ws="hostile", timeout_s=40))
    add(Case("codex-hostile-no-project-doc", "Codex in a hostile workspace, project_doc_max_bytes=0", [6], "codex",
             [*hostile_codex, "-c", "project_doc_max_bytes=0", "say hello"], key_env="CODEX_API_KEY", ws="hostile", timeout_s=40))

    return cases
