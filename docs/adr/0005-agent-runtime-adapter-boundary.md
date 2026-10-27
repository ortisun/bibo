# 0005: Drive agents through an AgentRuntime port with probed adapters that run inside the sandbox, behind a model broker

- Status: Accepted for the port, the probing rules and the argument safety rules. **Decided by default, pending human confirmation:** the agent command line tool runs inside the sandbox in Slice 1, and model credentials are API keys with hard spend limits held by a broker. Work package `s0-agent-runtime-spike` must prove the parts marked UNVERIFIED. Revised again on 2026-10-27 by ADR 0014 (see "Revision note (ADR 0014)").
- Date: 2026-10-27
- Deciders: software_architect with the security specialist's recommendation (threat model questions Q1 and Q2). A human confirms.
- Related: [ADR 0003](0003-sandbox-strategy.md), [ADR 0006](0006-spec-kit-boundary.md), [ADR 0009](0009-operating-defaults-pending-confirmation.md), [`agent-manifest` schema](../../schemas/agent-manifest.schema.json), [`secrets-and-credentials.md`](../security/secrets-and-credentials.md)

## Revision note (ADR 0014)

Revised on 2026-10-27 by [ADR 0014](0014-ports-v1-1-claim-protocol-and-port-revision.md): `run` returns a report that survives failure; the final output is bytes that only `OutputValidator::validate_bytes` parses; the router takes the runtimes that already failed and the probe results, so a retry on another runtime is possible; the job token file is written and removed by the sandbox adapter and the secret travels in the spec; spend reaches the broker through a metering seam that the engine does not hold.

## Context and problem statement

The master prompt (sections 1, 2 and 17.3) asks for runtime-neutral agent adapters, starting with the real Claude Code and Codex command line tools where installed and a deterministic fake for tests. Each adapter must be version- and capability-probed, must not assume unsupported switches, and provider and model routing must stay out of the orchestrator.

Two further forces decide the shape. Model-written tool calls must never run as shell on the control-plane host. And a tool that runs in a sandbox with no network cannot reach its model provider, so the design has to say how it does, and with whose credential.

## What we checked

From `--help` of the installed binaries on 2026-10-27, plus the real runs reported by the Spec Kit specialist in [`docs/spec-kit/integration-guide.md`](../spec-kit/integration-guide.md) (section 8) and the security review in [`sandbox-policy.md`](../security/sandbox-policy.md) (section 10). I did not re-run the Spec Kit runs. I made no model call.

| Tool | Flags relevant to us (help text) |
|---|---|
| Claude Code 2.1.311 | `-p/--print`; `--output-format text\|json\|stream-json`; `--input-format`; `--json-schema`; `--max-budget-usd`; `--permission-mode` (acceptEdits, auto, bypassPermissions, manual, dontAsk, plan); `--permission-prompts`; `--allowedTools`, `--disallowedTools`, `--tools` (empty string disables built-in tools); `--mcp-config` with `--strict-mcp-config`; `--settings`, `--setting-sources`; `--no-session-persistence`; `--bare`; `--disable-slash-commands` (disables all skills and commands); `--dangerously-skip-permissions` |
| Codex 0.163.0 (`codex exec`) | `--json`; `--output-schema`; `-o/--output-last-message`; `-s/--sandbox`; `-C/--cd`; `--ephemeral`; `--ignore-user-config`; `--ignore-rules`; `-c key=value`; `--dangerously-bypass-approvals-and-sandbox`; `--dangerously-bypass-hook-trust` |

Findings that shape the design:

- Claude Code 2.1.311 has **no `--max-turns`**. Codex `exec` shows **no budget flag**. Turn and cost control cannot rest on the tools.
- `--bare` makes Anthropic authentication strictly `ANTHROPIC_API_KEY` or an `apiKeyHelper`. OAuth and keychain are never read.
- `claude auth status` reports a claude.ai login and `codex login status` reports a ChatGPT login on this machine. These are **subscription logins**. The factory design cannot broker or meter them. I looked for no API key variables.
- **A command allowlist does not contain an agent.** The Spec Kit specialist observed (guide section 8.1) that with an allowlisted prefix `mkdir`, the chained command `mkdir -p ... && printf '...' > .specify/feature.json && git branch --show-current` ran. Their conclusion, reached independently of the security review, is that the headless tool must run inside the factory sandbox.
- A headless Claude Code route is verified for multi-turn work: `claude -p --input-format stream-json --output-format stream-json --verbose --permission-mode acceptEdits --permission-prompts none --disallowedTools AskUserQuestion --allowedTools ...`, with denied calls reported in `permission_denials`. Codex was verified for one skill only (`codex exec -C <dir> -s workspace-write --json -o <file>`). Both ran on the host with an allowlist, so none of this has run inside the hardened container.
- `policies/security.yaml` section 14 lists required flags for Claude Code that include `--disable-slash-commands`. Spec Kit's skills are invoked as slash commands, so that flag would disable them. The flag set must be per stage (see below).

Not verified: whether either tool starts under the hardened profile and a masked `.git`; whether either accepts a base URL that points at the broker; whether they read the credential from a file or helper; whether `--bare` still resolves project skills; JSON usage and cost field names; whether `--json-schema` and `--output-schema` accept schemas that use `if/then`, `oneOf` and `not`; installing either tool into an image.

## Considered options

1. **Command line adapters that run inside the sandbox, behind a per-job relay and a model broker (security "Model A").** The container is the boundary. The tool never sees a real key.
2. **Command line adapters that run on the host with built-in tools disabled and a factory tool server (security "Model B", the tool bridge).** Smaller blast radius for the process. Needs a bridge, and it is UNVERIFIED that the tools can be limited this way.
3. **Provider APIs called directly with a tool loop written in Rust.** Full control. We would own the loop, retries, caching and every provider's quirks, and the prompt asks for the real tools.

Not evaluated: embedding an agent SDK in Python or TypeScript, which adds a second language runtime to the control plane.

## Decision outcome

Chosen by default: **option 1 for Slice 1. Option 2 is the hardening target** and stays reserved in the schema as `host_tool_bridge`. A human confirms.

### The port

`AgentRuntime` has `identity`, `probe` and `run` (signatures in the [slice plan](../architecture/slice-plan.md)). Adapters are in the `runtime` crate (`ClaudeCodeRuntime`, `CodexRuntime`). `FakeAgentRuntime`, including the scripted adversarial mode FX-ADV, is in `testkit`. An adapter reports what happened. The engine decides whether it counts.

### Where the tool runs

Every agent run happens in the `agent` profile container ([ADR 0003](0003-sandbox-strategy.md)). The manifest and stage contract carry a placement of `sandbox` or `host_tool_bridge`. **There is no value that runs an agent directly on the host.** Policy keeps `host_tool_bridge` off in Slice 1.

### Credentials: API keys behind a broker (default, pending confirmation)

- Real provider keys live only in the **model broker**, which runs in the control plane. In Slice 1 the broker listener runs inside the worker process, in the `egress` crate.
- The container gets one **job token**, bound to tenant, job and stage, delivered as a read-only file on a worker-side tmpfs. A per-job **egress sidecar** on an internal network relays to the broker. The broker checks the token, meters usage against the job ceiling, replaces the credential, forwards only allowed API paths, and revokes the token at the ceiling or when the job ends.
- **Subscription logins cannot be brokered or metered and are not used.** A claude.ai or ChatGPT login stays on the host. Consequently **a real-provider adapter smoke test, and any live end-to-end run with real agents, is BLOCKED until a human supplies API keys with a provider-side spend limit.** On this machine both tools are logged in by subscription only. The slice plan says the same, and no acceptance report may present fake-runtime results as a real-provider result.
- UNVERIFIED and the first job of the spike: that each tool can be pointed at the broker's base URL and read its credential from a file or helper. The spike can test redirection against a labelled fake provider with a dummy key, at no cost, before any real key exists. If a tool cannot be redirected, the fallback in `secrets-and-credentials.md` section 4.4 applies (a dedicated, spend-limited key in the container with a CONNECT-only allowlist), with its residual risk recorded and a human's acceptance.

### Probing

- `probe` runs `--version` and `--help` (for Codex, `exec --help`) and checks each flag the adapter uses. It returns a capability record with one observation per flag and its source. A missing flag means the capability is false. The adapter never guesses.
- Accepted version ranges are policy. An unsupported version makes the stage **BLOCKED**.
- The record is stored and referenced by hash from each attempt. A live smoke test runs only on demand and only with a key. A claim that a real provider works stays unverified until it has passed and its result is in the ledger.

### Argument safety

- Argument builders are pure functions from the run request to an argument vector, built from a closed allow list. **Bypass flags** (`--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--dangerously-bypass-hook-trust`, `--permission-mode bypassPermissions`, `-s danger-full-access`) are emitted **only** when the target is a sandbox whose posture check passed and whose runtime self-check succeeded. For any other target the builder refuses, and a test generates requests to prove it.
- **The flag set is per stage.** `--bare`, `--strict-mcp-config`, `--no-session-persistence` and `--settings` from a factory-generated file apply to every Claude Code run. `--disable-slash-commands` applies to every stage **except** specification, where the Spec Kit skills must resolve. For that stage, skill integrity comes from `specify integration status --json` and the pinned manifest hashes ([ADR 0006](0006-spec-kit-boundary.md)). Whether `--bare` still finds project skills is UNVERIFIED.
- Repository copies of `CLAUDE.md`, `AGENTS.md`, `.claude/settings.json`, `.mcp.json` and `.codex/config.toml` are data. The adapter passes factory-authored instructions explicitly and never honors the repository's copies (negative test NT-INJ-07).

### Prompts, output and budgets

- Untrusted text is never placed in the instruction channel. It goes into a typed data envelope with source, class and hash, and a delimiter collision check runs (policy `untrusted_content.prompt_assembly`, test NT-INJ-02). The `s1-prompt-assembly` work package owns this.
- The engine validates the returned JSON against the full schema. Invalid output fails the attempt with class `INVALID_OUTPUT`. At most two repairs run as new attempts. Unknown fields are rejected.
- The budget control is the broker's token and cost meter and the supervisor's wall clock. The tools' own flags (`--max-budget-usd`) are a second line, because a tool that ignores or miscounts its budget must still stop (NT-BUD-07).
- Provider and model routing is a separate pure `ModelRouter` that reads `policies/model_routing.yaml`. The adapter maps failures to a closed set. The engine may retry on another runtime with the capabilities the stage needs. Job state is in PostgreSQL, so a switch loses nothing.

### Consequences

- Good: the container is the boundary, so command allowlists need not hold; no real key enters the sandbox; spend is capped outside the tool; the fake and the real adapter share one port.
- Good: the host tool bridge stays possible without a schema change.
- Bad: the broker and the sidecar are new components to build, secure and run, and no code exists. They are on the Slice 1 path (`s1-egress-and-broker`) because the default needs them.
- Bad: **Slice 1 cannot run real agents on this machine today.** It has subscription logins only. Until a key is supplied, verified behavior is limited to the fake runtime in test mode and the probe.
- Bad: output parsing depends on third-party formats that change between versions. Pinned ranges, recorded outputs as labelled fixtures and the probe contain this, at the price of upgrade work.
- Bad: a tool that cannot be redirected to the broker forces the key-in-container fallback, which a prompt-injected agent could read.
- Bad: no turn cap on either tool and no Codex cost cap.
- Neutral: subscription logins stay useful for a human working interactively and for the Spec Kit specialist's recorded evidence, which is why that evidence is labelled as host-run.

## Pros and cons of the options

**Inside the sandbox with a broker**: strongest containment of keys and tools, matches the master prompt's sandbox rule. More components, and credentials need API keys.

**Host with a tool bridge**: the tool process is outside the blast radius and works with a subscription login. Needs a bridge, and may not be possible for every tool.

**Direct provider APIs**: strong control and cheap deterministic tests. Rebuilds what the tools already do.

## Confirmation

`s0-agent-runtime-spike` records help text, redirection against a labelled fake provider, startup under the hardened profile with a masked `.git`, and, when a key exists, minimal live calls. It writes an amendment here. `s1-agent-runtime-adapters` then passes the probe, argument-safety, output, failure and cancellation tests, and a live smoke test that reports **BLOCKED**, not PASSED, when no key or binary is present.
