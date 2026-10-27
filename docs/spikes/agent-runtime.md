# Agent runtime spike: how Claude Code and Codex run inside the sandbox behind the broker

- Status: Complete for everything that needs no live provider. Every live-provider and subscription-login item is BLOCKED and listed in section 3.
- Date: 2026-10-27
- Author: software_engineer
- Reviewers: software_architect, security
- Work package: `s0-agent-runtime-spike`
- Tested versions: Claude Code 2.1.311, Codex 0.163.0
- Evidence: [`fixtures/recordings/agent-cli/`](../../fixtures/recordings/agent-cli/README.md). Its README lists the commands that reproduce every claim below.
- Related: [ADR 0003](../adr/0003-sandbox-strategy.md), [ADR 0005](../adr/0005-agent-runtime-adapter-boundary.md), [ADR 0006](../adr/0006-spec-kit-boundary.md), [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md), [sandbox policy](../security/sandbox-policy.md), [secrets and credentials](../security/secrets-and-credentials.md), [Spec Kit integration guide](../spec-kit/integration-guide.md)

This report does not edit any other document. Section 6 lists the edits that other packages and owners must make.

## 1. Summary

ADR 0005 chose to run the agent tool inside the `agent` sandbox, behind a per-job sidecar and a model broker. The spike tested that choice with both real tools, in the real hardened container profile, against a labelled fake model provider. **The choice holds. The design needs the changes in section 6, and three flags named in the policy (`--bare`, `--ignore-user-config` and `--ignore-rules`) do not do what the policy assumes.**

Overall verdict: **GO WITH CHANGES** for option 1 of ADR 0005 (tool inside the sandbox, behind the broker). The fallback in `secrets-and-credentials.md` section 4.4 (a real key inside the container) is **not needed**: both tools can be redirected to a broker, and both can take their credential from a file.

| # | Design assumption | Claude Code | Codex | Section |
|---|---|---|---|---|
| 1 | Install exact versions from official channels into a clean image | GO | GO | 4.1 |
| 2 | Start and run headless under the hardened profile with a masked `.git` | GO | GO WITH CHANGES (home must be writable) | 4.2 |
| 3 | All model traffic can be sent to a broker base URL | GO | GO WITH CHANGES (custom provider, not the environment variable) | 4.3 |
| 4 | With only the broker reachable, the tool needs nothing else | GO WITH CHANGES (one switch) | GO WITH CHANGES (two switches) | 4.4 |
| 5 | The credential can come from a file, not from an environment variable | GO | GO | 4.5 |
| 6 | The policy flags neutralize repository-resident configuration | **NO-GO as written** (`--bare` is not enough) | GO WITH CHANGES (`project_doc_max_bytes=0`) | 4.6 |
| 6 | Skills: four visible in the specification stage, six hidden, none elsewhere | GO WITH CHANGES (not with `--bare`; mount the four in the user skill root) | GO (overlays or `skills.config`) | 4.6 |
| 7 | Turn and budget caps | GO (hidden `--max-turns`) | NO-GO on the tool; the broker and supervisor must cap | 4.7 |
| 7 | Structured output with the factory schemas | **NO-GO** (all 11 rejected) | GO WITH CHANGES (accepted, strict mode unverified at the provider) | 4.7 |
| 7 | Cancellation | GO WITH CHANGES | GO WITH CHANGES | 4.7 |
| 8 | Permission flags as a containment layer | NO-GO (a filter, not a boundary) | NO-GO (the tool's own sandbox cannot start in the container) | 4.8 |
| 9 | Host tool bridge as the hardening target | GO | GO WITH CHANGES (`apply_patch` stays) | 4.9 |

How to read the verdicts. GO means the assumption held as written. GO WITH CHANGES means it holds after the changes in section 6. NO-GO means the assumption failed and section 6 names the replacement.

The five findings that change the design most:

1. **`--bare` is not the neutralizing flag the policy assumes.** In a hostile workspace, `--bare` still honored the `env` block of `.claude/settings.json`, which pointed the model traffic at an attacker host. It also loaded no project skills and no user skills. `--setting-sources user` neutralized hooks, MCP servers, the environment block and `CLAUDE.md` in one flag, but it hides the project skills too, so the specification stage needs its four skills mounted into the user skill root.
2. **Codex ignores `OPENAI_BASE_URL`.** It needs a custom provider entry. Its built-in provider tries a WebSocket first and ignores `OPENAI_API_KEY`.
3. **Neither tool needs the credential in an environment variable.** An environment variable is visible to the shell the model drives. `apiKeyHelper` (Claude Code) and a provider `auth` command (Codex) keep the key out of every variable.
4. **Both tools contact other hosts by default.** One switch (Claude Code) and two switches (Codex) reduce that to the broker alone.
5. **Revoking the job token does not stop the tools quickly.** Claude Code retries a 401 answer up to ten times, with delays that add up to well over a minute. Codex retries five times. The supervisor must kill the container.

## 2. What was run, and how far to trust it

### 2.1 Setup

| Item | Value |
|---|---|
| Engine | Docker 29.5.2 in a dedicated Colima virtual machine (Ubuntu 24.04, kernel 6.8, `runc` 1.3.5, cgroup v2, AppArmor and the builtin seccomp profile active). Recorded in `manifest.json`, key `engine`. |
| Why not Docker Desktop | The shared Docker Desktop daemon had stopped answering to every client I could observe, for about twenty minutes, when the private engine was started. The cause is unknown. A private engine was safer than waiting. Its mounts were limited to the scratch run directory, so no host home directory was reachable. A first run on Docker Desktop, before it stopped, reached the same startup and the same `system/init` event. |
| Images | Alpine 3.24.3 on `linux/arm64`, pinned by digest. One scratch image per tool, built from the official release channels with a checksum check (section 4.1). Not the production sandbox image. |
| Container profile | The `agent` profile of `sandbox-policy.md` section 3.2: uid 10001, read-only root, `--cap-drop ALL`, `no-new-privileges`, `--init`, `--ipc none`, 256 processes, 4 GiB memory, 2 CPUs, tmpfs for `/tmp` (512 MiB, `noexec`) and for the home directory (64 MiB, `noexec`), the workspace as a bind mount with `/dev/null` over `.git`, an output directory, and the fake key as a read-only file at `/run/secrets/job_token`. |
| Network | A Docker network created with `--internal`. It holds the fake provider, the sinkhole and the fake bridge. The tool container has no route out. |
| Fake provider | `fake/fake_provider.py`. Speaks the Anthropic Messages and OpenAI Responses streaming formats. Answers a canned text or one scripted tool call chosen by the prompt. Labelled "fidelity: fake". |
| Sinkhole | `fake/sinkhole.py`. Answers every DNS question with its own address, accepts TCP on ports 80 and 443 and logs the TLS server name. It sees names only. A tool that connects to a hard-coded address finds no route and leaves no trace. |
| Credential | A fake key generated at run time (marker prefix `sfjt_FAKE`), never committed, deleted at the end. No host environment variable, no `~/.claude`, no `~/.codex`, no keychain reached any container. |
| Model calls | None. Tokens, costs and answers in the recordings come from the fake provider. |

### 2.2 Limits of the evidence

- One machine, one architecture (arm64), one engine, one run of each case plus earlier exploratory runs. Durations and memory figures are single observations.
- The fake provider speaks the protocol that the tools sent in these runs. A real provider can send fields, headers and stream events that the fake does not. Nothing here shows that a real provider accepts the requests the tools build.
- The tools were run inside the container. The host tool bridge (Model B) was tested only for tool availability, not as a bridge.
- No skill ran to completion. The fake provider returns canned text, so the tests show which skills are visible and whether their text reaches the first request, not what a skill does.
- Static checks on the binaries (`strings`) were used to find names of settings and environment variables. Every such name used in a claim was then confirmed by a recorded run. A name that was only seen in `strings` is marked UNVERIFIED.

## 3. Verified, unverified and blocked

| Status | Items |
|---|---|
| VERIFIED (recorded run) | Install by checksum from two official channels each. Both tools start, run a headless turn and run tool calls under the hardened profile. Base URL redirection of every model request for both tools. Eight ways to deliver a credential (section 4.5). The hosts each tool contacts by default, and the switches that stop them. Skill listing, overlays, `--disable-slash-commands`, per-skill deny rule, `skills.config`. Hostile repository configuration with and without each flag. Output formats, result fields, exit codes, turn and budget caps, retry behavior, cancellation. What the permission flags allow and refuse. Tool availability under the bridge flags. |
| UNVERIFIED | Behavior on `linux/amd64`. Signature checks of the vendor manifests (files exist, I did not verify them). Codex in a project with trust granted. Interactive-mode requests (the spike used headless mode only). Whether a real provider accepts Codex's `strict` output schema. Whether the `agent` profile behaves the same on a Linux host without a virtual machine layer (the bind mount ownership rules of `sandbox-policy.md` section 13 still apply). Whether any behavior changes with a real model, which can emit thinking blocks, parallel tool calls and longer streams. |
| BLOCKED | A live call to Anthropic or OpenAI (no API key with a spend limit exists). A subscription login of either tool (not used; `secrets-and-credentials.md` section 4.1). Real usage and cost figures. The refusal behavior of the real providers for 401, 402, 403, 429 and 529 answers. The host tool bridge as a running component (no bridge exists). A human must provide the items in section 8 to unblock these. |

## 4. Findings by question

Each finding has the evidence (recording ids, found under `fixtures/recordings/agent-cli/runs/`), a verdict and the consequence.

### 4.1 Install

**Finding.** Both tools install into a clean image at the exact pinned version, with a checksum that can be verified in the build.

| Tool | Official channel | Integrity data | Result |
|---|---|---|---|
| Claude Code 2.1.311 | `https://downloads.claude.ai/claude-code-releases/2.1.311/<platform>/claude`, a single executable file. | `manifest.json` lists a SHA-256 per platform (`linux-arm64-musl`: `172150e3...09b9`). A `manifest.json.sig` file exists. | The Dockerfile checks the SHA-256 and the build stops on a mismatch. Inside the container `sha256sum` printed the same value (recording `claude-posture`). |
| Claude Code 2.1.311 | npm package `@anthropic-ai/claude-code` plus the platform package `@anthropic-ai/claude-code-linux-arm64-musl`. | The registry lists a SHA-512 `dist.integrity` per package. | I downloaded the platform package outside the container. Its binary has the same SHA-256 as the native channel, so both channels deliver identical bytes. |
| Codex 0.163.0 | npm package `@openai/codex`, platform package `@openai/codex@0.163.0-linux-arm64`. | `dist.integrity` SHA-512 (`IH2/R+4O...`). | The Dockerfile checks it. The tarball was 154.7 MB. |
| Codex 0.163.0 | GitHub release `rust-v0.163.0`. | `codex-package_SHA256SUMS`, one `.sigstore` file per asset and a digest on every asset. | Not used for the image. UNVERIFIED: signature verification. |

**Runtime needed.** None. The npm launcher for Codex needs Node, but the native binary does not, and the image holds only the native files. Both tools started and finished a turn on a bare Alpine image with no `bash`, no `libgcc`, no `libstdc++` and no CA certificates (recordings `claude-bare-image-turn`, `codex-bare-image-turn`). `ldd` shows that Claude Code links only against musl (`claude-posture`). The Claude Code `Bash` tool and the Spec Kit helper scripts do need `bash`, so the production image should include it.

**Size** (recordings `claude-image-facts`, `codex-image-facts`, measured once):

| Image | Layers | Total |
|---|---|---|
| Claude Code | Alpine 9.3 MB, packages 9.0 MB, binary 285.8 MB | about 304 MB |
| Codex | Alpine 9.3 MB, packages 6.0 MB, tool files 330 MB (`codex` 258 MB, `codex-code-mode-host` 67 MB, `rg` 4.5 MB, `bwrap` 0.5 MB) | about 345 MB |

The Docker engine reported larger numbers for both images because of its image store. The layer sizes are the ones that matter for disk planning.

**Verdict: GO.** Pin by checksum, not by tag. Build each image in a network-enabled build step and run it with no network.

**Consequences.** `s1-sandbox-images` must pin the version and the SHA, and must add `bash`. It may choose one image for both tools or one image per tool. Combined, the two tools weigh about 650 MB.

### 4.2 Start under the hardened profile

**Finding.** Both tools start, run a headless turn and run a tool call under the full profile, with `.git` masked by `/dev/null`.

| Check | Claude Code | Codex | Recordings |
|---|---|---|---|
| `--version` with no network | exit 0 in about 0.1 s | exit 0 in about 0.2 s | `claude-version`, `codex-version` |
| Headless turn against the fake provider | exit 0 in about 0.4 s | exit 0 in about 0.3 s | `claude-turn-env`, `codex-turn-custom-provider` |
| Peak memory, peak processes | 119 to 135 MiB, 13 to 14 | 22 to 26 MiB, 32 to 40 | `footprint.txt` of those runs |
| Home directory read-only (no tmpfs) | works, writes nothing | **fails**: "failed to initialize in-process app-server client: Read-only file system", exit 1 | `claude-ro-home`, `codex-ro-home` |
| `noexec` on the home tmpfs | works | works | all runs |
| Masked `.git` | The prompt says "Is a git repository: false"; `.git` is a character device; no `git` binary in the image. | Runs with or without `--skip-git-repo-check`. | `claude-git-masked`, `codex-git-check-default` |
| Seccomp and AppArmor | Seccomp mode 2, `NoNewPrivs` 1, all capability sets zero, AppArmor `docker-default` enforced. Both tools ran under all of them. | same | `claude-posture` |

**What each tool writes** (from `footprint.txt`, which lists every file left in the writable mounts):

- Claude Code: `~/.claude.json` (about 0.7 to 0.9 KB), `~/.claude/backups/`, `~/.claude/plugins/store/`, and `~/.claude/telemetry/1p_failed_events.*.json` (175 to 225 KB, 115 events, written when its upload to `api.anthropic.com` fails; absent with the switch in section 4.4). In `/tmp`: `claude-<uid>/fswatch-probe-*/probe` and a socket `/tmp/cc-socks/<n>.sock` while it runs. With `--no-session-persistence` it writes no transcript.
- Codex: everything under `~/.codex`, 57 to 60 files and 0.75 to 2.9 MB per run: four to five SQLite databases with their write-ahead logs (`state_5`, `logs_2`, `goals_1`, `memories_1`, `queue_1`), `installation_id`, `.sandbox_migration`, `.tmp/plugins.sync.lock`, and a fresh copy of its bundled "system" skills under `skills/.system/` (about 250 KB, including Python and Node scripts). It also prints "WARNING: proceeding, even though we could not create PATH aliases" when the home is read-only.

The 64 MiB home tmpfs and the 512 MiB `/tmp` of the profile are ample. **Nothing needs to be pre-seeded.** Both tools built their own state in an empty home. Claude Code's first-run onboarding did not block `-p`, and Codex created its databases and skills without help.

**What blocks nothing, but should be known.**

- Codex's own sandbox cannot start under the default seccomp profile. Every command in `-s read-only`, `-s workspace-write` and the default mode failed with "bwrap: No permissions to create a new namespace" (section 4.8). The policy already expects this.
- Claude Code with `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` refuses to start without `bubblewrap` and prints a stack dump (`claude-toolenv-scrub`). Do not set it.

**Verdict: GO for Claude Code. GO WITH CHANGES for Codex** (mount a writable home, and plan for its sandbox being unusable).

**Consequences.** `s1-sandbox-adapter` must give every `agent` container a writable, `noexec` tmpfs home for both tools, and the adapter must set `HOME`. A bind mount placed inside the tmpfs home creates its parent directories owned by root; Codex then fails with "Permission denied" (`codex-skills-user-root`), so do not mount anything below `~/.codex`. The posture self-check of `sandbox-policy.md` section 9 is unchanged.

### 4.3 Redirecting model traffic to a broker

**Finding.** Both tools can be pointed at a plain-HTTP broker address inside the job network. Claude Code uses an environment variable or a settings value. Codex needs a custom model provider.

| | Claude Code | Codex |
|---|---|---|
| Works | `ANTHROPIC_BASE_URL` in the environment (`claude-turn-env`) or in a `--settings` JSON `env` block (`claude-baseurl-settings`). | `-c model_provider="x"` plus `-c model_providers.x={name=..., base_url="http://host:port/v1", wire_api="responses", supports_websockets=false, ...}` (`codex-turn-custom-provider`). `-c openai_base_url=...` also redirects the built-in provider (`codex-baseurl-builtin-codex-key`). |
| Does not work | n/a | `OPENAI_BASE_URL` is ignored: the tool went to `api.openai.com` (`codex-baseurl-env-ignored`). |
| Route the broker must serve | `POST /v1/messages?beta=true`, streaming server-sent events. | `POST /v1/responses`, streaming server-sent events. |
| Extra routes | none in headless mode | `GET /v1/models?client_version=0.163.0`, twice at start, when the credential comes from a provider `auth` command, and four times when the plugin features are on (`codex-auth-command`, `codex-auth-command-no-discovery`). It was not sent with `env_key` and the switches of section 4.4. The built-in provider also opens `GET /v1/responses` with `Upgrade: websocket` first and falls back after five failed tries, about 6 s. A custom provider with `supports_websockets=false` skips this. |
| HTTP versions and schemes | `http://` accepted, HTTP/1.1, chunked responses. | same |

**The request each tool sends** (recordings `provider-requests.jsonl`, long strings cut to a prefix plus length and SHA-256):

| | Claude Code | Codex |
|---|---|---|
| Credential header | `x-api-key` (key from the environment, helper or file descriptor) or `Authorization: Bearer` (`ANTHROPIC_AUTH_TOKEN`) | `Authorization: Bearer` |
| Other headers the broker should expect | `anthropic-version: 2023-06-01`, a long `anthropic-beta` list, `x-app: cli`, `x-claude-code-session-id`, `x-stainless-retry-count`, `x-stainless-timeout: 600`, `user-agent: claude-cli/2.1.311 (external, sdk-cli)`, `accept: application/json` | `originator: codex_exec`, `session-id`, `thread-id`, `x-client-request-id`, `x-codex-turn-metadata`, `x-codex-beta-features`, `x-openai-internal-codex-responses-lite: true`, `accept: text/event-stream` |
| Body | JSON, `stream: true`, `max_tokens: 128000`, `thinking`, `output_config`, `context_management`, `metadata.user_id` (a JSON string with a device identifier and the session), `system` blocks, `messages`, `tools`. First request 46 KB. | JSON, `stream: true`, `store: false`, `model`, `input` (with the tool list inside an `additional_tools` item), `reasoning`, `text`, `include`, `prompt_cache_key`, `client_metadata`. First request 56 to 68 KB. |
| Default model | `claude-opus-5-5` | `gpt-6.1-sol` |
| Retry marker | none: the seven retries of `claude-auth-wrong` all carried `x-stainless-retry-count: 0` | none seen |

**Two points for the broker.** The default model of each tool is the expensive one. The adapter must always pass `--model` (Claude Code) or `-m` (Codex), and the broker should still check the model against the job token's allowed list. The `metadata.user_id` of Claude Code and the `x-codex-turn-metadata` header carry per-install and per-session identifiers; the broker should not log them.

**Verdict: GO for Claude Code. GO WITH CHANGES for Codex.** Because both can be redirected, **the fallback in `secrets-and-credentials.md` section 4.4 is not needed.**

**Consequences.** The broker and sidecar specification must name the two routes above, accept `http`, stream server-sent events, forward the `anthropic-beta` header unchanged and answer or refuse the Codex WebSocket upgrade quickly (a plain 404 works, but the built-in provider wastes 6 s on it). The adapter for Codex must always build the custom provider entry.

### 4.4 Other hosts at startup, and how to switch them off

**Finding.** With only the broker reachable, each tool still tries to reach other hosts unless told not to. The attempts fail fast on the internal network, so startup is not slowed much, but they are traffic the egress rules would have to refuse and log.

| Case | Hosts the tool tried (DNS name or TLS server name) | Recording |
|---|---|---|
| Claude Code, default | `api.anthropic.com` (about three TLS attempts per run; telemetry events and a registry fetch) | `claude-turn-env` |
| Claude Code, `--bare` | `api.anthropic.com`. **`--bare` does not stop it.** | `claude-bare-turn` |
| Claude Code, `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `DISABLE_AUTOUPDATER` | `api.anthropic.com`. **These three do not stop it.** | `claude-egress-disable-telemetry` |
| Claude Code, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | none | `claude-egress-minimal` |
| Codex, default | `api.github.com`, `chatgpt.com`, `ab.chatgpt.com` | `codex-turn-custom-provider` |
| Codex, `--disable plugins` only | `ab.chatgpt.com` | `codex-egress-only-plugins` |
| Codex, `-c analytics.enabled=false` only | `api.github.com`, `chatgpt.com` | `codex-egress-only-analytics` |
| Codex, both | none | `codex-egress-minimal` |

The other single switches tried for Codex (`apps`, `remote_plugin`, `tool_suggest`, `image_generation`, `plugin_sharing`, `feedback.enabled`, `check_for_update_on_startup`) changed nothing on their own (`codex-egress-only-*`). The recorded minimal set still includes them, which is harmless.

What the traffic is: the telemetry file of Claude Code lists the names of the fields it would send, among them a device identifier, platform, kernel, shell, terminal, installed package managers, process data and a session identifier (`claude-telemetry-file-keys`, names only). With the switch off, that file is not written.

**Limits.** A tool that connects to a hard-coded IP address leaves no trace in the sinkhole. The internal network blocks it either way.

**Unreachable provider.** Claude Code gives up after its retries with exit 1 and the message "Can't reach the API server" (`claude-unreachable`, 17 s with `CLAUDE_CODE_MAX_RETRIES=2`; the default is ten retries). Codex **never gives up by default** ("Reconnecting... waiting for network", killed by the harness after 60 s in `codex-unreachable`) because the `unbounded_connection_retries` feature is on. With `--disable unbounded_connection_retries` it failed after about 21 s with exit 1 (`codex-unreachable-bounded`).

**Verdict: GO WITH CHANGES.**

**Consequences.** The argument builders must always set `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` for Claude Code, and `--disable plugins`, `-c analytics.enabled=false` and `--disable unbounded_connection_retries` for Codex. The probe must record each. The egress sidecar must still log and refuse everything except the broker, because a future version can add a host.

### 4.5 Authentication

**Finding.** Both tools accept the credential from a file, so the job token can stay out of every environment variable. This matters: an environment variable is visible to the shell the model drives.

| Way to give the credential | Claude Code | Codex | Recordings |
|---|---|---|---|
| Environment variable | `ANTHROPIC_API_KEY` works (`x-api-key`). `ANTHROPIC_AUTH_TOKEN` works (`Authorization: Bearer`). | A provider `env_key` works. `CODEX_API_KEY` works for the built-in provider. **`OPENAI_API_KEY` is not read by `codex exec`.** | `claude-turn-env`, `claude-auth-token-env`, `codex-turn-custom-provider`, `codex-baseurl-builtin-codex-key`, `codex-baseurl-builtin-openai-key` |
| Helper command that reads a file | `--settings '{"apiKeyHelper":"cat /run/secrets/job_token"}'` works, with and without `--bare`. | `auth={command="cat", args=["/run/secrets/job_token"]}` in the provider entry works. | `claude-auth-helper`, `claude-auth-helper-bare`, `codex-auth-command` |
| File descriptor | `CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR=3` with `exec 3</run/secrets/job_token` works. | n/a | `claude-auth-fd` |
| Stored login file | n/a | `codex login --with-api-key` writes `~/.codex/auth.json` and the next run uses it. | `codex-auth-json` |
| No credential | The turn fails at once: "Not logged in", exit 1, `is_error` true. No request is sent. | "Missing environment variable", exit 1. No request is sent. | `claude-auth-none`, `codex-auth-none` |
| Wrong credential | Retried, up to ten times (seven tries in the 40 s the harness allowed). | Retried five times (about 6.5 s), then fails with exit 1. | `claude-auth-wrong`, `codex-auth-wrong` |

**What the model's shell can see** (the probe counted variables and read the parent's `/proc/<pid>/environ`, `claude-toolenv-*`, `codex-toolenv-*`):

| Credential delivered by | Variable visible to the model's shell | Parent environment readable |
|---|---|---|
| Environment variable (both tools) | yes | yes |
| `apiKeyHelper` (Claude Code), `auth.command` (Codex) | no | no |

Neither tool strips the credential from the environment of the commands it runs. `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` would, but it needs `bubblewrap` and crashes the tool in this container (section 4.2).

The job token file itself stays readable by the model: `cat /run/secrets/job_token` works from a tool call. That is by design in `secrets-and-credentials.md` section 4.2, and acceptable because the token only works at the broker, for one job, with a cap.

The key never appeared in anything a tool printed. The harness replaces the key with the marker `<fake-key>` before it writes a file, and the marker appears only in the recorded `docker run` command lines (`case.json`), never in a `stdout.txt`, `stderr.txt` or `footprint.txt`, including in the failing runs. The provider log removes the credential header and records only whether it matched.

**Verdict: GO.**

**Consequences.** The adapters must deliver the job token with `apiKeyHelper` (Claude Code) and `auth.command` (Codex), never as an environment variable. The policy line "an environment variable is a recorded exception" can become "an environment variable is forbidden". The file descriptor route is an alternative for Claude Code that avoids a second process.

### 4.6 Skills, slash commands and repository-resident configuration

#### Claude Code skills (Spec Kit project, real skill layout from `specify init --integration claude`)

| Setup | Spec Kit skills listed | Other skills | Recording |
|---|---|---|---|
| Default | all ten | 16 bundled | `claude-skills-baseline` |
| `--bare` | **none** | 16 bundled | `claude-skills-bare` |
| `--setting-sources user` (and `--strict-mcp-config`) | **none** | 16 bundled | `claude-skills-sources-user` |
| `--disable-slash-commands` | none | none; no slash commands at all | `claude-skills-disabled` |
| Six read-only empty overlays over the denied project skill directories | exactly four (checklist, clarify, constitution, specify) | 16 bundled | `claude-skills-overlay-spec-stage` |
| Overlay over `.claude/skills` and `.claude/commands` | none | 16 bundled | `claude-skills-overlay-all` |
| `--setting-sources user` with the four pinned skills mounted read-only in the user skill root (`~/.claude/skills/speckit-<name>`) | **exactly four, same names** | 16 bundled | `claude-skills-user-root` |
| `--bare` with the same four mounts | none | 16 bundled | `claude-skills-user-root-bare` |
| `--bare` plus a factory plugin directory with the four skills | four, named `speckit-factory:speckit-<name>` | 16 bundled | `claude-skills-bare-plugin` |
| `CLAUDE_CODE_DISABLE_BUNDLED_SKILLS=1` | ten | 2 | `claude-skills-no-bundled` |

- **`--bare` resolves neither project skills nor user skills.** The help text says "Skills still resolve via /skill-name"; in 2.1.311 that covers bundled skills and a `--plugin-dir` only. The policy line `required_flags: [--bare, ...]` for every run cannot hold for the specification stage.
- **`--setting-sources user` also drops the project skills**, because the project skill root belongs to the project source. The other source choice, `project,local` (the route used in the Spec Kit integration guide), brings the repository's own settings back, and those ran a hostile hook (next subsection). It is safe only in a repository the factory team wrote.
- **The way to give the specification stage exactly four skills is the user skill root.** The supervisor mounts the four pinned, hash-checked skill directories read-only at `~/.claude/skills/speckit-<name>`. With `--setting-sources user` the model sees exactly four skills under their normal names, and a prompt starting with `/speckit-specify` expands (`claude-skills-user-root-slash`). Repository skill directories are never read. In a hostile Spec Kit workspace this produced no hostile effect (`claude-factory-profile-spec`). The overlays also work as designed and are the right tool when project skills must stay visible (`claude-skills-slash-overlay-denied`, `claude-skills-tool-overlay`).
- **A mount inside the tmpfs home creates its parent directories as root.** Claude Code tolerates that (it simply cannot write below `~/.claude`). Codex does not: bind-mounting skills into `~/.codex/skills` made it exit with "Permission denied" (`codex-skills-user-root`).
- **The bundled skills are not repository content.** A test that "the visible set equals the four ids" must filter to the `speckit-` names, or set `CLAUDE_CODE_DISABLE_BUNDLED_SKILLS=1`.
- **Single-shot invocation works.** `claude -p "/speckit-specify <text>"` expands the skill body into the first request (marker "Check for extension hooks" present in `claude-skills-slash-direct`). This settles an unverified item of the integration guide at the protocol level. With `--disable-slash-commands` the same text is not expanded (`claude-skills-slash-disabled`).
- **Per-skill permission rule.** `--disallowedTools=Skill(speckit-plan)` blocks the model's `Skill` tool call ("Skill execution blocked by permission rules", listed in `permission_denials`; `claude-skills-tool-rule-denied`). It does **not** block a prompt that starts with `/speckit-plan` (`claude-skills-slash-rule-denied`). The adapter writes the prompt, so that path is under its control. Use the rule as a second layer.
- **Variadic options swallow the prompt.** `--allowedTools`, `--disallowedTools`, `--tools` and `--mcp-config` take a list. `claude -p --disallowedTools Skill(x) "prompt"` fails with "Input must be provided". Write them as `--disallowedTools=...`.

#### Codex skills

| Setup | Spec Kit skills listed | Bundled skills | Recording |
|---|---|---|---|
| Default | ten | 4 (`imagegen`, `openai-docs`, `skill-creator`, `skill-installer`) | `codex-skills-baseline` |
| Overlays over the six denied directories | four | 4 | `codex-skills-overlay-spec-stage` |
| Overlay over `.agents/skills` | none | 4 | `codex-skills-overlay-all` |
| `-c skills.config=[{path="...SKILL.md", enabled=false}, ...]` | the ten minus the disabled paths | 4 | `codex-skills-config-disable` |
| `-c skills.bundled.enabled=false` | ten | none | `codex-skills-bundled-off` |

So **Codex can hide skills**, by overlay, by a per-path setting, and the bundled ones by a switch. `codex debug prompt-input` lists them with no model call, which gives the adapter a free check. The integration guide's "Codex: unverified" can be updated. For the specification stage use the six overlays on `.agents/skills`, plus `skills.bundled.enabled=false`. A prompt that starts with `$speckit-specify` expands the skill body (`codex-factory-profile-spec`).

#### Repository-resident configuration (a hostile workspace)

The hostile workspace holds a `.claude/settings.json` with a `SessionStart` hook, an `env` block that sets `ANTHROPIC_BASE_URL` to an attacker host, a `.mcp.json` server, `CLAUDE.md`, `AGENTS.md` and a `.codex/config.toml` that names an attacker provider. Outcomes:

| Claude Code flags | Hook ran | MCP server ran | Traffic sent to attacker host | `CLAUDE.md` in the prompt | Recording |
|---|---|---|---|---|---|
| none | **yes** | **yes** | **yes** | n/a (no request reached the fake provider) | `claude-hostile-default` |
| `--setting-sources project,local` | **yes** | **yes** | **yes** | n/a | `claude-hostile-sources-project-local` |
| `--bare` | no | no | **yes** | no | `claude-hostile-bare`, `claude-docs-bare` |
| `--safe-mode` | no | no | **yes** | not tested | `claude-hostile-safe-mode` |
| `--setting-sources user` | no | no | no | no | `claude-hostile-sources-user`, `claude-docs-sources-user` |
| `--bare --setting-sources user --strict-mcp-config` | no | no | no | no | `claude-hostile-factory-flags` |

| Codex flags | Attacker provider used | `AGENTS.md` in the prompt | Recording |
|---|---|---|---|
| default | no (project `.codex/config.toml` ignored in an untrusted project) | **yes** | `codex-hostile-default`, `codex-docs-default` |
| `--ignore-user-config --ignore-rules` | no | **yes** | `codex-hostile-ignore-flags` |
| `-c project_doc_max_bytes=0` | no | no | `codex-hostile-no-project-doc`, `codex-docs-no-project-doc` |

In `-p` mode the trust dialog is skipped (stated in the help text), so Claude Code ran the repository's hook and MCP command without asking. This is the main reason the policy flags matter.

**Verdict: Claude Code NO-GO as written** (the policy's `--bare` does not neutralize the `env` block; `--setting-sources user` does). **Skills: GO WITH CHANGES** for Claude Code (user skill root, not `--bare`, not project skills), GO for Codex. **Codex configuration: GO WITH CHANGES** (add `project_doc_max_bytes=0`).

**Consequences.** Every Claude Code run uses `--setting-sources user` and `--strict-mcp-config`. The non-specification stages add `--disable-slash-commands` (`claude-factory-profile`: tool ran as uid 10001, hostile workspace had no effect, nothing left the job network). The specification stage omits it and mounts the four pinned skills in the user skill root (`claude-factory-profile-spec`). Codex uses the flags listed in section 6.1 (`codex-factory-profile`, `codex-factory-profile-spec`). The negative test NT-INJ-07 can now be written against the CLI: marker files absent, no connection to the overridden host, no marker text in the first request.

### 4.7 The headless contract

**Output formats.**

| | Claude Code | Codex |
|---|---|---|
| Plain | `-p` prints the final text (`claude-fmt-text`). | `codex exec` prints events in human form to standard error and the final message to standard output (`codex-fmt-text`). |
| One document | `--output-format json` prints one result object (`claude-fmt-json`). | `-o <file>` writes the last message (`codex-last-message`). |
| Event stream | `--output-format stream-json --verbose`: `system/init`, `assistant`, `user`, `result` (`claude-turn-env`). `--include-partial-messages` adds `stream_event` records (`claude-fmt-stream-partial`). `--input-format stream-json` accepts user messages on standard input (`claude-stdin-stream-json`). | `--json`: `thread.started`, `turn.started`, `item.started`, `item.completed`, `turn.completed`, `turn.failed`, `error` (`codex-turn-custom-provider`). |

**How tool use is reported.** Claude Code puts `tool_use` blocks in `assistant` events and `tool_result` blocks in `user` events, and lists refusals in `result.permission_denials` (tool name, input, id). Codex reports `command_execution` items (command wrapped as `/bin/sh -lc '...'`, `aggregated_output`, `exit_code`, `status`) and `mcp_tool_call` items (`server`, `tool`, `arguments`, `error`).

**Usage and cost.** The fake provider sent 1234 input, 56 output, 7 cache-write and 89 cache-read tokens. Claude Code reported them as `usage.input_tokens`, `output_tokens`, `cache_creation_input_tokens` and `cache_read_input_tokens`, and per model in `modelUsage`. Its `total_cost_usd` is computed in the tool from a built-in price list (`costBasis: "list"`), so it means nothing behind a broker. Codex reported `input_tokens`, `cached_input_tokens`, `cache_write_input_tokens`, `output_tokens`, `reasoning_output_tokens` and no cost. Usage adds up across requests of one run (`claude-tool-turns`, `codex-tool-turns`). The broker's own meter is the source of truth.

**Result fields and exit codes (Claude Code).**

| Situation | Exit code | `result` event | Recording |
|---|---|---|---|
| Success | 0 | `is_error: false`, `terminal_reason: "completed"` | `claude-turn-env` |
| No credential | 1 | `is_error: true`, `terminal_reason: "api_error"`, **`subtype: "success"`** | `claude-auth-none` |
| Provider error 500 or 529 | 1 | same, with `api_error_status` set | `claude-http-500`, `claude-http-529` |
| `--max-turns` or `CLAUDE_CODE_MAX_TURNS` reached | 1 | `subtype: "error_max_turns"`, `terminal_reason: "max_turns"` | `claude-max-turns-flag`, `claude-max-turns-env` |
| `--max-budget-usd` reached | 1 | `subtype: "error_max_budget_usd"`, `terminal_reason: "budget_exhausted"` | `claude-max-budget` |
| SIGINT | **0** | `subtype: "error_during_execution"`, `is_error: true`, `terminal_reason: "aborted_streaming"` | `claude-cancel-int` |
| SIGTERM | 143 | **no result event** | `claude-cancel-term` |

The adapter must read `is_error` and `terminal_reason`, not `subtype` and not the exit code alone.

**Codex.** Exit 0 and a `turn.completed` event for success. Exit 1 and `turn.failed` for authentication, rate limit and outage. SIGTERM gives exit 143 and no terminal event (`codex-cancel-term`). SIGINT gave exit 1 and no terminal event; it took between 0.1 and 2.9 seconds after the signal in two runs (`codex-cancel-int`).

**Turn limit, budget and counting requests.**

- **Claude Code has a hidden `--max-turns <n>` flag and a `CLAUDE_CODE_MAX_TURNS` variable.** They do not appear in `--help`. Both worked: `--max-turns 2` against a model that never stopped calling tools sent exactly two model requests, then ended with `error_max_turns`. ADR 0005 says "no `--max-turns`"; that is wrong for 2.1.311. A hidden flag can vanish, so the probe must test it by behavior.
- `--max-budget-usd 0.01` stopped after the second request, which crossed the limit by one request. The tool's budget uses its own price list, so it is only a second line of defense.
- **Codex has no turn cap and no budget flag.** Against a model that never stops calling tools, Codex ran until the broker cut it (`codex-loop-no-cap`: nine tool calls, then 401).
- **Counting at the broker.** One model request is one `POST /v1/messages?beta=true` (Claude Code) or one `POST /v1/responses` (Codex). A turn with one tool call is two requests for both tools. `GET /v1/models` and the WebSocket probe are not model requests. Retries are new requests, and no header tells them apart from first tries. A broker that counts every POST caps the work correctly and counts retries as spend, which matches NT-BUD-08.

**What the tools do when the broker refuses.**

| Answer | Claude Code | Codex |
|---|---|---|
| 401 (revoked token) | Retries up to ten times (`max_retries: 10` in the event) with growing delays of 0.6 s to 37 s. Seven tries happened in the first 36 s and the harness stopped the run at 40 s, so the full sequence takes well over a minute (`claude-auth-wrong`, `claude-loop-revoked`). | Six requests in about 6.5 s, then `turn.failed`, exit 1 (`codex-auth-wrong`, `codex-loop-no-cap`). |
| 402 | **Stops at once**: one request, exit 1, `api_error_status: 402` (`claude-http-402`). | Six requests in about 6.5 s, then fails (`codex-http-402`). |
| 403 | **Stops at once**: one request, exit 1 (`claude-http-403`). | Six requests in about 6.5 s, then fails (`codex-http-403`). |
| 400 | Six requests in under a second, then fails (`claude-http-400`). | **Stops at once**: one request (`codex-http-400`). |
| 429 | Retries with backoff; six requests and still retrying at 25 s (`claude-http-429`). | Six requests in about 5 s, then fails (`codex-http-429`). |
| 500, 529 | With `CLAUDE_CODE_MAX_RETRIES=1`: two requests, then fails (`claude-http-500`, `claude-http-529`). The default is ten retries. | **Thirty requests** in about 30 s (five reconnects of six requests each), then fails (`codex-http-500`). |

Answering 402 ends a Claude Code run immediately and a Codex run in about six seconds. No single status ends both at once. A Codex outage multiplies the load on the provider by 30.

Revoking the job token therefore ends the budget but not the process. **The supervisor must kill the container when the broker revokes the token or the deadline passes**, as `sandbox-policy.md` already says for the wall clock.

**Structured output with the real schemas.**

- **Claude Code `--json-schema` rejects all eleven factory schemas as they are** ("no schema with key or ref https://json-schema.org/draft/2020-12/schema"). Removing the `$schema` key is not enough: eight schemas still fail in the tool's strict validator (`dependentSchemas` in the gate report, `prefixItems` in the project manifest, and "missing type" errors inside `if` and `then` branches in the others). Two schemas pass without their `$schema` key (`domain-capability-profile`, `domain-event`). Recordings `claude-struct-*` and `claude-schema-matrix`.
- **Codex `--output-schema` accepts all eleven** and forwards the file unchanged as `text.format` with `type: "json_schema"` and **`strict: true`** (`codex-schema-matrix`, `provider-requests.jsonl` of `codex-struct-valid`). The schemas use `allOf`, `if`, `then`, `not`, `oneOf`, `$ref` and optional properties. I expect OpenAI's strict mode to reject several of these, but I did not check the provider's current documentation and no key exists to test it, so whether the real provider accepts them is BLOCKED. Codex does not check the model's answer: an answer that breaks the schema still ended with exit 0 (`codex-struct-invalid`).
- Therefore: **the engine's own validation, already required by ADR 0005, is the control.** The CLI flags are optional hints and must not be built from the factory schemas without a reduced per-role output schema.

**Standard output and standard error that a redactor must handle.** The run-time key never appeared in either stream, including in 401 error messages. What does appear: the full file content that a tool read (a Read of `.env` printed it in the `tool_result`, `claude-perm-deny-read-rule-slash`); the working directory, session identifiers and memory path in the `init` event; host and port of the broker in error text; for Codex a stderr line "Reading additional input from stdin..." and, when a WebSocket fails, `ERROR codex_api::endpoint::responses_websocket` lines; for Claude Code a source-code dump to standard error when it crashes at startup (`claude-toolenv-scrub`). Codex reads standard input when it is not a terminal and appends it to the prompt, so the supervisor must start it with standard input closed or redirected from `/dev/null` (the harness did; a held-open pipe is UNVERIFIED).

**Cancellation.** SIGTERM reached the tool through `--init` and ended it in under a second with exit 143 for both. Neither wrote a result. SIGINT is gentler for Claude Code (clean result with `aborted_streaming`, exit 0) and less predictable for Codex. Use SIGTERM for the supervisor's kill path, and treat "no terminal event" as cancelled.

**Verdicts.** Turn and budget: Claude Code GO, Codex NO-GO on the tool (cap at the broker). Structured output: Claude Code NO-GO, Codex GO WITH CHANGES. Cancellation: GO WITH CHANGES.

**Consequences.** `s1-agent-runtime-adapters` parses the two event formats as above and maps the closed error set in section 6.7. Set `CLAUDE_CODE_MAX_RETRIES` and the Codex retry settings low enough that a refusal ends fast, and pass `--max-turns` as a second line. The broker meters and enforces the real cap.

### 4.8 What the permission flags enforce

All runs below used the hardened container. The fake provider returned the tool call.

**Claude Code.**

| Request | Setting | Outcome | Recording |
|---|---|---|---|
| Read a workspace file | default mode, no one to answer prompts | **allowed** | `claude-perm-read-default` |
| Run `touch` and `cat` in `Bash` | default mode, no one to answer prompts | **refused** ("this session has no approval surface"), listed in `permission_denials` | `claude-perm-bash-default` |
| Run `Bash` | `--permission-mode dontAsk` | refused | `claude-perm-bash-dontask` |
| `touch a && echo ... > b` | `--allowedTools=Bash(touch:*)` | refused as a whole | `claude-perm-allow-prefix-chain` |
| `mkdir -p d && printf ... > d/f && id` | `acceptEdits` and `--allowedTools=Bash(mkdir:*)` | **allowed as a whole**: the file after `&&` was written. This reproduces the observation in the integration guide that an allowlist does not contain the agent. | `claude-perm-acceptedits-chain` |
| Write inside / outside the workspace | `acceptEdits` | inside allowed; outside refused | `claude-perm-write-inside-acceptedits`, `claude-perm-write-outside-acceptedits` |
| Anything | `--dangerously-skip-permissions` or `--permission-mode bypassPermissions` | allowed; the shell ran as uid 10001, wrote into `/workspace`, and `touch /etc/...` failed with "Read-only file system" | `claude-perm-bypass-flag`, `claude-perm-bypass-mode` |
| Read `.env` | deny rule `Read(./.env)` or `Read(//workspace/.env)` | refused | `claude-perm-deny-read-rule`, `claude-perm-deny-read-rule-abs` |
| Read `.env` | deny rule `Read(/workspace/.env)` (one slash) | **allowed: the rule did nothing** | `claude-perm-deny-read-rule-slash` |
| `cat .env`, `awk 1 .env` in `Bash` | deny rule `Read(./.env)` | refused | `claude-perm-deny-read-rule-bash-cat`, `-awk` |
| `sh -c 'cat /workspace/.env'` in `Bash` | deny rule `Read(./.env)` | **allowed** (read 32 bytes) | `claude-perm-deny-read-rule-bash-sh-c` |

**Codex.** In the hardened container **every** command failed in the three sandbox modes: `bwrap: No permissions to create a new namespace` (`codex-perm-default`, `codex-perm-read-only`, `codex-perm-workspace-write`). The tool fails closed: it does not fall back to running without its sandbox. Only `--dangerously-bypass-approvals-and-sandbox` ran the command, again as uid 10001 with a read-only root (`codex-perm-bypass`). In `exec` mode an MCP tool call needs `default_tools_approval_mode="approve"` on its server, otherwise it fails with "MCP tool call requires approval, but approval policy is never" (`codex-bridge-call-unapproved`).

**What this means.** The permission flags are a filter on what the model is allowed to ask for. They are not a boundary, because a nested shell reads a file that a deny rule protects, and a path written with one leading slash silently matches nothing. What actually stopped writes outside the workspace and reads of host files was the container. This confirms the premise of ADR 0005 and the statement in `sandbox-policy.md` section 2.2. **Verdict: NO-GO for flags as containment, GO for the container as the boundary.**

**Consequences.** The negative tests NT-TOOL-04 and NT-TOOL-05 can assert the refusals above as telemetry (the `permission_denials` list and the `tool_result` text), but their pass conditions stay the container effects. The bypass flags are acceptable only inside a container that passed the posture check, as the policy says. The path syntax of deny rules (`./path` relative to the working directory, `//path` absolute) must be covered by a unit test of the rule generator.

### 4.9 The host tool bridge as hardening target (Model B)

The question: can the tool be left with only factory-provided tools, so that the tool process can run outside the sandbox? A fake bridge (`fake/fake_mcp_bridge.py`, a small Model Context Protocol server over HTTP with one tool, `factory_exec`) stood in for the real one.

**Claude Code: GO.**
- `--tools= --strict-mcp-config --mcp-config=<json>` left the model with exactly one working tool, `mcp__bridge__factory_exec` (the tool list in `provider-requests.jsonl` of `claude-bridge-call`; a placeholder named `DeferredToolPlaceholder` is also listed).
- The model asked for `Bash` anyway and got "No such tool available: Bash. Bash is disabled for this session, in subagents as well as here" (`claude-bridge-tools-empty`).
- Adding `--dangerously-skip-permissions` did not bring `Bash` back (`claude-bridge-bypass-attempt`).
- The call to the bridge tool arrived at the bridge as `initialize`, `tools/list` and `tools/call` over streamable HTTP (`claude-bridge-call`, file `bridge-calls.jsonl`).
- `--restricted` removes `Bash` but keeps `Read`, `Write`, `Edit`, `Glob`, `Grep`, `Skill` and `Agent` (`claude-bridge-restricted`). It is weaker than `--tools=`.

**Codex: GO WITH CHANGES.**
- `--disable shell_tool --disable unified_exec` removes `exec_command` and `write_stdin` from the tools declared to the model (marker counts in `codex-bridge-shell-off`). The model's attempt to call `exec_command` ended with "TypeError: tools.exec_command is not a function", and the bypass flag did not bring the tool back (`codex-bridge-shell-off`, `codex-bridge-bypass-attempt`).
- The bridge tool needs `mcp_servers.bridge={url=..., default_tools_approval_mode="approve", enabled_tools=[...]}` and then worked (`codex-bridge-call`).
- **`apply_patch` stays.** `include_apply_patch_tool=false` is not a known key in 0.163.0 (the tool printed "ignoring 1 unrecognized configuration setting"), and disabling the removed `apply_patch_freeform` feature changed nothing (`codex-bridge-no-patch-config`, `codex-bridge-no-patch-feature`). A host-run Codex could therefore still edit files under its working directory. The `exec` JavaScript tool also remains, but it is described as an isolate with no file system, no network and no console.

**What is not shown.** The bridge itself (typed tools run with `docker exec`), the behavior of either tool on the host with a subscription login (BLOCKED), and macOS or Windows host behavior. This is why Model B stays a hardening target and not a Slice 1 choice.

**Verdict: Claude Code GO. Codex GO WITH CHANGES** (run it with `-s read-only`, an empty working directory and the host tool sandbox, and treat `apply_patch` as the residual risk).

## 5. What the broker and the sidecar must do (input for `s1-egress-and-broker`)

Derived from section 4 and the recorded requests.

1. **Routes.** Allow `POST /v1/messages` (any query string, Claude Code sends `beta=true`), `POST /v1/responses`, and `GET /v1/models?client_version=...` (Codex asks twice at start when its credential comes from an `auth` command; an empty `{"models": []}` was accepted, and refusing it was not tested). Refuse the rest. Answer the Codex WebSocket upgrade (`GET /v1/responses` with `Upgrade: websocket`) with 404 or 426 at once; a custom provider with `supports_websockets=false` never sends it.
2. **Credential.** Read the job token from `x-api-key` or from `Authorization: Bearer`. The tools send exactly one of the two. Replace it with the real key towards the provider. Never forward the job token upstream and never log either.
3. **Transport.** Accept plain HTTP/1.1 from the sidecar. Stream server-sent events without buffering the whole response. Support chunked transfer encoding.
4. **Counting.** Count each `POST` to a model route as one request. Count retries too, because nothing marks them. A turn with one tool call is two requests.
5. **Size.** First requests are 46 KB (Claude Code) and 56 to 68 KB (Codex) and grow with the conversation. Set the body limit well above that and cap it by policy, not by default.
6. **Model.** Check the `model` field of the body against the job token's allowed list. The tools default to the most expensive model.
7. **Refusal behavior.** A 401 is retried up to ten times by Claude Code and five times by Codex. For a budget stop, answer 402: Claude Code stops at once and Codex gives up after six requests. Whatever status is used, the supervisor kills the container, because a tool that keeps retrying still costs requests. Expect up to 30 requests from Codex for one failed turn when the broker answers 500.
8. **Usage.** Read token counts from the provider's response (`usage` in the Anthropic message events, `usage` in `response.completed`). The tools' own cost figures are not usable.
9. **Reference.** The Codex release also ships `codex-responses-api-proxy`, a small proxy for the Responses API (asset `codex-responses-api-proxy-aarch64-unknown-linux-musl.tar.gz`, SHA-256 `691a67ee...9698`). Only its `--help` was read (`codex-responses-proxy-help`). It may be a useful design reference. It was not tested and is not part of any decision here.

## 6. Edits other documents and packages must make

This report changes no other file. The edits below are for their owners.

### 6.1 ADR 0005 (software_architect)

Add an amendment with this content.

> **Amendment, 2026-10-27, from `s0-agent-runtime-spike`** ([report](../spikes/agent-runtime.md)).
>
> - Decision confirmed: option 1 holds for Claude Code 2.1.311 and Codex 0.163.0. The fallback in `secrets-and-credentials.md` section 4.4 is not needed, because both tools can be redirected to a broker and both can read the credential from a file.
> - **Accepted versions.** Exactly Claude Code 2.1.311 and Codex 0.163.0, until a probe run proves another version. The probe must test behavior, not only flag presence: the hidden `--max-turns` of Claude Code is not in `--help`.
> - **Correct the statement "Claude Code 2.1.311 has no `--max-turns`".** It has a hidden `--max-turns` flag and a `CLAUDE_CODE_MAX_TURNS` variable, and both work. Codex has no turn or budget flag.
> - **Replace the per-stage flag rule for `--bare`.** `--bare` neither loads project or user skills nor stops the `env` block of a repository `settings.json`. For Claude Code use `--setting-sources user` and `--strict-mcp-config` in every stage, with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` in the environment. Use `--disable-slash-commands` in every stage except specification. In the specification stage mount the four pinned skills read-only in `~/.claude/skills`, because `--setting-sources user` hides the project skills. For Codex always set `project_doc_max_bytes=0`, `--disable plugins`, `-c analytics.enabled=false` and `--disable unbounded_connection_retries`, build a custom model provider entry, and hide the six denied skills with read-only overlays in the specification stage.
> - **Credentials.** The adapter delivers the job token with `apiKeyHelper` (Claude Code) or `auth.command` (Codex), both reading `/run/secrets/job_token`. It never uses an environment variable for a credential.
> - **Structured output.** The CLI schema flags are not used with the factory schemas. The engine validates the final answer.
> - **Budgets.** The broker counts requests and tokens and the supervisor kills the container. `--max-turns` and `--max-budget-usd` are a second line for Claude Code.
> - **Bridge verdict.** Model B stays the hardening target. Claude Code: GO (`--tools=` with a strict MCP configuration). Codex: GO WITH CHANGES (`apply_patch` cannot be disabled).
> - Remove from "Not verified": container start and masked `.git`, base URL, credential from a file, `--bare` and project skills, usage field names, schema acceptance, installing into an image. Keep as unverified: real-provider behavior, the signed manifests, `linux/amd64`.

### 6.2 `docs/security/sandbox-policy.md` (security)

- Section 2.2, last paragraph and the boundary table: the `[C]` observables are now known. Claude Code: `system/init` `skills` and `slash_commands`, `result.permission_denials`, `tool_result` text. Codex: `command_execution` and `mcp_tool_call` items, and the prompt listing from `codex debug prompt-input`.
- Section 6.3, last paragraph: the overlay mechanism is verified for both tools. Add that Claude Code's and Codex's bundled skills remain visible and can be switched off (`CLAUDE_CODE_DISABLE_BUNDLED_SKILLS=1`, `skills.bundled.enabled=false`), and that Codex can also hide a skill with `skills.config`. Add the alternative for Claude Code: with `--setting-sources user` the project skills are not read at all, so the supervisor mounts the four pinned skills read-only in the user skill root instead. State that a mount below the tmpfs home leaves root-owned parent directories, which Codex cannot tolerate.
- Section 8, last paragraph: replace "UNVERIFIED" with the measured result. Both tools start. Codex's own sandbox cannot start (default seccomp and AppArmor), and every command fails unless the bypass flag is given. Claude Code's `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` also needs bubblewrap and must not be set.
- Section 3.1 and 3.2: add that Codex needs a writable home tmpfs, and that both tools run with the home tmpfs `noexec`.
- Section 10 table: fix the `--bare` row (it skips hooks and CLAUDE.md but not the `env` block and not project skills) and add the flags of section 6.1 above. Fix the "per-run cost cap" row for Claude Code. Fill the `skill_permission_rule` answer: `Skill(name)` deny rules work for the model's tool call, not for a typed slash command.
- Section 10, rule 4: the base URL for Claude Code is `ANTHROPIC_BASE_URL`; for Codex it is a model provider entry, not `OPENAI_BASE_URL`.
- Section 13: remove the items settled here.

### 6.3 `docs/security/secrets-and-credentials.md` (security)

- Section 4.1 and 4.2: state that both tools were redirected and that both read the token from a file helper. Replace "UNVERIFIED" in sections 4.1, 4.2 and 11.
- Section 4.4: mark the fallback as not needed for these two tools.
- Section 4.2, delivery: forbid the environment variable route (section 4.5 above shows the model's shell sees it).
- Add the retry facts of section 4.7 to the revocation design.

### 6.4 `policies/security.yaml` (security)

- `untrusted_content.agent_runtimes.claude_code.required_flags`: add `--setting-sources user`. Keep `--bare` in every stage except specification (it skips hooks and attribution but loads no skills), and say in a comment that `--bare` alone is not enough. Add the environment `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`.
- `untrusted_content.agent_runtimes.claude_code.settings_source` comment about `--bare` and project skills: answer it ("`--bare` does not resolve project skills").
- `untrusted_content.agent_runtimes.claude_code.per_run_budget_flag`: add `--max-turns` and `CLAUDE_CODE_MAX_TURNS`.
- `untrusted_content.agent_runtimes.codex_cli.required_flags`: add `-c project_doc_max_bytes=0`, `--disable plugins`, `-c analytics.enabled=false`, `--disable unbounded_connection_retries`. Note that `--ignore-user-config` and `--ignore-rules` do not stop `AGENTS.md`.
- `agent_stage_profiles.specification.claude_code.skill_permission_rule`: set to "supported for the Skill tool, not for a typed slash command".
- `agent_stage_profiles.specification.claude_code`: add the user-skill-root mounts and `--setting-sources user`; note that `--bare` and project skills do not combine.
- `agent_stage_profiles.*.codex_cli.skill_visibility`: add `skills.config` and `skills.bundled.enabled=false` as mechanisms.
- `untrusted_content.agent_runtimes.codex_cli.env_policy`: the tool passes its environment, including a key variable, to its shell. State that the key must not be in the environment.

### 6.5 Broker specification and `s1-egress-and-broker`

Use section 5. Add the retry behavior as a test: after revocation the next request is refused in under two seconds (NT-BUD-07), and the supervisor kills the container within the deadline even if the tool keeps retrying.

### 6.6 `docs/security/negative-test-catalog.md` (security, qa)

- NT-INJ-07: add the hostile fixture of this spike as the case. Pass conditions: the hook and MCP marker files absent, no DNS query for the overridden host, the markers `CLAUDE.md` and `AGENTS.md` absent from the first model request. Only the flag sets in section 6.1 pass; `--bare` alone must fail the test.
- NT-POL-08 [C]: the observable is the `system/init` `skills` list filtered to `speckit-`, and `codex debug prompt-input`.
- NT-TOOL-04 and NT-TOOL-05 [C]: the observable is `permission_denials` and the `tool_result`; the pass condition remains the container effect. Add the one-slash deny rule as a case.
- NT-BUD-07: add the retry behavior and the supervisor kill.

### 6.7 Waiting packages

| Package | What to take from this report |
|---|---|
| `s1-agent-runtime-adapters` | The flag sets in section 6.1, the argument builders per stage, the event parsing of section 4.7, the closed error set below, the probe observations (behavioral test for `--max-turns`), `--model` always set, standard input closed, retries bounded. Recorded outputs for the parsing tests are in `runs/`. |
| `s1-agent-definitions` | Tool lists in the manifests map to `--tools=`, `--allowedTools=` and `--disallowedTools=` (Claude Code) and to feature switches (Codex). Do not rely on CLI schema flags for the outputs. Skills are exposed by overlays. |
| `s0-spec-kit-spike` | Single-shot `/speckit-<name>` works. `--bare` and `--setting-sources user` both hide project skills; mount the four pinned skills in `~/.claude/skills`, or use the overlays. The route in the integration guide (`--setting-sources project,local`) runs a repository's hooks and must not be used on a target repository. Skills ran under the hardened profile only as far as the protocol (the fake provider returns canned text, so no skill executed). `SPECIFY_FEATURE_DIRECTORY` can be set as a container variable, which both tools pass to their shell. Reuse `fake/` and `harness/`, and rebuild the images from the recipes (about two minutes). |
| `s1-sandbox-adapter` | A writable `noexec` tmpfs home for both tools. `HOME` set. No bind mount below `~/.codex`. Empty directory sources for overlays. Read-only mounts of the four pinned skills at `~/.claude/skills/speckit-<name>` in the specification stage. The token file mount. Environment allowlist: `ANTHROPIC_BASE_URL`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, `CLAUDE_CODE_MAX_RETRIES`, `HOME`, and `SPECIFY_FEATURE_DIRECTORY` for Spec Kit. Production needs no `--dns` flag, because the sidecar name resolves on the internal network (the harness used `--dns` only to log lookups). |
| `s1-sandbox-images` | Pin both tools by checksum. Include `bash`. Binary sizes in section 4.1. |
| `s1-egress-and-broker` | Section 5. |

**Closed error set for the adapters** (proposal from the recorded signals):

| Error | Claude Code signal | Codex signal |
|---|---|---|
| Missing credential | `terminal_reason: api_error`, text "Not logged in" | "Missing environment variable", `turn.failed` |
| Rejected credential or revoked token | `api_retry` with `error_status: 401`, then `api_error` | `turn.failed` with "unexpected status 401" |
| Rate limit | `api_retry` 429, or `api_error_status: 429` | "exceeded retry limit, last status: 429" |
| Provider outage | `api_error_status: 500` or 529 | "high demand" message after five retries |
| Provider unreachable | `api_error`, "Can't reach the API server" | "waiting for network" (needs `unbounded_connection_retries` off to end) |
| Turn cap | `subtype: error_max_turns` | not applicable; the broker cap |
| Budget cap | `subtype: error_max_budget_usd` | not applicable; the broker cap |
| Cancelled | no `result` event, exit 143; or `aborted_streaming` | no terminal event, exit 143 |
| Invalid output | the engine's validation | the engine's validation |

## 7. Dangerous defaults noticed

1. **Claude Code runs repository hooks and MCP servers in `-p` mode without asking**, and honors an `env` block that can redirect all model traffic (section 4.6).
2. **`--bare` looks like a safety switch and is not one.** It left the traffic redirection in place.
3. **Both tools put the credential in the environment of the commands the model runs**, and the parent's environment is readable.
4. **Both tools contact third parties by default**: telemetry to the vendor, and for Codex plugin synchronisation with GitHub.
5. **Codex loads `AGENTS.md` by default**, and `--ignore-user-config` and `--ignore-rules` do not stop it.
6. **Codex retries a lost connection forever by default.**
7. **Claude Code reports provider failures with `subtype: "success"` and exits 0 on SIGINT.** An adapter that trusts the subtype or the exit code will record a failed run as a success.
8. **Defaults pick the most expensive model** for both tools.
9. **`--dangerously-skip-permissions` is accepted for a non-root user with no check that it runs in a container.** The policy's posture check is the only guard.
10. **A deny rule written with one leading slash silently matches nothing.**
11. **A refused credential is retried ten times (Claude Code) or five times (Codex),** which multiplies requests at the broker.

## 8. What stays blocked, and what a human must provide

| To unblock | A human must provide |
|---|---|
| Live smoke test of both adapters (`s1-agent-runtime-adapters`, `s1-egress-and-broker`) | One Anthropic API key and one OpenAI API key, each created only for the factory, each with a hard provider-side spend limit, stored in the secret manager and not in the repository or a chat. A small live budget approved in writing. |
| Real usage, cost and refusal behavior; strict-mode schema check | The same keys, plus approval to send the small prompts of the smoke test to each provider. |
| Confirmation of ADR 0009 items 1 and 2 | A decision that the tool runs in the sandbox (item 1) and that credentials are API keys behind a broker (item 2). The spike supports both. |
| Subscription-login demonstration (optional) | The signed exception of `secrets-and-credentials.md` section 4.5, after the legal question is settled. Not needed for Slice 1. |
| `linux/amd64` and a Linux host without a virtual machine layer | A Linux sandbox host for a repeat of the recordings. |

## 9. Reproduction and what was left behind

The README of the recordings directory has the commands. A full run takes about twenty minutes plus two minutes to build the images. At the end of this work the containers, networks, generated key, scratch images and the private Colima virtual machine were removed, on the private engine and on the shared Docker Desktop engine (where a first, interrupted session had left two stopped containers, a network and the two images, now deleted). A later package starts by rebuilding the two images from `images/Dockerfile.*`.
