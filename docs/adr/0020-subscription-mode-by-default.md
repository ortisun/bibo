# 0020: Run the factory on the owner's Claude subscription by default

- Status: **Decided by the owner on 2026-11-12.** Built on the branch `feat/subscription-mode`. No independent review has covered it.
- Date: 2026-11-12
- Deciders: the owner ("Delete essa necessidade de chave. Vou usar a fabrica em subscription mode": remove the need for a key; I will use the factory in subscription mode). The engineer wrote the design and the code.
- Reverses: [ADR 0009](0009-operating-defaults-pending-confirmation.md) item 2, and the "subscription logins are off" stance of `policies/security.yaml` and [secrets and credentials](../security/secrets-and-credentials.md) sections 4.1 and 4.5.
- Related: [ADR 0005](0005-agent-runtime-adapter-boundary.md), [threat model](../security/threat-model.md) T-19, T-26 and Q2

## Context and problem statement

ADR 0009 item 2 made provider API keys with a provider-side spend limit the only credential the factory would use, on the grounds that a subscription login could not be brokered or metered. No such key exists, so every live run was BLOCKED. The owner has a Claude subscription and wants the factory to run on it.

Can the broker design survive with a subscription as the real credential, so that the sandbox still holds nothing but a per-job token?

## Decision

`credentials.model_providers.mode` in `policies/security.yaml` takes two values. A file without the key means the first.

- **`subscription` (the default).** The real credential is the owner's long-lived Claude subscription token, made with `claude setup-token` (prefix `sk-ant-oat01-`). The broker holds it, and only the broker. The sandbox gets the per-job token, as before, and Claude Code presents it as its OAuth token (`CLAUDE_CODE_OAUTH_TOKEN`) to the broker through the sidecar. The broker swaps it for the subscription token and sends `Authorization: Bearer`. No provider API key and no provider-side spend limit is required.
- **`api_key`.** Everything as before this record: one API key per provider with a provider-side spend limit, for Claude Code and for Codex.

### What changes

| Where | In subscription mode |
|---|---|
| Policy | `mode: subscription`; a new `subscription_token` block (held by the broker only, never in a sandbox, Anthropic only, no provider-side limit required, `codex-cli` unavailable). The loader refuses a file that puts the token anywhere but the broker. `subscription_logins` and its signed exception are removed, and so is the approval row `accept_subscription_login_exception`. `secrets.exact_values.register_from` gains `subscription_token`. |
| Configuration | The `anthropic` entry of `broker.upstreams` names the token file as `key_file`, for example `~/claud-oauth-token.txt`; a leading `~/` is the worker's home directory. |
| Start-up | The worker reads the token file before the broker listens and refuses to start with a line that begins "subscription mode needs the owner's Claude subscription token" when the file is missing, has a mode looser than `0600`, holds a token with a line break or a space inside ("it was probably wrapped when copied"), or holds something that does not start with `sk-ant-oat01-`. Whitespace around the token is removed. The token is registered with the redactor by exact value; the existing `sk-ant-` pattern also matches it. An `openai` entry is not started, and the worker prints `BLOCKED: agent runtime codex-cli: broker.upstreams: ...` and claims nothing. |
| Broker (`crates/egress`) | The Anthropic upstream sends `Authorization: Bearer <token>` instead of `x-api-key`, adds `anthropic-beta: oauth-2025-04-20` to the betas it lets through, keeps `?beta=true` and its own user agent, and forwards the system prompt unchanged. Before it forwards a Messages request it checks that the system prompt opens with a Claude Code identity, and refuses it with `subscription_identity_missing` otherwise. It meters every request (tokens in and out) as before. |
| Rate limits | A provider 429 is recorded by name (`provider_rate_limited`, with the delay), charged nothing, and does not revoke the token. The tool gets a 429 with the broker's fixed body and the delay and retries. A stage run that still fails is a `PROVIDER_ERROR`: retried within its attempts, then sent to a person (ADR 0010), never failed for this alone. This holds in both modes. |
| Claude Code adapter | No `apiKeyHelper` settings document. A fixed launcher line, `/bin/sh -c 'CLAUDE_CODE_OAUTH_TOKEN="$(/usr/bin/cat /run/factory/job-token)" ...; exec "$0" "$@"' <claude> <flags>`, sets the OAuth token from the job token file inside the tool's own process, so the token is in no container variable, no argument and no log. `CLAUDE_CODE_PROMPT_CACHE_TTL=5m` is set, because on a subscription the tool otherwise asks for one-hour cache writes, which the broker refuses (RR-2). `--setting-sources user`, `--strict-mcp-config`, `--disable-slash-commands` and the clean home per run stay. |
| Budgets | Unchanged. The job and day ceilings are measured, as before, as the list-price equivalent of the token counts the broker reads from every answer (`policies/model_routing.yaml`). On a subscription that is not what the owner pays; it is how much of the plan a job may use, counted in dollars at list price. |

### What is lost

- **Codex.** Its ChatGPT login (`~/.codex/auth.json`, refreshing tokens) is not brokered. In subscription mode Codex does not run, and an `openai` entry is BLOCKED by name rather than replaced silently. A consequence for the reviewer roles whose policy requires a model of another family than the author's (`policies/model_routing.yaml` section 4):
  - **Code review** (`REVIEW`) finds no independent model and waits for a person before any reviewer runs. The stage run and the job are `WAITING_FOR_HUMAN`, and the reason is `independent-reviewer-unavailable` in the timeline and in the audit log. Nothing fails. From there an approver can send the work back (`rework ... target=IMPLEMENTATION`) or reject it, and an operator can cancel the job. An approver can also approve the stage run, which passes the review on the person's judgment, with no reviewer verdict stored.
  - **Documentation review** (`DOCUMENTATION_REVIEW`) is not held to the rule yet. The documenting stage does not store the model of its writer, so the engine cannot name the author, and the review runs on a Claude model after a Claude writer.
  - **Specification review** is not held to the rule either, in either mode. The writer and the reviewer run in one stage run with one job token for one model, routed with no author, so the reviewer always runs on the writer's model.
  - **The owner's option.** Setting `must_differ_by: model` on the code review and documentation review rules passes the policy's own check and makes `claude-opus-5-5` independent of a `claude-sonnet-5-5` author. It is not enough on its own: the review stages ask for the `standard` tier, whose routes do not list `claude-opus-5-5`, and the check refuses a `large` model on a `standard` route. Opus reviews Sonnet's work only once a review asks for the `large` tier, which is a code change.
- **A provider-side spend limit.** None exists for a subscription. The factory's ceilings and the plan's own limits are the only bounds.
- **A credential that belongs to the factory.** The token is tied to the owner's personal account. If it leaks, the owner's account is exposed until the owner revokes it.
- **Certainty about the provider's terms.** Whether automated use of the subscription is allowed is the owner's responsibility. This record does not assert what any provider's terms say.

## What was verified

On 2026-11-12. "VERIFIED" means run, with the version named.

- **The owner's live checks, straight to `https://api.anthropic.com/v1/messages`** with the real subscription token as `Authorization: Bearer`, `anthropic-version: 2023-06-01`, model `claude-haiku-5-5`:
  1. Accepted (200) only when the system prompt starts with the text block "You are Claude Code, Anthropic's official CLI for Claude.", `anthropic-beta` includes `oauth-2025-04-20` (sent: `claude-code-20250219,oauth-2025-04-20`) and the URL has `?beta=true`. The user agent does not matter: `factory-model-broker` worked (200, 41 tokens in, 4 out) as `claude-cli/2.1.323` did. VERIFIED.
  2. Without the identity block the provider answers 429 `{"type":"rate_limit_error","message":"Error"}` whatever the headers, so a 429 on a subscription is ambiguous unless the broker refuses unshaped requests itself. VERIFIED.
  3. A token pasted from a terminal that wrapped it, with a line break and a space inside, gave 401 "OAuth access token is invalid". VERIFIED.
  4. Claude Code 2.1.323 with `CLAUDE_CODE_OAUTH_TOKEN` (the cleaned token), an empty `HOME`, `--setting-sources user` and `--strict-mcp-config` answered "ok". VERIFIED.
- **What Claude Code 2.1.323 sends on `CLAUDE_CODE_OAUTH_TOKEN` with `ANTHROPIC_BASE_URL` at a local listener** (captured on the development machine, no real credential, no request to the provider): `POST /v1/messages?beta=true`, `Authorization: Bearer <the value>`, user agent `claude-cli/2.1.323 (external, sdk-cli)`, a beta list that includes `oauth-2025-04-20` and `claude-code-20250219`. In print mode the system prompt is a billing block (`x-anthropic-billing-header: ...`) followed by "You are a Claude agent, built on Anthropic's Claude Agent SDK.", not the identity of item 1. The same CLI got its answer in item 4, so the broker accepts both sentences, as the first system text or the first after the billing block. Without `CLAUDE_CODE_PROMPT_CACHE_TTL=5m` the request carries `"ttl":"1h"` cache writes and the `extended-cache-ttl-2025-04-11` beta; with it, neither. VERIFIED.
- **The OAuth token stays out of the agent's shell.** Claude Code 2.1.323 on the development machine, and 2.1.311 in the hardened agent container with the hostile checkout (`crates/runtime/tests/negative.rs`, `negative_nt_inj_07_and_nt_tool_06_hold_in_subscription_mode`), run with the token in `CLAUDE_CODE_OAUTH_TOKEN`: the `env` the model's shell tool printed held no `CLAUDE_CODE_OAUTH_TOKEN` and not the token value, and the repository's hooks, servers, settings and instructions were ignored. VERIFIED, against the spike's fake provider.
- **The broker side**, against a fake provider (`crates/egress/tests/subscription_mode.rs`): the bearer header, the OAuth beta, the unchanged system prompt, the metering, the identity refusal and the named 429. VERIFIED in test mode.

## What is not verified

- **The real broker in front of the real provider.** No request has gone from this broker to `api.anthropic.com`. The owner runs the live check below.
- Whether the provider accepts, in the long run, every request shape a long Claude Code session sends through the broker (thinking blocks, the mid-conversation system messages, context management), and what it sends when a plan limit is reached in the middle of a stream. UNVERIFIED.
- Whether the provider could start to require the CLI's own user agent, or another identity sentence. The broker sends its own user agent, which worked in item 1; if that changes, the live check fails with 429 or 401. UNVERIFIED.
- `count_tokens` on a subscription token: the identity check applies to Messages requests only. UNVERIFIED.
- The lifetime of a `claude setup-token` token. The policy rotates it every 180 days. UNVERIFIED.
- Claude Code 2.1.323 in the hardened container: the image pins 2.1.311. The container test ran with 2.1.311.

## How the owner turns it on

1. On the machine where the worker runs, as the worker's user, run `claude setup-token` and follow its prompts. It prints a token that starts `sk-ant-oat01-`.
2. Save the token as **one line** in a file outside the repository, for example `~/claud-oauth-token.txt`, and make it private: `chmod 600 ~/claud-oauth-token.txt`. A terminal that wraps the token while you copy it puts a line break or a space inside it; the worker refuses such a file and says so.
3. In the worker configuration, list the Anthropic provider with that file, and no `openai` entry:

   ```yaml
   broker:
     listen: '127.0.0.1:8731'
     upstreams:
       - { provider: anthropic, base_url: 'https://api.anthropic.com', key_file: ~/claud-oauth-token.txt }
   ```

   `policies/security.yaml` already says `credentials.model_providers.mode: subscription`.
4. Run the live check (next section). It prints one line with the status, the model and the token counts.
5. Start the factory. A line that begins "subscription mode needs the owner's Claude subscription token" names what to fix.

To revoke: revoke the token from the Claude account, run `claude setup-token` again, replace the file, restart the worker.

## The live check

`crates/egress/tests/live_subscription.rs`, test `live_subscription_one_tiny_request_through_the_broker`. It is ignored by default, and only the owner runs it:

```text
cargo test -p factory-egress --test live_subscription -- --ignored --nocapture
```

It reads the token file from `FACTORY_SUBSCRIPTION_TOKEN_FILE`, or `~/claud-oauth-token.txt`, with the worker's checks; starts the real broker in subscription mode in front of `https://api.anthropic.com`; issues a job token; sends one Messages request of at most 16 output tokens as Claude Code would send it; and prints only `LIVE subscription: status <code> model <name> input_tokens <n> output_tokens <n>`. Never the token, never the answer text. The model is `FACTORY_LIVE_MODEL`, or `claude-haiku-5-5`. It has not been run by the engineer, who had no token.

## Consequences

- Live runs with Claude Code are no longer BLOCKED on a provider key; they wait on the owner's token and the live check.
- Runs that need Codex, and the end-to-end harness that runs both tools (`tests/end_to_end`), run in API-key mode only.
- Tests that start the worker use a made-up subscription token, because the repository policy is now in subscription mode. Tests that exercise API-key behaviour say so and set the mode.
