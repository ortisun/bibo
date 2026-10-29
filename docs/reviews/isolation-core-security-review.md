# Isolation core security review

Reviewer: independent security specialist, not the author of this code. Scope: `crates/sandbox`,
`crates/egress`, `apps/egress-sidecar`, `crates/runtime`, the prompt assembler
(`crates/workflow/src/prompts`), `infra/sandbox-images`, and the security docs and policy that
describe them. Date: 2026-10-28. Base: `feat/slice-0-foundation` at `7f7c94d`.

Environment: macOS, Docker Desktop 29.9.2 (a Linux VM, arm64), `claude` 2.1.312, `codex`
0.163.0 (CLI version; the images and fixtures are pinned to 2.1.311/0.163.0, a difference that did
not matter to anything tested here), no real model, no external network, no real credentials. New
tests under `*/tests/security_review/` and `crates/workflow/tests/prompt_security_review/` were
discovered by Cargo without any edit to a `Cargo.toml`; no `[[test]]` line was touched.

## Verdicts

| Area | Verdict | Why |
| --- | --- | --- |
| Sandbox (Docker adapter, posture, ingestion, process runner) | **PASS WITH CONDITIONS** | The posture verifier, the argument builder, the ingestion audit walk, and the resource limits held against everything I tried except two low-severity gaps in the deny-list's own defence-in-depth and in the audit's name filter (SBX-1, SBX-2), and a real integrity gap in the authenticity of the tool event stream (SBX-4). None of the three is a route out of the container. |
| Egress (broker, sidecar/relay) | **FAIL** | The broker forwards a request body to the real model provider with no check on provider-side tool and remote-MCP fields (EGR-1). A sandbox that can reach the broker (every `agent`-profile job) can make the provider itself fetch an attacker URL or call an attacker MCP server, entirely outside the sidecar's host allowlist. This is the one finding in this review I would block a release on. |
| Runtime adapters (Claude Code, Codex) | **PASS WITH CONDITIONS** | The flag sets, the environment allowlist, the skill overlays and the timeout/kill path held. The Claude Code success rule does not check how the process exited (RTM-1), which combines with SBX-4 into a real, if narrow, forged-success path. |
| Prompt assembly (the data envelope) | **PASS** | I could not break the quoting: every Unicode scalar value, the broadest set of line-break characters I know of, every delimiter-forging shape the module's own documentation names, and a secret hidden by zero-width characters. |
| Images (`infra/sandbox-images`) | **NOT FULLY REVIEWED** | I read the Dockerfiles and the pin mechanism and found nothing wrong, but I did not run `fsaudit.py`, `audit.sh` or `negative-tests.sh` against the built images, and I did not review `check-pins.sh`'s own correctness. Say what I did not reach, below. |

## Findings

| ID | Severity | Status | Evidence | Impact | Smallest fix | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| EGR-1 | **High** | Confirmed | `crates/egress/src/http/server.rs:494-509` (`serve_model_request` touches only `max_tokens`/`max_output_tokens`), `:568-606` (`build_upstream_request` forwards the body byte-for-byte to the provider). Test: `cargo test -p factory-egress --test security_review -- --ignored egr_1` (two tests, both FAIL today). | A sandbox that holds a valid job token (every `agent`-profile job) can craft a request with `tools: [{"type": "web_fetch_20250910"}]`/`mcp_servers` (Anthropic) or `tools: [{"type": "mcp", "server_url": "..."}]` (OpenAI Responses) and the broker forwards it unchanged. The **provider's own infrastructure**, not the sandbox, then makes the outbound request, so the egress sidecar's host allowlist (`policies/security.yaml` `egress.profiles.agent`) is never in the path. This is a full bypass of T-17 (network egress exfiltration) and opens a route to running attacker-chosen tool calls through a remote MCP server using the broker's own credential. It does not need the official CLI to construct the body: a compromised job with `Bash` access (granted to every builder/implementation stage) can read the job token file and send the request itself; the broker has no other check standing between the token and the provider. | Reject (400) any request body that contains `tools` entries of a type not in a small allowlist (local, non-networked tool types only) and reject `mcp_servers`/`mcp_server_url` fields outright; strip or refuse the `anthropic-beta` values that enable them (`web-fetch-*`, `mcp-client-*`). Add the same check to `/v1/responses` for `type: "mcp"`, `web_search*`, `code_interpreter`, `file_search`, `image_generation`. | `egress` |
| SBX-1 | Low (defence in depth) | Confirmed | `crates/sandbox/src/container/posture.rs:76-128` (`denied_flag_in`). Test: `cargo test -p factory-sandbox --test security_review -- --ignored sbx_1` (FAILS today: 11/11 vectors pass the deny list unflagged). Hand-verified against the real daemon: `docker create -v/private/tmp:/h:ro ...` and `docker create --security-opt seccomp:unconfined ...` are both accepted by Docker 29.9.2. | The module's own documentation says this list is the second layer against "a later edit of the builder [that] cannot start a weaker container without this check failing." Today `create_args` never emits the missed spellings (`-v<src>:<dst>`, `--security-opt flag:value`, `--mount source=`/`target=` without `src=`/`dst=`, `--cgroupns host`, a zero or negative `--pids-limit`/`--memory`), so there is no live path to a weaker container through this gap. It is a hole in the second layer, not a first-layer bypass. | Make `denied_flag_in` parse each argument the way Docker's own flag parser does (accept `-vSRC:DST[:OPTS]` glued to the flag, `source=`/`target=` as mount key aliases, and the `:` form of `--security-opt`), or replace the string scan with a structured re-parse of the vector before it is sent. | `sandbox` |
| SBX-2 | Low | Confirmed | `crates/sandbox/src/workspace/audit.rs:249-259` (`name_problem`: control characters and backslash only). Test: `cargo test -p factory-sandbox --test security_review -- --ignored sbx_2` (FAILS today: 8/8 hostile names accepted). | A file name with a right-to-left override, a line/paragraph separator, a zero-width character or a tag character is accepted by the audit walk and becomes a `ChangedPath`. Unlike text the assembler quotes (`crates/workflow/src/prompts/sanitize.rs` strips exactly this class), a path that is *listed* (a diff summary, a PR file list, a log line) is not run through that cleaner, so the same class of character that `sanitize::is_hidden` treats as an injection vector for text is not treated the same way for paths. | Reuse `factory_workflow::prompts::sanitize::is_hidden`'s character class (or move it to a shared crate) in `name_problem`, rejecting any name that contains one of those code points, the same way control characters are rejected today. | `sandbox` |
| SBX-4 | Medium | Confirmed | `crates/sandbox/src/supervisor/exec.rs` (the only capture of a `docker exec`'s stdout), mechanism: any process of the sandbox user can open `/proc/<pid>/fd/1` of another process of the same user and write into it. Test: `cargo test -p factory-sandbox --test security_review -- --ignored sbx_4` (FAILS today: a forged line written by a sibling shell through `/proc/$PPID/fd/1` reaches the captured stream). | The event stream the runtime adapters parse (`crates/runtime/src/claude/events.rs`, `crates/runtime/src/codex/mod.rs`) is the standard output of one `docker exec`. Any process the compromised tool starts — a tool call, a background job, anything running as the same uid — can write directly into that file descriptor and add lines the tool itself never produced. The classification functions (`classify` in both adapters) trust the *last* `result`/completion line of that stream; a forged one changes the run's outcome. This is the mechanism RTM-1 exploits. | Make the supervisor the only writer trusted: redirect the tool's own stdout to a private, unguessable path inside the container (e.g. a per-run fifo or file under a directory the tool's children cannot `stat`, created with a mode the sandbox uid alone can open) instead of relying on fd 1 of the `docker exec` process being unreachable, which it is not. | `sandbox`, `runtime` |
| RTM-1 | Medium | Confirmed | `crates/runtime/src/claude/mod.rs:529` (`classify`: `if !done.is_error && done.terminal_reason.as_deref() == Some("completed")` — no check of `result.exit_code`, `result.signal` or `result.oom_killed` before this branch; contrast `crates/runtime/src/codex/mod.rs:513` which requires `exit.code == Some(0)` in addition to `stream.completed`). Test: `cargo test -p factory-runtime --test security_review -- --ignored rtm_1` (FAILS today for Claude Code; the matching Codex assertion already holds). | Combined with SBX-4: a tool child forges a `{"type":"result","is_error":false,"terminal_reason":"completed",...}` line into the shared stdout and then kills or crashes the real tool process. The Claude Code adapter reports the run as a **success** with the forged text as its output, because nothing after the last `result` line is consulted. Codex cannot be fooled the same way because it additionally requires a clean exit. | Add the same requirement to Claude Code's `classify`: require `exit.code == Some(0)` (or the documented soft-deadline/no-signal cases already handled above it) before trusting `done`. | `runtime` |
| EGR-3 | Low | Hypothesis (narrow) | `crates/egress/src/relay/policy.rs:66-83` (`DEFAULT_DENY_RANGES`), `:108-114` (`is_denied` only unwraps `::ffff:a.b.c.d`, the IPv4-*mapped* form, through `to_ipv4_mapped()`). Test: `cargo test -p factory-egress --test security_review -- --ignored egr_3` (FAILS today for `198.18.0.1`/`198.19.255.254`, the IANA benchmarking range, and for `::7f00:1`, `::a00:1`, `64:ff9b:1::1`, IPv4-*compatible* (not mapped) and other NAT64/well-known-prefix spellings of a private address). | Only matters for the `fetch_deps` profile (`connect` mode), since `agent`-profile traffic is pinned to one address by the supervisor and never resolves anything (`Mode::Broker`, `serve_broker`). A registry host that resolved to one of these forms (through DNS rebinding infrastructure, a misconfigured resolver, or an attacker-controlled authoritative server for a dependency's documented download host) would reach a private address the policy meant to exclude. I found no registry host on the allowlist that plausibly resolves this way; this is a hardening gap, not a demonstrated route. | Add `198.18.0.0/15` to the deny list, and check `Ipv4Addr::from(((v6.segments()... ))`-style IPv4-compatible unwrapping, not only `to_ipv4_mapped()`, in `is_denied`. | `egress` |
| SBX-3 | Low/Medium | **Hypothesis, not reproduced end-to-end** | Mechanism confirmed directly against the Docker daemon (commands below); the module's own documentation (`crates/sandbox/src/supervisor/watchdog.rs:1-11`) already states "a measurement that fails ... is skipped, not counted as zero." My attempt to reproduce the same effect through the full `DockerSandboxProvider` pipeline (new test `held_the_disk_cap_is_enforced_while_the_process_table_is_at_its_limit`) did **not** show a failure: the watchdog's `du` poll succeeded every time I drove the real adapter, and the over-cap container was killed on schedule. See "What I could not verify," below, for the raw reproduction and why I did not resolve the discrepancy. | If sustained (a process-table-saturating workload held for longer than the disk poll interval), the disk cap has no fallback: a poll that fails is simply skipped, forever, with no circuit breaker on repeated failures. I could not show that the real adapter's workload and timing let an attacker sustain that saturation in practice. | Make a run of consecutive failed disk polls fail closed (kill the container) above a small threshold, instead of only ever treating a failed poll as "try again later." | `sandbox` |

## Claimed negative tests that cannot fail, or pass for the wrong reason

I read every `negative_nt_*` test name in `crates/sandbox/tests`, `crates/egress/tests` and
`crates/runtime/tests` against the catalog (`docs/security/negative-test-catalog.md`) and ran the
ones most central to this review's priorities (sandbox boundary, egress, runtime). I did not run
every test in the suites (see "What I did not reach"). Two observations from what I did read and
run:

1. **NT-SBX-05's allowlist exactness is real, but it is the wrong layer for EGR-1.** The egress
   test suite (`crates/egress/tests/negative_nt_sbx_05.rs`, `crates/egress/tests/core_rules.rs`)
   thoroughly exercises the *sidecar's* host-matching exactness (suffix tricks, userinfo, IP
   literals, port checks) and the broker's own token/model checks. None of those tests, and no
   test I found in the catalog or the suite, asserts anything about the *content* of the request
   body the broker forwards to the real provider beyond the model name and the output-token cap.
   The catalog's T-17 ("Attack: POST data to an allowlisted host... use the model API with an
   attacker's key") describes exactly the EGR-1 mechanism but the attached tests (NT-SBX-04,
   NT-SBX-05, NT-SEC-01) are all sandbox-side network tests; none can fail for EGR-1, because
   EGR-1 never touches the sandbox's network path at all — it rides inside a request the sandbox
   is *supposed* to send to the broker. This is not a test that fails for the wrong reason; it is
   a real gap in the catalog's coverage of T-17 that I could not find a test for anywhere.
2. **`negative_nt_tool_06_the_tools_environment_is_the_adapters_list_and_nothing_the_repository_or_agent_wrote`**
   and its sibling in `crates/runtime/tests/negative.rs` assert on the environment dump of a real
   container and hold up; I did not find a control-removed variant committed in the suite (the
   catalog's own rule 2, "a 'control off' switch... must fail when the switch is on"), so I cannot
   say from the committed tests alone whether they would fail if `EnvName`'s allowlist check were
   removed, only that they pass today. I did not have time to build the control myself for this
   test; I note it as unverified rather than broken.

I found no test that passes only because an unrelated earlier check already stopped the scenario
("a refused request that was refused for an earlier unrelated reason") among the tests I actually
ran. I did not audit the full catalog this way; see below.

## What I tried that held

* **Prompt injection into the envelope.** Every Unicode scalar value (the full `0..=0x10FFFF`
  range, in 2048-character chunks) fed through the intake-classifier's template; the forged
  delimiter in eight shapes (plain, after `\r`, after U+2028, after U+0B mixed with a second fake
  open block, after a right-to-left override, with a zero-width character spliced into `<<`, in
  fullwidth Unicode forms, and alongside fake `{{trusted.x}}`/`{{input.request}}` placeholders and
  a fake `## Output contract` heading); a secret hidden by interleaving zero-width characters
  between every byte. None broke the property that every line of data starts with `> ` and the
  instruction text outside the blocks stays byte-identical to the template.
  (`crates/workflow/tests/prompt_security_review/main.rs`.)
* **Shell metacharacters and argument injection** against the typed `docker exec` vector and the
  real agent image's own shell: literal arguments, no host side-effect, correct uid and zero
  capabilities inside the sandbox (existing `negative_nt_tool_01`, re-read, not re-run beyond the
  suite's own pass).
* **The posture verifier's deny list**, exercised against the real daemon: privileged, added
  capabilities, unconfined seccomp/AppArmor, host namespaces, a `docker.sock` or `/etc` mount, a
  writable root, root user, a non-`no` restart policy, a non-`none` network for `verify`, were all
  refused before the container started (existing suite, re-read).
* **Network boundaries of the `agent` profile**, extended beyond the existing
  `negative_nt_sbx_04` test: no default route, no gateway address on the job network, the
  embedded DNS server (127.0.0.11) answers only for the sidecar's own alias and fails closed
  (`rc=2`, `NXDOMAIN`) for an external name and for `host.docker.internal`; the VM host address,
  the default bridge gateway and an IPv6 address are all unreachable
  (`held_an_agent_sandbox_has_no_route_no_gateway_and_no_external_name_resolution`).
* **Credential handling in the token path**: the job token never reaches the provider in any form
  (header, query, body), and the provider's own key is never echoed back to the sandbox even when
  the fake provider is scripted to try (`held_the_job_token_is_not_forwarded_and_the_provider_key_is_not_echoed`).
* **Request-smuggling shapes at the broker's HTTP parser**: `Transfer-Encoding` alongside
  `Content-Length`, and two different `Content-Length` values, both refused with 400 before the
  provider is ever reached (`held_request_smuggling_shapes_are_refused_before_the_provider`).
* **IP-literal and address-range lookalikes** at the relay's target parser and its deny ranges: all
  of the policy's listed private/loopback/link-local/metadata/NAT64 ranges, the IPv4-mapped form of
  a loopback and a link-local address, decimal/octal/hex/short IPv4 literals, bracketed and
  unbracketed IPv6, a trailing `@`/second-authority smuggling attempt, NFKC-lookalike dots and
  whitespace padding — all refused (`held_listed_ranges_and_literal_spellings_are_refused`).
* **The disk-cap/watchdog pipeline under free process budget**: an over-cap write with the pid
  limit untouched was detected and the container killed within seconds, both as the repository's
  own `negative_nt_sbx_07` and as a fresh control written for this review
  (`held_an_over_cap_write_with_free_pids_is_killed_within_seconds`).
* **Codex's success rule** already requires a clean exit in addition to a `completed` stream, and
  held against the same forged-plus-killed scenario that breaks Claude Code
  (`held_codex_success_needs_a_clean_exit`); missing and malformed result streams are typed
  failures for both tools, not silent passes (`held_missing_and_error_results_are_failures`).
* **Git-directory and control-character path rejection** at the type that every changed path goes
  through (`RepoPath::new`): every spelling of `.git` the walk itself recognizes
  (`is_git_directory_alias`, case folding, the NTFS/HFS `~1` short name, trailing dot/space) and
  every control character, NUL and backslash are refused before a path can exist in a change set
  (`held_git_directory_aliases_and_control_names_are_refused`).

## What I could not verify, and why

* **SBX-3's end-to-end reproduction.** I confirmed the underlying Docker mechanism directly
  against the daemon used by this review (Docker Desktop 29.9.2, the real `factory-sandbox/agent`
  image, the exact hardening flags `create_args` emits): a throwaway container built with
  `--pids-limit 24` and driven to `pids.current == pids.max == 24` by a shell that then blocks on
  a builtin read (no further forks) makes **every** `docker exec` into it fail with
  `OCI runtime exec failed: ... nsexec-0[...]: unable to spawn stage-1: Resource temporarily
  unavailable`, for as long as the saturation is held, and recovers the instant it is released.
  That is the exact call the disk watchdog makes (`disk_usage_kib` in
  `crates/sandbox/src/supervisor/watchdog.rs`). I could not, in the time available, build a Rust
  integration test through the real `DockerSandboxProvider` that reproduced the same failure: the
  watchdog's own poll consistently succeeded when I drove the same shell script through
  `SandboxSession::exec`. I did not resolve why a hand-run container and a provider-created one
  with the same flags behave differently under my scripted timing, so I report the mechanism as
  confirmed and the exploitability of it through the real pipeline as unresolved, not as proven
  either way. A kernel engineer with more time than this review had should resolve the
  discrepancy before SBX-3 is dismissed or escalated.
* **Every kernel-level isolation claim** (seccomp filtering of specific syscalls beyond what the
  self-check reads from `/proc/self/status`, the exact behaviour of `unshare`, `ptrace` against a
  process outside the container, `/sys/firmware` contents, ASLR, cgroup v1-vs-v2 edge cases) is
  untestable here in the way the architecture document itself says: Docker Desktop on macOS runs a
  Linux virtual machine, and I have no way to compare that VM's kernel and container runtime
  (runc) against what a bare-metal Linux production host, gVisor, Kata or a microVM would do. The
  threat model's own section on T-14/T-15 (container escape) says the same. I read the code and
  the existing `negative_nt_sbx_06`/`07`/`08` results and take them as what a Linux VM under
  Docker Desktop reports; I make no claim about a different runtime.
* **Whether a real, un-sandboxed Claude Code or Codex CLI, talking to a real provider, would ever
  itself construct a request body with `tools: [{"type": "web_fetch_..."}]` or `mcp_servers`
  without the repository's own `.mcp.json` (which the adapter's flags neutralize).** EGR-1 does
  not depend on this — a compromised job with `Bash` access can reach the broker directly with its
  own HTTP request, bypassing the CLI's own request construction entirely — but I note that I did
  not verify the *official* CLI's own default tool-use behaviour against a live Anthropic/OpenAI
  endpoint, because no real network or real credential is permitted in this review.
* **The sidecar's own binary and image** (`infra/sandbox-images/agent/Dockerfile`,
  `.../egress-sidecar`, `fsaudit.py`, `check-pins.sh`, `audit.sh`, `negative-tests.sh`). I read the
  Dockerfiles, the pinning mechanism (`ADD --checksum=sha256:...`) and the fsaudit script's
  documentation, and found no obvious defect, but I did not run `infra/sandbox-images/test.sh` or
  the fsaudit/setuid walk against the built images, and I did not review `check-pins.sh`'s own
  correctness. This is the largest area of the assigned scope I did not reach; I prioritized the
  sandbox adapter, the egress path and the runtime success rule by blast radius (container escape,
  credential theft, egress bypass, then integrity) as instructed, and ran out of budget before the
  image tooling.
* **The redactor's resistance to secret leakage through sinks other than the prompt and the
  broker** (NT-SEC-01 through NT-SEC-11: the full canary sweep of a complete job, process
  arguments and environment of every spawned process, markdown exfiltration sanitization,
  model-context exclusions). I read `crates/domain/src/redaction/*` enough to understand the
  architecture (streaming scan, exact-value registry, fail-closed on scanner error) and did not
  find a defect, but I did not run the repository's own `NT-SEC-*` suite (I did not find a
  `security_review`-style gap in it worth a new test, and a from-scratch canary sweep of a full
  job was outside the time this review had after the egress and sandbox findings).
* **Authority and webhook handling** (`NT-AUTHZ-*`, `NT-WH-*`) and **tenant isolation**
  (`NT-TEN-*`, row-level security): entirely outside the assigned scope (sandbox, egress, runtime,
  prompt assembly, images) and I did not look at them.
* **The host tool bridge** (`[T]`-tagged rows of the catalog): the deployment default has it off
  (`policies/security.yaml`); I did not build or exercise it, consistent with the catalog's own
  "NOT_APPLICABLE unless the host tool bridge is chosen" rule.

## Requirements on the deployment

* **EGR-1 must be fixed before any multi-tenant or external-facing deployment.** It is a complete
  bypass of the egress allowlist for any job with network-adjacent credentials (every `agent`
  profile job holds a job token), independent of which CLI or model is in use.
* The job token store (`crates/sandbox/src/container/token.rs`) still assumes a deployment chooses
  a tmpfs-backed root for `TokenStore`; the crate cannot enforce this itself ("a Linux host `root`
  should be on a tmpfs, so the secret never reaches a disk; this crate cannot make one, so the
  choice of `root` is the deployment's"). Verify this at deployment time; I did not test it.
  (`crates/sandbox/src/container/token.rs:13-16`.)
* Production hosts need the hardening the threat model already names and which a Linux VM under
  Docker Desktop cannot exercise: dedicated machines or strong tenant isolation, rootless or
  user-namespace remapping, AppArmor or SELinux actually enforcing (not `NotAvailable`), and for
  true multi-tenant use a stronger isolation technology (gVisor, Kata, microVMs) than a shared
  kernel with namespaces and cgroups. I could not test any of this here.
* Resolve the SBX-3 discrepancy (mechanism confirmed, pipeline reproduction inconclusive) with a
  longer, more controlled experiment than this review had time for, ideally on the actual
  production container runtime, before relying on the disk cap against a determined attacker.

## How to reproduce the confirmed defects

```text
# EGR-1 (both providers)
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-egress --test security_review -- --ignored egr_1

# SBX-1 (deny-list second layer)
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-sandbox --test security_review -- --ignored sbx_1

# SBX-2 (hidden/reordering characters in a tracked path)
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-sandbox --test security_review -- --ignored sbx_2

# SBX-4 (a child writes into its parent's docker-exec stdout)
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-sandbox --test security_review -- --ignored sbx_4
# needs Docker; reports BLOCKED, never PASSED, without it.

# RTM-1 (Claude Code accepts a forged, non-clean-exit success)
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-runtime --test security_review -- --ignored rtm_1

# EGR-3 (benchmark range and IPv4-compatible forms not refused)
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-egress --test security_review -- --ignored egr_3

# SBX-3's raw Docker mechanism (not a committed test; run by hand against the real daemon)
docker create --name probe --user 10001:10001 --read-only --cap-drop ALL \
  --security-opt no-new-privileges --init --pids-limit 24 --memory 256m --network none \
  --log-driver none factory-sandbox/agent:rust1.98.0-claude2.1.311-codex0.163.0 sleep 60
docker start probe
docker exec probe bash -c 'while :; do read c < /sys/fs/cgroup/pids.current; \
  read m < /sys/fs/cgroup/pids.max; [ "$c" -ge "$m" ] && break; sleep 20 >/dev/null 2>&1 & done; \
  read -t 15 x < /dev/zero'   # run in the background, then in another shell:
docker exec probe cat /sys/fs/cgroup/pids.current   # fails while the above holds
docker rm -f probe
```

## New tests added by this review

* `crates/egress/tests/security_review/main.rs` — EGR-1, EGR-3, and two held tests (job-token
  non-forwarding, request-smuggling refusal).
* `crates/sandbox/tests/security_review/main.rs` — SBX-1, SBX-2, SBX-4, and four held tests
  (git-alias/control-name rejection, the free-pids disk-cap control, the process-table-saturation
  attempt, the agent network-view assertions). Docker-dependent tests report `BLOCKED:` and never
  `PASSED` without a daemon and the built images (inherited from `require_docker()` in the
  existing harness).
* `crates/runtime/tests/security_review/main.rs` — RTM-1 and two held tests (Codex's stricter
  success rule, missing/malformed result handling). No Docker needed; uses the existing scripted
  session.
* `crates/workflow/tests/prompt_security_review/main.rs` — three held tests against the real
  assembler, the real policy fixture and the nine real agent prompts (the full Unicode sweep, the
  forged-delimiter sweep, the hidden-secret sweep). No Docker needed.

No existing file was edited to register these targets; Cargo's default test-discovery found each
`tests/<name>/main.rs` on its own.
