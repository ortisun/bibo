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

---

# Status after fixes

Written by the software engineer who fixed the findings, 2026-10-28, on top of `feat/slice-0-foundation` at
`69784ed`. **This section is the author's account, not a verdict.** A re-review is still to be done; where this
section says "fixed" it means "the test that failed now passes and the deliberate break of the control is caught",
not "the area passes". The reviewer's text above is unchanged.

## What happened to each finding

| ID | Status | What changed | Tests that now pass (and the break that is caught) |
| --- | --- | --- | --- |
| EGR-1 (High) | **Fixed**, with two parts UNVERIFIED (below) | The broker checks every request body against a closed schema per provider API (`crates/egress/src/broker/shape`), refuses a beta header that enables provider-side tools, forwards only the query `beta=true`, and returns only a media type and a retry delay in seconds of the provider's answer headers. The Codex adapter switches off Codex's own live `web_search`, which was in every request it made. | `egr_1_*` (both un-ignored); `negative_nt_sbx_17.rs` (nine tests, catalog row NT-SBX-17); `e2e_docker` (the real Claude Code and Codex through the real sidecar and broker). Breaks caught: `forward-the-body-without-the-schema`, `accept-an-unlisted-field`, `accept-an-unlisted-tool-type`, `accept-a-repeated-key`, `accept-an-image-by-address`, `forward-the-beta-header-unchanged`, `forward-the-provider-request-ids` (`crates/egress/tests/mutations.py`). |
| RTM-1 (Medium) | **Fixed** | Claude Code success needs `is_error == false`, `terminal_reason == "completed"`, exit code 0 and no signal. Both adapters also refuse a stream with a second terminal event or an event after it (97 recorded runs show exactly one, last). | `rtm_1_*` (un-ignored, plus a new test). Breaks caught: `claude-success-without-the-exit-check`, `claude-success-with-a-second-result`, `codex-success-with-a-second-completion` (`crates/runtime/tests/mutations.py`). |
| SBX-4 (Medium) | **Fixed in the image recipe, not yet in a built image; the original test stays ignored** | `claude`, `codex`, `codex-code-mode-host` and `timeout` are made execute-only (mode 0711) by `harden.sh`. See "SBX-4: the design" below. | `sbx_4_a_tool_that_nobody_can_read_has_a_stdout_that_proc_does_not_open` (real Docker, with a control that the readable program is forged); the real tools in the end-to-end lab (below). The original `sbx_4_a_child_cannot_write_into_the_stdout_pipe_of_its_parent` uses the readable `bash`, is true of any readable program, and stays `#[ignore]` with that reason. The image rule `TOOLS-EXECUTE-ONLY` in `test.sh` fails on the current image until it is rebuilt. |
| SBX-1 (Low) | **Fixed** | `denied_flag_in` reads the vector as Docker does (glued and separate values, short clusters, the image ends the flags) and checks what each flag means: a security option is a key and a value and only `no-new-privileges` is allowed, a mount is a map with aliases whose host source is checked after resolving the path, a limit must be above zero, the user a nonzero number, every namespace flag refuses `host`, `container:` and `ns:`. | `sbx_1_*` (un-ignored), 4000 random specs still build and pass (`denied_flags_are_never_emitted`), unit tests in `posture_args.rs`. Breaks caught: `a-deny-list-spelling`, `a-seccomp-colon-option`, `a-mount-of-the-host-root`, `a-limit-of-zero` (`crates/sandbox/tests/mutations.py`). |
| SBX-2 (Low) | **Fixed for the audit walk; the `RepoPath` half is OPEN** | The audit rejects the whole Unicode category Cf, the line and paragraph separators, the tag block (U+E0000 to U+E0FFF) and the invisible fillers, and escapes such a name in the finding that reports it. Names in other scripts, with accents or with emoji pass. | `sbx_2_the_audit_refuses_names_that_hide_or_reorder_text` (un-ignored, with a control for legitimate names); unit tests. Breaks caught: `a-bidi-file-name`, `a-tag-character-name`. `sbx_2_repo_path_refuses_names_that_hide_or_reorder_text` stays ignored: `RepoPath::new` is in `crates/ports`, outside what this change could edit. |
| EGR-3 (Low) | **Fixed** | The relay unwraps the IPv4-compatible, IPv4-translated, NAT64 and 6to4 forms of an IPv6 address and checks the address inside; it refuses `198.18.0.0/15`, NAT64 for local use, 6to4 and Teredo whole. | `egr_3_*` (un-ignored); unit test with the new addresses and neighbours that must still pass. |
| SBX-3 (hypothesis) | **Not reproduced; fail-closed rule implemented as a defence** | A disk measurement that fails is never read as zero. Three failed polls in a row, in a container Docker says is running, kill it and end the attempt as a disk resource failure; a good reading resets the count; a container that is gone ends the watchdog with no verdict. | `sbx_3_*` in `tests/scripted.rs` (through the provider, with a control where `du` works) and unit tests of the verdict. Breaks caught: `a-failed-disk-measurement-as-zero`, `a-container-that-is-never-stopped-for-an-unmeasured-disk`. |

## Found while fixing

* **Codex puts a live web search in every request by default.** The real request captured in the end-to-end lab holds
  `{"type":"web_search","external_web_access":true}`. The provider, not the sandbox, runs that search. With the schema
  check in place every Codex run was refused until the adapter wrote `-c web_search="disabled"` (`crates/runtime/src/codex/argv.rs`).
  `policies/security.yaml`, `agent_runtimes.codex_cli.required_flags`, does not list the flag yet; it is outside this change.
* The sidecar's request-id headers (`request-id`, `x-request-id`) were passed to the sandbox. They are not any more.

## The broker's allowed fields

The full table, with the reason for each field, is the module documentation of `crates/egress/src/broker/shape/mod.rs`
(rendered by `cargo doc -p factory-egress`). In short: **Anthropic Messages** accepts `model`, `max_tokens` (clamped),
`messages` (roles `user`, `assistant`, `system`; blocks `text`, `image` and `document` with an inline `base64` source,
`tool_use`, `tool_result`, `thinking`, `redacted_thinking`), `system`, `stream`, client `tools` (`name`, `description`,
`input_schema`, `cache_control`, `defer_loading`, `type: custom`), `tool_choice`, `thinking`, `output_config`,
`context_management` (two edits), `metadata.user_id`, `temperature`, `top_p`, `top_k`, `stop_sequences`.
**OpenAI Responses** accepts `model`, `input` (items `message`, `function_call`, `function_call_output`,
`custom_tool_call`, `custom_tool_call_output`, `reasoning`, `additional_tools`; an image only as a `data:` URL),
`instructions`, `tools` (`function`, `custom`, `namespace`), `tool_choice`, `parallel_tool_calls`, `reasoning`, `store`,
`include` (only `reasoning.encrypted_content`), `prompt_cache_key`, `client_metadata`, `text`, `max_output_tokens`,
`temperature`, `top_p`, `stream`. Refused with a class of their own: `mcp_servers` and every tool, block or item named
`mcp*`, `container`, `files`, `betas`, `service_tier`, `previous_response_id`, `background`, a stored `prompt`,
`conversation`, any tool `type` other than the client forms, an image or document by URL or file id, a schema
`$ref` that leaves its document, a repeated key, a byte order mark, text after the document, nesting past 64.

Derived from: the recorded sessions in `fixtures/recordings/agent-cli`, four full request bodies captured from the
real tools in the end-to-end lab (trimmed copies are the golden fixtures in `crates/egress/tests/fixtures/golden`), and
the published shape of the APIs for what a long session sends back. **UNVERIFIED against a live provider**: the thinking
and reasoning items of a real model, the image and PDF results of a real Read, and any field a newer tool version adds.
A legitimate field the schema lacks is refused with HTTP 400, a fixed sentence and an audit event naming the class; the
fix is one reviewed line in `anthropic.rs` or `openai.rs`.

The schemas are code, not data in `policies/`, on purpose (a new field is a change to what the provider may do for a
sandbox, so it should arrive with a test). `rules.rs` already treats them as data; the architect can move them.

## SBX-4: the design, why it holds, and what it does not cover

**Mechanism.** The adapters read the standard output of `docker exec ... env -i ... timeout ... claude|codex ...`. That
is a pipe, and runc gives it to the process owned by the sandbox user. Any process of that user can open
`/proc/<pid>/fd/1` of the process that holds the pipe and write into it. The kernel does not allow that when the target
is not dumpable, and a process started from a file that nobody can read is not dumpable. Its `/proc/<pid>/fd`,
`mem` and `environ` then belong to root.

**Shown, with the real tools** (the end-to-end lab: the real Claude Code and Codex, the real sidecar and broker, a
labelled fake provider; the image's own `claude`, `codex`, `codex-code-mode-host` and `timeout` copied to a tmpfs and
made mode 0111, because the image is not rebuilt in this change):

* Control, readable binaries: a command the model asked the tool to run wrote a forged `result` (Claude Code, through
  `/proc/$PPID/fd/1`) or `turn.completed` (Codex, through every process that holds the pipe) line into the stream, and the
  lab counted it: 1 forged line for Claude Code, 3 for Codex (`timeout`, the tool, and PID 1 of the lab's `docker run`).
* Execute-only `claude` or `codex` and `timeout`: both tools ran a whole turn with a tool call through the broker
  (2 model requests, exit 0), and the same command failed with "Permission denied" (`/proc/<pid>/fd` is `root root`).
  The one line that still arrived for Codex came through PID 1 (`docker-init`), which holds the lab's `docker run` stdout.
  Production uses `docker exec`, where PID 1's output is not the exec's pipe.
* Execute-only `claude` and a **readable** `timeout`: the forged line still arrived (two lines). `timeout` holds the
  same pipe, so it has to be execute-only too. That is why the rule lists four files.

**What it does not cover.**

1. It takes effect when the image is rebuilt. Until then `test.sh` fails `TOOLS-EXECUTE-ONLY` on purpose.
2. It protects a process only if every process that holds the exec pipe is not dumpable. Today those are `env` (which
   becomes `timeout`), `timeout` and the tool. A future wrapper that is a readable program in front of the tool, or a tool
   that hands its own standard output to a child, breaks it silently; no test watches the holders of the pipe in a built
   image (it is a follow-up for the image owner: list `/proc/*/fd/1` holders in the end-to-end lab and fail on a readable one).
3. Output of any other `docker exec` (`bash -c` for verification, for instance) is still forgeable by a sibling. No
   adapter trusts such a stream for events, but the original `sbx_4` stays ignored because it is true.
4. It relies on a kernel rule (the dumpable flag of an unreadable executable). It was shown on Docker Desktop 29.9.2's Linux
   VM, whose kernel has no Yama. It is old, core kernel behaviour, but it was not shown on the production kernel.
5. What the tool itself writes is authentic only because it is the tool's. A prompt-injected model can make the tool write
   misleading text; that is not forgery and is what the data envelope and the gates are for.

**Adapter hardening, independent of the image** (RTM-1): exit status and the one-terminal-event rule. They are the part a
sibling cannot write, and they close the combination the review found (forge a result, then kill the tool). They do not
authenticate the lines before the result (a forged `agent_message` item before a real `turn.completed` is still
indistinguishable); the image change is what protects those.

## Images (`infra/sandbox-images`), reviewed as a hostile reader would

Run against the built images (arm64, Docker Desktop): `audit.sh`, `negative-tests.sh`, the `fsaudit.py` walk inside them,
and `check-pins.sh` **offline only** (its real run needs the network and external hosts, which this task did not allow;
what I could check is its logic, on copies, with a stand-in registry and keys made at run time).

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| IMG-1 | Medium | The Rust toolchain is world-writable: 170 files and directories under `/opt/rust`, `cargo`, `rustc` and `rustdoc` at mode 0777 (the base image ships them so). The read-only root hides it at run time; any run with a writable root, or a layer copy, lets any user replace the compiler. | **Fixed in the recipe** (`toolchain.sh` removes group and world write); new rule `NO-WORLD-WRITABLE`; a control and a mutation in `negative-tests.sh`. Takes effect at rebuild; the rule fails on the current image. |
| IMG-2 | Medium | `check-pins.sh` accepted a signature made by **any** key in the downloaded key file (a key file served by the same host as the manifest, with the pinned key plus another one, passed with "signature verified, key <pinned>"). Shown on a copy. | **Fixed** (only a `VALIDSIG` by the pinned key counts); `tools/selftest-check-pins.sh`. |
| IMG-3 | Low | `check-pins.sh` printed OK for an emptied pin whose upstream lookup also gave nothing, and printed `RESULT: PASSED` with exit 0 when there was no Docker daemon for the base image digests. | **Fixed** (an empty pin is a DIFF; an unchecked part is BLOCKED, exit 3). Unpinned base, wrong digest and floating tag with a different digest already failed; shown on a copy. |
| IMG-4 | Medium (gate) | `NO-SECRET-CONTENT` is **red at HEAD** on the agent and verify images: 30 Debian copyright files under `/usr/share/doc` hold `cvs://:pserver:anoncvs@sources.redhat.com:/cvs/src`, which the `url_with_credentials` pattern of `policies/security.yaml` (widened by commit 9923aaf, API-5) now matches. A false positive, not a secret. | **Open**, not mine to fix: the pattern is policy; an exception in `fsaudit.py` would be a blind spot. |
| IMG-5 | Low | `negative-tests.sh` counted a mutation as caught on any `FAIL` line of the rule, so a rule that was already red on the real image (IMG-4, or an image not rebuilt) made every mutation of it look caught. | **Fixed** (the `FAIL` line must name what the mutation added and the real image must not show it; otherwise `UNPROVEN`). Three mutations (`readable-tool`, `world-writable`, `credential-file`) and a control added. |
| IMG-6 | Low | `negative-tests.sh` breaks 7 of 19 rules (now 10 of 21). `RUNTIME-PROFILE`, `READONLY-ROOT`, `NO-TOOLS-RUN`, `TOOLCHAIN`, `OFFLINE-BUILD`, `AGENT-TOOLS-RUN`, `SIDECAR-*`, `PINS`, `IMAGES-JSON` have never been seen to fail. | **Open.** |
| IMG-7 | Low | `CODEX_SIGSTORE_IDENTITY` is pinned in `pins.env` and used by nothing. Codex's provenance rests on the SHA-256 that GitHub lists, not on the sigstore bundle. | **Open** (documentation only today). |
| IMG-8 | Low | `fsaudit.py` does not read extended attributes, so a file capability (`security.capability`) would not be found. With `--cap-drop ALL` and `no-new-privileges` a file capability does nothing at run time. | **Open.** |
| IMG-9 | Low | `fsaudit.py` knew `sfjt_` but not `sfat_` for binaries and large files (small text files were covered through the policy pattern `api_token`). | **Fixed** (`sfat_` added; also in the `HIGH_SIGNAL_LITERALS`). |
| IMG-10 | Low | The Dockerfile and README say "no network client", but `/usr/bin/openssl` (`s_client`), bash's `/dev/tcp`, `cargo` and `chroot` are in the agent image. The network namespace, not the image, is the control. | **Open.** Removing `openssl` needs a build to verify; recommended. |
| IMG-11 | Low | `PINS` records only the hash of `pins.env` in `images.json`, not of the Dockerfiles, `harden.sh` or `toolchain.sh`. An image built from an older recipe still says "built from the current pins". This change edits `harden.sh` and `toolchain.sh`, and only the two new rules reveal that the image is stale. | **Open**: record a hash of the recipe files. |

What held: the setuid and setgid audit can fail (mutation `setuid-bit` caught); no setuid file exists; toolchain and tool
versions match the pins (`rustc 1.98.0`, `cargo 1.98.0`, `clippy 0.1.98`, `rustfmt 1.9.0-stable`, `claude 2.1.311`,
`codex 0.163.0`, both tool binaries at their pinned SHA-256: rule `TOOLS-ONLY-IN-AGENT`); no forbidden program; no credential
file; the image configuration holds only `PATH`; no file is owned by the sandbox user outside its home, and with the read-only root nothing is
writable at run time outside the mounts (the world-writable toolchain, IMG-1, is hidden by that); all seven original mutations were caught on the first run.

## What remains open, and who owns it

* **Architect (ports):** `RepoPath::new` still accepts names with bidirectional controls, separators, zero width and tag
  characters (`crates/ports/src/paths.rs`, `check_text`). The audit refuses them before a sandbox path is built, but a
  `RepoPath` made from any other text is not checked. The ignored test `sbx_2_repo_path_*` is the acceptance test.
* **Architect or policy owner:** `policies/security.yaml` `codex_cli.required_flags` should list
  `-c web_search="disabled"`; the broker allow schema may move from code to `policies/` as data (the walker already treats it
  as data); `url_with_credentials` matches `cvs://:pserver:anoncvs@...` in Debian documentation (IMG-4), which turns
  `NO-SECRET-CONTENT` red on the stock images.
* **Image owner:** rebuild the agent image (and the verify image for IMG-1), run `test.sh` and `audit.sh`, and record the new
  digests. Until then `TOOLS-EXECUTE-ONLY` and `NO-WORLD-WRITABLE` fail on purpose, and `negative-tests.sh` reports
  `readable-tool` as UNPROVEN. Then also: a check in the end-to-end lab that no readable program holds the exec pipe (limit 2
  of "What it does not cover"); remove `openssl` after a build check (IMG-10); record a hash of the recipe files in
  `images.json` (IMG-11); mutations for the rules that have none (IMG-6); read extended attributes in `fsaudit.py` (IMG-8).
* **Whoever owns provider access:** run the schema against a real Anthropic and a real OpenAI request of a long session
  (thinking blocks, reasoning items, an image result), because nothing here met a live provider. The allowed `anthropic-beta`
  list follows Claude Code 2.1.311; a new tool version that sends another beta has it dropped (and its feature may be refused
  by the provider) until the list is extended.
* **SBX-3** was not reproduced through the real provider by me either. The rule is defensive. A longer experiment on the
  production runtime is still the way to settle whether the original gap was real.
* `docs/spikes/agent-runtime.md` still says the broker should forward the `anthropic-beta` header unchanged and pass the
  request identifiers; that is superseded by `shape/mod.rs` and the spike was not edited.

## Commands and results

Environment: macOS, Docker Desktop (arm64), the image `factory-sandbox/agent:rust1.98.0-claude2.1.311-codex0.163.0` as
built before this change. `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0` throughout.

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean |
| `cargo test -p factory-egress --test security_review -- --ignored` and the same for `factory-runtime` | 0 tests left: every ignored test of these two files was un-ignored and passes |
| `cargo test -p factory-sandbox --test security_review -- --ignored` | 2 left, both fail on purpose: `sbx_2_repo_path_*` (needs `crates/ports`) and `sbx_4_a_child_cannot_write_into_the_stdout_pipe_of_its_parent` (true of any readable program) |
| `cargo nextest run --workspace --locked --no-fail-fast`, run as the `rust-test` step of `./scripts/ci.sh` | 4254 run, 4254 passed (35 slow), 31 skipped, 689 s |
| `./scripts/ci.sh` (full) | 30 of 31 steps PASSED on the final code, including `rust-fmt`, `rust-clippy`, `rust-test`, `rust-doctest`, `rust-deny`, `rust-audit`, `architecture-check`, `xtask-links`, `xtask-invariants`, `xtask-generated`, `secret-scan`, `shellcheck`. The one failure, `work-packages-doc` (the catalog row NT-SBX-17 had no owner in `docs/architecture/work-packages.json`), is fixed by an entry there and the regenerated `slice-plan.md`; both are outside the paths the task listed and are the minimal change the catalog row needs. |
| `cargo deny --locked check` | advisories, bans, licenses, sources ok |
| `cargo xtask check-architecture`, `check-links`, `check-invariants`, `check-generated` | all pass |
| `python3 -I crates/egress/tests/mutations.py <the seven new breaks>` | all seven CAUGHT |
| `python3 -I crates/sandbox/tests/mutations.py` | all eight CAUGHT, rerun after the last change to the audit |
| `python3 -I crates/runtime/tests/mutations.py` | all three CAUGHT |
| `infra/sandbox-images/audit.sh` | 3 FAIL, expected: `TOOLS-EXECUTE-ONLY` (the image is not rebuilt), and `NO-SECRET-CONTENT` on the agent and verify images (IMG-4, a policy pattern matching Debian documentation). `NO-WORLD-WRITABLE` was added after this run and also fails on the unrebuilt image (the negative test shows `/opt/rust` listed). |
| `infra/sandbox-images/negative-tests.sh` | first run, before the marker rule: the original seven CAUGHT. After it: `secret-in-file`, `credential-file`, `world-writable` CAUGHT (the other six originals were not rerun with the marker rule); the control `world-writable-repaired` OK; `readable-tool` UNPROVEN until the image is rebuilt (the real image already shows the mode 0755) |
| `infra/sandbox-images/tools/selftest-check-pins.sh` | all nine cases behave |

Two test runs behaved differently when several Docker test suites ran at once on the shared daemon (my own
`cargo nextest run -p factory-egress -p factory-sandbox -p factory-runtime` beside other stacks): three runtime
tests hit nextest's 600 s limit, and `negative_nt_sbx_07_the_disk_poll_kills_a_writer_that_passes_its_cap` failed
after 421 s with its `dd` killed by the disk poll. The same tests pass alone (the three runtime tests in 2 s, 86 s and 97 s;
`sbx_07` in 12 s) and pass in the full workspace run above. That test has a race that predates this change (the
`dd` must finish before the next poll), and I could not show whether the new fail-closed rule contributed under that
load; the rule counts three failed polls in a running container, which slowness alone does not produce.

Docker objects: before and after the work the containers, networks and volumes were compared. Nothing of mine was left
except possibly two networks, `sf-net-00000000-00000000-013afb00` and `sf-net-00000000-00000000-011d0b01`, labelled
`factory.test_run=80635-b12cb188` and `72971-d0067499` (dead pids, created about 22:07 local time, no containers
attached). I could not prove they are mine, so I did not remove them.
