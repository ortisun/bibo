# Isolation core security re-review

Reviewer: independent security specialist. I did not write `docs/reviews/isolation-core-security-review.md`
(the first review) and I did not write the fixes. My job was to try to break the fixes, not to confirm
them. Scope: the egress broker allow schema (EGR-1), the relay's range policy (EGR-3), the two adapters'
success rule (RTM-1) and the hardened image recipe (SBX-4), the sandbox posture deny list (SBX-1), the
audit name filter (SBX-2), the disk-measurement fail-closed rule (SBX-3), and the image tooling the fix
claims to have repaired. Date: 2026-10-29. Base: `feat/slice-0-foundation` at `4c11489` (fast-forwarded
from the review's own base; fix commits `6af49d2..2381c2b`, merged at `82b9493`).

Environment: macOS, Docker Desktop 29.9.2 (a Linux VM, arm64), the pinned images already built
(`factory-sandbox/agent:rust1.98.0-claude2.1.311-codex0.163.0`, `factory-sandbox/verify:rust1.98.0`). No
image was rebuilt. No real model, no real provider, no external network, no real credential.

## Verdicts

| Area | Verdict | Why |
| --- | --- | --- |
| Broker allow schema (EGR-1) | **PASS WITH CONDITIONS** | The closed-schema design holds against a large grammar-driven property test with my own oracle (40,000 bodies per provider, a different generator and a different judge than the author's), against 38 hand-built parser-differential and field-smuggling cases, and against header/path/method/query tricks at the live listener. It does not hold against the output-token cap on OpenAI routes (RR-1, confirmed, cost/DoS) or against a one-hour cache-write TTL booked at the five-minute price (RR-2, confirmed, billing). Two narrower gaps are open as hypotheses (RR-3 inline SVG/arbitrary image subtype, RR-4 `$id`/`$schema`/`$vocabulary` resolver bait) and one resource gap (RR-6, no cap on the number of JSON values, 218 MB resident for an 8 MiB body) is confirmed but of uncertain severity at the listener's own connection limit. |
| Relay range policy (EGR-3) | **PASS WITH CONDITIONS** | Every form I tried of every listed private/loopback/link-local/metadata/NAT64/6to4/benchmarking address is refused, including forms the author's own test did not enumerate (uppercase, trailing dot, `255.255.255.255`, `ff02::1`, the full NAT64-local and Teredo ranges). RR-5 (confirmed) is a short list of other IANA special-purpose ranges (Azure's platform address, the DS-Lite/PCP block, `fec0::/10`) that the policy still does not name; narrow (only the `fetch_deps` profile uses this path) but a plain gap, not a hypothesis. |
| Runtime success rule (RTM-1) + hardened image (SBX-4) | **PASS WITH CONDITIONS** | On real Docker, against the actual pinned agent image (not rebuilt), making `claude`, `codex`, `codex-code-mode-host` and `timeout` mode 0711 does stop a sibling of the tool from writing into the exec's stdout pipe through `/proc/<pid>/fd/1` after the exec has started — I reproduced the paper's result exactly, including the control (a readable binary is still forgeable). But a process that opens that file descriptor **before** the hardening takes effect — i.e., before the tool process exists, racing the moment `env`/`timeout`/the tool start under the shared pipe — keeps the descriptor and forges lines into it for the whole life of the pipe: 8 of 8 trials succeeded against the hardened container. This is RR-14 (confirmed, high blast radius: it defeats the headline SBX-4 claim, not a residual case). The exit-status/one-terminal-event rule (RTM-1) itself held against every exit/signal/truncation/interleaving shape I tried except two gaps I found: RR-7 (a terminal line torn by an interleaved write, confirmed) and RR-8 (a truncated stream with an early forged terminal event, confirmed); RR-9 (Codex's rule not reading a signal, unreachable with today's `exit_parts`, hypothesis only). |
| Sandbox deny list (SBX-1) | **PASS WITH CONDITIONS** | The typed re-parse reads flags the way the real Docker CLI does for everything I threw at it (abbreviations, case, clusters, glued/separate values, `--` and image-ends-flags, every `--security-opt`/namespace/mount spelling in the original finding). Confirmed by also asking the live daemon's own CLI which spellings it accepts (`held_docker_reads_flags_the_way_the_deny_list_does`). Three gaps remain, all confirmed on the real daemon: RR-10 (mount key case-insensitivity: Docker lower-cases `SRC=`/`Source=`/`SOURCE=` and the deny list's key match is case-sensitive, so the wrong source is checked while the right one is mounted), RR-11 (the host-path denylist is eight roots and the text `docker.sock`; the container runtime's own socket, `/run`, `/home`, `/Users`, `/var/lib/containerd` and others are not on it and `docker create` accepts them), and RR-12 (allowed flags' weakening values are not read: an executable/setuid/device tmpfs, a negative ulimit, `--init=false`, a mount destination over a tool or a credential file). |
| Audit name filter (SBX-2) | **PASS WITH CONDITIONS, one hypothesis open** | Every hostile name in the original finding and the fix's own test is refused. RR-13 (hypothesis, not confirmed as exploitable): names that print as blank (`U+00A0`, `U+2800`, `U+3000`, `U+2009`) or that differ only by a combining-mark sequence pass the audit unchanged; two such names can be visually identical or visually empty in a diff listing. I could not show this reaches an injection the way the original Cf/Zl/Zp finding did; it is a hardening gap I flag as unverified exploitability. |
| Disk-measurement fail-closed rule (SBX-3) | **NOT RE-EXERCISED** | I read the rule (`MAX_UNMEASURED_POLLS = 3`, `crates/sandbox/src/supervisor/watchdog.rs:89`) and it is what the fix claims. I did not have time to repeat the first review's own open question (the discrepancy between the hand-run container and the `DockerSandboxProvider` pipeline), and I did not attempt a new reproduction. Carried over as unresolved. |
| Image tooling (`check-pins.sh`, `negative-tests.sh`, `fsaudit.py`) | **FAIL** on one point, **PASS** on the rest I reached | `negative-tests.sh`'s own self-test (`selftest-check-pins.sh`) passes and the `UNPROVEN`-vs-`CAUGHT` logic is sound for the cases it covers. But `check-pins.sh`'s signature check (its own claimed fix for IMG-2, "only a `VALIDSIG` by the pinned key counts") accepts a signature made by a **revoked** key with the pinned fingerprint (RR-15, confirmed, reproduced with throwaway keys made at run time, no network). `fsaudit.py`'s new `sfat_` pattern and its `tool-modes.txt` output both work on a synthetic tar as documented; I did not find a defect in `images_json.py` or in the mutation-counting logic itself beyond what I already ran through `selftest-check-pins.sh`. |

## Original findings: HOLDS / PARTIAL / BROKEN

| ID | Verdict | Attack tried | Evidence |
| --- | --- | --- | --- |
| EGR-1 | **HOLDS**, with two new defects adjacent to it (RR-1, RR-2) | A grammar-driven property test (not the author's mutation-of-a-recorded-body generator) building 40,000 valid-shaped Anthropic and OpenAI bodies per run, each field independently replaced with a hostile value from a pool (URLs, `mcp*`, every server-tool type name, `__proto__`, case/whitespace variants, schema `$ref` escapes) at random depths, judged by a second, independently written oracle that allows only a closed list of keys/tags by structural position and flags any URL-looking string outside the handful of fields meant to hold free text. 7,936 and 9,310 bodies were accepted per provider; none held a disallowed key, tag or address. Also: 38 hand-built parser-differential bytes (escaped keys, NUL in a key, Cyrillic homoglyph, comments, BOM, lone surrogates, overlong UTF-8, `NaN`/`Infinity`/hex/leading-zero numbers, 65-deep nesting) are all refused; the live listener never forwards the sidecar's session/cookie headers, the attacker's own `openai-organization`/`x-forwarded-for`/`content-encoding` headers, or path/query/method tricks (`/v1/messages/../files`, `//v1/messages`, percent-encoded slashes, `beta=true&x=1`, method-override headers); request-smuggling shapes (two `Content-Length`s, folded headers, two credentials) are refused before the provider; the answer headers stay a closed set even when the fake provider is scripted to send `Set-Cookie`, `Location`, `Link`, a CSP header, `Refresh`, and the provider's own request/org identifiers. | `crates/egress/tests/security_rereview/main.rs::held_property_no_accepted_body_holds_a_key_a_tag_or_an_address_the_oracle_does_not_allow`, `::held_documents_that_two_readers_could_read_differently_are_refused`, `::held_paths_queries_and_methods_that_try_to_reach_another_endpoint_never_reach_the_provider`, `::held_framing_and_credential_tricks_are_refused_before_the_provider`, `::held_the_answer_headers_are_a_closed_set_even_for_a_hostile_provider` |
| RTM-1 | **HOLDS** for every shape the original finding and its own fix test enumerate; **PARTIAL** against two new tearing/truncation shapes (RR-7, RR-8) | Exit codes 1, 2, 124–127, −1; signals 1 (HUP), 2 (INT), 3 (QUIT), 6 (ABRT), 9 (KILL), 15 (TERM); the real Docker exit codes measured on the pinned image for each signal (129, 131, 137, 143); OOM-style kill; NUL bytes, a 900 KB line, a BOM, a double document, an array-wrapped event, a boolean `is_error`, case variants of `terminal_reason`, a capitalized `type` key — none of these creates a success from a stream with no real result. | `crates/runtime/tests/security_rereview/main.rs::held_a_complete_stream_is_not_a_success_when_the_process_did_not_end_cleanly`, `::held_noise_around_a_stream_does_not_create_a_result` |
| SBX-4 | **PARTIAL → effectively BROKEN for the headline claim under a pre-existing hostile process**, confirmed on real Docker against the unrebuilt pinned image | Reproduced the fix's own experiment exactly (readable binary forgeable, execute-only binary not, `timeout` must be execute-only too) — that part holds. Then ran a second experiment the fix's documentation does not mention: a hostile process started **before** the `docker exec` of the tool, sitting in a tight loop over `/proc`, opens the standard-output pipe of the short-lived `env` process (the first, readable program of the wrapper chain `env -i ... timeout ... claude`) the instant it appears, and keeps that file descriptor open past the point where `env` execs into the execute-only `timeout`/tool. The kernel's non-dumpable rule governs who can *open* `/proc/<pid>/fd/1` of the *current* occupant of a pipe; it says nothing about a descriptor opened while the pipe's occupant was still the readable `env`, and that descriptor keeps working once the readable process has replaced itself via `execve`. 8 of 8 trials forged a line into the final tool's captured stdout, with the execute-only modes verified in place on the same container. | `/private/tmp/.../scratchpad/rr/racer.sh`, `/private/tmp/.../scratchpad/rr/exp_race.sh` (not committed; reproduction is RR-14 below) |
| SBX-1 | **HOLDS** against every spelling in the original finding and the fix's own tests, confirmed against the live daemon; **PARTIAL** against three further weakenings not covered by "Docker-accepted spellings" (RR-10, RR-11, RR-12) | `--cap-ad`/`--cap_add`/`--CAP-ADD`, `--priv`, `--security-opts`, `--PID=host`, `--privileged=yes`, `-privileged` are all refused by the Docker CLI itself before the daemon is asked (so the deny list does not need to and does not need to catch them); every spelling the deny list is meant to catch (`-v`, `--volume=`, `--mount` key aliases, `--security-opt` with `:` or `=`, every namespace flag, `--user` in every numeric form, `--read-only=false`, `--restart`, `--pull`, `--log-driver`) is refused. | `crates/sandbox/tests/security_rereview/main.rs::held_the_spellings_docker_accepts_for_a_weaker_container_are_refused`, `::held_docker_reads_flags_the_way_the_deny_list_does`, `::held_the_image_ends_the_flags_and_a_flag_before_it_cannot_hide_behind_a_value` |
| SBX-2 | **HOLDS** for the audit walk against the Cf/Zl/Zp/tag characters named in the original finding; **PARTIAL**, one new hypothesis (RR-13) | Every original hostile name plus a dozen more of the same Unicode categories refused; the `RepoPath` half stays open exactly as the fix's own author-written status says (I did not attempt that; it is outside this change's reach per the fix's own note). | `infra/sandbox-images/lib/harden.sh` not touched here; `crates/sandbox/src/workspace/audit.rs:255-311` read, not modified |
| EGR-3 | **HOLDS** for the ranges and forms named in the original finding; **PARTIAL**, one new gap (RR-5) | Every IPv4 private/loopback/link-local/CGNAT/benchmarking/metadata/multicast/reserved address, in the plain form and in IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64 (well-known and local-use), and 6to4 IPv6 forms (27 IPv4 bases times up to 9 IPv6 encodings), plus `::1`, `::`, `fe80::1`, `febf::1` (the top of the link-local range, still inside it), `fc00::1`, `ff02::1`, and a 6to4-embedded complement address — all refused. | `crates/egress/tests/security_rereview/main.rs::held_every_spelling_of_a_private_address_the_relay_policy_names_is_refused` |
| SBX-3 | **NOT RE-EXERCISED** | — | — |

## New findings

| ID | Severity | Status | Evidence (file:line) | Command | Impact | Smallest fix | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RR-1 | Medium | Confirmed | `crates/egress/src/http/server.rs:560-595` (`clamp_output_tokens`: the `Provider::OpenAi` branch of the "request names none" case returns `false` and never sets a field) | `cargo test -p factory-egress --test security_rereview -- --ignored rr_1` | A Responses or Chat Completions request that omits `max_output_tokens`/`max_completion_tokens`/`max_tokens` is forwarded with no limit at all; the provider's own default governs cost and reasoning-token spend for that one request, past `per_request.max_output_tokens`, until the ceiling check on the *next* request catches up. | When no output-limit field is present on an OpenAI route, insert the cap (as is already done for Anthropic) instead of leaving the request unbounded. | `egress` |
| RR-2 | Low | Confirmed | `crates/egress/src/broker/shape/anthropic.rs:8-14` (`CACHE_CONTROL.ttl: Enum(&["5m", "1h"])`); `crates/egress/src/broker/pricing.rs` (`ModelPrice` has one `cache_write` rate per model, no TTL dimension); `crates/egress/src/http/usage.rs:33` (`cache_creation_input_tokens` read without which TTL produced it) | `cargo test -p factory-egress --test security_rereview -- --ignored rr_2` | Anthropic bills a 1-hour cache write at roughly double the 5-minute rate; the broker's price table and usage parser have no way to tell which TTL a `cache_creation_input_tokens` count came from, so every accepted `ttl: "1h"` write is under-booked against the actual provider invoice. Not a security bypass by itself, but a silent, provider-confirmed billing gap next to a module whose whole job is to meter spend precisely. | Either refuse `ttl: "1h"` until the price table can distinguish the two rates, or add the second rate and read it from the provider's own answer shape. | `egress` |
| RR-5 | Low | Confirmed | `crates/egress/src/relay/policy.rs:72-95` (`DEFAULT_DENY_RANGES`) | `cargo test -p factory-egress --test security_rereview -- --ignored rr_5` | Azure's link-local platform address (`168.63.129.16`), the IETF protocol/DS-Lite/PCP block (`192.0.0.0/24`), and the IPv6 site-local range (`fec0::/10`, deprecated by RFC 3879 but still assigned by some stacks) are not in the deny list and would reach a private host if a `fetch_deps`-profile name resolved there. Narrow: only the `connect` mode of the relay resolves names at all. | Add `168.63.129.16/32`, `192.0.0.0/24`, and `fec0::/10` to `DEFAULT_DENY_RANGES`. | `egress` |
| RR-6 | Low/Medium | Confirmed | `crates/egress/src/broker/shape/json.rs:35-169` (the hand-written `Reader`: depth is bounded by `MAX_DEPTH`, the number of values in one array or object is not) | `cargo test -p factory-egress --test security_rereview -- --ignored rr_6_a_body`; memory measured by hand with `/usr/bin/time -l target/debug/deps/security_rereview-* --ignored --exact rr_6_measure_the_parser_on_a_full_size_body --nocapture` (shapes `arrays`/`numbers`/`objects` via `BODY_SHAPE=...`) | An 8 MiB body of three million `0,` tokens parses into a `Vec<Value>` of three million `serde_json::Value::Number`s before the schema rejects it for being the wrong top-level shape; the `numbers` shape measured 218 MB resident (about 26x the body size) for a body at the listener's own `max_body_bytes`. The listener accepts up to 64 concurrent connections, so a holder of one job token (every `agent`-profile job) can hold several such bodies in flight; this is a resource question, not a bypass, and I did not measure it against the server's real `max_connections`/timeouts to say how far it goes. | Cap the total number of values read per document (a counter threaded through `object`/`array`), not only the nesting depth. | `egress` |
| RR-7 | Medium | Confirmed | `crates/runtime/src/claude/events.rs:330-382` (`parse`: a line split on `\n` that fails `serde_json::from_slice` is counted in `malformed_lines` and otherwise ignored); `crates/runtime/src/codex/mod.rs:496-532` (`classify`: no use of `malformed_lines`/its Codex equivalent) | `cargo test -p factory-runtime --test security_rereview -- --ignored rr_7` | A sibling that interleaves a write in the middle of the tool's own write of its terminal line tears that line into two malformed fragments; if the sibling's own forged line is a complete JSON object between the fragments, the stream now holds exactly one well-formed terminal event (the forged one) with nothing after it and the process still exits 0. Both adapters accepted this as a success with the forged text in both of my trials. This is the same SBX-4 mechanism the original review and its fix already treat as closed by the image hardening going forward; it shows the adapter-level rule (RTM-1) has no independent defense against it once a writer exists. | Count malformed lines and refuse a success when any appear in a stream that also has no record of ever starting a normal conversation (e.g., no `system/init` for Claude Code, no `thread.started` for Codex), or move to a private, unguessable output channel as the original review's SBX-4 fix already plans. | `runtime` |
| RR-8 | Medium | Confirmed | `crates/runtime/src/claude/mod.rs:516-556`, `crates/runtime/src/codex/mod.rs:496-532` (`result.stdout_truncated` is consulted only inside the *failure* branches, never when `done`/`stream.completed` plus a clean exit have already returned `Ok`) | `cargo test -p factory-runtime --test security_rereview -- --ignored rr_8` | A forged terminal line early in the stream followed by enough filler to push the real end of the capture past the sandbox's output cap produces: one well-formed terminal event, nothing parsable after it (the tail is truncated mid-line, so it is dropped as partial), and a clean exit — a success, with the forged text, and `stdout_truncated` never examined because the success path returns before that check is reached. | Check `stdout_truncated` on the success path too, not only on the paths that already return an error. | `runtime` |
| RR-10 | Medium | Confirmed | `crates/sandbox/src/container/posture_args.rs:256-290` (`mount`: `key` is matched against `"src" \| "source"` exactly, case-sensitive; Docker itself lower-cases the key before comparing) | `cargo test -p factory-sandbox --test security_rereview -- --ignored rr_10`; confirmed against the real daemon with `docker create --mount type=bind,src=/tmp/ok,SRC=/etc,dst=/x` then `docker inspect` showing the mounted source is `/etc` | `--mount type=bind,src=/tmp/ok,SRC=/etc,dst=/x` passes the deny list's check (it reads `src=/tmp/ok` as the source and finds nothing wrong), while Docker itself takes the *last* occurrence of the case-folded key and actually mounts `/etc`. Any uppercase or mixed-case alias (`SRC`, `Source`, `SOURCE`, and the same for `TYPE`) bypasses the host-path check entirely. | Case-fold the key before matching `src`/`source`/`type`/`dst`/`target`, and take the last occurrence as Docker does, not the first match found. | `sandbox` |
| RR-11 | Medium | Confirmed | `crates/sandbox/src/container/posture_args.rs:162-170` (`DENIED_SOURCES`: eight literal roots plus a substring check for `docker.sock`) | `cargo test -p factory-sandbox --test security_rereview -- --ignored rr_11`; each vector separately confirmed accepted by the real `docker create` | `--mount type=bind,src=/run/containerd/containerd.sock,dst=/x` (the container runtime's own control socket, equivalent in power to the Docker socket the list does name), `.../run`, `/home`, `/Users`, `/var/lib/containerd`, `/var/lib/kubelet`, and `/lib/modules` are all accepted: none of them is one of the eight listed roots and none contains the substring `docker.sock`. The builder's own legitimate mounts are all under paths the adapter itself constructs (`/workspace`, `/out`, named caches, the token file); an allowlist of permitted mount destinations/sources, rather than a denylist of a few roots, would close this class instead of enumerating it forever. | Either allowlist the mount sources the builder itself ever produces, or extend `DENIED_SOURCES` to the container-runtime sockets and home/user directories, recognizing that a denylist here will always be one root behind the next runtime. | `sandbox` |
| RR-12 | Low | Confirmed | `crates/sandbox/src/container/posture_args.rs:69-73` (`BOOLEAN`: no entry for `--init`, meaning `--init=false` is read as a value-bearing flag and never checked against `false`); `mount()` (no check that `dst` does not overlay a path the builder itself binds); no rule for `--tmpfs` option flags (`exec`, `suid`, `dev`) or for negative `--ulimit` values | `cargo test -p factory-sandbox --test security_rereview -- --ignored rr_12` | `--tmpfs /t:rw,exec,suid,dev` (an executable, setuid-honoring, device-bearing tmpfs — the strict posture's own `strict_posture` only checks `h.devices`/`h.sysctls`, not what a tmpfs option string says), `--ulimit core=-1`/`nproc=-1`/`nofile=-1`/`fsize=-1` (a negative limit, read by the shell/kernel as "unlimited" on some systems), and `--init=false` (silently disables the init process the builder asked for) all pass `denied_flag_in` unchanged. None of these is reachable through the builder's own `create_args` today (which hard-codes safe values), so this is defence-in-depth, the same severity class as the original SBX-1. | Add `--init` to a checked set requiring a truthy value (or boolean-absent), reject `--tmpfs` values containing `exec`/`suid`/`dev`, and reject a `--ulimit` value that is negative or the literal `unlimited`. | `sandbox` |
| RR-13 | Low | Hypothesis | `crates/sandbox/src/workspace/audit.rs:283-311` (`hides_text`: the Cf/Zl/Zp/tag ranges only; no-break space U+00A0, braille blank U+2800, ideographic space U+3000, thin space U+2009, variation selector U+FE0E and combining marks U+0300-0302 are not in the list) | `cargo test -p factory-sandbox --test security_rereview -- --ignored rr_13` | A file named with a trailing no-break space, an all-braille-blank name, or a name distinguished only by a combining-mark sequence prints as blank or near-identical to another name in a diff summary or PR file list, the same class of confusion the original SBX-2 targeted, but through characters that are not "format characters": I could not show this produces the kind of hidden-instruction or path-collision exploit the original finding demonstrated, only the visual-confusion mechanism. | Extend `hides_text` with the Zs (space separator) category beyond plain ASCII space, and the variation-selector and default-ignorable ranges `hides_text` currently omits (`U+FE00..FE0F`, `U+2065`), weighed against the existing note that emoji variation selectors must stay allowed; a person, not an automatic rule, may be the right owner of this trade-off. | `sandbox` |
| RR-14 | **High** | Confirmed | Mechanism: `infra/sandbox-images/lib/harden.sh:84-98` (execute-only is a property of the *file*, applied once at image build time; it governs who may *open* `/proc/<pid>/fd/1` of the *process currently holding* the pipe, not who may have opened it earlier). The adapters' own wrapper chain, `crates/runtime/src/command.rs:163-182` (`into_argv`: `env -i ... timeout ... <program>`), starts with the readable `/usr/bin/env`, which execs into the execute-only `timeout`, which execs into the execute-only tool — three processes sharing one pipe over the life of the exec, the first of which is readable. | Reproduced on real Docker against the unrebuilt pinned agent image with the execute-only modes applied by hand (matching `harden.sh` exactly): `/private/tmp/.../scratchpad/rr/racer.sh` (the hostile sibling, started before the exec), `/private/tmp/.../scratchpad/rr/exp_race.sh` (the driver: starts the sibling, waits 2s, then runs the real wrapper chain `env -i ... timeout -s INT -k 3 6 claude -p hi --output-format stream-json --verbose` and checks the captured stdout for the forged line). 8/8 trials forged. Not yet committed as a Rust test (see "What I could not verify," below, for why). | A sibling process, started by an earlier tool call in the same container and still running (a background job, a long `Bash` invocation whose own children survive, anything that watches `/proc`), can win the race to open the standard-output pipe while it is still held by the readable `env` process at the start of the *next* `docker exec`, and keep writing into it after `env` has exec'd into the execute-only chain. This defeats the central claim of the SBX-4 fix ("a tool that nobody can read has a stdout that `/proc` does not open") for any job whose turn is not the container's very first command — which, for a multi-turn agent run, is every turn after the first. | The fix needs to stop any process from acquiring the descriptor in the first place, not only stop it from acquiring it *after* the readable hand-off: either make `env` itself execute-only (it is a stock coreutils binary the image ships readable for other uses, so this needs its own audit of what else calls it), or stop wrapping through a readable program at all — redirect to a private path/fifo before the readable `env` ever runs, as the original review's own "smallest fix" for SBX-4 already proposes, independent of file modes. | `sandbox`, `runtime` |
| RR-15 | Medium | Confirmed | `infra/sandbox-images/check-pins.sh:70-78` (`verify_signature`: `gpg --status-fd 1 --verify` is asked only for a `VALIDSIG` line whose key matches the pinned fingerprint; `gpg` reports `VALIDSIG`/`GOODSIG` for a signature made by a revoked key exactly as it does for a live one, with no `REVKEYSIG` or expiry status checked) | `/private/tmp/.../scratchpad/rr/gpg_revoked.sh` (keys generated at run time with `gpg --batch --gen-key`, no network, no committed secret; signs a file, verifies it, revokes the key with `--gen-revoke`, imports the revocation, verifies the same signature again) | A signing key that is pinned by fingerprint but has since been revoked (compromised, rotated, or withdrawn by the upstream project) still produces a `VALIDSIG` for a signature it made before revocation, and `check-pins.sh`'s own filter accepts it as `OK`. This undercuts the IMG-2 fix's stated guarantee ("only a `VALIDSIG` by the pinned key counts") in exactly the scenario pinning-by-fingerprint is meant to survive: the pinned key going bad. | After a `VALIDSIG` match, also require that `gpg`'s status output contains no `REVKEYSIG` for that key and, if `gpg --with-colons --list-keys` reports the imported key's own validity as revoked or expired at verification time, treat the signature as failed. | image owner |

## Claimed negative tests, judged as a map

I read `crates/egress/tests/mutations.py`, `crates/sandbox/tests/mutations.py`, `crates/runtime/tests/mutations.py`
and `infra/sandbox-images/negative-tests.sh` against the fixes they claim to prove, and ran the Docker-free
ones (`mutations.py` for all three crates; `negative-tests.sh` needs a rebuild to show anything new since
the image was not rebuilt, so I ran only its self-test, `selftest-check-pins.sh`).

* **The egress and sandbox `mutations.py` scripts can fail, and for the right reason.** I confirmed this
  independently of the authors' own harness: `/private/tmp/.../scratchpad/rr/mutate_rr.py` applies four of
  my own temporary breaks to `crates/egress/src/broker/shape/{rules,json}.rs` (schema `$ref` check
  disabled, the `data:image/` prefix check removed, an unknown tag accepted instead of refused, duplicate-key
  detection disabled) and confirms each is caught by my *own* new tests, which gives independent evidence
  that the schema's tests (both the author's and mine) are not vacuously passing. I did not re-run every one
  of the author's ~20 `mutations.py` entries by hand; I spot-checked the four above because they sit closest
  to the property I most wanted to trust.
* **`negative-tests.sh`'s own self-test holds.** `selftest-check-pins.sh` passed all nine of its own cases
  (base-image digest mismatches, an empty pin, no Docker daemon, a signature by a non-pinned key in the
  downloaded key file, a signature by the pinned key). This is the harness that stops `check-pins.sh`'s
  mutation-counting from being circular, and it is itself sound for the cases it covers — but see RR-15: none
  of its nine cases is a revoked key, so the harness's own blind spot matches the defect's.
* **`infra/sandbox-images/negative-tests.sh`'s `expect_failure` logic (the `UNPROVEN`-vs-`CAUGHT` distinction
  IMG-5 added) is sound on paper**: it requires the mutant's `FAIL` line to name the specific marker the
  mutation introduced, and separately requires that marker to be absent from the real image's own `FAIL`
  line for the same rule, so a rule that is already red on the real image cannot make an unrelated mutation
  look caught. I did not run it against the live images (that needs a rebuild to show anything beyond what
  the fix's own reproduction already recorded), so this is read-and-reasoned-about, not freshly run.
* I found no test, among the ones I ran, that passes only because an earlier unrelated check already
  stopped the scenario.

## What I tried that held (not already listed as HOLDS above)

* The broker's listener itself: method override headers (`X-HTTP-Method-Override`, `X-Method-Override`,
  `X-HTTP-Method`) never change the method the broker treats the request as; HTTP/1.0 and HTTP/2.0 request
  lines are refused; a wildcard `*` request-target, a fragment, and backslash path-traversal attempts are
  all refused before any body is read.
* The relay's address-form coverage against hand-built IPv6 encodings of 20 different IPv4 bases across 9
  encodings each (180 combinations), plus `febf::1` (the top of the `fe80::/10` link-local range, correctly
  refused) and multicast (`ff02::1`), ULA (`fd00:ec2::254`) and a second private-looking rebinding target
  (`fd12:3456::1`), all correctly refused.
* Docker's own CLI refuses every malformed or abbreviated flag spelling I tried before the daemon is ever
  asked (`--cap-ad`, `--cap_add`, `--CAP-ADD`, `--priv`, `--PID=host`, `-privileged`, `--security-opts`,
  `--privileged=yes`), which is why the deny list does not need to special-case them — I checked this against
  the live daemon rather than assuming it.
* The image's own fsaudit script correctly flags a world-writable file outside the sticky directories, a
  non-0711 agent tool, and the new `sfat_` pattern in both a small text file and inside a synthetic ELF
  binary, on a tar stream I built by hand (not a rebuilt image).

## New findings table (short form)

| ID | Severity | Confirmed/Hypothesis | Impact | Smallest fix | Owner |
| --- | --- | --- | --- | --- | --- |
| RR-1 | Medium | Confirmed | Unbounded OpenAI output-token/cost per request | Insert the cap when the field is absent on OpenAI routes too | egress |
| RR-2 | Low | Confirmed | 1-hour cache write billed at the 5-minute rate | Refuse `ttl:"1h"`, or price it separately | egress |
| RR-5 | Low | Confirmed | A few IANA special-purpose ranges missing from the deny list | Add `168.63.129.16/32`, `192.0.0.0/24`, `fec0::/10` | egress |
| RR-6 | Low/Medium | Confirmed | No cap on the number of JSON values read per body (218 MB for an 8 MiB body) | Cap total values parsed, not only depth | egress |
| RR-7 | Medium | Confirmed | A torn terminal line plus a forged one is a success | Refuse success when malformed lines were seen | runtime |
| RR-8 | Medium | Confirmed | A truncated stream with an early forged terminal event is a success | Check `stdout_truncated` on the success path | runtime |
| RR-10 | Medium | Confirmed | Mount-key case folding lets the wrong source be checked | Case-fold mount keys, take the last occurrence | sandbox |
| RR-11 | Medium | Confirmed | The host-path denylist misses the runtime socket and home directories | Allowlist mount sources, or extend the denylist | sandbox |
| RR-12 | Low | Confirmed | Weakening values of already-allowed flags are not read | Check `--init`, `--tmpfs` options, negative `--ulimit` | sandbox |
| RR-13 | Low | Hypothesis | Names that print blank or identical pass the audit | Extend `hides_text`'s character classes | sandbox |
| RR-14 | **High** | Confirmed | A sibling that pre-exists the exec forges the stream of every turn after the first | Stop wrapping through a readable `env`, or redirect to a private path | sandbox, runtime |
| RR-15 | Medium | Confirmed | `check-pins.sh` accepts a signature by a revoked pinned key | Check for `REVKEYSIG` / key validity after a `VALIDSIG` match | egress |

## Reproducing each confirmed defect

```text
# RR-1, RR-2, RR-5, RR-6 (egress): Cargo tests, no Docker
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-egress --test security_rereview -- --ignored rr_1
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-egress --test security_rereview -- --ignored rr_2
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-egress --test security_rereview -- --ignored rr_5
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-egress --test security_rereview -- --ignored rr_6_a_body

# RR-7, RR-8 (runtime): Cargo tests, no Docker
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-runtime --test security_rereview -- --ignored rr_7
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-runtime --test security_rereview -- --ignored rr_8

# RR-10, RR-11, RR-12 (sandbox): Cargo tests, no Docker (pure functions)
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-sandbox --test security_rereview -- --ignored rr_10
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-sandbox --test security_rereview -- --ignored rr_11
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-sandbox --test security_rereview -- --ignored rr_12

# RR-13 (sandbox): Cargo test, no Docker, writes empty files in a scratch directory
CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
  cargo test -p factory-sandbox --test security_rereview -- --ignored rr_13

# RR-14: not a committed Rust test (see "What I could not verify"). Reproduced by hand against the
# real, unrebuilt pinned agent image with the execute-only modes of harden.sh applied manually:
docker run -d --pull never --name rr-sbx4 --label factory.test=true --user 0 --network none \
  --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \
  --security-opt no-new-privileges --pids-limit 256 --memory 1g --init --log-driver none \
  --tmpfs /home/agent:rw,mode=0700,uid=10001,gid=10001,size=64m --tmpfs /tmp:rw,mode=1777,size=64m \
  --entrypoint sleep factory-sandbox/agent:rust1.98.0-claude2.1.311-codex0.163.0 3000
docker exec rr-sbx4 chmod 0711 /usr/local/bin/claude /opt/codex/bin/codex \
  /opt/codex/bin/codex-code-mode-host /usr/bin/timeout
# then run the sibling (opens the exec's fd 1 before the tool starts) concurrently with the real
# wrapper chain `env -i ... timeout ... claude ...`; the forged line reaches the captured stdout.
docker rm -f rr-sbx4

# RR-15: not a committed Rust or shell test in the repository (check-pins.sh is POSIX sh with no
# test harness of its own besides selftest-check-pins.sh, which this defect's case is not yet
# added to). Reproduced with throwaway keys made at run time, no network:
#   generate an ed25519 key, sign a file, verify it (VALIDSIG), revoke the key with
#   `gpg --gen-revoke`, import the revocation, verify the same signature again: gpg still reports
#   VALIDSIG/GOODSIG for the now-revoked key, which is exactly what check-pins.sh's filter accepts.
```

## What I could not verify, and why

* **RR-14 as a committed Rust integration test.** The existing `sbx_4_a_tool_that_nobody_can_read_...`
  test already builds a container by hand (not through `DockerSandboxProvider`) because a bind mount from
  a macOS host cannot be made execute-only; RR-14 needs the same hand-built container *and* a hostile
  process racing the start of a fresh `docker exec`, which the sandbox test harness's `Lab`/`DriftRunner`
  abstractions do not expose a seam for (they run commands through the adapter's own `SandboxSession::exec`,
  which starts after the race window this defect depends on). I reproduced it with shell scripts against
  the real daemon (above) rather than fabricating a Rust harness that would not actually exercise the
  adapter's own code path. I recommend the sandbox owner add a seam for "start a sibling exec, then start
  the tool's exec, with a controlled delay" before writing the permanent regression test; I did not have
  that seam available without changing production code, which is outside my mandate.
* **RR-15 against the real GitHub/crates.io/npm signing infrastructure.** I used throwaway keys generated
  locally; I did not check whether the actual pinned release keys (Claude Code's, Rust's) are ever rotated
  in a way that would make this reachable in practice, only that the script's own logic accepts a revoked
  key's signature when one exists. No network was used.
* **Whether RR-6's memory cost matters at the server's real concurrency limits.** I measured one parse in
  isolation (one process, one body) and did not drive 64 concurrent connections each holding an 8 MiB
  adversarial body through the real `BrokerServer` to see what the host actually does under that load; I
  report the per-parse number as a fact and the aggregate risk as untested.
* **SBX-3.** Not re-exercised; see the verdict table. The first review's own open question (hand-run
  container vs. the real provider pipeline) is unresolved by me too.
* **Everything the first review already listed as unverifiable** (kernel-level isolation claims beyond
  what a Docker Desktop Linux VM shows; a real, un-sandboxed CLI's default tool-use behaviour against a
  live provider; the redactor's full canary sweep; authority/webhook/tenant isolation; the host tool
  bridge) — I did not revisit any of these; they were out of this task's assigned scope.
* **The rest of the image tooling blast-radius list** (IMG-4 through IMG-11 of the first review's "Status
  after fixes" section, `images_json.py`'s own correctness beyond what `selftest-check-pins.sh` exercises):
  read, not independently attacked. I prioritized egress bypass and credential theft first, as instructed,
  and spent the remaining budget on the runtime/sandbox race (RR-14) once it surfaced, because it undercuts
  the single highest-severity claim in the "Status after fixes" section.

## Docker cleanup

`docker ps -a`, `docker network ls`, `docker volume ls` were compared by exact name/ID list three times:
before any Docker command of mine, right after the interactive container experiments (containers
`338271789a31` and `rr-sbx4-b`, each created and removed with `--label factory.test=true --label
factory.test_run=rr-review`, never a named volume or a network), and again at the end of the review.
Containers and networks show zero difference across all three snapshots. Volumes show zero difference
between the first two snapshots, but the final snapshot has 11 more anonymous volumes
(`labels=map[com.docker.volume.anonymous:]`, no `factory.test` or other label of mine) than the second
one. They appeared in a 15-second window that falls inside the span of the verification commands (`cargo
fmt`, `cargo clippy`, `cargo xtask check-architecture`, the secret scan, and the final combined `cargo
test` run), none of which invoke Docker from any code I wrote or touched, and the agent image declares no
`VOLUME` that container creation could have triggered. I could not connect them to any command of mine,
and nothing identifies them as mine, so, per the constraint to remove only what can be proven mine, I did
not remove them. No image was built or pulled; the three pinned images already on the host were read
from, never modified.

## Status after fixes

Written by the software engineer who made the fixes, not by the reviewer; the reviewer's text above is
unchanged. A re-review follows and decides what is closed. Base: `feat/slice-0-foundation` at `9da293e`.
Date: 2026-10-29.

| ID | Status | What was done | Tests (each was `#[ignore]`d or is new) |
| --- | --- | --- | --- |
| RR-14 (a) | **Fixed in the recipe; image not rebuilt** | `infra/sandbox-images/lib/execute-only.txt` is the one list of the programs of the adapters' command chain (`/usr/bin/env`, `/usr/bin/timeout`, `claude`, `codex`, `codex-code-mode-host`). `harden.sh` sets mode 0711 on every line; `test.sh` rule `TOOLS-EXECUTE-ONLY` checks each with `stat` in the built image; a runtime test requires every program that `command.rs` puts in a command vector to be on the list. | `crates/runtime/tests/execute_only_chain.rs` (`a_hostile_process_that_exists_before_the_exec_cannot_forge_a_line_through_the_chain`, `every_program_the_adapters_put_in_a_command_vector_is_execute_only`, `harden_sh_reads_the_list_and_keeps_none_of_its_own`); `infra/sandbox-images/tools/selftest-execute-only.sh` |
| RR-14 (b) | **Fixed** | A run is a success only when the model broker, outside the sandbox, saw it end (see below). New port `TurnAttestation`. | `crates/runtime/tests/stream_rule.rs` (attestation tests), `crates/egress/tests/turn_attestation.rs`, `attest::tests` |
| RR-7, RR-8 | **Fixed** | Any malformed line before the terminal event, a cut capture, a second terminal event or any line after it fails the run with a fixed reason. | `rr_7_...`, `rr_8_...` in `crates/runtime/tests/security_rereview`; `stream_rule.rs` properties |
| RR-9 | **Fixed** (it was a hypothesis) | The Codex rule reads the signal as the Claude rule does. | `rr_9_...` |
| RR-1 | **Fixed** | An OpenAI request with no output limit gets the cap, in `max_output_tokens` (Responses) or `max_completion_tokens` (Chat). The recorded Codex requests name none, so the real tool is affected: the unchanged-body test now expects the cap. | `rr_1_...` |
| RR-2 | **Fixed by refusing** | `cache_control.ttl` is `5m` or absent; `1h` is refused by the schema, because the price list has one cache-write rate and the usage report cannot tell the two apart, and the factory does not need the longer cache. | `rr_2_...` |
| RR-5 | **Fixed** | `168.63.129.16/32`, `192.0.0.0/24`, `fec0::/10` joined `DEFAULT_DENY_RANGES`. | `rr_5_...` |
| RR-6 | **Fixed** | The reader counts values as each starts and refuses past 100000 in all or 10000 in one array or object, before the tree is built (new class `too_many_values`). The recorded bodies hold about 2000 values at most. | `rr_6_...`, `json::tests::a_body_past_the_value_limits_is_refused_before_it_is_built` |
| RR-10 | **Fixed** | `--mount` keys are lower-cased as Go's `ToLower` does, the last `src`, `dst` and `type` wins, an unknown key, a quote or a non-bind type is refused. | `rr_10_...`, `posture_args::tests` |
| RR-11 | **Fixed** | The second look at the `docker create` vector allows a bind mount only as a (source, destination) pair derived from the spec and the plan (`allowed_binds`); the old roots stay as a second line. | `rr_11_...`, `posture_args::tests`, `scripted::denied_flags_are_never_emitted` |
| RR-12 | **Fixed** | `--init=false`, a `--tmpfs` with `exec`/`suid`/`dev` or at another path, a negative or non-numeric `--ulimit`, two mounts at one destination are refused. The builder's tmpfs is `noexec`, so nothing allows `exec`. | `rr_12_...` |
| RR-13 | **Partly fixed** | Refused: a name that begins or ends in a space-like character, the braille blank, a variation selector with no base, more than two stacked Latin combining marks. Not refused, on purpose: a non-ASCII space inside a name (the ideographic space is how Japanese names are written; it is logged), a name not in NFC (the standard library has no tables, and a dependency was not added for a hypothesis). The original test is split in two to say so. | `rr_13_...` (two tests), `audit::tests` |
| RR-15 | **Fixed** | `check-pins.sh` needs `GOODSIG` and a `VALIDSIG` of the pinned key, none of `REVKEYSIG`, `EXPKEYSIG`, `EXPSIG`, `KEYREVOKED` and the other bad statuses, and no status line it does not know. | `tools/selftest-check-pins.sh` (a really revoked key, an expired key, a control, a table of status lines) |
| SBX-3 | **Still not reproduced** | See below. | none added |
| RR-3, RR-4 | **Untouched** | Hypotheses outside the order of this change; still `#[ignore]`d and still failing. | `rr_3_...`, `rr_4_...` |

### A correction to the reproduction of RR-15

The finding is real, but its reproduction (`gpg_revoked.sh`) never revoked the key: `gpg --batch --gen-revoke`
answers "can't do this in batch mode", the revocation file was not made, and `gpg --list-keys` after the
"revocation" shows an ordinary key. The `GOODSIG` it printed was the status of a live key. With a key that is really
revoked (a revocation made with `--no-tty` and the answers on standard input, and checked with `--with-colons`),
gpg 2.5.24 prints `REVKEYSIG`, `VALIDSIG`, `KEYREVOKED`: `VALIDSIG` of the pinned fingerprint is still there, which
is what the old rule accepted. The self-test makes the revoked key this way and fails if gpg does not list it as revoked.

### RR-14, what closes it and what does not

**Part a, the window.** The pipe of one `docker exec` is held by `env`, then `timeout`, then the tool. The kernel
closes `/proc/<pid>/fd/1` of a process started from a file nobody can read, but a descriptor opened while a readable
program held the pipe stays valid across the `execve` calls that follow. With `env` execute-only, no process of the chain
is ever dumpable, so there is no moment at which the pipe can be taken. Shown on a container of the pinned agent image with
the modes of the list applied at start (not a rebuilt image: the images in the local store predate even the first version of
the recipe, their tools are mode 0755, and a rebuild needs the network for the pinned downloads, which this change was not
allowed): a racer started before the exec, looping over `/proc` in bash builtins, opens the output of every process
that appears after it. With `env` left readable it forged lines on the first trial (and in 3 of 3 trials of the hand-run); with
the list applied, 4 trials of about nine thousand refused open attempts each forged nothing, and the chain really ran
(the real `claude` printed its init event). `test.sh --rule TOOLS-EXECUTE-ONLY` fails against the local image, as it should,
until it is rebuilt.

**Part b, the broker's word.** Before the tool starts the adapter takes a `TurnSummary` from the broker for the job
token; after the tool ended it takes another. The run is a success only if, between the two: no request is in flight (it
waits up to 2 seconds for one to settle), the broker admitted a request and read an answer, the most recent answer ended the turn
(`end_turn`/`stop_sequence`, Responses `completed` with no call item, Chat `stop`), and the stream does not claim more
messages than the broker read answers plus 2, nor more input or output tokens than the broker metered plus 10 percent and 256 tokens. The broker may
have metered more than the stream says (side requests), never less. Otherwise the run fails as `OutputMissing` with the code
`unattested_completion` or `claim_exceeds_ledger` in the transcript note. A broker that cannot answer before the run keeps
the tool from starting (`ProviderUnavailable`); one that cannot answer after it leaves the run unattested. The broker settles
a streamed answer before the last bytes reach the tool.

What it does not cover: **the content of the final text**. A process that can alter the stream of a run that really ended can still
replace the text with its own; the attestation removes the cheaper attack (a forged "completed" in a run that did not complete or
never reached the model). Binding a digest of the last answer to the output was not done, because the tools reformat the text. It
also trusts the broker's reading of the provider's stop reason, and it needs `ClaudeCodeRuntime::new` and `CodexRuntime::new`
to be given the broker (a third argument), which the worker wiring does not do yet: see the report of this change.

### SBX-3, the discrepancy

Not reproduced, and the hand-run no longer reproduces either. Through `DockerSandboxProvider` a held process table
(`pids.current` 25 against `pids.max` 24, the shell alive and blocked on a builtin `read`) did not stop `docker exec ... du` from
working. The review's hand-run was repeated with its own flags and its own script on the same daemon: `docker exec cat
/sys/fs/cgroup/pids.current` printed 25 three times out of three; none failed with "unable to spawn stage-1". The two observations
agree with each other and not with the review's note. Why the review saw the failure is not known; a different `runc` in the
Desktop VM at that time is the guess, and it is only a guess. No code was added; the fail-closed rule (three failed polls kill
the container) stays as the defence.

### What remains open

* The agent image is not rebuilt, so `test.sh` fails `TOOLS-EXECUTE-ONLY` and `negative-tests.sh` reports `readable-env` and
  `readable-tool` as `UNPROVEN` until someone with network access runs `build.sh`.
* The content of the final text is not bound to the broker's record.
* RR-3 and RR-4 (hypotheses) and the non-NFC part of RR-13.
* `TurnAttestation` is pending architect confirmation (`ports-v1.1.md` section 16).

### Deliberate breaks, shown caught

Each was applied to the source, the tests were run, and the source was restored. The harnesses are
`crates/{runtime,egress,sandbox}/tests/mutations.py` (new entries), plus two by hand for the Docker test and the pin check.

| Break | Caught by |
| --- | --- |
| a readable `/usr/bin/env` left in the exec chain (removed from `execute-only.txt`) | the Docker test (`forged 11 line(s) into the output of the chain`), `every_program_the_adapters_put_in_a_command_vector_is_execute_only`, the list test; the control of the same test shows the race forges when `env` is readable |
| success accepted without the broker's word (`attestation-skipped`) | six tests of `stream_rule.rs` |
| a torn line before the terminal event ignored (`stream-torn-line-ignored`) | `a_line_torn_by_an_interleaved_write_never_makes_a_success`, `each_fault_of_a_stream_has_its_fixed_reason_in_the_transcript` |
| the cut capture ignored (`stream-cut-capture-ignored`) | `a_cut_capture_is_never_a_success`, the fault table |
| the whole stream rule off (`stream-rule-off`) | `rr_7_...`, `rr_8_...`, `rtm_1_...` and five tests of `stream_rule.rs` |
| the OpenAI route without a cap (`openai-request-without-a-cap`) | `rr_1_...`, the unit test, the unchanged-body test |
| `SRC=` after `src=` not read (`a-mount-key-in-another-case`, `the-first-mount-source-wins`) | `posture_args::tests` |
| a source outside the allowlist (`a-source-outside-the-allowlist`) | `rr_11_...`, three unit tests |
| a revoked-key signature accepted (the old VALIDSIG-only rule restored in `check-pins.sh`) | the real revoked key, the real expired key, and seven status-line cases of `selftest-check-pins.sh` |

The others (`a-tmpfs-with-exec`, `a-negative-ulimit`, `init-switched-off`, `a-name-that-ends-in-a-blank`,
`a-variation-selector-with-no-base`, the three relay ranges, `accept-a-one-hour-cache-write`,
`json-reader-without-a-value-limit`, `broker-attests-a-tool-use-turn`, `attestation-ignores-the-last-answer`, `-the-baseline`
and `-the-claim`, `codex-success-ignores-the-signal`) are in the same harnesses and were each CAUGHT.

### Commands and results

```text
cargo fmt --all -- --check                                              clean
cargo clippy --workspace --all-targets --locked -- -D warnings          clean
cargo test -p factory-egress -p factory-sandbox -p factory-runtime \
  --test security_rereview -- --ignored                                 only rr_3 and rr_4 (hypotheses, untouched) still fail
cargo nextest run -p factory-egress -p factory-sandbox -p factory-runtime   518 tests; all pass (two real-Docker contract tests failed once
                                                                        because a stand-in broker did not grow between two runs;
                                                                        fixed in the stand-in, then both pass)
cargo xtask check-architecture                                          passed
cargo deny --locked check                                               advisories, bans, licenses, sources ok
infra/sandbox-images/tools/selftest-check-pins.sh                       PASSED (revoked key, expired key, control, status table)
infra/sandbox-images/tools/selftest-execute-only.sh                     PASSED
infra/sandbox-images/test.sh --only agent --rule TOOLS-EXECUTE-ONLY     FAIL against the local image, as it must (all five programs 0755)
infra/sandbox-images/negative-tests.sh --only readable-env              UNPROVEN, as it must be until the image is rebuilt
```

Docker cleanup: containers and networks identical before and after. The volume list grew by 48 anonymous
volumes with no label (created in four bursts while the suites ran). None of the three images the tests use
(`factory-sandbox/agent`, the stand-in sidecar, `python:3.13-alpine`) declares a volume, no container mounts
them, and other stacks on the machine were restarting containers at the time, so they cannot be shown to be
mine and were not removed.
