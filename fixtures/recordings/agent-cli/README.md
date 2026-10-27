# Agent command line tool recordings

This directory holds the evidence for the report `docs/spikes/agent-runtime.md` (work package `s0-agent-runtime-spike`). It records how Claude Code 2.1.311 and Codex 0.163.0 behave when they run inside the hardened container profile of `docs/security/sandbox-policy.md` and talk to a labelled fake model provider.

Everything here is labelled. **No recording contains a real model answer, a real credential or a live-provider result.** The model is `fake/fake_provider.py`. The key is a throwaway string that the harness generates at run time and deletes afterwards. Nothing was read from `~/.claude`, `~/.codex`, the keychain or any host environment variable.

## What is in this directory

| Path | What it is |
|---|---|
| `manifest.json` | One entry per recording: tool, version, exact `docker run` command (key removed), exit code, duration, network mode, fidelity label and the SHA-256 of every file. |
| `check_manifest.py` | Checks the manifest: required keys, pinned versions, hashes, no real fidelity, no secret-shaped text. Run `python3 -I fixtures/recordings/agent-cli/check_manifest.py`. |
| `runs/<case id>/` | One folder per case: `case.json`, `stdout.txt`, `stderr.txt`, `provider-requests.jsonl` (what the fake provider received), `sinkhole.jsonl` (names the tool tried to reach), `workspace-changes.json`, and where useful `footprint.txt` (files left in the writable mounts, peak memory and process counts) and `bridge-calls.jsonl`. |
| `images/` | `Dockerfile.claude` and `Dockerfile.codex`: scratch images built from the official release channels, each with a checksum check. |
| `fake/` | `fake_provider.py` (Anthropic Messages and OpenAI Responses streaming), `sinkhole.py` (DNS and TLS name logger) and `fake_mcp_bridge.py` (a stand-in for the factory tool bridge). All three carry a "fidelity: fake" label. |
| `harness/` | `spike.py` (starts the fake world and runs cases), `cases.py` (the `Case` class and the case list), `wrap.sh` (writes the footprint file). |

How the recordings are cleaned. The harness replaces the run-time key, the planted `.env` value and anything shaped like a token before it writes a file. The provider log keeps request bodies as short prefixes plus length and SHA-256, so it holds no long repository content. Full request bodies stay in the scratch directory and are not committed.

## What you need

- Docker with a Linux engine. The recordings used Docker 29.5.2 on Ubuntu 24.04, kernel 6.8, `runc` 1.3.5, AppArmor and seccomp active, in a dedicated Colima virtual machine (`colima start ars-spike --vm-type vz --cpus 4 --memory 6 --disk 20 --activate=false --mount <scratch run dir>:w`). Docker Desktop also works for everything except the AppArmor line.
- Python 3.12 or newer, with the standard library only.
- `specify` 1.1.2 on the PATH, for the Spec Kit skill cases. The harness runs `specify init` and `specify integration install codex` in a scratch folder.
- Network access, only for building the two images and for `extract-binaries` (it downloads one release asset and checks its SHA-256).

## Reproduce

Run these from the repository root. `SCRATCH` is any empty directory outside the repository.

```bash
export SCRATCH=/path/to/empty/scratch
export ARS_RUN_DIR="$SCRATCH/run"
export DOCKER_HOST=unix://$HOME/.colima/ars-spike/docker.sock   # skip this line to use the default engine

# 1. Build the two scratch images. Each build checks a published checksum.
docker pull alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
mkdir -p "$SCRATCH/empty"
docker build -f fixtures/recordings/agent-cli/images/Dockerfile.claude -t ars-claude:2.1.311 "$SCRATCH/empty"
docker build -f fixtures/recordings/agent-cli/images/Dockerfile.codex  -t ars-codex:0.163.0  "$SCRATCH/empty"
docker pull python:3.13-alpine   # runs the fake provider and the sinkhole

# 2. Start the fake world: an internal network, the fake provider, the sinkhole and the fake bridge.
python3 fixtures/recordings/agent-cli/harness/spike.py world-up
python3 fixtures/recordings/agent-cli/harness/spike.py extract-binaries

# 3. Run cases. Use one id, a prefix ending in *, or all.
python3 fixtures/recordings/agent-cli/harness/spike.py list
python3 fixtures/recordings/agent-cli/harness/spike.py run claude-turn-env codex-turn-custom-provider
python3 fixtures/recordings/agent-cli/harness/spike.py run "claude-skills-*"
python3 fixtures/recordings/agent-cli/harness/spike.py run all
python3 fixtures/recordings/agent-cli/harness/spike.py image-facts

# 4. Check the manifest.
python3 -I fixtures/recordings/agent-cli/check_manifest.py

# 5. Clean up. This removes every container, the network and the generated key.
python3 fixtures/recordings/agent-cli/harness/spike.py world-down
docker rmi ars-claude:2.1.311 ars-codex:0.163.0
```

A full `run all` takes about twenty minutes, mostly in cases that wait for a timeout on purpose. Outputs differ between runs in session identifiers, timestamps and durations. The findings do not.

## Where each claim is recorded

The question numbers are those in the report.

| Question | Cases to read |
|---|---|
| 1. Install, size, runtime | `claude-image-facts`, `codex-image-facts`, `claude-posture`, `codex-posture`, `claude-bare-image-version`, `claude-bare-image-turn`, `codex-bare-image-version`, `codex-bare-image-turn` |
| 2. Start under the hardened profile, files written | `claude-version`, `codex-version`, `claude-turn-env` and `codex-turn-custom-provider` (read `footprint.txt`), `claude-ro-home`, `codex-ro-home`, `claude-git-masked`, `codex-git-check-default` |
| 3. Base URL and the request each tool sends | `claude-turn-env`, `claude-baseurl-settings`, `codex-baseurl-env-ignored`, `codex-baseurl-builtin-openai-key`, `codex-baseurl-builtin-codex-key`, `codex-turn-custom-provider` (read `provider-requests.jsonl`) |
| 4. Other hosts and how to switch them off | `claude-turn-env`, `claude-bare-turn`, `claude-egress-disable-telemetry`, `claude-egress-minimal`, `claude-telemetry-file-keys`, `codex-turn-custom-provider`, `codex-egress-*`, `claude-unreachable`, `codex-unreachable`, `codex-unreachable-bounded` (read `sinkhole.jsonl`) |
| 5. Credentials | `claude-turn-env`, `claude-auth-*`, `codex-baseurl-builtin-*`, `codex-auth-*`, `claude-toolenv-*`, `codex-toolenv-*` |
| 6. Skills, slash commands, repository configuration | `claude-skills-*`, `codex-skills-*`, `claude-hostile-*`, `claude-docs-*`, `codex-hostile-*`, `codex-docs-*` |
| 7. Headless contract | `claude-fmt-*`, `claude-stdin-stream-json`, `claude-tool-turns`, `claude-max-*`, `claude-loop-revoked`, `claude-http-*`, `claude-cancel-*`, `claude-struct-*`, `claude-schema-matrix`, `codex-fmt-text`, `codex-last-message`, `codex-tool-turns`, `codex-loop-no-cap`, `codex-http-*`, `codex-cancel-*`, `codex-struct-*`, `codex-schema-matrix` |
| 8. Permission model | `claude-perm-*`, `codex-perm-*` |
| Host tool bridge | `claude-bridge-*`, `codex-bridge-*` |
| The proposed flag sets, in a hostile workspace | `claude-factory-profile`, `claude-factory-profile-spec`, `codex-factory-profile`, `codex-factory-profile-spec` |
| Vendor proxy asset (help text only) | `codex-responses-proxy-help` |

## Directives for the fake provider

A prompt can carry one directive. The provider answers it and ignores everything else in the request, so extra helper requests from a tool cannot disturb a test.

| Directive | Effect |
|---|---|
| `FAKE:TOOL <name> <json>` | Answer with one tool call. For Codex's `exec` tool the input is raw JavaScript. After the tool result returns, the provider answers with a text summary of the result. |
| `FAKE:LOOP <n> <name> <json>` | Keep calling the tool until `n` tool results are in the conversation, then answer HTTP 401 like a broker that revoked the job token. |
| `FAKE:HTTP <status>` | Answer with that status and a provider-shaped error body. |
| `FAKE:SLEEP <seconds>` | Start the stream, wait, then finish. Used for cancellation. |
| `FAKE:STRUCT` and `FAKE:STRUCT_BAD` | Answer with a valid or an invalid gate report. |

Fixed usage numbers (1234 input, 56 output, 7 cache write, 89 cache read tokens) let a reader see which usage fields each tool reads and how it adds them up.
