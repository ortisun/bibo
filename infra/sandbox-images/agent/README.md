# The agent image

`factory-sandbox/agent` runs the agent profile: the Claude Code or Codex command line tool and every command it asks for, together, in one container (ADR 0005, Model A). The container is the boundary, so this image is built to be a poor place to attack from: no git, no package manager, no network client, no setuid file, nothing writable, and no credential.

## What is in it

| Part | Version | Source and integrity check |
|---|---|---|
| Debian 13 userland, `gcc`, `libc6-dev`, CA certificates, `rustc` and `cargo` | Rust 1.98.0 | the official `rust:1.98.0-slim-trixie` image, pinned by index digest |
| `clippy`, `rustfmt` | 1.98.0 | Rust dist archives, SHA-256 pinned |
| `claude` at `/usr/local/bin/claude` | 2.1.311 | `https://downloads.claude.ai/claude-code-releases/2.1.311/linux-<arch>/claude`, SHA-256 pinned. Anthropic signs the manifest that lists this checksum; `check-pins.sh` verifies the signature |
| `codex`, `codex-code-mode-host`, `rg` under `/opt/codex` | 0.163.0 | the npm platform package `@openai/codex@0.163.0-linux-<arch>`, SHA-256 pinned, plus a second check of `bin/codex` after unpacking |
| One user, `agent`, uid and gid 10001, home `/home/agent` (empty) | | created by `lib/harden.sh` |

`PATH` is the only environment variable the image sets: `/opt/rust/bin:/opt/codex/codex-path:/opt/codex/bin:` and the usual system directories.

### How the host installed the tools, and how the image does

| Tool | Host | Image |
|---|---|---|
| Claude Code 2.1.311 | The native installer (`https://claude.ai/install.sh`) put the binary in `~/.local/share/claude/versions/2.1.311`. Its SHA-256 equals the `darwin-arm64` checksum in the release manifest. | The same release manifest, the `linux-arm64` (glibc) checksum, downloaded by BuildKit with `ADD --checksum`. |
| Codex 0.163.0 | `npm install -g @openai/codex`, which pulls the platform package `@openai/codex@0.163.0-darwin-arm64`. | The platform package for Linux, taken from the npm registry with `ADD --checksum`. No Node, no npm. |

### Differences from the spike images, and why

The recipes in `fixtures/recordings/agent-cli/images/` are the model for this image: same release channels, same checksum discipline, same user id, same working directory. These things differ.

| Spike image | This image | Why |
|---|---|---|
| Alpine 3, BusyBox, `apk add bash ca-certificates libgcc libstdc++` | Debian 13 from the official Rust image, GNU userland | The image must also hold a C linker and the Rust toolchain. Alpine's BusyBox is one program that carries `wget`, `nc`, `telnet` and a shell, and deleting its links removes nothing, so "no network client" cannot be enforced there. `apk add` also takes whatever version is current. The Rust image is pinned whole by digest, and its glibc matches the CI runner. |
| Claude Code `linux-arm64-musl`, SHA-256 `172150e3...09b9` | `linux-arm64` (glibc), SHA-256 `2e2496c9...61f3` | Debian is glibc. Same release manifest, same version. |
| Codex files copied into `/opt/codex`, including `bwrap` | The same files, **without `bwrap`** and without the voice libraries | `bwrap` is Codex's own sandbox helper. It cannot start under the default seccomp profile (spike section 4.8), and it is a program built to create namespaces. Every Codex sandbox mode already fails closed without it. |
| `ENTRYPOINT` set to the tool | No entrypoint, no command | The supervisor passes the argument vector. |
| Checks `sha512` of the npm tarball | Checks the `sha256` of the same tarball | BuildKit's download check supports SHA-256 only. For arm64 the SHA-256 was computed from the registry file and equals the digest GitHub lists for it. |

What the spike proved on Alpine does not automatically carry over to Debian for Claude Code. `claude --version` and the posture rules below pass here. A headless turn against the fake provider under the hardened profile was **not repeated** on this image. See "Not verified".

## The shell, and why it stays

The tools run the commands the model asks for through a shell: Claude Code's `Bash` tool, Codex's shell tool, and the Spec Kit helper scripts all need `bash` (spike section 4.1). So this image keeps `bash` and `sh` (which is `dash`). Everything else that is a shell is removed (`lib/shells.txt`): `rbash`, `ash`, `zsh`, `busybox`, and the rest. `test.sh` (rule `SHELLS`) fails if the image holds any other.

## What is not in it

- No git, no GitHub command line, no package manager (`apt`, `dpkg`, `rustup`, `pip`, `npm`), no `curl`, `wget`, `ssh`, `nc`, no `python`, `perl`, no `su`, `mount` or account tools (`lib/forbidden-binaries.txt`). Cargo stays, as the build tool. The agent profile reaches only the model broker, so it cannot fetch a crate either.
- No setuid or setgid file.
- No hook, MCP server, settings file, instruction file or skill. The home directory is empty, and the supervisor puts a tmpfs over it. Skills for the specification stage are mounted by the supervisor, read-only, at `~/.claude/skills/speckit-<name>`, and the specification stage needs no other file (spike section 4.6).
- No credential. The job token is a file the supervisor mounts at `/run/secrets/job_token`.

## What the adapter must do for these tools

These come from the spike (`docs/spikes/agent-runtime.md`) and are not enforced by the image.

- Mount a **writable, `noexec` tmpfs at `/home/agent`** and set `HOME`. Codex fails with "Read-only file system" without one. Do not bind-mount anything below `~/.codex`; the parent directories would belong to root and Codex fails with "Permission denied".
- Use `--setting-sources user` and `--strict-mcp-config` for Claude Code, and the Codex switches of spike section 6.1. The image holds no configuration that could replace them.
- Deliver the job token with `apiKeyHelper` or `auth.command`, never as an environment variable.
- Do not set `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`. It needs bubblewrap, which this image does not hold, and the tool stops.

## Build and test

```sh
infra/sandbox-images/agent/build.sh         # builds and records the digest in images.json
infra/sandbox-images/test.sh --only agent   # posture tests
infra/sandbox-images/audit.sh --only agent  # secrets, git, package managers, agent tools
```
