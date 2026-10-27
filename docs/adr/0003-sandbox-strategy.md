# 0003: Run untrusted work in hardened ephemeral containers under a supervisor, with a masked git workspace, behind SandboxProvider and WorkspaceProvider ports

- Status: Accepted. Revised on 2026-10-27 after the security review (see "Revision note"). Revised again on 2026-10-27 by ADR 0014 (see "Revision note (ADR 0014)").
- Date: 2026-10-27
- Deciders: software_architect. The container settings, network design and ingestion rules are owned by the security specialist in [`docs/security/sandbox-policy.md`](../security/sandbox-policy.md) and `policies/security.yaml`. This record decides the architecture around them and does not restate them.
- Related: [ADR 0005](0005-agent-runtime-adapter-boundary.md), [ADR 0009](0009-operating-defaults-pending-confirmation.md), [overview](../architecture/overview.md)

## Revision note (ADR 0014)

Revised on 2026-10-27 by [ADR 0014](0014-ports-v1-1-claim-protocol-and-port-revision.md): the job owns the trusted object store and an attempt owns a worktree (`JobRepo` and `Workspace`), a commit made in one workspace is pushable from any other, mounts in a sandbox spec are typed so the policy check is an allow list by construction, the posture report covers hardening, image, limits, network, mounts and environment, the sandbox adapter writes and removes the job token file, AppArmor may be reported as not available where the policy allows it, and every host process is started through one `ProcessRunner`.

## Context and problem statement

The master prompt (section 1) forbids running untrusted generated shell code on the control-plane host. It requires ephemeral containers and git worktree isolation, no privileged containers, bounded CPU, memory, disk and time, filesystem allowlists, network restrictions and short-lived scoped credentials. Tests need fakes that never start a process.

How does the factory isolate the agent, the builder's commands and the validation gates, and how does it handle the repository that the sandbox writes to?

## Revision note

The first draft of this record mounted the shared git directory into the container read-only so that `git status` and `git diff` would work inside it. The security review showed that this is the wrong default. A sandbox-writable or sandbox-visible git directory is a host code-execution path, and the review found further vectors (`core.fsmonitor` and other config keys) that a deny list of `-c` overrides cannot close. The design below follows the review: the git directory is never mounted, `.git` is masked, and all git runs on the host. The earlier experiments stay in the evidence list because they agree with the review.

## What was verified

Docker Desktop 29.9.2, `runc`, aarch64, 2026-10-27. Items 1 to 5 were run by the architect. The security review ran a larger set (its experiment ids are in `sandbox-policy.md` section 3.1 and section 12).

1. A hardened profile works: non-root, `--cap-drop ALL`, `no-new-privileges`, read-only root, `--network none`, memory, swap, pids and CPU limits, noexec `tmpfs`. The process saw no capabilities, no network, a read-only root, a writable workspace, and a fork loop stopped at "can't fork".
2. A memory limit alone did not give a timely kill. A runaway allocator sat at 123 of 128 MiB at 48% CPU for about two and a half minutes with `OOMKilled=false`. One run, one image, not root-caused. `docker kill` returned at once and `--rm` left nothing behind.
3. A worktree's `.git` file points to an absolute path under the main repository's `.git/worktrees/`. Inside a container that holds only the worktree the path is dangling and git fails.
4. A `post-commit` hook in the shared `.git/hooks` ran when a commit was made on the host from the worktree. `git -c core.hooksPath=/dev/null` stopped it. The security review's `core.fsmonitor` experiment (its G3) shows the same class of problem for a plain `git status`.
5. Only `runc` is registered. There is no gVisor or Kata runtime here.

From the security review, relevant to the architecture: `--storage-opt size=` silently does nothing on this storage driver, and Docker offers no wall-clock limit for a container. Both must be enforced by a supervisor. `docker network create --internal` blocks IP egress and external DNS, and a relay attached to both networks can reach the outside (its N2 to N4).

Not verified: disk quotas on a Linux host, AppArmor and SELinux, user-namespace remapping, gVisor, Kata, the sidecar and broker (no code exists), whether the agent command line tools start under the hardened profile.

## Considered options

1. **Docker command line with typed argument vectors, a supervisor, and host-side git, behind two ports.**
2. **Docker Engine API through `bollard` 0.21.1, same shape.**
3. **A stronger runtime (gVisor, Kata, Firecracker) from the start.**
4. **Run on the host and rely on each agent tool's own sandbox.**

## Decision outcome

Chosen: **option 1**, with the ports shaped so options 2 and 3 are later adapters. Option 4 is rejected because section 1 forbids it.

### Ports

- `SandboxProvider` creates a `SandboxSession` per attempt from a `SandboxSpec` that names a **profile**: `fetch_deps`, `agent` or `verify`. `SandboxSpec::validate()` is pure and rejects anything weaker than the policy.
- `WorkspaceProvider` creates a `Workspace` per job. It is a separate port because it runs on the host and the sandbox never sees most of it.
- `FakeSandbox` and `FakeWorkspace` live in `testkit`, report `fidelity = fake`, and never start a process or run git. Signatures are in the [slice plan](../architecture/slice-plan.md).

### The supervisor sequence

Implemented in the `sandbox` crate and specified in `sandbox-policy.md` section 9: authorize, prepare, `docker create`, **verify posture by `docker inspect` against policy**, start with a runtime self-check, run with redacted log streaming and `--log-driver none`, collect, destroy. Any mismatch, a missing image, a dead daemon or a policy that fails to load makes the job **BLOCKED**. There is no downgrade to a weaker profile and no fallback to the host.

### Profiles and network

| Profile | Network | Real credentials | Used by |
|---|---|---|---|
| `fetch_deps` | per-job internal network, sidecar relays to exact registry hosts | none | dependency downloads only, install scripts disabled |
| `agent` | per-job internal network, sidecar relays to the model broker only | none; one job token | the agent command line tool and the commands it runs |
| `verify` | `--network none` | none | every gate, in a fresh container, with gate definitions read from the base commit |

The sidecar and the broker belong to the new `egress` crate ([overview](../architecture/overview.md)). Their design is in `sandbox-policy.md` section 5 and ADR 0005.

### What the supervisor enforces because Docker does not

- **Wall-clock deadline:** a supervisor timer and `docker kill`, per profile. The memory limit is a second line of defense, not the first.
- **Disk:** the workspace is a host directory and `--storage-opt` does nothing here. The baseline is a poll every 5 seconds with a no-follow walk of bytes and inodes, kill on breach, and filesystem headroom for the overshoot. Per-directory quotas on a Linux host are a production item for `sre` (UNVERIFIED here).

### Workspace and git

Rules from `sandbox-policy.md` section 6, adopted without change:

- The trusted bare repository is never mounted. Each job gets a detached, sparse worktree. Held-out and secret-bearing paths are excluded from the checkout, so there is nothing to mount or read.
- `/dev/null` is bound read-only over `/workspace/.git`. The sandbox contains no `git` binary. Version control is typed operations executed on the host (`vcs.read`, `vcs.commit`) against the trusted directory.
- Host git runs with a fixed environment (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `core.hooksPath=/dev/null`, `core.fsmonitor=false`, no submodule recursion, no prompts) and **never against a git directory the sandbox can write**.
- Ingestion treats everything the sandbox wrote as hostile: stop the container first, run the no-follow audit walk, compute the tree diff on the host with a temporary index, evaluate protected paths on that diff (a rename counts as two paths), reject gitlinks and symlinks that leave the workspace, scan for secrets, and only then commit. All reads of workspace or output paths go through one ingestion module (static check ST-09).
- The control plane pushes the branch in the delivery stage. The sandbox holds no GitHub credential.

### Consequences

- Good: the architecture matches the security review, so one set of rules is tested once; the ports let a stronger runtime replace Docker later; every container's posture is checked before it runs.
- Good: gates cannot be weakened from inside the builder's workspace, because they run in a fresh container from the base commit.
- Bad: the `sandbox` crate is large. It holds the supervisor, the posture verifier, the network and sidecar lifecycle and the whole host-side workspace. The plan splits it into two work packages with disjoint directories.
- Bad: no git inside the sandbox means the agent cannot run `git diff` or `git log` itself. Every version-control need becomes a typed operation, and some agent CLI features that expect git will not work. Whether the installed tools tolerate a masked `.git` is UNVERIFIED.
- Bad: no disk quota. A fast writer can overshoot between polls, and a full host disk is possible. Accepted for Slice 1 with headroom.
- Bad: container isolation shares the host kernel. Multi-tenant production needs gVisor, Kata or a microVM and a dedicated host (security open question Q3).
- Neutral: images must be built and pinned by digest (`sre`, work package `s1-sandbox-images`), now including the sidecar image.

## Pros and cons of the options

**Docker CLI**: simple, auditable, matches what was tested. Streaming and event handling are manual.

**`bollard`**: typed API and streaming, but a larger dependency for a benefit not needed in Slice 1.

**Stronger runtime**: better isolation, not installed here, Linux-only for the most part. Revisit for production hosting.

**Host execution**: rejected by the master prompt.

## Confirmation

Work packages `s1-sandbox-adapter` and `s1-workspace-ingestion` carry the sandbox and workspace tests NT-SBX-01 to NT-SBX-14, NT-SUP-05 and ST-03, ST-04 and ST-09 from [`negative-test-catalog.md`](../security/negative-test-catalog.md), each with its control-off variant failing. A Docker-dependent test that cannot run reports BLOCKED. It never passes silently.
