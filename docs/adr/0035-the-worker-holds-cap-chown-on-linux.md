# 0035: On a Linux host the worker holds CAP_CHOWN, to hand the job token file to the sandbox user

- Status: **Decided by the owner on 2026-11-22**; the engineer found the problem and wrote the options. No independent review has covered it.
- Date: 2026-11-22
- Deciders: the owner chose among four options after the first GitHub CI run on Linux showed the problem.
- Related: [ADR 0034](0034-github-ci-on-arm64-with-a-database-and-built-images.md) (the Linux CI that found it), the job token file (`crates/sandbox/src/container/token.rs`), the [sandbox policy](../security/sandbox-policy.md), [local deployment](../operations/local-deployment.md) (Docker access is still an open decision there).

## Context and problem statement

An `agent` or `troubleshooter` sandbox receives its job token as a file, never in its environment, because the Docker daemon shows environment values to anyone who can inspect a container. The sandbox adapter writes the file under its token root with mode `0400`, gives it to the sandbox user (`10001:10001` in the agent image) with `chown`, bind-mounts it read-only, and reads it back from inside the started container before it releases the workload. If the read fails, provisioning ends with `ProvisionFailed(TokenFile)`, and no job runs without a working token.

`chown` to another user needs `CAP_CHOWN`: root has it, an ordinary user does not. On the owner's Mac this never mattered, because Docker Desktop's file sharing shows a host file to the container as owned by the container user (experiment B1 in `token.rs`). On a Linux host the container sees the real owner. On 2026-11-22 the first GitHub CI run on Linux, where the tests run as the unprivileged user `runner`, failed 15 Docker sandbox tests this way. The behaviour was correct, since the sandbox closes by default, but it meant that a worker without privileges on a Linux host could start no agent job at all.

## Considered options

1. **The worker holds `CAP_CHOWN`** (chosen). Nothing changes in the code or in the file, which stays `0400` and owned by the sandbox user. A Linux deployment gives the worker that one capability, either as `cap_add: [CHOWN]` on its container or as a file capability on its program (`setcap cap_chown+ep`). This does not widen what the worker can do, because the worker already drives the Docker daemon, which is the same as root on that machine.
2. **A group-readable file.** Mode `0440`, owned by the worker, with the sandbox's group, and the worker a member of that group on the host. It needs no capability, but it changes the code and loosens the file: any host process in that group could read every job token.
3. **The worker runs as root on Linux.** This needs no change, but it gives up least privilege for every other thing the worker does.
4. **No decision yet.** The Linux CI would stay red on these tests, and a Linux deployment would stay unable to run agent jobs.

## Decision

- **A Linux deployment of the worker grants `CAP_CHOWN` and no other added capability for this purpose.** The token file stays as it is: mode `0400`, owned by the sandbox user, in a `0700` directory, mounted read-only, and read back before the workload starts. The adapter keeps its current rule of applying the owner when the process may and leaving the file with its writer when it may not, so a worker without the capability still fails at provisioning and never later.
- **The GitHub CI runs `scripts/ci.sh` as the `runner` user with `CAP_CHOWN` as an ambient capability**, set with `capsh`, so the test processes have exactly what a Linux worker would have. Root is used only to set the capability, never to run the checks.
- **On Docker Desktop nothing changes**: its file sharing already shows the file as owned by the container user.
- **Not decided here:** how a containerised worker reaches the Docker daemon and shares host paths with it (item 2 of "What the stack cannot provide" in [local deployment](../operations/local-deployment.md)). That decision must include this capability. `infra/compose/local.yml` therefore still drops every capability of the worker and adds none, because that worker cannot start sandboxes yet.

## Consequences

- Good: agent jobs can run on a Linux host without root, and the file keeps the strictest mode.
- Good: the Linux CI exercises the same delivery a Linux deployment uses.
- Bad: a Linux deployment needs one more line of configuration, which is easy to miss. The failure it causes is loud and early (`ProvisionFailed(TokenFile)` at the first agent job), not silent.
- Neutral: `CAP_CHOWN` lets the worker change the owner of any file it can reach. That is no new power for a process that already controls the Docker daemon.

## What was checked

- On GitHub (run 45048962104, `ubuntu-24.04-arm`, tests as `runner` without capabilities): 15 Docker sandbox tests ended with `ProvisionFailed(TokenFile)`; every other Docker sandbox test passed.
- The result with the ambient capability is recorded in the pull request that brings this record.
