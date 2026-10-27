# Sandbox policy

Status: DESIGNED baseline. Nothing in this document is implemented in the product yet.
Date of the Docker experiments: 2026-10-27.
Machine-readable form: `policies/security.yaml`, section `sandbox`, `egress`, `path_access`.
Threat IDs (T-nn) and control IDs (C-nn) refer to `docs/security/threat-model.md`.
Tests that prove these rules (NT-*) are in `docs/security/negative-test-catalog.md`.

## 0. How to read the status labels

| Label | Meaning |
| --- | --- |
| REQUIRED | The product must implement this. Not implemented yet. |
| DESIGNED | Specified here, no code and no test exist. |
| VERIFIED | A Docker flag or git behavior was observed on the development machine described in section 12. It proves the flag exists and behaves as described there. It does not prove the factory uses it. |
| UNVERIFIED | Not exercised. Treat as an assumption until a test proves it. |

The sandbox is the primary control for everything the factory runs on behalf of an untrusted request. Allowlists in the policy files are the second layer. Command denylists are a backstop only.

## 1. Policy in one page

1. Generated code, build scripts, tests and agent CLIs run only inside an ephemeral container created by the factory supervisor. There is no host-execution fallback. If the sandbox cannot start or fails verification, the job stops.
2. Every container is non-root, has a read-only root filesystem, no Linux capabilities, `no-new-privileges`, the runtime's default seccomp profile or stricter, a private PID namespace, no SysV IPC, and hard CPU, memory, process and file-size limits.
3. The network is default deny. Containers have either `--network none` or a per-job `--internal` network whose only peer is a factory-run sidecar. The sidecar relays to an exact-host allowlist, or to the model broker.
4. Execution is split into profiles with different network and mount rules: `fetch_deps` (registries, no repository code), `agent` (model broker only) and `verify` (no network, trusted gates).
5. The sandbox never holds a GitHub credential or a real model-provider key. It may hold one opaque, job-scoped, budget-capped, revocable token (`sfjt_...`).
6. The workspace is a plain directory from a git worktree. The `.git` pointer is masked, protected paths are read-only overlays, hidden paths do not exist in the checkout. All git operations run on the host against a trusted git directory the sandbox cannot reach.
7. Everything that leaves the sandbox (files, logs, diffs) is untrusted input to the control plane and is ingested with no-follow, size-capped, audited reads.
8. The created container is inspected and compared with policy before it starts. Any mismatch aborts the job.

## 2. Execution model

### 2.1 Profiles

| Profile | Purpose | Network | Source tree | Secrets | Runs repository code |
| --- | --- | --- | --- | --- | --- |
| `fetch_deps` | Download dependencies with install scripts disabled | Proxied allowlist (registries) | Dependency directories only | None | No |
| `agent` | Agent CLI and the commands it requests | Model broker only | Read-write for task-owned files | One job token | Yes |
| `verify` | Build, test, lint, scan, documentation gates | None | Read-only source, writable build output | None | Yes |

`fetch_deps` runs package-manager download commands only (for example `cargo fetch --locked`, `npm ci --ignore-scripts`). It never runs `build.rs`, `postinstall` or `setup.py`. Dependency changes go through a typed `deps.request` tool call. The policy engine decides, a human decides for new direct dependencies, and only then does a `fetch_deps` run happen. The builder cannot run `cargo add` or `npm install` itself.

`verify` is a fresh container for each gate run. Gate definitions come from the base commit or from central configuration, never from the builder's workspace. Held-out tests are mounted only here, read-only. The pass or fail result is the supervisor's observation of the exit code and output, not a file the builder could have written.

### 2.2 Where the agent CLI runs

Two models are possible. The choice belongs to the architect and a human (open question Q1 in `threat-model.md`).

* Model A, recommended for Slice 1: the agent CLI (Claude Code or Codex CLI) and the commands it runs execute together inside the `agent` container. The container is the security boundary. Vendor flags that disable the CLI's own approval prompts and sandbox (`--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`) are acceptable only here, because the container is the external sandbox the Codex help text describes ("environments that are externally sandboxed"). They are forbidden on the host.
* Model B, hardening target: the CLI runs outside the sandbox with built-in shell and edit tools disabled, and every action goes through factory-provided typed tools that execute inside the sandbox with `docker exec`. This matches the master prompt ("typed command wrappers") and removes the CLI process from the blast radius, at the cost of re-implementing tools. UNVERIFIED that the installed CLIs expose enough control (`--tools`, `--strict-mcp-config`) to make it practical.

### 2.3 Topology for a job

```mermaid
flowchart LR
    subgraph HOST["Sandbox host (dedicated; no control-plane databases)"]
        SUP["Supervisor (trusted)"]
        subgraph JOBNET["Per-job internal network (docker network create --internal)"]
            SBX["Sandbox container (profile agent / fetch_deps / verify)"]
            SIDE["Egress sidecar (trusted relay)"]
        end
        GIT["Trusted git directory (never mounted)"]
        JOBDIR["Job directory: worktree, out"]
    end
    BROKER["Model broker (control plane; holds real keys, meters budget)"]
    REG["Package registries (allowlist)"]
    SUP -->|"docker create, inspect, start, kill"| SBX
    SUP -->|"host-side git"| GIT
    SUP -->|"audit walk, no-follow reads"| JOBDIR
    JOBDIR -.->|"bind mount /workspace, /out"| SBX
    SBX -->|"HTTP to sidecar name only"| SIDE
    SIDE -->|"job token, allowlisted API paths"| BROKER
    SIDE -->|"fetch_deps profile only; exact hosts"| REG
```

The sidecar is a small relay with static configuration generated by the supervisor from the policy: the allowed hosts for this profile, the job token it will accept, the byte quota. It holds no real credentials. The real provider keys live in the model broker, which sits in the control plane, checks the token, enforces the budget, replaces the credentials and forwards only the allowed API paths. One sidecar per job is the default because it removes any cross-job and cross-tenant path through shared proxy state. A shared multi-homed proxy needs a separate security review.

## 3. Container requirements

### 3.1 Required settings and what was observed

Every row marked VERIFIED was run on the machine in section 12. Experiment IDs refer to the table in section 12.

| Requirement | Docker option | Observed result | Status |
| --- | --- | --- | --- |
| Not privileged | no `--privileged` | `docker inspect` shows `Privileged=false` by default. With `--privileged --security-opt seccomp=unconfined` it shows `Privileged=true` and `label=disable` (P3). | VERIFIED |
| Non-root numeric user | `--user 10001:10001` | `id` returned `uid=10001 gid=10001 groups=10001` (E4b). Default is root (E0). | VERIFIED |
| Drop all capabilities | `--cap-drop ALL` | `CapEff`, `CapPrm`, `CapBnd` all zero as root and as non-root; `chown` returned EPERM (E4a, E4b). The default set is `00000000a80425fb` (E0). | VERIFIED |
| No privilege gain | `--security-opt no-new-privileges` | `NoNewPrivs: 1` (E5). | VERIFIED |
| Read-only root filesystem | `--read-only` | `touch /x` and `touch /tmp/x` both returned "Read-only file system" (E2). | VERIFIED |
| Writable scratch only on tmpfs | `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m` | Writes work; running a copied binary from it returned "Permission denied" (exit 126); the size cap held (E3). `uid=`, `gid=`, `mode=` options are accepted on `--tmpfs` (U1). | VERIFIED |
| Default seccomp profile on | omit `--security-opt seccomp`; never `unconfined` | `Seccomp: 2` and `unshare -U` returned "Operation not permitted" (E6). With `seccomp=unconfined` it showed `Seccomp: 0` and `unshare` succeeded (E6b). | VERIFIED |
| Custom seccomp profile mechanism | `--security-opt seccomp=FILE` | A test profile denying `uname` changed behavior (S1). A real custom profile must be a complete profile derived from the runtime default, never a short allow-everything file. | VERIFIED (mechanism only) |
| Private PID namespace | default; never `--pid host` | PID 1 inside was the container's own process (E13). | VERIFIED |
| No SysV IPC | `--ipc none` | `/dev/shm` did not exist (E13). Browser-based tests need `--ipc private` and an explicit `--shm-size`. | VERIFIED |
| Init process | `--init` | PID 1 was `docker-init` (I1). | VERIFIED |
| Process limit | `--pids-limit 256` | With limit 12: `pids.max` was 12, further forks failed with "Resource temporarily unavailable", `pids.events` counted `max 1` (E7). | VERIFIED |
| Memory limit, no swap | `--memory 4g --memory-swap 4g` | 300 MB allocation under a 64 MB limit: exit 137, `OOMKilled=true` (E8). | VERIFIED |
| CPU limit | `--cpus 2` | `cpu.max` showed `50000 100000` for `--cpus 0.5` (E9). | VERIFIED |
| Max single file size | `--ulimit fsize=<bytes>` | Writer was killed with "File size limit exceeded" at the limit (E12). | VERIFIED |
| Open files, core dumps | `--ulimit nofile=4096:4096 --ulimit core=0` | `ulimit -n` returned 64 and `ulimit -c` returned 0 in the test (E12). | VERIFIED |
| Scratch disk cap | `tmpfs size=` | 32 MB write into an 8 MB tmpfs stopped at 8 MB (E3, E10). | VERIFIED |
| Writable-layer quota | `--storage-opt size=` | Accepted silently and NOT enforced: a 128 MiB write succeeded under `size=64m` (E11, E11b). Do not rely on it. | VERIFIED (not enforced here) |
| Wall-clock limit | none in Docker | `docker run --help` has `--stop-timeout` and `--health-timeout` only. The supervisor sends `docker kill` at the deadline; exit code was 137 (E15). | VERIFIED |
| Network off | `--network none` | Only `lo` (plus unconfigured tunnel devices) existed; `wget 1.1.1.1` returned "Network unreachable"; DNS lookups returned "Network unreachable" (E1). | VERIFIED |
| Network restricted | `docker network create --internal` | See section 5. | VERIFIED |
| Kernel paths masked | default | `/proc/kcore` read 0 bytes; writing `/proc/sys/kernel/core_pattern` returned "Read-only file system"; `/sys` mounted read-only (E14). | VERIFIED |
| No Docker socket | no mount of `docker.sock` | The default container had no `/var/run/docker.sock` (E0). The policy check forbids mounting it; the mount itself was deliberately not attempted. | VERIFIED (default); policy check DESIGNED |
| No implicit image pull | `--pull=never` | Unknown image failed with "No such image", exit 125 (X1). | VERIFIED |
| Image pinned by digest | `name@sha256:...` | `docker run python@sha256:2d9a...` ran (E17). | VERIFIED |
| No daemon-side log copy | `--log-driver none` | Attached `docker start -a` / `docker run` still delivered stdout; `docker logs` failed with "configured logging driver does not support reading" (L1, P1). The default driver here was `local` and kept an unredacted copy readable with `docker logs` (L2). | VERIFIED |
| AppArmor profile | `--security-opt apparmor=...` | The daemon on the test machine lists only `seccomp` and `cgroupns` in `SecurityOptions`. No AppArmor, no SELinux, not rootless (E18). | UNVERIFIED on the test machine; REQUIRED on the Linux production host |

Findings that change the design:

* `--cap-drop ALL` does not stop ICMP echo to loopback or binding port 80 as root. Docker sets `net.ipv4.ping_group_range` and `net.ipv4.ip_unprivileged_port_start` so both worked with zero capabilities (E4a). This does not matter under `--network none`. On a job-internal network it means the sandbox can bind low ports and send ICMP echo (only loopback was tested). The network design must not rely on capability removal to prevent either.
* Environment variables are not secret from the Docker daemon. `-e FAKE_TOKEN=...` was readable through `docker inspect` and through `/proc/1/environ` (E16). Secrets go in files on a worker-side tmpfs, not in `--env`.
* `--storage-opt size=` silently does nothing on this storage driver. With a read-only root filesystem the writable layer is not used anyway; the real disk controls are on the mounted directories (section 4).

### 3.2 Canonical command shape

The supervisor builds the container from a typed `SandboxSpec` and passes arguments as an array, never through a shell and never by concatenating strings. A Docker Engine API client may be used instead of the CLI; the fields are the same. The table above is the checklist; this is the same content as one command, with placeholders in `${...}`.

```text
docker create
  --pull=never
  --name sf-${job_short}-${attempt}-${rand}
  --label factory.tenant=${tenant_id} --label factory.job=${job_id} --label factory.stage_run=${stage_run_id}
  --user ${uid}:${gid}                                  # numeric, both >= 10000
  --read-only
  --cap-drop ALL
  --security-opt no-new-privileges
  --init
  --ipc none                                            # "private" plus --shm-size only for browser tests
  --pids-limit ${pids}
  --memory ${mem_mb}m --memory-swap ${mem_mb}m
  --cpus ${cpus}
  --ulimit nofile=${nofile}:${nofile} --ulimit core=0 --ulimit fsize=${max_file_bytes}
  --network ${none | sf-net-${job_id}}
  --log-driver none
  --stop-timeout 10
  --workdir /workspace
  --env HOME=/home/agent --env <fixed supervisor-owned variables only>
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=${tmp_mb}m,mode=1777
  --tmpfs /home/agent:rw,noexec,nosuid,nodev,size=64m,uid=${uid},gid=${gid},mode=0700
  --mount type=bind,src=${job_root}/worktree,dst=/workspace
  --mount type=bind,src=${job_root}/worktree/${protected_path},dst=/workspace/${protected_path},readonly   # repeated per protected path that exists
  --mount type=bind,src=/dev/null,dst=/workspace/.git,readonly
  --mount type=bind,src=${job_root}/out,dst=/out
  --mount type=bind,src=${job_secret_tmpfs}/token,dst=/run/secrets/job_token,readonly    # agent profile only
  --mount type=bind,src=${tool_cache},dst=/cache,readonly
  ${image}@sha256:${digest}
  ${entrypoint_argv...}
```

Notes:

* Do not pass `--rm`. The supervisor must read `State.ExitCode` and `State.OOMKilled` after exit, then remove the container (E8 relied on this).
* Run `docker create`, then `docker inspect`, then verify (section 9), then `docker start -a`. `docker start -a` returned the container's stdout with `--log-driver none` and exit code 0 in experiment P1.
* There is no `--cap-add`, `--device`, `--privileged`, `--pid host`, `--network host`, `--userns host`, `--sysctl`, `--security-opt seccomp=unconfined`, `--security-opt apparmor=unconfined`, `--security-opt systempaths=unconfined`, `--volumes-from`, `--add-host` pointing at internal addresses, or `--publish`.
* `--tmpfs ...,noexec` breaks toolchains that execute from `/tmp`. A toolchain that truly needs it gets a named exception in its capability profile, reviewed by security. The build output directory is the exec-capable location.
* `nosuid` and `nodev` cannot be set on a bind mount through `--mount` in the options exercised here (UNVERIFIED for other versions). The compensating controls are `no-new-privileges` and zero capabilities, which neutralize setuid binaries in the workspace, plus the workspace audit walk that rejects setuid and setgid bits (`policies/security.yaml`, `path_access.workspace_audit`).

### 3.3 Forbidden

The posture verifier (section 9) rejects a container that has any of: privileged mode, added capabilities, a device, a sysctl override, host PID, host IPC, host network, `container:` network mode, host user namespace, an unconfined seccomp or AppArmor option, a mount from `/var/run/docker.sock` or from any path in `sandbox.forbidden_mount_sources`, a mount with a `/dev` source other than the single `/dev/null` mask, an image without a digest, or a running user of 0.

## 4. Resource limits

Defaults are in `policies/security.yaml`, `sandbox.profiles`. Projects may lower them. Raising any limit is an always-human decision.

| Limit | `fetch_deps` | `agent` | `verify` | Enforced by |
| --- | --- | --- | --- | --- |
| CPUs | 1 | 2 | 4 | `--cpus` (VERIFIED) |
| Memory and swap | 1 GiB | 4 GiB | 8 GiB | `--memory`, `--memory-swap` equal (VERIFIED) |
| Processes | 128 | 256 | 512 | `--pids-limit` (VERIFIED) |
| Wall clock | 10 min | 60 min | 30 min | Supervisor timer and `docker kill` (VERIFIED approach) |
| Per-command timeout | 10 min | 10 min | per gate | Typed command wrapper, kills the process group |
| Largest file | 512 MiB | 512 MiB | 1 GiB | `--ulimit fsize` (VERIFIED) |
| tmpfs `/tmp` | 256 MiB | 512 MiB | 512 MiB | `--tmpfs size=` (VERIFIED) |
| Workspace and output disk | 4 GiB | 2 GiB | 4 GiB | See below |

Workspace and output disk. The writable-layer quota is not enforced on the test machine, and the workspace is a host directory, so a per-container flag cannot cap it. In order of preference:

1. Place each job root on a filesystem with per-directory quotas (XFS project quotas, or ext4 project quotas). UNVERIFIED; needs a Linux host.
2. Mount a fixed-size loopback image per job. UNVERIFIED; needs a Linux host and privileges for the worker, which is a trade-off to review.
3. Baseline that works everywhere: the supervisor polls the job directory every 5 seconds with a no-follow walk (bytes and inode count). On breach it kills the container and fails the job with an audit event. `--ulimit fsize` bounds individual files. A fast writer can overshoot the cap between polls, so the sandbox host's filesystem must have headroom for `limit + (write rate * 5 s)`.

`RLIMIT_NPROC` (`--ulimit nproc`) is per user across the host and does not bound a single container. Use `--pids-limit`.

## 5. Network

### 5.1 Default and mechanism

Docker's default bridge allows outbound traffic: `wget example.com` succeeded from a default container (N0). The factory must never use the default network.

Docker has no per-domain egress allowlist. The mechanism is topological:

* `--network none` for profiles that need no network (`verify`, and any `agent` run that does not need the model, for example tool-only steps). VERIFIED.
* A per-job network created with `docker network create --internal sf-net-${job_id}` for `agent` and `fetch_deps`. VERIFIED behavior on the test machine:
  * IP egress failed: `wget http://1.1.1.1` returned "Network unreachable"; `wget http://169.254.169.254/` (cloud metadata address) also returned "Network unreachable" (N2).
  * Name resolution of external names failed: `wget example.com` returned "bad address"; `nslookup example.com` against the embedded resolver `127.0.0.11` returned SERVFAIL (N2). The embedded resolver did not forward external queries, so DNS tunneling to an outside resolver was not available from this network.
  * Containers on the same internal network resolved each other by name and could talk (N3).
  * A relay attached to both the internal network and `bridge` reached `example.com` (exit 0) while a client on the internal network only could not (N4). This is the sidecar topology.

### 5.2 Egress sidecar requirements (REQUIRED, DESIGNED)

* Static configuration from the supervisor: allowed hosts and ports from `egress.profiles.<profile>`, accepted job token, byte quota, job ID.
* Exact hostname matching. No wildcards, no suffix matching, no IP literals.
* The sidecar resolves names itself and applies `egress.proxy_rules.reject_resolved_ip_ranges` to the resolved address (loopback, RFC 1918, link-local and metadata, CGNAT, unique-local). It connects to the pinned address, so a rebinding DNS answer cannot redirect the connection.
* HTTPS passthrough (CONNECT) for registries. No TLS interception of package hosts.
* Methods limited to GET and HEAD for registries. The `agent` profile reaches only the model broker over HTTP to the sidecar, which forwards to the broker.
* A per-job transfer cap (default 2 GiB). It limits data volume leaving through any allowed host.
* Every request is logged to the audit stream: job, host, port, bytes, decision.
* The sidecar itself runs with the container requirements in section 3, with its own digest-pinned image built by the factory.

### 5.3 What the allowlist is and is not

`github.com`, `api.github.com`, `gist.github.com`, `raw.githubusercontent.com`, paste sites and file-drop sites are denied from every sandbox profile (`egress.never_allow_from_sandbox`). With a GitHub token an allowlisted `github.com` would be a way to push stolen data to an attacker repository. The sandbox does not need GitHub: the control plane clones and pushes.

An allowlisted package registry is still a very low bandwidth exfiltration channel (request paths and package names). The risk is accepted and bounded by the byte cap and by the fact that the registry operator, not the attacker, sees the requests. The `fetch_deps` profile runs no repository code, so the practical exposure there is the dependency name list itself.

The `agent` profile cannot reach any registry. Package installation is not possible during the agent session, which closes the "install a malicious package at runtime" path.

### 5.4 Network limits that remain

* Lateral movement between jobs is prevented by one internal network per job. Docker's default address pools are finite. Planning for many concurrent jobs means configuring `default-address-pools` with small subnets in the daemon. UNVERIFIED at scale.
* Inside a job network, the sandbox can reach the sidecar. The sidecar is therefore part of the attack surface and must treat all input as hostile.

## 6. Filesystem, worktrees and ingestion

### 6.1 Layout

```text
${job_root}/                 mode 0700, owned by the sandbox host worker user, one per job attempt
  worktree/                  git worktree of the base commit; mounted read-write at /workspace
  out/                       mounted read-write at /out; structured results and logs spill
  .secrets/ (tmpfs on host)  job token file; mounted read-only at /run/secrets; removed at job end
${repo_cache}/${tenant}/${repo}.git   trusted bare repository; NEVER mounted; read and written only by host-side git
```

Rules:

* The job root is created for one job attempt and deleted afterwards. No volume is shared between jobs. No path is shared between tenants. Toolchain and dependency caches are mounted read-only and are written only by `fetch_deps` runs for the same tenant and repository.
* Only `${job_root}/worktree` and `${job_root}/out` are writable from inside. Nothing from the user's home, the factory's configuration, the Docker socket, or any other host path is mounted.
* The worktree is created by the control plane with `git worktree add --detach --no-checkout` followed by a sparse checkout, so held-out evaluation data and secret-bearing files never exist in the checkout. VERIFIED (W1): after `sparse-checkout` with `!/tests/holdout/`, the directory was absent and `git status` was clean.

### 6.2 The `.git` pointer

A linked worktree's `.git` is a file with an absolute path into the main repository's `.git/worktrees/<name>`. Inside the container this path is dangling, which accidentally protects the main repository, but the file also reveals the host path layout (G1). The factory must not "fix" the dangling pointer by mounting the main `.git` directory. A sandbox-writable git directory is host code execution: a `core.fsmonitor` entry in a hostile `.git/config` made a plain `git status` on the host run the attacker's script (G3). Passing `-c core.fsmonitor=false` blocked that one vector. Other config keys can do the same (hooks path, diff and merge drivers, pager, credential helper, SSH command, aliases), so a denylist of `-c` overrides is not a control.

The control is structural:

1. Bind `/dev/null` read-only over `/workspace/.git`. VERIFIED (G2, M1): the container sees an empty file; the host file is unchanged; `rm` and `mv` of the masked entry return "Resource busy".
2. The sandbox contains no `git` binary the agent can use for repository operations. Version-control operations are typed tools executed on the host (`vcs.read`, `vcs.commit`) against the trusted git directory.
3. Host-side git always runs with a fixed environment: `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `core.hooksPath=/dev/null`, `core.fsmonitor=false`, no submodule recursion, no prompts. The loader must never set `safe.directory=*` to silence an ownership error; that guard is a defense, not an obstacle.
4. A nested `.git` directory created by the builder inside the workspace is rejected by the workspace audit walk. The tree diff alone does not report it (W3).

If the architect decides builders need in-sandbox git (Model A with a full clone), that is a security decision: the clone is then fully untrusted, the control plane never runs git inside it, and results are extracted by recomputing a diff from file contents on the host. It needs its own review.

### 6.3 Protected paths inside the sandbox

Defense in depth. The authoritative check is the host-side tree diff (section 6.5). In addition, the supervisor re-mounts each existing `deny_write` and `append_only` protected path read-only over the writable workspace. VERIFIED (M1):

* Appending to `.github/workflows/ci.yml` returned "Read-only file system"; `rm` of it returned "Read-only file system"; creating a file under a read-only `tests/holdout` returned "Read-only file system"; renaming the overlaid directory returned "Resource busy". An unprotected file (`src/main.rs`) stayed writable. The host files were unchanged afterwards.
* `append_only` groups (fixtures, golden files) cannot be expressed as a read-only overlay without also blocking new files, so the overlay applies to the existing files only and the tree diff enforces "add allowed, modify and delete blocked".
* UNVERIFIED: when a read-only overlay target does not exist in the checkout, Docker is expected to create an empty directory for the mount point on the host side. That would be harmless for git but means the audit walk must ignore empty directories at overlay targets. The supervisor should create overlay targets itself before `docker create`, and only for paths that exist in the base tree.

### 6.4 Hidden paths

Hidden groups (`evaluation_holdouts`, `secret_bearing_files`) are removed from the checkout with sparse-checkout exclusion, so there is nothing to mount and nothing to read. If the builder creates a file at a hidden path, git silently leaves it out of the staged tree (W3: "paths ... exist outside of your sparse-checkout definition, so will not be updated in the index"). The audit walk therefore fails the job when any file exists under a hidden path. A silent omission would hide the attempt.

### 6.5 Ingestion of sandbox output

The control plane treats everything under `worktree/` and `out/` as hostile input.

1. Stop and remove the container first.
2. Run the workspace audit walk (`path_access.workspace_audit`). The walk uses `lstat` and no-follow opens; it never follows a symlink. A container-created symlink to an absolute host path was followed by a plain host `cat` (B2), so any host reader that opens paths from the workspace without no-follow would read arbitrary host files and could attach them to a pull request or an artifact.
3. Compute the head tree on the host: copy the worktree's index to a temporary index (this keeps skip-worktree bits), run `git add -A`, `git write-tree`, then `git diff-tree -r --raw --find-renames` against the base tree. VERIFIED (W3): the output showed deletes, adds, modifications, a rename (`R100` with both paths), a mode change (`100644` to `100755`) and a new symlink (`120000`).
4. Evaluate the protected path rules on that diff, counting a rename as two paths and a mode or type change as a modification.
5. Reject gitlinks (`160000`), `.gitmodules` changes and symlinks whose target resolves outside the workspace.
6. Run the secret scanner on the diff before anything is committed or sent.
7. Only then commit, using the host-side `vcs.commit` operation.

Artifacts in `out/` are size-capped, count-capped, hashed, and never rendered or executed by the control plane. Archive extraction (if any) rejects absolute paths, `..`, links and device nodes.

## 7. Credentials and environment inside the sandbox

Details are in `docs/security/secrets-and-credentials.md`. The rules the sandbox depends on:

* No GitHub token, no App key, no webhook secret, no database or object-store credential, no real model-provider key ever enters a sandbox.
* The `agent` profile gets one job token (`sfjt_...`), bound to tenant, job and stage, valid only at the model broker, capped by tokens and USD, and revoked at job end. It is delivered as a read-only file on a worker-side tmpfs. Delivery by `--env` is visible in `docker inspect` and `/proc/1/environ` (E16); it is acceptable only where an agent CLI offers no file-based option, and that exception is recorded.
* Environment variables are set by the supervisor from a fixed list. The agent cannot add variables to a command (`exec.run` has `env: fixed_by_supervisor`). The agent CLI is configured not to inherit the supervisor's environment.
* `--log-driver none` keeps the daemon from storing an unredacted copy of output (L1, L2). The supervisor streams stdout and stderr through the redactor and stores only redacted output. If the supervisor dies mid-run, that output is lost, and the job is retried or failed. This is the trade-off for not leaving a raw copy on the host.

## 8. Kernel isolation stance

| Layer | Stance | Status |
| --- | --- | --- |
| Namespaces and cgroups (runc) | Baseline. Shares the host kernel. | VERIFIED on Docker Desktop |
| Seccomp | Runtime default profile is mandatory. A custom profile may only be stricter and must be a complete profile. It blocks `unshare` of a user namespace, which is intended. | VERIFIED (E6) |
| AppArmor / SELinux | Required on the Linux production host where the distribution provides it. Not active on the Docker Desktop VM used for the experiments. | UNVERIFIED |
| User namespace remapping or rootless daemon | Strongly recommended for the production sandbox host so that "root in the container" is not root on the host. Not exercisable on Docker Desktop. | UNVERIFIED |
| gVisor (`runsc`), Kata Containers, Firecracker | Recommended for multi-tenant production, where a shared kernel is the largest residual risk. Only `runc` is installed on the test machine. | UNVERIFIED |
| Docker daemon access | Only the supervisor talks to the daemon. The daemon socket is never mounted into any container. The supervisor builds requests from a typed spec and checks them before start. | DESIGNED |

The default seccomp profile denies `unshare(CLONE_NEWUSER)`. Agent CLIs that implement their own sandbox with user namespaces (for example a bubblewrap-based or Landlock-based mode) may fail to initialize inside this container. That is acceptable, because the container is the boundary. Whether Claude Code 2.1.311 and Codex CLI 0.163.0 start cleanly under this profile in non-interactive mode is UNVERIFIED and is a capability-probe item for the adapters.

## 9. Supervisor lifecycle and posture verification

1. Authorize: the policy engine confirms the stage, the task, the profile, the mounts and the budget. Missing policy or a failed load stops the job.
2. Prepare: create the job root, the worktree (sparse), the output directory, the secret tmpfs file, and for proxied profiles the job network and sidecar.
3. Create: `docker create` with the typed spec. Not started yet.
4. Verify posture: `docker inspect` the created container and compare these fields with policy. Fields observed on Docker 29.9.2 (P2): `HostConfig.Privileged`, `Config.User`, `HostConfig.ReadonlyRootfs`, `HostConfig.CapAdd`, `HostConfig.CapDrop`, `HostConfig.SecurityOpt`, `HostConfig.PidsLimit`, `HostConfig.Memory`, `HostConfig.MemorySwap`, `HostConfig.NanoCpus`, `HostConfig.NetworkMode`, `HostConfig.IpcMode`, `HostConfig.PidMode`, `HostConfig.UsernsMode`, `HostConfig.Init`, `HostConfig.LogConfig.Type`, `HostConfig.Devices`, `HostConfig.Ulimits`, `HostConfig.Tmpfs`, `Mounts`, `Config.Image`, `HostConfig.RestartPolicy`, `HostConfig.AutoRemove`.
   * Reading the output: `CapAdd` printed `<no value>` when unset. An unset seccomp option is an empty `SecurityOpt` (P2), so the verifier cannot confirm "default seccomp" from the field; it rejects any `seccomp=unconfined` or custom path not on the allowlist, and the runtime self-check below confirms the result. `SecurityOpt` showed `[seccomp=unconfined label=disable]` for the privileged test container (P3). `PidMode` and `UsernsMode` print empty for the private default. Tmpfs mounts appear under `HostConfig.Tmpfs`, not under `Mounts`.
   * Any mismatch: remove the container, fail the job, write an audit event with the diff. No retry with relaxed settings.
5. Start attached (`docker start -a`). The first action of the entrypoint wrapper is a self-check that prints `/proc/self/status` fields `Seccomp`, `NoNewPrivs` and `CapEff`. The supervisor requires `Seccomp: 2`, `NoNewPrivs: 1` and `CapEff` of zero before it releases the workload. This proves the runtime applied what the inspect output promised, including on a daemon whose default seccomp profile has been altered.
6. Run: stream stdout and stderr through the redactor to the log store. Enforce the wall-clock deadline and the disk poll. On breach, `docker kill`, record the exit code and `OOMKilled`.
7. Collect: read `State.ExitCode` and `State.OOMKilled`, then remove the container, the sidecar and the network. Run ingestion (section 6.5).
8. Destroy: delete the job root and revoke the job token. Verify nothing remains with the factory's labels. Experiment T1 confirmed the cleanup approach left no containers or networks behind.

If the Docker daemon is unreachable, the supervisor is down or the image is missing, the job is BLOCKED. It does not run on the host and it does not downgrade to a weaker profile.

## 10. Agent CLI considerations (from the installed binaries)

These flags were read from `claude --help` (2.1.311) and `codex exec --help` (0.163.0) on 2026-10-27. They exist. How well they neutralize repository-resident configuration is UNVERIFIED and must be proven by the adapter capability probe and by NT-INJ-07.

| Concern | Claude Code | Codex CLI |
| --- | --- | --- |
| Skip repository hooks, plugins, auto-discovered instruction files | `--bare` (documented to skip hooks, plugin sync, auto-memory, keychain reads, CLAUDE.md auto-discovery) | `--ignore-user-config`, `--ignore-rules` |
| Control settings sources | `--settings <file>`, `--setting-sources` | `-c key=value`, `--strict-config` |
| MCP servers | `--mcp-config` with `--strict-mcp-config` | `codex mcp` config; use `--ignore-user-config` |
| Tool restriction | `--tools`, `--allowedTools`, `--disallowedTools`, `--permission-mode` | `-s read-only` / `workspace-write` |
| Authentication | With `--bare`: `ANTHROPIC_API_KEY` or `apiKeyHelper` via `--settings`; OAuth and keychain are never read | `codex login --with-api-key` reads from stdin |
| Per-run cost cap | `--max-budget-usd` (only with `--print`) | none seen in `exec --help` |
| Session persistence | `--no-session-persistence` | `--ephemeral` |
| Bypass flags | `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions` | `--dangerously-bypass-approvals-and-sandbox`, `--dangerously-bypass-hook-trust` |

Rules:

* The bypass flags are allowed only inside a container that passed posture verification and the runtime self-check. The adapter must refuse to add them otherwise.
* The CLI's own budget flag is not the budget control. The broker meters tokens and USD and cuts the job token, so a CLI that ignores or mis-counts its budget still stops.
* The adapter must pass the instruction set explicitly. Repository copies of `AGENTS.md`, `CLAUDE.md`, `.claude/settings.json`, `.mcp.json` and `.codex/config.toml` are data, not configuration. A project settings file that sets a model base URL environment variable would otherwise redirect traffic that carries a credential. Because the sandbox only holds a job token and only reaches the broker through the sidecar, such a redirect cannot reach an attacker host, but the adapter must still not honor it.
* Whether the CLIs accept a base URL for the broker (`ANTHROPIC_BASE_URL` and the OpenAI equivalent) is UNVERIFIED here. If a CLI cannot be pointed at the broker, the fallback in `secrets-and-credentials.md` section 4.4 applies and its residual risk is recorded.

## 11. Production host guidance

The Docker Desktop VM on a developer laptop is a development convenience. For anything that runs untrusted code for other people:

* Run sandboxes on dedicated Linux hosts or VMs that hold no control-plane database, no secrets and no other workloads.
* Prefer rootless Docker or Podman, or at minimum user-namespace remapping, and enable AppArmor or SELinux.
* For multi-tenant use, run sandboxes under gVisor or Kata Containers, or in microVMs. A shared kernel is the main residual risk of this design.
* Keep the host kernel and runc patched. Container breakouts are kernel and runtime bugs; the controls above reduce what a breakout reaches, they do not prevent one.
* Do not expose the Docker daemon over TCP. The supervisor is the only client.
* Egress from the sandbox host itself should be restricted by the host or network firewall to the model broker, registries and the control plane, as a second layer behind the sidecar.
* Pre-pull and scan images by digest. Rebuild factory-owned images on a fixed schedule (the policy proposes 14 days).

## 12. Verification record

Machine: Apple Silicon Mac, Docker Desktop. `docker version`: client 29.9.2, server 29.9.2, `linux/arm64`. Daemon: kernel `7.0.14-linuxkit`, cgroup v2 with `cgroupfs`, storage driver `overlayfs` (containerd snapshotter), runtime `runc` 1.5.2, 16 CPUs, 8.3 GB memory. `docker info` security options: `name=seccomp,profile=builtin name=cgroupns`. Image: `python:3.13-alpine` (BusyBox 1.37), run with `--pull=never`. Host git: 2.50.1 (Apple Git-155). Scripts ran from the session scratchpad; nothing was pulled and no container was privileged.

`docker run --help` confirmed these options exist: `--network`, `--read-only`, `--cap-drop`, `--cap-add`, `--security-opt`, `--pids-limit`, `--memory`, `--memory-swap`, `--cpus`, `--ulimit`, `--tmpfs`, `--mount`, `--user`, `--userns`, `--ipc`, `--pid`, `--init`, `--log-driver`, `--pull`, `--stop-timeout`, `--storage-opt`, `--cgroupns`, `--oom-kill-disable`, `--annotation`, `--device`, `--sysctl`. It has no `--kernel-memory`, and no run-time or wall-clock limit option (only `--stop-timeout` and `--health-timeout`).

| ID | What was run | Observed result |
| --- | --- | --- |
| E0 | Default container: `id`, `/proc/self/status`, write to `/` | `uid=0`; `CapEff 00000000a80425fb`; `NoNewPrivs 0`; `Seccomp 2`; root filesystem writable; no `/var/run/docker.sock` |
| E1 | `--network none`: interfaces, `wget 1.1.1.1`, `nslookup` | Loopback and unconfigured tunnel devices only; "Network unreachable" for IP and for DNS |
| E2 | `--read-only` | `touch /x` and `touch /tmp/x`: "Read-only file system" |
| E3 | `--read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m` | tmpfs writable; exec of a copied binary exit 126 "Permission denied"; size capped (100% used) |
| E4a | `--cap-drop ALL` as root | All capability sets zero; `chown` EPERM; ping to 127.0.0.1 worked; `nc -l -p 80` bound without error |
| E4b | `--cap-drop ALL --user 10001:10001` | `uid=10001`; capability sets zero |
| E5 | `--security-opt no-new-privileges` | `NoNewPrivs: 1` |
| E6 / E6b | `unshare -U true` with default seccomp, then with `seccomp=unconfined` | EPERM with `Seccomp: 2`; succeeded with `Seccomp: 0` |
| E7 | `--pids-limit 12`, 40 background sleeps | `pids.max 12`; "can't fork: Resource temporarily unavailable"; `pids.events: max 1` |
| E8 | `--memory 64m --memory-swap 64m`, 300 MB allocation | exit 137; `OOMKilled=true` |
| E9 | `--cpus 0.5` | `cpu.max 50000 100000` |
| E10 | `--tmpfs /scratch:size=8m`, write 32 MB | Stopped at 8 MiB |
| E11 / E11b | `--storage-opt size=64m`, write 128 MiB to `/` | Accepted; the 128 MiB write succeeded. Not enforced. |
| E12 | `--ulimit fsize=1048576 nofile=64:64 core=0`, write 4 MiB | "File size limit exceeded"; limits applied |
| E13 | `--ipc none` | `/dev/shm` absent; PID 1 is the container's own process |
| E14 | Default masked paths | `/proc/kcore` 0 bytes; `core_pattern` write EROFS; `/sys` read-only |
| E15 | Run `sleep 300`, `docker kill` | exit 137, not running |
| E16 | `-e FAKE_TOKEN=...` then `docker inspect` and `/proc/1/environ` | Fake token visible in both |
| E17 | Run by digest | Ran; Python 3.13.16 |
| E18 | `docker info` security options | seccomp and cgroupns only |
| N0 | Default bridge, `wget example.com` | exit 0 (egress open by default) |
| N1 / N2 | `docker network create --internal`; from a container on it: `wget 1.1.1.1`, `wget example.com`, `wget 169.254.169.254`, `nslookup example.com` | `Internal=true`; unreachable; "bad address"; unreachable; SERVFAIL from 127.0.0.11 |
| N3 | Server and client on the same internal network, by name | Worked |
| N4 | Server also attached to `bridge`; relay and client | Relay reached `example.com` (exit 0); client did not |
| B1 | `--mount type=bind,...,readonly` and a read-write bind with `--user 10001` | Read-only write EROFS; read-write write worked; file appeared on the host owned by the host user (Docker Desktop file sharing), not uid 10001 |
| B2 | Container creates a symlink to an absolute host path; host `cat` | Host read the target |
| G1 | `git worktree add`; `.git` file inside container | Absolute host path to `main/.git/worktrees/wt1`; dangling in the container |
| G2 | `/dev/null` bind over `/workspace/.git` | 0 bytes inside; host file unchanged |
| G3 | Hostile `.git/config` with `core.fsmonitor`; host `git status` | Attacker script ran on the host; `-c core.fsmonitor=false` stopped it |
| M1 | Read-only overlays on `.github` and `tests/holdout`; masked `.git`; tamper attempts | EROFS on edit, create, delete; "Resource busy" on rename or remove of mount roots; unprotected file writable; host unchanged |
| S1 | `--security-opt seccomp=FILE` denying `uname` | Behavior changed (kernel string missing) |
| L1 / L2 | `--log-driver none` vs default driver | none: stdout delivered to the attached client, `docker logs` unsupported; default `local`: raw output readable via `docker logs` |
| I1 | `--init` | PID 1 `docker-init` |
| U1 / U2 | Non-root, read-only, `--tmpfs ...,uid=10001,gid=10001,mode=0700`; `--mount type=tmpfs,...,tmpfs-mode=0500` | First worked and `HOME` defaulted to `/`; second created a root-owned directory the user cannot read |
| X1 | Unknown image with `--pull=never` | exit 125 "No such image" |
| R1 | `docker info` runtimes | `runc` and `io.containerd.runc.v2` only |
| P1 | `docker create` then `docker start -a` with `--log-driver none` | Output delivered, exit 0, `State.ExitCode`, `State.OOMKilled` readable afterwards |
| P2 / P3 | `docker inspect` of a hardened created container; of a `--privileged --security-opt seccomp=unconfined` one | Field values as listed in section 9; unconfined shows `[seccomp=unconfined label=disable]` and `Privileged=true` |
| W1 | `git worktree add --no-checkout`, `sparse-checkout` non-cone excluding `tests/holdout` | Directory absent; `git status` clean |
| W3 | Edits, new file, rename, chmod, symlink, file in hidden path, nested `.git`; temp-index diff | Modify, add, delete, `R100` rename, mode change, symlink all reported; hidden-path file silently omitted; nested `.git` ignored |
| T1 | Cleanup | No `sf-sec-exp*` containers or networks left |

## 13. Not verified

* AppArmor and SELinux profiles, user-namespace remapping, rootless Docker, gVisor, Kata, Firecracker: not available or not active on the test machine.
* `--storage-opt size=` enforcement on a Linux host with `overlay2` on XFS with project quotas; project quotas and loopback images for workspace caps.
* Ownership and permission behavior of bind mounts on a Linux host (the test machine remapped ownership through Docker Desktop file sharing, B1). The design needs the job root owned by a UID that matches `--user`, or a remapped range.
* Per-bind-mount `nosuid`, `nodev` flags.
* The egress sidecar and the model broker: no code exists, only the Docker network topology was exercised.
* Docker network address pool exhaustion with many concurrent per-job networks.
* Whether the agent CLIs start cleanly under the hardened profile, accept a broker base URL, honor `--bare` and `--setting-sources` as described, and read their credential from a file helper.
* The posture verifier and the self-check: the field names and values were read, but no verifier code was run.
* Behavior of other Docker versions and other git versions than the ones listed.

## 14. Residual risks

| Risk | Why it remains | Owner (proposed) |
| --- | --- | --- |
| Kernel or runtime breakout from a shared-kernel container | runc shares the host kernel | Security and SRE; mitigated by dedicated hosts, rootless mode, and gVisor or Kata for multi-tenant |
| Sidecar or broker compromise from a hostile sandbox | They accept input from the sandbox | Security; small Rust relay, no real credentials in the sidecar, per-job instance |
| Low-bandwidth leakage through an allowlisted registry | Request paths and names leave the sandbox | Accepted; bounded by byte cap and audit |
| Disk overshoot between watchdog polls | No kernel quota in the baseline | SRE; headroom plus project quotas on Linux |
| A host-side tool that forgets no-follow | One missed reader is enough (B2) | Engineering; a single ingestion module and NT-SBX-09 |

These are proposed residual risks. They become accepted risks only when a named human records acceptance with an expiry (`approval.yaml`, `accept_residual_risk`).
