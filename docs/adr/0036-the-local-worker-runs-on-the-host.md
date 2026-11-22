# 0036: In the local deployment the worker runs on the host, and only PostgreSQL and the API run in Compose

- Status: **Decided by the owner on 2026-11-22**; the engineer wrote the options and the shape. No independent review has covered it.
- Date: 2026-11-22
- Deciders: the owner chose among three options ("how the worker reaches Docker", item 2 of "What the stack cannot provide" in [local deployment](../operations/local-deployment.md)).
- Related: [ADR 0035](0035-the-worker-holds-cap-chown-on-linux.md) (the worker's `CAP_CHOWN` on Linux), the [sandbox policy](../security/sandbox-policy.md) ("Docker daemon access": the socket is never mounted into any container), [local deployment](../operations/local-deployment.md), question Q3 of the [threat model](../security/threat-model.md) (where sandboxes run in production, still open).

## Context and problem statement

The worker starts every sandbox through the Docker daemon. The local stack (`infra/compose/local.yml`) ran the worker in a container and mounted no Docker socket, as the sandbox policy requires ("the daemon socket is never mounted into any container"). So that worker could start no sandbox, and every job that needs one ended `BLOCKED`. Four more facts bound the choice:

1. `sandbox.token_root` and `sandbox.workspace_root` are mounted into sandboxes **by the daemon**, so they must be paths on the daemon's machine, and none may be under a forbidden mount source (`/var`, `/home`, `/usr`, `/etc`, `/root`, `/`). The container worker's example put both under `/var/lib/factory`, which the policy refuses.
2. On a Linux host the worker needs `CAP_CHOWN` to hand each job token file to the sandbox user (ADR 0035).
3. The per-job sidecar relays the sandbox's traffic to the worker's model broker. It is attached to the job's internal network and to the default bridge, and reaches the broker at the address a container on that bridge has for the host (`host-gateway`). The egress end-to-end test and the live test (`crates/egress/tests/e2e_docker.rs`, `apps/api/tests/live/`) already run that topology, with the worker's broker on the host.
4. The API reads the artifacts the worker writes. Both must see the same store.

## Considered options

1. **The worker on the host** (chosen). Compose keeps PostgreSQL and the API. The worker runs as an ordinary process of the operator's user, talks to the daemon as that user's own `docker` client does, and writes the token and workspace roots on the host, where the daemon mounts them. It needs no socket in any container and no path translation, and it runs the topology the tests already prove. On Linux its program holds `CAP_CHOWN` as a file capability.
2. **A dedicated Docker daemon for sandboxes** (`docker:dind`), which a containerised worker talks to over a shared volume. It keeps the host daemon away from the worker, but the `dind` container must be privileged, the images must be loaded into it, and the broker network and the shared paths need more machinery. None of it is tested.
3. **Deferring the decision to the production sandbox host** (Q3). The local stack would stay unable to run an agent job.

## Decision

- **The worker runs on the host**, started by `scripts/worker-host.sh`:
  - `--check` prepares and checks everything and starts nothing. It exits `0` when the worker would start, or `3` (BLOCKED) with one line for each missing item.
  - Without a flag it also builds the worker (`cargo build --release -p factory-worker`) and runs it in the foreground.
  - `--setcap` asks `sudo` to give the built program `cap_chown` (Linux only). Without that flag the script never runs `sudo`; it prints the command and reports BLOCKED.
- **Where its files are.** One folder, `FACTORY_HOST_DIR`, holds the generated configuration, the workspaces, the artifacts, a copy of the protected checkout (the same folders that Compose mounted read-only into the container) and the host's database URL files. The default is `.local/host-worker` in the repository, used only when the policy allows that path as a mount source. A Linux checkout under `/home` is refused, and the script then asks for a folder such as `/srv/factory`. Job tokens go to `/run/user/<uid>/factory-tokens` when that folder exists (a tmpfs on a systemd Linux host, as the sandbox policy prefers), and otherwise to `FACTORY_HOST_DIR/tokens`. Every root is checked against `sandbox.forbidden_mount_sources` of `policies/security.yaml` before anything is written.
- **The configuration is generated**, never edited by hand. The script fills in `infra/compose/config/worker.host.example.yaml` (a template that `crates/composition/tests/examples.rs` parses like the other examples), then merges `FACTORY_HOST_DIR/credentials.yaml` over it when that file exists. That file holds the parts only a person can supply: the model provider, the GitHub App and the tenants. No credential is in the template or in the repository.
- **Docker.** `sandbox.docker_host` is the endpoint of the current `docker context`. `sandbox.docker_config` is an empty folder of the script's own, so the worker never follows a context or a credential helper.
- **The broker** listens where the sidecars reach the host, and nowhere else. On Linux that is the default bridge's gateway address, not every address of the machine. On Docker Desktop it is `127.0.0.1`, because Docker Desktop forwards its `host-gateway` address to the host's loopback. The sidecar's `--upstream` is the `host-gateway` address that a container on the bridge resolves, which the verify image looks up.
- **The API** keeps running in Compose. `scripts/local-up.sh --api` starts it without the container worker. The override file `infra/compose/host-worker.yml` mounts `FACTORY_HOST_DIR/artifacts` as the API's artifact store, so both read one store. On Linux the API runs as the host user (`FACTORY_UID`/`FACTORY_GID`), who owns the files.
- **The container worker** stays in `local.yml` as it is, for a deployment that does not run sandboxes. It must not run beside a host worker for the same tenants. `--factory` keeps starting both services, and `--api` starts only the API.

## Consequences

- Good: the local stack can run agent jobs without breaking the sandbox policy, using the topology the tests already run.
- Good: one script checks every path, address and capability before the worker starts, and names what is missing.
- Bad: the worker is not isolated from the operator's user by a container. On the operator's own machine this changes little, because the worker already drives the Docker daemon. It is not a production shape; Q3 stays open for that.
- Bad: a person now starts two things, `scripts/local-up.sh --api` and `scripts/worker-host.sh`.
- Neutral: on Docker Desktop no capability is needed (ADR 0035), and the broker stays on loopback.

## What was checked

- On the owner's Mac (Docker Desktop 29.9.3), with `scripts/local-up.sh --api` and the override:
  - The API answered `/healthz` and `/readyz` (database schema, policy and ports pass), with `FACTORY_HOST_DIR/artifacts` bound as its store.
  - `scripts/worker-host.sh --check` reported only the missing `credentials.yaml`. It found the docker context's endpoint and the verify image, and the sidecar upstream it resolved was `192.168.65.254`. The first try returned an IPv6 address, so the lookup asks for IPv4 only.
  - The worker started on the host passed its preparation (both database pools through the host URL files, the protected copy, the policies). With no provider entry it stopped at the broker ("no upstream was given", exit code 1). With a provider entry whose token file holds no real token, it stopped at the subscription token check.
- The script's own tests (`scripts/tests/test_worker_host.py`, with a fake `docker`, `getcap` and `uname`), which `scripts/ci.sh` runs: refused roots, the Linux listen address and upstream, the capability check, the credentials merge, and that no secret is printed.
- Not run: a job through the host worker. That needs the credentials only the owner holds (the model provider token and a registered GitHub App).
