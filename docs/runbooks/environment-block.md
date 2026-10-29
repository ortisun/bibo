# A stage is blocked by the environment

- Status: written from the state machine and the start-up code. No recorded run has a stage blocked by the environment, so the recovery path below is described, not demonstrated.
- Form: runbook.
- Goal: find out what the environment lacks, fix it, and get the job moving again or end it.

## Symptom

A stage run is `BLOCKED` and the job is `BLOCKED`. No attempt is running. Nothing retries, because retrying with the same settings cannot help.

The state machine gives these causes for an environment block: the container runtime is unreachable, a sandbox image is not on the host, the posture check of the created container found a difference from the policy, a required tool or runtime capability is absent, or a policy file could not be loaded. A gate that cannot run, for example a missing tool, also gives BLOCKED. The factory never turns BLOCKED into a pass.

A block can have other causes. A deterministic policy check can block, such as a builder change to a protected path. That is not an environment block. The timeline tells the two apart: the event holds the gate and the code of the block.

## Before you begin

- You can read the job: `factory-cli status` and `factory-cli timeline` need any designation.
- You can reach the machine where the worker runs, to read its log and to fix its environment.

## Steps

### 1. See the block

```bash no-run reason="needs a running API and a token"
factory-cli status --api "$FACTORY_API_URL" --token-file operator.token JOB
factory-cli timeline --api "$FACTORY_API_URL" --token-file operator.token JOB
```

`status` shows the stage run as `BLOCKED`. `timeline` shows `stage_run.blocked` with a transition `S11` (a gate blocked) or `S21` (an attempt was blocked by the environment).

### 2. Find the cause

Read the worker log for the attempt. Each log line carries the correlation id of the job. Typical causes and where to look:

| Cause | How to check |
|---|---|
| The Docker daemon is not reachable | `docker info` on the worker host. The worker needs the daemon for every sandbox. |
| A sandbox image is missing or does not match the catalog | `infra/sandbox-images/images.json` lists the pinned images by digest. Compare with `docker image ls`. The agent image must be rebuilt and tested with `infra/sandbox-images/test.sh` before a live run. |
| The posture check found a difference | The audit stream holds the denial. The sandbox spec must match `sandbox` in `policies/security.yaml`. |
| A tool or runtime capability is missing | `factory-cli probe` lists what it cannot check. The capability probes of the runtimes stay BLOCKED until a runtime adapter exists. |
| A policy file cannot be loaded | Start the worker by hand. It prints the start-up failure and exits with code 1. |

### 3. Fix the environment

Repair the cause on the worker host. Do not edit the policy to make the block go away. A policy change is a reviewed pull request on the protected branch.

### 4. Move the job

The state machine allows these ways out of a blocked stage run:

- The block clears. A passed capability re-probe, or a dependency that is now available, returns the stage run to `READY` (transition `S17`, by an operator).
- A person sends the work back: `factory-cli rework` with the stage run and `target=STAGE` (transition `S15`).
- A person cancels the job: `factory-cli cancel` (transition `S19`).

The command line has no `unblock` verb today. The worker README lists no override verb either: the override transition `S18` exists in the state machine, and the security re-review says to wire none until finding RR-18 is closed.

```bash no-run reason="needs a running API, a token and a blocked job"
factory-cli rework --api "$FACTORY_API_URL" --token-file approver.token JOB STAGE_RUN target=VALIDATION The Docker daemon is back; run the stage again.
```

## Check that it worked

`factory-cli timeline` shows the stage run moving to `READY` or `REWORK_REQUESTED` and then a new attempt (`attempt.running`). The job leaves `BLOCKED` when every blocked stage run has a recorded disposition.

## If something goes wrong

| You see | Why | What to do |
|---|---|---|
| The block returns at once | The cause is not fixed. | Read the worker log again. |
| `rework` is refused | You lack the designation, or the stage run is not blocked. | Check `status`, and check the allowlist. |
| The job stays `BLOCKED` and you cannot find the cause | The audit stream may hold the answer. | Read the full timeline. If it names nothing, cancel the job and file the case as a finding. |

## Related

- [Troubleshooting the local deployment](../operations/troubleshooting.md): the Docker and stack errors, with the messages as they appear.
- [Leaked test clusters and Docker problems](leaked-test-clusters.md).
- [State machine](../architecture/state-machine.md): the guards of the transitions named above.
