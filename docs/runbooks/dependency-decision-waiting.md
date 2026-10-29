# A dependency decision is waiting

- Status: the verbs and the rules are the real ones. The path was tested in test mode (`apps/api/tests/dependency_run.rs`). No live run has met it.
- Form: runbook.
- Goal: decide on a new dependency, or on the build code of one, so that the blocked validation stage can run again.

## Symptom

A job stops in the validation stage. The stage run is `BLOCKED`. The gate `dependency-review` is blocked with the reason `policy_unresolvable`: the change adds a direct dependency, or a package with build code, and nobody has decided on it yet.

In the production profile this happens for every new direct dependency. The registry source and the advisory database have no real adapter, so the gates cannot judge a package on their own. They answer "unknown", and the decision goes to a person.

## Before you begin

- `approve-dependency` needs the `approver` designation. `approve-build-code` needs `security_approver`. The person who asked for the job may not be the one who approves build code. The policy engine checks this again when the worker applies the decision.
- You have the name and the version of each awaited package, and its checksum when two awaited packages share a name and a version.
- You have read what the package does, who maintains it and which licence it has. The factory does not decide this for you.

## Steps

### 1. See that the job is blocked on a dependency

```bash no-run reason="needs a running API and a token"
factory-cli status --api "$FACTORY_API_URL" --token-file approver.token JOB
factory-cli timeline --api "$FACTORY_API_URL" --token-file approver.token JOB
```

The `VALIDATION` stage run shows `BLOCKED`, and the timeline shows `stage_run.blocked`. The gate report of `dependency-review` names the awaited packages with their versions and checksums. No API endpoint serves gate reports today. An operator reads the report from the artifact store, by the hash in the ledger entry `The gate dependency-review reported BLOCKED`.

### 2. Decide

For a new direct dependency:

```bash no-run reason="needs a running API, a token and a blocked job"
factory-cli approve-dependency --api "$FACTORY_API_URL" --token-file approver.token JOB PACKAGE_NAME VERSION CHECKSUM_PREFIX I read the licence and the maintainers and accept this package.
```

For the build script or procedural macro of a package:

```bash no-run reason="needs a running API, a token and a blocked job"
factory-cli approve-build-code --api "$FACTORY_API_URL" --token-file security.token JOB PACKAGE_NAME VERSION CHECKSUM_PREFIX I read the build script and it only compiles local sources.
```

The reason has 10 to 500 characters. It is redacted before the engine stores it. `CHECKSUM_PREFIX` is 12 to 64 hex digits, with or without `sha256:`. You need it only when two awaited packages share a name and a version. Without `--stage-run` the decision is for the blocked validation stage run of the job.

To refuse a package, do not approve it. Send the work back with `rework`, or cancel the job. See [a job is waiting for a person](stuck-waiting-for-a-person.md).

### 3. Let the stage run go again

A decision is recorded where the engine reads it. The stage run stays `BLOCKED` until an operator lets it go:

```bash no-run reason="needs a running API, a token and a blocked job"
factory-cli unblock --api "$FACTORY_API_URL" --token-file operator.token JOB STAGE_RUN The decision on the package is recorded; run the stage again.
```

The engine lets the run go only when a decision for what it waited for was recorded after the attempt that blocked it. Before that, the answer is `not_cleared`. `STAGE_RUN` is the validation stage run that `factory-cli status JOB` prints.

## Check that it worked

The timeline shows `decision.dependency_requested`, then `decision.applied`. The validation stage run leaves `BLOCKED` when every awaited package has a decision that matches its exact name, version and checksum. The engine reads what it stored when the stage run blocked. It does not take the package from your words.

## If something goes wrong

| You see | Why | What to do |
|---|---|---|
| `decision.rejected` | The request was not signed, was older than 72 hours, came from someone who is not a current user of the tenant, or the person lacks the designation now. The marker holds a fixed code. | Check the allowlist and repeat the decision. |
| The stage stays `BLOCKED` after `decision.applied` | Another package is still awaited, or the advisories gate is blocked. | Decide on each awaited package. The advisories gate stays BLOCKED in the production profile until an adapter reports the date of the advisory database. |
| The API answers `400` | A field is missing or wrong, for example a reason of fewer than 10 characters. | Read the field named in the answer. |

## Related

- The supply chain gates and their reviews: [supply chain review](../reviews/supply-chain-and-delivery-security-review.md) and [re-review](../reviews/authority-api-supply-chain-security-rereview.md).
- The policy rows `add_new_direct_dependency` and `approve_build_code` in `policies/approval.yaml`: [policy reference](../reference/policies.md).
