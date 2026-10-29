# A job is waiting for a person

- Status: the commands are the real ones. The decision path through the API and the worker was run in test mode (`apps/api/tests/full_run.rs`), not against a live deployment.
- Form: runbook.
- Goal: find out what a waiting job needs, then approve, reject, send back or cancel it.

## Symptom

A job stays in the state `WAITING_FOR_HUMAN`. No stage advances. Nobody has answered the factory.

A job waits for a person in these cases: the specification draft needs approval, the pull request needs approval, an agent asked for a person, a budget limit was reached, a gate returned `NEEDS_HUMAN`, or the original request changed after it was authorized and the requester must confirm.

## Before you begin

- You hold the designation that the verb needs: `approver` for `approve`, `reject` and `rework`, and `operator` for `pause`, `resume` and `cancel`. A designation comes from the protected allowlist. A GitHub role never grants one.
- You have a token file that only you can read.
- A worker is running for the tenant. The worker applies each decision. Without it a decision stays recorded and unapplied. See `worker.tenants` in the [configuration reference](../reference/configuration.md).

## Steps

### 1. See what the job waits on

```bash no-run reason="needs a running API and a token"
factory-cli status --api "$FACTORY_API_URL" --token-file approver.token JOB
factory-cli timeline --api "$FACTORY_API_URL" --token-file approver.token JOB
```

`status` prints each stage run with its state and its identifier. The stage run in `WAITING_FOR_HUMAN` is the one you answer. `timeline` prints the moves with their reasons. The last `stage_run.waiting_for_human` line names the reason, for example `agent-requested-a-human`.

### 2. Read what you are deciding on

For the specification draft, `show-draft` gives the commit that holds it, the head of the ledger and the values to approve with, and `artifact` prints the draft document:

```bash no-run reason="needs a running API and a token"
factory-cli show-draft --api "$FACTORY_API_URL" --token-file approver.token JOB
factory-cli artifact --api "$FACTORY_API_URL" --token-file approver.token JOB DRAFT_SHA256
```

For the gate reports, `status --gates` lists them with their hashes, and `artifact` prints one:

```bash no-run reason="needs a running API and a token"
factory-cli status --gates --api "$FACTORY_API_URL" --token-file approver.token JOB
```

For the `APPROVAL` stage run, open the draft pull request on GitHub. Its description holds the evidence manifest hash, the gates that ran and the ones that did not, and the line `Ledger head, entry N` with a hash. Read the diff and the gate list.

### 3. Answer

To approve the pull request, give the head commit you read and the ledger hash from the description. Write `sha256:` before the hash.

```bash no-run reason="needs a running API, a token and a real job"
factory-cli approve --api "$FACTORY_API_URL" --token-file approver.token JOB STAGE_RUN head=HEAD_COMMIT evidence=sha256:LEDGER_HASH Read the diff and the evidence.
```

To refuse, or to send the work back to a stage:

```bash no-run reason="needs a running API, a token and a real job"
factory-cli reject --api "$FACTORY_API_URL" --token-file approver.token JOB STAGE_RUN The change does not match the request.
factory-cli rework --api "$FACTORY_API_URL" --token-file approver.token JOB STAGE_RUN target=IMPLEMENTATION The tests do not cover the empty file.
```

To stop the job, or to hold it while you think:

```bash no-run reason="needs a running API, a token and a real job"
factory-cli cancel --api "$FACTORY_API_URL" --token-file operator.token JOB The issue was withdrawn.
factory-cli pause --api "$FACTORY_API_URL" --token-file operator.token JOB Waiting for the release freeze to end.
factory-cli resume --api "$FACTORY_API_URL" --token-file operator.token JOB The freeze has ended.
```

Each command prints an idempotency key. If the answer is lost, repeat the command with `--key` and that key. The repeat does not apply the decision twice.

## Check that it worked

The command prints `Decision ... is recorded`. That is not the end. The API only records the decision. The worker applies it on its next pass. Poll the timeline:

```bash no-run reason="needs a running API and a token"
factory-cli timeline --api "$FACTORY_API_URL" --token-file approver.token JOB
```

You should see `recorded: decision.requested` and then `recorded: decision.applied`. After an approval of the pull request the job ends `COMPLETED`. The factory does not merge. You merge outside it.

## If something goes wrong

| You see | Why | What to do |
|---|---|---|
| Exit code 2 and `you are not permitted to do this` | You do not hold the designation, or you are not on the allowlist. | Ask an `org_admin` to check the allowlist. The answer never says which test failed. |
| `recorded: decision.rejected` after your request | The worker refused it. The marker holds a fixed code, not a reason in words. Common codes: the request is not signed with the key the worker holds (`not_signed`), the specification draft moved since you read it (`draft_moved`), or the head is no longer the head the approval request names. | Read the head and the evidence again and repeat the decision. For `not_signed`, check that the API and the worker use the same decision key, see [rotate the decision key](rotate-the-decision-key.md). |
| Nothing after `decision.requested` for several minutes | No worker serves the tenant, or the worker is stopped. | Start the worker. Check `worker.tenants`. A request that stays unapplied for 72 hours is rejected. |
| You cannot find the head and the ledger hash of a specification draft | `factory-cli show-draft JOB` prints them. If it answers `503`, the API has no artifact root in its configuration. | Add `artifacts.root` to the API configuration. |
| An approval is refused while a translation warning is open (`gates_not_clear`) | Each open warning needs a decision of the person who approves. | Read the warnings in the gate reports (`factory-cli status --gates JOB`, then `factory-cli artifact JOB HASH`), then decide on each one by its number: `factory-cli ack-translation-warning JOB APPROVAL_STAGE_RUN 1 The translation says what the original says.` Then repeat the approval. A new approval request has another manifest and needs its decisions again. |

## Related

- [Command reference](../reference/commands.md): every verb, option and exit code.
- [Walkthrough](../walkthroughs/test-mode-run.md): the two approvals in a recorded run.
