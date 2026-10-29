# Runbooks

- Status: written on 2026-10-29. Each runbook covers a situation that exists in the code today. None was exercised against a live deployment, because none exists. Where a step was only tested in test mode, the runbook says so.
- Form: index of how-to guides.
- Goal: help a person who operates the factory find the right procedure for a symptom.

## Which runbook

| You see | Read |
|---|---|
| A job that has waited for a long time in `WAITING_FOR_HUMAN` | [A job is waiting for a person](stuck-waiting-for-a-person.md) |
| A job whose validation stage waits for a decision about a new dependency | [A dependency decision is waiting](dependency-decision-waiting.md) |
| A stage run in `BLOCKED` because a tool, an image or the container runtime is missing | [A stage is blocked by the environment](environment-block.md) |
| A damaged or lost database or artifact store | [Restore from a backup](restore-from-backup.md) |
| `no PostgreSQL server`, a full shared-memory table, or a Docker problem when you run the tests or the local stack | [Leaked test clusters and Docker problems](leaked-test-clusters.md) |
| A reason to replace the key that signs decision requests | [Rotate the decision signing key](rotate-the-decision-key.md) |
| A token, a key or a secret that may have been exposed | [A secret may have leaked](suspected-leaked-token.md) |

## Conventions

Every runbook has the same parts: the symptom, how to see it, what to do, and how to confirm that it worked. The commands use two placeholders. `JOB` is the job identifier and `STAGE_RUN` is the stage run identifier, both UUIDs. `factory-cli status JOB` prints both.

The command line needs the address of the API and a token file. The runbooks assume you set the address once:

```bash no-run reason="needs a running API; set the address of your own deployment"
export FACTORY_API_URL=https://factory.example.test
```

The token comes from a file that only you can read, named with `--token-file`. It never goes into an option or the environment. See the [command reference](../reference/commands.md).

## What a runbook cannot do

- It cannot make a decision for you. The factory records only decisions of people who hold the right designation on the protected allowlist.
- It cannot skip a gate. There is no verb that overrides a BLOCKED stage, and no verb that merges or deploys.
- It does not replace the [operations documents](../operations/local-deployment.md) for the local stack, the [backup and restore guide](../operations/backup-and-restore.md) and the [troubleshooting page](../operations/troubleshooting.md). The runbooks link to them and do not copy them.
