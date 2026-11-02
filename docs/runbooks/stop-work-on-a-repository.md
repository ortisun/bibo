# Stop the work on a repository

- Status: written on 2026-11-02 from the code of the repository routes and of the issue status step. It was not exercised against a live deployment, because none exists.
- Form: runbook.
- Goal: stop the factory from working on one repository in an incident, knowing what `disable` does and what it does not do.

## Symptom

You need the factory to stop working on a repository now. A job wrote something it should not have, a credential for the repository may have leaked, or the project map was wrong.

## What disable does, and what it does not

`factory-cli repository disable` stops new work. It is not a stop button.

| After `disable` | What happens |
|---|---|
| A label event for the repository | The webhook drops it. No job is made. |
| A job submitted through the API | It is refused. |
| A job that already exists | It runs on. Its stages go on, and it can still open a draft pull request. |
| The status on the issue of a job that exists | The factory stops writing it. The issue keeps the last `factory:` label that was written, and that label goes stale. |

The status step checks that the repository is enabled each time before it writes. It writes no final state for a disabled repository, and it does not go back for it when you enable the repository again.

## Before you begin

- You hold the `operator` designation on the protected allowlist. Disabling and cancelling need it.
- You know the repository identifier that `repository register` printed.
- You can list the open jobs of the repository. No command lists the jobs of one repository today. Use the issues that carry a `factory:` label other than a final one, the status comments the factory wrote, or ask the person who runs the database.

## Steps

### 1. Disable the repository

```bash no-run reason="needs a running API and a token"
factory-cli repository disable --api "$FACTORY_API_URL" --token-file operator.token REPOSITORY_ID An incident is open for this repository.
```

Check it with `factory-cli repository show`. The line `Enabled:` must say `no`.

### 2. Cancel each job that is still open

For each job that you found, cancel it. Do this for every job. Disabling the repository did not touch them.

```bash no-run reason="needs a running API and a token"
factory-cli cancel --api "$FACTORY_API_URL" --token-file operator.token JOB The repository is stopped because of an incident.
```

`factory-cli status JOB` shows the new state of the job. A job that is being stopped can show `CANCELLING` before it shows `CANCELLED`.

### 3. Deal with the stale label

The issue of each job keeps the `factory:` label from before the disable, for example `factory: working`. The label is wrong now.

Do not remove it by hand. The GitHub Action reverts any `factory:` label that a person changes, because only the App may write that namespace. Write a comment on the issue that says what happened. The label changes again when a later job on that issue writes its state.

### 4. After the incident

Fix the cause. If the project map was wrong, confirm the right commit with `repository confirm-map`. An approver then enables the repository again with `repository enable`, naming the commit that was read. See the [onboarding guide](../guides/onboarding.md).

## Confirm that it worked

- `factory-cli repository show` says the repository is not enabled.
- Every job you listed is `CANCELLED`, or in a final state.
- A label event on an issue of the repository makes no job.
- The issues carry a comment that explains the stale label.

## What this runbook cannot do

- It cannot make a running stage stop at once. A cancel is a decision that the engine applies, and `factory-cli status` shows when it has.
- It cannot take back a draft pull request that was already opened. Close it on GitHub.
