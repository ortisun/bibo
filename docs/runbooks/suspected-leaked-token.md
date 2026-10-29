# A secret may have leaked

- Status: written from the code, the policy and the [secrets and credentials](../security/secrets-and-credentials.md) document. The steps for the GitHub App and the model provider describe what those services offer in general, because the factory has never been connected to a real App or a real provider. The steps for the API token and the decision key are specific to this repository.
- Form: runbook.
- Goal: contain the damage of an exposed token, key or password, replace it, and find out whether anyone used it.

## Symptom

A secret appeared where it should not: in a log, a chat, a pull request, a screenshot, a committed file, or an agent's output. Or an audit record shows an action nobody on the team took.

Treat a secret as leaked when you cannot show that it was not. Replacing it costs little.

## Before you begin

- Do not repeat the secret in a ticket, a chat or a commit message. Name it by its kind and its file path.
- You can reach the host that holds the secret files, and the database as its owner.
- Decide who is the incident lead before you start.

## Steps

### 1. Contain

If the secret may be in use right now, cancel the jobs that are running and stop the worker. The broker token of a stage run is revoked when the stage run ends. Stopping the API closes the door to API tokens.

```bash no-run reason="needs a running API and a token"
factory-cli cancel --api "$FACTORY_API_URL" --token-file operator.token JOB The token of this job may have leaked.
```

### 2. Replace the secret that leaked

| Kind | Where it lives | Replace it |
|---|---|---|
| An API bearer token (`sfat_` followed by 43 characters) | The database keeps only its SHA-256 hash, in `api_tokens`. | Revoke it, then issue another. See step 3. |
| The decision signing key | `decisions.key_file` | Follow [rotate the decision key](rotate-the-decision-key.md). |
| The webhook secret | `github.webhook_secret_files` on the API, and the webhook setting at GitHub | Add the new secret as a second file, set it at GitHub, then remove the old file. The API accepts every secret in the list. Restart the API each time. |
| The GitHub App private key | `github.key_file` on the worker | Generate a new key for the App at GitHub, replace the file, restart the worker, and delete the old key at GitHub. |
| A GitHub installation token | Minted for one job and one repository, valid for at most one hour, revoked by the factory at the end of the job | Cancel the job. Revoke the token at GitHub if it is still valid. |
| A model provider key | `broker.upstreams[].key_file` on the worker | Revoke the key at the provider, create another, replace the file, restart the worker. The provider-side spend limit bounds the damage until then. |
| A database login password | The URL file named by `database.*.url_file` | Change the password of the login role in PostgreSQL as the owner, write the new URL into the file, restart the process. |
| A secret committed to a repository | The git history | Replace the secret first. Removing it from history does not make it safe again. Then run `./scripts/ci.sh --only secret-scan`, which scans the full history of all branches. |

The files must stay mode `0600` or `0400`, and must not be symbolic links. The processes refuse anything else.

### 3. Revoke an API token

An API token has no revoke command today. The store port has no operation for it. A person with the database owner login sets the revocation time. The change is final: once `revoked_at` is set it cannot change.

```sql no-run reason="changes a production table; run it as the database owner"
UPDATE api_tokens SET revoked_at = now() WHERE tenant_id = 'TENANT_ID' AND id = 'TOKEN_ID' AND revoked_at IS NULL;
```

The next request with that token gets `401`. The API keeps no cache, so there is no delay. To issue a new token, make 32 random bytes, format them with `tokens::format_token`, show the value once to its owner, and store `tokens::hash_token` of it. Rotation is two tokens that overlap, then a revocation of the old one.

### 4. Find out whether it was used

- `api_tokens.last_used_at` tells you when an API token was last seen.
- The job timeline shows the audit records of a job: `decision.requested`, `decision.applied`, `decision.rejected` and `decision.denied`. A request made with a stolen approver token shows as a decision by that person. Compare the times with what the person did.
- Check that the worker's `decision.applied` rows carry the allowlist hash of the time. A row that the worker did not write is not trusted: the keyed word is wrong, and the row is rejected with `not_signed`.
- For a provider key, read the provider's usage page. For the GitHub App, read the App's audit log.

### 5. Remove the cause

Find how the secret got out and close that path. The redactor and the secret scan catch the shapes they know. They did not catch a token glued to a letter, a digit or an underscore, nor a URL password with an unusual host. Findings RR-1 to RR-4 and RR-22 of the [re-review](../reviews/authority-api-supply-chain-security-rereview.md) list the shapes that are still open.

## Check that it worked

- The old secret fails: an API token gets `401`, an old webhook secret gets `401` from the webhook endpoint, an old provider key is refused by the provider.
- The new secret works: `factory-cli health --api "$FACTORY_API_URL"` answers, the worker starts, and a test decision is applied.
- `./scripts/ci.sh --only secret-scan` passes after you removed the secret from the tree.
- You wrote down what leaked, when, how you found out, and what you replaced.

## If something goes wrong

| You see | Why | What to do |
|---|---|---|
| The worker refuses to start after you replaced a file | The file has the wrong mode, is a link, or holds a URL with a password inline. | Fix the file. The message names the path and never the value. |
| Jobs still run with the old key | The process was not restarted. | The keys are read at start-up. Restart. |
| You cannot tell whether a token was used | Few records exist for some secrets. | Assume it was used. Review what the person or the App could reach. |
