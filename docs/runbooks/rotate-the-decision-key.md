# Rotate the decision signing key

- Status: the settings and the rules are those of the code (`crates/composition/src/decision_signing.rs`) and of the [API README](../../apps/api/README.md). The rotation was tested in test mode. It has not been done on a deployment.
- Form: runbook.
- Goal: replace the key that signs decision requests without losing a request that is already recorded, and stop the old key from verifying on its own.

## Symptom

You need a new key because the old one may have leaked, because a person who could read it has left, or because the schedule says so. A decision request is an audit record that ends with a keyed word. Only the API can make the word. The worker applies a request only when the word is right. A key that leaked lets someone forge a request, so rotate at once.

## Before you begin

- You can change the configuration and restart the API and the worker. Both read the key files when they start.
- You know the approval window: 72 hours. A request older than that is rejected, so the old key must stay valid for no longer.
- The key must be random: at least 32 bytes, written as 64 hexadecimal digits. A key of one repeated byte or one short repeated word is not a key.
- In the production profile every directory above the key file must be closed to group and others (a sticky directory is allowed). The file belongs to the owner of its directory, or the directory belongs to root, **and to the user the process runs as** (RR-25): a key that another user owns is refused, whatever its mode says, because that user can replace it. The process finds its own user by making a file in the temporary directory and reading the owner of it, which is an approximation: on a file system that maps owners (a network mount that squashes root) the answer is the mapped owner. A process that can write no file in the temporary directory or in its working directory is refused, because a user that could not be found was not checked. The file mode is `0600` or `0400`.

## Steps

### 1. Make the new key

```bash no-run reason="creates a real secret on the host that holds the keys"
umask 077
openssl rand -hex 32 > /run/secrets/decision_signing_key_new
```

Do not print the key, paste it in a chat or commit it. Do not put it in the configuration. The configuration names the file only.

### 2. Name both keys

On the API host and on the worker host, move the file that is current to the previous name, and put the new file in its place. Then change the `decisions` table of both configuration files:

```yaml
decisions:
  key_file: /run/secrets/decision_signing_key
  previous_key_file: /run/secrets/decision_signing_key_previous
  previous_key_valid_until: 2026-11-02T12:00:00Z
```

Write `previous_key_valid_until` as a UTC time, 72 hours after the moment you restart. Without it the production profile ignores the previous key. That is safe, and it rejects the requests that the old key signed and nobody has dealt with yet.

### 3. Restart the API and the worker

Restart both. The API signs with `key_file` from now on. The worker accepts a word made with either key until the time passes.

### 4. Remove the old key

After `previous_key_valid_until` passes and the pending requests are dealt with, delete `previous_key_file` and `previous_key_valid_until` from both configuration files, delete the old key file, and restart both again. The `local` and `test` profiles accept the previous key until its file is removed, so do not skip this step there.

## Check that it worked

1. Record a decision with the command line, for example a `pause` on a test job: `factory-cli pause --api "$FACTORY_API_URL" --token-file operator.token JOB Checking the new key.`
2. Read the timeline. It must show `decision.requested` and then `decision.applied`.
3. A `decision.rejected` marker with the fixed code `not_signed` means the worker does not hold the key the API signed with. Check that both processes name the same file, read the same content, and were restarted.

```bash no-run reason="needs a running API and a token"
factory-cli timeline --api "$FACTORY_API_URL" --token-file operator.token JOB
```

## If something goes wrong

| You see | Why | What to do |
|---|---|---|
| The API or the worker refuses to start and names the key file | The file is not mode `0600` or `0400`, is a symbolic link, is shorter than 32 bytes, or lies under a directory that others can write. | Fix the file or the directory. The message never prints the key. |
| Every request is `not_signed` | The two processes hold different keys. | Copy the same file to both hosts, or let both read one path. Restart both. |
| Requests from before the rotation are `not_signed` | The previous key is missing, or `previous_key_valid_until` has passed. | Put the previous key back and set a new time, or ask the person to repeat the decision. |
| You are unsure the old key ever left the host | Assume it did. | Rotate, then follow [a secret may have leaked](suspected-leaked-token.md). |

## What this does not give you

The worker holds the same key and can verify. A compromised worker could also forge a request, because the key is shared. The security re-review notes that an asymmetric signature would remove this and add a dependency. It is not done.
