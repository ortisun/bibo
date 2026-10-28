# factory-cli

The operator command line: a composition root in ring 3 ([ADR 0002](../../docs/adr/0002-workspace-layout-and-dependency-rule.md)).
It talks to the [API](../api/README.md) over HTTP with a token read from a file, and runs the environment checks of
`probe` in process through the composition library ([ADR 0015](../../docs/adr/0015-composition-library.md)).
It holds no database login and starts no process (rule DEP-10).

```text
factory-cli health   --api URL
factory-cli submit   --api URL --token-file FILE --repository ID --text-file FILE [--key K] [--source-ref R]
factory-cli status   --api URL --token-file FILE JOB
factory-cli timeline --api URL --token-file FILE JOB
factory-cli approve  --api URL --token-file FILE [--key K] JOB STAGE_RUN head=H evidence=sha256:D [reason...]
factory-cli reject   --api URL --token-file FILE [--key K] JOB STAGE_RUN reason...
factory-cli rework   --api URL --token-file FILE [--key K] JOB STAGE_RUN target=STAGE reason...
factory-cli pause | resume | cancel  --api URL --token-file FILE [--key K] JOB reason...
factory-cli probe    --protected-checkout DIR [--images-catalog FILE] [--profile production|local|test]
```

The address may also be set in `FACTORY_API_URL`. The words after the ids are the grammar every channel shares
(`factory_composition::commands`), so `approve` here and `/factory approve` in a pull request comment are read by the
same function. There is no command that merges or deploys: `merge`, `deploy`, `ready` and `undraft` are not commands.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | the command was not understood, or a local check failed (a bad id, a token file others can read, a `FAILED:` probe line) |
| 2 | **refused**: the API answered 4xx |
| 3 | **blocked**: the API is not ready or asked to try later (429, 5xx), or `probe` found something it cannot check (`BLOCKED:` lines) |
| 4 | **unreachable**: no connection, or no answer in 30 seconds |

## Secrets

The token is read from a file: a regular file, not a symbolic link, readable by its owner only. It is never read from
an argument or an environment variable. It is sent as `Authorization: Bearer` over HTTPS or to a loopback address, and
an `http://` address to anything else, or an address with credentials in it, is refused before any request. Redirects
and proxies are off. The token is not printed, logged or put in an error message; every test in `tests/api_calls.rs`
checks both output streams for it.

## `probe`

Runs the start-up checks the composition library runs for the worker that need no credential (the policy from the
protected checkout, hashed; the redactor built from it; the sandbox image catalog) and prints `OK:` for each. It then
prints a `BLOCKED:` line for each thing it cannot check, and exits 3: each agent runtime (`claude`, `codex`), whose
capability record is read by a probe inside the agent sandbox that needs the pinned image and a model credential; each
adapter the composition does not assemble yet (the agent runtime, the model router, the issue source and the change
host); and the two delivery seam methods that fail closed. **A `BLOCKED` is never a pass.**

What is not there: the command cannot run `claude --version` or `docker version` itself, because only the sandbox crate
may start `docker` or `git`, and only the runtime crate an agent tool. The capability record of a runtime therefore
stays BLOCKED here until the worker (or the API) exposes the probes it took at start-up; `CachedProbes` in the
composition library holds them and the live probe is BLOCKED there too.

## Tests

```text
cargo nextest run -p factory-cli                  # all
cargo nextest run -p factory-cli --test probe     # the probe command
```

`tests/api_calls.rs` runs the commands against a small loopback server that answers what a test says and records what it
was sent. It does not run the real API; the API's own tests cover the server side. **Not verified:** the command against
a real API on a real network, and TLS to a real host.

## Dependencies

One direct dependency is new to this app and **pending confirmation by a person**: `ureq` 3.5.0 (MIT or Apache-2.0,
default features off, `rustls` only), the crate and feature set the `github` and `egress` crates already use, so nothing
is new to `Cargo.lock`. It is listed with the reason in `docs/architecture/crate-dependency-rules.json`.
