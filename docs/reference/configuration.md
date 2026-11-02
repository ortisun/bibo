# Configuration reference

- Status: checked against the code by `scripts/docs-check.sh --config-keys`. The check lists the settings from the Rust structures themselves (the serde field names), so a setting added in code without a row here fails the check.
- Form: reference.
- Goal: say what every setting of the worker, the API and the command line does, what type it has, whether it is required, and what its default is.

The worker and the API each read one YAML file. The command line has no file: it takes options, listed in the [command reference](commands.md), and one environment variable. The types are in `crates/composition/src/config.rs` (the worker, and the parts the API shares) and `apps/api/src/config.rs` (the API).

## Rules that apply to every file

- The file is read with a restricted YAML reader. It refuses anchors, tags and merge keys, and it limits the size and the depth.
- An unknown key is an error. A misspelled setting stops the process. It never weakens a run.
- A setting with no default must be written. The profile, the database logins, the protected checkout and the artifact root have none.
- A secret is never a value. It is the path of a file. The file must be a regular file, not a symbolic link, and not readable by group or others (mode `0600` or `0400`). A value that looks like a URL with a password is refused wherever it appears.
- A path setting must be an absolute path.
- The environment may name the file, repeat the profile and replace the log filter. It cannot widen anything. A `FACTORY_PROFILE` that differs from the file stops the process.

## Environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `FACTORY_CONFIG` | worker, API | The path of the configuration file. Required. There is no default file. |
| `FACTORY_PROFILE` | worker, API | Optional. If set, it must equal `profile` in the file. A different value stops the process with exit code 2. |
| `FACTORY_LOG` | worker, API | Replaces `telemetry.log_filter`. Same syntax. |
| `FACTORY_API_URL` | command line | The API address. The `--api` option overrides it. |

## Profiles

The `profile` key picks the kind of run. There is no default.

| Profile | The engine records | A fake adapter is accepted for |
|---|---|---|
| `production` | production | nothing |
| `local` | test | the agent runtime, the model router, the broker and the GitHub ports |
| `test` | test | every port |

The [production guide](../guides/production.md) lists what a person must supply before `production` can run.

## Worker configuration

The worker reads `FACTORY_CONFIG`. In the column "Required", `yes` means the file is refused without it. `production` means the file is refused only under the production profile. For a key inside an optional table, `yes` means the key is required once the table is written.

### Top level

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `profile` | profile | yes | no default | `production`, `local` or `test`. |
| `protected_checkout` | path | yes | no default | A checkout of the protected configuration branch. It holds `policies/`, `allowlist/allowlist.yaml` and `.specify/`. It must lie outside every job workspace. |
| `definitions_root` | path | yes | no default | A checkout that holds `agents/`, `profiles/` and the schemas. Often the same directory as `protected_checkout`. |
| `database` | table | yes | no default | The two connection pools. |
| `artifacts` | table | yes | no default | Where artifacts are kept. |
| `sandbox` | table | yes | no default | The sandbox side. |
| `broker` | table | yes | no default | The model broker that the worker hosts. |
| `github` | table | production | none | The GitHub App. |
| `decisions` | table | production | none | The key that signs decision requests. |
| `registry` | table | no | none | The package registry the dependency gate asks about a new package. Without it the gate treats every package as unknown. |
| `advisory_database` | table | no | none | Where the date of the advisory database is kept. Without it the advisories gate is blocked. |
| `runtimes` | table | no | see keys | The agent tools in the agent image. |
| `stages` | table | no | see keys | Agents, budgets and limits of the stages. |
| `worker` | table | no | see keys | Pacing of the worker loop. |
| `telemetry` | table | no | see keys | Logs and traces. |
| `extra_secrets` | list of tables | no | empty | More secret values that the redactor must know. |

### database

The tenant pool and the system pool must name different login roles. A file that names the same role twice is refused. The role that each URL really connects as must equal the role the file names.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `database.tenant` | table | yes | no default | The tenant pool. A member of `factory_app`. |
| `database.tenant.url_file` | secret file | yes | no default | The file that holds the connection URL. |
| `database.tenant.login` | text | yes | no default | The login role the URL connects as. |
| `database.tenant.max_connections` | whole number | no | 8 | From 1 to 256. |
| `database.system` | table | yes | no default | The system pool. A member of `factory_system`. It finds work across tenants. |
| `database.system.url_file` | secret file | yes | no default | The file that holds the connection URL. |
| `database.system.login` | text | yes | no default | The login role the URL connects as. |
| `database.system.max_connections` | whole number | no | 8 | From 1 to 256. |

### artifacts

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `artifacts.root` | path | yes | no default | The root of the content-addressed store. |
| `artifacts.max_bytes` | whole number | no | 67108864 | The largest single artifact, in bytes. |

### sandbox

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `sandbox.images_catalog` | path | yes | no default | The catalog of pinned images, `infra/sandbox-images/images.json`. |
| `sandbox.token_root` | path | yes | no default | Where job token files are written for the broker mount. |
| `sandbox.platform` | text | no | none | The platform to pick from the catalog. Asked of the Docker daemon when absent. |
| `sandbox.workspace_root` | path | yes | no default | The root of the job workspaces. |
| `sandbox.owner` | text | no | factory-worker | The label value that marks the containers this factory created. |
| `sandbox.labels` | map of text to text | no | empty | More Docker labels for every object the factory creates. |
| `sandbox.remote` | table | no | see keys | Where target repositories are fetched from and pushed to. Set at most one of the two keys below. |
| `sandbox.remote.https_host` | text | no | none | The host of `https://<host>/<owner>/<name>.git`. When both keys are empty the host is `github.com`. |
| `sandbox.remote.directory` | path | no | none | A directory of bare repositories. The production profile refuses it. |
| `sandbox.sidecar_command` | list of text | no | empty | The arguments of the egress sidecar program. A deployment that runs agents must set them. The real sidecar refuses to start without them. |

The two root paths that the Docker daemon mounts, `sandbox.token_root` and `sandbox.workspace_root`, must be paths on the machine where the daemon runs. They must not lie under a forbidden mount source of the policy, such as `/var`, `/etc`, `/home`, `/usr`, `/root` or `/`.

### broker

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `broker.listen` | address | yes | no default | Where the listener binds, for example `127.0.0.1:8731`. |
| `broker.upstreams` | list of tables | production | empty | The providers the broker forwards to. The production profile needs at least one. |
| `broker.upstreams[].provider` | text | yes | no default | `anthropic` or `openai`. |
| `broker.upstreams[].base_url` | text | yes | no default | The base URL, `scheme://host[:port]`. |
| `broker.upstreams[].key_file` | secret file | yes | no default | The file that holds the provider key. |
| `broker.upstreams[].models` | list of text | no | empty | The models of the routing policy that this provider is enabled for. Empty means every model the policy lists for the provider. A name the policy does not list for it stops the start. |
| `broker.prices` | list of tables | no | empty | A price that may only raise a price of `policies/model_routing.yaml`. The policy is the price list; a model it does not list stops the start. |
| `broker.prices[].provider` | text | yes | no default | `anthropic` or `openai`. |
| `broker.prices[].model` | text | yes | no default | The model name as the provider spells it. |
| `broker.prices[].input` | whole number | yes | no default | Millionths of a dollar for one million input tokens. |
| `broker.prices[].cache_write` | whole number | yes | no default | The same unit, for cache write tokens. |
| `broker.prices[].cache_read` | whole number | yes | no default | The same unit, for cache read tokens. |
| `broker.prices[].output` | whole number | yes | no default | The same unit, for output tokens. |

### github

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `github.app_id` | whole number | yes | no default | The GitHub App identifier. |
| `github.key_file` | secret file | yes | no default | The file that holds the App private key. |
| `github.webhook_secret_file` | secret file | no | none | The webhook secret. The API holds this secret, so the worker leaves it out. |
| `github.api_base_url` | text | no | https://api.github.com | Where the GitHub API is. The production profile accepts `https://api.github.com` only. The other profiles also accept plain http on the loopback interface. |
| `github.installations` | list of tables | no | empty | Which installation of the App covers which repository of which tenant. A repository with no entry is unreachable, and the worker is blocked while the list is empty. |
| `github.installations[].tenant` | text | yes | no default | The tenant, as a UUID. |
| `github.installations[].repository` | text | yes | no default | The repository, as `owner/name`. |
| `github.installations[].installation_id` | whole number | yes | no default | The installation of the App on that repository. Above zero. |
| `github.bypass_attestations` | list of tables | no | empty | An administrator's statement that the App is on no bypass list of a repository. The App cannot read the list. Without a statement the repository runs at level L0. |
| `github.bypass_attestations[].tenant` | text | yes | no default | The tenant, as a UUID. |
| `github.bypass_attestations[].repository` | text | yes | no default | The repository, as `owner/name`. |
| `github.bypass_attestations[].principal` | text | yes | no default | The administrator who made the statement, as the UUID of their principal. |
| `github.bypass_attestations[].recorded_at` | text | yes | no default | When the statement was recorded, as a UTC time such as `2026-10-28T09:00:00Z`. |
| `github.write_issue_status` | true or false | no | true | Writes the state of each job on its issue: one `factory: <state>` label and one status comment. Set it to false to stop the worker writing on issues. Nothing else changes, because no job depends on the labels. The worker also needs `policies/issue-workflow.yaml` in the protected checkout when this is true. |

### registry

The crates.io API, asked about a package that a change adds as a new direct dependency. Anything the worker cannot read from the answer is unknown, and the gate reads unknown as the worst case.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `registry.base_url` | text | yes | no default | The base URL of the registry API, such as `https://crates.io`. The production profile needs https and a host that the egress policy lists for the cargo ecosystem. The stock policy lists `crates.io` (the entry `crates_api`, for the control plane's registry client), `index.crates.io` and `static.crates.io`. |
| `registry.user_agent` | text | production | none | The `User-Agent` the client sends. The registry asks clients to say who to reach. |
| `registry.timeout_seconds` | whole number | no | 10 | The wall time of one request. From 1 to 120. |
| `registry.max_response_bytes` | whole number | no | 1048576 | The largest answer read. A larger one reads as unknown. From 1 KiB to 16 MiB. |

### advisory_database

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `advisory_database.date_file` | path | yes | no default | A file with one line, the UTC time the database was last updated, such as `2026-10-28T09:00:00Z` or `2026-10-28`. The image build writes it, or a person keeps it in the protected checkout. A file that is missing, not a date or in the future reads as unknown. |

### runtimes

Which runtimes exist follows from `broker.upstreams`: the provider `anthropic` gives `claude-code-cli` and `openai` gives `codex-cli`. The keys below say where the tool is and which versions the adapter accepts. At start-up the worker probes each runtime in a sandbox. If the Docker daemon does not answer, the worker is blocked and says why.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `runtimes.claude_code` | table | no | none | The Claude Code tool. |
| `runtimes.claude_code.binary` | text | no | none | The path of the tool inside the image. Without it the adapter's own default is used. |
| `runtimes.claude_code.versions` | list of text | no | empty | The versions the adapter accepts. Empty means the one it was tested with. |
| `runtimes.codex` | table | no | none | The Codex tool. |
| `runtimes.codex.binary` | text | no | none | The path of the tool inside the image. |
| `runtimes.codex.versions` | list of text | no | empty | The versions the adapter accepts. |
| `runtimes.declare_capabilities` | true or false | no | false | Takes the capabilities of the runtimes from a declaration and not from a probe. The local and test profiles only: the production profile refuses it, because a declared list is a claim nobody checked. |

### decisions

The API signs each decision request with this key. The worker verifies the signature before it reads anything else in the record. Both processes name the same file. See the [rotation runbook](../runbooks/rotate-the-decision-key.md).

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `decisions.key_file` | secret file | yes | no default | The current key. At least 32 random bytes, so 64 hex digits. In production every directory above the file must be closed to group and others, and the file must belong to the user the process runs as. |
| `decisions.previous_key_file` | secret file | no | none | The previous key, during a rotation. It verifies only. |
| `decisions.previous_key_valid_until` | text | no | none | A UTC time such as `2026-11-02T12:00:00Z`, 72 hours after the rotation at most. Without it the production profile ignores the previous key. |

### stages

Every setting has a default, the numbers the stage tests use. A deployment names only what it changes.

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `stages.label` | text | no | factory | The label whose application asks the factory to work. |
| `stages.definition_commit` | text | production | none | The commit of the factory's gate definitions, 40 hex digits, recorded in every gate report. The other profiles derive one from the policy. |
| `stages.commit_identity` | table | no | see keys | The identity that commits are made under. |
| `stages.commit_identity.name` | text | yes | no default | The author name. Without the table the name is `Software Factory`. |
| `stages.commit_identity.email` | text | yes | no default | The author address. Without the table it is `factory@users.noreply.invalid`. |
| `stages.budget` | table | no | see keys | The budget of one stage run. |
| `stages.budget.wall_time_seconds` | whole number | no | 3600 | The wall time of a stage run. |
| `stages.budget.max_tokens` | whole number | no | 2000000 | The model tokens a stage run may use. |
| `stages.budget.max_cost_usd` | number | no | 10.0 | The model cost a stage run may use, in dollars. |
| `stages.budget.attempt_timeout_seconds` | whole number | no | 3600 | The wall time of one attempt. |
| `stages.budget.max_attempts` | whole number | no | 2 | The attempts of a stage run. |
| `stages.max_output_bytes` | whole number | no | 524288 | The largest answer of an agent. |
| `stages.max_patch_bytes` | whole number | no | 1048576 | The largest patch a stage reads. |
| `stages.max_clarification_rounds` | whole number | no | 2 | The rounds of questions the specification stage may ask a person. |
| `stages.agents` | table | no | see keys | The agent of each stage, by its identifier under `agents/`. |
| `stages.agents.intake` | text | no | intake-classifier | Classifies the request. |
| `stages.agents.specification_writer` | text | no | specification-writer | Writes the specification. |
| `stages.agents.specification_reviewer` | text | no | specification-reviewer | Reviews the specification. |
| `stages.agents.architect` | text | no | architect | Designs. |
| `stages.agents.critic` | text | no | code-reviewer | Criticizes the design. |
| `stages.agents.planner` | text | no | planner | Plans the tasks. |
| `stages.agents.builder` | text | no | builder | Writes the code. |
| `stages.agents.reviewer` | text | no | code-reviewer | Reviews the code. It must not be the builder. |
| `stages.agents.documentation_writer` | text | no | documentation-writer | Writes the documentation. |
| `stages.agents.documentation_reviewer` | text | no | documentation-reviewer | Reviews the documentation. |
| `stages.documentation` | table | no | see keys | How the documentation review builds the target project. |
| `stages.documentation.build` | list of text | no | cargo build --locked | The command that builds the project. |
| `stages.documentation.binary` | text | no | word-count | The program the build makes and the pages describe. |
| `stages.documentation.command_timeout_seconds` | whole number | no | 120 | The wall time of one command. |
| `stages.documentation.max_output_bytes` | whole number | no | 1048576 | The most output of one command. |

### worker

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `worker.name_prefix` | text | no | worker | A slug that starts the name of this worker in leases. The process id is appended. |
| `worker.poll_interval_ms` | whole number | no | 1000 | The wait between claims when there was no work. Above zero. |
| `worker.sweep_interval_s` | whole number | no | 10 | The wait between sweeps of expired leases and deadlines. Above zero. |
| `worker.drain_s` | whole number | no | 120 | How long a stop request lets a running attempt finish. After that the lease is left to expire and the worker exits with code 4. |
| `worker.tenants` | list of text | no | empty | The tenants this worker serves, as UUIDs. Empty means none: the worker admits no received job. |

### telemetry

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `telemetry.otlp_endpoint` | text | no | none | The collector endpoint. None means no export. |
| `telemetry.log_filter` | text | no | none | A log filter in the syntax of the tracing library. When absent the level is `info`. |

### extra_secrets

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `extra_secrets[].label` | text | yes | no default | The label in the redaction marker. |
| `extra_secrets[].file` | secret file | yes | no default | The file that holds the value. |

## API configuration

The API reads `FACTORY_CONFIG` too. It has its own type. It has one database pool, under `database.api`, and no system pool. Do not point a worker at an API file or the reverse.

### Top level

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `profile` | profile | yes | no default | `production`, `local` or `test`. |
| `protected_checkout` | path | yes | no default | The checkout that holds `policies/` and `allowlist/allowlist.yaml`. |
| `database` | table | yes | no default | The one pool of the API. |
| `listen` | address | yes | no default | Where the server binds, for example `127.0.0.1:8080`. Put TLS and a proxy in front of it. |
| `artifacts` | table | no | none | Where the API reads the documents of a job from: the artifact volume the worker writes. Without it the three endpoints that serve documents (`specification-draft`, `gate-reports`, `artifacts/{sha256}`) answer 503. The API reads and never writes it. |
| `github` | table | no | see keys | The webhook settings. |
| `decisions` | table | production | none | The key that signs decision requests. The same file the worker verifies with. |
| `tokens` | table | no | see keys | Token settings. |
| `limits` | table | no | see keys | Limits on one request and one source. |
| `telemetry` | table | no | see keys | Logs and traces. |

### database

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `database.api` | table | yes | no default | The API login. A member of `factory_api_app` and `factory_resolver`, and of nothing else. |
| `database.api.url_file` | secret file | yes | no default | The file that holds the connection URL. |
| `database.api.login` | text | yes | no default | The login role the URL connects as. |
| `database.api.max_connections` | whole number | no | 8 | From 1 to 256. |

### artifacts

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `artifacts.root` | path | yes | no default | The artifact volume. Required once the table is written. |
| `artifacts.max_bytes` | whole number | no | 67108864 | The largest document the store reads. The API serves at most 4 MiB of it in one download. |

### github

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `github.webhook_secret_files` | list of secret files | production | empty | One file for each webhook secret in the rotation window. The production profile needs at least one. |
| `github.factory_label` | text | no | factory | The label whose application starts a job. From 1 to 50 printable characters. |

### decisions

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `decisions.key_file` | secret file | yes | no default | The current key. At least 32 random bytes. The local and test profiles create the file with mode `0600` when it is missing. |
| `decisions.previous_key_file` | secret file | no | none | The previous key, during a rotation. |
| `decisions.previous_key_valid_until` | text | no | none | A UTC time, 72 hours after the rotation at most. |

### tokens

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `tokens.audience` | text | no | factory-api | The audience this API serves. A lower-case slug of at most 64 characters. A token issued for another audience is unknown. |

### limits

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `limits.max_body_bytes` | whole number | no | 262144 | The largest body of an ordinary request. From 1 byte to 4 MiB. The webhook has its own limit. |
| `limits.header_timeout_ms` | whole number | no | 10000 | How long a client may take to send the headers. |
| `limits.body_timeout_ms` | whole number | no | 10000 | How long a client may take to send the body once the headers are in. |
| `limits.request_timeout_ms` | whole number | no | 30000 | How long one request may take in all. |
| `limits.max_connections` | whole number | no | 256 | The most connections open at once. From 1 to 65536. |
| `limits.max_connections_per_source` | whole number | no | none | The most connections one source may hold. When absent it is a sixteenth of `max_connections`, at least 1. Behind a proxy every connection comes from the proxy, so set it to `max_connections` and cap clients at the proxy. |
| `limits.drain_s` | whole number | no | 15 | How long a stop request lets open requests finish. |
| `limits.per_ip_per_minute` | whole number | no | 600 | Requests allowed for each source address in a minute. The source is the TCP peer. A forwarded header is never read. |
| `limits.webhook_per_installation_per_minute` | whole number | no | 120 | Webhook deliveries allowed for each installation in a minute. |

### telemetry

| Key | Type | Required | Default | Notes |
|---|---|---|---|---|
| `telemetry.otlp_endpoint` | text | no | none | The collector endpoint. None means no export. |
| `telemetry.log_filter` | text | no | none | A log filter. When absent the level is `info`. |

## Command line

The command line reads no file. It takes its settings as options and one environment variable. See the [command reference](commands.md). The token is always read from a file named by `--token-file`, never from an option or the environment.

## Examples in the repository

- `infra/compose/config/worker.local.example.yaml` is a valid `local` configuration with no credential. The worker stops with `BLOCKED:` lines until a deployment adds the broker, the GitHub App and the tenants.
- `infra/compose/config/api.local.example.yaml` is the API file of the local stack. It names `protected_checkout` and the same `decisions.key_file` as the worker, and a test parses it as written.

## How this page is checked

`scripts/docs-check.sh --config-keys` reads the Rust structures and compares them with the tables above, in both directions. A key in code without a row fails. A row without a key in code fails.

For each key that exists in both, the check also compares three columns with the code: the type, whether the key is required, and the default when the default is a plain number or word. It also compares the environment variable names.

The check does not compare the notes, the ranges and the word `production` in the column "Required". A person keeps those true, with `validate()` in the two configuration files as the source.
