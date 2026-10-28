# factory-composition

The shared composition core of the factory: what the worker, and later the API and the operator
CLI, are made of before each adds its own shell. A ring 3 **library**
([ADR 0015](../../docs/adr/0015-composition-library.md)). Only binaries in `apps/` may depend on it
(rule `DEP-11`), and it has no `main`, no HTTP route, no command parser and no loop.

## Modules

| Module | What it holds |
|---|---|
| `config` | The typed configuration: one YAML file read with the restricted reader of `factory-contracts`, the environment, secrets by file reference |
| `profile` | `production`, `local`, `test`, and the ports each may stand in for |
| `registry` | `PortRegistry`: every adapter in one value, and the check that runs `require_permitted` for every port |
| `startup` | The policy from the protected checkout (hashed), the sandbox image catalog |
| `redaction` | The redactor built from the policy, the registry of the factory's secret values, the telemetry scrubber, the broker wrapper that registers job tokens |
| `database` | The two pools and the two logins (ADR 0012) |
| `health` | Health and readiness as plain data |
| `telemetry` | The telemetry configuration with the real scrubber, and the `factory.job` stretch span |
| `system` | The real clock, identifier source, `Ticker` and shutdown signal |
| `seams`, `authority`, `sandbox_specs` | The seams the stages declare |
| `indexing` | Indexes what a sandbox writes, for the tenant, when it is written |
| `hooks` | The work a loop does before it claims (`BeforeClaim`) |
| `assemble` | Start-up in order (`prepare`), and the list of adapters not assembled (`blocked_adapters`) |

## What a binary does with it

1. Read the configuration: `FactoryConfig::from_environment` or `from_file`.
2. `assemble::prepare(&config, Identity { service, version })` runs the start-up checks and returns
   the policy, the redactor, the registry of secret values, the connected store and the telemetry
   guard.
3. Add what the binary alone needs (the worker starts the broker listener), then
   `Prepared::check_secret_kinds(profile)`.
4. Build a `PortRegistry`, call `check(profile)`, and only then build the engine.

## Tests

```text
cargo nextest run -p factory-composition
```

The database tests start a private PostgreSQL cluster from the local binaries through the storage
crate's provisioning code (`#[path]` include of `crates/storage/tests/support`). A test that cannot
get a server panics with `BLOCKED:` and is never a pass.
