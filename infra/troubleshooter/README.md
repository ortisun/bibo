# Troubleshooter upstreams

The services that the troubleshooter's MCP gateway reaches as upstreams ([ADR 0021](../../docs/adr/0021-troubleshooter-agent-and-mcp-sources.md), decision 3). Today that is one: the official VictoriaMetrics MCP server, which the gateway offers to the agent as the `vm_*` tools. The agent never reaches it directly and never holds its token.

What the troubleshooter does, and what a person must set up before a live run, is in [the troubleshooter guide](../../docs/guides/troubleshooter.md).

## What is here

| File | Purpose |
|---|---|
| `compose.yaml` | `mcp-victoriametrics` v1.21.0, pinned by digest, in Streamable HTTP mode on `127.0.0.1:8809`, reading the VictoriaMetrics of [`infra/otel`](../otel/README.md). |

The Datadog MCP server is remote (`https://mcp.<site>/v1/mcp`) and runs nothing here. The PostgreSQL MCP server runs inside the troubleshooter process ([`apps/mcp-postgres`](../../apps/mcp-postgres/README.md) is the same code as a program).

## Start it

You need Docker with Compose 2.24 or newer.

1. Start the telemetry stack. The server joins its network and reads VictoriaMetrics there as `http://victoriametrics:8428`:

   ```bash
   docker compose -f infra/otel/compose.yaml up -d --wait
   ```

2. Make the token file, once. The gateway and the server read the same file:

   ```bash
   mkdir -p ~/.config/factory
   umask 077
   openssl rand -hex 32 > ~/.config/factory/vm-mcp.token
   ```

   The server refuses to start (exit code 2) when the file is missing, empty or shorter than 32 characters. On Linux the file must also be readable by the user the container runs as (1000 by default): either `chown 1000:1000` the file, or set `FACTORY_VM_MCP_UID` and `FACTORY_VM_MCP_GID` to the file's owner. Never set them to 0. Docker Desktop on macOS reads a `0600` file of yours without either.

3. Start the server and wait until it is healthy. It takes about 20 seconds (see "Memory" below):

   ```bash
   FACTORY_VM_MCP_TOKEN_FILE=$HOME/.config/factory/vm-mcp.token \
   docker compose -f infra/troubleshooter/compose.yaml up -d --wait
   ```

4. The troubleshooter configuration names the same token file and the address `http://127.0.0.1:8809/mcp` (the settings of `apps/troubleshooter`, not built yet).

5. Stop it:

   ```bash
   FACTORY_VM_MCP_TOKEN_FILE=$HOME/.config/factory/vm-mcp.token \
   docker compose -f infra/troubleshooter/compose.yaml down
   ```

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `FACTORY_VM_MCP_TOKEN_FILE` | none, required | The token file of step 2. Mounted as the Docker secret `/run/secrets/vm_mcp_token`. |
| `FACTORY_VM_MCP_PORT` | `8809` | Host port, published on `127.0.0.1` only. |
| `FACTORY_OTEL_NETWORK` | `factory-otel_default` | The network of the telemetry stack. |
| `FACTORY_VM_MCP_UID`, `FACTORY_VM_MCP_GID` | `1000` | The user the server runs as. |

## Where each secret file goes

| File | Who makes it | Mode | Read by |
|---|---|---|---|
| The VictoriaMetrics MCP token (`~/.config/factory/vm-mcp.token` above) | you, step 2 | `0600` | this compose file (Docker secret) and the gateway |
| The Datadog API key and application key | a person with Datadog admin rights ([guide](../../docs/guides/troubleshooter.md)) | `0600` | the gateway; the API key also by the collector overlay `infra/otel/compose.datadog.yaml` |
| The `factory_troubleshooter` database password | the person who runs [`docs/database/observer-login.sql`](../../docs/database/observer-login.sql) | `0600` | the gateway's in-process PostgreSQL upstream, or `apps/mcp-postgres` |

No secret value is ever in a compose file, an argument or a container's configuration.

## What the server is allowed to do

- **Tools.** `MCP_DISABLED_TOOLS` is exactly `upstreams.victoriametrics.disabled_tools` of [`policies/troubleshooting.yaml`](../../policies/troubleshooting.yaml): `export`, `flags`, the four debug tools, `test_rules` and `metric_statistics`. Checked on 2026-11-20 with `tools/list`: none of them is offered. The server still offers tools that the gateway does not map (`documentation`, `prettify_query`, `rules`, `series`, `top_queries`, `tsdb_status`); the gateway's allowlist is what the agent sees. `MCP_DISABLE_RESOURCES=true` removes the documentation resources.
- **Answers.** `MCP_MAX_RESPONSE_SIZE` is 256 KiB, four times the gateway's 64 KiB result cap. A larger VictoriaMetrics answer is a tool error, which tells the agent to narrow the query.
- **Logs.** JSON at level `info`. Never `debug`: at that level the server logs request and result payloads.

## Security choices

- **Loopback only.** The port is published on `127.0.0.1`. Checked: the binding is `127.0.0.1:<port>`.
- **A token on every call.** Checked on 2026-11-20: `initialize` without a token and with a wrong token both get 401; with the token, 200. The health paths need no token, so the container health check works.
- **The token stays out of the container's configuration.** The image's shell reads the secret file into `MCP_AUTH_TOKEN` of the server process only (the server has no file variant). Checked: the token value is not in `docker inspect` and not in the container log. It is in the environment of the server process inside the container, which only someone who can run `docker exec` on this machine can read.
- **Hardened container.** User 1000, read-only root file system, every capability dropped, `no-new-privileges`, a 16 MiB `/tmp`, limits on memory and processes.
- **Pinned image.** `ghcr.io/victoriametrics/mcp-victoriametrics:v1.21.0` by the digest of its multi-platform index, read on 2026-11-20. The release is from 2026-11-12, younger than the two weeks the other pins of this repository wait; ADR 0021 names it, and the pin needs a person's review like any image change (`infra/**` is a sensitive path).

## Known limits

- **Memory.** With the policy's list, the server builds a search index of the VictoriaMetrics documentation for its `documentation` tool when it starts: about 20 seconds of three CPUs and about 705 MiB held for as long as it runs, measured on 2026-11-20. Under a 128 MiB or 512 MiB limit it never starts listening. The limit is therefore 1 GiB. With `documentation` added to the disabled tools it starts at once and holds about 18 MiB. The gateway never offers that tool, so adding it to `policies/troubleshooting.yaml` costs nothing; that is a policy change for a person, and then this file's list and limits follow.
- **Outbound network.** The server's network is the telemetry stack's ordinary bridge network, because a port cannot be published from an internal network. The container can therefore open connections to the internet. Nothing it does needs that, and nothing filters it.
- **Host header.** The server's guard against DNS rebinding applies to requests that reach it on its own loopback. A request through the published port with a foreign `Host` header is answered (checked: 200 with the token). The token is the control that matters.
- **The gateway is not built.** Nothing in the factory calls this server yet (`crates/mcp_gateway`, `apps/troubleshooter`).
