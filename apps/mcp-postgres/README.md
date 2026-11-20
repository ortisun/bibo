# factory-mcp-postgres

The read-only PostgreSQL MCP server of the software factory ([ADR 0021](../../docs/adr/0021-troubleshooter-agent-and-mcp-sources.md), decision 4), as a program. It serves the library `crates/mcp_postgres` so that an engineer can point Claude Code at the factory's database with the same guarantees the troubleshooter gets.

## What it guarantees

- **Read-only by the database.** It logs in as a member of `factory_observer` (migration `2026-11-20-002900_observer_role`): `SELECT` on operational columns only (the list is [`docs/database/observer-columns.txt`](../../docs/database/observer-columns.txt)), never a request text, payload, token digest or person's identity. It refuses to start with a login that is a superuser, bypasses row-level security, or belongs to a group that can write.
- **Every call** runs in `BEGIN READ ONLY ... ROLLBACK` with a 5 s statement timeout and a 1 s lock timeout, then `DISCARD ALL`.
- **Free SQL** (`pg_query`) is wrapped as a subquery and sent with the extended protocol: one query, no writes, no DDL, no `COPY`, no second statement.
- **Caps:** 200 rows, 64 KiB per result (a `truncated` object says how much was cut), 300 calls per process.
- **Redaction** of every string with the factory's redactor, and literals scrubbed from the query texts of other sessions.

The tools: `pg_list_relations`, `pg_describe_relation`, `pg_query`, `pg_explain`, `pg_activity`, `pg_locks`, `pg_table_health`, `pg_factory_health`.

## Before the first run

1. The migrations, up to `2026-11-20-002900_observer_role`, are applied.
2. A login exists. Make it with [`docs/database/observer-login.sql`](../../docs/database/observer-login.sql), which reads the password from a file:

   ```bash
   umask 077
   openssl rand -hex 24 > ~/.config/factory/troubleshooter.password
   psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -v password_file="$HOME/.config/factory/troubleshooter.password" \
        -f docs/database/observer-login.sql
   ```

3. A settings file, for example `~/.config/factory/mcp-postgres.json`:

   ```json
   {
     "host": "127.0.0.1",
     "port": 5432,
     "user": "factory_troubleshooter",
     "database": "factory",
     "password_file": "/home/me/.config/factory/troubleshooter.password",
     "policy_checkout": "/home/me/src/factory"
   }
   ```

   `policy_checkout` is a checkout of the factory whose `policies/security.yaml` gives the redactor its secret patterns. Without it, only the password and the token are redacted, and the program says so on stderr. Unknown keys are refused. The same settings can come from the environment instead: `FACTORY_MCP_PG_USER` (required), `FACTORY_MCP_PG_HOST`, `FACTORY_MCP_PG_PORT`, `FACTORY_MCP_PG_DATABASE`, `FACTORY_MCP_PG_PASSWORD_FILE`, `FACTORY_MCP_PG_POLICY_CHECKOUT`, or `FACTORY_MCP_PG_CONFIG` naming the file.

Secret files must not be readable by group or others (`chmod 600`). The program never takes a password or a token in an argument or an environment variable.

## Point Claude Code at it (stdio)

Build it (`cargo build --release -p factory-mcp-postgres`) and add a project `.mcp.json`, or merge this into yours. It holds no secret: only the path of the settings file.

```json
{
  "mcpServers": {
    "factory-postgres": {
      "command": "/path/to/target/release/factory-mcp-postgres",
      "args": ["--config", "/home/me/.config/factory/mcp-postgres.json"]
    }
  }
}
```

Claude Code then lists the tools as `mcp__factory-postgres__pg_query` and so on. Diagnostics go to stderr; stdout carries the protocol only.

## Streamable HTTP

```bash
umask 077
openssl rand -hex 32 > ~/.config/factory/mcp-postgres.token
factory-mcp-postgres --config ~/.config/factory/mcp-postgres.json \
    --http 127.0.0.1:8808 --token-file ~/.config/factory/mcp-postgres.token
```

Every request to `http://127.0.0.1:8808/mcp` needs `Authorization: Bearer <token>`. The token has at least 32 characters. The program refuses to listen on an address that is not loopback unless `--allow-non-loopback` is also given; think twice before giving it, since the database's read access would then be reachable from the network.

For Claude Code over HTTP:

```json
{
  "mcpServers": {
    "factory-postgres": {
      "type": "http",
      "url": "http://127.0.0.1:8808/mcp",
      "headers": { "Authorization": "Bearer ${FACTORY_MCP_PG_TOKEN}" }
    }
  }
}
```

`${FACTORY_MCP_PG_TOKEN}` is expanded by Claude Code from your environment, so the token stays out of the file.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The session ended (stdin closed, or Ctrl-C in HTTP mode). |
| 1 | It could not serve: the database is unreachable, the login is not fit, or the socket could not be opened. |
| 2 | Bad usage or settings: an unknown argument, a missing or unsafe secret file, a non-loopback address without the flag. |

## Tests

`cargo nextest run -p factory-mcp-postgres` runs the unit tests of the settings and checks. The database tests are in `crates/mcp_postgres` and need `FACTORY_DB_ADMIN_URL` ([docs/database/running.md](../../docs/database/running.md)).
