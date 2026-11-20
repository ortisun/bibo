# factory-egress-sidecar

The per-job relay of `docs/security/sandbox-policy.md` section 5.2. It holds no credential. The logic is in `factory_egress::relay` (`crates/egress/src/relay/`); this program reads the command line, starts it and stays alive. This file is the contract the sandbox supervisor builds against; it answers the proposal in `infra/sandbox-images/egress-sidecar/README.md`.

## Command line

```text
factory-egress-sidecar --mode broker  --listen ADDR:PORT --upstream IP:PORT [--second-listen ADDR:PORT --second-upstream IP:PORT] [--max-bytes N] [--job ID]
factory-egress-sidecar --mode connect --listen ADDR:PORT --allow HOST:PORT ... [--max-bytes N] [--job ID]
```

| Flag | Meaning |
|---|---|
| `--mode broker` | The `agent` profile. Every connection is relayed to `--upstream`, an IP address and port (a name is refused: nothing is resolved). The sandbox reaches the broker through this and nothing else. |
| `--second-listen`, `--second-upstream` | Broker mode only, both or neither, and off unless given. The `troubleshooter` profile (ADR 0021 Decision 5): a second listener whose every connection is relayed to one more fixed IP address and port, the MCP gateway. Like the first relay it reads nothing, resolves nothing and has no host list; it shares the byte quota and the connection limit. Its port must be 1024 or higher and differ from `--listen`, and its upstream may not be either listener. |
| `--mode connect` | The `fetch_deps` profile. A `CONNECT` proxy: each `--allow` is one exact host and port. |
| `--listen` | Where to listen. The port must be 1024 or higher. |
| `--max-bytes` | Bytes the job may move through the relay, both directions together. Default 2 GiB (`egress.proxy_rules.max_bytes_per_job`). After that, connections are refused and a running transfer is cut at the cap. |
| `--max-connections`, `--connect-timeout-secs`, `--idle-timeout-secs` | Limits, with defaults of 64, 10 and 600. |
| `--deny-range CIDR` | Connect mode. Adds a refused range to the built-in list (the policy list plus this-network, multicast, reserved and NAT64). Nothing removes one. |
| `--job ID` | A label for the decision log. It never decides anything. |

A command line the program does not understand (an unknown or repeated flag, a missing or bad value, a flag of the other mode) ends it with **exit code 2** before it listens, and the message holds no value from the command line. A listener that cannot bind ends it with **exit code 1**. The configuration comes from the supervisor and never from the sandbox.

## What it does

- **Broker mode.** It reads nothing the sandbox sends, so there is nothing to trick: no host name, no Host header, no CONNECT target is used to choose where to connect. A sandbox that sends a proxy request or a request for another host gets the broker's own refusal (the broker serves four routes and refuses the rest).
- **Connect mode.** For each `CONNECT host:port`: the target is read in one spelling (lower case, no trailing dot) and refused if it holds userinfo, an IP address in any spelling, a character a host name cannot hold, a host that no sandbox may reach (`egress.never_allow_from_sandbox`), a host that is not on the list, or a port that is not on the list for that host. Only then is the name resolved, once. Every address in the answer must be outside the refused ranges, and the connection goes to the first address, the one that was checked. A refused request gets `403` (`502` when the name did not resolve or the connection failed, `405` for a method other than `CONNECT`).

## Output

Standard output, one JSON object per line, for the supervisor to read through the attached stream and redact (the profile uses `--log-driver none`):

```json
{"event":"ready","mode":"broker","listen":"0.0.0.0:8443","job":"job-1"}
{"event":"egress_decision","decision":"allow","reason":"broker","mode":"broker","host":"172.17.0.1","port":9443,"job":"job-1"}
{"event":"egress_decision","decision":"deny","reason":"not_allowlisted","mode":"connect","host":"evil.test:443","port":0,"job":"job-1"}
{"event":"egress_closed","mode":"broker","host":"172.17.0.1","port":9443,"bytes_up":812,"bytes_down":4096,"quota_exhausted":false,"job":"job-1"}
```

**The `ready` line is the ready signal**: it is written after the listener is bound and before the first connection is accepted. A host string from the sandbox is cut to 253 characters and JSON-escaped. Reasons are a closed set: `broker`, `allowed`, `malformed`, `userinfo`, `ip_literal`, `not_allowlisted`, `port_not_allowed`, `never_allowed`, `resolve_failed`, `resolved_to_denied_range`, `method_not_allowed`, `upstream_unreachable`, `too_many_connections`, `quota_exhausted`.

## Build

Build it for the platform of the image, in the pinned verify image (Debian 13, the same glibc as the base image), not on a Mac. Its dependency graph is `serde_json` and `thiserror` with what they pull in; it does not link the broker.

```sh
docker run --rm --user 0:0 -v "$PWD":/src:ro -v "$OUT":/out \
  -e CARGO_HOME=/out/cargo -e CARGO_TARGET_DIR=/out/target -w /src \
  factory-sandbox/verify:rust1.98.0 cargo build --release --locked -p factory-egress-sidecar
infra/sandbox-images/egress-sidecar/build.sh --binary "$OUT/target/release/factory-egress-sidecar" --sha256 "$(shasum -a 256 "$OUT/target/release/factory-egress-sidecar" | cut -d' ' -f1)"
```

## What the supervisor must know

- The sidecar listens on the interface it is told to. Started with `--listen 0.0.0.0:PORT` it also listens on the address it has on the default bridge (the supervisor connects it there so it can reach the broker). Only the broker is reachable through it and the broker wants a job token, but a better arrangement is to pass the sidecar's address on the job network. The sandbox crate does not know that address when it builds the command, so this stays a residual risk (see the report).
- `sidecar_command` in the sandbox crate's `ProviderConfig` is one list for every job. The broker address in it is therefore the same for every job; a broker with one listener per job (`BrokerServerConfig::expected_job`) needs the command to vary per job.
- The container runs with `--init`, so SIGTERM ends the program at once. It handles no signal itself.
- A name given to `--upstream` is refused. The supervisor passes the broker's address as an IP literal.
