# Local telemetry stack

A small stack for development: an OpenTelemetry Collector that receives data from the factory processes, VictoriaMetrics for metrics, and Jaeger for traces. It is for a developer's machine. It has no authentication, and its data is not protected.

The names of the spans, attributes and metrics are in [docs/observability/conventions.md](../../docs/observability/conventions.md).

## What is here

| File | Purpose |
|---|---|
| `collector.yaml` | The collector pipelines: data in the OpenTelemetry Protocol (OTLP) in, metrics to VictoriaMetrics, traces to Jaeger, a short count of what arrived in the collector log. |
| `compose.yaml` | Runs the collector, VictoriaMetrics and Jaeger with pinned image versions. |
| `validate.sh` | Checks `collector.yaml` with the exact collector image that `compose.yaml` pins, and `collector.yaml` merged with `collector.datadog.yaml` with the digest-pinned image of the overlay. |
| `compose.datadog.yaml` | Optional overlay: the same collector release pinned by digest, hardened, with the Datadog additions below. |
| `collector.datadog.yaml` | Optional additions to `collector.yaml`: the `datadog` exporter on the traces and metrics pipelines, and a logs pipeline from the containers' json-file logs. |

## Start it

You need Docker with the Compose plugin.

1. Start the stack and wait until it is healthy:

   ```
   docker compose -f infra/otel/compose.yaml up -d --wait
   ```

2. Run any factory process with the collector address set. For example, the sample program in the observability crate sends one fake job:

   ```
   OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 cargo run -p factory-observability --example emit_sample
   ```

   The address is a base URL. The process adds `/v1/traces` and `/v1/metrics` itself.

3. Look at the result:
   - Traces: open `http://127.0.0.1:16686`, choose the service `factory-sample` and open the trace. It has six spans, one for each part of a job.
   - Metrics: open `http://127.0.0.1:8428/vmui` and run a query such as `sum(factory_spend_usd_total) by (provider)` or `factory_queue_depth`.
   - The collector log (`docker compose -f infra/otel/compose.yaml logs collector`) shows a line for each batch it received, with the span and data point counts.

4. Stop it and delete its data:

   ```
   docker compose -f infra/otel/compose.yaml down -v
   ```

## Also send to Datadog (optional)

The troubleshooter ([guide](../../docs/guides/troubleshooter.md), [ADR 0021](../../docs/adr/0021-troubleshooter-agent-and-mcp-sources.md) decision 8) can only read logs and traces that some backend holds. The overlay `compose.datadog.yaml` sends traces and metrics to Datadog as well as to Jaeger and VictoriaMetrics, and adds the factory's logs, which otherwise go nowhere. The default stack above is unchanged and needs no account.

1. Put the Datadog API key in a file, mode `0600`. Only the API key: the collector needs no application key.

   ```bash
   umask 077
   $EDITOR ~/.config/factory/datadog-api-key     # one line, the key only
   ```

2. Start the stack with both files. `FACTORY_DD_SITE` is required and has no default, so data never goes to a region nobody chose:

   ```bash
   FACTORY_DD_SITE=datadoghq.eu \
   FACTORY_DD_API_KEY_FILE=$HOME/.config/factory/datadog-api-key \
   docker compose -f infra/otel/compose.yaml -f infra/otel/compose.datadog.yaml up -d --wait
   ```

   Optional: `FACTORY_DD_HOSTNAME` (default `factory-local`) and `FACTORY_DOCKER_CONTAINERS_DIR` (default `/var/lib/docker/containers`, right for Docker Engine on Linux and for Docker Desktop).

What the overlay does:

- **Same release, pinned by digest.** `otel/opentelemetry-collector-contrib:0.162.0@sha256:39923a8e…` (the multi-platform index, read on 2026-11-20). `validate.sh` fails when the overlay's release differs from the tag in `compose.yaml`.
- **The key is a Docker secret.** The collector reads `/run/secrets/dd_api_key` through its `file` configuration provider when it starts. The exporter has `fail_on_invalid_key: true`, so a refused key stops the collector at start instead of losing data quietly.
- **Logs.** A `file_log` receiver reads every container's json-file log under `/var/lib/docker/containers`, read-only, unwraps Docker's object and keeps a line only when it is a JSON object whose `target` starts with `factory_`. PostgreSQL's lines, the telemetry stack's own and any other text are dropped in the collector. Agent sandboxes and their sidecars run with `--log-driver none`, so their output is never in these files. A line is filed under the service `factory-<compose service>` when the factory service's logging names the label `com.docker.compose.service` (`logging.options.labels`), and under `factory-process` otherwise. The receiver starts at the end of each file and keeps no position, so a restart skips the lines written while the collector was down.
- **Hardening.** Read-only root file system, every capability dropped, `no-new-privileges`, limits on memory and processes. The collector runs as root, because Docker writes the log files as root with mode `0640`; with no capability it can read what root owns and nothing else. Checked on 2026-11-20: as root with no capability the files are readable, as the image's user 10001 they are not.

How it was checked, on 2026-11-20 with Docker 29.9.3 (Docker Desktop):

- `validate.sh` accepted the merged configuration with the pinned image, with no network and a placeholder key, and rejected a copy with a misspelled key of the logs receiver.
- The pinned collector ran the logs pipeline over a fixture of Docker log lines, with the Datadog exporter replaced by the debug exporter: the two factory lines came out with their time, severity and service name, and the four others (a line of another `target`, plain text, a line that is not Docker's JSON, and a PostgreSQL line) did not.
- **Not checked:** sending to a real Datadog account. Nothing in this repository has a Datadog key, so no trace, metric or log has reached Datadog, and how Datadog shows the factory's metric names and log bodies is unverified.

## Ports

Every port is published on the loopback address only, so only programs on the same machine can reach it. If another stack already uses a port, set the matching variable before `up`.

| Port | Variable | Use |
|---|---|---|
| 4318 | `FACTORY_OTLP_HTTP_PORT` | OTLP over HTTP. This is what the factory processes use. |
| 4317 | `FACTORY_OTLP_GRPC_PORT` | OTLP over gRPC. |
| 8428 | `FACTORY_VM_PORT` | VictoriaMetrics query API and web UI. |
| 16686 | `FACTORY_JAEGER_PORT` | Jaeger web UI. |

If you change the OTLP HTTP port, put the new port in `OTEL_EXPORTER_OTLP_ENDPOINT`.

## Versions

| Component | Version | Why this one |
|---|---|---|
| OpenTelemetry Collector, contrib build | 0.162.0 | Released on 2026-09-29, four weeks before it was chosen. The contrib build is used because the health check extension is part of it. The newest release at the time was one day old. |
| VictoriaMetrics single node | v1.153.0 | Released on 2026-09-28. |
| Jaeger | 2.21.0 | Released on 2026-09-14. Jaeger 2 accepts OTLP directly. |

The Datadog overlay pins the same collector release by digest. The VictoriaMetrics MCP server that the troubleshooter reads this VictoriaMetrics through is in [`infra/troubleshooter`](../troubleshooter/README.md).

Change a version only together with a run of `validate.sh` and the check below.

## How it was checked

On 2026-10-27, on a developer machine with Docker 29.9.2:

- `validate.sh` accepted `collector.yaml` with the pinned collector image, and rejected a copy with a misspelled key. So the check can fail.
- The stack started and every container reported healthy.
- The sample program sent one job. The collector log showed one batch of 6 spans and one of 12 metric data points.
- Jaeger returned the trace: six spans in the right tree, with the required attributes of each span and no others.
- VictoriaMetrics returned all six factory metrics under their exact names. The histogram appeared as `_bucket`, `_count` and `_sum` series with the documented upper bounds as the `le` label. The only labels from the factory were `stage`, `outcome`, `gate`, `provider` and `queue`, as listed for each metric. No job identifier was present.

This was one run on one machine. It has not been repeated in continuous integration.

## Things to know

- VictoriaMetrics starts with `-opentelemetry.usePrometheusNaming`. It turns the resource attributes into labels with underscores, such as `service_name` and `deployment_environment_name`. Without the flag the labels keep their dots, such as `service.name`, which must be quoted in a query. The factory's metric names are the same either way.
- The collector config has no extra scrubbing step. The factory process removes secrets and unlisted attributes before it sends anything. Anything else that sends to this collector, such as a tool run by hand, is not covered.
- The factory process can send only to a plain `http://` address, because its build has no TLS support. Use this stack, or a collector on the same host, and let the collector handle TLS toward any remote backend.
- The default stack does not export logs. Logs go to the standard error of each process. Only the Datadog overlay above reads them, from Docker's log files.
