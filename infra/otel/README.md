# Local telemetry stack

A small stack for development: an OpenTelemetry Collector that receives data from the factory processes, VictoriaMetrics for metrics, and Jaeger for traces. It is for a developer's machine. It has no authentication, and its data is not protected.

The names of the spans, attributes and metrics are in [docs/observability/conventions.md](../../docs/observability/conventions.md).

## What is here

| File | Purpose |
|---|---|
| `collector.yaml` | The collector pipelines: OTLP in, metrics to VictoriaMetrics, traces to Jaeger, a short count of what arrived in the collector log. |
| `compose.yaml` | Runs the collector, VictoriaMetrics and Jaeger with pinned image versions. |
| `validate.sh` | Checks `collector.yaml` with the exact collector image that `compose.yaml` pins. |

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
- The stack does not export logs. Logs go to the standard error of each process.
