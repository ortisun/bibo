//! The local telemetry stack in `infra/otel` keeps the properties that matter: pinned images,
//! loopback-only ports, the receiver ports the crate's default assumes, and the path
//! VictoriaMetrics reads OTLP metrics from.
//!
//! These are text checks. They do not start the collector. `infra/otel/validate.sh` does that, and
//! it needs Docker.

const COMPOSE: &str = include_str!("../../../infra/otel/compose.yaml");
const COLLECTOR: &str = include_str!("../../../infra/otel/collector.yaml");

fn lines_with<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with(key))
        .collect()
}

#[test]
fn every_image_has_an_exact_version() {
    let images = lines_with(COMPOSE, "image:");
    assert_eq!(
        images.len(),
        3,
        "expected the collector, VictoriaMetrics and Jaeger: {images:?}"
    );
    for line in images {
        let reference = line.trim_start_matches("image:").trim();
        let (_, tag) = reference
            .rsplit_once(':')
            .unwrap_or_else(|| panic!("{reference} has no tag"));
        assert!(
            tag != "latest" && tag.chars().any(|c| c.is_ascii_digit()),
            "{reference} is not pinned to a version"
        );
    }
}

#[test]
fn every_published_port_is_bound_to_the_loopback_address() {
    // The list items that follow each `ports:` key, up to the next line that is not a list item.
    let mut published: Vec<&str> = Vec::new();
    let mut in_ports = false;
    for line in COMPOSE.lines().map(str::trim) {
        if line == "ports:" {
            in_ports = true;
        } else if in_ports && line.starts_with("- ") {
            published.push(line);
        } else {
            in_ports = false;
        }
    }
    assert_eq!(
        published.len(),
        4,
        "expected four published ports: {published:?}"
    );
    for line in &published {
        assert!(
            line.starts_with("- \"127.0.0.1:"),
            "{line} is not bound to the loopback address"
        );
    }
}

#[test]
fn the_collector_listens_where_the_crate_default_expects() {
    assert!(
        COLLECTOR.contains("endpoint: 0.0.0.0:4318"),
        "OTLP over HTTP must be on 4318"
    );
    assert!(
        COLLECTOR.contains("endpoint: 0.0.0.0:4317"),
        "OTLP over gRPC must be on 4317"
    );
    // The compose file maps the same container ports.
    assert!(COMPOSE.contains(":4318\""));
    assert!(COMPOSE.contains(":4317\""));
}

#[test]
fn metrics_go_to_the_path_victoriametrics_reads_otlp_from() {
    assert!(
        COLLECTOR
            .contains("metrics_endpoint: http://victoriametrics:8428/opentelemetry/v1/metrics"),
        "VictoriaMetrics reads OTLP metrics at /opentelemetry/v1/metrics"
    );
}

#[test]
fn both_pipelines_limit_memory_before_they_batch() {
    for pipeline in ["traces", "metrics"] {
        let at = COLLECTOR
            .find(&format!("    {pipeline}:"))
            .unwrap_or_else(|| panic!("no {pipeline} pipeline"));
        let block: Vec<&str> = COLLECTOR[at..].lines().skip(1).take(4).collect();
        let processors = block
            .iter()
            .find(|line| line.contains("processors:"))
            .unwrap_or_else(|| panic!("no processors in {pipeline}: {block:?}"));
        assert!(
            processors.contains("[memory_limiter, batch]"),
            "{pipeline} must run memory_limiter before batch: {processors}"
        );
    }
}

#[test]
fn the_collector_version_in_the_header_matches_the_pinned_image() {
    let image = lines_with(COMPOSE, "image: otel/opentelemetry-collector-contrib:");
    let version = image[0].rsplit(':').next().expect("a tag");
    assert!(
        COLLECTOR.contains(&format!("version {version}")),
        "collector.yaml says it is written for a different collector version than compose.yaml pins ({version})"
    );
}
