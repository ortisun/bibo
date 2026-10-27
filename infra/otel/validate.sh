#!/bin/sh
# Check collector.yaml with the exact collector image that compose.yaml pins.
#
#   infra/otel/validate.sh
#
# Exit 0: the collector accepted the file. Exit 1: it rejected it, and its message is printed.
# Exit 2: BLOCKED. The check could not run because Docker is missing or not running. A blocked
# run proves nothing about the file.
set -eu

here=$(cd "$(dirname "$0")" && pwd)

image=$(sed -n 's|^ *image: \(otel/opentelemetry-collector-contrib:[^ ]*\)$|\1|p' "$here/compose.yaml")
if [ -z "$image" ]; then
    echo "error: no collector image found in $here/compose.yaml" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "BLOCKED: docker is not installed, so $image cannot be used to validate the file." >&2
    exit 2
fi
if ! docker info >/dev/null 2>&1; then
    echo "BLOCKED: the docker daemon is not running, so $image cannot be used to validate the file." >&2
    exit 2
fi

echo "validating $here/collector.yaml with $image"
docker run --rm \
    -v "$here/collector.yaml:/etc/otelcol/collector.yaml:ro" \
    "$image" validate --config=/etc/otelcol/collector.yaml
echo "collector.yaml is valid"
