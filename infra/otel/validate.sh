#!/bin/sh
# Check the collector configuration with the exact collector images that the compose files pin.
#
#   infra/otel/validate.sh
#
# Two checks:
#   1. collector.yaml alone, with the image of compose.yaml (the default stack);
#   2. collector.yaml merged with collector.datadog.yaml, with the digest-pinned image of the
#      Datadog overlay compose.datadog.yaml. It runs with no network, a placeholder site and a
#      placeholder API key file made for the run, so nothing is sent to Datadog and no real key is
#      needed. The overlay must pin the same release as compose.yaml.
#
# Exit 0: the collector accepted every file. Exit 1: it rejected one, and its message is printed.
# Exit 2: BLOCKED. The check could not run because Docker is missing or not running. A blocked
# run proves nothing about the files.
set -eu

here=$(cd "$(dirname "$0")" && pwd)

image=$(sed -n 's|^ *image: \(otel/opentelemetry-collector-contrib:[^ @]*\)$|\1|p' "$here/compose.yaml")
if [ -z "$image" ]; then
    echo "error: no collector image found in $here/compose.yaml" >&2
    exit 1
fi
dd_image=$(sed -n 's|^ *image: \(otel/opentelemetry-collector-contrib:[^ @]*@sha256:[0-9a-f]\{64\}\)$|\1|p' "$here/compose.datadog.yaml")
if [ -z "$dd_image" ]; then
    echo "error: no collector image pinned by digest found in $here/compose.datadog.yaml" >&2
    exit 1
fi
if [ "${dd_image%@*}" != "$image" ]; then
    echo "error: compose.datadog.yaml pins ${dd_image%@*} but compose.yaml uses $image; change both together" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "BLOCKED: docker is not installed, so $image cannot be used to validate the files." >&2
    exit 2
fi
if ! docker info >/dev/null 2>&1; then
    echo "BLOCKED: the docker daemon is not running, so $image cannot be used to validate the files." >&2
    exit 2
fi

echo "validating $here/collector.yaml with $image"
docker run --rm \
    -v "$here/collector.yaml:/etc/otelcol/collector.yaml:ro" \
    "$image" validate --config=/etc/otelcol/collector.yaml
echo "collector.yaml is valid"

work=$(mktemp -d "${TMPDIR:-/tmp}/factory-otel-validate.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
# A placeholder, not a key. The exporter needs a non-empty value to build. It is readable by all,
# because the image's user (10001) must read it and it holds nothing secret; a real key file is
# mode 0600 (README.md).
printf 'placeholder-for-validation-only\n' >"$work/dd_api_key"
chmod 644 "$work/dd_api_key"

echo "validating $here/collector.yaml + $here/collector.datadog.yaml with $dd_image"
# fail_on_invalid_key is turned off for this run only: with it on, building the exporter asks
# Datadog whether the key is valid, and this run has neither a network nor a real key.
docker run --rm --network none \
    -e DD_SITE=datadoghq.com \
    -e DD_HOSTNAME=factory-validate \
    -v "$here/collector.yaml:/etc/otelcol/collector.yaml:ro" \
    -v "$here/collector.datadog.yaml:/etc/otelcol/collector.datadog.yaml:ro" \
    -v "$work/dd_api_key:/run/secrets/dd_api_key:ro" \
    "$dd_image" validate \
    --config=/etc/otelcol/collector.yaml \
    --config=/etc/otelcol/collector.datadog.yaml \
    --set=exporters::datadog::api::fail_on_invalid_key=false
echo "collector.yaml with collector.datadog.yaml is valid"
