#!/usr/bin/env bash
# Validate the factory JSON Schemas and their examples.
#
#   schemas/validate.sh
#
# Checks, in order:
#   1. Every *.schema.json declares JSON Schema draft 2020-12 and passes the metaschema.
#   2. Shared $defs that appear in more than one schema are identical everywhere.
#   3. Every schema has at least one valid and one invalid example.
#   4. Every valid example validates.
#   5. Every invalid example is rejected, and the validator output contains the text in
#      the example's .expect sidecar, so it fails for the intended reason and not by accident.
#
# Set CHECK_JSONSCHEMA to use an installed binary instead of uvx, for example in CI.
# Exit status is 0 only if every check passed.
set -uo pipefail
cd "$(dirname "$0")"

CJ_VERSION="0.39.0"
# check-jsonschema pins itself and not the library that words its errors. Check 5 compares that
# wording with the .expect sidecars, so the library is pinned here as well: an unpinned run took
# jsonschema 4.26.0 on 2026-11-03 and four sidecars no longer matched, with no change in a schema.
JSONSCHEMA_VERSION="4.25.1"
if [ -n "${CHECK_JSONSCHEMA:-}" ]; then
  cj() { "$CHECK_JSONSCHEMA" "$@"; }
else
  cj() { uvx --from "check-jsonschema==${CJ_VERSION}" --with "jsonschema==${JSONSCHEMA_VERSION}" check-jsonschema "$@"; }
fi

failures=0
checks=0
fail() { echo "FAIL  $*"; failures=$((failures + 1)); }
pass() { echo "ok    $*"; }

echo "== 1. Metaschema (draft 2020-12)"
for schema in *.schema.json; do
  checks=$((checks + 1))
  dialect=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("$schema",""))' "$schema")
  if [ "$dialect" != "https://json-schema.org/draft/2020-12/schema" ]; then
    fail "$schema declares dialect '$dialect'"
    continue
  fi
  if out=$(cj --check-metaschema "$schema" 2>&1); then pass "$schema"; else fail "$schema: $out"; fi
done

echo "== 2. Shared definitions are identical across schemas"
checks=$((checks + 1))
if out=$(python3 -I - <<'EOF'
import glob, json, sys
seen, bad = {}, []
for path in sorted(glob.glob("*.schema.json")):
    for name, definition in json.load(open(path)).get("$defs", {}).items():
        if name in seen and seen[name][1] != definition:
            bad.append(f"$defs/{name} differs between {seen[name][0]} and {path}")
        seen.setdefault(name, (path, definition))
print("\n".join(bad)); sys.exit(1 if bad else 0)
EOF
); then pass "shared \$defs"; else fail "$out"; fi

echo "== 3. Example coverage and sidecars"
for schema in *.schema.json; do
  name="${schema%.schema.json}"
  checks=$((checks + 1))
  nvalid=$(find "examples/$name/valid" -type f 2>/dev/null | wc -l | tr -d ' ')
  ninvalid=$(find "examples/$name/invalid" -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
  if [ "$nvalid" -lt 1 ] || [ "$ninvalid" -lt 1 ]; then fail "$name has $nvalid valid and $ninvalid invalid examples"; continue; fi
  missing=""
  for f in examples/$name/invalid/*.json; do [ -s "${f%.json}.expect" ] || missing="$missing $f"; done
  if [ -n "$missing" ]; then fail "$name: invalid examples without a non-empty .expect sidecar:$missing"; else pass "$name: $nvalid valid, $ninvalid invalid"; fi
done

echo "== 4. Valid examples validate"
for schema in *.schema.json; do
  name="${schema%.schema.json}"
  for f in examples/$name/valid/*; do
    checks=$((checks + 1))
    if out=$(cj --schemafile "$schema" "$f" 2>&1); then pass "$f"; else fail "$f: $out"; fi
  done
done

echo "== 5. Invalid examples are rejected for the stated reason"
for schema in *.schema.json; do
  name="${schema%.schema.json}"
  for f in examples/$name/invalid/*.json; do
    checks=$((checks + 1))
    expect=$(head -n 1 "${f%.json}.expect")
    if out=$(cj --schemafile "$schema" "$f" 2>&1); then
      fail "$f was accepted but must be rejected"
    elif printf '%s' "$out" | grep -qF -- "$expect"; then
      pass "$f"
    else
      fail "$f was rejected, but not for the stated reason. Expected to find: $expect"
    fi
  done
done

echo
if [ "$failures" -eq 0 ]; then
  echo "All $checks checks passed."
else
  echo "$failures of $checks checks failed."
  exit 1
fi
