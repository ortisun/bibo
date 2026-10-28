#!/usr/bin/env python3
"""Keep the hashes in the agent manifests equal to the files they point at.

Every manifest under agents/ names a prompt file and two schema files by content hash. After you
edit a prompt or a schema, run this script from the repository root and commit the manifests it
changed:

    python3 -I agents/refresh_hashes.py            # rewrite the hashes that are out of date
    python3 -I agents/refresh_hashes.py --check    # change nothing, exit 1 if any hash is stale

The factory refuses to load a manifest whose prompt hash differs from its file, so a stale hash is
a reviewed change, not a surprise at run time. Only the standard library is used.
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENTS = ROOT / "agents"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def wanted_hashes(manifest: dict) -> list[tuple[str, dict, Path]]:
    """Each place a hash lives: a label, the object that holds it and the file it must match."""
    found = [("prompt.template_sha256", manifest["prompt"], ROOT / manifest["prompt"]["template_path"])]
    for field in ("inputs_schema", "outputs_schema"):
        ref = manifest[field]
        schema = AGENTS / "schemas" / "{}.v{}.schema.json".format(ref["name"], ref["version"])
        found.append((field + ".sha256", ref, schema))
    return found


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = 0
    for path in sorted(AGENTS.glob("*/manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        changed = False
        for label, holder, target in wanted_hashes(manifest):
            key = "template_sha256" if label.startswith("prompt") else "sha256"
            if not target.is_file():
                print("{}: {} does not exist".format(path.relative_to(ROOT), target.relative_to(ROOT)))
                stale += 1
                continue
            actual = digest(target)
            if holder[key] != actual:
                print("{}: {} is stale".format(path.relative_to(ROOT), label))
                holder[key] = actual
                changed = True
                stale += 1
        if changed and not check:
            path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if stale and check:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
