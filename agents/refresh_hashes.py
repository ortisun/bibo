#!/usr/bin/env python3
"""Keep the agent manifests and prompts equal to the files they point at.

Every manifest under agents/ names a prompt file and two schema files by content hash. Every
prompt also shows, in its "Output contract" section, the schemas the factory checks the answer
against, so that the model sees the same text the validator reads. After you edit a prompt or a
schema, run this script from the repository root and commit the files it changed:

    python3 -I agents/refresh_hashes.py            # rewrite what is out of date
    python3 -I agents/refresh_hashes.py --check    # change nothing, exit 1 if anything is stale

The schemas shown in a prompt are rewritten first, because that changes the prompt and so its hash.

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


# The factory schemas an answer is checked against besides the agent's own output schema. The
# planner's envelope holds a plan that the engine validates against task-dag.
EXTRA_ANSWER_SCHEMAS = {"planner": [ROOT / "schemas" / "task-dag.schema.json"]}

SECTION = "## Output contract\n"
OPEN, CLOSE = "```json", "```"


def answer_schemas(manifest: dict, agent_dir: str) -> list[Path]:
    """The schema files the prompt must show, in the order it shows them."""
    ref = manifest["outputs_schema"]
    own = AGENTS / "schemas" / "{}.v{}.schema.json".format(ref["name"], ref["version"])
    return [own] + EXTRA_ANSWER_SCHEMAS.get(agent_dir, [])


def with_schemas(prompt: str, schemas: list[Path]) -> str | None:
    """The prompt with each schema of its output contract replaced by its file, or None when the
    section does not hold exactly one fenced block for each schema."""
    if prompt.count(SECTION) != 1:
        return None
    head, rest = prompt.split(SECTION, 1)
    end = rest.find("\n## ")
    body, tail = (rest, "") if end < 0 else (rest[: end + 1], rest[end + 1 :])
    out, shown, inside = [], 0, False
    for line in body.split("\n"):
        if not inside and line == OPEN:
            if shown >= len(schemas):
                return None
            out.append(line)
            out.extend(schemas[shown].read_text(encoding="utf-8").rstrip("\n").split("\n"))
            shown += 1
            inside = True
        elif inside and line == CLOSE:
            out.append(line)
            inside = False
        elif not inside:
            out.append(line)
    if inside or shown != len(schemas):
        return None
    return head + SECTION + "\n".join(out) + tail


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = 0
    for path in sorted(AGENTS.glob("*/manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        changed = False
        prompt_path = ROOT / manifest["prompt"]["template_path"]
        if prompt_path.is_file():
            prompt = prompt_path.read_text(encoding="utf-8")
            wanted = with_schemas(prompt, answer_schemas(manifest, path.parent.name))
            if wanted is None:
                print("{}: the output contract does not show one schema block for each schema of the answer".format(prompt_path.relative_to(ROOT)))
                stale += 1
            elif wanted != prompt:
                print("{}: a schema shown in the output contract is stale".format(prompt_path.relative_to(ROOT)))
                stale += 1
                if not check:
                    prompt_path.write_text(wanted, encoding="utf-8")
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
