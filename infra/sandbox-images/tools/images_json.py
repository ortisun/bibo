"""Read and write infra/sandbox-images/images.json, the file the sandbox adapter reads.

The build scripts call `record` after each image is built. The test scripts call `get` to find
the reference of the image they must test. Nothing else knows the layout of the file.

    images_json.py record --file F --platform P --role R --pins PINS --inspect INSPECT.json
                          [--field name=value ...]
    images_json.py get    --file F --platform P --role R --field NAME
    images_json.py platforms --file F

Standard library only. The output is deterministic: sorted keys, no timestamps, so rebuilding
identical images leaves the file unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "factory-sandbox-images/1"

# Which image each sandbox profile runs. fetch_deps only runs cargo downloads and runs no
# repository code, so it needs the toolchain and nothing else.
PROFILE_IMAGES = {
    "agent": "agent",
    "fetch_deps": "verify",
    "verify": "verify",
    "egress_sidecar": "egress-sidecar",
}

Json = Dict[str, Any]


def load(path: Path) -> Json:
    if not path.exists():
        return {"schema": SCHEMA, "profile_images": PROFILE_IMAGES, "platforms": {}}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise SystemExit(f"{path}: not a {SCHEMA} file")
    return data


def save(path: Path, data: Json) -> None:
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def split_user(user: str) -> Json:
    uid, _, gid = user.partition(":")
    if not uid.isdigit() or not gid.isdigit():
        raise SystemExit(f"image user '{user}' is not a numeric uid:gid")
    return {"uid": int(uid), "gid": int(gid)}


def env_map(env: Optional[List[str]]) -> Json:
    result: Json = {}
    for item in env or []:
        name, _, value = item.partition("=")
        result[name] = value
    return result


def set_dotted(target: Json, dotted: str, value: str) -> None:
    keys = dotted.split(".")
    node = target
    for key in keys[:-1]:
        child = node.setdefault(key, {})
        if not isinstance(child, dict):
            raise SystemExit(f"field {dotted}: {key} is not an object")
        node = child
    node[keys[-1]] = value


def command_record(args: argparse.Namespace) -> int:
    with Path(args.inspect).open("r", encoding="utf-8") as handle:
        inspected = json.load(handle)
    image = inspected[0]
    descriptor = image.get("Descriptor") or {}
    digest = descriptor.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise SystemExit(
            "this Docker daemon does not report a manifest digest for the local image. "
            "Use the containerd image store (the default in Docker 29 and Docker Desktop), "
            "or build with a registry."
        )
    config = image.get("Config") or {}
    name = args.name
    labels = config.get("Labels") or {}
    entry: Json = {
        "name": name,
        "tag": args.tag,
        "digest": digest,
        "reference": f"{name}@{digest}",
        "image_id": image.get("Id"),
        "os": image.get("Os"),
        "architecture": image.get("Architecture"),
        "size_bytes": image.get("Size"),
        "user": split_user(config.get("User") or ""),
        "workdir": config.get("WorkingDir"),
        "env": env_map(config.get("Env")),
        "entrypoint": config.get("Entrypoint"),
        "cmd": config.get("Cmd"),
        "labels": labels,
    }
    for item in args.field or []:
        key, sep, value = item.partition("=")
        if not sep:
            raise SystemExit(f"--field needs name=value, got '{item}'")
        set_dotted(entry, key, value)

    path = Path(args.file)
    data = load(path)
    platform = data["platforms"].setdefault(args.platform, {"pins_sha256": None, "images": {}})
    pins_hash = sha256_of(Path(args.pins))
    if platform.get("pins_sha256") not in (None, pins_hash):
        # Images built from an older pins.env are stale. Keep only what this build produces.
        platform["images"] = {}
    platform["pins_sha256"] = pins_hash
    platform["images"][args.role] = entry
    save(path, data)
    print(entry["reference"])
    return 0


def lookup(node: Any, dotted: str) -> Any:
    for key in dotted.split("."):
        if not isinstance(node, dict) or key not in node:
            raise SystemExit(f"no field '{dotted}'")
        node = node[key]
    return node


def command_get(args: argparse.Namespace) -> int:
    data = load(Path(args.file))
    platform = data["platforms"].get(args.platform)
    if platform is None:
        raise SystemExit(f"no platform {args.platform} in {args.file}")
    image = platform["images"].get(args.role)
    if image is None:
        raise SystemExit(f"no image '{args.role}' for {args.platform} in {args.file}")
    value = lookup(image, args.field)
    if isinstance(value, (dict, list)):
        print(json.dumps(value, sort_keys=True))
    elif value is None:
        print("")
    else:
        print(value)
    return 0


def command_platforms(args: argparse.Namespace) -> int:
    data = load(Path(args.file))
    for platform in sorted(data["platforms"]):
        print(platform)
    return 0


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    record = sub.add_parser("record")
    record.add_argument("--file", required=True)
    record.add_argument("--platform", required=True)
    record.add_argument("--role", required=True)
    record.add_argument("--name", required=True)
    record.add_argument("--tag", required=True)
    record.add_argument("--pins", required=True)
    record.add_argument("--inspect", required=True)
    record.add_argument("--field", action="append")
    record.set_defaults(handler=command_record)

    get = sub.add_parser("get")
    get.add_argument("--file", required=True)
    get.add_argument("--platform", required=True)
    get.add_argument("--role", required=True)
    get.add_argument("--field", required=True)
    get.set_defaults(handler=command_get)

    platforms = sub.add_parser("platforms")
    platforms.add_argument("--file", required=True)
    platforms.set_defaults(handler=command_platforms)

    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
