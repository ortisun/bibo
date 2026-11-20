"""Small readers for the upstream files that check-pins.sh compares with pins.env.

    pincheck.py rust-hash  CHANNEL_MANIFEST.toml COMPONENT TRIPLE   SHA-256 of the .tar.gz archive
    pincheck.py claude-hash MANIFEST.json PLATFORM                  SHA-256 of the claude binary
    pincheck.py github-digest RELEASE.json ASSET_NAME               SHA-256 GitHub lists for an asset

Each prints the hash, or nothing and exit code 1 if the file does not list it. Standard library
only (tomllib needs Python 3.11 or newer).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def rust_hash(path: Path, component: str, triple: str) -> Optional[str]:
    import tomllib

    with path.open("rb") as handle:
        manifest: Dict[str, Any] = tomllib.load(handle)
    target = manifest["pkg"][component]["target"][triple]
    value = target.get("hash")
    return value if isinstance(value, str) else None


def claude_hash(path: Path, platform: str) -> Optional[str]:
    data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    value = data["platforms"][platform]["checksum"]
    return value if isinstance(value, str) else None


def github_digest(path: Path, name: str) -> Optional[str]:
    data: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    for asset in data.get("assets", []):
        if asset.get("name") == name:
            digest = asset.get("digest")
            if isinstance(digest, str) and digest.startswith("sha256:"):
                return digest[len("sha256:") :]
    return None


def main(argv: List[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    command = argv[0]
    result: Optional[str] = None
    try:
        if command == "rust-hash" and len(argv) == 4:
            result = rust_hash(Path(argv[1]), argv[2], argv[3])
        elif command == "claude-hash" and len(argv) == 3:
            result = claude_hash(Path(argv[1]), argv[2])
        elif command == "github-digest" and len(argv) == 3:
            result = github_digest(Path(argv[1]), argv[2])
        else:
            print(__doc__)
            return 2
    except (KeyError, ValueError) as error:
        print(f"pincheck: {error}", file=sys.stderr)
        return 1
    if result is None:
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
