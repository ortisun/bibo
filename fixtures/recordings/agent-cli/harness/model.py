"""The case model of the agent runtime spike harness (work package s0-agent-runtime-spike)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Case:
    """One recorded run of a command line tool (or of a probe command) in the hardened container."""

    id: str
    title: str
    questions: list[int]
    tool: str  # claude or codex: selects the image
    args: list[str]  # arguments after the entrypoint
    env: dict[str, str] = field(default_factory=dict)  # non-secret environment of the container
    key_env: str | None = None  # name of the environment variable that carries the fake key, if any
    net: str = "internal"  # internal: the spike network with the fake provider; none: --network none
    ws: str = "clean"  # clean, hostile, speckit or hostile-speckit
    mounts: list[str] = field(default_factory=list)  # extra --mount values; {ws} and {run} are replaced
    home: str = "tmpfs"  # tmpfs: writable tmpfs home; readonly: the empty read-only home of the image
    stdin: str | None = None
    kill_after: tuple[float, str] | None = None  # (seconds, signal) sent with docker kill
    timeout_s: int = 90
    wrap: bool = True  # run through wrap.sh, which writes a footprint file
    root_ro: bool = True
    entrypoint: list[str] | None = None  # replaces the tool entrypoint; args follow
    secret_file: bool = True  # mount the fake key at /run/secrets/job_token
    setup: Callable[[Path], None] | None = None  # extra changes to the scratch workspace
    keep_out: list[str] = field(default_factory=list)  # file names under /out to keep in the recording
    image: str | None = None  # replaces the image of the tool (for the minimal-runtime check)
