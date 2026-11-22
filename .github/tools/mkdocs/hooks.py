"""MkDocs hook: fit the documents of docs/ to the site without changing them on disk.

It changes two things in the copy that MkDocs renders (ADR 0033):

1. Links. The documents link to source files, schemas and scripts with relative paths, for example
   ``../../crates/workflow/src/lib.rs``. Those work on GitHub, but the site holds only docs/, so
   such a link becomes a link to the file on GitHub, at the published branch. A link to a folder in
   docs/ becomes a link to the folder's README.md. A link inside docs/ is left alone, so MkDocs
   still checks it, and a link to nothing is left alone too: the hook never hides a broken link.
2. Code fences. Shell blocks carry words for scripts/docs-check.sh, such as
   ``bash quickstart step=build``. Only the language is kept for rendering.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path
from typing import Any

# The published branch and repository. The Pages workflow publishes from this branch.
REPOSITORY_URL = "https://github.com/ortisun/bibo"
BRANCH = "develop"

# Folders under docs/ that mkdocs.yml leaves out of the site (exclude_docs). A link into them leaves
# the site just like a link to the source code does.
EXCLUDED_UNDER_DOCS = ("architecture/tools/", "reference/tools/")

# An inline Markdown link or image: ](target) or ](target "title"). Reference-style definitions are
# handled by DEFINITION below.
INLINE = re.compile(r"(\]\()(<[^>]+>|[^)\s]+)((?:\s+\"[^\"]*\")?\))")
DEFINITION = re.compile(r"^(\s{0,3}\[[^\]]+\]:\s+)(\S+)(.*)$", re.M)
FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})([^`\s]*)(.*)$")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _plain_fence(opening: re.Match[str], line: str) -> str:
    """Keep only the language of a fence opening.

    The documents mark their shell blocks for scripts/docs-check.sh, for example
    ``bash quickstart step=build expect="Finished"``. Those words are instructions for the check,
    not for the reader, and Python-Markdown does not take a fence whose info string carries them,
    so the block and the headings after it would render as one long code span.
    """
    if not opening.group(4).strip() or opening.group(4).lstrip().startswith("{"):
        return line
    ending = "\n" if line.endswith("\n") else ""
    return f"{opening.group(1)}{opening.group(2)}{opening.group(3)}{ending}"


def _site_target(target: str, page_src: str, repo_root: Path) -> str | None:
    """Return the new target of a relative link, or None to keep the link as it is.

    A link to a file outside the site becomes a link to that file on GitHub. A link to a folder in
    the site becomes a link to the folder's README.md, the page MkDocs makes its index; a folder
    with no such page becomes a link to the folder on GitHub. Everything else is kept.
    """
    bare = target[1:-1] if target.startswith("<") else target
    if not bare or bare.startswith(("#", "/")) or SCHEME.match(bare):
        return None
    path, _, fragment = bare.partition("#")
    if not path:
        return None
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(f"docs/{page_src}"), path))
    if resolved.startswith("../"):
        return None
    on_disk = repo_root / resolved
    if not on_disk.exists():
        return None  # Broken: MkDocs reports it and --strict fails the build.
    in_site = resolved.startswith("docs/") and not resolved[len("docs/"):].startswith(EXCLUDED_UNDER_DOCS)
    if in_site and on_disk.is_file():
        return None
    if in_site:
        for index in ("index.md", "README.md"):
            if (on_disk / index).is_file():
                return f"{path.rstrip('/')}/{index}" + (f"#{fragment}" if fragment else "")
    kind = "tree" if on_disk.is_dir() else "blob"
    return f"{REPOSITORY_URL}/{kind}/{BRANCH}/{resolved}" + (f"#{fragment}" if fragment else "")


def _rewrite(text: str, page_src: str, repo_root: Path) -> str:
    def inline(match: re.Match[str]) -> str:
        url = _site_target(match.group(2), page_src, repo_root)
        return match.group(0) if url is None else f"{match.group(1)}{url}{match.group(3)}"

    def definition(match: re.Match[str]) -> str:
        url = _site_target(match.group(2), page_src, repo_root)
        return match.group(0) if url is None else f"{match.group(1)}{url}{match.group(3)}"

    out: list[str] = []
    fence: str | None = None
    chunk: list[str] = []

    def flush() -> None:
        if chunk:
            prose = "".join(chunk)
            prose = INLINE.sub(inline, prose)
            prose = DEFINITION.sub(definition, prose)
            out.append(prose)
            chunk.clear()

    for line in text.splitlines(keepends=True):
        opening = FENCE.match(line)
        if fence is None and opening:
            flush()
            fence = opening.group(2)[0] * len(opening.group(2))
            out.append(_plain_fence(opening, line))
        elif fence is not None:
            out.append(line)
            if line.strip().startswith(fence) and line.strip().strip(fence[0]) == "":
                fence = None
        else:
            chunk.append(line)
    flush()
    return "".join(out)


def on_page_markdown(markdown: str, page: Any, config: Any, **_: Any) -> str:
    """MkDocs event: rewrite the links and fences of one page before it is rendered."""
    repo_root = Path(config["docs_dir"]).resolve().parent
    return _rewrite(markdown, page.file.src_uri, repo_root)
