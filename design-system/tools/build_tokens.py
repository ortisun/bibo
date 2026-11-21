#!/usr/bin/env python3
"""Turn the design tokens into CSS custom properties and check their contrast.

The tokens live in design-system/tokens/ in the format of the W3C Design Tokens Community
Group: every token is an object with "$value" and "$type". A value may point at another
token with a reference such as "{palette.ink.900}".

Files:
  primitives.tokens.json       raw values; resolved, never written out
  semantic.light.tokens.json   colour tokens of the light theme (written on :root)
  semantic.dark.tokens.json    the same names with dark values
  scale.tokens.json            type, space, shape, motion and layers (written on :root)
  contrast-pairs.json          the pairs whose contrast ratio is checked in both themes

USAGE
  build_tokens.py              Write design-system/dist/tokens.css and print the contrast table.
  build_tokens.py --check      Write nothing. Fail if tokens.css is stale or a pair fails.
  build_tokens.py --help       Show this text.

EXIT CODES
  0  done, every pair meets its minimum
  1  a contrast pair failed, a theme lacks a token, or tokens.css is stale (--check)
  2  wrong usage
  3  a token file could not be read or is malformed
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Union

JsonValue = Union[str, int, float, bool, None, list["JsonValue"], dict[str, "JsonValue"]]

ROOT = Path(__file__).resolve().parent.parent
TOKENS_DIR = ROOT / "tokens"
OUTPUT = ROOT / "dist" / "tokens.css"
PREFIX = "--ds-"
REFERENCE = re.compile(r"^\{([A-Za-z0-9_.-]+)\}$")
HEX = re.compile(r"^#([0-9a-fA-F]{6})$")


class TokenError(Exception):
    """A token file is malformed: a bad reference, a cycle, an unknown type."""


@dataclass(frozen=True)
class Token:
    path: str
    type: str
    value: JsonValue


def load_json(path: Path) -> dict[str, JsonValue]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TokenError(f"{path.name}: cannot be read ({error})") from error
    if not isinstance(data, dict):
        raise TokenError(f"{path.name}: the top level must be an object")
    return data


def flatten(tree: dict[str, JsonValue], prefix: str = "", inherited_type: str | None = None) -> list[Token]:
    """Walk a token tree and return its tokens in file order. "$type" on a group is inherited."""
    group_type = tree.get("$type")
    if group_type is not None and not isinstance(group_type, str):
        raise TokenError(f"{prefix or '<root>'}: $type must be a string")
    current_type = group_type if isinstance(group_type, str) else inherited_type
    if "$value" in tree:
        if current_type is None:
            raise TokenError(f"{prefix}: a token needs a $type")
        return [Token(prefix, current_type, tree["$value"])]
    tokens: list[Token] = []
    for key, child in tree.items():
        if key.startswith("$"):
            continue
        if not isinstance(child, dict):
            raise TokenError(f"{prefix}.{key}: expected a token or a group")
        tokens.extend(flatten(child, f"{prefix}.{key}" if prefix else key, current_type))
    return tokens


def resolve(path: str, table: dict[str, Token], seen: tuple[str, ...] = ()) -> JsonValue:
    """Follow references until a literal value. A cycle or a missing target is an error."""
    if path in seen:
        raise TokenError("reference cycle: " + " -> ".join((*seen, path)))
    token = table.get(path)
    if token is None:
        raise TokenError(f"{seen[-1] if seen else path}: unknown reference {{{path}}}")
    value = token.value
    if isinstance(value, str):
        match = REFERENCE.match(value)
        if match:
            return resolve(match.group(1), table, (*seen, path))
    return value


def css_name(path: str) -> str:
    return PREFIX + path.replace(".", "-")


def css_value(token_type: str, value: JsonValue, path: str) -> str:
    if token_type in ("color", "dimension", "duration", "shadow") and isinstance(value, str):
        return value
    if token_type in ("fontWeight", "number") and isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if token_type == "fontFamily" and isinstance(value, list):
        names: list[str] = []
        generic = {"serif", "sans-serif", "monospace", "system-ui", "ui-monospace", "-apple-system"}
        for name in value:
            if not isinstance(name, str):
                raise TokenError(f"{path}: every font family must be a string")
            names.append(name if name in generic else f'"{name}"')
        return ", ".join(names)
    if token_type == "cubicBezier" and isinstance(value, list) and len(value) == 4:
        points: list[str] = []
        for point in value:
            if not isinstance(point, (int, float)) or isinstance(point, bool):
                raise TokenError(f"{path}: a cubic Bezier needs four numbers")
            points.append(str(point))
        return f"cubic-bezier({', '.join(points)})"
    raise TokenError(f"{path}: a value of type {token_type} cannot be {value!r}")


def relative_luminance(hex_colour: str) -> float:
    """WCAG 2.2 relative luminance of an opaque sRGB colour written #rrggbb."""
    match = HEX.match(hex_colour)
    if not match:
        raise TokenError(f"contrast needs an opaque #rrggbb colour, not {hex_colour}")
    digits = match.group(1)
    channels: list[float] = []
    for index in (0, 2, 4):
        srgb = int(digits[index : index + 2], 16) / 255
        channels.append(srgb / 12.92 if srgb <= 0.04045 else ((srgb + 0.055) / 1.055) ** 2.4)
    red, green, blue = channels
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(first: str, second: str) -> float:
    lighter, darker = sorted((relative_luminance(first), relative_luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


@dataclass(frozen=True)
class Theme:
    name: str
    tokens: list[Token]
    table: dict[str, Token]


def build_table(*groups: list[Token]) -> dict[str, Token]:
    table: dict[str, Token] = {}
    for group in groups:
        for token in group:
            if token.path in table:
                raise TokenError(f"{token.path}: defined twice")
            table[token.path] = token
    return table


def load(tokens_dir: Path) -> tuple[Theme, Theme, list[Token], dict[str, JsonValue]]:
    primitives = flatten(load_json(tokens_dir / "primitives.tokens.json"))
    light = flatten(load_json(tokens_dir / "semantic.light.tokens.json"))
    dark = flatten(load_json(tokens_dir / "semantic.dark.tokens.json"))
    scale = flatten(load_json(tokens_dir / "scale.tokens.json"))
    pairs = load_json(tokens_dir / "contrast-pairs.json")
    light_theme = Theme("light", light, build_table(primitives, light, scale))
    dark_theme = Theme("dark", dark, build_table(primitives, dark, scale))
    return light_theme, dark_theme, scale, pairs


def parity_errors(light: Theme, dark: Theme) -> list[str]:
    light_paths = [token.path for token in light.tokens]
    dark_paths = [token.path for token in dark.tokens]
    errors = [f"{path}: in the light theme, missing in the dark theme" for path in light_paths if path not in dark_paths]
    errors += [f"{path}: in the dark theme, missing in the light theme" for path in dark_paths if path not in light_paths]
    return errors


@dataclass(frozen=True)
class PairResult:
    theme: str
    fg: str
    bg: str
    ratio: float
    minimum: float

    @property
    def passed(self) -> bool:
        return self.ratio >= self.minimum


def check_pairs(themes: tuple[Theme, Theme], pairs: dict[str, JsonValue]) -> list[PairResult]:
    entries = pairs.get("pairs")
    if not isinstance(entries, list) or not entries:
        raise TokenError("contrast-pairs.json: 'pairs' must be a non-empty list")
    results: list[PairResult] = []
    for theme in themes:
        for entry in entries:
            if not isinstance(entry, dict):
                raise TokenError("contrast-pairs.json: every pair must be an object")
            fg, bg, minimum = entry.get("fg"), entry.get("bg"), entry.get("min")
            if not isinstance(fg, str) or not isinstance(bg, str):
                raise TokenError("contrast-pairs.json: fg and bg must be token paths")
            if not isinstance(minimum, (int, float)) or isinstance(minimum, bool) or minimum < 1:
                raise TokenError(f"contrast-pairs.json: {fg} on {bg} needs a min of at least 1")
            fg_value, bg_value = resolve(fg, theme.table), resolve(bg, theme.table)
            if not isinstance(fg_value, str) or not isinstance(bg_value, str):
                raise TokenError(f"{fg} on {bg}: both must be colours")
            results.append(PairResult(theme.name, fg, bg, contrast_ratio(fg_value, bg_value), float(minimum)))
    return results


def declarations(tokens: list[Token], table: dict[str, Token], indent: str) -> list[str]:
    lines: list[str] = []
    for token in tokens:
        value = resolve(token.path, table)
        lines.append(f"{indent}{css_name(token.path)}: {css_value(token.type, value, token.path)};")
    return lines


def render(light: Theme, dark: Theme, scale: list[Token]) -> str:
    durations = [token for token in scale if token.type == "duration"]
    out = [
        "/* Generated by design-system/tools/build_tokens.py from design-system/tokens/. Do not edit. */",
        "",
        ":root {",
        "  color-scheme: light;",
        *declarations(light.tokens, light.table, "  "),
        *declarations(scale, light.table, "  "),
        f"  --ds-focus-ring: var({PREFIX}size-focus-width) solid var({PREFIX}color-focus);",
        "}",
        "",
        "@media (prefers-color-scheme: dark) {",
        '  :root:not([data-theme="light"]) {',
        "    color-scheme: dark;",
        *declarations(dark.tokens, dark.table, "    "),
        "  }",
        "}",
        "",
        ':root[data-theme="dark"] {',
        "  color-scheme: dark;",
        *declarations(dark.tokens, dark.table, "  "),
        "}",
        "",
        "@media (prefers-reduced-motion: reduce) {",
        "  :root {",
        *[f"    {css_name(token.path)}: 0ms;" for token in durations],
        "  }",
        "}",
        "",
    ]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if argv in (["--help"], ["-h"]):
        print(__doc__)
        return 0
    if argv not in ([], ["--check"]):
        print("usage: build_tokens.py [--check | --help]", file=sys.stderr)
        return 2
    check_only = argv == ["--check"]
    try:
        light, dark, scale, pairs = load(TOKENS_DIR)
        css = render(light, dark, scale)
        results = check_pairs((light, dark), pairs)
    except TokenError as error:
        print(f"FAILED: {error}", file=sys.stderr)
        return 3
    failures = parity_errors(light, dark)
    for result in results:
        mark = "ok  " if result.passed else "FAIL"
        if not check_only or not result.passed:
            print(f"{mark} {result.theme:5} {result.ratio:6.2f} >= {result.minimum:<4} {result.fg} on {result.bg}")
        if not result.passed:
            failures.append(f"{result.theme}: {result.fg} on {result.bg} is {result.ratio:.2f}, needs {result.minimum}")
    if check_only:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
        if current != css:
            failures.append("design-system/dist/tokens.css is stale: run python3 -I design-system/tools/build_tokens.py")
    if failures:
        for failure in failures:
            print(f"FAILED: {failure}", file=sys.stderr)
        return 1
    if not check_only:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(css, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT.parent)}")
    passed = sum(1 for result in results if result.passed)
    print(f"{passed}/{len(results)} contrast pairs pass")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
