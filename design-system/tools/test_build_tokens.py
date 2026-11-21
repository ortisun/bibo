#!/usr/bin/env python3
"""Tests of build_tokens.py. Run: python3 -I design-system/tools/test_build_tokens.py"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_tokens as bt  # noqa: E402


def color(value: str) -> dict[str, str]:
    return {"$type": "color", "$value": value}


class ContrastTests(unittest.TestCase):
    def test_black_on_white_is_21(self) -> None:
        self.assertAlmostEqual(bt.contrast_ratio("#000000", "#ffffff"), 21.0, places=9)

    def test_same_colour_is_1(self) -> None:
        self.assertAlmostEqual(bt.contrast_ratio("#3558e0", "#3558e0"), 1.0, places=9)

    def test_order_does_not_matter(self) -> None:
        self.assertEqual(bt.contrast_ratio("#161a22", "#f2f4f7"), bt.contrast_ratio("#f2f4f7", "#161a22"))

    def test_known_boundary_values(self) -> None:
        # #767676 on white is the darkest grey that passes 4.5; #777777 is the first that fails.
        self.assertGreaterEqual(bt.contrast_ratio("#767676", "#ffffff"), 4.5)
        self.assertLess(bt.contrast_ratio("#777777", "#ffffff"), 4.5)

    def test_low_channel_uses_the_linear_segment(self) -> None:
        # 10/255 = 0.0392 is below the 0.04045 knee, so luminance is 0.7152 * 0.0392 / 12.92 for green only.
        self.assertAlmostEqual(bt.relative_luminance("#000a00"), 0.7152 * (10 / 255) / 12.92, places=12)

    def test_rgba_is_refused(self) -> None:
        with self.assertRaises(bt.TokenError):
            bt.relative_luminance("rgba(0, 0, 0, 0.5)")


class ResolveTests(unittest.TestCase):
    def table(self, tree: dict[str, object]) -> dict[str, bt.Token]:
        return bt.build_table(bt.flatten(json.loads(json.dumps(tree))))

    def test_reference_chain_resolves(self) -> None:
        table = self.table({"a": color("#111111"), "b": color("{a}"), "c": color("{b}")})
        self.assertEqual(bt.resolve("c", table), "#111111")

    def test_cycle_is_an_error(self) -> None:
        table = self.table({"a": color("{b}"), "b": color("{a}")})
        with self.assertRaisesRegex(bt.TokenError, "cycle"):
            bt.resolve("a", table)

    def test_missing_reference_is_an_error(self) -> None:
        table = self.table({"a": color("{nowhere}")})
        with self.assertRaisesRegex(bt.TokenError, "unknown reference"):
            bt.resolve("a", table)

    def test_group_type_is_inherited(self) -> None:
        tokens = bt.flatten({"space": {"$type": "dimension", "4": {"$value": "16px"}}})
        self.assertEqual(tokens, [bt.Token("space.4", "dimension", "16px")])

    def test_token_without_type_is_an_error(self) -> None:
        with self.assertRaises(bt.TokenError):
            bt.flatten({"a": {"$value": "1px"}})

    def test_duplicate_is_an_error(self) -> None:
        tokens = [bt.Token("a", "color", "#000000")]
        with self.assertRaisesRegex(bt.TokenError, "twice"):
            bt.build_table(tokens, tokens)


class CssTests(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(bt.css_name("color.state.human.bg"), "--ds-color-state-human-bg")

    def test_font_family_quotes_named_faces_only(self) -> None:
        self.assertEqual(bt.css_value("fontFamily", ["Inter", "system-ui", "sans-serif"], "f"), '"Inter", system-ui, sans-serif')

    def test_cubic_bezier(self) -> None:
        self.assertEqual(bt.css_value("cubicBezier", [0.2, 0, 0, 1], "e"), "cubic-bezier(0.2, 0, 0, 1)")

    def test_wrong_value_for_type(self) -> None:
        with self.assertRaises(bt.TokenError):
            bt.css_value("dimension", 16, "d")


class RepositoryTokensTests(unittest.TestCase):
    """The committed tokens: both themes have the same names, every pair passes, the CSS is current."""

    def setUp(self) -> None:
        self.light, self.dark, self.scale, self.pairs = bt.load(bt.TOKENS_DIR)

    def test_themes_have_the_same_tokens(self) -> None:
        self.assertEqual(bt.parity_errors(self.light, self.dark), [])

    def test_every_pair_passes(self) -> None:
        failed = [r for r in bt.check_pairs((self.light, self.dark), self.pairs) if not r.passed]
        self.assertEqual(failed, [])

    def test_generated_css_is_current(self) -> None:
        self.assertEqual(bt.OUTPUT.read_text(encoding="utf-8"), bt.render(self.light, self.dark, self.scale))

    def test_dark_blocks_redefine_every_colour(self) -> None:
        css = bt.render(self.light, self.dark, self.scale)
        media, explicit = css.split("@media (prefers-color-scheme: dark)")[1], css.split(':root[data-theme="dark"]')[1]
        for token in self.light.tokens:
            self.assertIn(bt.css_name(token.path) + ":", media)
            self.assertIn(bt.css_name(token.path) + ":", explicit)

    def test_missing_dark_token_is_found(self) -> None:
        dark = bt.Theme("dark", self.dark.tokens[1:], self.dark.table)
        self.assertEqual(len(bt.parity_errors(self.light, dark)), 1)

    def test_failing_pair_is_found(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            for source in bt.TOKENS_DIR.glob("*.json"):
                (directory / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
            light = json.loads((directory / "semantic.light.tokens.json").read_text(encoding="utf-8"))
            light["color"]["fg-muted"]["$value"] = "{palette.ink.300}"
            (directory / "semantic.light.tokens.json").write_text(json.dumps(light), encoding="utf-8")
            light_theme, dark_theme, _, pairs = bt.load(directory)
            failed = {(r.theme, r.fg) for r in bt.check_pairs((light_theme, dark_theme), pairs) if not r.passed}
            self.assertIn(("light", "color.fg-muted"), failed)


if __name__ == "__main__":
    unittest.main()
