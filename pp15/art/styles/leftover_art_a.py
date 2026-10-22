"""Styles for the leftover art of group A (2026-10-22): the Success-mode celebration letters of scc_dem1.arc (bank
r4_dmo: 甲子園出場決定 / 全国制覇 / おめでとう！, one glyph per sprite, placed one by one by the game code).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow. Colours are palette indices read from the Japanese lettering of the same sprite.

Used by: specs/scc_dem1.json (group "lo_a celebration").
"""
from .common import ringfill

STYLES = {}

# ---- scc_dem1.arc r4_dmo (4-bit pages, palette 0): white letters (15), a 2 px black outline (7) and a 3 px black drop
# shadow down and to the right (7), as the Japanese glyphs (style_reader.from_bank on 00 / 0b / 11).
STYLES["lo_a_dmo"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [7, 7, 7])
