"""Styles for the Pennant main screen (the "Travel Day" / today's-game screen) of pena_sub.arc: the side-menu buttons
(bank s3_phz00: Schedule, Manage, New Talent, Records, Coach Navi, System, Reorganize) and the rest of that screen
(bank s3_phm00: league and result tabs, the game-flow strip, button hints, win / tie counters, the Team Analysis title)
and the date plate (bank s3_phh00: weekdays, 月 -> "/", 年 and 日 cleared).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow. Colours are palette indices read from the Japanese lettering of the same sprite.

Used by: specs/pena_sub.json (groups "pmenu ...").
"""
from .common import ringfill, flat

STYLES = {}

# ---- s3_phz00: side-menu button words (8-bit pages). Gradient fill, dark outline, white ring, blue ring + blue drop.
_PHZ = {
    "00": ([245, 246, 247, 248, 250, 252], 109),      # 日程表 yellow -> orange
    "01": ([241, 243, 244, 214, 213, 211], 169),      # 采配 yellow-green -> green
    "02": ([233, 239, 228, 229, 230, 231], 110),      # 新戦力 pink
    "03": ([53, 54, 51, 59, 58, 56], 143),            # 記録室 teal
    "04": ([30, 32, 35, 50, 48, 45], 149),            # コーチナビ green
    "05": ([60, 61, 62, 63, 65, 67], 139),            # システム cyan -> blue
    "06": ([223, 239, 228, 229, 230, 231], 109),      # 再編成 pink
}
for _s, (_fill, _dark) in _PHZ.items():
    STYLES["pmenu_phz_" + _s] = ringfill(_fill, [_dark, 15, 15, 201], [199, 83])

# ---- s3_phm00 (4-bit pages; the colours come from pal_s3_phd00 by each part's palette number)
STYLES["pmenu_tab"] = ringfill([15, 15, 15, 15, 15, 15], [7, 5], [3])          # league / result / today tabs (pal 22-24)
STYLES["pmenu_hint"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7])              # small white words, black outline (pal 16, 25)
STYLES["pmenu_vs"] = ringfill([13, 12, 11, 10, 9, 8], [3, 3, 2])               # 対 (pal 4): yellow -> orange, blue ring
STYLES["pmenu_rain"] = ringfill([14, 13, 12, 11, 10, 10], [4, 4], [2])         # 雨天中止 (pal 80): white -> cyan, navy ring
STYLES["pmenu_flow"] = ringfill([13, 13, 13, 13, 13, 13], [4, 4, 4], [14])     # 通常試合 / 高速試合 / スキップ (pal 37-39)
STYLES["pmenu_wt_s"] = ringfill([9, 9, 9, 9, 9, 9], [3])                       # small 勝 / 分 (pal 40)
STYLES["pmenu_wt"] = ringfill([15, 15, 15, 15, 15, 15], [6, 6, 2])            # big 勝 / 分 (pal 48)
STYLES["pmenu_title"] = ringfill([1, 1, 2, 2, 3, 3], [8, 11, 11, 15, 15])      # 戦力分析 title (pal 163)

# ---- s3_phh00: date plate glyphs (pal 54 / 55 / 56: index 15 = the letter colour, 1..14 its soft edge toward the light plate)
STYLES["pmenu_date"] = flat([0, 3, 6, 9, 12, 14, 15])
