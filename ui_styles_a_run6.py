"""Label styles of art run 6, agent A (pn_trade.arc, gdt_pn.arc, pnbg_sum.arc, pnbg_fal.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering; every style is crisp (solid rings, fill ramps only)."""
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat

STYLES = {}

# ---- g3_ptf_0 (plain black / red lettering on a light plate, no ring) -------------------------------------------------
STYLES["a6_ptf_black"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)       # pal 121: index 1 = black
STYLES["a6_ptf_red"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)         # pal 122: index 1 = red

# ---- g3_ptk_0 (cyan-white letters, azure and blue rings, dark blue shadow) --------------------------------------------
STYLES["a6_ptk_item"] = ringfill([15, 14, 13, 12, 11, 10], [7, 3], [1, 1])      # pal 101
STYLES["a6_ptk_any"] = ringfill([15, 14, 13, 12, 11, 10], [5, 3], [1, 1])       # pal 100: pink-white, purple rings
STYLES["a6_ptk_help"] = ringfill([12, 12, 11, 11, 10, 10], [1, 4], [6])        # pal 131: purple letters, white ring
STYLES["a6_ptk_big"] = ringfill([9, 9, 8, 8, 7, 7], [10, 12, 14], [2, 2])      # pal 102: the 3-line notice
