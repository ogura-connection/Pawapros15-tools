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

# ---- g3_pt_0 ------------------------------------------------------------------------------------------------------------
STYLES["a6_head_green"] = ringfill([8, 9, 10, 11, 13, 15], [5, 2], [])                 # pal 97: lime letters, blue ring (headings 08, 09)
STYLES["a6_pt_title"] = ringfill([15, 14, 11, 12, 12, 13], [5, 1], [8, 8])                  # pal 98: orange titles, white ring, blue ring
STYLES["a6_tab"] = ringfill([1, 1, 2, 2, 3, 3], [8, 9], [11, 13])                       # tabs and column headings: dark letters, white ring
STYLES["a6_btn_white"] = ringfill([1, 1, 1, 1, 1, 1], [4, 14], [7])                    # pal 57: white letters
STYLES["a6_btn_navy"] = ringfill([2, 2, 2, 2, 2, 2], [1, 11], [7])                     # pal 55 / 39 family: navy letters, white ring
STYLES["a6_btn_purple"] = ringfill([6, 6, 6, 6, 6, 6], [1, 14], [7])                   # pal 42
STYLES["a6_btn_olive"] = ringfill([15, 14, 14, 13, 13, 12], [1, 2], [8, 4])            # pal 38
STYLES["a6_btn_green"] = ringfill([3, 3, 3, 8, 8, 8], [1, 14], [7])                    # pal 58: green letters
STYLES["a6_btn_crimson"] = ringfill([6, 6, 6, 6, 6, 6], [1, 14], [7])                  # pal 58: crimson letters
STYLES["a6_btn_brown"] = ringfill([5, 5, 5, 5, 5, 5], [1, 14], [7])                    # pal 39
STYLES["a6_pt_out"] = ringfill([1, 1, 1, 2, 2, 2], [11, 13], [15])                      # pal 99: "'s Outgoing Players"
STYLES["a6_banner"] = ringfill([12, 12, 13, 13, 14, 14], [3, 10, 8], [2, 1])              # pal 103: "No trade requests pending!"
STYLES["a6_empty"] = ringfill([8, 8, 7, 7, 6, 6], [3, 11, 13], [2, 1])                    # pal 104: "List / Empty"
STYLES["a6_noplayers"] = ringfill([4, 4, 5, 5, 6, 6], [1], [])                          # pal 110: "No Players"

# ---- g3_pts_0 -----------------------------------------------------------------------------------------------------------
STYLES["a6_pts_head"] = ringfill([1, 1, 1, 2, 2, 3], [9, 12], [])                       # pal 120: dark brown letters, tan edge
