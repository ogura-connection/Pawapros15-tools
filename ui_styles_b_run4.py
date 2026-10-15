"""Label styles of art run 4, agent B (sct_titl.arc, sct_g_cd.arc, sct_a_pr.arc, sct_a_sy.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering of each palette; every style is crisp (solid rings, fill ramps only)."""
from ui_styles_ore_ini import ringfill
import ui_type

ui_type.TTF["b4uni"] = ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0)       # has the star of the messenger lines

STYLES = {}

# ---- sct_g_cd.arc z4_gmc_0: white letters, near-black ring, teal / olive / blue glow (palettes 93, 84, 90, 28, 44, 24, 21) ---------
STYLES["b4_gm"] = ringfill([15, 15, 15, 14, 13, 12], [4, 4], [3, 2])
# orange / yellow tab words (palettes 98 / 99; the dark twin copy in 100 / 101 is the same art)
STYLES["b4_or"] = ringfill([15, 15, 15, 14, 14, 13], [8, 6])
# ---- sct_g_cd.arc z4_gmd_0 -------------------------------------------------------------------------------------------------
STYLES["b4_gd_blue"] = ringfill([5, 4, 3, 3, 2, 2], [8, 8], [10])                        # pal 18: blue letters, white ring
STYLES["b4_gd_black"] = ringfill([1], [1, 1, 1], [1, 1])                                   # pal 13: the black twin of the blue line
STYLES["b4_gd_green"] = ringfill([15, 14, 14, 13, 12, 12], [4, 4], [3, 2])                 # pal 20: lime letters, black ring
