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
STYLES["b4_gm_s"] = ringfill([15, 15, 15, 14, 13, 12], [4], [3])                           # the same on small plates: one ring, one shadow row

# ---- sct_a_pr.arc z4_edr_0 (Eikan Nine practice-order screen) -----------------------------------------------------------------------
STYLES["b4_pr_tab"] = ringfill([15, 15, 15, 14, 13, 12], [4, 4, 3, 2])                     # pal 40-43: white letters, dark ring, coloured glow
STYLES["b4_pr_head"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4], [3])                     # pal 49 / 56: column heads and "Active" on a teal plate
STYLES["b4_pr_pos"] = ringfill([15, 15, 14, 14, 13, 13], [3])                              # pal 52 / 53: position glyphs, black on a light cell
STYLES["b4_pr_col"] = ringfill([6, 4, 3, 2, 2, 4], [8, 8], [14])                           # pal 61-63: brown / blue / green letters, white ring (hands, years)
STYLES["b4_pr_msg"] = ringfill([3, 2, 1, 1, 1, 2], [8, 8, 8], [12, 13])                    # pal 64-68: dark letters, white band, pale glow (practice orders)
STYLES["b4_pr_head_s"] = ringfill([15, 15, 14, 13, 12, 11], [4])                           # the same with one ring: heads of 32 px cells (two arts fit one 24 row cell)
