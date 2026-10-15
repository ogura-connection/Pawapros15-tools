"""Label styles of art run 4, agent C (school.arc, sct_a_ar.arc, sct_a_nh.arc, sct_a_td.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering of each palette; every style is crisp (solid rings, no half tones except fill ramps)."""
from ui_styles_ore_ini import ringfill
import ui_type

STYLES = {}

# ---- school.arc g3_ms (Baseball School menu) -------------------------------------------------------------------------------
STYLES["c4_ms_00"] = ringfill([14, 12, 12, 13, 13, 13], [2, 2, 15], [9, 7, 5])      # pal 0: gold, dark ring, white ring, blue glow
STYLES["c4_ms_02"] = ringfill([12, 12, 11, 10, 9, 9], [5, 5, 13, 14], [2, 3])        # pal 38: peach to orange, maroon ring, white
STYLES["c4_ms_05"] = ringfill([12, 12, 11, 10, 9, 9], [5, 5, 13, 14], [2, 3])        # pal 39: mint to green
STYLES["c4_ms_06"] = ringfill([11, 11, 10, 9, 9, 8], [5, 5, 12, 14], [3, 4])         # pal 40: yellow to green
STYLES["c4_ms_07"] = ringfill([12, 11, 10, 10, 9, 8], [6, 6, 13, 14], [3, 4])        # pal 41: pink to lilac
STYLES["c4_ms_08"] = ringfill([15, 13, 12, 11, 10, 9], [5, 5, 1, 3], [4, 8])         # pal 42: sky blue, navy ring, white
STYLES["c4_ms_10"] = ringfill([10, 11, 12, 13, 14, 15], [1, 1, 9, 8], [7, 6])        # pal 32: peach to orange
STYLES["c4_ms_13"] = ringfill([10, 11, 12, 13, 14, 15], [1, 1, 8, 7], [6, 5])        # pal 33: mint to green
STYLES["c4_ms_15"] = ringfill([13, 13, 12, 11, 10, 5], [1, 1, 14, 9], [8, 7])        # pal 34: yellow to lime
STYLES["c4_ms_16"] = ringfill([13, 12, 11, 10, 9, 9], [1, 1, 15, 8], [7, 6])         # pal 35: pink to lilac
STYLES["c4_ms_17"] = ringfill([15, 9, 8, 7, 6, 5], [1, 1, 12, 13], [11, 10])         # pal 36: sky blue

# ---- school.arc g3_rsz (Baseball School tabs: gold letters in a blue oval, 8-bit page) ---------------------------------------
STYLES["c4_rsz"] = ringfill([142, 144, 148, 152, 157, 162, 166], [75, 70, 70, 197], [32, 32])
