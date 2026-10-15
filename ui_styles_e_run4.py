"""Label styles of art run 4, agent E (school_g.arc, sct_card.arc, sct_comd.arc, sct_a_ed.arc, sct_a_od.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering of each palette; every style is crisp (solid rings, no half tones except fill ramps)."""
from ui_styles_ore_ini import ringfill

STYLES = {}

# ---- sct_a_od.arc (Eikan Nine order screen) -----------------------------------------------------------------------------
STYLES["e4_od_title"] = ringfill([15, 15, 15, 15, 13, 12], [4, 4, 3, 2])             # pal 40: white, navy rings, blue glow
STYLES["e4_od_cancel"] = ringfill([12, 12, 11, 11, 8, 3], [15, 15, 5], [7, 9])         # pal 35: lavender, white ring, blue glow
STYLES["e4_od_blue"] = ringfill([15, 15, 15, 15, 14, 13], [1, 1])                      # pal 20: white, blue ring
