"""Label styles of the match intro (2026-10-20): the team / stadium name atlas dscn_str.arc (drawn by gameplay.arc
h3_tnm_0 / y5_knm_0 / y4r_skn_0 with colour table 4 of pal_y5_knm_0) and the starting-lineup panel (gameplay.arc
h3_dem_0). Loaded by ui_type.py."""
from ui_styles_ore_ini import ringfill

STYLES = {}

# dscn_str names (palette 4 of gameplay pal_y5_knm_0): white letters (15), navy ring (4), navy shadow cast down-right
STYLES["mi_name"] = ringfill([0xf], [4], [4, 4])
# h3_dem_0 スターティングオーダー / オーダー (palette 4): yellow shading to orange (13, 14, 15), blue ring (1) (the thin white
# rim of the Japanese is left out: qa RING wants the dark outside), blue shadow (2)
STYLES["mi_head"] = ringfill([0xd, 0xd, 0xe, 0xe, 0xf], [1, 1], [2, 2])
# h3_dem_0 打率 / 本塁打 (palette 3): white letters on a navy band (4), a blue shadow (6, 8)
STYLES["mi_col"] = ringfill([0xf], [4, 4], [6, 8])
