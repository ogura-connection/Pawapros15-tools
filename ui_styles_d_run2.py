"""Label styles of art run 2, agent D (scs_open fiction notice, scs_grad graduation, orihen ball naming, scs_intr
scenario introduction, scs_titl start screen). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# scs_open z3_fic_0 (palette 0, grey ramp): white letters, a grey soft edge, black outline, dark blue-grey shadow
STYLES["d2_fic"] = ringfill([0xf], [0xb, 4], [3, 2])

ui_type.TTF["d_georgia"] = ("/System/Library/Fonts/Supplemental/Georgia Bold.ttf", 0)
ui_type.TTF["d_times"] = ("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf", 0)
ui_type.TTF["d_impact"] = ("/System/Library/Fonts/Supplemental/Impact.ttf", 0)

# scs_titl r4_staz (8-bit, palette 16): the three buttons. Gradient letters, a thin dark outline, a white band, a blue
# shadow to the lower right (orange / lime / green fill; each has its own run of palette entries)
STYLES["d2_staz_new"] = ringfill([1, 2, 3, 4, 6, 5, 9, 11], [25, 57, 57, 35], [35, 35])
STYLES["d2_staz_cont"] = ringfill([166, 168, 169, 170, 171, 175, 176], [129, 181, 181, 152], [152, 152])
STYLES["d2_staz_list"] = ringfill([215, 216, 218, 221, 226, 229], [240, 210, 210, 193], [193, 193])
