"""Label styles of art run 2, agent D (scs_open fiction notice, scs_grad graduation, orihen ball naming, scs_intr
scenario introduction, scs_titl start screen). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# scs_open z3_fic_0 (palette 0, grey ramp): white letters, a grey soft edge, black outline, dark blue-grey shadow
STYLES["d2_fic"] = ringfill([0xf], [0xb, 4, 4], [3, 2])

ui_type.TTF["d_georgia"] = ("/System/Library/Fonts/Supplemental/Georgia Bold.ttf", 0)
ui_type.TTF["d_times"] = ("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf", 0)
ui_type.TTF["d_impact"] = ("/System/Library/Fonts/Supplemental/Impact.ttf", 0)
