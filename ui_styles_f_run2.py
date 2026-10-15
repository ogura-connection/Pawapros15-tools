"""Label styles of art run 2, agent F (scg_camp.arc: elite squad camp mini-games; scs_g_ed.arc: draft announcements).
Loaded by ui_type.py. Colours were read from the Japanese lettering of each palette."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# h3_st_0 HUD labels (palette 13): yellow letters, tan inner edge, deep blue outline, light blue outer edge
STYLES["f_st_yel"] = ringfill([0xf, 0xf, 0xe, 0xe, 0xd, 0xd], [6, 6, 1])
# h3_st_0 Bonus (palette 15): white to pink letters, deep blue outline, blue shadow
STYLES["f_st_pink"] = ringfill([7, 7, 8, 9, 0xa, 0xb], [1, 1], [3, 4])
