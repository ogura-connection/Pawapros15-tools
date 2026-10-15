"""Label styles of art run 1, agent C (vs.arc, sd_mode.arc, title.arc, dem_open.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering of each palette with _work/ui_pages/run1/C/style_probe.py."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# vs.arc s4_ts00 headings (palette 0): deep blue letters, pale ring, white ring, blue ring, teal shadow
STYLES["c_vs_head"] = ringfill([6, 6, 6, 6, 6, 6, 8], [12, 15, 9], [4])
# s4_ts00 option values (palette 1): purple gradient letters, white ring, blue shadow
STYLES["c_vs_opt"] = ringfill([9, 11, 11, 11, 11, 11, 11, 11], [4, 4], [15])
