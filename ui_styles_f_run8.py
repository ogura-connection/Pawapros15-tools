"""Label styles of art run 8, agent F. Read from the Japanese lettering by
run8/F/f8_lib.py; every style is crisp (solid rings, fill ramps only). _s = small plates (one ring)."""
import numpy as np
from ui_styles_ore_ini import ringfill

STYLES = {}

def _sil(front, c):
    def style(ink, base):
        out, b = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), b
    return style

STYLES["f8_y3_kane_0a"] = ringfill([15, 9, 9, 15, 5, 15], [6], [6])
STYLES["f8_y3_kane_0a_s"] = ringfill([15, 9, 9, 15, 5, 15], [6], [])
STYLES["f8_y3_kane_0b"] = ringfill([15, 15, 15, 15, 15, 15], [15, 15, 3], [])
STYLES["f8_y3_kane_0b_s"] = ringfill([15, 15, 15, 15, 15, 15], [15], [])
STYLES["f8_y3_kane_0d"] = ringfill([15, 15, 15, 15, 15, 15], [15, 15, 5], [])
STYLES["f8_y3_kane_0d_s"] = ringfill([15, 15, 15, 15, 15, 15], [15], [])
STYLES["f8_y3_kane_0e"] = ringfill([15, 9, 9, 15, 5, 15], [1], [])
STYLES["f8_y3_kane_0e_s"] = ringfill([15, 9, 9, 15, 5, 15], [1], [])
