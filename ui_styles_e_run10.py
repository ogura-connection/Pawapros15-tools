"""Label styles of art run 10, agent E. Read from the Japanese lettering by
run10/E/c6_lib.py; every style is crisp (solid rings, fill ramps only). _s = small plates (one ring)."""
import numpy as np
from ui_styles_ore_ini import ringfill

STYLES = {}

def _win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

def _sil(front, c):
    def style(ink, base):
        out, b = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), b
    return style

STYLES["e10_stp_00"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_00_m"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_00_s"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_01"] = ringfill([1, 10, 11, 1, 13, 4], [7], [7, 7, 7])
STYLES["e10_stp_01_m"] = ringfill([1, 10, 11, 1, 13, 4], [7], [])
STYLES["e10_stp_01_s"] = ringfill([1, 10, 11, 1, 13, 4], [7], [])
