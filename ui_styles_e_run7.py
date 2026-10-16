"""Label styles of art run 7, agent E (chrsong, arr_chg, arr_num). Read from the Japanese lettering by
run7/E/c6_lib.py; every style is crisp (solid rings, fill ramps only). _s = small plates (one ring)."""
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

STYLES["e7_s3_no_02"] = ringfill([9, 15, 15, 15, 9, 9], [4, 1], [1])
STYLES["e7_s3_no_02_s"] = ringfill([9, 15, 15, 15, 9, 9], [4], [])
STYLES["e7_s3_no_06_7"] = ringfill([15, 15, 7, 7, 15, 15], [6], [])
STYLES["e7_s3_no_06_7_s"] = ringfill([15, 15, 7, 7, 15, 15], [6], [])
STYLES["e7_s3_no_06_8"] = ringfill([15, 15, 7, 7, 15, 15], [6], [])
STYLES["e7_s3_no_06_8_s"] = ringfill([15, 15, 7, 7, 15, 15], [6], [])
STYLES["e7_s3_no_24"] = ringfill([1, 1, 1, 1, 1, 5], [1], [])
STYLES["e7_s3_no_24_s"] = ringfill([1, 1, 1, 1, 1, 5], [1], [])
STYLES["e7_s3_no_25"] = ringfill([1, 1, 1, 1, 1, 5], [1], [])
STYLES["e7_s3_no_25_s"] = ringfill([1, 1, 1, 1, 1, 5], [1], [])
STYLES["e7_s3_no_26"] = ringfill([1, 1, 8, 1, 1, 1], [1], [])
STYLES["e7_s3_no_26_s"] = ringfill([1, 1, 8, 1, 1, 1], [1], [])
STYLES["e7_s3_no_27"] = ringfill([1, 8, 1, 8, 8, 1], [1], [])
STYLES["e7_s3_no_27_s"] = ringfill([1, 8, 1, 8, 8, 1], [1], [])
STYLES["e7_s3_no_28"] = ringfill([1, 8, 1, 1, 1, 1], [1], [])
STYLES["e7_s3_no_28_s"] = ringfill([1, 8, 1, 1, 1, 1], [1], [])
STYLES["e7_s3_no_2c"] = ringfill([1, 6, 10, 1, 2, 1], [1], [])
STYLES["e7_s3_no_2c_s"] = ringfill([1, 6, 10, 1, 2, 1], [1], [])
STYLES["e7_s3_no_2d"] = ringfill([1, 1, 1, 1, 1, 5], [6], [])
STYLES["e7_s3_no_2d_s"] = ringfill([1, 1, 1, 1, 1, 5], [6], [])
