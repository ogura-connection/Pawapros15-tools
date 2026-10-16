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
STYLES["e7_s3_no_06_7_h"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["e7_s3_no_06_7_h_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["e7_s3_no_06_8_h"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["e7_s3_no_06_8_h_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["e7_s3_no_24_h"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_24_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_25_h"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_25_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_26_h"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_26_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_27_h"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_27_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_28_h"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_28_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_2c_h"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_2c_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_2d_h"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["e7_s3_no_2d_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
