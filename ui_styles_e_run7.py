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

STYLES["e7_s3_id_00_33_h"] = ringfill([3, 3, 3, 3, 3, 3], [15], [])
STYLES["e7_s3_id_00_33_h_s"] = ringfill([3, 3, 3, 3, 3, 3], [15], [])
STYLES["e7_s3_id_00_36_h"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["e7_s3_id_00_36_h_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["e7_s3_id_00_4.0.112-4.96.112_h"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.0.112-4.96.112_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.0.80_h"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.0.80_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.0.96_h"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.0.96_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.48.80_h"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.48.80_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.80.80_h"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.80.80_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.96.96_h"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_00_4.96.96_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [0], [])
STYLES["e7_s3_id_06_h"] = ringfill([13, 13, 11, 11, 11, 13], [5, 15], [3])
STYLES["e7_s3_id_06_h_s"] = ringfill([13, 13, 11, 11, 11, 13], [5], [])
STYLES["e7_s3_id_07_h"] = ringfill([12, 12, 11, 11, 10, 10], [5, 13], [3])
STYLES["e7_s3_id_07_h_s"] = ringfill([12, 12, 11, 11, 10, 10], [5], [])
STYLES["e7_s3_id_08_10.0.0_h"] = ringfill([14, 13, 13, 12, 12, 12], [5, 15], [3])
STYLES["e7_s3_id_08_10.0.0_h_s"] = ringfill([14, 13, 13, 12, 12, 12], [5], [])
STYLES["e7_s3_id_09_h"] = ringfill([14, 13, 13, 12, 12, 12], [5, 15], [3])
STYLES["e7_s3_id_09_h_s"] = ringfill([14, 13, 13, 12, 12, 12], [5], [])
STYLES["e7_s3_id_17_h"] = ringfill([5, 5, 5, 5, 5, 5], [7, 14], [])
STYLES["e7_s3_id_17_h_s"] = ringfill([5, 5, 5, 5, 5, 5], [7], [])
STYLES["e7_s3_id_18_h"] = ringfill([5, 5, 5, 5, 5, 5], [7, 14], [])
STYLES["e7_s3_id_18_h_s"] = ringfill([5, 5, 5, 5, 5, 5], [7], [])
STYLES["e7_s3_id_2c_7.0.0-7.0.32_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2c_7.0.0-7.0.32_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_2c_7.0.64-7.0.96_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2c_7.0.64-7.0.96_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_2c_7.80.96-8.0.0_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2c_7.80.96-8.0.0_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_2d_9.88.0-9.0.32_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2d_9.88.0-9.0.32_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_2e_9.88.0-9.0.32_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2e_9.88.0-9.0.32_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_2f_8.56.32-8.0.64_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2f_8.56.32-8.0.64_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_2f_8.56.96_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2f_8.56.96_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_2f_h"] = ringfill([1, 1, 1, 1, 1, 1], [10], [15])
STYLES["e7_s3_id_2f_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["e7_s3_id_33_33_h"] = ringfill([3, 3, 3, 3, 3, 3], [15], [])
STYLES["e7_s3_id_33_33_h_s"] = ringfill([3, 3, 3, 3, 3, 3], [15], [])
STYLES["e7_s3_id_34_h"] = ringfill([5, 5, 5, 5, 5, 5], [7, 14], [])
STYLES["e7_s3_id_34_h_s"] = ringfill([5, 5, 5, 5, 5, 5], [7], [])
STYLES["e7_s3_id_35_h"] = ringfill([5, 5, 5, 5, 5, 5], [7, 14], [])
STYLES["e7_s3_id_35_h_s"] = ringfill([5, 5, 5, 5, 5, 5], [7], [])
STYLES["e7_s3_id_00_4.0.112-4.96.112_h~0_92"] = _win(STYLES["e7_s3_id_00_4.0.112-4.96.112_h"], 0, 92)
STYLES["e7_s3_id_00_4.0.112-4.96.112_h~92_4096"] = _win(STYLES["e7_s3_id_00_4.0.112-4.96.112_h"], 92, 4096)
STYLES["e7_s3_id_2c_7.0.0-7.0.32_h~0_128"] = _win(STYLES["e7_s3_id_2c_7.0.0-7.0.32_h"], 0, 128)
STYLES["e7_s3_id_2c_7.0.0-7.0.32_h~128_4096"] = _win(STYLES["e7_s3_id_2c_7.0.0-7.0.32_h"], 128, 4096)
STYLES["e7_s3_id_2c_7.0.64-7.0.96_h~0_128"] = _win(STYLES["e7_s3_id_2c_7.0.64-7.0.96_h"], 0, 128)
STYLES["e7_s3_id_2c_7.0.64-7.0.96_h~128_4096"] = _win(STYLES["e7_s3_id_2c_7.0.64-7.0.96_h"], 128, 4096)
STYLES["e7_s3_id_2c_7.80.96-8.0.0_h~0_48"] = _win(STYLES["e7_s3_id_2c_7.80.96-8.0.0_h"], 0, 48)
STYLES["e7_s3_id_2c_7.80.96-8.0.0_h~176_4096"] = _win(STYLES["e7_s3_id_2c_7.80.96-8.0.0_h"], 176, 4096)
STYLES["e7_s3_id_2c_7.80.96-8.0.0_h~48_176"] = _win(STYLES["e7_s3_id_2c_7.80.96-8.0.0_h"], 48, 176)
STYLES["e7_s3_id_2d_9.88.0-9.0.32_h~0_40"] = _win(STYLES["e7_s3_id_2d_9.88.0-9.0.32_h"], 0, 40)
STYLES["e7_s3_id_2d_9.88.0-9.0.32_h~162_258"] = _win(STYLES["e7_s3_id_2d_9.88.0-9.0.32_h"], 162, 258)
STYLES["e7_s3_id_2d_9.88.0-9.0.32_h~258_4096"] = _win(STYLES["e7_s3_id_2d_9.88.0-9.0.32_h"], 258, 4096)
STYLES["e7_s3_id_2d_9.88.0-9.0.32_h~40_162"] = _win(STYLES["e7_s3_id_2d_9.88.0-9.0.32_h"], 40, 162)
STYLES["e7_s3_id_2e_9.88.0-9.0.32_h~0_40"] = _win(STYLES["e7_s3_id_2e_9.88.0-9.0.32_h"], 0, 40)
STYLES["e7_s3_id_2e_9.88.0-9.0.32_h~168_296"] = _win(STYLES["e7_s3_id_2e_9.88.0-9.0.32_h"], 168, 296)
STYLES["e7_s3_id_2e_9.88.0-9.0.32_h~296_4096"] = _win(STYLES["e7_s3_id_2e_9.88.0-9.0.32_h"], 296, 4096)
STYLES["e7_s3_id_2e_9.88.0-9.0.32_h~40_168"] = _win(STYLES["e7_s3_id_2e_9.88.0-9.0.32_h"], 40, 168)
STYLES["e7_s3_id_2f_8.56.32-8.0.64_h~0_72"] = _win(STYLES["e7_s3_id_2f_8.56.32-8.0.64_h"], 0, 72)
STYLES["e7_s3_id_2f_8.56.32-8.0.64_h~200_4096"] = _win(STYLES["e7_s3_id_2f_8.56.32-8.0.64_h"], 200, 4096)
STYLES["e7_s3_id_2f_8.56.32-8.0.64_h~72_200"] = _win(STYLES["e7_s3_id_2f_8.56.32-8.0.64_h"], 72, 200)
