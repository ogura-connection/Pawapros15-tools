"""Label styles of art run 11, agent Q (copy of the run 9 C lib). Read from the Japanese lettering by
run9/C/c6_lib.py; every style is crisp (solid rings, fill ramps only). _s = small plates (one ring)."""
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

STYLES["q11_h3_cha_0_03_1.0.0_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4, 4])
STYLES["q11_h3_cha_0_03_1.0.0_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_03_1.0.0_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_03_1.72.0_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_03_1.72.0_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_03_1.72.0_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_05_1.88.0_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_05_1.88.0_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_05_1.88.0_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_06_1.0.24_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4, 4])
STYLES["q11_h3_cha_0_06_1.0.24_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_06_1.0.24_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_07_1.0.48_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4, 4])
STYLES["q11_h3_cha_0_07_1.0.48_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_07_1.0.48_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_0b_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_0b_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_0b_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_0c_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_0c_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_0c_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_10_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_10_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_10_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_14_0.88.104_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4, 4])
STYLES["q11_h3_cha_0_14_0.88.104_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_14_0.88.104_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_3a_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_3a_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_3a_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_3b_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_3b_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_3b_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_3f_h"] = ringfill([15, 15, 14, 14, 13, 12], [2], [4])
STYLES["q11_h3_cha_0_3f_h_m"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_h3_cha_0_3f_h_s"] = ringfill([15, 15, 14, 14, 13, 12], [2], [])
STYLES["q11_od_name"] = ringfill([15, 15, 15, 15, 15, 15], [5, 5], [5])
STYLES["q11_od_thin"] = ringfill([15] * 6, [5], [5])
