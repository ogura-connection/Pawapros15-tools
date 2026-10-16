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

STYLES["e10_h3_stp_0_00_h"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1, 11, 4, 4], [])
STYLES["e10_h3_stp_0_00_h_m"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1], [])
STYLES["e10_h3_stp_0_00_h_s"] = ringfill([15, 15, 14, 14, 13, 13], [1], [])
STYLES["e10_h3_stp_0_01_h"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1, 11, 4, 4], [])
STYLES["e10_h3_stp_0_01_h_m"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1], [])
STYLES["e10_h3_stp_0_01_h_s"] = ringfill([15, 15, 14, 14, 13, 13], [1], [])
STYLES["e10_r3_tvsx_09_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_09_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_09_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0a_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_0a_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0a_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0b_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_0b_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0b_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0c_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_0c_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0c_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0d_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_0d_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0d_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0e_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_0e_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0e_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0f_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_0f_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0f_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_10_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [60, 60])
STYLES["e10_r3_tvsx_10_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_10_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_stp_00"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_00_m"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_00_s"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_01"] = ringfill([1, 10, 11, 1, 13, 4], [7], [7, 7, 7])
STYLES["e10_stp_01_m"] = ringfill([1, 10, 11, 1, 13, 4], [7], [])
STYLES["e10_stp_01_s"] = ringfill([1, 10, 11, 1, 13, 4], [7], [])
STYLES["e10_tvsx_game"] = ringfill([207, 207, 207, 207, 207, 207], [157, 80, 157, 157], [60])
STYLES["e10_tvsx_game_m"] = ringfill([207, 207, 207, 207, 207, 207], [157, 80], [])
STYLES["e10_tvsx_game_s"] = ringfill([207, 207, 207, 207, 207, 207], [157], [])
