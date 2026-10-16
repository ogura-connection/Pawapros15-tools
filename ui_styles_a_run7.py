"""Label styles of art run 7, agent A (arr_sub). Read from the Japanese lettering by
run7/A/a7_lib.py; every style is crisp (solid rings, fill ramps only). _s = small plates (one ring)."""
import numpy as np
from ui_styles_ore_ini import ringfill

STYLES = {}

def _sil(front, c):
    def style(ink, base):
        out, b = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), b
    return style

STYLES["p5_btn"] = ringfill([9, 9, 9, 1, 9, 1], [7], [])
STYLES["p5_btn_c"] = ringfill([1, 9, 9, 9, 1, 1], [1], [])
STYLES["p5_btn_c_h"] = ringfill([9, 9, 9, 9, 9, 9], [1, 1, 3], [5, 8])
STYLES["p5_btn_c_h_s"] = ringfill([9, 9, 9, 9, 9, 9], [1], [])
STYLES["p5_btn_c_s"] = ringfill([1, 9, 9, 9, 1, 1], [1], [])
STYLES["p5_btn_cp"] = ringfill([7, 7, 7, 1, 7, 1], [6], [6, 6, 15])
STYLES["p5_btn_cp_h"] = ringfill([7, 7, 7, 7, 7, 7], [1, 1, 2], [6, 3])
STYLES["p5_btn_cp_h_s"] = ringfill([7, 7, 7, 7, 7, 7], [1], [])
STYLES["p5_btn_cp_s"] = ringfill([7, 7, 7, 1, 7, 1], [6], [])
STYLES["p5_btn_h"] = ringfill([9, 9, 9, 9, 9, 9], [1, 1, 3], [4, 6])
STYLES["p5_btn_h_s"] = ringfill([9, 9, 9, 9, 9, 9], [1], [])
STYLES["p5_btn_s"] = ringfill([9, 9, 9, 1, 9, 1], [7], [])
STYLES["p5_head"] = ringfill([4, 2, 2, 2, 2, 2], [1], [])
STYLES["p5_head_h"] = ringfill([2, 2, 2, 2, 2, 2], [1, 1], [6])
STYLES["p5_head_h_s"] = ringfill([2, 2, 2, 2, 2, 2], [1], [])
STYLES["p5_head_s"] = ringfill([4, 2, 2, 2, 2, 2], [1], [])
STYLES["p5_help"] = ringfill([2, 1, 2, 2, 2, 2], [1], [])
STYLES["p5_help_h"] = ringfill([2, 2, 2, 2, 2, 2], [1, 1], [6])
STYLES["p5_help_h_s"] = ringfill([2, 2, 2, 2, 2, 2], [1], [])
STYLES["p5_help_s"] = ringfill([2, 1, 2, 2, 2, 2], [1], [])
STYLES["p5_tab"] = ringfill([1, 3, 1, 1, 3, 1], [1], [])
STYLES["p5_tab_s"] = ringfill([1, 3, 1, 1, 3, 1], [1], [])
STYLES["p5_tabbest_h"] = ringfill([1, 1, 1, 1, 1, 1], [3, 3], [])
STYLES["p5_tabbest_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [3], [])
STYLES["p5_tablhp_h"] = ringfill([1, 1, 1, 1, 1, 1], [4, 4], [])
STYLES["p5_tablhp_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["p5_tabnbest_h"] = ringfill([1, 1, 1, 1, 1, 1], [3, 3], [])
STYLES["p5_tabnbest_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [3], [])
STYLES["p5_tabnlhp_h"] = ringfill([1, 1, 1, 1, 1, 1], [3, 3], [])
STYLES["p5_tabnlhp_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [3], [])
STYLES["p5_tabnrhp_h"] = ringfill([1, 1, 1, 1, 1, 1], [3, 3], [])
STYLES["p5_tabnrhp_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [3], [])
STYLES["p5_tabrhp_h"] = ringfill([1, 1, 1, 1, 1, 1], [2, 2], [])
STYLES["p5_tabrhp_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [2], [])

def _win(style, c0, c1):
    def cut(ink, base):
        art, b = STYLES[style](ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

STYLES["p5_help_h~0_58"] = _win("p5_help_h", 0, 58)
STYLES["p5_help_h~0_64"] = _win("p5_help_h", 0, 64)
STYLES["p5_help_h~0_66"] = _win("p5_help_h", 0, 66)
STYLES["p5_help_h~0_108"] = _win("p5_help_h", 0, 108)
STYLES["p5_help_h~58_4096"] = _win("p5_help_h", 58, 4096)
STYLES["p5_help_h~64_4096"] = _win("p5_help_h", 64, 4096)
STYLES["p5_help_h~66_4096"] = _win("p5_help_h", 66, 4096)
STYLES["p5_help_h~108_4096"] = _win("p5_help_h", 108, 4096)
