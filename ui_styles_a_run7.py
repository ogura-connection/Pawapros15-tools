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
STYLES["p5_btn_c_s"] = ringfill([1, 9, 9, 9, 1, 1], [1], [])
STYLES["p5_btn_cp"] = ringfill([7, 7, 7, 1, 7, 1], [6], [6, 6, 15])
STYLES["p5_btn_cp_s"] = ringfill([7, 7, 7, 1, 7, 1], [6], [])
STYLES["p5_btn_s"] = ringfill([9, 9, 9, 1, 9, 1], [7], [])
STYLES["p5_head"] = ringfill([4, 2, 2, 2, 2, 2], [1], [])
STYLES["p5_head_s"] = ringfill([4, 2, 2, 2, 2, 2], [1], [])
STYLES["p5_help"] = ringfill([2, 1, 2, 2, 2, 2], [1], [])
STYLES["p5_help_s"] = ringfill([2, 1, 2, 2, 2, 2], [1], [])
STYLES["p5_tab"] = ringfill([1, 3, 1, 1, 3, 1], [1], [])
STYLES["p5_tab_s"] = ringfill([1, 3, 1, 1, 3, 1], [1], [])

def _win(style, c0, c1):
    def cut(ink, base):
        art, b = STYLES[style](ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

STYLES["p5_help~0_64"] = _win("p5_help", 0, 64)
STYLES["p5_help~0_66"] = _win("p5_help", 0, 66)
STYLES["p5_help~0_107"] = _win("p5_help", 0, 107)
STYLES["p5_help~64_4096"] = _win("p5_help", 64, 4096)
STYLES["p5_help~66_4096"] = _win("p5_help", 66, 4096)
STYLES["p5_help~107_4096"] = _win("p5_help", 107, 4096)
