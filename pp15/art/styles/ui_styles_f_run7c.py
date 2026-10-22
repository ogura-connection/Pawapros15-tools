"""Window styles of art run 7, agent F (written by gen_arr_sub_f_spec.py). Keep importable."""
import numpy as np
from pp15.art import typeset as ui_type
STYLES = {}

def _win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

STYLES["f7_kkw~0_37"] = _win(ui_type.RENDER["f7_kkw"], 0, 37)
STYLES["f7_kkw~0_52"] = _win(ui_type.RENDER["f7_kkw"], 0, 52)
STYLES["f7_kkw~0_83"] = _win(ui_type.RENDER["f7_kkw"], 0, 83)
STYLES["f7_kkw~0_101"] = _win(ui_type.RENDER["f7_kkw"], 0, 101)
STYLES["f7_kkw~0_112"] = _win(ui_type.RENDER["f7_kkw"], 0, 112)
STYLES["f7_kkw~0_119"] = _win(ui_type.RENDER["f7_kkw"], 0, 119)
STYLES["f7_kkw~0_122"] = _win(ui_type.RENDER["f7_kkw"], 0, 122)
STYLES["f7_kkw~37_152"] = _win(ui_type.RENDER["f7_kkw"], 37, 152)
STYLES["f7_kkw~52_115"] = _win(ui_type.RENDER["f7_kkw"], 52, 115)
STYLES["f7_kkw~83_211"] = _win(ui_type.RENDER["f7_kkw"], 83, 211)
STYLES["f7_kkw~101_4096"] = _win(ui_type.RENDER["f7_kkw"], 101, 4096)
STYLES["f7_kkw~112_240"] = _win(ui_type.RENDER["f7_kkw"], 112, 240)
STYLES["f7_kkw~119_4096"] = _win(ui_type.RENDER["f7_kkw"], 119, 4096)
STYLES["f7_kkw~122_4096"] = _win(ui_type.RENDER["f7_kkw"], 122, 4096)
STYLES["f7_kkw~165_4096"] = _win(ui_type.RENDER["f7_kkw"], 165, 4096)
STYLES["f7_kkw~180_4096"] = _win(ui_type.RENDER["f7_kkw"], 180, 4096)
STYLES["f7_kkw~211_4096"] = _win(ui_type.RENDER["f7_kkw"], 211, 4096)
STYLES["f7_kkw~240_4096"] = _win(ui_type.RENDER["f7_kkw"], 240, 4096)
