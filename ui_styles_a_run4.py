"""Label styles of art run 4, agent A (sct_a_mk.arc, gdt_sch.arc, sct_a_lb.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering (bank.style_from); every style is crisp (solid rings, fill ramps only)."""
from ui_styles_ore_ini import ringfill
import numpy as np

STYLES = {}


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


# ---- sct_a_lb.arc (graduation album) --------------------------------------------------------------------------------------
STYLES["a4_lb_title"] = ringfill([15, 15, 15, 15, 15, 15], [1, 3, 8, 12], [6, 7])       # pal 16: white, dark ring, gold bands
STYLES["a4_lb_title~0_128"] = win(STYLES["a4_lb_title"], 0, 128)
STYLES["a4_lb_title~128_4096"] = win(STYLES["a4_lb_title"], 128, 4096)
STYLES["a4_lb_head"] = ringfill([2, 2, 2, 2, 2, 2], [1, 1, 8])                                          # pal 18: olive letters, white ring, grey edge
