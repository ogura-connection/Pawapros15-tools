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


# ---- gdt_sch.arc: Baseball School test banners (palettes of pal_h3_kyo_0) ------------------------------------------------
def fixed(style, W, align="centre"):
    """The styled word on a canvas exactly W columns wide (a word shared out over parts with fixed windows)."""
    def make(ink, base):
        art, b = style(ink, base)
        if art.shape[1] >= W:
            return art, b
        pad = W - art.shape[1]
        left = pad if align == "right" else pad // 2
        out = np.zeros((art.shape[0], W), np.uint8)
        out[:, left:left + art.shape[1]] = art
        return out, b
    return make


STYLES["a4_stk_blue"] = ringfill([15, 14, 13, 13, 12, 12, 11, 11], [1, 10, 10, 2, 2], [5, 5, 6, 6])       # pal 3: cyan, white ring, blue
STYLES["a4_stk_pink"] = ringfill([9, 9, 10, 11, 11, 12, 13, 13], [1, 15, 13, 4, 4], [6, 7, 7])             # pal 0: pink, white ring, magenta
STYLES["a4_stk_violet"] = ringfill([8, 8, 9, 10, 11, 12, 13], [1, 2, 15, 13, 3], [7, 7, 7])                # pal 11: violet, white ring
STYLES["a4_stk_pass"] = ringfill([6, 6, 7, 8, 8, 9, 9], [3, 3, 3, 10, 10, 14, 15, 15])                     # pal 4: yellow, purple, white, hot pink
# Test Start: a 192 column canvas (parts 32 + 128 + 32), the word flush right so "Start" ends where the Japanese 開始 ends;
# Start: a 96 column canvas (parts 16 + 48 + 32), flush right: both end in the same last 32 columns (a part they share)
STYLES["a4_stk_ts"] = fixed(STYLES["a4_stk_blue"], 192, "right")
STYLES["a4_stk_s"] = fixed(STYLES["a4_stk_blue"], 96, "right")
STYLES["a4_stk_over"] = fixed(STYLES["a4_stk_pink"], 184, "centre")
for _n, _c in (("a4_stk_ts", (0, 32, 160)), ("a4_stk_s", (0, 16, 64)), ("a4_stk_over", (0, 32, 160))):
    _e = list(_c) + [4096]
    for _a, _b in zip(_e, _e[1:]):
        STYLES["%s~%d_%d" % (_n, _a, _b)] = win(STYLES[_n], _a, _b)
STYLES["a4_stk_pass~0_128"] = win(STYLES["a4_stk_pass"], 0, 128)
STYLES["a4_stk_pass~128_4096"] = win(STYLES["a4_stk_pass"], 128, 4096)
