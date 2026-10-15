"""Label styles of art run 2, agent A (scs_end.arc: end of a Success game). Loaded by ui_type.py (every ui_styles_*.py is).
Colours read from the Japanese lettering of each palette (_work/ui_pages/run2/A/dump.py, palette lists).
`rpad(style, w)` pads a word on the left to w columns (right-aligned lines); `win(style, c0, c1)` returns the columns c0..c1
of the whole word (a line shared out over parts that stand side by side): the windows named "<style>~c0_c1" exist for
columns at multiples of 8 up to 392, and the last window ends at 4096."""
import numpy as np
import ui_type
from ui_type import grow, shift, logo
from ui_styles_ore_ini import ringfill

STYLES = {}


def rpad(style, w):
    def cut(ink, base):
        art, b = style(ink, base)
        out = np.zeros((art.shape[0], max(w, art.shape[1])), np.uint8)
        out[:, out.shape[1] - art.shape[1]:] = art
        return out, b
    return cut


def win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


def windows(name, step=8, top=392):
    for c0 in range(0, top + 1, step):
        for c1 in list(range(c0 + step, top + 1, step)) + [4096]:
            STYLES["%s~%d_%d" % (name, c0, c1)] = win(STYLES[name], c0, c1)


# m4_stt01 / m4_stt00 team names, forms, drop-down lists (palettes 27, 2): white letters, thick navy outline
STYLES["a_name"] = ringfill([15], [1, 1], [])
# y5_sss_1 names, forms, items (palettes 35, 46): white letters, blue and dark blue rings
STYLES["a_y5name"] = ringfill([15], [5, 1], [])
# m4_stt01 08 colour lines (palette 4): yellow letters, blue rings, right-aligned in 192 columns
STYLES["a_eqm_u"] = ringfill([14, 14, 13, 12], [1], [])
STYLES["a_name1"] = ringfill([15], [1], [])
STYLES["a_eqm"] = rpad(STYLES["a_eqm_u"], 200)
# y5_sss_1 35-38 (palette 41): yellow letters, blue rings
STYLES["a_eqy"] = ringfill([1, 1, 2, 3], [15, 14, 13], [])


def flat(ramp, cut=1):
    """Letters only, no ring: ink level k (1..6) -> palette index ramp[k]; pixels below `cut` are clear."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        out = np.where(ink >= cut, ramp[ink], 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


# m4_stt00 menu buttons (palettes 17-25): coloured letters, white ring, dark blue shadow cast down and right
for _pal, _fill in {17: [5, 5, 5, 5, 7], 18: [5, 5, 5, 5, 7], 19: [3, 3, 3, 3, 6], 20: [3, 3, 5, 5, 6], 21: [4, 4, 4, 6, 7],
                    22: [5, 5, 5, 6, 8], 23: [4, 4, 4, 4, 6], 24: [1, 1, 1, 3, 6], 25: [2, 2, 2, 4, 6]}.items():
    STYLES["a_btn%d" % _pal] = ringfill(_fill, [14, 14], [3, 2, 1])
# thin black pixel-font items: m4_stt00 (palette 5, cream), y5_sss_0 (palette 32, grey ramp), tags on the tan tabs (palette 19)
STYLES["a_thin5"] = flat([0, 7, 5, 3, 2, 1, 1])
STYLES["a_thin32"] = flat([0, 4, 7, 10, 12, 14, 15])
STYLES["a_tab19"] = flat([0, 12, 9, 6, 4, 2, 1])
# y5_sss_0 (palette 16 title, 28 buttons): blue and white lettering
STYLES["a_y5title"] = ringfill([15, 15, 14, 13, 12, 11], [8, 4, 2], [1])
STYLES["a_y5btn"] = ringfill([3, 2, 2, 2], [15, 15], [10])


# z3_sav_0: title (palette 28), buttons 終了 / 登録 (37, 38), プロ入り選手 (45; 14 draws its dark copy), パスワードを見る and
# 能力詳細 (44, a grey ramp), the two panel headings (47 orange, 46 lilac; palette 31 draws each again as a blue shadow)
STYLES["a_z3title"] = ringfill([10, 10, 7, 7, 6, 4], [15, 15, 3, 1], [])
STYLES["a_z3end"] = ringfill([13, 12, 12, 11], [8, 7, 14], [6])
STYLES["a_z3reg"] = ringfill([9, 10, 11, 12], [14, 13, 1], [3])
STYLES["a_z3pro"] = ringfill([3, 2, 1, 1], [11, 11], [9, 8])
STYLES["a_z3pw"] = ringfill([2], [15], [])
STYLES["a_z3det"] = ringfill([15], [2], [])
STYLES["a_z3new"] = ringfill([1, 1, 2, 3, 4], [8, 9, 12, 13], [])
STYLES["a_z3del"] = ringfill([1, 2, 3, 4, 5], [8, 9, 10, 12], [])


def stamp(size=40):
    """The 済 stamp (palette 33): a round red seal, pale rim, white inside; the word is set in red in the middle."""
    def style(ink, base):
        out = np.zeros((size, size), np.uint8)
        c = (size - 1) / 2.0
        yy, xx = np.mgrid[0:size, 0:size]
        r = np.hypot(yy - c, xx - c)
        out[r <= c + 0.5] = 12
        out[r <= c - 0.5] = 2
        out[r <= c - 3.5] = 7
        out[r <= c - 4.5] = 15
        h, w = ink.shape
        y0 = (size - h) // 2 + 1
        x0 = (size - w) // 2
        ramp = np.array([0, 7, 5, 3, 2, 1, 1], np.uint8)
        sub = out[y0:y0 + h, x0:x0 + w]
        sub[ink > 0] = ramp[ink[ink > 0]]
        return out, y0 + base
    return style


STYLES["a_stamp"] = stamp()
