"""Label styles of art run 2, agent F (scg_camp.arc: elite squad camp mini-games; scs_g_ed.arc: draft announcements).
Loaded by ui_type.py. Colours were read from the Japanese lettering of each palette."""
import numpy as np
import ui_type
from ui_type import grow, shift, logo
from ui_styles_ore_ini import ringfill

STYLES = {}

# h3_st_0 HUD labels (palette 13): yellow letters, tan inner edge, deep blue outline, light blue outer edge
STYLES["f_st_yel"] = ringfill([0xf, 0xf, 0xe, 0xe, 0xd, 0xd], [6, 6, 1])
# h3_st_0 Bonus (palette 15): white to pink letters, deep blue outline, blue shadow
STYLES["f_st_pink"] = ringfill([7, 7, 8, 9, 0xa, 0xb], [1, 1], [3, 4])
STYLES["f_st_yel2"] = ringfill([0xf, 0xf, 0xe, 0xe, 0xd, 0xd], [6, 6])


def stacked(inner, overlap=2):
    """The same style applied to every line of a block on its own (typeset stacks lines with clear rows between them): each
    line gets its own gradient and rings; the lines are centred on each other and overlap by `overlap` rows (the rings)."""
    def style(ink, base):
        rows = np.nonzero(ink.any(1))[0]
        cuts = [0] + [k for k in range(1, len(rows)) if rows[k] != rows[k - 1] + 1]
        blocks = []
        for a, b in zip(cuts, cuts[1:] + [len(rows)]):
            r0, r1 = rows[a], rows[b - 1] + 1
            art, bs = inner(ink[r0:r1], r1 - r0)
            blocks.append((art, bs))
        W = max(a.shape[1] for a, _ in blocks)
        H = sum(a.shape[0] for a, _ in blocks) - overlap * (len(blocks) - 1)
        out = np.zeros((H, W), np.uint8)
        y = 0
        for art, bs in blocks:
            x = (W - art.shape[1]) // 2
            area = out[y:y + art.shape[0], x:x + art.shape[1]]
            area[art > 0] = art[art > 0]
            y += art.shape[0] - overlap
        return out, H - (blocks[-1][0].shape[0] - blocks[-1][1])
    return style


# h3_st_0 popups (palettes 53 pink / 54 blue, the same indices): lilac to white letters, deep blue outline, blue edge
STYLES["f_st_flash"] = stacked(ringfill([0xb, 0x9, 0x9, 0x8, 0x7, 0x7], [1, 1, 3]))

# h3_kyos_0_opd HUD labels (palette 10): pale to deep yellow letters, navy outline, blue shadow running to violet
STYLES["f_ky_yel"] = ringfill([0xf, 0xe, 0xa, 0xd, 0xd, 0xc], [3, 3], [5, 5, 6, 7])
# swing tags (palettes 16-19, white letters on the orange / yellow / green / purple plates): navy outline, blue rim
STYLES["f_ky_btn"] = ringfill([0xf, 0xf, 0xe, 0xd, 0xd], [5, 4])
# 点 next to the digits (palette 6): lilac-white letters, light edge, navy outline, blue shadow
STYLES["f_ky_pts"] = ringfill([0xe, 0xe, 0xd, 0xd, 0xc, 0xb], [0xa, 4], [2, 2])


# z4_teu_0 titles (one palette each; the white twins, palette 15, take the same art: every index is white there).
# Letters: a gradient, a thin dark outline, a white band two pixels wide, a pale rim, a navy shadow below and to the right.
STYLES["f_teu_blue"] = logo([8, 8, 7, 6, 5, 5], [8, 8], 9, 1, 3, [0xd, 0xd, 0xd, 0xd], 2, 1)        # palette 0: Test Start
STYLES["f_teu_pink"] = logo([7, 7, 8, 9, 10, 11], [7, 7], 3, 15, 5, [1, 1, 1, 1], 2, 1)             # palette 2: Test Over
STYLES["f_teu_orange"] = logo([6, 6, 5, 4, 3, 2, 1], [6, 6], 7, 15, 11, [10, 10, 10, 10], 2, 1)     # palette 4: Win
STYLES["f_teu_steel"] = logo([7, 8, 8, 9, 10, 10], [7, 7], 2, 15, 11, [1, 1, 1, 1], 2, 1)           # palette 6: Loss
STYLES["f_teu_green"] = logo([7, 7, 8, 9, 10, 10], [7, 7], 2, 15, 3, [1, 1, 1, 1], 2, 1)            # palette 8: Tie


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


for _name in ("f_teu_blue", "f_teu_pink", "f_teu_orange", "f_teu_steel", "f_teu_green"):
    for _c in ((0, 128), (128, 256), (0, 4096), (128, 4096)):
        STYLES["%s~%d_%d" % (_name, _c[0], _c[1])] = win(STYLES[_name], *_c)

# scs_g_ed.arc i5_h (4-bit pages, palette 0): the draft team names: chrome blue letters (dark, light in the middle, dark),
# a pale edge, a navy outline three pixels wide
STYLES["f_g_team"] = ringfill([4, 5, 7, 9, 0xa, 0xa, 9, 8, 6, 4], [0xe, 1, 1, 1], edge=2)


def tilted(style, rise):
    """The word on a slope: each column of the ink is lifted `rise` pixels per 100 columns towards the right (whole pixels:
    the steps stay crisp), then the style is applied."""
    def lift(ink, base):
        h, w = ink.shape
        dy = [int(round(rise * (w - 1 - x) / 100.0)) for x in range(w)]
        out = np.zeros((h + max(dy), w), ink.dtype)
        for x in range(w):
            out[dy[x]:dy[x] + h, x] = ink[:, x]
        return style(out, base + max(dy))
    return lift


# scs_g_ed.arc i5_h sprites 00 / 01 (palette 1, the shadow twin palette 2): the welcome banner: mint to green letters, a thin
# dark outline, a yellow band three pixels wide, a white rim; tilted up to the right as the Japanese is
STYLES["f_g_title"] = tilted(logo([0xa, 9, 8, 7, 6, 5], [0xa, 0xa], 1, 0xf, 0xb, [], 4, 1), 6.0)
for _c in ((0, 128), (128, 256), (256, 384), (384, 512), (0, 4096), (128, 4096), (256, 4096), (384, 4096)):
    STYLES["f_g_title~%d_%d" % _c] = win(STYLES["f_g_title"], *_c)
