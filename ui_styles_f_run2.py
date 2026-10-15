"""Label styles of art run 2, agent F (scg_camp.arc: elite squad camp mini-games; scs_g_ed.arc: draft announcements).
Loaded by ui_type.py. Colours were read from the Japanese lettering of each palette."""
import numpy as np
import ui_type
from ui_type import grow, shift
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
