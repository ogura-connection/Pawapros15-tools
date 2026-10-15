"""Label styles of art run 2, agent C (gdt_scs.arc Success match labels, scs_vs.arc versus screen, scs_win.arc result screen).
Loaded by ui_type.py. Plain numbers read from the Japanese lettering of each palette (see the comment on every style)."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}


def padded(style, h):
    """The art of `style` padded with clear rows at the foot to exactly h rows (labels of one band group are as high as the band)."""
    def cut(ink, base):
        art, b = style(ink, base)
        H, W = art.shape
        if H > h:
            return art, b
        out = np.zeros((h, W), np.uint8)
        out[:H] = art
        return out, b
    return cut


# gdt_scs z3_sgr_0 (palette 11): white letters in a dark blue outline, one pixel, so that 71 phrases fit the ten pages
STYLES["c2_sgr"] = padded(ringfill([15], [4], []), 17)
# gdt_scs z3_sgi_0 (palette 2): white letters, navy outline, blue ring
STYLES["c2_sgi"] = padded(ringfill([15], [4, 2], []), 20)
# gdt_scs h3_mrs_0 (palette 0): orange letters, dark brown outline, brown ring
STYLES["c2_mrs"] = ringfill([15], [1, 3], [])
# gdt_scs / scs_vs svt_0 (palette 0): white letters, navy outline, blue band, white rim
STYLES["c2_svt"] = ringfill([15], [1, 1, 9, 9, 9, 15, 15], [7, 13])


def window(inner, W, c0, c1):
    """`inner` art centred on a canvas W columns wide, only the columns c0..c1 returned: one word shared out over the pieces
    (parts) that the sprite is drawn from, each piece painted in place by a "paint" entry."""
    def cut(ink, base):
        art, b = inner(ink, base)
        H, aw = art.shape
        full = np.zeros((H, W), np.uint8)
        x = (W - aw) // 2
        if x >= 0:
            full[:, x:x + aw] = art
        else:
            full[:] = art[:, -x:-x + W]
        out = full[:, c0:c1]
        return (out if out.shape[1] else np.zeros((H, 1), np.uint8)), b
    return cut


for _w, _c0, _c1 in ((80, 0, 80), (80, 0, 48), (80, 48, 80), (32, 0, 32)):
    STYLES["c2_mrsw_%d_%d_%d" % (_w, _c0, _c1)] = window(STYLES["c2_mrs"], _w, _c0, _c1)
