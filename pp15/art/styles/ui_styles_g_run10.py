"""Label styles of art run 10, agent G (names g10_*): lettering of code-drawn atlases painted in place.
mk(fill, rings, t=3, foot=None, edge=None): crisp letters (ink level >= t), `fill` = palette index per row from the top
of the lettering (last value repeats), `foot` (optional) = index of a letter pixel with no letter pixel below it,
solid `rings` (innermost first, diagonals included)."""
import numpy as np
from pp15.art import typeset as ui_type

STYLES = {}


def mk(fill, rings, t=3, foot=None):
    fill = list(fill)

    def style(ink, base):
        pad = len(rings)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        big[pad:pad + h, pad:pad + w] = ink >= t
        out = np.zeros(big.shape, np.uint8)
        for k in range(pad, 0, -1):
            out[ui_type.grow(big, k)] = rings[k - 1]
        ys, xs = np.nonzero(big)
        top = ys.min()
        for y, x in zip(ys, xs):
            r = y - top
            v = fill[min(r, len(fill) - 1)]
            if foot is not None and not big[y + 1, x]:
                v = foot
            out[y, x] = v
        return out, base + pad
    return style


STYLES["g10_wd"] = mk([1, 2, 4], [8, 8])
STYLES["g10_wd1"] = mk([1, 2, 4], [8])
STYLES["g10_ban"] = mk([4], [8, 8, 15], foot=5)
STYLES["g10_none"] = lambda ink, base: (np.zeros((1, 1), np.uint8), base)
STYLES["g10_ok"] = mk([15], [11, 6])


def card(core=15, shadow=5, t=3):
    """Lettering of the My Life card atlas (y3_mym page 7): crisp letters `core`, a one-pixel `shadow` down and to the right."""
    def style(ink, base):
        pad = 1
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= t
        out = np.zeros(m.shape, np.uint8)
        sh = ui_type.shift(m, 1, 1)
        out[sh & ~m] = shadow
        out[m] = core
        return out, base + 0
    return style


def bevel(top, core, bottom, t=3):
    """Crisp letters `core`; left / top edge `top`, right / bottom edge `bottom` (no ring)."""
    def style(ink, base):
        h, w = ink.shape
        m = ink >= t
        up = np.zeros_like(m); up[1:] = m[:-1]
        left = np.zeros_like(m); left[:, 1:] = m[:, :-1]
        dn = np.zeros_like(m); dn[:-1] = m[1:]
        rt = np.zeros_like(m); rt[:, :-1] = m[:, 1:]
        out = np.zeros(m.shape, np.uint8)
        out[m] = core
        out[m & (~dn | ~rt)] = bottom
        out[m & (~up | ~left)] = top
        return out, base
    return style


STYLES["g10_mc"] = card()
STYLES["g10_mn"] = card(shadow=0)
STYLES["g10_mt"] = bevel(11, 13, 5)
STYLES["g10_mtf"] = bevel(13, 13, 5)
