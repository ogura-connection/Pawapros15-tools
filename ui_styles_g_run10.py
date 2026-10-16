"""Label styles of art run 10, agent G (names g10_*): lettering of code-drawn atlases painted in place.
mk(fill, rings, t=3, foot=None, edge=None): crisp letters (ink level >= t), `fill` = palette index per row from the top
of the lettering (last value repeats), `foot` (optional) = index of a letter pixel with no letter pixel below it,
solid `rings` (innermost first, diagonals included)."""
import numpy as np
import ui_type

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
