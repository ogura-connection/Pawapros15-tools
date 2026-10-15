"""Label styles of art run 3, agent B (scc_tops.arc: the Linked World screens, bank z4_li_0). Loaded by ui_type.py.
Colours are read from the Japanese lettering of each palette (the title: palette 16, the three village headings:
palettes 17 / 18 / 19, the A-button legend: 43, the small plates: 35 / 39 / 51 / 52 / 53). Every style is crisp: solid
rings, no half tones except the fill gradients. The dark layers (sprites 01 and 41-43) draw the same page art with a
flat palette, so they follow the front layer exactly and need no style of their own."""
import numpy as np
import ui_type
from ui_type import grow, shift

STYLES = {}


def trim(out, base):
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


def stack(fill, layers, inner=None, edge=3):
    """Letters filled top to foot from `fill`, then `layers` outwards, each ("ring", [index per pixel of width]) all round
    the whole so far, or ("se", [index per step]) a copy of the whole so far cast down and to the right (an extruded
    edge, a shadow). A pixel of the soft edge (ink level below `edge`) takes the colour of the first layer. `inner` = an
    index for the outermost pixel row of the letters themselves (a thin darker edge of the fill)."""
    fill = list(fill)
    layers = [(k, list(v)) for k, v in layers]
    reach = sum(len(v) for _, v in layers)

    def style(ink, base):
        pad = reach + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        out = np.zeros(big.shape, np.uint8)
        cur = letters.copy()
        first = True
        for kind, idxs in layers:
            if kind == "ring":
                for v in idxs:
                    new = grow(cur, 1, diagonal=first)
                    first = False
                    out[new & ~cur] = v
                    cur = new
            else:                                              # "se"
                n = len(idxs)
                union = cur.copy()
                for k in range(n, 0, -1):
                    reg = (shift(cur, k, k) | shift(cur, k, k - 1) | shift(cur, k - 1, k)) & ~cur
                    out[reg] = idxs[k - 1]
                    union |= reg
                cur = union
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        first_idx = layers[0][1][0]
        body = np.where(big >= edge, row, first_idx)
        if inner is not None:
            p = np.pad(letters, 1, constant_values=False)
            border = letters & ~(p[:-2, 1:-1] & p[2:, 1:-1] & p[1:-1, :-2] & p[1:-1, 2:])
            body = np.where(border & (big >= edge), inner, body)
        out[letters] = body[letters]
        return trim(out, base + pad)
    return style


def win(style, c0, c1, r0=0, r1=4096):
    """Only the columns c0..c1 and rows r0..r1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[r0:r1, c0:c1]
        if out.shape[1] == 0 or out.shape[0] == 0:
            out = np.zeros((max(out.shape[0], 1), max(out.shape[1], 1)), np.uint8)
        return out, b - r0
    return cut


# ---- the title: Linked World (palette 16): yellow letters, brown rim and extruded edge, white band, light blue shadow, blue ring
STYLES["b3_title"] = stack([0xc, 0xc, 0xd, 0xd, 0xe, 0xe], [("ring", [8, 8]), ("se", [8, 8, 8, 7, 7]), ("ring", [1, 1, 1]),
                                                           ("se", [5, 5, 5, 5]), ("ring", [4, 2, 2])], inner=0xa)
