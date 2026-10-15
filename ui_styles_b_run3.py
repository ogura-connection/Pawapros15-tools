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


def close_h(mask, n):
    """Gaps of up to n columns between ink on a row filled (dilate, then erode, sideways)."""
    m = mask.copy()
    for _ in range(n):
        m = m | shift(m, 0, 1) | shift(m, 0, -1)
    for _ in range(n):
        m = m & shift(m, 0, 1) & shift(m, 0, -1)
    return m | mask


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
            if kind == "close":                                # gaps of up to 4 columns between letters filled with one colour
                gap = close_h(cur, 4) & ~cur
                out[gap] = idxs[0]
                cur = cur | gap
            elif kind == "ring":
                for v in idxs:
                    new = grow(cur, 1, diagonal=first)
                    first = False
                    out[new & ~cur] = v
                    cur = new
            else:                                              # "se" (or "sec": gaps of up to 3 columns between letters closed first)
                n = len(idxs)
                union = cur.copy()
                src = close_h(cur, 3) if kind == "sec" else cur
                for k in range(n, 0, -1):
                    reg = (shift(src, k, k) | shift(src, k, k - 1) | shift(src, k - 1, k)) & ~cur
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
                                                           ("se", [5, 5, 5, 5]), ("close", [5]), ("ring", [4, 2, 2])], inner=0xa)

# ---- the village headings and the three buttons: green (palette 17), mint (18), lavender (19) letters with a dark outline cast
# down and to the right, a white band, a light blue shadow and a thin blue ring
STYLES["b3_head1"] = stack([0xe, 0xe, 0xc, 0xc, 0xb, 0xb, 0x8, 0x8], [("ring", [2]), ("se", [2, 1]), ("ring", [5]), ("se", [9, 9]), ("ring", [3])])
STYLES["b3_head2"] = stack([0xd, 0xd, 0xc, 0xc, 0xa, 0xa], [("ring", [5]), ("se", [3, 2]), ("ring", [1]), ("se", [9, 9]), ("ring", [4])])
STYLES["b3_head3"] = stack([0xd, 0xc, 0xc, 0xb, 0xa, 0xa], [("ring", [4]), ("se", [3, 2]), ("ring", [1]), ("se", [9, 9]), ("ring", [5])])

# ---- the A-button legend (palette 43): white letters, a black ring, a thin dark rim
STYLES["b3_legend"] = stack([0xf, 0xf, 0xf, 0xe, 0xd, 0xc], [("ring", [4, 4]), ("ring", [2]), ("se", [1])])

# ---- the small plates (pages 8 / 9): white letters, a dark ring in the plate's own colour, a thin rim; palette 35 (Pro Yr, dark
# green), 39 (Grad, dark green), 51 / 52 / 53 (the team plates: red, blue, orange)
_WHITE = [0xe, 0xf, 0xf, 0xf, 0xf, 0xd]
STYLES["b3_plate35"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_plate39"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_team51"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_team52"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_team53"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])

# ---- words shown by two parts that stand side by side: the left 128 columns, the rest (ui_type: "<style>~<c0>_<c1>")
for _name in ("b3_title", "b3_head1", "b3_head2"):
    STYLES[_name + "~0_128"] = win(STYLES[_name], 0, 128)
    STYLES[_name + "~128_4096"] = win(STYLES[_name], 128, 4096)
