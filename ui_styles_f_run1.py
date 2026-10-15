"""Label styles of art run 1, agent F (order.arc, vs_st.arc). Loaded by ui_type.py (every ui_styles_*.py is).
Colours read from the Japanese lettering of each palette with _work/ui_pages/run1/F/work/roles2.py / probe.py."""
import numpy as np
import ui_type
from ui_type import grow, shift

STYLES = {}


def cast(mask, shadow):
    """The shadow of `mask`: colour shadow[k-1] at k steps down and to the right (near to far), only outside the mask."""
    out = np.zeros(mask.shape, np.uint8)
    for k in range(len(shadow), 0, -1):
        out[shift(mask, k, k) | shift(mask, k, k - 1) | shift(mask, k - 1, k)] = shadow[k - 1]
    return out


def trimmed(out, base):
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


def bandtext(ramp, rings, shadow=()):
    """Coloured letters (ramp[ink], ink 0..6) directly inside solid one-pixel rings (innermost first; the first ring
    keeps square corners, the others are rounded) and a cast shadow (near to far)."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings) + len(shadow) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = cast(masks[-1], shadow)
        for m, v in zip(masks[::-1], rings[::-1]):
            out[m] = v
        out[letters] = ramp[big[letters]]
        return trimmed(out, base + pad)
    return style


def onoval(oval, rim, ring, shadow, ramp, height=13, margin=6, ends=(4, 2, 1)):
    """White letters on a dark oval (a stadium shape `height` rows high, the ends cut in by `ends` pixels on the first
    rows, `margin` pixels longer than the word each side) with a lighter `rim` row round it, a one-pixel `ring` round
    the letters (the colour of the oval: letters that stand out of it keep an edge) and the shadow of what hangs out
    of it. The word headings of the bars in g3_od: the oval replaces the dark middle of the bar, which the heading's
    part used to carry."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pd = margin + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * 4 + 4, w + 2 * pd), int)
        big[4:4 + h, pd:pd + w] = ink
        L = big > 0
        B = grow(L, 1)
        cy = 4 + base // 2
        top = cy - height // 2
        ov = np.zeros(L.shape, bool)
        for y in range(top, top + height):
            d = min(y - top, top + height - 1 - y)
            inset = ends[d] if d < len(ends) else 0
            ov[y, pd - margin + inset:pd + w + margin - inset] = True
        rimm = grow(ov, 1, diagonal=False) & ~ov
        out = cast(B, shadow)
        out[(out > 0) & ov] = 0
        out[rimm] = rim
        out[ov] = oval
        out[B & ~ov] = ring
        out[L] = ramp[big[L]]
        return trimmed(out, base + 4)
    return style


# g3_od buttons (palettes 16-23): letters in the colour of the palette (8 .. e, e the light edge), a white ring, a
# blue ring, a light blue shadow
STYLES["f_btn"] = bandtext([0, 12, 10, 9, 8, 8, 8], [15, 7], [4, 3])
# g3_od bars (palettes 32-36): white letters on the dark oval (1) with a lighter rim (4); a light blue shadow (13, 12)
STYLES["f_bar"] = onoval(1, 4, 1, [13, 12], [0, 9, 9, 8, 8, 8, 8])
