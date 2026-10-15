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


def bandtext(ramp, rings, shadow=(), top=None):
    """Coloured letters (ramp[ink], ink 0..6) directly inside solid one-pixel rings (innermost first; the first ring
    keeps square corners, the others are rounded) and a cast shadow (near to far). Palettes 16-23 of g3_od (buttons)."""
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
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


# g3_od buttons: letters 8 (the colour of the palette) shading up to e at the edge, white ring, lilac and blue rings,
# a light blue shadow
STYLES["f_btn"] = bandtext([0, 14, 13, 12, 11, 9, 8], [15, 15, 1, 7], [4, 3, 2])
