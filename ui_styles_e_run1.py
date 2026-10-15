"""Label styles of art run 1, agent E: scorebook tags, team initials, plates, shift editor (see ui_type.py)."""
import numpy as np
import ui_type
from ui_type import banded, outlined, tight, grow

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def crisp(style, thr=3):
    """The style applied to ink cut at `thr`: every letter pixel full ink, no half tones."""
    def s(ink, base):
        return style(np.where(ink >= thr, 6, 0), base)
    return s


def scm_style(ink, base):
    """Team initials of the scoreboard (g3_scm, palette 0): white letters whose lower edge turns grey, a dark green
    outline that is cast two pixels down and to the right, a green fringe on that shadow."""
    pad = 4
    ink = np.where(ink >= 3, 6, 0)
    h, w = ink.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), int)
    big[pad:pad + h, pad:pad + w] = ink
    letters = big > 0
    ring = grow(letters, 1)
    body = ring | ui_type.shift(ring, 1, 1) | ui_type.shift(ring, 2, 2) | ui_type.shift(ring, 1, 2) | ui_type.shift(ring, 2, 1)
    fringe = (ui_type.shift(body, 1, 0) | ui_type.shift(body, 0, 1) | ui_type.shift(body, 1, 1)) & ~body
    out = np.zeros(big.shape, np.uint8)
    out[fringe] = 6
    out[body] = 7
    out[letters] = 15
    low = letters & ~ui_type.shift(letters, -1, 0)                  # no letter pixel below: the foot of a stroke
    out[low] = 11
    low2 = letters & ~ui_type.shift(letters, -2, 0) & ~low
    out[low2] = 13
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()


STYLES = {
    "e_scm": scm_style,
    # scorebook tags (g3_nk, g3_tij): white letters, navy ring, a blue outer ring (palettes 7-10 share indices 3..f)
    "e_tag": crisp(tight(banded([0, 15, 15, 15, 15, 15, 15], [4, 6]))),
}
