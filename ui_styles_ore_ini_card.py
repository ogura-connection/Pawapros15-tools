"""Label styles of the My Life profile card lists (ore_ini.arc, banks y3_mym / y3_mys). See ui_type.py."""
import numpy as np
import ui_type
from ui_type import grow

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def bevel(top, core, bottom, thresh=3):
    """Letters with a one-pixel bevel like the Japanese list lettering of y3_mys (palette 8): the left and top
    edge of every stroke is `top`, the right and lower edge `bottom`, the rest `core`; no outline, no soft edge."""
    def style(ink, base):
        pad = 1
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        up = np.zeros_like(m); up[1:] = m[:-1]
        left = np.zeros_like(m); left[:, 1:] = m[:, :-1]
        dn = np.zeros_like(m); dn[:-1] = m[1:]
        rt = np.zeros_like(m); rt[:, :-1] = m[:, 1:]
        out = np.zeros(m.shape, np.uint8)
        out[m] = core
        out[m & (~dn | ~rt)] = bottom
        out[m & (~up | ~left)] = top
        return out, base + pad
    return style


def outlined_pair(top, core, bottom, thresh=3):
    """Letters of palette index `core` in a solid one-pixel ring: `top` on the upper-left side of a stroke, `bottom` on
    the lower-right side (the Japanese list lettering of y3_mys is dark outline / pale fill / dark outline)."""
    def style(ink, base):
        pad = 1
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        ring = grow(m, 1) & ~m
        dn = np.zeros_like(m); dn[:-1] = m[1:]          # letter below
        rt = np.zeros_like(m); rt[:, :-1] = m[:, 1:]    # letter to the right
        out = np.zeros(m.shape, np.uint8)
        out[ring] = bottom
        out[ring & (dn | rt)] = top
        out[m] = core
        return out, base + pad
    return style


STYLES = {
    "mysr": outlined_pair(5, 14, 7),
    # y3_mys (palette 8, pink ramp): core 14 (e), left/top edge 5, right/bottom edge 7
    "mysl": bevel(5, 14, 7),
}
