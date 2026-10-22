"""Label styles of ore_ini.arc banks y3_myk (prefectures / background on the My Life card) and y3_kzo (wife and children
settings). See pp15/art/typeset.py."""
import numpy as np
from pp15.art import typeset as ui_type
from pp15.art.typeset import grow

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def ringed(fill, rings, shadow=None, off=(2, 2), bottom=None, thresh=3):
    """Letters of palette index `fill` (the lowest row of a stroke at least two high is `bottom` if given) inside
    solid one-pixel rings (first value innermost), plus a solid drop shadow `shadow` of the outer ring `off` pixels
    down and right. No soft edges."""
    def style(ink, base):
        pad = len(rings) + (max(off) if shadow is not None else 0)
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        masks = [grow(m, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(m.shape, np.uint8)
        if shadow is not None:
            sh = np.zeros_like(m)
            for k in range(1, max(off) + 1):          # the shadow is the outline slid down-right, no gaps
                dy, dx = min(k, off[0]), min(k, off[1])
                sh[dy:, dx:] |= masks[-1][:m.shape[0] - dy, :m.shape[1] - dx]
            out[sh] = shadow
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        out[m] = fill
        if bottom is not None:
            dn = np.zeros_like(m); dn[:-1] = m[1:]
            up = np.zeros_like(m); up[1:] = m[:-1]
            out[m & ~dn & up] = bottom
        return out, base + pad
    return style


STYLES = {
    # y3_myk (palette 23): blue letters, white ring, pale blue ring, blue-grey shadow to the lower right
    "mykblue": ringed(5, [14, 11], shadow=3, off=(2, 2)),
    # y3_kzo list words (palette 20): mint letters, dark teal ring, grey-teal ring, blue-grey shadow
    "kzomint": ringed(15, [11, 6], shadow=4, off=(2, 2), bottom=12),
    # headings (pink palette 7 / green palette 6): light fill, dark ring (two pixels), white ring, grey shadow
    "kzohead_p": ringed(8, [14, 14, 6], shadow=2, off=(1, 1)),
    "kzohead_g": ringed(8, [14, 14, 6], shadow=2, off=(1, 1)),
    # plate words (palette 10): white letters in a blue ring
    "kzoplate": ringed(15, [1, 5], bottom=11),
    # small units of the birth line (palette 3): blue letters, white ring, cyan ring, teal shadow
    "kzounit": ringed(15, [8, 6], shadow=1, off=(1, 1)),
}
