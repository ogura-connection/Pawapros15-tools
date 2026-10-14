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


def layered(fill, rings, thresh=3, bottom=None, shadow_fill=None):
    """Letters of palette index `fill` (the lowest row of a stroke at least two high is `bottom` if given) inside
    solid one-pixel rings, first value innermost; corners rounded from the second ring on."""
    def style(ink, base):
        pad = len(rings)
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        masks = [grow(m, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(m.shape, np.uint8)
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        out[m] = fill
        if bottom is not None:
            dn = np.zeros_like(m); dn[:-1] = m[1:]
            up = np.zeros_like(m); up[1:] = m[:-1]
            out[m & ~dn & up] = bottom
        return out, base + pad
    return style


def blob(index, radius=3, thresh=2):
    """A black cut-out of the letters grown by `radius` pixels (the shadow sprites): rounded corners."""
    def style(ink, base):
        pad = radius
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        b = grow(m, 1)
        for _ in range(radius - 1):
            b = grow(b, 1, diagonal=False)
        return np.where(b, index, 0).astype(np.uint8), base + pad
    return style


def cardplate(width, plate=1, core=15, light=5, height=16, thresh=3):
    """A label of the profile card: a plate (index `plate`) at least `width` wide and `height` high with the letters
    (index `core`) centred on it and a one-pixel `light` shadow below and to the right of them."""
    def style(ink, base):
        h, w = ink.shape
        bw, bh = max(width, w + 6), max(height, h + 2)
        x, y = (bw - w) // 2, max((bh - base) // 2, 0)
        bh = max(bh, y + h + 1)
        m = np.zeros((bh, bw), bool)
        m[y:y + h, x:x + w] = ink >= thresh
        out = np.full((bh, bw), plate, np.uint8)
        sh = np.zeros_like(m); sh[1:, 1:] = m[:-1, :-1]
        out[sh & ~m] = light
        out[m] = core
        return out, y + base
    return style


STYLES = {
    "mysr": outlined_pair(5, 14, 7),
    # y3_mys (palette 8, pink ramp): core 14 (e), left/top edge 5, right/bottom edge 7
    "mysl": bevel(5, 14, 7),
    # y3_mym pitching forms (palette 12): fill f (lowest row b), ring 7 (white), halo 4 (mint)
    "mypit": layered(15, [7, 4], bottom=11),
    # batting forms (palette 13): pink fill f (lowest row b) in a black ring (indices 1-7 are all black)
    "mybat": layered(15, [7, 4], bottom=11),
    # the black shadow sprites 2f-3a (palette 38, one colour)
    "myshad": blob(1, 3),
    # the turn-view hints (palette 20): mint fill f, dark blue ring a, mid blue 4, light halo 1
    "myhint": layered(15, [10, 4, 1]),
    # the card labels (palette 7): plate 1, dark letters f, white shadow 5
    "mycard40": cardplate(40), "mycard48": cardplate(48), "mycard64": cardplate(64),
}
