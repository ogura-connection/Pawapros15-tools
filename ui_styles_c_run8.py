"""Label styles of art run 8, agent C (rec_room.arc part 3), read from the Japanese lettering by run8/C/c8_lib.py."""
import numpy as np
from ui_styles_ore_ini import ringfill


def flat(c):
    def style(ink, base):
        out = np.where(ink >= 2, c, 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


def sil(front, c):
    def style(ink, base):
        out, bb = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), bb
    return style


def comp(inner, blob, h, w, cx, cy):
    import zlib, base64
    bg = np.frombuffer(zlib.decompress(base64.b64decode(blob)), np.uint8).reshape(h, w).copy()
    def style(ink, base):
        art, b = STYLES[inner](ink, base)
        out = bg.copy()
        ah, aw = art.shape
        top = max(0, min(h - ah, int(round(cy - ah / 2.0)))); left = max(0, min(w - aw, int(round(cx - aw / 2.0))))
        sl = out[top:top + ah, left:left + aw]
        sl[art > 0] = art[art > 0]
        return out, b + top
    return style


def win(style, c0, c1):
    def f(ink, base):
        out, b = style(ink, base)
        return out[:, c0:c1], b
    return f


STYLES = {}
STYLES["c8_000"] = ringfill([7, 1, 1, 7, 7, 1], [15], [])
STYLES["c8_001"] = ringfill([7, 1, 1, 1, 7, 1], [4, 15], [])
STYLES["c8_002"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15])
STYLES["c8_003"] = ringfill([6, 9, 9, 10, 6, 6], [3, 3], [3])
STYLES["c8_004"] = ringfill([15, 15, 15, 15, 15, 15], [12, 7], [7])
STYLES["c8_005"] = ringfill([9, 15, 15, 15, 15, 15], [7], [])
