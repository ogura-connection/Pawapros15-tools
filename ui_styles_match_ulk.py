"""Label styles of main_prg.arc h3_ulk_0 (the match: inning, home-run number, distance, replay banners).
Loaded by ui_type.py. banner(fill, inner, ext, outer): crisp letters (ink >= cut of 6) with a fill that steps from
the first colour at the top to the last at the foot, solid one-pixel rings `inner` (against the letters, inside
out), a solid extrusion `ext` (one colour a step, down and to the right of the letters and their rings), and
solid rings `outer` round the whole."""
import numpy as np
import ui_type
from ui_type import grow, shift

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def banner(fill, inner, ext=(), outer=(), cut=3):
    def style(ink, base):
        pad = len(inner) + len(ext) + len(outer) + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big >= cut
        out = np.zeros(big.shape, np.uint8)
        masks = []
        m = letters
        for k in range(len(inner)):
            m = grow(m, 1, diagonal=(k == 0))
            masks.append(m)
        body = masks[-1] if masks else letters
        sil = body.copy()
        steps = []
        for k in range(1, len(ext) + 1):
            s = shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
            steps.append(s)
            sil |= s
        rings = []
        m = sil
        for k in range(len(outer)):
            m = grow(m, 1, diagonal=False)
            rings.append(m)
        for mk, v in zip(rings[::-1], list(outer)[::-1]):
            out[mk] = v
        for s, v in zip(steps[::-1], list(ext)[::-1]):
            out[s] = v
        for mk, v in zip(masks[::-1], list(inner)[::-1]):
            out[mk] = v
        ys = np.nonzero(letters.any(1))[0]
        y0, y1 = ys.min(), ys.max() + 1
        for y in range(y0, y1):
            row = letters[y]
            out[y][row] = fill[min(len(fill) - 1, (y - y0) * len(fill) // (y1 - y0))]
        yy = np.nonzero(out.any(1))[0]
        xx = np.nonzero(out.any(0))[0]
        r0, r1, c0, c1 = yy.min(), yy.max() + 1, xx.min(), xx.max() + 1
        return out[r0:r1, c0:c1], base + pad - r0
    return style


STYLES = {
    # inning, home-run number, distance (pal 14): white, blue ring, deep blue shadow, as the digits beside them
    "ulk_inn": banner([15], [6], [5, 2]),
    # the big home-run number plate (pal 160): white, blue ring, bright blue extrusion
    "ulk_hr": banner([15], [6], [4, 4, 4, 4]),
    # Replay of the bar (pal 38): yellow-to-orange, dark olive ring, teal shadow
    "ulk_a": banner([14, 14, 13, 12, 11, 11], [4, 4], [2, 1]),
    # the replay tags (pal 125): yellow, brown rings, dark brown extrusion
    "ulk_b": banner([15, 15, 14, 13], [5, 6], [6, 6]),
    # the replay banners (pal 158): gold, navy outline and extrusion, white ring
    "ulk_c": banner([15, 14, 13, 12], [8, 8], [8, 8, 8], [7, 7]),
}
