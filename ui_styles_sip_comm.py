"""Label style of sip_comm.arc bank r4_smo: the inning card of the Eikan Nine practice game (bold blue italic type, white
face, blue band, dark bottom / right shading, light outer rim). Palette 3 is the coloured layer, palette 4 a black copy
three pixels right and six down (the sprite's "layers": 2). Hard edges only: the face is the ink at level 3 or more.
Indices of palette 3: 15 white, 9..14 light-blue face shading, 1 / 3 dark blue, 4 blue, 5..7 lighter blue, 8 rim."""
import numpy as np
from ui_type import grow, shift

STYLES = {}

TOPLEFT = [4, 4, 4, 5, 7, 8, 8]       # rings (inner to outer) where the face lies below / right of the pixel
BOTRIGHT = [1, 3, 4, 4, 5, 8, 8]      # rings where the face lies above / left of the pixel


def sipcard(tl=TOPLEFT, br=BOTRIGHT):
    n = max(len(tl), len(br))

    def raw(ink, base):
        """The art with `n + 1` clear pixels round it (not trimmed): (art, baseline row, pad)."""
        pad = n + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        F = big >= 3
        masks = [F, grow(F, 1)]
        for _ in range(n - 1):
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        for k in range(1, n + 1):
            L = masks[k] & ~masks[k - 1]
            inner = masks[k - 1]
            up = np.zeros_like(inner); up[1:] = inner[:-1]               # the nearer pixel lies above
            left = np.zeros_like(inner); left[:, 1:] = inner[:, :-1]     # ... or to the left
            dark = L & (up | left)
            if k <= len(br): out[dark] = br[k - 1]
            if k <= len(tl): out[L & ~dark] = tl[k - 1]
            if k > len(br): out[dark] = tl[min(k, len(tl)) - 1]
            if k > len(tl): out[L & ~dark] = br[min(k, len(br)) - 1]
        # the face: white, with a light-blue shade on its top, left and bottom edges
        face = np.full(big.shape, 15, np.uint8)
        above = np.zeros_like(F); above[1:] = F[:-1]
        below = np.zeros_like(F); below[:-1] = F[1:]
        lft = np.zeros_like(F); lft[:, 1:] = F[:, :-1]
        face[F & ~below] = 10
        face[F & ~above] = 12
        face[F & ~lft & above & below] = 13
        out[F] = face[F]
        return out, base + pad, pad

    def style(ink, base):
        out, b, pad = raw(ink, base)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], b - ys.min()

    def trim_rows(a, base):
        ys = np.nonzero(a.any(1))[0]
        return a[ys.min():ys.max() + 1], base - ys.min()

    def chain(inks, gap=4, margin=n + 2):
        """([(art, baseline row, x offset)], width) of a label set from one or two words. For two words the whole label is
        rendered and cut into three pieces: left of x = (end of the first word + gap) - margin, a middle (the join, which
        depends on both words) and the rest. The rings reach n pixels from a letter, so the left piece is the same for every
        label that starts with the same first word, and the right piece for every label that ends with the same second."""
        if len(inks) == 1:
            art, b = style(*inks[0])
            return [(art, b, 0)], art.shape[1]
        (A, ab), (B, bb) = inks
        up = max(ab, bb)
        down = max(A.shape[0] - ab, B.shape[0] - bb)
        canvas = np.zeros((up + down, A.shape[1] + gap + B.shape[1]), int)
        canvas[up - ab:up - ab + A.shape[0], :A.shape[1]] = A
        canvas[up - bb:up - bb + B.shape[0], A.shape[1] + gap:] = B
        out, b, pad = raw(canvas, up)
        xs = np.nonzero(out.any(0))[0]
        lo, hi = xs.min(), xs.max() + 1
        c1 = pad + A.shape[1] + gap - margin
        c2 = pad + A.shape[1] + margin
        if not lo < c1 < c2 < hi:
            raise ValueError("cannot cut %d + %d columns" % (A.shape[1], B.shape[1]))
        res = []
        for a, z in ((lo, c1), (c1, c2), (c2, hi)):
            art, base = trim_rows(out[:, a:z], b)
            res.append((art, base, a - lo))
        return res, hi - lo

    style.chain = chain
    style.raw = raw
    return style


STYLES["sip_card"] = sipcard()                                                 # 7-pixel rings, as the Japanese lettering
STYLES["sip_small"] = sipcard([4, 4, 5, 8, 8], [1, 3, 4, 8, 8])                # 5-pixel rings, the situation line
