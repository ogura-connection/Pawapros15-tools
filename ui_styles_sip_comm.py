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

    def style(ink, base):
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
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


STYLES["sip_card"] = sipcard()
