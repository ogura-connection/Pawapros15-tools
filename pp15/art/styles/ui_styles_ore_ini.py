"""Label styles of ore_ini.arc (My Life title buttons, team choice, profile screens). See pp15/art/typeset.py."""
from pp15.art import typeset as ui_type
from pp15.art.typeset import banded, ringed, outlined, shadowed, haloed, logo, captioned, dropped, boxed, plated

STYLES = {
    # y3_myt: "Choose your ..." headings, palette 2 of the mye table: gold letters, blue outline, white band, pale shadow
    "mylhead": logo([11, 10, 9, 8, 7], [3], 1, 15, 15, [12], 2, 1),
}


import os
import numpy as np
from pp15.script import scan as _S
from pp15.art import textures as _U


def _orig_page(arc, bank, page):
    """Index page of the untouched file (the saved original once pp15/art/labels.py has made one)."""
    path = os.path.join(_U.ORIG_ARC_DIR, arc)
    if not os.path.exists(path):
        path = os.path.join(_S.DATA_FILES, arc)
    d = open(path, "rb").read()
    b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == bank)
    return _U.decode_indices(d, *b["pages"][page])


def onbar(inner, nrings, bar, rows, canvas, window, cap=None):
    """A style for lettering on a flat bar (y3_c16, the team-choice headings). The word is drawn by `inner`, centred
    on a canvas `canvas` wide and `rows` (top row, last row) of bar high, over a bar of palette index `bar`; only the
    columns `window` (c0, c1) are returned, so one heading can be shared out over several parts. `cap` = (arc, bank,
    page, rect, row0) puts the original rounded end of the bar in the first columns."""
    def style(ink, base):
        art, b = inner(ink, base)
        h = rows + 1
        top = 1                                                  # bar rows 1 .. h - 1
        capline = b - 1 + nrings                                 # last row of the capitals with their rings
        first = np.nonzero(art.any(1))[0][0]
        t = top + ((h - top) - (capline - first + 1)) // 2 - first
        full = np.zeros((h, canvas), np.uint8)
        left = canvas // 2 - art.shape[1] // 2
        full[top:, :] = bar
        if cap:
            arc, bank, page, (x0, y0, x1, y1), r0 = cap
            full[:, : x1 - x0] = _orig_page(arc, bank, page)[y0 + r0:y0 + r0 + h, x0:x1]
        ys, xs = np.nonzero(art)
        for y, x in zip(ys, xs):
            if 0 <= t + y < h:
                full[t + y, left + x] = art[y, x]
        return full[:, window[0]:window[1]], t + b
    return style


_ring = banded([0, 6, 5, 4, 3, 2, 1], [15])
# sprite 00 of y3_c16: the whole heading on one piece 92 wide; sprite 03: three pieces of a bar 408 wide
STYLES["c16_00"] = onbar(_ring, 1, 11, 16, 116, (0, 116))
STYLES["c16_03a"] = onbar(_ring, 1, 11, 16, 408, (0, 128), ("ore_ini.arc", "y3_c16", 3, (0, 56, 32, 80), 6))
STYLES["c16_03b"] = onbar(_ring, 1, 11, 16, 408, (128, 256))
STYLES["c16_03c"] = onbar(_ring, 1, 11, 16, 408, (256, 376))


def copyof(arc, bank, page, rect, r0, r1):
    """A style that ignores its word and returns the rows r0..r1 of a rectangle of the original page (a plate end that has to stay as it is)."""
    def style(ink, base):
        x0, y0, x1, y1 = rect
        return _orig_page(arc, bank, page)[y0 + r0:y0 + r1 + 1, x0:x1].copy(), 0
    return style


STYLES["c16_cap"] = copyof("ore_ini.arc", "y3_c16", 3, (0, 56, 32, 80), 6, 22)


def gloss(fill, soft, outline, white, rim, shadow, band=2, thick=1, inner=None):
    """Like pp15.art.typeset.logo (letters filled top to foot from `fill`, an `outline`, a `white` band with a `rim`, a cast `shadow`),
    but the soft edge of a letter runs outline -> soft -> fill and never leaves a hole."""
    from pp15.art.typeset import grow, shift
    fill = list(fill)

    def style(ink, base):
        pad = band + 1 + thick + len(shadow)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(letters, 1)
        for _ in range(thick - 1):
            dark = grow(dark, 1, diagonal=False)
        plate = grow(grow(dark, band - 1), 1, diagonal=False) if band > 1 else grow(dark, 1, diagonal=False)
        edge = grow(plate, 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(edge, k, k) | shift(edge, k, k - 1) | shift(edge, k - 1, k)] = shadow[k - 1]
        out[edge] = rim
        out[plate] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        ring = np.array([outline] + list(soft))
        lvl = np.rint((big - 1).clip(0, 4) * len(ring) / 4.0).astype(int)        # 1 .. 5 -> outline .. fill
        low = np.where(lvl >= len(ring), row, ring[np.minimum(lvl, len(ring) - 1)])
        out[letters] = np.where(big >= 5, row, low)[letters]
        return out, base + pad
    return style


_YEL = [182, 180, 178, 177, 175, 173, 171, 170, 168, 162, 164]
_SAL = [140, 143, 144, 147, 148, 151, 153, 155, 157, 158, 160]
_PNK = [222, 223, 224, 225, 227, 231, 232, 233, 235, 237, 238, 240]
# y4_t256 (8-bit page, 256 colours): gradient letters, navy outline, white band, cyan rim
STYLES["mlbtn_y"] = gloss(_YEL, [29], 82, 15, 9, [], 3, 2)
STYLES["mlbtn_s"] = gloss(_SAL, [29], 82, 15, 9, [], 3, 2)
STYLES["mlbtn_p"] = gloss(_PNK, [26], 82, 15, 9, [], 3, 2)


def ringfill(fill, rings, shadow=(), edge=3):
    """Letters filled top to foot from `fill` (a pixel of the soft edge below ink level `edge` takes the first ring's colour),
    inside solid one-pixel `rings` (innermost first, rounded corners from the second ring on) and a `shadow` (near to far)
    cast down and to the right of the last ring."""
    from pp15.art.typeset import grow, shift
    fill = list(fill)

    def style(ink, base):
        pad = len(rings) + len(shadow) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(masks[-1], k, k) | shift(masks[-1], k, k - 1) | shift(masks[-1], k - 1, k)] = shadow[k - 1]
        for m, v in zip(masks[::-1], rings[::-1]):
            out[m] = v
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        out[letters] = np.where(big >= edge, row, rings[0])[letters]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


# y3_c256 (8-bit): the team-choice banner, orange to pink letters, white / blue / light blue / navy rings, purple shadow
_BAN = [205, 206, 209, 207, 211, 210, 214, 213, 217, 221, 216, 220, 226, 225, 230, 234, 233, 243]
STYLES["mlban"] = ringfill(_BAN, [255, 255, 128, 160, 160, 131], [180, 180])
