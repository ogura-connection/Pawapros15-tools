"""Label styles of ore_ini.arc (My Life title buttons, team choice, profile screens). See ui_type.py."""
import ui_type
from ui_type import banded, ringed, outlined, shadowed, haloed, logo, captioned, dropped, boxed, plated

STYLES = {
    # y3_myt: "Choose your ..." headings, palette 2 of the mye table: gold letters, blue outline, white band, pale shadow
    "mylhead": logo([11, 10, 9, 8, 7], [3], 1, 15, 15, [12], 2, 1),
}


import os
import numpy as np
import scan_story as _S
import ui_textures as _U


def _orig_page(arc, bank, page):
    """Index page of the untouched file (the saved original once ui_labels has made one)."""
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


_ring = banded([0, 6, 5, 4, 3, 2, 1], [15, 13])
# sprite 00 of y3_c16: the whole heading on one piece 92 wide; sprite 03: three pieces of a bar 408 wide
STYLES["c16_00"] = onbar(_ring, 2, 11, 16, 92, (0, 92))
STYLES["c16_03a"] = onbar(_ring, 2, 11, 16, 408, (0, 128), ("ore_ini.arc", "y3_c16", 3, (0, 56, 32, 80), 6))
STYLES["c16_03b"] = onbar(_ring, 2, 11, 16, 408, (128, 256))
STYLES["c16_03c"] = onbar(_ring, 2, 11, 16, 408, (256, 376))
