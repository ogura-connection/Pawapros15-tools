"""Label styles of the ore_sub.arc schedule screen (bank y3_yotei). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import banded, logo, dropped, outlined, grow, shift

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))

def onband(style, band, size, pad=(3, 2), rim=None):
    """`style`'s art set on a filled rectangle of colour `band`, at least `size` (w, h) (the part's band)."""
    def made(ink, base):
        art, b = style(ink, base)
        h, w = art.shape
        bw, bh = max(size[0], w + 2 * pad[0]), max(size[1], h + 2 * pad[1])
        out = np.full((bh, bw), band, np.uint8)
        x, y = (bw - w) // 2, (bh - h) // 2
        sub = out[y:y + h, x:x + w]
        sub[art > 0] = art[art > 0]
        if rim is not None:
            out[0, :] = out[-1, :] = rim
            out[:, 0] = out[:, -1] = rim
        return out, b + y
    return made


STYLES = {
    # big yellow headings with blue ring and white band (palette 21)
    "yhead": logo([10, 11, 12, 13], [8, 7], 9, 3, 2, [5, 4], 2, 2),
    # white letters, dark blue ring, paler ring (stadium names, palette 16)
    "stad": banded([0, 12, 13, 14, 15, 15, 15], [5, 9]),
    # navy place names with a pale ring (palette 36)
    "city": banded([0, 9, 11, 13, 14, 15, 15], [3]),

    # day tags on the plates (palette 48, grey ramp): dark letters in a solid white ring
    "chip": banded([0, 8, 4, 2, 2, 2, 2], [15]),
    "homeblue": banded([0, 10, 11, 12, 13, 13, 13], [3, 5], 2),                 # palette 27
    "pinkband": onband(banded([0, 3, 4, 5, 5, 5, 5], []), 1, (96, 20)),                    # palette 66, 24: pink letters on the pale band
    "greenband": onband(banded([0, 3, 4, 5, 5, 5, 5], []), 1, (48, 20)),                  # palette 67, 25: dark green on light green
    "starter": ui_type.boxed([3, 5, 6, 7, 7, 7, 7], (2, 2), (46, 15), 4),       # palette 63 (55): yellow on brown
    "pitchtag": banded([0, 8, 5, 3, 1, 1, 1], [14]),                                      # palette 62 (8b): red with a white ring
    "rain": banded([0, 9, 10, 12, 13, 14, 15], [3, 4]),                          # palette 45, purple
    "gamew": banded([0, 10, 12, 13, 14, 15, 15], [1]),                           # palette 52, navy
    "bigdrop": dropped([0, 3, 2, 1, 1, 1, 1], [8, 9, 10]),                       # palette 44
    "select": banded([0, 10, 12, 13, 14, 15, 15], [6], 4),                       # palette 75
    "transfer": banded([0, 9, 6, 3, 1, 1, 1], [13]),                             # palette 49, red
    "others": banded([0, 8, 10, 12, 14, 15, 15], [2]),                           # palette 47
    "weekly": banded([0, 6, 4, 3, 2, 1, 1], [15]),                               # palette 126
    "wksun": banded([0, 4, 5, 6, 7, 7, 7], [8, 8]),                              # palette 131
    "wkday": banded([0, 4, 5, 6, 7, 7, 7], [8, 8]),                              # palette 132
    "wksat": banded([0, 3, 4, 5, 6, 7, 7], [8, 8]),                              # palette 133
    "dsun": banded([0, 8, 10, 12, 14, 15, 15], [1]),                             # palettes 54 / 55 / 56
    "dday": banded([0, 8, 10, 12, 14, 15, 15], [1]),
    "dsat": banded([0, 8, 10, 12, 14, 15, 15], [1]),
    "pinkmsg": banded([0, 9, 11, 12, 13, 14, 15], [2], 7),                       # palette 112
    "stopmsg": banded([0, 9, 10, 12, 13, 14, 15], [2], 6),                       # palette 125
    "listnavy": banded([0, 8, 10, 12, 13, 14, 15], [1]),                         # palette 119
    "askhead": banded([0, 9, 11, 13, 14, 14, 14], [1, 3]),                       # palette 116
    "bubble": banded([0, 8, 10, 12, 13, 14, 15], [2]),                           # palette 123
    "fastbtn": banded([0, 11, 10, 9, 9, 9, 9], [4, 6]),                          # palette 105
    "slash": banded([0, 9, 8, 7, 6, 6, 6], [3, 2], 4),                           # palette 26
    "daygame": banded([0, 9, 11, 13, 14, 14, 14], [1]),                           # palette 53 (8d)
}
