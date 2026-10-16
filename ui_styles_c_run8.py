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


STYLES = {}
STYLES["c8_000"] = ringfill([7, 1, 1, 7, 7, 1], [15], [])
STYLES["c8_001"] = ringfill([6, 9, 9, 10, 6, 6], [3, 3], [3])
STYLES["c8_002"] = ringfill([15, 15, 15, 15, 15, 15], [12, 7], [7])
STYLES["c8_003"] = ringfill([9, 15, 15, 15, 15, 15], [7], [])
