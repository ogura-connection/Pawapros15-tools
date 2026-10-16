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
STYLES["c8_000"] = ringfill([14, 14, 12, 12, 11, 11], [4, 1], [9])
STYLES["c8_001"] = ringfill([4, 4, 3, 4, 4, 4], [15], [14])
STYLES["c8_002"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15])
STYLES["c8_003"] = ringfill([7, 7, 7, 7, 8, 8], [1, 1], [14])
STYLES["c8_004"] = ringfill([11, 11, 7, 6, 5, 5], [1, 1], [8])
STYLES["c8_005"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [1])
STYLES["c8_006"] = ringfill([15, 15, 15, 15, 15, 15], [9, 1], [10])
STYLES["c8_007"] = ringfill([15, 15, 15, 15, 15, 15], [10, 1], [])
STYLES["c8_008"] = ringfill([2, 15, 15, 15, 15, 15], [1], [])
