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
STYLES["c8_000"] = ringfill([15, 15, 3, 2, 2, 15], [13, 6], [10])
STYLES["c8_001"] = ringfill([8, 8, 8, 8, 10, 10], [12], [1])
STYLES["c8_002"] = ringfill([2, 2, 2, 10, 2, 2], [1, 1], [8])
STYLES["c8_003"] = ringfill([12, 12, 12, 10, 10, 10], [13, 1], [8])
STYLES["c8_004"] = ringfill([11, 11, 10, 11, 11, 10], [12, 1], [7])
STYLES["c8_005"] = ringfill([1, 1, 1, 10, 1, 1], [8, 8], [7])
STYLES["c8_006"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [])
STYLES["c8_007"] = ringfill([11, 11, 10, 11, 11, 10], [12, 1], [8])
STYLES["c8_008"] = ringfill([11, 10, 10, 11, 11, 10], [12, 1], [])
STYLES["c8_009"] = ringfill([1, 1, 1, 1, 1, 1], [5], [])
STYLES["c8_010"] = ringfill([3, 3, 3, 9, 3, 3], [2, 12], [1])
STYLES["c8_011"] = ringfill([1, 1, 1, 1, 1, 1], [13], [])
STYLES["c8_sil_c8_002_10"] = sil("c8_002", 10)
