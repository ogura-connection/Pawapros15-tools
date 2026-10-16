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
STYLES["c8_000"] = ringfill([12, 12, 11, 10, 11, 10], [1, 14], [8])
STYLES["c8_001"] = ringfill([12, 12, 11, 10, 11, 10], [8], [8])
STYLES["c8_002"] = flat(10)
STYLES["c8_003"] = ringfill([2, 2, 12, 11, 2, 2], [8], [])
STYLES["c8_004"] = ringfill([12, 12, 12, 12, 12, 12], [1], [1])
STYLES["c8_005"] = flat(12)
STYLES["c8_006"] = ringfill([12, 12, 12, 10, 10, 10], [8], [])
STYLES["c8_sil_c8_000_10"] = sil("c8_000", 10)
STYLES["c8_sil_c8_000_12"] = sil("c8_000", 12)
