"""Label styles of art run 8, agent C (rec_room.arc part 3), read from the Japanese lettering by run8/C/c8_lib.py."""
import numpy as np
from ui_styles_ore_ini import ringfill


def flat(c):
    def style(ink, base):
        out = np.where(ink >= 2, c, 0).astype(np.uint8)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


STYLES = {}
STYLES["c8_000"] = ringfill([1, 15, 1, 15, 15, 1], [2, 10], [10])
STYLES["c8_001"] = ringfill([15, 15, 15, 15, 15, 15], [10, 1], [])
STYLES["c8_002"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [])
