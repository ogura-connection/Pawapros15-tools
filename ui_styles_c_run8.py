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
STYLES["c8_000"] = ringfill([15, 15, 15, 15, 15, 15], [8], [])
STYLES["c8_001"] = ringfill([11, 10, 11, 9, 8, 9], [4], [])
STYLES["c8_002"] = ringfill([8, 8, 8, 8, 8, 8], [1], [])
STYLES["c8_003"] = flat(13)
STYLES["c8_004"] = ringfill([14, 14, 14, 15, 15, 15], [11], [11])
STYLES["c8_005"] = ringfill([6, 6, 3, 2, 2, 1], [12, 15], [])
STYLES["c8_006"] = ringfill([8, 8, 8, 8, 8, 8], [10, 12], [1])
STYLES["c8_007"] = ringfill([8, 15, 14, 10, 8, 8], [1, 1], [])
STYLES["c8_008"] = ringfill([8, 15, 1, 1, 8, 1], [3], [])
STYLES["c8_009"] = ringfill([13, 12, 12, 12, 13, 13], [1, 1], [])
STYLES["c8_010"] = ringfill([12, 10, 10, 9, 12, 12], [15, 3], [])
STYLES["c8_011"] = ringfill([13, 13, 13, 13, 13, 13], [1], [])
STYLES["c8_012"] = ringfill([11, 15, 12, 12, 15, 15], [6, 1], [])
STYLES["c8_013"] = ringfill([4, 9, 9, 7, 6, 6], [13, 15], [])
STYLES["c8_014"] = ringfill([9, 9, 14, 12, 11, 9], [4, 1], [])
STYLES["c8_015"] = ringfill([8, 8, 8, 8, 8, 8], [4], [15])
STYLES["c8_016"] = ringfill([8, 8, 8, 8, 8, 8], [3, 1], [15])
STYLES["c8_017"] = ringfill([9, 9, 9, 7, 8, 8], [1, 1], [])
STYLES["c8_018"] = ringfill([13, 13, 7, 6, 5, 5], [1, 1], [])
STYLES["c8_019"] = ringfill([15, 15, 15, 15, 15, 15], [10, 1], [1])
STYLES["c8_020"] = ringfill([1, 15, 1, 15, 15, 1], [2, 10], [10])
STYLES["c8_021"] = ringfill([15, 15, 15, 15, 15, 15], [10, 1], [])
STYLES["c8_022"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [])
