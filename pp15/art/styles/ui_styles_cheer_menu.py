"""Cheer Song menu (chrsong.arc r3_okf): white bold letters with the dark-blue ring, read from the Japanese buttons."""
from .ui_styles_ore_ini import ringfill
STYLES = {}
STYLES["cheer_title"] = ringfill([12, 12, 13, 14, 15, 15], [9, 9, 4, 4], [7, 7, 3])
STYLES["cheer_b03"] = ringfill([15]*6, [9, 9, 3, 3], [3])
STYLES["cheer_b04"] = ringfill([15]*6, [9, 9, 4, 4], [3])
STYLES["cheer_b05"] = ringfill([15]*6, [9, 9, 4, 1], [3])
STYLES["cheer_b39"] = ringfill([15]*6, [9, 8, 5], [3])
STYLES["cheer_b3a"] = ringfill([15]*6, [9, 9, 4, 1], [3])
