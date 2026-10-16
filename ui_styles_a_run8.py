"""Label styles of art run 8, agent A (rec_room.arc: pages of g3_gkn, g3_mvp, g3_nen). Read from the Japanese lettering with Bank.style_from. Keep importable."""
import ui_type
from ui_styles_ore_ini import ringfill

STYLES = {}

STYLES["a8_gkn"] = ringfill([1, 15, 15, 15, 15, 15], [11])
STYLES["a8_gkn_s"] = ringfill([8, 1, 1, 1, 1, 1], [9], [15, 15])
STYLES["a8_gkn_6f"] = ringfill([1, 8, 8, 8, 8, 1], [7])
STYLES["a8_gkn_71"] = ringfill([1, 8, 8, 8, 8, 1], [2], [15, 15])
STYLES["a8_mvp"] = ringfill([1, 1, 15, 15, 1, 15], [9])
STYLES["a8_mvp_ab"] = ringfill([1, 1, 15, 1, 15, 1], [5])
STYLES["a8_nen01"] = ringfill([15, 15, 15, 7, 15, 9], [2])
STYLES["a8_nen02"] = ringfill([15, 15, 15, 7, 15, 15], [2])
STYLES["a8_nen03"] = ringfill([15, 15, 15, 15, 15, 15], [6])
STYLES["a8_nen04"] = ringfill([15, 15, 15, 15, 15, 15], [6])
STYLES["a8_nen05"] = ringfill([1, 1, 1, 1, 1, 1], [6])
STYLES["a8_nen17"] = ringfill([1, 1, 8, 1, 8, 1], [3], [15])
STYLES["a8_nen18"] = ringfill([5, 1, 8, 1, 8, 1], [1], [15, 13])
STYLES["a8_nen19"] = ringfill([13, 13, 8, 8, 13, 13], [12, 10])
