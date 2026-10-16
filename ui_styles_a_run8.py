"""Label styles of art run 8, agent A (rec_room.arc: pages of g3_gkn, g3_mvp, g3_nen). Read from the Japanese lettering
(Bank.style_from with the face indices given, rings checked on index dumps). Keep importable."""
import ui_type
from ui_styles_ore_ini import ringfill

STYLES = {}

STYLES["a8_gkn"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [6])
STYLES["a8_gkn_s"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 9], [15, 15])
STYLES["a8_gkn_6f"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15])
STYLES["a8_gkn_71"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15])
STYLES["a8_mvp"] = ringfill([15, 15, 15, 15, 15, 15], [9, 1, 1, 5])
STYLES["a8_mvp_ab"] = ringfill([15, 15, 15, 15, 15, 15], [9, 1, 1, 5])
STYLES["a8_nen01"] = ringfill([5, 5, 6, 7, 7, 7], [4, 15], [15, 2])
STYLES["a8_nen02"] = ringfill([5, 5, 6, 6, 7, 7], [4, 15], [15, 2])
STYLES["a8_nen03"] = ringfill([8, 8, 8, 8, 8, 8], [4, 15], [15, 2])
STYLES["a8_nen04"] = ringfill([12, 12, 11, 10, 7, 9], [4, 15, 15], [15])
STYLES["a8_nen05"] = ringfill([1, 1, 1, 1, 1, 1], [6])
STYLES["a8_nen17"] = ringfill([8, 8, 8, 8, 8, 8], [3, 1, 5], [15, 13])
STYLES["a8_nen18"] = ringfill([8, 8, 8, 8, 8, 8], [3, 1, 5], [15, 13])
STYLES["a8_nen19"] = ringfill([8, 8, 8, 8, 8, 8], [12, 13, 13, 13, 13, 13, 13], [1])
