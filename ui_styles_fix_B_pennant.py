"""Label styles of the review fix, area B (pennant). New names fxB_*; loaded by ui_type.py. Keep importable at every moment."""
from ui_styles_ore_ini import ringfill
import ui_type
import numpy as np

STYLES = {}

# b5_pen00 00-08 (Pennant record captions): the Japanese has dark outer outline, white inline, a mid ring and a shadow.
# fill = the fill of the e5_b5_pen00_NN style; rings innermost first, read from the bottom edge of the Japanese lettering.
_PEN = {
    "00": ([180, 93, 180, 241, 239, 177], [25, 246, 127, 211, 211], [34]),
    "01": ([177, 182, 180, 184, 239, 176], [25, 246, 127, 211, 211], [34]),
    "02": ([59, 61, 185, 186, 209, 60], [108, 70, 34, 20], [243]),
    "03": ([59, 61, 184, 184, 210, 60], [108, 70, 34, 20], [243]),
    "04": ([173, 119, 179, 208, 246, 109], [21, 177, 145, 140, 140], [28]),
    "05": ([171, 115, 179, 248, 245, 107], [21, 177, 145, 140, 140], [28]),
    "06": ([107, 64, 64, 167, 164, 138], [20, 197, 84, 222, 222], [24]),
    "07": ([131, 132, 176, 176, 208, 131], [18, 255, 49, 51, 51], [94]),
    "08": ([131, 129, 176, 177, 205, 131], [18, 255, 49, 51, 51], [94]),
}
for _k, (_f, _r, _s) in _PEN.items():
    STYLES["fxB_pen00_" + _k] = ringfill(_f, _r, _s)

# pena_ini s3_ptz00 04 / 06 / 0b (buttons): fill, inner dark ring, white rings, outer ring, read from the Japanese lettering.
STYLES["fxB_ptz_04"] = ringfill([234, 230, 212, 182, 174, 180], [6, 255, 24], [153])
STYLES["fxB_ptz_06"] = ringfill([249, 249, 242, 233, 222, 201], [2, 255, 24], [185])
STYLES["fxB_ptz_0b"] = ringfill([232, 232, 232, 200, 200, 232], [30, 255], [56])

# rec_room g2_km#2 (bats/throws R/R..., prefectures): black letters with the soft brown edge the Japanese has, on the orange plate
from ui_styles_a_run1 import flat as _flat
STYLES["fxB_km_text"] = _flat([0, 13, 13, 12, 1, 1, 1], cut=2)
