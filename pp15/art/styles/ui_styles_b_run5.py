"""Label styles of art run 5, agent B (pena_sub.arc: s3_opc_0, s3_pir00, s3_pih00). Loaded by pp15/art/typeset.py.
Colours are read from the Japanese lettering; every style is crisp (solid rings, fill ramps only)."""
from .ui_styles_ore_ini import ringfill

STYLES = {}

# s3_pih00: pitch names on the orange / cream plates (palette 125: white letters, dark brown ring, pale pink shadow)
STYLES["b5_pitch"] = ringfill([15, 15, 15, 15, 15, 15], [2, 1], [7, 8])

# s3_pir00 / s3_opc_0 buttons: same construction in every hue ramp (index 1 darkest .. 15 white): white letters, dark ring, pale shadow
STYLES["b5_btn"] = ringfill([15, 15, 15, 15, 15, 15], [2, 1], [7, 8])
# small plates (cap < 11): one dark ring only, so the counters of the capitals stay open
STYLES["b5_pitch_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [7])
STYLES["b5_btn_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [7])

# s3_opc_0
from .ui_styles_voice import flat
# values on the coloured plates (palettes 26-28, 38-41, 43: index 1-8 dark ramp, 9 white, 10+ cream): dark letters, white ring, cream shadow
STYLES["b5_val"] = ringfill([2, 1, 1, 1, 1, 2], [9], [10, 11])
STYLES["b5_val_s"] = ringfill([2, 1, 1, 1, 1, 2], [9], [10])
# headings (palette 24 blue / 23 green: white letters, dark ring, pale halo)
STYLES["b5_head"] = ringfill([15, 15, 15, 15, 15, 14], [4, 4, 12])
STYLES["b5_head_s"] = ringfill([15, 15, 15, 15, 15, 14], [4, 12])
# "Other Teams" (palette 9, black letters on the white plate, no ring)
STYLES["b5_black"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
