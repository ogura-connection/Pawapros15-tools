"""Label styles of art run 10, agent F (scs_rens.arc z3_smr_0 icons, Super Ability GET!, Hot Blood). Keep importable."""
import ui_type
from ui_styles_ore_ini import ringfill
from ui_styles_a_run9 import bandeco

STYLES = {}
STYLES["f10_ico"] = ringfill([15, 15, 15, 15, 15, 15], [3], [3])
# yellow lettering (top orange to foot lime), dark ring, olive extrusion, cream rings: the Japanese GET wipe logo
STYLES["f10_sup"] = bandeco([11, 10, 10, 9, 8, 8], [1, 2], [3, 4, 5, 6], [15, 14])
# 熱血: yellow to red flame fill, dark red ring, white / pink rings, dark shadow
STYLES["f10_hot"] = ringfill([10, 9, 8, 7, 6, 5], [2, 15, 13, 11], [1, 1, 1])
