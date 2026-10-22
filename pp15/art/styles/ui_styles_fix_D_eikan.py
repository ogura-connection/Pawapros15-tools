"""Label styles of the D_eikan art fix (review fixes). New names only (fxD_...). Loaded by pp15/art/typeset.py."""
from .ui_styles_ore_ini import ringfill

STYLES = {}

# sct_a_mk p4_mp small prefecture plates (pal 1): white letters, ONE thin blue ring (was two rings + italic: letters ran together)
STYLES["fxD_mk_small"] = ringfill([1], [3])
