"""Label styles of art run 1, agent D (gameplay.arc: defensive shift panel, record banners, team names, position names,
turning / attack / defense point, substitution headings, score challenge, standings, rankings, hero banners,
defence practice). Loaded by ui_type.py. Colours are read from the Japanese lettering of each palette
(_work/ui_pages/run1/D/hist.py, roles.py)."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# h3_aps_0: Def. Shift title (palette 14): orange letters in two black rings
STYLES["d_aps_title"] = ringfill([0xf], [1, 1])
# Outfield / Infield (palettes 50, 51): lavender letters, a blue-lavender ring, black shadow
STYLES["d_aps_side"] = ringfill([0xf], [6], [3, 2])
# the rows of shift choices and the Bunt Shift line (palette 52): navy letters in light rings
STYLES["d_aps_row"] = ringfill([4], [0xe, 0xa])
STYLES["d_aps_row1"] = ringfill([4], [0xe])
