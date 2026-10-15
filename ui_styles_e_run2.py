"""Label styles of art run 2, agent E (sn_abiup.arc, scs_load.arc, scs_make.arc, scs_rens.arc, scs_b_ed.arc).
Loaded by ui_type.py (every ui_styles_*.py is). Colours read from the Japanese lettering with
_work/ui_pages/tools/roles.py."""
import numpy as np
import ui_type
from ui_type import grow, shift

STYLES = {}
ui_type.TTF.setdefault("chancery", ("/System/Library/Fonts/Supplemental/Apple Chancery.ttf", 0))

# scs_b_ed.arc v4_go_16ji, the ending title: white calligraphic letters in a grey and a dark ring
STYLES["e_go"] = ui_type.ringed([0, 10, 12, 13, 14, 15, 15], [8, 1])
