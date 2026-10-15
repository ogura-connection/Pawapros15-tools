"""Label styles of art run 2, agent A (scs_end.arc: end of a Success game). Loaded by ui_type.py (every ui_styles_*.py is).
Colours read from the Japanese lettering of each palette (_work/ui_pages/run2/A/dump.py / roles.py)."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# m4_stt01 team names and forms (palettes 27, 2): white letters, thick navy outline
STYLES["a_name"] = ringfill([15], [1, 1], [])
