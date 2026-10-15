"""Label styles of art run 2, agent E (sn_abiup.arc, scs_load.arc, scs_make.arc, scs_rens.arc, scs_b_ed.arc).
Loaded by ui_type.py (every ui_styles_*.py is). Colours read from the Japanese lettering with
_work/ui_pages/tools/roles.py."""
import numpy as np
import ui_type
from ui_type import grow, shift

STYLES = {}
ui_type.TTF.setdefault("italic", ("/System/Library/Fonts/Supplemental/Arial Italic.ttf", 0))
ui_type.TTF.setdefault("chancery", ("/System/Library/Fonts/Supplemental/Apple Chancery.ttf", 0))

# scs_b_ed.arc v4_go_16ji, the ending title: white calligraphic letters in a grey and a dark ring
STYLES["e_go"] = ui_type.ringed([0, 10, 12, 13, 14, 15, 15], [8, 1])

# scs_rens.arc y5_mic_0 (palette 17, a grey ramp 1 = white .. f = dark navy): the "one more round?" question and its
# answers: heavy italic dark letters in a one-pixel light ring
STYLES["e_mic"] = ui_type.ringed([0, 15, 15, 15, 15, 15, 15], [7])

# scs_load.arc y5_tlog_0 (palette 20, white to dark brown): Cleared / Pitchers / Fielders: dark brown letters in a grey and a
# white ring (as the Japanese lettering is)
STYLES["e_tlog"] = ui_type.ringed([0, 5, 4, 3, 2, 1, 1], [8, 15])

# scs_load.arc z5_sop_0 (palette 0, a blue ramp): the story lines, white italic letters in a thin dark blue ring
STYLES["e_sop"] = ui_type.ringed([0, 15, 15, 15, 15, 15, 15], [2])
