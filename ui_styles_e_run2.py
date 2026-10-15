"""Label styles of art run 2, agent E (sn_abiup.arc, scs_load.arc, scs_make.arc, scs_rens.arc, scs_b_ed.arc).
Loaded by ui_type.py (every ui_styles_*.py is). Colours read from the Japanese lettering with
_work/ui_pages/tools/roles.py."""
import numpy as np
import ui_type
from ui_type import grow, shift

STYLES = {}
ui_type.TTF.setdefault("italic", ("/System/Library/Fonts/Supplemental/Arial Italic.ttf", 0))
ui_type.TTF.setdefault("narrow-italic", ("/System/Library/Fonts/Supplemental/Arial Narrow Italic.ttf", 0))
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


def _stack_unused(lines, gap=4):
    """Two or more lines of ink, centred, each from ui_type.ttf_ink(*args): (ink, baseline row of the last line)."""
    inks = [ui_type.ttf_ink(*a) for a in lines]
    w = max(i.shape[1] for i, _ in inks)
    rows, base = [], 0
    for k, (i, b) in enumerate(inks):
        x = (w - i.shape[1]) // 2
        rows.append(np.pad(i, ((0, 0), (x, w - i.shape[1] - x))))
        if k < len(inks) - 1:
            rows.append(np.zeros((gap, w), int))
        else:
            base = sum(r.shape[0] for r in rows[:-1]) + b
    return np.vstack(rows), base


def _sop_title(project=None):
    # scs_load.arc z5_sop_0 sprite 13: the title and its subtitle, two lines of ink in two sizes
    for cap in range(48, 20, -1):                      # the largest title that leaves room for the rings in 288 columns
        title = ("Hakkyu Dream", "rounded", cap, 0.12, 0.92, 1.0)
        if ui_type.ttf_ink(*title)[0].shape[1] <= 278:
            break
    sub = ("~ Hot-Blooded Industrial-League Ball! ~", "narrow", 14, 0.0, 1.0, 0.6)
    return {"words": {"SOP_T1": ui_type.ttf_ink(*title), "SOP_T2": ui_type.ttf_ink(*sub)}, "glyphs": {}, "space": 4, "gap": 1}


ui_type.FONTS["e_sop_title"] = _sop_title
# the title: white letters in a dark blue ring and a darker one (palette 0, a blue ramp)
STYLES["e_sop_title"] = ui_type.ringed([0, 15, 15, 15, 15, 15, 15], [3, 1])
