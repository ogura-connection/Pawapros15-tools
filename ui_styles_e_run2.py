"""Label styles of art run 2, agent E (sn_abiup.arc, scs_load.arc, scs_make.arc, scs_rens.arc, scs_b_ed.arc).
Loaded by ui_type.py (every ui_styles_*.py is). Colours read from the Japanese lettering with
_work/ui_pages/tools/roles.py."""
import numpy as np
import ui_type
from ui_type import grow, shift

STYLES = {}
ui_type.TTF.setdefault("italic", ("/System/Library/Fonts/Supplemental/Arial Italic.ttf", 0))
ui_type.TTF.setdefault("narrow-italic", ("/System/Library/Fonts/Supplemental/Arial Narrow Italic.ttf", 0))
ui_type.TTF.setdefault("times-bold", ("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf", 0))
ui_type.TTF.setdefault("tahoma", ("/System/Library/Fonts/Supplemental/Tahoma.ttf", 0))
ui_type.TTF.setdefault("tahoma-bold", ("/System/Library/Fonts/Supplemental/Tahoma Bold.ttf", 0))
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
    sub = ("~ Hot-Blooded Industrial-League Ball! ~", "narrow", 15, 0.0, 1.0, 0.3)
    return {"words": {"SOP_T1": ui_type.ttf_ink(*title), "SOP_T2": ui_type.ttf_ink(*sub)}, "glyphs": {}, "space": 4, "gap": 1}


ui_type.FONTS["e_sop_title"] = _sop_title
# the title: white letters in a dark blue ring and a darker one (palette 0, a blue ramp)
_big = ui_type.ringed([0, 15, 15, 15, 15, 15, 15], [3, 1])
_small = ui_type.ringed([0, 15, 15, 15, 15, 15, 15], [3])
STYLES["e_sop_title"] = lambda ink, base: (_big if ink.shape[0] > 30 else _small)(ink, base)      # one ring on the subtitle

# sn_abiup.arc z3_upp_0 (palettes 42-47: teal, pink, blue, yellow, green plates; the index ramp is the same in all of them):
# white letters shading to the plate colour at the foot, in a dark ring and a mid ring (8 = darkest, a = mid)
STYLES["e_btn"] = ui_type.ringed([0, 15, 15, 15, 15, 15, 15], [8])

# sn_abiup.arc z3_up_0: headings of the ability-up panels. Every palette has its own ramp; the colours are read from them
# (_work/ui_pages/run2/E/ notes): 現能力 green letters in dark blue, a white band, light blue glow and shadow (palette 60);
# 能力アップ後 yellow in purple blue, white band (61); 経験点 columns green in violet (21); アイテム効果 white letters in the
# plate's dark green (54); the tabs white letters in a dark ring of the plate's colour and a lighter one (24 pink, 25 blue,
# 26 green); キャンセル purple letters in white and light blue (75; 76 draws the same art again as a flat blue shadow)
STYLES["e_cur"] = ui_type.logo([7, 8, 9, 10, 10, 10], [14], 15, 1, 4, [5, 6], 2, 1)
STYLES["e_after"] = ui_type.logo([10, 10, 11, 12, 12, 13], [2], 1, 9, 5, [15], 2, 1)
STYLES["e_exp"] = ui_type.logo([9, 9, 10, 10, 11, 11], [8], 5, 14, 2, [], 1, 1)
STYLES["e_item"] = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [2])
STYLES["e_tabp"] = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [8, 8, 11])
STYLES["e_tabf"] = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [8, 7, 2])
STYLES["e_tabo"] = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [8, 7, 11])
STYLES["e_cancel"] = ui_type.logo([8, 9, 10, 11, 12, 13, 14], [7], 14, 1, 3, [], 2, 1)
