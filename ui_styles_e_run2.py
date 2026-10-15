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
STYLES["e_tabp"] = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [8, 11])
STYLES["e_tabf"] = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [8, 2])
STYLES["e_tabo"] = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [8, 11])
STYLES["e_cancel"] = ui_type.ringed([0, 10, 12, 13, 14, 14, 14], [1, 3])


# z3_up_0 sprite 37 (the "acquired" bar, palette 23): the whole bar is one piece of art, 280 x 40: the mint gradient bar with its
# rounded right end (as the Japanese bar is built from its pieces) and the word in white letters in blue rings in the middle
_BAR = [0, 0, 0, 0, 0, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 7, 7, 7, 6, 6, 6, 5, 5, 5, 4, 4, 3, 3, 2, 2, 0, 0, 0, 0, 0]
_CAP = {5: 10, 6: 12, 7: 13, 8: 13, 31: 13, 32: 13, 33: 12, 34: 10}      # width of the end piece's rows (14 elsewhere)
_ACQ_TEXT = ui_type.ringed([0, 13, 14, 15, 15, 15, 15], [8, 8, 12])


def _acq(ink, base):
    out = np.zeros((40, 280), np.uint8)
    for y, v in enumerate(_BAR):
        if v:
            out[y, :264 + _CAP.get(y, 14)] = v
    art, b = _ACQ_TEXT(ink, base)
    h, w = art.shape
    y0, x0 = 20 - h // 2, 144 - w // 2
    area = out[y0:y0 + h, x0:x0 + w]
    area[art > 0] = art[art > 0]
    return out, 20


STYLES["e_acq"] = _acq


# z3_up_0 sprite b2 / b3 (palettes 80, 81): the round division tag, drawn again with an E in it (the picture does not depend on
# the ink): a dark ring, the green ring that shades from top to foot, a white ring, the pale disc and the letter
def _badge(ink, base):
    H, W = 23, 20
    out = np.zeros((H, W), np.uint8)
    for y in range(H):
        for x in range(W):
            r = (((y - 11.0) / 11.6) ** 2 + ((x - 9.5) / 10.1) ** 2) ** 0.5
            if r > 1.0:
                continue
            yn = y / (H - 1)
            out[y, x] = (1 if yn < 0.30 else 2 if yn < 0.70 else 3) if r > 0.88 else min(8, 4 + int(yn * 5)) if r > 0.66 \
                else 9 if r > 0.55 else 10
    for j, row in enumerate(["######", "##....", "##....", "#####.", "#####.", "##....", "##....", "######"]):
        for i, c in enumerate(row):
            if c == "#":
                out[7 + j, 7 + i] = 15
    return out, H


STYLES["e_badge"] = _badge


# scs_make.arc y5_make_bg_opd: the application form in perspective on a desk. ui_sheet.py draws a word from this "font" as
# ink: the flat lettering is sheared and rotated to the direction of the paper (rows rise 0.14 per column, columns lean
# 0.217 per row) and softened like the photograph (the key is the text; sizes: OPD_SIZES)
OPD_SIZES = {"OPD_TITLE": ("Baseball Club Application", "times-bold", 10, 0.0), "OPD_DATE": ("Date", "tahoma", 8, 0.2),
             "OPD_SLASH": ("/", "tahoma", 8, 0.4), "OPD_NAME": ("Name", "tahoma", 9, 0.2), "OPD_HAND": ("Hand", "tahoma", 9, 0.2),
             "OPD_POS": ("Position", "tahoma", 9, 0.2), "OPD_FORM": ("Form", "tahoma", 9, 0.2),
             "OPD_NOTES": ("Notes", "tahoma", 8, 0.2)}


def _opd_font(project=None):
    from PIL import Image, ImageFilter
    words = {}
    for key, (text, face, cap, bold) in OPD_SIZES.items():
        ink, base = ui_type.ttf_ink(text, face, cap, 0.0, 1.0, bold)
        img = Image.fromarray((np.clip(ink, 0, 6) * 255 // 6).astype(np.uint8), "L")
        pad = 4
        big = Image.new("L", (img.width + 2 * pad, img.height + 2 * pad), 0)
        big.paste(img, (pad, pad))
        k, m = -0.14, 0.217                              # rows rise k per column, columns lean m per row
        det = 1.0 - m * k
        # output pixel (X, Y) comes from the input pixel (u, v) = M^-1 (X, Y), M = [[1, m], [k, 1]]
        a, b, c, d = 1 / det, -m / det, -k / det, 1 / det
        W, H = big.width + int(abs(m) * big.height) + 4, big.height + int(abs(k) * big.width) + 4
        cx, cy = big.width / 2, big.height / 2
        ox, oy = W / 2, H / 2
        # input = M^-1 (output - centre) + input centre
        coeffs = (a, b, cx - a * ox - b * oy, c, d, cy - c * ox - d * oy)
        out = big.transform((W, H), Image.AFFINE, coeffs, Image.BICUBIC).filter(ImageFilter.GaussianBlur(0.6))
        arr = np.asarray(out, dtype=np.float32)
        lv = np.rint(arr * 6 / 255).astype(int)
        ys, xs = np.nonzero(lv)
        words[key] = (lv[ys.min():ys.max() + 1, xs.min():xs.max() + 1], 0)
    return {"words": words, "glyphs": {}, "space": 4, "gap": 1}


ui_type.FONTS["e_opd"] = _opd_font
