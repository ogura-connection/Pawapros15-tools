"""Styles for the main screens of Success Mode, the story mode in which you build a player.

The player sees the daily training and menu screens, the player-data screen, the ability-up screen, the save/load
screens, the elite squad camp mini-games, the draft announcements, and the match labels, versus screen and result screen.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): scs_main, scg_camp, scs_rens, gdt_scs, are_abi, sn_abiup, scs_data, scs_g_ed, scs_win, gdt_sch, scs_vs, scs_load, scs_make, scs_b_ed.
"""
import numpy as np
import base64 as _b64
import zlib as _zlib
import os
from pp15.art.typeset import boxed, grow, shift, logo
from pp15.art import typeset as ui_type
from pp15.script import scan as _S
from pp15.art import textures as _U
from .common import ringfill, flat, win

STYLES = {}


# ---- scs_main.arc, scs_data.arc, scs_rens.arc, scs_make.arc: leftover pages ------------------------------------------

def bandeco(fill, inner, shadow, outer, edge=3):
    """Banner lettering: letters filled top to foot from `fill`, a thin `inner` ring, a dark extrusion `shadow` (near to far, down and
    to the right of the ring) and the `outer` rings (nearest first) round letters and extrusion together."""
    from pp15.art.typeset import grow, shift
    fill = list(fill)

    def style(ink, base):
        pad = len(inner) + len(shadow) + len(outer) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        ring = letters
        rings = []
        for _ in inner:
            ring = grow(ring, 1, diagonal=False) if rings else grow(ring, 1)
            rings.append(ring)
        body = rings[-1]
        sh = np.zeros(big.shape, bool)
        for k in range(1, len(shadow) + 1):
            sh |= shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
        whole = body | sh
        out = np.zeros(big.shape, np.uint8)
        o = whole
        orings = []
        for _ in outer:
            o = grow(o, 1, diagonal=False) if orings else grow(o, 1)
            orings.append(o)
        for m, v in zip(orings[::-1], outer[::-1]):
            out[m] = v
        for k in range(len(shadow), 0, -1):
            mk = shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
            out[mk] = shadow[k - 1]
        for m, v in zip(rings[::-1], inner[::-1]):
            out[m] = v
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        out[letters] = np.where(big >= edge, row, inner[0])[letters]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


# styles_scs_data.txt
STYLES["a9_dtn_45"] = ringfill([12, 13, 13, 14, 14, 15], [9, 6, 6, 5, 4, 3], [1])
STYLES["a9_dtn_46"] = ringfill([8, 9, 10, 10, 11, 12], [14, 1, 1, 3], [15])
STYLES["a9_dtn_47"] = ringfill([4, 4, 4, 4, 4, 4], [8, 8, 8], [15])
STYLES["a9_dtn_48"] = ringfill([4, 4, 4, 4, 4, 4], [8, 8, 8], [13])
STYLES["a9_dtn_49"] = boxed([7, 7, 7, 15, 15, 15, 15], pad=(1, 1), size=(29, 22), rim=1)
STYLES["a9_dtn_4a"] = boxed([8, 8, 8, 15, 15, 15, 15], pad=(1, 1), size=(29, 22), rim=1)
STYLES["a9_dtn_4b"] = boxed([8, 8, 8, 15, 15, 15, 15], pad=(1, 1), size=(29, 22), rim=3)
STYLES["a9_dtj_24"] = ringfill([15, 14, 13, 12, 10, 9], [11, 1, 1, 8, 8])
# styles_scs_main.txt
STYLES["a9_smi_8a"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_smi_8b"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)
STYLES["a9_ai_0f"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_24"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_39"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3a"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_ai_3b"] = ringfill([8, 8, 8, 8, 8, 8], [15, 15], [15])
STYLES["a9_smj_a"] = bandeco([7, 8, 9, 10, 11, 11], [3], [1, 1, 1], [15, 15, 14])
STYLES["a9_smj_b"] = bandeco([7, 8, 9, 10, 11, 11], [3], [1, 1, 1], [15, 15, 14])
STYLES["a9_smj_c"] = bandeco([5, 6, 7, 9, 10, 10], [1], [1, 1, 1], [14, 14, 14, 15])
STYLES["a9_smj_d"] = bandeco([5, 6, 7, 9, 10, 10], [1], [1, 1, 1], [14, 14, 14, 15])
STYLES["a9_tem"] = ringfill([9, 9, 8, 8, 7, 7], [1, 1, 13, 13, 14], [15])
STYLES["a9_snm"] = ringfill([15, 15, 15, 15, 15, 15], [4, 4], [4, 4])
# styles_scs_main_win.txt
STYLES["a9_smj_a~0_64"] = win(STYLES["a9_smj_a"], 0, 64)
STYLES["a9_smj_a~64_119"] = win(STYLES["a9_smj_a"], 64, 119)
STYLES["a9_smj_a~119_175"] = win(STYLES["a9_smj_a"], 119, 175)
STYLES["a9_smj_a~175_191"] = win(STYLES["a9_smj_a"], 175, 191)
STYLES["a9_smj_a~191_231"] = win(STYLES["a9_smj_a"], 191, 231)
STYLES["a9_smj_b~0_61"] = win(STYLES["a9_smj_b"], 0, 61)
STYLES["a9_smj_b~61_117"] = win(STYLES["a9_smj_b"], 61, 117)
STYLES["a9_smj_b~117_149"] = win(STYLES["a9_smj_b"], 117, 149)
STYLES["a9_smj_b~149_172"] = win(STYLES["a9_smj_b"], 149, 172)
STYLES["a9_smj_b~172_226"] = win(STYLES["a9_smj_b"], 172, 226)
STYLES["a9_smj_c~0_40"] = win(STYLES["a9_smj_c"], 0, 40)
STYLES["a9_smj_c~40_85"] = win(STYLES["a9_smj_c"], 40, 85)
STYLES["a9_smj_c~85_138"] = win(STYLES["a9_smj_c"], 85, 138)
STYLES["a9_smj_c~138_146"] = win(STYLES["a9_smj_c"], 138, 146)
STYLES["a9_smj_c~146_193"] = win(STYLES["a9_smj_c"], 146, 193)
STYLES["a9_smj_c~193_249"] = win(STYLES["a9_smj_c"], 193, 249)
STYLES["a9_smj_d~0_24"] = win(STYLES["a9_smj_d"], 0, 24)
STYLES["a9_smj_d~24_55"] = win(STYLES["a9_smj_d"], 24, 55)
STYLES["a9_smj_d~55_109"] = win(STYLES["a9_smj_d"], 55, 109)
STYLES["a9_tem~0_32"] = win(STYLES["a9_tem"], 0, 32)
STYLES["a9_tem~32_68"] = win(STYLES["a9_tem"], 32, 68)
STYLES["a9_tem~68_84"] = win(STYLES["a9_tem"], 68, 84)
STYLES["a9_tem~84_116"] = win(STYLES["a9_tem"], 84, 116)
STYLES["a9_tem~116_164"] = win(STYLES["a9_tem"], 116, 164)
STYLES["a9_tem~164_212"] = win(STYLES["a9_tem"], 164, 212)
STYLES["a9_tem~212_255"] = win(STYLES["a9_tem"], 212, 255)
STYLES["a9_tem~255_303"] = win(STYLES["a9_tem"], 255, 303)
STYLES["a9_tem~303_335"] = win(STYLES["a9_tem"], 303, 335)
STYLES["a9_tem~335_351"] = win(STYLES["a9_tem"], 335, 351)
# styles_scs_make.txt
STYLES["a9_nan_04"] = ringfill([15, 15, 15, 15, 15, 15], [4, 4, 1])
STYLES["a9_nan_08"] = ringfill([15, 15, 15, 15, 15, 15], [4, 4, 2])
# styles_scs_rens.txt
STYLES["a9_smr_68"] = ringfill([13, 13, 13, 13, 13, 13], [2, 2], [2])
STYLES["a9_smr_69"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_6a"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_6b"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_6c"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_6d"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_6e"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_6f"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_70"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_71"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])
STYLES["a9_smr_72"] = ringfill([9, 8, 7, 6, 5, 4], [15, 15])


# ---- scs_rens.arc z3_smr_0 icons, Super Ability GET!, Hot Blood ------------------------------------------------------

STYLES["f10_ico"] = ringfill([15, 15, 15, 15, 15, 15], [3], [3])
# yellow lettering (top orange to foot lime), dark ring, olive extrusion, cream rings: the Japanese GET wipe logo
STYLES["f10_sup"] = bandeco([11, 10, 10, 9, 8, 8], [1, 2], [3, 4, 5, 6], [15, 14])
# 熱血: yellow to red flame fill, dark red ring, white / pink rings, dark shadow
STYLES["f10_hot"] = ringfill([10, 9, 8, 7, 6, 5], [2, 15, 13, 11], [1, 1, 1])


# ---- sn_abiup.arc, scs_load.arc, scs_make.arc, scs_rens.arc, scs_b_ed.arc --------------------------------------------

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
    """Two or more lines of ink, centred, each from pp15.art.typeset.ttf_ink(*args): (ink, baseline row of the last line)."""
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


# scs_make.arc y5_make_bg_opd: the application form in perspective on a desk. pp15/art/sheet.py draws a word from this "font" as
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


# ---- are_abi.arc: the player-data screen of Arrange and of Success's Linked World ------------------------------------

def cut(style, thr=3):
    """`style` with the soft edge of the letters taken away: ink below level `thr` (of 6) is dropped, so the strokes keep
    the width the typeface gave them (ringfill counts any ink as a full pixel and would thicken them by up to one pixel)."""
    def thin(ink, base):
        return style(np.where(ink >= thr, ink, 0), base)
    return thin

# two regular-weight faces for the thin lettering (tags, hints): Arial Rounded Bold is too heavy there
ui_type.TTF["c3reg"] = ("/System/Library/Fonts/Supplemental/Arial.ttf", 0)
ui_type.TTF["c3regn"] = ("/System/Library/Fonts/Supplemental/Arial Narrow.ttf", 0)


def plain(ramp):
    """Letters drawn straight from `ramp` (palette index per ink level 0..6), no outline: thin lettering that is
    anti-aliased into the plate behind it."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        return ramp[big], base + pad
    return style


# ---- m3_an, palette 5 (the lilac / white player-data screen) -------------------------------------------------------------
# tabs (page 3): white letters, dark purple outline (e), medium purple shadow (d)
STYLES["c3_tab"] = cut(ringfill([1, 1, 1, 3, 4, 5], [14], [13]))
# the stat words, teams, forms, B/T: dark purple letters (e), white outline, lilac shadow (b)
STYLES["c3_name"] = cut(ringfill([14], [1], [11]))
# birthday / voice / pro-years words: medium purple letters (d), white outline, two rows of lilac shadow (a)
STYLES["c3_mid"] = cut(ringfill([13], [1], [10, 10]))
# the column headings on the lilac plates (page 12): white letters, two rows of dark purple outline, medium purple shadow
STYLES["c3_head"] = cut(ringfill([1, 1, 1, 4, 5], [14, 14], [13, 13]))

# ---- m3_an, the pill tags (palette 71, lettering on a mint plate): thin navy letters, anti-aliased into the plate ---------------------
ui_type.TTF["c3uni"] = ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0)       # has the star the tags use
STYLES["c3_tag"] = plain([0, 2, 5, 8, 11, 14, 15])
# the hints (palette 85, pages 13): thin blue-violet strokes
STYLES["c3_hint"] = plain([0, 7, 5, 4, 3, 3, 3])
# "this player cannot be uploaded" (palette 86): red letters, soft edge into the page behind
STYLES["c3_red"] = plain([0, 7, 9, 11, 13, 14, 15])
# the message of an unset voice (palette 13): white to yellow letters, dark blue outline, two lighter blue rings
STYLES["c3_msg"] = cut(ringfill([10, 11, 12, 12, 13, 13], [1, 1, 3, 5], []))
# the Role cell (palette 66): blue letters, light outline, painted into the plate
STYLES["c3_role"] = cut(ringfill([1], [15], []))
# the three blue buttons (palettes 83, 80, 84: teal, olive, violet from index 10 on): coloured letters, two white rings, blue glow
STYLES["c3_btn"] = cut(ringfill([15], [9, 9, 7, 5], []))
# z3_nph_0 (palette 32): the pitch-name plates, dark blue letters in a two-pixel white outline, light blue shadow
STYLES["c3_nph"] = cut(ringfill([1, 1, 2, 2], [8, 8], [13, 14]))
# z3_it_0 (palette 1): the colour words, black letters with a white outline
STYLES["c3_it"] = cut(ringfill([15], [1], []))


# ---- scg_camp.arc (elite squad camp mini-games), scs_g_ed.arc (draft announcements), gdt_sch.arc ---------------------

# h3_st_0 HUD labels (palette 13): yellow letters, tan inner edge, deep blue outline, light blue outer edge
STYLES["f_st_yel"] = ringfill([0xf, 0xf, 0xe, 0xe, 0xd, 0xd], [6, 6, 1])
# h3_st_0 Bonus (palette 15): white to pink letters, deep blue outline, blue shadow
STYLES["f_st_pink"] = ringfill([7, 7, 8, 9, 0xa, 0xb], [1, 1], [3, 4])
STYLES["f_st_yel2"] = ringfill([0xf, 0xf, 0xe, 0xe, 0xd, 0xd], [6, 6])


def stacked(inner, overlap=2):
    """The same style applied to every line of a block on its own (typeset stacks lines with clear rows between them): each
    line gets its own gradient and rings; the lines are centred on each other and overlap by `overlap` rows (the rings)."""
    def style(ink, base):
        rows = np.nonzero(ink.any(1))[0]
        cuts = [0] + [k for k in range(1, len(rows)) if rows[k] != rows[k - 1] + 1]
        blocks = []
        for a, b in zip(cuts, cuts[1:] + [len(rows)]):
            r0, r1 = rows[a], rows[b - 1] + 1
            art, bs = inner(ink[r0:r1], r1 - r0)
            blocks.append((art, bs))
        W = max(a.shape[1] for a, _ in blocks)
        H = sum(a.shape[0] for a, _ in blocks) - overlap * (len(blocks) - 1)
        out = np.zeros((H, W), np.uint8)
        y = 0
        for art, bs in blocks:
            x = (W - art.shape[1]) // 2
            area = out[y:y + art.shape[0], x:x + art.shape[1]]
            area[art > 0] = art[art > 0]
            y += art.shape[0] - overlap
        return out, H - (blocks[-1][0].shape[0] - blocks[-1][1])
    return style


# h3_st_0 popups (palettes 53 pink / 54 blue, the same indices): lilac to white letters, deep blue outline, blue edge
STYLES["f_st_flash"] = stacked(ringfill([0xb, 0x9, 0x9, 0x8, 0x7, 0x7], [1, 1, 3]))

# h3_kyos_0_opd HUD labels (palette 10): pale to deep yellow letters, navy outline, blue shadow running to violet
STYLES["f_ky_yel"] = ringfill([0xf, 0xe, 0xa, 0xd, 0xd, 0xc], [3, 3], [5, 5, 6, 7])
# swing tags (palettes 16-19, white letters on the orange / yellow / green / purple plates): navy outline, blue rim
STYLES["f_ky_btn"] = ringfill([0xf, 0xf, 0xe, 0xd, 0xd], [5, 4])
# 点 next to the digits (palette 6): lilac-white letters, light edge, navy outline, blue shadow
STYLES["f_ky_pts"] = ringfill([0xe, 0xe, 0xd, 0xd, 0xc, 0xb], [0xa, 4], [2, 2])


# z4_teu_0 titles (one palette each; the white twins, palette 15, take the same art: every index is white there).
# Letters: a gradient, a thin dark outline, a white band two pixels wide, a pale rim, a navy shadow below and to the right.
STYLES["f_teu_blue"] = logo([8, 8, 7, 6, 5, 5], [8, 8], 9, 1, 3, [0xd, 0xd, 0xd, 0xd], 2, 1)        # palette 0: Test Start
STYLES["f_teu_pink"] = logo([7, 7, 8, 9, 10, 11], [7, 7], 3, 15, 5, [1, 1, 1, 1], 2, 1)             # palette 2: Test Over
STYLES["f_teu_orange"] = logo([6, 6, 5, 4, 3, 2, 1], [6, 6], 7, 15, 11, [10, 10, 10, 10], 2, 1)     # palette 4: Win
STYLES["f_teu_steel"] = logo([7, 8, 8, 9, 10, 10], [7, 7], 2, 15, 11, [1, 1, 1, 1], 2, 1)           # palette 6: Loss
STYLES["f_teu_green"] = logo([7, 7, 8, 9, 10, 10], [7, 7], 2, 15, 3, [1, 1, 1, 1], 2, 1)            # palette 8: Tie


for _name in ("f_teu_blue", "f_teu_pink", "f_teu_orange", "f_teu_steel", "f_teu_green"):
    for _c in ((0, 128), (128, 256), (0, 4096), (128, 4096)):
        STYLES["%s~%d_%d" % (_name, _c[0], _c[1])] = win(STYLES[_name], *_c)

# scs_g_ed.arc i5_h (4-bit pages, palette 0): the draft team names: chrome blue letters (dark, light in the middle, dark),
# a pale edge, a navy outline three pixels wide
STYLES["f_g_team"] = ringfill([4, 5, 7, 9, 0xa, 0xa, 9, 8, 6, 4], [0xe, 1, 1, 1], edge=2)


def tilted(style, rise):
    """The word on a slope: each column of the ink is lifted `rise` pixels per 100 columns towards the right (whole pixels:
    the steps stay crisp), then the style is applied."""
    def lift(ink, base):
        h, w = ink.shape
        dy = [int(round(rise * (w - 1 - x) / 100.0)) for x in range(w)]
        out = np.zeros((h + max(dy), w), ink.dtype)
        for x in range(w):
            out[dy[x]:dy[x] + h, x] = ink[:, x]
        return style(out, base + max(dy))
    return lift


# scs_g_ed.arc i5_h sprites 00 / 01 (palette 1, the shadow twin palette 2): the welcome banner: mint to green letters, a thin
# dark outline, a yellow band three pixels wide, a white rim; tilted up to the right as the Japanese is
STYLES["f_g_title"] = tilted(logo([0xa, 9, 8, 7, 6, 5], [0xa, 0xa], 1, 0xf, 0xb, [], 4, 1), 6.0)
for _c in ((0, 128), (128, 256), (256, 384), (384, 512), (0, 4096), (128, 4096), (256, 4096), (384, 4096)):
    STYLES["f_g_title~%d_%d" % _c] = win(STYLES["f_g_title"], *_c)


# ---- scs_g_ed.arc newspaper pictures: lettering that is stored as a mask in the spec itself -------------------------------
# The "text" of a sheet item is "m:<h>x<w>:<base64 of zlib of the mask bits>": a 1-bit picture (set = ink level 6) that the
# font "f_pic" returns as it is. Used for the lettering set on a slope (headlines, a vertical strip) and for the masks that
# paint the Japanese lettering away (gen_g_ed_pics.py makes both).


class _MaskWords(dict):
    def __contains__(self, key):
        return isinstance(key, str) and key.startswith("m:")

    def __getitem__(self, key):
        _, size, data = key.split(":", 2)
        h, w = (int(v) for v in size.split("x"))
        bits = np.unpackbits(np.frombuffer(_zlib.decompress(_b64.b64decode(data)), np.uint8))[:h * w].reshape(h, w)
        return (bits * 6).astype(int), h


ui_type.FONTS["f_pic"] = lambda project=None: {"words": _MaskWords(), "glyphs": {}, "space": 0, "gap": 0}


def encode_mask(mask):
    """The text of a sheet item for a boolean array (see above)."""
    mask = np.asarray(mask, bool)
    return "m:%dx%d:%s" % (mask.shape[0], mask.shape[1], _b64.b64encode(_zlib.compress(np.packbits(mask.reshape(-1)).tobytes(), 9)).decode())


# ---- gdt_scs.arc (Success match labels), scs_vs.arc (versus screen), scs_win.arc (result screen) ---------------------

# a rounded face that has the star of 5e / 09 "Ageage★" (Arial Rounded Bold has none)
ui_type.TTF["sfr"] = ("/System/Library/Fonts/SFNSRounded.ttf", 0)


def padded(style, h):
    """The art of `style` padded with clear rows at the foot to exactly h rows (labels of one band group are as high as the band)."""
    def cut(ink, base):
        art, b = style(ink, base)
        H, W = art.shape
        if H > h:
            return art, b
        out = np.zeros((h, W), np.uint8)
        out[:H] = art
        return out, b
    return cut


# gdt_scs z3_sgr_0 (palette 11): white letters in a dark blue outline, one pixel, so that 71 phrases fit the ten pages;
# every label 17 rows high so that the capitals of all of them stand on the same row
STYLES["c2_sgr"] = padded(ringfill([15], [4], []), 17)
# gdt_scs z3_sgi_0 (palette 2): white letters, navy outline, blue ring
STYLES["c2_sgi"] = ringfill([15], [4, 2], [])
# gdt_scs h3_mrs_0 (palette 0): orange letters, dark brown outline, brown ring
STYLES["c2_mrs"] = ringfill([15], [1, 3], [])
# gdt_scs / scs_vs svt_0 (palette 0): white letters, navy outline, blue band, white rim
STYLES["c2_svt"] = ringfill([15], [1, 1, 9, 9, 9, 15, 15], [7, 13])


def window(inner, W, c0, c1):
    """`inner` art centred on a canvas W columns wide, only the columns c0..c1 returned: one word shared out over the pieces
    (parts) that the sprite is drawn from, each piece painted in place by a "paint" entry."""
    def cut(ink, base):
        art, b = inner(ink, base)
        H, aw = art.shape
        full = np.zeros((H, W), np.uint8)
        x = (W - aw) // 2
        if x >= 0:
            full[:, x:x + aw] = art
        else:
            full[:] = art[:, -x:-x + W]
        out = full[:, c0:c1]
        return (out if out.shape[1] else np.zeros((H, 1), np.uint8)), b
    return cut


for _w, _c0, _c1 in ((80, 0, 80), (80, 0, 48), (80, 48, 80), (32, 0, 32)):
    STYLES["c2_mrsw_%d_%d_%d" % (_w, _c0, _c1)] = window(STYLES["c2_mrs"], _w, _c0, _c1)


# ---- gdt_scs y4_mmk_1: the 32 x 32 team emblems with one kanji (two Latin capitals instead) ---------------------------
_ORIG = {}


def _orig_rect(arc, bank, page, rect):
    """The 32 x 32 indices of an emblem in the untouched file."""
    key = (arc, bank, page)
    if key not in _ORIG:
        path = os.path.join(_U.ORIG_ARC_DIR, arc)
        if not os.path.exists(path):
            path = os.path.join(_S.DATA_FILES, arc)
        d = open(path, "rb").read()
        b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == bank)
        _ORIG[key] = _U.decode_indices(d, *b["pages"][page])
    x0, y0, x1, y1 = rect
    return _ORIG[key][y0:y1, x0:x1]


def _erode(mask, n):
    m = mask.copy()
    for _ in range(n):
        p = np.pad(m, 1)
        m = m & p[:-2, 1:-1] & p[2:, 1:-1] & p[1:-1, :-2] & p[1:-1, 2:]
    return m


def emblem(fill, rings, shadow=(), plate=None, dy=0):
    """The word (two capitals) in `ringfill` colours on a 32 x 32 canvas; `plate` = (page, rect, depth, inner, drop) keeps the
    tile or ring of the original emblem: its edge `depth` pixels deep is copied (index in `drop` = old letter, replaced by `inner`),
    the inside is flat `inner`."""
    inner_style = ringfill(fill, rings, shadow)
    cut = _emblem_cut(inner_style, plate, dy)
    cut.raw = inner_style                           # the bare word (to measure it)
    return cut


def _emblem_cut(inner_style, plate, dy):
    def cut(ink, base):
        art, _ = inner_style(ink, base)
        out = np.zeros((32, 32), np.uint8)
        mid = (16, 16)
        if plate:
            out, mid = _plate(*plate)
        H, W = art.shape
        y, x = mid[0] - H // 2 + dy, mid[1] - W // 2
        area = out[y:y + H, x:x + W]
        area[art > 0] = art[art > 0]
        return out, 0
    return cut


def _plate(kind, page, rect):
    """The tile (kind "tile") or the ring and disc (kind "disc") of an emblem, cleaned of its kanji, from the untouched file."""
    old = _orig_rect("gdt_scs.arc", "y4_mmk_1", page, rect)
    solid = old > 0
    ys, xs = np.nonzero(solid)
    out = np.zeros((32, 32), np.uint8)
    if kind == "tile":                       # 選: a red tile; the sweep of the kanji left of it is dropped
        x0, x1, y0, y1 = xs.min() + 3, xs.max() + 1, ys.min(), ys.max() + 1
        out[y0:y1, x0:x1] = 2                # pale blue edge
        out[y0 + 1:y1 - 1, x0 + 1:x1 - 1] = 5     # dark red border
        out[y0 + 2:y1 - 2, x0 + 2:x1 - 2] = 7     # red tile
        out[y0 + 2, x0 + 2:x1 - 2] = 9            # light top edge
        for cy, cx in ((y0, x0), (y0, x1 - 1), (y1 - 1, x0), (y1 - 1, x1 - 1)):
            out[cy, cx] = 0
        return out, ((y0 + y1) // 2, (x0 + x1) // 2)
    cy, cx = (ys.min() + ys.max()) / 2.0, (xs.min() + xs.max()) / 2.0      # disc
    r = (ys.max() - ys.min() + 1) / 2.0
    yy, xx = np.mgrid[0:32, 0:32]
    dist = np.hypot(yy - cy, xx - cx)
    out = np.where(solid & (dist > r - 4.5), old, 0).astype(np.uint8)
    out[np.isin(out, (2, 3, 4, 5, 6)) & (dist > r - 4.5)] = 8
    out[dist <= r - 4.5] = 12
    return out, (int(round(cy)), int(round(cx)))


# 選 (palette 23): red tile, white capitals in dark red
STYLES["c2_emb_03"] = emblem([15, 15, 15, 14, 14, 14, 14, 14], [4], [], ("tile", 1, (64, 0, 96, 32)), dy=1)
# 極 (palette 43): pale lilac capitals, purple outline, blue shadow
STYLES["c2_emb_05"] = emblem([7, 6, 6, 5, 5, 4, 4, 3], [1, 1], [13, 15])
# て (palette 45): blue capitals, pale cyan outline, blue shadow
STYLES["c2_emb_06"] = emblem([14, 14, 14, 14, 14, 14, 14, 14], [10], [5])
# 浪 (palette 36): white capitals, dark purple outline, lilac shadow
STYLES["c2_emb_08"] = emblem([1, 1, 2, 2, 3, 3, 3, 3], [7, 7], [10])
# ぴ (palette 37): white capitals, royal blue outline, sky blue ring
STYLES["c2_emb_09"] = emblem([15, 15, 14, 14, 13, 13, 12, 12], [2, 2], [9])
# 覇 (palette 47): dark capitals on the pale grey disc of a red ring
STYLES["c2_emb_0b"] = emblem([2, 2, 2, 2, 3, 3, 3, 3], [12], [], ("disc", 1, (32, 0, 64, 32)), dy=0)
# ど (palette 44): black capitals, pale blue outline
STYLES["c2_emb_0d"] = emblem([2, 2, 3, 3, 2, 2, 1, 1], [10, 9], [7])


for _k in list(STYLES):
    if _k.startswith("c2_emb_"):
        STYLES["c2_embm" + _k[6:]] = STYLES[_k].raw


# ---- scs_vs z5_svx_0 (256 colours): the tournament titles --------------------------------------------------------------------------
def extruded(fill, extrude, white, lavender, blue, wide=4, edge=3):
    """Letters filled top to foot from `fill`, pushed out to the lower right by `extrude` (near to far, one pixel each), in a white
    band `wide` pixels wide with a one pixel `lavender` edge and a thick `blue` band (colours inside to out)."""
    fill = list(fill)

    def style(ink, base):
        pad = len(extrude) + wide + 1 + len(blue) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big >= edge
        ext = np.zeros_like(letters)
        for k in range(1, len(extrude) + 1):
            ext |= shift(letters, k, k) | shift(letters, k, k - 1) | shift(letters, k - 1, k)
        solid = letters | ext
        out = np.zeros(big.shape, np.uint8)
        masks = [grow(solid, 1)]
        for _ in range(wide + 1 + len(blue) - 1):
            masks.append(grow(masks[-1], 1, diagonal=False))
        for k in range(len(blue), 0, -1):                          # outermost band first
            out[masks[wide + k]] = blue[k - 1]
        out[masks[wide]] = lavender
        for m in masks[:wide][::-1]:
            out[m] = white
        for k in range(len(extrude), 0, -1):
            out[shift(letters, k, k) | shift(letters, k, k - 1) | shift(letters, k - 1, k)] = extrude[k - 1]
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        out[letters] = np.broadcast_to(row, big.shape)[letters]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


# red-orange letters turning to yellow at the foot, a dark red edge below and right, white band, lilac and blue bands
STYLES["c2_svx"] = extruded([80, 78, 76, 73, 69, 65, 57, 51, 47, 43, 40, 37], [120, 125], 199, 182, [168, 168, 168, 154, 154, 148], 4)

# ---- scs_win r4_vs (palettes 0, 3, 4, 5): the result screen ------------------------------------------------------------------------
# 勝利 (palette 3): letters from white at the top to dark gold at the foot, a thick black outline and shadow
_GOLD = [15, 14, 14, 13, 12, 11, 10, 9, 8, 7, 6, 6]
STYLES["c2_win_gold"] = ringfill(_GOLD, [1, 1, 1], [1, 1])
# 敗北 (palette 4), 引き分け (5): the same from white to lilac
STYLES["c2_win_lilac"] = ringfill([15, 14, 14, 13, 12, 11, 10, 9, 8, 7, 6, 6], [1, 1, 1], [1, 1])
# the match types and the side words (palette 0): white letters, black outline and shadow
STYLES["c2_win_h"] = ringfill([15], [7, 7], [7, 5])
# the team names (palette 0, 32 rows): the same, thinner
STYLES["c2_win_n"] = ringfill([15], [7], [7])

# svt_0 12 / 13 / 14 (palette 4, drawn again in white and in black by palettes 1 and 2): white letters, navy outline, cyan band, white rim
STYLES["c2_svt_sel"] = ringfill([14], [1, 1, 9, 8, 8, 14, 14], [10])
