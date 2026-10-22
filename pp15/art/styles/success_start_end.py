"""Styles for the opening and ending screens of Success Mode (the story mode in which you build a player).

The player sees the legal notice at the start, the title and intro screens, the ball-naming screen, the graduation
screen and the end-of-game screen. Also holds the on-demand "cut:" styles and "d:" fonts that the generator scripts enable with enable_lazy().

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): scs_end, scs_grad, scs_intr, scs_titl, sct_titl, orihen, scs_open.
"""
import numpy as np
from pp15 import config
from pp15.art.typeset import grow, shift, logo
from pp15.art import typeset as ui_type
from .common import ringfill, flat

STYLES = {}


# ---- scs_open.arc, scs_grad.arc, scs_titl.arc, scs_intr.arc, orihen.arc; also the lazy "cut:" styles and "d:" fonts of the generators ----

# scs_open z3_fic_0 (palette 0, grey ramp): white letters, a grey soft edge, black outline, dark blue-grey shadow
STYLES["d2_fic"] = ringfill([0xf], [0xb, 4], [3, 2])

ui_type.TTF["d_georgia"] = ("/System/Library/Fonts/Supplemental/Georgia Bold.ttf", 0)
ui_type.TTF["d_times"] = ("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf", 0)
ui_type.TTF["d_georgiai"] = ("/System/Library/Fonts/Supplemental/Georgia Bold Italic.ttf", 0)
ui_type.TTF["d_narrowi"] = ("/System/Library/Fonts/Supplemental/Arial Narrow Bold Italic.ttf", 0)
ui_type.TTF["d_impact"] = ("/System/Library/Fonts/Supplemental/Impact.ttf", 0)

# scs_titl r4_staz (8-bit, palette 16): the three buttons. Gradient letters, a thin dark outline, a white band, a blue
# shadow to the lower right (orange / lime / green fill; each has its own run of palette entries)
STYLES["d2_staz_new"] = ringfill([1, 2, 3, 4, 6, 5, 9, 11], [25, 57, 57, 35], [35, 35])
STYLES["d2_staz_cont"] = ringfill([166, 168, 169, 170, 171, 175, 176], [129, 181, 181, 152], [152, 152])
STYLES["d2_staz_list"] = ringfill([215, 216, 218, 221, 226, 229], [240, 210, 210, 193], [193, 193])


# ---- a text font of this file: "d:<face>:<cap>:<squeeze>:<bold>[:<pitch>]" -------------------------------------------------
# Lines are separated by "|" and left aligned, `pitch` rows apart (baseline to baseline); a line may hold the symbols
# ◎ and × (drawn here, no font has them in this style) between words; everything else is pp15.art.typeset.ttf_ink.
def _symbol(ch, cap, bold):
    """(ink, base) of ◎ or × drawn as capitals `cap` high: supersampled, 6 ink levels like ttf_ink."""
    from PIL import Image, ImageDraw
    k = 8
    size = int(cap) + 2
    big = Image.new("L", (size * k, size * k), 0)
    dr = ImageDraw.Draw(big)
    c = size * k / 2
    r = cap * k / 2
    w = max(1.2, 0.13 * cap) * k
    if ch == "◎":
        dr.ellipse((c - r, c - r, c + r, c + r), fill=255)
        dr.ellipse((c - r + w, c - r + w, c + r - w, c + r - w), fill=0)
        q = r * 0.34
        dr.ellipse((c - q, c - q, c + q, c + q), fill=255)
    else:                                           # ×
        r *= 0.8
        dr.line((c - r, c - r, c + r, c + r), fill=255, width=int(w * 1.1))
        dr.line((c - r, c + r, c + r, c - r), fill=255, width=int(w * 1.1))
    small = np.asarray(big.resize((size, size), Image.BOX), dtype=np.float32)
    ink = np.rint(small * 6 / 255).astype(int)
    ys, xs = np.nonzero(ink)
    ink = ink[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    return ink, ink.shape[0] - (1 if ch == "×" else 0)


def _line(text, face, cap, squeeze, bold):
    import re
    items = []
    for tok in re.split("([◎×])", text):
        if not tok:
            continue
        if tok in "◎×":
            items.append(_symbol(tok, cap * 0.95, bold))
        else:
            lead, trail = len(tok) - len(tok.lstrip(" ")), len(tok) - len(tok.rstrip(" "))
            if tok.strip():
                ink, base = ui_type.ttf_ink(tok.strip(), face, cap, 0.0, squeeze, bold)
            else:
                ink, base = np.zeros((1, 0), int), 1
            items.append((np.pad(ink, ((0, 0), (round(lead * cap * 0.3), round(trail * cap * 0.3)))), base))
    up = max(b for _, b in items)
    down = max(i.shape[0] - b for i, b in items)
    w = sum(i.shape[1] for i, _ in items) + 2 * (len(items) - 1)
    out = np.zeros((up + down, w), int)
    x = 0
    for ink, base in items:
        out[up - base:up - base + ink.shape[0], x:x + ink.shape[1]] = ink
        x += ink.shape[1] + 2
    return out, up


class _Words(dict):
    def __init__(self, spec):
        a = spec.split(":")
        self.face, self.cap, self.sq, self.bold = a[0], int(a[1]), float(a[2]), float(a[3])
        self.pitch = int(a[4]) if len(a) > 4 else 0

    def __contains__(self, text):
        return True

    def __getitem__(self, text):
        lines = [_line(t, self.face, self.cap, self.sq, self.bold) for t in text.split("|")]
        if len(lines) == 1:
            return lines[0]
        pitch = self.pitch or self.cap + 6
        w = max(i.shape[1] for i, _ in lines)
        h = pitch * (len(lines) - 1) + lines[-1][0].shape[0] + max(b for _, b in lines)
        out = np.zeros((h, w), int)
        base_last = 0
        for k, (ink, base) in enumerate(lines):
            y = k * pitch + max(b for _, b in lines) - base
            out[y:y + ink.shape[0], :ink.shape[1]] = np.maximum(out[y:y + ink.shape[0], :ink.shape[1]], ink)
            base_last = y + base
        ys = np.nonzero(out.any(1))[0]
        out = out[ys.min():ys.max() + 1]
        return out, base_last - ys.min()


def _font(name):
    words = _Words(name[2:])
    return lambda project=None: {"words": words}


class _Fonts(dict):
    def __missing__(self, name):
        if name.startswith("d:"):
            return _font(name)
        raise KeyError(name)


def dfont(face, cap, squeeze=1.0, bold=0.4, pitch=0):
    return "d:%s:%d:%s:%s:%d" % (face, cap, squeeze, bold, pitch)

# scs_intr m3_syoukai
STYLES["d2_sy_title"] = ringfill([13, 12, 11, 9, 8], [2, 2, 15, 7], [4, 1])           # palette 12: orange letters, navy outline, white band
STYLES["d2_sy_hint"] = ringfill([2], [15], [9])                                                # palette 15: blue letters, white edge, lilac shadow
STYLES["d2_sy_label"] = ringfill([14, 13, 12, 11, 10], [1, 1], [4])                            # palette 5: yellow letters, navy outline
STYLES["d2_sy_t11"] = ringfill([2], [15], [4])                                              # palettes 26 / 22 / 23 / 25 / 24: coloured letters, white edge, blue shadow
STYLES["d2_sy_t12"] = ringfill([2], [15], [4])
STYLES["d2_sy_t13"] = ringfill([2], [15], [4])
STYLES["d2_sy_t14"] = ringfill([3], [15], [2])
STYLES["d2_sy_t15"] = ringfill([2], [15], [3])
STYLES["d2_sy_nodata"] = ringfill([4, 3], [15], [7])                                        # palette 14: grey-blue letters, white edge


def halved(style, part, offset, rows=16, total=32):
    """One horizontal band of a styled label: the art is laid on a canvas `total` rows high (`offset` empty rows above it) and
    band `part` (0 = top) of `rows` rows is returned, with the baseline at the band's foot. A label drawn in two parts that
    stand one above the other (the Japanese art is 32 rows high on two 16-row rectangles)."""
    def f(ink, base):
        art, b = style(ink, base)
        canvas = np.zeros((total, art.shape[1]), np.uint8)
        h = min(art.shape[0], total - offset)
        canvas[offset:offset + h] = art[:h]
        return canvas[part * rows:(part + 1) * rows], rows
    return f


def title_halves(name, style, offset):
    STYLES[name + "_top"] = halved(style, 0, offset)
    STYLES[name + "_bot"] = halved(style, 1, offset)

# the title of scs_intr: 29 rows of art, 1 empty row above it
STYLES["d2_sy_title_top"] = halved(STYLES["d2_sy_title"], 0, 1)
STYLES["d2_sy_title_bot"] = halved(STYLES["d2_sy_title"], 1, 1)

# orihen m3_sbn00
STYLES["d2_ori_head"] = ringfill([12, 13, 14, 15], [7, 7, 2], [4, 5])             # palette 4: green to yellow letters, blue outline, white band, lilac shadow
STYLES["d2_ori_hint"] = ringfill([11, 10, 9, 8], [2, 2], [4, 5])                  # palette 5: magenta to violet letters, white edge, lilac shadow
STYLES["d2_ori_ask"] = ringfill([3, 3, 2, 2, 1], [7, 7, 15], [11, 12])            # palette 10: orange to yellow letters, violet outline, white band, lilac shadow

# scs_grad z4_ls_0 (player directory)
STYLES["d2_ls_title"] = ringfill([8], [2, 1, 12, 12, 9], [])                    # palette 16: white letters, brown outline, orange band
STYLES["d2_ls_head"] = ringfill([2, 3, 4], [14, 13], [9])                      # palette 18: yellow letters, brown outline
STYLES["d2_ls_t14"] = ringfill([15], [4, 4, 3], [])                              # team plates: white letters, dark outline, one soft ring (palettes 35 red, 36 blue, 37 orange)
STYLES["d2_ls_t15"] = ringfill([15], [4, 4, 3], [])
STYLES["d2_ls_t16"] = ringfill([15], [4, 4, 3], [])

# scs_grad m3_stu
STYLES["d2_st_tag"] = ringfill([4, 3], [15], [9])                                      # palette 11: practice names, blue letters, white edge, grey-blue shadow
STYLES["d2_st_res"] = ringfill([5, 4, 3, 2], [15, 15], [])                                   # palette 23: results, seasons: dark violet letters, white edge
STYLES["d2_st_res1"] = ringfill([5, 4, 3, 2], [15], [])                                          # palette 23, small words: one white ring
STYLES["d2_st_ok"] = ringfill([7, 5, 4, 3, 2], [15], [])                               # palette 19: Success! pink to red
STYLES["d2_st_ng"] = ringfill([7, 6, 5, 4, 3], [15], [])                              # palette 20: Failure... blue
STYLES["d2_st_half"] = ringfill([7, 6, 5, 4, 3], [15], [])                            # palette 21: Half and Half? violet
STYLES["d2_st_none"] = ringfill([8, 5, 3, 2], [15], [])                               # palette 22: No Surgery, black to grey
STYLES["d2_st_r1"] = ringfill([14, 12, 9], [1, 15, 15], [8])                           # palette 6: 1st, pink gradient, navy outline, white band
STYLES["d2_st_r2"] = ringfill([14, 10, 7], [1, 15, 15], [])                            # palette 7: 2nd / 3rd orange
STYLES["d2_st_r4"] = ringfill([14, 11, 8], [1, 15, 15], [])                           # palette 8: 4th / 5th green
STYLES["d2_st_r6"] = ringfill([13, 11, 8], [1, 15, 15], [9])                           # palette 9: 6th cyan
STYLES["d2_st_r7"] = ringfill([13, 10, 8], [1, 15, 15], [7])                        # palette 10: 7th lavender
STYLES["d2_st_school"] = ringfill([3, 2, 2], [15, 14], [])                                   # palette 24: green letters, pale outline
STYLES["d2_st_head"] = ringfill([13, 12, 12, 10], [2, 2], [])                                 # palette 5: yellow letters, navy outline
STYLES["d2_st_single"] = ringfill([2, 3], [15], [9])                                           # palette 18: navy letters, white edge


# ==== registry (keep last) ============================================================================================================

# ---- "cut" styles: a label drawn on a canvas the size of the Japanese art, and one piece of it --------------------------------
# "cut:<style>:<W>:<H>:<ax>:<ay>:<x>:<y>:<w>:<h>": the styled art is laid on a W x H canvas (ax = left column, or c for centred;
# ay = top row) and the w x h piece at (x, y) is returned, baseline at its foot. Every part of a Japanese label that is made
# of several rectangles (some of them shared with other sprites) is re-pointed at its own piece, so the lettering keeps the
# geometry of the original sprites and every sprite that shows the rectangles follows.
def _cut(base, W, H, ax, ay, x, y, w, h):
    def style(ink, base_row):
        art, b = base(ink, base_row)
        canvas = np.zeros((H, W), np.uint8)
        ox = (W - art.shape[1]) // 2 if ax == "c" else int(ax)
        oy = int(ay)
        sx0, sy0 = max(-ox, 0), max(-oy, 0)
        dx0, dy0 = max(ox, 0), max(oy, 0)
        cw, ch = min(art.shape[1] - sx0, W - dx0), min(art.shape[0] - sy0, H - dy0)
        if cw > 0 and ch > 0:
            canvas[dy0:dy0 + ch, dx0:dx0 + cw] = art[sy0:sy0 + ch, sx0:sx0 + cw]
        return canvas[y:y + h, x:x + w], h
    return style


def _cut_style(name, table):
    a = name.split(":")
    return _cut(table[a[1]], int(a[2]), int(a[3]), a[4], a[5], int(a[6]), int(a[7]), int(a[8]), int(a[9]))


class _Styles(dict):
    def __missing__(self, name):
        if name.startswith("cut:"):
            st = self[name] = _cut_style(name, self)
            return st
        raise KeyError(name)


def enable_lazy():
    """For the generators: styles "cut:..." and fonts "d:..." are made on first use. (The files that use them are written as specs, and
    _register below makes them known when pp15/art/typeset.py is imported, so nothing is replaced in pp15/art/typeset.py for anyone else.)"""
    if not isinstance(ui_type.RENDER, _Styles):
        ui_type.RENDER = _Styles(dict(ui_type.RENDER, **STYLES))
    if not isinstance(ui_type.FONTS, _Fonts):
        ui_type.FONTS = _Fonts(ui_type.FONTS)


def _register():
    """Every "cut:" style and "d:" font a spec of this run uses is registered as a plain entry (pp15/art/typeset.py loads this file before it
    applies a spec)."""
    import json, os
    for stem in ("scs_grad", "scs_titl", "scs_open", "scs_intr", "orihen"):
        path = os.path.join(config.SPECS_DIR, stem + ".json")
        if not os.path.exists(path):
            continue
        try:
            spec = json.load(open(path))
        except Exception:
            continue
        for g in spec.get("repack", ()):
            for lab in g.get("labels", ()) + [g]:
                st, font = lab.get("style"), lab.get("font")
                if isinstance(st, str) and st.startswith("cut:") and st not in STYLES:
                    try:
                        STYLES[st] = _cut_style(st, STYLES)
                    except KeyError:
                        pass
                if isinstance(font, str) and font.startswith("d:") and font not in ui_type.FONTS:
                    ui_type.FONTS[font] = _font(font)


_register()


# ---- scs_end.arc: end of a Success game ------------------------------------------------------------------------------

def rpad(style, w):
    def cut(ink, base):
        art, b = style(ink, base)
        out = np.zeros((art.shape[0], max(w, art.shape[1])), np.uint8)
        out[:, out.shape[1] - art.shape[1]:] = art
        return out, b
    return cut


def win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


def windows(name, step=8, top=392):
    for c0 in range(0, top + 1, step):
        for c1 in list(range(c0 + step, top + 1, step)) + [4096]:
            STYLES["%s~%d_%d" % (name, c0, c1)] = win(STYLES[name], c0, c1)


# m4_stt01 / m4_stt00 team names, forms, drop-down lists (palettes 27, 2): white letters, thick navy outline
STYLES["a_name"] = ringfill([15], [1, 1], [])
# y5_sss_1 names, forms, items (palettes 35, 46): white letters, blue and dark blue rings
STYLES["a_y5name"] = ringfill([15], [5, 1], [])
# m4_stt01 08 colour lines (palette 4): yellow letters, blue rings, right-aligned in 192 columns
STYLES["a_eqm_u"] = ringfill([14, 14, 13, 12], [1], [])
STYLES["a_name1"] = ringfill([15], [1], [])
STYLES["a_eqm"] = rpad(STYLES["a_eqm_u"], 200)
# y5_sss_1 35-38 (palette 41): yellow letters, blue rings
STYLES["a_eqy"] = ringfill([1, 1, 2, 3], [15, 14, 13], [])


# m4_stt00 menu buttons (palettes 17-25): coloured letters, white ring, dark blue shadow cast down and right
for _pal, _fill in {17: [5], 18: [5], 19: [3], 20: [3], 21: [4], 22: [5], 23: [4], 24: [1], 25: [2]}.items():
    STYLES["a_btn%d" % _pal] = ringfill(_fill, [14, 14], [3, 2, 1])
# thin black pixel-font items: m4_stt00 (palette 5, cream), y5_sss_0 (palette 32, grey ramp), tags on the tan tabs (palette 19)
STYLES["a_thin5"] = flat([0, 7, 5, 3, 2, 1, 1])
STYLES["a_thin32"] = flat([0, 4, 7, 10, 12, 14, 15])
STYLES["a_tab19"] = flat([0, 12, 9, 6, 4, 2, 1])
# y5_sss_0 (palette 16 title, 28 buttons): blue and white lettering
STYLES["a_y5title"] = ringfill([15, 15, 14, 13, 12, 11], [6, 3, 2], [1])
STYLES["a_y5btn"] = ringfill([3, 2, 2, 2], [15], [9])


# z3_sav_0: title (palette 28), buttons 終了 / 登録 (37, 38), プロ入り選手 (45; 14 draws its dark copy), パスワードを見る and
# 能力詳細 (44, a grey ramp), the two panel headings (47 orange, 46 lilac; palette 31 draws each again as a blue shadow)
STYLES["a_z3title"] = ringfill([10, 10, 7, 7, 6, 4], [15, 15, 3, 2], [1])
STYLES["a_z3end"] = ringfill([13, 12, 12, 11], [8, 7, 14], [6])
STYLES["a_z3reg"] = ringfill([9, 10, 11, 12], [14, 13, 1], [3])
STYLES["a_z3pro"] = ringfill([3, 2, 1, 1], [11, 11], [9, 8])
STYLES["a_z3pw"] = ringfill([2], [15], [])
STYLES["a_z3det"] = ringfill([15], [2], [])
STYLES["a_z3new"] = ringfill([1, 1, 2, 3, 4], [8, 9, 12, 13], [])
STYLES["a_z3del"] = ringfill([1, 2, 3, 4, 5], [8, 9, 10, 12], [])


def stamp(size=40):
    """The 済 stamp (palette 33): a round red seal, pale rim, white inside; the word is set in red in the middle."""
    def style(ink, base):
        out = np.zeros((size, size), np.uint8)
        c = (size - 1) / 2.0
        yy, xx = np.mgrid[0:size, 0:size]
        r = np.hypot(yy - c, xx - c)
        out[r <= c + 0.5] = 12
        out[r <= c - 0.5] = 2
        out[r <= c - 3.5] = 7
        out[r <= c - 4.5] = 15
        h, w = ink.shape
        y0 = (size - h) // 2 + 1
        x0 = (size - w) // 2
        ramp = np.array([0, 7, 5, 3, 2, 1, 1], np.uint8)
        sub = out[y0:y0 + h, x0:x0 + w]
        sub[ink > 0] = ramp[ink[ink > 0]]
        return out, y0 + base
    return style


STYLES["a_stamp"] = stamp()


def rows_win(style, r0, r1):
    """Rows r0..r1 of the whole word (lettering painted into a picture that is cut over two pages)."""
    def cut(ink, base):
        art, b = style(ink, base)
        return art[r0:r1], b - r0
    return cut


def crisp(fill, shadow=None, edge=3, depth=1):
    """Solid letters (ink at `edge` or more -> fill), a one-pixel `shadow` down and to the right; no soft edge."""
    def style(ink, base):
        pad = depth + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big >= edge
        out = np.zeros(big.shape, np.uint8)
        if shadow is not None:
            for k in range(1, depth + 1):
                out[shift(letters, k, k)] = shadow
        out[letters] = fill
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base + pad - ys.min()
    return style


def nothing(ink, base):
    return np.zeros((1, 1), np.uint8), 0


# m4_stt00 profile card (palette 6): tags white on brown with a dark shadow, the heading white in brown rings
STYLES["a_none"] = nothing
STYLES["a_tag"] = crisp(15, 2, 3)
STYLES["a_cardhead"] = ringfill([15], [4, 3], [6])
for _name in ("a_tag", "a_cardhead"):
    for _r0 in range(0, 27):
        for _r1 in range(_r0 + 1, 28):
            STYLES["%s~%d_%d" % (_name, _r0, _r1)] = rows_win(STYLES[_name], _r0, _r1)


# m4_drf / y5_drf_0: the draft result screens. Help lines: m4 (palette 3) dark blue letters in a white band, y5 (27) green letters in a
# white band; the two-line help on the pale plate: m4 (3) dark blue, y5 (22) blue; banners: m4_df256 (8-bit palette) and y5_drf_0 (29)
STYLES["a_help_m1"] = ringfill([3], [15], [])
STYLES["a_help_m2"] = crisp(1, None, 3)
STYLES["a_help_y1"] = ringfill([6, 5, 4, 3], [15, 14], [])
STYLES["a_help_y2"] = crisp(1, None, 3)
STYLES["a_ban_y5"] = ringfill([12, 12, 11, 13, 14, 15], [7, 7, 4, 3], [2])
STYLES["a_ban_m"] = ringfill([146, 139, 125, 115, 84, 72, 52], [255, 255, 109, 7], [106, 104])
windows("a_help_m2")
windows("a_help_y2")

# m4_stt00 drop-down lists 3a / 3e (palette 2): small navy letters on the pale plate
STYLES["a_drop"] = crisp(1, None, 3)
