"""Label styles of art run 2, agent D (scs_open fiction notice, scs_grad graduation, orihen ball naming, scs_intr
scenario introduction, scs_titl start screen). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# scs_open z3_fic_0 (palette 0, grey ramp): white letters, a grey soft edge, black outline, dark blue-grey shadow
STYLES["d2_fic"] = ringfill([0xf], [0xb, 4], [3, 2])

ui_type.TTF["d_georgia"] = ("/System/Library/Fonts/Supplemental/Georgia Bold.ttf", 0)
ui_type.TTF["d_times"] = ("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf", 0)
ui_type.TTF["d_georgiai"] = ("/System/Library/Fonts/Supplemental/Georgia Bold Italic.ttf", 0)
ui_type.TTF["d_impact"] = ("/System/Library/Fonts/Supplemental/Impact.ttf", 0)

# scs_titl r4_staz (8-bit, palette 16): the three buttons. Gradient letters, a thin dark outline, a white band, a blue
# shadow to the lower right (orange / lime / green fill; each has its own run of palette entries)
STYLES["d2_staz_new"] = ringfill([1, 2, 3, 4, 6, 5, 9, 11], [25, 57, 57, 35], [35, 35])
STYLES["d2_staz_cont"] = ringfill([166, 168, 169, 170, 171, 175, 176], [129, 181, 181, 152], [152, 152])
STYLES["d2_staz_list"] = ringfill([215, 216, 218, 221, 226, 229], [240, 210, 210, 193], [193, 193])


# ---- a text font of this file: "d:<face>:<cap>:<squeeze>:<bold>[:<pitch>]" -------------------------------------------------
# Lines are separated by "|" and left aligned, `pitch` rows apart (baseline to baseline); a line may hold the symbols
# ◎ and × (drawn here, no font has them in this style) between words; everything else is ui_type.ttf_ink.
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


class _Fonts(dict):
    def __missing__(self, name):
        if name.startswith("d:"):
            words = _Words(name[2:])
            return lambda project=None: {"words": words}
        raise KeyError(name)


if not isinstance(ui_type.FONTS, _Fonts):
    ui_type.FONTS = _Fonts(ui_type.FONTS)


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
STYLES["d2_st_res"] = ringfill([5, 4, 3, 2], [15, 15], [10])                                   # palette 23: results, seasons: dark violet letters, white edge
STYLES["d2_st_res1"] = ringfill([5, 4, 3, 2], [15], [])                                          # palette 23, small words: one white ring
STYLES["d2_st_ok"] = ringfill([7, 5, 4, 3, 2], [15, 15, 9], [1])                               # palette 19: Success! pink to red
STYLES["d2_st_ng"] = ringfill([7, 6, 5, 4, 3], [15, 15, 13], [1])                              # palette 20: Failure... blue
STYLES["d2_st_half"] = ringfill([7, 6, 5, 4, 3], [15, 15, 11], [1])                            # palette 21: Half and Half? violet
STYLES["d2_st_none"] = ringfill([8, 5, 3, 2], [15, 15, 11], [7])                               # palette 22: No Surgery, black to grey
STYLES["d2_st_r1"] = ringfill([14, 12, 9], [1, 15, 15], [8])                           # palette 6: 1st, pink gradient, navy outline, white band
STYLES["d2_st_r2"] = ringfill([14, 10, 7], [1, 15, 15], [])                            # palette 7: 2nd / 3rd orange
STYLES["d2_st_r4"] = ringfill([14, 11, 8], [1, 15, 15], [])                           # palette 8: 4th / 5th green
STYLES["d2_st_r6"] = ringfill([13, 11, 8], [1, 15, 15], [9])                           # palette 9: 6th cyan
STYLES["d2_st_r7"] = ringfill([13, 10, 8], [1, 15, 15], [7])                        # palette 10: 7th lavender
STYLES["d2_st_school"] = ringfill([14, 13], [4, 3], [1])                                       # palette 24: pale letters, green outline
STYLES["d2_st_head"] = ringfill([13, 12, 12, 10], [2, 2], [6])                                 # palette 5: yellow letters, navy outline
STYLES["d2_st_single"] = ringfill([2, 3], [15], [9])                                           # palette 18: navy letters, white edge

# ==== registry (keep last): the cut styles are made on demand; ui_type's loader updates RENDER only after this file is imported, so STYLES is merged here

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


class _Styles(dict):
    def __missing__(self, name):
        if name.startswith("cut:"):
            a = name.split(":")
            st = _cut(self[a[1]], int(a[2]), int(a[3]), a[4], a[5], int(a[6]), int(a[7]), int(a[8]), int(a[9]))
            self[name] = st
            return st
        raise KeyError(name)




if not isinstance(ui_type.RENDER, _Styles):
    ui_type.RENDER = _Styles(dict(ui_type.RENDER, **STYLES))
