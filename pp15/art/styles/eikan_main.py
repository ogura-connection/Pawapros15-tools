"""Styles for the main screens of Eikan Nine, the Success Mode scenario in which you manage a high-school baseball team.

The player sees the main screen with its calendar, the date card and weekday cells, the school and card screens, and the inning card of the practice game.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): sct_main, sct_sugo, sct_a_sc, sct_card, gdt_sct, sct_a_pd, school_g, order, sct_a_ed, sct_comd, sip_comm, sct_a_it, sct_a_od, sct_a_ar.
"""
import numpy as np
import os as _os
from PIL import Image, ImageDraw, ImageFont
from pp15 import config
from pp15.art.typeset import grow, shift
from pp15.art import typeset as ui_type
from pp15.art import textures as _U
from .common import ringfill

STYLES = {}


# ---- sct_main.arc, gdt_sct.arc, sct_a_sc.arc, sct_a_it.arc, sct_sugo.arc ---------------------------------------------

ui_type.TTF["d4narrow"] = ("/System/Library/Fonts/Supplemental/Arial Narrow.ttf", 0)       # regular weight, for the thin black lettering
ui_type.TTF["d4hand"] = ("/System/Library/Fonts/Supplemental/Bradley Hand Bold.ttf", 0)           # the manager's handwriting
ui_type.TTF["d4uni"] = ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0)             # has the circle and the circled plus of the button hints
ui_type.TTF["d4tahoma"] = ("/System/Library/Fonts/Supplemental/Tahoma.ttf", 0)

# ---- sct_main z5_emj_0 (scout window labels) -----------------------------------------------------------------------------
STYLES["d4_emj_head"] = ringfill([1, 1, 2, 3, 4, 5], [15, 15], [11, 10])          # pal 23: violet ramp, white ring, pale blue glow
STYLES["d4_emj_word"] = ringfill([15, 15, 15, 15, 14, 13], [4, 4, 3], [2, 1])      # pal 18: white letters, navy ring, blue glow


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    import numpy as np

    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


def windows(name):
    """STYLES[name~c0_c1] for every c0, c1 on the 16-column grid (and 4096 = to the end): what Bank.window_n asks for."""
    base = STYLES[name]
    for step, top in ((16, 192), (8, 96)):
        for c0 in range(0, top, step):
            for c1 in list(range(c0 + step, top + 16, step)) + [4096]:
                STYLES["%s~%d_%d" % (name, c0, c1)] = win(base, c0, c1)

# ---- sct_main z5_esr_0 (growth report) ------------------------------------------------------------------------------------
STYLES["d4_esr_name"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4], [3, 2, 1])       # pal 32 / 34 / 35 / 36 share the index roles
STYLES["d4_esr_title"] = ringfill([15, 15, 15, 15, 15, 15], [11, 8, 5])              # pal 22 (and the black copy, pal 18)
STYLES["d4_esr_trust"] = ringfill([2, 2, 1, 1, 3, 5], [8], [10, 12])                 # pal 23: dark green, white ring, teal glow
for _n in ("d4_esr_name", "d4_esr_title"):
    windows(_n)


def plain(dark, mid=None, edge=3):
    """Flat dark lettering (the player info window, black on a white panel): solid `dark` where the ink is at least `edge`,
    `mid` for the thinner edge (None: nothing)."""
    import numpy as np

    def style(ink, base):
        out = np.zeros(ink.shape, np.uint8)
        out[ink >= edge] = dark
        if mid is not None:
            out[(ink > 0) & (ink < edge)] = mid
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


# ---- sct_main z4_edsm_0 (player info window): pal 24, black ramp f (black) .. 1 (near white) ----------------------------------
STYLES["d4_edsm"] = plain(15, 8)
windows("d4_edsm")

# ---- sct_main logos (4-bit pages, big letters: fill ramp, dark inner rings, white ring, shadow) ------------------------------
STYLES["d4_efd"] = ringfill([15, 14, 14, 13, 12, 11], [8, 7, 5, 3, 1], [1, 1])               # pal 0: silver-white, teal, near-black
STYLES["d4_efk"] = ringfill([7, 8, 9, 10, 11, 11], [13, 12, 1, 1], [3, 3, 3, 4])             # pal 2: yellow to orange, dark red, white, violet shadow
STYLES["d4_efc"] = ringfill([13, 9, 9, 10, 11, 12], [3, 3, 15, 15], [1, 2, 2, 1])            # pal 4: pale to deep cyan, blue, white, navy shadow

# ---- gdt_sct.arc (Eikan Nine match screen) -------------------------------------------------------------------------------------
STYLES["d4_gm20"] = ringfill([15, 15, 15, 14, 13, 12], [4, 3])                  # z4_gm_0 pal 20: white letters, black ring
STYLES["d4_gm22"] = ringfill([15, 15, 15, 14, 13, 12], [1])                         # z4_gm_0 pal 22: white letters, black ring (stats headings)
STYLES["d4_gmt"] = ringfill([15, 15, 14, 13, 12, 11], [4, 3], [2, 1])                  # z5_gmt_0 pal 20: yellow letters, olive and dark green rings
STYLES["d4_gmu"] = ringfill([15, 15, 14, 13, 12, 11], [7, 4, 4, 2])                    # z5_gmu_0 pal 20 / 21: white letters, blue (red) rings; the black layer behind is a copy
STYLES["d4_gmh"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4, 2])                       # z5_gmu_0 sprite 00 (pal 23): white letters, dark ring
STYLES["d4_gms"] = ringfill([2, 2, 1, 1, 3, 5], [8], [10, 12])                         # z5_gmu_0 06 / 07 (pal 18): dark green letters, white ring
windows("d4_gmu")
windows("d4_gm20")
windows("d4_gm22")

# ---- sct_a_sc.arc (schedule, manager's memo) / sct_a_it.arc / sct_sugo.arc ------------------------------------------------------
STYLES["d4_edy_head"] = plain(15, 11)                                # z4_edy_0 pal 24: grey letters (ramp 1 light .. f dark)
def padded(style, n):
    """The styled art with `n` clear rows / columns round it (a margin the sprite's parts keep: nothing touches a part edge)."""
    import numpy as np

    def make(ink, base):
        art, b = style(ink, base)
        return np.pad(art, n), b + n
    return make


STYLES["d4_edy_month"] = padded(plain(15, 9, edge=4), 1)                  # pal 25: black letters, 1 clear px round them
STYLES["d4_hint"] = ringfill([15, 15, 14, 13, 12, 10], [4, 4], [3, 2, 1])      # z4_ekk_0 pal 24: white letters, dark green-grey ring, pale glow


def memo(ink, base):
    """z5_edm_0: the manager's handwriting, one colour ramp (index 15 strongest .. 1 faintest)."""
    import numpy as np
    out = np.zeros(ink.shape, np.uint8)
    for lv, ix in ((2, 8), (4, 15)):
        out[ink >= lv] = ix
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


STYLES["d4_memo"] = memo
STYLES["d4_edi_title"] = ringfill([8, 8, 9, 11, 13, 15], [4, 2, 1])            # z4_edi_0 pal 18: white to teal, blue rings
STYLES["d4_edi_owned"] = ringfill([15, 15, 14, 13, 12, 11], [4, 3], [2, 1])    # pal 24: white letters, navy ring, blue glow
STYLES["d4_etk"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1, 1, 1])               # z4_etk_0: big white italic letters, black ring
for _n in ("d4_edy_head", "d4_edy_month", "d4_hint", "d4_memo", "d4_edi_owned"):
    windows(_n)


# ---- school_g.arc, sct_card.arc, sct_comd.arc, sct_a_ed.arc, sct_a_od.arc --------------------------------------------

ui_type.TTF["e4uni"] = ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0)       # has the star of the help line


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    import numpy as np

    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

# ---- sct_a_od.arc (Eikan Nine order screen) -----------------------------------------------------------------------------
STYLES["e4_od_title"] = ringfill([15, 15, 15, 15, 13, 12], [4, 4, 3, 2])             # pal 40: white, navy rings, blue glow
STYLES["e4_od_cancel"] = ringfill([12, 12, 11, 11, 8, 3], [15, 15, 5], [7, 9])         # pal 35: lavender, white ring, blue glow
STYLES["e4_od_blue"] = ringfill([15, 15, 15, 14, 13, 12], [1])                      # pal 20: white, blue ring

# ---- sct_a_ed.arc (graduates screen) ------------------------------------------------------------------------------------
STYLES["e4_ed_title"] = ringfill([15, 14, 13, 12, 11, 10], [5, 5, 1, 1], [2])          # pal 0: gold, near-black ring, blue ring
STYLES["e4_ed_gold"] = ringfill([15, 14, 13, 11, 9, 7], [1, 1], [2])                   # pal 1: olive-gold brush, black ring
STYLES["e4_ed_gold~0_8"] = win(STYLES["e4_ed_gold"], 0, 8)
STYLES["e4_ed_gold~8_4096"] = win(STYLES["e4_ed_gold"], 8, 4096)

# ---- sct_comd.arc (team strength screen) ---------------------------------------------------------------------------------
STYLES["e4_cd_abil"] = ringfill([15, 15, 15, 14, 13, 12], [4], [3, 2])                 # pal 24: white letters, black ring, grey shadow
STYLES["e4_cd_year"] = ringfill([4, 3, 3, 2, 2, 2], [8, 11])                           # pal 17-19 / 4: coloured digits, white ring, pale glow

# ---- school_g.arc (Baseball School) --------------------------------------------------------------------------------------
# the lesson plates: white letters, navy ring, blue shadow; the same indices serve the blue / red / teal / purple palettes (10-13)
STYLES["e4_sg_btn"] = ringfill([15, 15, 15, 15, 14, 14], [8, 7], [5, 3, 2])
STYLES["e4_sg_head"] = ringfill([15, 15, 15, 15, 15, 15], [6, 3])                       # pal 15: white letters, green ring
STYLES["e4_sg_small"] = ringfill([15, 15, 15, 15, 15, 15], [6])                         # pal 15: score panel words


def plate(style, w, h, bg):
    """The styled word centred on a plain plate of index `bg` (at least w x h): lettering that is part of a solid plate."""
    import numpy as np

    def make(ink, base):
        art, b = style(ink, base)
        H, W = max(h, art.shape[0]), max(w, art.shape[1])
        out = np.full((H, W), bg, np.uint8)
        oy, ox = (H - art.shape[0]) // 2, (W - art.shape[1]) // 2
        sub = out[oy:oy + art.shape[0], ox:ox + art.shape[1]]
        sub[art > 0] = art[art > 0]
        return out, b + oy
    return make


# pal 14: Start Practice on a black plate (index 1), white letters
STYLES["e4_sg_start"] = plate(ringfill([15, 15, 15, 14, 14, 13], [6]), 80, 24, 1)
STYLES["e4_sg_start_t"] = ringfill([15, 15, 15, 14, 14, 13], [6])                      # the same letters without the plate (for measuring)


def vcut(style, lo, hi, H, W):
    """The styled word centred on an H x W canvas, then only its rows lo..hi (a word cut across two page rectangles stacked
    on top of each other: the pieces of クリア). The canvas rows below the word stay empty (0)."""
    import numpy as np

    def make(ink, base):
        art, b = style(ink, base)
        out = np.zeros((H, W), np.uint8)
        oy, ox = (H - art.shape[0]) // 2, (W - art.shape[1]) // 2
        out[oy:oy + art.shape[0], ox:ox + art.shape[1]] = art[:H, :W]
        return out[lo:hi], b + oy - lo
    return make


# クリア (p16 y98-128 + p17 y96-108, one 42-row word): "Clear" 96 x 42
STYLES["e4_sg_clear_0"] = vcut(STYLES["e4_sg_head"], 0, 30, 42, 96)
STYLES["e4_sg_clear_1"] = vcut(STYLES["e4_sg_head"], 30, 42, 42, 96)

# ---- sct_card.arc (Eikan Nine command cards) -----------------------------------------------------------------------------
STYLES["e4_em_item"] = ringfill([15, 15, 15, 15, 12, 11], [6, 1])                      # pal 84: white letters, blue ring
STYLES["e4_em_item1"] = ringfill([15, 15, 15, 15, 12, 11], [1])                        # the same with a one-pixel ring (two lines in 24 rows)

# the 80x24 command buttons (pal 24) and the small cards / cross icon (pal 114): white letters, dark blue ring, teal glow
STYLES["e4_em_card"] = ringfill([15, 15, 15, 14, 13, 12], [4, 3], [2])
# the "(The more ...)" help line (pal 42) and the "Ability Details" help pieces (pal 9): white letters, dark rim, grey shadow
STYLES["e4_em_help"] = ringfill([14, 14, 14, 13, 12, 11], [4, 4], [5])
STYLES["e4_em_help2"] = ringfill([14, 14, 14, 13, 12, 11], [1, 1], [3, 4])
# words cut over side-by-side page rectangles (window_n): the styles "<style>~c0_c1"
for _n, _cuts in (("e4_em_card", [(0, 32), (32, 4096)]), ("e4_em_help", [(0, 128), (128, 256), (256, 4096)]),
                  ("e4_em_help2", [(0, 32), (32, 4096)])):
    for _c0, _c1 in _cuts:
        STYLES["%s~%d_%d" % (_n, _c0, _c1)] = win(STYLES[_n], _c0, _c1)


# ---- sct_sugo.arc: the big Eikan date card (second z4_emp_0 bank) ----------------------------------------------------

NARROW_I = "/System/Library/Fonts/Supplemental/Arial Narrow Bold Italic.ttf"
WHITE, EDGE, SH1, SH2 = 15, 8, 5, 3


def _cov(text, cap, over=4, squeeze=1.0):
    probe = ImageFont.truetype(NARROW_I, 400)
    bb = probe.getbbox("H")
    f = ImageFont.truetype(NARROW_I, round(400 * cap * over / (bb[3] - bb[1])))
    l, t, r, b = f.getbbox(text, anchor="ls")
    W, H = r - l + 8 * over, (cap + 8) * over
    img = Image.new("L", (W, H), 0)
    ImageDraw.Draw(img).text((4 * over - l, (cap + 3) * over), text, fill=255, font=f, anchor="ls")
    if squeeze != 1:
        img = img.resize((round(W * squeeze), H), Image.BICUBIC)
    W, H = (img.width // over) * over, (img.height // over) * over
    a = np.asarray(img.crop((0, 0, W, H)).resize((W // over, H // over), Image.BOX), np.float32)
    ys, xs = np.nonzero(a > 127)
    return a[ys.min():ys.max() + 1, xs.min():xs.max() + 1] > 127


def _grow(m, n):
    p = np.pad(m, n)
    out = np.zeros_like(p)
    for dy in range(-n, n + 1):
        for dx in range(-n, n + 1):
            out |= np.roll(np.roll(p, dy, 0), dx, 1)
    return out[n:-n, n:-n] if n else out


def lettering(text, cap, squeeze=1.0, edge=1):
    """white italic letters, black outline `edge` px, soft dark shadow down-right: index array"""
    m = _cov(text, cap, squeeze=squeeze)
    pad = edge + 8
    m = np.pad(m, pad)
    ring = _grow(m, edge)
    sh = np.roll(np.roll(_grow(ring, 1), 2, 0), 1, 1)
    sh2 = np.roll(np.roll(_grow(ring, 2), 2, 0), 1, 1)
    out = np.zeros(m.shape, np.uint8)
    out[sh2] = SH2
    out[sh] = SH1
    out[ring] = EDGE
    out[m] = WHITE
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1]


def fit(text, w, h, caps, squeeze=1.0):
    for cap in caps:
        a = lettering(text, cap, squeeze)
        if a.shape[1] <= w and a.shape[0] <= h:
            return a
    raise ValueError((text, w, h))


def put(art, w, h, valign):
    cell = np.zeros((h, w), np.uint8)
    ah, aw = art.shape
    x = (w - aw) // 2
    y = {"bottom": h - ah, "center": (h - ah) // 2}[valign]
    cell[y:y + ah, x:x + aw] = art
    return cell


UNITS = {"mo": "Mo", "day": "Day"}
WEEK = {"04": "Mon", "05": "Tue", "06": "Wed", "07": "Thu", "08": "Fri", "09": "Sat", "0a": "Sun"}

def common_cap(texts, w, h, caps, sq=1.0):
    """the largest cap height at which every text fits, so the set shares one letter size"""
    for cap in caps:
        if all(lettering(t, cap, sq).shape[1] <= w and lettering(t, cap, sq).shape[0] <= h for t in texts):
            return cap
    raise ValueError(texts)


CELLS = {}
SQ = 0.85
UCAP = common_cap(["Mo", "Day"], 40, 40, range(26, 8, -1), SQ)
CELLS["mo"] = put(lettering("Mo", UCAP, SQ), 40, 40, "bottom")
CELLS["day"] = put(lettering("Day", UCAP, SQ), 40, 40, "bottom")
WCAP = common_cap(list(WEEK.values()), 48, 48, range(30, 8, -1), SQ)
for sp, t in WEEK.items():
    CELLS[sp] = put(lettering(t, WCAP, SQ), 48, 48, "center")

# sprites 07 / 08 draw their 48 x 48 cell as two parts: the top 16 rows (page 3) and the next 32 rows (page 4)
for sp in ("07", "08"):
    full = CELLS[sp]
    CELLS[sp + "_a"] = full[:16].copy()
    CELLS[sp + "_b"] = full[16:].copy()


def _fixed(arr):
    def style(ink, base):
        return arr.copy(), 0
    return style


for k, a in CELLS.items():
    STYLES["dd_" + k] = _fixed(a)


# sct_a_ar.arc z4_ed_0#1 page 0, palette 15: "グラウンド LV." strip (sprite 1d, 80 x 24): white letters, black outline, dark shadow
def ground_label(text="Ground Lv.", w=80, h=24):
    probe = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf", 400)
    bb = probe.getbbox("H")
    over = 4
    for cap in range(15, 7, -1):
        f = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf", round(400 * cap * over / (bb[3] - bb[1])))
        l, t, r, b = f.getbbox(text, anchor="ls")
        img = Image.new("L", ((r - l) + 8 * over, (cap + 8) * over), 0)
        ImageDraw.Draw(img).text((4 * over - l, (cap + 3) * over), text, fill=255, font=f, anchor="ls")
        W, H = (img.width // over) * over, (img.height // over) * over
        a = np.asarray(img.crop((0, 0, W, H)).resize((W // over, H // over), Image.BOX), np.float32) > 127
        ys, xs = np.nonzero(a)
        m = np.pad(a[ys.min():ys.max() + 1, xs.min():xs.max() + 1], 4)
        ring = _grow(m, 1)
        shadow = np.roll(np.roll(ring, 1, 0), 1, 1)
        out = np.zeros(m.shape, np.uint8)
        out[shadow] = 3
        out[ring] = 1
        out[m] = 15
        ys, xs = np.nonzero(out)
        out = out[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
        if out.shape[1] <= w - 2 and out.shape[0] <= h - 2:
            cell = np.zeros((h, w), np.uint8)
            oh, ow = out.shape
            x0, y0 = 2, (h - oh) // 2
            cell[y0:y0 + oh, x0:x0 + ow] = out
            return cell
    raise ValueError(text)


STYLES["dd_ground"] = _fixed(ground_label())


# order.arc g3_od#1 page 0 (8-bit, own palette): 先攻 / 後攻 / 対 of the lineup header -> Away / Home / VS.
# Pictures are built in RGBA (gradient letters, rings) and snapped to the page palette.

_ORDER_PAL = {}


def _order_palette():
    if not _ORDER_PAL:
        p = _os.path.join(config.ORIG_ARC_DIR, "order.arc")
        d = open(p, "rb").read()
        b = _U.banks(d, _U.elf_symbols(d))[1]
        cols = _U.page_colours(_U.palette_colours(d, b["pal"]), 0, _U.raw_size(d, *b["pages"][0]))
        _ORDER_PAL["c"] = cols.astype(int)
    return _ORDER_PAL["c"]


ROUND = "/System/Library/Fonts/Supplemental/Arial Rounded Bold.ttf"


def _mask(text, cap, path=ROUND, over=4):
    probe = ImageFont.truetype(path, 400)
    bb = probe.getbbox("H")
    f = ImageFont.truetype(path, round(400 * cap * over / (bb[3] - bb[1])))
    l, t, r, b = f.getbbox(text, anchor="ls")
    img = Image.new("L", ((r - l) + 8 * over, (cap + 10) * over), 0)
    ImageDraw.Draw(img).text((4 * over - l, (cap + 4) * over), text, fill=255, font=f, anchor="ls")
    W, H = (img.width // over) * over, (img.height // over) * over
    a = np.asarray(img.crop((0, 0, W, H)).resize((W // over, H // over), Image.BOX), np.float32) > 127
    ys, xs = np.nonzero(a)
    return a[ys.min():ys.max() + 1, xs.min():xs.max() + 1]


def _header(text, cap, top, bottom, rings, shadow, w, h, dy=0):
    """rings = [(colour, px)] outward from the letters; shadow colour one pixel down-right of the outermost ring"""
    m = _mask(text, cap)
    pad = sum(px for _, px in rings) + 3
    m = np.pad(m, pad)
    H, W = m.shape
    rgba = np.zeros((H, W, 4), int)
    reach, grown = 0, []
    for c, px in rings:
        reach += px
        grown.append((c, _grow(m, reach)))
    out_ring = grown[-1][1]
    sh = np.roll(np.roll(out_ring, 1, 0), 1, 1)
    rgba[sh] = list(shadow) + [255]
    for c, g in reversed(grown):
        rgba[g] = list(c) + [255]
    ys, xs = np.nonzero(m)
    y0, y1 = ys.min(), ys.max()
    for y in range(y0, y1 + 1):
        t = (y - y0) / max(1, y1 - y0)
        col = [round(top[k] + (bottom[k] - top[k]) * t) for k in range(3)] + [255]
        rgba[y][m[y]] = col
    ys, xs = np.nonzero(rgba[..., 3])
    rgba = rgba[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    pal = _order_palette()
    opaque = np.nonzero(pal[:, 3] > 0)[0]
    flat = rgba.reshape(-1, 4)
    idx = np.zeros(len(flat), np.uint8)
    for i, px in enumerate(flat):
        if px[3]:
            d = ((pal[opaque, :3] - px[:3]) ** 2).sum(1)
            idx[i] = opaque[int(d.argmin())]
    idx = idx.reshape(rgba.shape[:2])
    ih, iw = idx.shape
    if iw > w or ih > h:
        raise ValueError((text, iw, ih, w, h))
    cell = np.zeros((h, w), np.uint8)
    x0, yy = (w - iw) // 2, (h - ih) // 2 + dy
    cell[yy:yy + ih, x0:x0 + iw] = idx
    return cell


TEAL, WHT, MINT = (0, 74, 90), (255, 255, 255), (170, 235, 220)


def _fit_header(text, caps, *a):
    for cap in caps:
        try:
            return _header(text, cap, *a)
        except ValueError:
            continue
    raise ValueError(text)


STYLES["dd_away"] = _fixed(_fit_header("Away", range(13, 7, -1), (222, 115, 0), (222, 16, 8), [(WHT, 1), (TEAL, 1)], MINT, 48, 32))
STYLES["dd_home"] = _fixed(_fit_header("Home", range(13, 7, -1), (120, 170, 250), (35, 85, 190), [(WHT, 1), (TEAL, 1)], MINT, 48, 32))
STYLES["dd_vs"] = _fixed(_fit_header("VS", range(20, 7, -1), (255, 235, 40), (255, 120, 0), [((16, 0, 164), 3), (WHT, 2)], MINT, 48, 48))


# ---- sip_comm.arc bank r4_smo: the inning card of the Eikan Nine practice game ---------------------------------------

TOPLEFT = [4, 4, 4, 5, 7, 8, 8]       # rings (inner to outer) where the face lies below / right of the pixel
BOTRIGHT = [1, 3, 4, 4, 5, 8, 8]      # rings where the face lies above / left of the pixel


def sipcard(tl=TOPLEFT, br=BOTRIGHT):
    n = max(len(tl), len(br))

    def raw(ink, base):
        """The art with `n + 1` clear pixels round it (not trimmed): (art, baseline row, pad)."""
        pad = n + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        F = big >= 3
        masks = [F, grow(F, 1)]
        for _ in range(n - 1):
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        for k in range(1, n + 1):
            L = masks[k] & ~masks[k - 1]
            inner = masks[k - 1]
            up = np.zeros_like(inner); up[1:] = inner[:-1]               # the nearer pixel lies above
            left = np.zeros_like(inner); left[:, 1:] = inner[:, :-1]     # ... or to the left
            dark = L & (up | left)
            if k <= len(br): out[dark] = br[k - 1]
            if k <= len(tl): out[L & ~dark] = tl[k - 1]
            if k > len(br): out[dark] = tl[min(k, len(tl)) - 1]
            if k > len(tl): out[L & ~dark] = br[min(k, len(br)) - 1]
        # the face: white, with a light-blue shade on its top, left and bottom edges
        face = np.full(big.shape, 15, np.uint8)
        above = np.zeros_like(F); above[1:] = F[:-1]
        below = np.zeros_like(F); below[:-1] = F[1:]
        lft = np.zeros_like(F); lft[:, 1:] = F[:, :-1]
        face[F & ~below] = 10
        face[F & ~above] = 12
        face[F & ~lft & above & below] = 13
        out[F] = face[F]
        return out, base + pad, pad

    def style(ink, base):
        out, b, pad = raw(ink, base)
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], b - ys.min()

    def trim_rows(a, base):
        ys = np.nonzero(a.any(1))[0]
        return a[ys.min():ys.max() + 1], base - ys.min()

    def chain(inks, gap=4, margin=n + 2):
        """([(art, baseline row, x offset)], width) of a label set from one or two words. For two words the whole label is
        rendered and cut into three pieces: left of x = (end of the first word + gap) - margin, a middle (the join, which
        depends on both words) and the rest. The rings reach n pixels from a letter, so the left piece is the same for every
        label that starts with the same first word, and the right piece for every label that ends with the same second."""
        if len(inks) == 1:
            art, b = style(*inks[0])
            return [(art, b, 0)], art.shape[1]
        (A, ab), (B, bb) = inks
        up = max(ab, bb)
        down = max(A.shape[0] - ab, B.shape[0] - bb)
        canvas = np.zeros((up + down, A.shape[1] + gap + B.shape[1]), int)
        canvas[up - ab:up - ab + A.shape[0], :A.shape[1]] = A
        canvas[up - bb:up - bb + B.shape[0], A.shape[1] + gap:] = B
        out, b, pad = raw(canvas, up)
        xs = np.nonzero(out.any(0))[0]
        lo, hi = xs.min(), xs.max() + 1
        c1 = pad + A.shape[1] + gap - margin
        c2 = pad + A.shape[1] + margin
        if not lo < c1 < c2 < hi:
            raise ValueError("cannot cut %d + %d columns" % (A.shape[1], B.shape[1]))
        res = []
        for a, z in ((lo, c1), (c1, c2), (c2, hi)):
            art, base = trim_rows(out[:, a:z], b)
            res.append((art, base, a - lo))
        return res, hi - lo

    style.chain = chain
    style.raw = raw
    return style


STYLES["sip_card"] = sipcard()                                                 # 7-pixel rings, as the Japanese lettering
STYLES["sip_small"] = sipcard([4, 4, 5, 8, 8], [1, 3, 4, 8, 8])                # 5-pixel rings, the situation line
