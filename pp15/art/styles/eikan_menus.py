"""Styles for the menus of Eikan Nine, the Success Mode scenario in which you manage a high-school team.

The player sees the weekday strip and event cards of the main screen, the title, card, profile and system menus, and a few labels drawn into code-made pictures.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): sct_sugo, sct_a_mk, gdt_sch, sct_a_pr, sct_g_cd, sct_main, sct_a_lb, ore_ini, sct_titl, school_g, sct_a_sy, sct_a_ar.
"""
import numpy as np
import os
import functools
from PIL import Image, ImageDraw, ImageFont
from pp15 import config
from pp15.art import typeset as ui_type
from .common import ringfill, win, flat
from . import logo_front_panel as _A3

STYLES = {}


# ---- sct_sugo.arc z4_emp_0: the Eikan Nine main screen (weekday strip, event cards of the progress-icon board) -------

NARROW = "/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf"
NARROW_I = "/System/Library/Fonts/Supplemental/Arial Narrow Bold Italic.ttf"
SLOPE = 12 / 24                       # the cards lean one pixel right per two rows up (the kanji parts step so)
ANGLE = float(np.degrees(np.arctan2(24, 12)))   # text along the card, read upwards
# ink level (0..6) -> index of the grey ramps of palettes 20 and 61 (1 = white .. 15 = black)
BLACK = np.array([0, 3, 6, 9, 11, 13, 15], np.uint8)

# sprite: (part count, lines, cap height) - vertical cards, text rotated to run up the card
CARDS = {
    "72": (3, ["Entrance", "Ceremony"], 11),     # 入学式
    "73": (3, ["Graduation"], 13),               # 卒業式
    "74": (3, ["Tournament"], 13),               # 公式戦
    "75": (4, ["Practice Game"], 12),            # 練習試合
    "76": (4, ["Away Game"], 13),                # 遠征試合
    "77": (2, ["Training Camp"], 12),            # 合宿
    "78": (4, ["Draft"], 13),                    # ドラフト
    "79": (4, ["Midterm Exams"], 12),            # 中間試験
    "7a": (4, ["Final Exams"], 13),              # 期末試験
    "7b": (2, ["Exams"], 13),                    # 試験
    "7c": (4, ["School Event"], 13),             # 学校行事
    "7d": (3, ["Sports Day"], 13),               # 体育祭
    "7e": (3, ["Culture", "Festival"], 11),      # 文化祭
    "7f": (4, ["School Trip"], 13),              # 修学旅行
    "93": (6, ["Day Before", "Camp"], 11),       # 合宿前日
}
# sprite: (part count, lines, cap height) - the short horizontal names (48 x 32 cells, centred on the origin)
NAMES = {
    "64": (1, ["Entrance"], 9), "65": (1, ["Grad."], 8), "66": (2, ["Tourney"], 10),
    "67": (1, ["Practice", "Game"], 9), "68": (1, ["Away", "Game"], 9), "69": (2, ["Camp"], 10),
    "6a": (1, ["Draft"], 10), "6b": (1, ["Midterm"], 10), "6c": (1, ["Finals"], 10), "6d": (1, ["Exams"], 10),
    "6e": (2, ["Event"], 10), "6f": (1, ["Sports", "Day"], 9), "70": (1, ["Culture", "Fest"], 9),
    "71": (3, ["School", "Trip"], 9),
}
WEEKDAYS = {"09": "Mon", "0a": "Tue", "0b": "Wed", "0c": "Thu", "0d": "Fri", "0e": "Sat", "0f": "Sun"}

_fonts = {}


def _font(path, cap, over):
    key = (path, cap, over)
    if key not in _fonts:
        probe = ImageFont.truetype(path, 400)
        t, b = probe.getbbox("H")[1], probe.getbbox("H")[3]
        _fonts[key] = ImageFont.truetype(path, round(400 * cap * over / (b - t)))
    return _fonts[key]


def coverage(lines, cap, path=NARROW, angle=0.0, gap=3, over=4, slant=0.0, squeeze=1.0):
    """0..255 coverage of the lines (centred, `gap` clear rows between them, line pitch = cap + descender room),
    rotated by `angle` degrees (counter-clockwise); drawn `over` times larger and averaged down."""
    f = _font(path, cap, over)
    pitch = round(cap * 1.3) + gap
    widths = [f.getbbox(t, anchor="ls")[2] - f.getbbox(t, anchor="ls")[0] for t in lines]
    W = (max(widths) + 8 * over)
    H = (pitch * len(lines) + cap) * over
    img = Image.new("L", (W, H), 0)
    dr = ImageDraw.Draw(img)
    for k, (t, w) in enumerate(zip(lines, widths)):
        l = f.getbbox(t, anchor="ls")[0]
        dr.text(((W - w) // 2 - l, (k * pitch + cap + 2) * over), t, fill=255, font=f, anchor="ls")
    if slant:
        img = img.transform(img.size, Image.AFFINE, (1, slant, -slant * img.height / 2, 0, 1, 0), Image.BICUBIC)
    if squeeze != 1:
        img = img.resize((round(img.width * squeeze), img.height), Image.BICUBIC)
    if angle:
        img = img.rotate(angle, resample=Image.BICUBIC, expand=True)
    w, h = (img.width + over - 1) // over * over, (img.height + over - 1) // over * over
    pad = Image.new("L", (w, h), 0)
    pad.paste(img, (0, 0))
    a = np.asarray(pad.resize((w // over, h // over), Image.BOX), dtype=np.float32)
    ys, xs = np.nonzero(a > 255 / 12)
    return a[ys.min():ys.max() + 1, xs.min():xs.max() + 1]


def levels(a):
    return np.rint(a * 6 / 255).astype(int)


def picture(lines, cap, angle):
    """index art (palette 61 ramp) of a card or name, and the offset of its top-left from the sprite origin
    (the text block is centred on the origin, as the Japanese parts are)"""
    art = BLACK[levels(coverage(lines, cap, angle=angle))]
    ys, xs = np.nonzero(art)
    art = art[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    h, w = art.shape
    return art, (-(w // 2), -(h // 2))


def cut(art, origin, parts):
    """the picture cut into `parts` bands of rows, each cropped to its ink: [(array, (ox, oy))]"""
    h = art.shape[0]
    edges = [round(h * k / parts) for k in range(parts + 1)]
    out = []
    for y0, y1 in zip(edges, edges[1:]):
        band = art[y0:y1]
        ys, xs = np.nonzero(band)
        if not len(xs):
            out.append((None, None))
            continue
        piece = band[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
        out.append((piece, (origin[0] + xs.min(), origin[1] + y0 + ys.min())))
    return out


def ringed(lines, cap, squeeze=1.0):
    """black italic letters inside a one-pixel white ring (1 = white in palettes 20 and 61), like the Japanese"""
    a = levels(coverage(lines, cap, path=NARROW_I, squeeze=squeeze, gap=1))
    letters = a > 0
    p = np.pad(letters, 1)
    ring = np.zeros_like(p)
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            ring |= np.roll(np.roll(p, dy, 0), dx, 1)
    out = np.where(ring, 1, 0).astype(np.uint8)
    out[1:-1, 1:-1][letters] = BLACK[a[letters]]
    out[1:-1, 1:-1][letters & (a <= 1)] = 1         # the faintest edge pixels become ring (no grey halo on white)
    return out


def weekday(text):
    """the 32 x 32 weekday cells"""
    return ringed([text], 14, squeeze=0.84)


def name(lines, w=48, h=32):
    """a horizontal event name: the largest capital height (11 down) that fits the 48 x 32 cell"""
    for cap in range(11, 5, -1):
        art = ringed(lines, cap)
        if art.shape[1] <= w and art.shape[0] <= h:
            return art
    raise ValueError(lines)


def build():
    """CELLS = {name: [(array, (ox, oy)) per part]}: every picture the spec draws, cut into its sprite's parts"""
    cells = {}
    for sp, (n, lines, cap) in CARDS.items():
        art, org = picture(lines, cap, ANGLE)
        cells[sp] = cut(art, org, n)
    for sp, (n, lines, cap) in NAMES.items():
        art = name(lines)
        h, w = art.shape
        cells[sp] = [(art, (-(w // 2), -(h // 2)))] + [(None, None)] * (n - 1)
    for sp, text in WEEKDAYS.items():
        art = weekday(text)
        cells[sp] = [(art, None)]
    return cells


CELLS = build()


def _fixed(arr):
    def style(ink, base):
        return arr.copy(), 0
    return style


for _sp, _parts in CELLS.items():
    for _k, (_a, _o) in enumerate(_parts):
        if _a is not None:
            STYLES["ek_cell_%s_%d" % (_sp, _k)] = _fixed(_a)
STYLES["ek_none"] = _fixed(np.zeros((1, 1), np.uint8))


# ---- sct_a_mk.arc, gdt_sch.arc, sct_a_lb.arc -------------------------------------------------------------------------

# ---- sct_a_lb.arc (graduation album) --------------------------------------------------------------------------------------
STYLES["a4_lb_title"] = ringfill([15, 15, 15, 15, 15, 15], [1, 3, 8, 12], [6, 7])       # pal 16: white, dark ring, gold bands
STYLES["a4_lb_title~0_128"] = win(STYLES["a4_lb_title"], 0, 128)
STYLES["a4_lb_title~128_4096"] = win(STYLES["a4_lb_title"], 128, 4096)
STYLES["a4_lb_head"] = ringfill([2, 2, 2, 2, 2, 2], [1, 1, 8])                                          # pal 18: olive letters, white ring, grey edge


# ---- gdt_sch.arc: Baseball School test banners (palettes of pal_h3_kyo_0) ------------------------------------------------
def fixed(style, W, align="centre"):
    """The styled word on a canvas exactly W columns wide (a word shared out over parts with fixed windows)."""
    def make(ink, base):
        art, b = style(ink, base)
        if art.shape[1] >= W:
            return art, b
        pad = W - art.shape[1]
        left = pad if align == "right" else pad // 2
        out = np.zeros((art.shape[0], W), np.uint8)
        out[:, left:left + art.shape[1]] = art
        return out, b
    return make


STYLES["a4_stk_blue"] = ringfill([15, 14, 13, 13, 12, 12, 11, 11], [1, 10, 10, 2, 2], [5, 5, 6, 6])       # pal 3: cyan, white ring, blue
STYLES["a4_stk_pink"] = ringfill([9, 9, 10, 11, 11, 12, 13, 13], [1, 15, 13, 4, 4], [6, 7, 7])             # pal 0: pink, white ring, magenta
STYLES["a4_stk_violet"] = ringfill([8, 8, 9, 10, 11, 12, 13], [1, 2, 15, 13, 3], [7, 7, 7])                # pal 11: violet, white ring
STYLES["a4_stk_pass"] = ringfill([6, 6, 7, 8, 8, 9, 9], [3, 3, 3, 10, 10, 14, 15, 15])                     # pal 4: yellow, purple, white, hot pink
# Test Start: a 192 column canvas (parts 32 + 128 + 32), the word flush right so "Start" ends where the Japanese 開始 ends;
# Start: a 96 column canvas (parts 16 + 48 + 32), flush right: both end in the same last 32 columns (a part they share)
STYLES["a4_stk_ts"] = fixed(STYLES["a4_stk_blue"], 192, "right")
STYLES["a4_stk_s"] = fixed(STYLES["a4_stk_blue"], 96, "right")
STYLES["a4_stk_over"] = fixed(STYLES["a4_stk_pink"], 184, "centre")
for _n, _c in (("a4_stk_ts", (0, 32, 160)), ("a4_stk_s", (0, 16, 64)), ("a4_stk_over", (0, 32, 160))):
    _e = list(_c) + [4096]
    for _a, _b in zip(_e, _e[1:]):
        STYLES["%s~%d_%d" % (_n, _a, _b)] = win(STYLES[_n], _a, _b)
STYLES["a4_stk_pass~0_128"] = win(STYLES["a4_stk_pass"], 0, 128)
STYLES["a4_stk_pass~128_4096"] = win(STYLES["a4_stk_pass"], 128, 4096)


# ---- sct_a_mk.arc (Eikan Nine: new club members setup, region and prefecture names) -------------------------------------------
STYLES["a4_mk_navy"] = flat([0, 2, 2, 2, 2, 2, 2], 3)                           # m4_mak pal 8: navy letters, no ring (form labels, list heading)
STYLES["a4_mk_navy~0_56"] = win(STYLES["a4_mk_navy"], 0, 56)                   # High School over its two parts (56 + 16)
STYLES["a4_mk_navy~56_4096"] = win(STYLES["a4_mk_navy"], 56, 4096)
STYLES["a4_mk_dark"] = flat([0, 2, 2, 2, 2, 2, 2], 3)                           # pal 3: the small black help text
STYLES["a4_mk_title"] = ringfill([1], [2, 2, 6])                                # pal 3: white letters, black ring, grey edge
STYLES["a4_mk_title~0_128"] = win(STYLES["a4_mk_title"], 0, 128)
STYLES["a4_mk_title~128_4096"] = win(STYLES["a4_mk_title"], 128, 4096)
STYLES["a4_mk_menu"] = ringfill([1], [5, 4])                                 # pal 6 / 11: white letters, black ring, dark green edge
STYLES["a4_mk_big"] = ringfill([1], [3, 3, 1, 2])                            # p4_mp pal 0: white letters, blue ring, white ring, pale glow
STYLES["a4_mk_small"] = ringfill([1], [3, 3])                                # p4_mp pal 1
STYLES["a4_mk_head"] = ringfill([1], [3, 3, 3, 1, 2])                               # p4_mp pal 0, the region headings (thinner rings: the words are long)
STYLES["a4_mk_big"] = ringfill([1], [3, 3, 1])                                   # big prefecture names: blue ring, white edge
STYLES["a4_mk_cell"] = ringfill([1], [2, 2])                                    # 77: white letters, blue ring on the pale blue cells
STYLES["a4_mk_cell~0_8"] = win(STYLES["a4_mk_cell"], 0, 8)                       # Schools over its two parts (8 + 56)
STYLES["a4_mk_cell~8_4096"] = win(STYLES["a4_mk_cell"], 8, 4096)
STYLES["a4_mk_flat1"] = flat([0, 1, 1, 1, 1, 1, 1], 3)                         # 7d-7f: solid letters of index 1 (the palette gives red / green / blue)

# the ten map call-out plates: the plate is part of the page (80 wide, border + flat orange / blue inside), so the label is the whole
# plate redrawn: the original plate with its interior cleared and the word set in it
PLATES = {(19, 0): 24, (19, 24): 24, (19, 48): 24, (19, 72): 24, (19, 96): 32, (20, 0): 24, (20, 24): 24, (20, 48): 24, (20, 72): 24, (20, 96): 24}
_PLATE_CACHE = {}


def _plate(page, y0, h):
    key = (page, y0, h)
    if key not in _PLATE_CACHE:
        import os
        from pp15.art import textures as U
        path = os.path.join(U.ORIG_ARC_DIR, "sct_a_mk.arc")
        if not os.path.exists(path):
            from pp15.script import scan as S
            path = os.path.join(S.DATA_FILES, "sct_a_mk.arc")
        d = open(path, "rb").read()
        b = U.bank_named(U.banks(d, U.elf_symbols(d)), "m4_mak#1")
        _PLATE_CACHE[key] = U.decode_indices(d, *b["pages"][page])[y0:y0 + h, 0:80].copy()
    return _PLATE_CACHE[key].copy()


STYLES["a4_mk_pltext"] = flat([0, 15, 15, 15, 15, 15, 15], 3)                                  # the word of a call-out plate (measured with this)


def callout(page, y0, h):
    text = STYLES["a4_mk_pltext"]

    def make(ink, base):
        art, _ = text(ink, base)
        out = _plate(page, y0, h)
        ys0, xs0 = np.nonzero(out)
        top, bot, left, right = ys0.min(), ys0.max(), xs0.min(), xs0.max()
        out[top + 2:bot - 1, left + 2:right - 1] = 4                    # the flat inside of the plate (the Japanese word stood here)
        ty0, ty1, tx0, tx1 = top + 3, bot - 2, left + 3, right - 2     # where the word may stand
        ah, aw = art.shape
        ox, oy = tx0 + (tx1 - tx0 - aw) // 2, ty0 + (ty1 - ty0 - ah) // 2
        sy0, sx0 = max(ty0 - oy, 0), max(tx0 - ox, 0)
        sub = art[sy0:ah, sx0:aw][:ty1 - max(oy, ty0), :tx1 - max(ox, tx0)]
        tgt = out[max(oy, ty0):max(oy, ty0) + sub.shape[0], max(ox, tx0):max(ox, tx0) + sub.shape[1]]
        tgt[sub > 0] = sub[sub > 0]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], 0
    return make


for (_pg, _y), _h in PLATES.items():
    STYLES["a4_mk_plate_%d_%d" % (_pg, _y)] = callout(_pg, _y, _h)


# ---- sct_titl.arc, sct_g_cd.arc, sct_a_pr.arc, sct_a_sy.arc ----------------------------------------------------------

ui_type.TTF["b4uni"] = ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0)       # has the star of the messenger lines


# ---- sct_g_cd.arc z4_gmc_0: white letters, near-black ring, teal / olive / blue glow (palettes 93, 84, 90, 28, 44, 24, 21) ---------
STYLES["b4_gm"] = ringfill([15, 15, 15, 14, 13, 12], [4, 4], [3, 2])
# orange / yellow tab words (palettes 98 / 99; the dark twin copy in 100 / 101 is the same art)
STYLES["b4_or"] = ringfill([15, 15, 15, 14, 14, 13], [8, 6])
# ---- sct_g_cd.arc z4_gmd_0 -------------------------------------------------------------------------------------------------
STYLES["b4_gd_blue"] = ringfill([5, 4, 3, 3, 2, 2], [8, 8], [10])                        # pal 18: blue letters, white ring
STYLES["b4_gd_black"] = ringfill([1], [1, 1, 1], [1, 1])                                   # pal 13: the black twin of the blue line
STYLES["b4_gd_green"] = ringfill([15, 14, 14, 13, 12, 12], [4, 4], [3, 2])                 # pal 20: lime letters, black ring
STYLES["b4_gm_s"] = ringfill([15, 15, 15, 14, 13, 12], [4], [3])                           # the same on small plates: one ring, one shadow row

# ---- sct_a_pr.arc z4_edr_0 (Eikan Nine practice-order screen) -----------------------------------------------------------------------
STYLES["b4_pr_tab"] = ringfill([15, 15, 15, 14, 13, 12], [4, 4, 3, 2])                     # pal 40-43: white letters, dark ring, coloured glow
STYLES["b4_pr_head"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4], [3])                     # pal 49 / 56: column heads and "Active" on a teal plate
STYLES["b4_pr_pos"] = ringfill([15, 15, 14, 14, 13, 13], [3])                              # pal 52 / 53: position glyphs, black on a light cell
STYLES["b4_pr_col"] = ringfill([6, 4, 3, 2, 2, 4], [8, 8], [14])                           # pal 61-63: brown / blue / green letters, white ring (hands, years)
STYLES["b4_pr_msg"] = ringfill([3, 2, 1, 1, 1, 2], [8, 8, 8], [12, 13])                    # pal 64-68: dark letters, white band, pale glow (practice orders)
STYLES["b4_pr_head_s"] = ringfill([15, 15, 14, 13, 12, 11], [4])                           # the same with one ring: heads of 32 px cells (two arts fit one 24 row cell)

# ---- sct_a_sy.arc z4_esy_0 (system settings: chalk on the blackboard, palette 24) ----------------------------------------------------------
STYLES["b4_sy"] = ringfill([15, 15, 14, 14, 13, 13], [3])                                  # chalk white, a dark green ring so the strokes stay solid

# ---- sct_titl.arc: the Eikan Nine title logo (bank r4_eik, 8-bit pages 0-2: a 304 x 128 picture, colour table palette 144) ----------------------
# The art is redrawn whole (as logo2 of logo_front_panel.py does for scc_tops.arc) and every page rectangle takes its window of it.


_B = os.path.join(config.UI_PAGES_DIR, "run4", "B")
LOGO_X = (0, 128, 256)                                           # canvas column of page 0, 1, 2


def _logo_in():
    return np.load(os.path.join(_B, "logo_orig_canvas.npy")), np.load(os.path.join(_B, "logo_pal.npy"))


def _dilate(m, up=3, left=3, down=5, right=5):
    out = m.copy()
    H, W = m.shape
    for dy in range(-up, down + 1):
        for dx in range(-left, right + 1):
            sy0, sy1 = max(0, -dy), min(H, H - dy)
            sx0, sx1 = max(0, -dx), min(W, W - dx)
            out[sy0 + dy:sy1 + dy, sx0 + dx:sx1 + dx] |= m[sy0:sy1, sx0:sx1]
    return out


def _propagate(rgb, mask, valid):
    """Fill `mask` pixels from the valid pixels round them, layer by layer (each takes the mean of its valid 8-neighbours)."""
    out = rgb.copy(); ok = valid & ~mask; todo = mask.copy()
    H, W = mask.shape
    while todo.any():
        pk = np.pad(ok, 1); pc = np.pad(out, ((1, 1), (1, 1), (0, 0)))
        cnt = np.zeros(mask.shape); acc = np.zeros(out.shape)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dy or dx:
                    sel = pk[1 + dy:1 + dy + H, 1 + dx:1 + dx + W]
                    cnt += sel
                    acc += pc[1 + dy:1 + dy + H, 1 + dx:1 + dx + W] * sel[..., None]
        now = todo & (cnt > 0)
        if not now.any():
            break
        out[now] = acc[now] / cnt[now][:, None]
        ok = ok | now; todo = todo & ~now
    return out


def sct_logo(title="Eikan Nine", sub="Build a Powerhouse Club!", tcap=34, tsq=0.9, tstroke=0.35, scap=12, ssq=0.9, sstroke=0.0, tcx=146, tcy=59, scx=148, scy=100):
    A = _A3
    c, pal = _logo_in()
    q = A.Quant(pal, c)
    rgb = pal[c][..., :3].astype(float)
    ri = pal[c][..., :3].astype(int)
    lum = 0.299 * ri[..., 0] + 0.587 * ri[..., 1] + 0.114 * ri[..., 2]
    plate = (lum < 125) & (ri[..., 2] >= ri[..., 0] - 4) & (ri[..., 2] >= ri[..., 1] - 10) & (pal[c][..., 3] > 0)
    new = c.copy()
    H, W = c.shape
    # --- erase the Japanese title: letters + their outline / shadow are cut out of the plate rows and filled from the plate beside them
    zone = np.zeros(c.shape, bool)
    for y in range(33, 87):
        L = next((x for x in range(26, 100) if plate[y, x:x + 5].all()), 40)
        R = next((x for x in range(290, 150, -1) if plate[y, x - 4:x + 1].all()), 250)
        zone[y, L + 4:R - 3] = True
    letters = zone & ~plate
    mask = _dilate(letters, 3, 3, 5, 5) & zone
    rgb2 = A.row_inpaint(rgb, mask, valid=plate & ~mask)
    new[mask] = q(rgb2[mask])
    # --- the new title
    m, base = A.crisp_mask(title, tcap, font="condbi", stroke=tstroke, squeeze=tsq)
    m = A.despeckle(m)
    h, w = m.shape
    pad = 4
    big = np.zeros((h + 2 * pad, w + 2 * pad), bool); big[pad:pad + h, pad:pad + w] = m
    out = np.zeros(big.shape + (3,)); alpha = np.zeros(big.shape, bool)
    bevel = A.grow(big, 1)
    shadow = A.shift(bevel, 2, 2) | A.shift(bevel, 1, 2) | A.shift(bevel, 2, 1)
    out[shadow] = (16, 16, 32); alpha |= shadow
    out[bevel] = (214, 216, 232); alpha |= bevel                         # silver bevel ring, as the Japanese lettering has
    ring = A.grow(bevel, 1, diag=False) & ~bevel
    out[ring] = (40, 40, 72); alpha |= ring
    ys = np.nonzero(big.any(1))[0]
    g = A.grad_rows(A.TITLE_GRAD, ys.max() - ys.min() + 1)
    rowc = np.zeros((big.shape[0], 3)); rowc[ys.min():ys.max() + 1] = g
    out[big] = np.broadcast_to(rowc[:, None, :], big.shape + (3,))[big]; alpha |= big
    hi = big & ~A.shift(big, 1, 0)
    out[hi] = (255, 250, 225)
    y0, x0 = tcy - big.shape[0] // 2, tcx - big.shape[1] // 2
    reg = (slice(y0, y0 + big.shape[0]), slice(x0, x0 + big.shape[1]))
    new[reg][alpha] = q(out[alpha])
    # --- subtitle: the old lettering and its cream halo are cut out of the green (rows filled from the green on both sides), the new
    # words are set in the same brown with a cream halo of their own, as the Japanese had
    green = (ri[..., 1] > ri[..., 0] + 40) & (ri[..., 1] > ri[..., 2] + 40) & (lum < 190)
    reg = np.zeros(c.shape, bool); reg[85:118, 38:266] = True
    rim = _dilate(pal[c][..., 3] == 0, 3, 3, 3, 3)                          # the white edge of the whole logo stays
    old = reg & ~green & ~plate & ~rim & (pal[c][..., 3] > 0)
    old = _dilate(old, 1, 1, 1, 1) & reg & ~green & ~plate & ~rim
    # the green behind the band: rows read from the green that still shows inside it (between the old letters at the top, in the point
    # below), the rows between them interpolated top to foot; the picture beside the band is darker at the top and lighter below it
    inner = np.zeros(c.shape, bool); inner[:, 66:234] = True
    known = {}
    for y in range(86, 117):
        px = rgb[y][green[y] & inner[y] & ~old[y]]
        if len(px) >= 3:
            known[y] = np.median(px, axis=0)
    ys_k = sorted(known)
    rgb3 = rgb.copy()
    for y in range(86, 117):
        row = np.array([np.interp(y, ys_k, [known[k][ch] for k in ys_k]) for ch in range(3)])
        rgb3[y][old[y]] = row
    new[old] = q(rgb3[old])
    sm, sbase = A.crisp_mask(sub, scap, font="condb", stroke=sstroke, squeeze=ssq)
    sm = A.despeckle(sm)
    sh_, sw_ = sm.shape
    pad2 = 5
    sbig = np.zeros((sh_ + 2 * pad2, sw_ + 2 * pad2), bool); sbig[pad2:pad2 + sh_, pad2:pad2 + sw_] = sm
    halo = A.grow(sbig, 3); edge = A.grow(halo, 1, diag=False) & ~halo
    sy0 = scy - sbig.shape[0] // 2; sx0 = scx - sbig.shape[1] // 2
    sreg = (slice(sy0, sy0 + sbig.shape[0]), slice(sx0, sx0 + sbig.shape[1]))
    new[sreg][edge] = q(np.array([(255, 255, 255)]))[0]
    new[sreg][halo] = q(np.array([(255, 252, 232)]))[0]
    new[sreg][sbig] = q(np.array([(98, 41, 16)]))[0]
    return new, (w, h), (sw_, sh_)


@functools.lru_cache(None)
def _logo():
    return sct_logo()[0]


def _logo_window(c0, c1):
    def style(ink, base):
        return _logo()[:, c0:c1].copy(), 0
    return style


STYLES["b4_eik0"] = _logo_window(0, 128)           # page 0 rect 0,0,128,128
STYLES["b4_eik1"] = _logo_window(128, 256)         # page 1 rect 0,0,128,128
STYLES["b4_eik2"] = _logo_window(256, 304)         # page 2 rect 0,0,48,128

# ---- sct_titl.arc r4_eikz page 4 / 5: the info card of the Continue screen (green letters, white ring, blue glow; palettes 1 / 7) ----------------
STYLES["b4_info"] = ringfill([9, 8, 5, 3, 2, 1], [10, 10, 12], [15, 15])
STYLES["b4_info2"] = ringfill([13, 15, 15, 15, 13, 11], [7, 7], [5, 4])                    # palette 7: dark green letters, white ring, pale glow (card labels)


# ---- Eikan Nine fix (fxD_...): sct_a_mk.arc --------------------------------------------------------------------------

# sct_a_mk p4_mp small prefecture plates (pal 1): white letters, ONE thin blue ring (was two rings + italic: letters ran together)
STYLES["fxD_mk_small"] = ringfill([1], [3])


# ---- lettering of code-drawn atlases painted in place (sct_main.arc, school_g.arc, ore_ini.arc; names g10_*) ---------

def mk(fill, rings, t=3, foot=None):
    fill = list(fill)

    def style(ink, base):
        pad = len(rings)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        big[pad:pad + h, pad:pad + w] = ink >= t
        out = np.zeros(big.shape, np.uint8)
        for k in range(pad, 0, -1):
            out[ui_type.grow(big, k)] = rings[k - 1]
        ys, xs = np.nonzero(big)
        top = ys.min()
        for y, x in zip(ys, xs):
            r = y - top
            v = fill[min(r, len(fill) - 1)]
            if foot is not None and not big[y + 1, x]:
                v = foot
            out[y, x] = v
        return out, base + pad
    return style


STYLES["g10_wd"] = mk([1, 2, 4], [8, 8])
STYLES["g10_wd1"] = mk([1, 2, 4], [8])
STYLES["g10_ban"] = mk([4], [8, 8, 15], foot=5)
STYLES["g10_none"] = lambda ink, base: (np.zeros((1, 1), np.uint8), base)
STYLES["g10_ok"] = mk([15], [11, 6])


def card(core=15, shadow=5, t=3):
    """Lettering of the My Life card atlas (y3_mym page 7): crisp letters `core`, a one-pixel `shadow` down and to the right."""
    def style(ink, base):
        pad = 1
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= t
        out = np.zeros(m.shape, np.uint8)
        sh = ui_type.shift(m, 1, 1)
        out[sh & ~m] = shadow
        out[m] = core
        return out, base + 0
    return style


def bevel(top, core, bottom, t=3):
    """Crisp letters `core`; left / top edge `top`, right / bottom edge `bottom` (no ring)."""
    def style(ink, base):
        h, w = ink.shape
        m = ink >= t
        up = np.zeros_like(m); up[1:] = m[:-1]
        left = np.zeros_like(m); left[:, 1:] = m[:, :-1]
        dn = np.zeros_like(m); dn[:-1] = m[1:]
        rt = np.zeros_like(m); rt[:, :-1] = m[:, 1:]
        out = np.zeros(m.shape, np.uint8)
        out[m] = core
        out[m & (~dn | ~rt)] = bottom
        out[m & (~up | ~left)] = top
        return out, base
    return style


STYLES["g10_mc"] = card()
STYLES["g10_mn"] = card(shadow=0)
STYLES["g10_mt"] = bevel(11, 13, 5)
STYLES["g10_mtf"] = bevel(13, 13, 5)
