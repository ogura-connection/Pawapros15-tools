"""sct_sugo.arc z4_emp_0 (the first of its two banks; its sprites are filed under the second): the Eikan Nine main screen.
Weekday strip (sprites 09-0f, page 1, palette 20) and the event cards of the progress-icon board (vertical cards 72-7f
and 93 on pages 5-7, horizontal names 64-71 on pages 7-8, palette 61). Spec built by
_work/ui_pages/eikan_strip/gen.py, which imports CELLS from here: every card / name is one finished picture, cut into as
many parts as its sprite table has, and drawn with the "ek_cell_<name>" styles (the style ignores the ink it is given)."""
import numpy as np
from PIL import Image, ImageDraw, ImageFont

STYLES = {}

NARROW = "/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf"
SLOPE = 12 / 24                       # the cards lean one pixel right per two rows up (the kanji parts step so)
ANGLE = float(np.degrees(np.arctan2(24, 12)))   # text along the card, read upwards
# ink level (0..6) -> index of the grey ramps of palettes 20 and 61 (1 = white .. 15 = black)
BLACK = np.array([0, 3, 6, 9, 11, 13, 15], np.uint8)

# sprite: (part count, lines, cap height) - vertical cards, text rotated to run up the card
CARDS = {
    "72": (3, ["Entrance", "Ceremony"], 11),     # 入学式
    "73": (3, ["Graduation"], 13),               # 卒業式
    "74": (3, ["Tournament"], 13),               # 公式戦
    "75": (4, ["Practice Game"], 13),            # 練習試合
    "76": (4, ["Away Game"], 13),                # 遠征試合
    "77": (2, ["Training Camp"], 13),            # 合宿
    "78": (4, ["Draft"], 13),                    # ドラフト
    "79": (4, ["Midterm Exams"], 13),            # 中間試験
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
    "64": (1, ["Entrance"], 9), "65": (1, ["Graduation"], 8), "66": (2, ["Tourney"], 10),
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


def weekday(text):
    """white-ringed black letters for the 32 x 32 weekday cells (palette 20: 1 = white)"""
    a = levels(coverage([text], 14, path="/System/Library/Fonts/Supplemental/Arial Narrow Bold Italic.ttf", squeeze=0.84))
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


def build():
    """CELLS = {name: [(array, (ox, oy)) per part]}: every picture the spec draws, cut into its sprite's parts"""
    cells = {}
    for sp, (n, lines, cap) in CARDS.items():
        art, org = picture(lines, cap, ANGLE)
        cells[sp] = cut(art, org, n)
    for sp, (n, lines, cap) in NAMES.items():
        art, org = picture(lines, cap, 0.0)
        cells[sp] = [(art, org)] + [(None, None)] * (n - 1)
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
