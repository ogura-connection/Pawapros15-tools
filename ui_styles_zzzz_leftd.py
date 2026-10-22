"""Leftovers D: sct_sugo.arc big Eikan date card (second z4_emp_0 bank, sprite tables under r4_hid).
Unit cells 月 / 日 (page 4, 40 x 40) and weekday cells 04-0a (48 x 48, 07/08 split over pages 3 and 4), palette 2:
15 white fill, 8 black outline, 6 / 4 / 2 shadow. Styles 'dd_<name>' return finished arrays the size of their rect."""
import numpy as np
from PIL import Image, ImageDraw, ImageFont

STYLES = {}
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


def lettering(text, cap, squeeze=1.0, edge=2):
    """white italic letters, black outline `edge` px, soft dark shadow down-right: index array"""
    m = _cov(text, cap, squeeze=squeeze)
    pad = edge + 3
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

CELLS = {}
CELLS["mo"] = put(fit("Mo", 40, 40, range(26, 8, -1)), 40, 40, "bottom")
CELLS["day"] = put(fit("Day", 40, 40, range(26, 8, -1)), 40, 40, "bottom")
for sp, t in WEEK.items():
    CELLS[sp] = put(fit(t, 48, 48, range(30, 8, -1)), 48, 48, "center")

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
