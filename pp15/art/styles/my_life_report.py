"""Styles for the My Life results report, game tags and pro news, and for the career ending screen.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): orepena, myend.
"""
import json
import os
import numpy as np
from pp15 import config
from pp15.art.typeset import grow, shift, dropped
from pp15.art import typeset as ui_type
from .common import ringfill
from . import my_life_screens as _O            # DIN font and the "dc<cap>g<gap>b<bold>" / "nb<size>" fonts

STYLES = {}


# ---- orepena.arc: banks w5_kek, w5_kek00, y3_k, y3_pnews, y3_mjun (results report, game tags, pro news) --------------

def _slant_font(cap, gap, bold, slant):
    def make(project=None):
        glyphs = {}
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,!?&'/-+:"
        for ch in chars:
            ink, base = ui_type.ttf_ink(ch, "din", cap, slant, 1.0, bold)
            glyphs[ch] = (ink, ink.shape[0] - base)
        return {"words": {}, "glyphs": glyphs, "space": max(3, round(cap * 0.3)), "gap": gap}
    return make


for _cap in range(10, 31):
    ui_type.FONTS["ds%d" % _cap] = _slant_font(_cap, 2, 0.1, 0.2)


def gsolid(fills, rings, shadow=0, cut=2):
    def style(ink, base):
        pad = len(rings) + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big >= cut
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        if shadow:
            out[shift(masks[-1], 1, 1)] = shadow
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        rows = np.nonzero(letters.any(1))[0]
        r0, r1 = rows.min(), rows.max() + 1
        n = len(fills)
        for y in rows:
            out[y][letters[y]] = fills[min(n - 1, (y - r0) * n // (r1 - r0))]
        ys = np.nonzero(out.any(1))[0]
        xs = np.nonzero(out.any(0))[0]
        a0, a1, c0, c1 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
        return out[a0:a1, c0:c1], base + pad - a0
    return style


def plate2(v):
    """Like plate() of my_life_screens.py, but the erased box takes the colour of row v["fillrow"] (a plate whose lettering shadow
    runs into the last rows)."""
    inner = _O.solid(v["fill"], v["rings"], v.get("shadow", 0), v.get("cut", 3))

    def style(ink, base):
        pic = np.concatenate([_O.old_page(v["bank"], pg)[y0:y1, x0:x1].copy() for pg, x0, y0, x1, y1 in v["rects"]], axis=1)
        ex0, ey0, ex1, ey1 = v["erase"]
        pic[ey0:ey1, ex0:ex1] = pic[v["fillrow"], (ex0 + ex1) // 2]
        art, b = inner(ink, base)
        h, w = art.shape
        x = v["cx"] - w // 2
        y = v["cy"] - h // 2
        sub = pic[y:y + h, x:x + w]
        sub[art > 0] = art[art > 0]
        a, c = v["part"]
        return pic[:, a:c], 0
    return style


def _load():
    path = os.path.join(config.SPECS_DIR, "orepena2_styles.json")
    out = {}
    if os.path.exists(path):
        for name, v in json.load(open(path)).items():
            out[name] = plate2(v) if v.get("kind") == "plate2" else _O.make(v) if v.get("kind") == "plate" else gsolid(v["fills"], v["rings"], v.get("shadow", 0), v.get("cut", 2))
    return out


STYLES.update(_load())


# ---- myend.arc: My Life ending (banks y3_end, y3_se16, y3_se256) -----------------------------------------------------

# y3_end: white letters, black shadow (palette 0)
STYLES["me_white"] = dropped([0, 0, 0, 15, 15, 15, 15], [1])

# y3_se16, palettes 16 (team names, W / L / T): white to pale blue letters, blue rings
_BLUE = [11, 12, 13, 14, 15, 15, 14, 13, 12, 11, 10]
STYLES["me_team"] = ringfill(_BLUE, [6, 5, 3], [])
STYLES["me_team"] = ringfill(_BLUE, [5, 3], [])
STYLES["me_wlt"] = ringfill(_BLUE, [6, 5, 5, 3], [])
# banners, 32 rows high: orange (17), violet (18), pink (22); stat words, green (19)
STYLES["me_ban17"] = ringfill([10, 11, 12, 13, 14, 15, 14, 13, 12, 11, 10], [5, 5, 3], [])
STYLES["me_ban18"] = ringfill([10, 11, 12, 13, 14, 15, 14, 13, 12, 11, 10], [5, 5, 3], [])
STYLES["me_ban22"] = ringfill([10, 11, 12, 13, 14, 15, 14, 13, 12, 11, 10], [2, 2, 3], [])
STYLES["me_stat"] = ringfill([11, 12, 13, 14, 14, 13, 12, 11, 10, 9], [5, 5, 3], [])

# y3_se256 (8-bit pages): chrome letters, blue outline, pale band, deep blue shadow
_CHROME = [209, 211, 215, 176, 174, 171, 169, 167, 166, 60, 58, 55, 52]
STYLES["me_chrome"] = ringfill(_CHROME, [106, 106, 219, 219, 219, 219], [111] * 6)
STYLES["me_slate"] = ringfill([252], [160, 160, 190], [111, 111])
_GOLD = [172, 179, 186, 192, 201, 206, 213, 214, 233, 234, 254, 251, 248]
STYLES["me_burn"] = ringfill(_GOLD, [104, 123, 123, 160], [111] * 6)


def window(style, k, size=128):
    """The columns k * size .. (k + 1) * size of the whole word as `style` draws it."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, k * size:(k + 1) * size]
        if out.shape[1] == 0:
            out = np.zeros((1, 1), np.uint8)
        return out, b
    return cut


for _name in ("me_chrome", "me_slate", "me_burn", "me_ban17", "me_ban18", "me_ban22", "me_team"):
    for _k in range(3):
        STYLES["win_%s_%d" % (_name, _k)] = window(STYLES[_name], _k)
