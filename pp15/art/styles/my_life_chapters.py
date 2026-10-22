"""Styles for the My Life chapter cards, file and history pages, records screens, and the prefecture and family pages of the profile card.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): orepena, ore_myk, ore_ini.
"""
import json
import os
import numpy as np
from pp15 import config
from pp15.art.typeset import grow, shift
from pp15.art import typeset as ui_type
from . import my_life_screens as _O
from . import my_life_report as _O2

STYLES = {}


# ---- orepena.arc: b5_m00, b5_mm, g3_rire, y3_file, y3_hist, y3_jim0, y3_jim1, y3_m256 and the chapter cards ----------

for _cap in range(29, 49):
    for _b in (10, 20):
        ui_type.FONTS["dc%dg2b%d" % (_cap, _b)] = _O._din_font(_cap, 2, _b / 100.0)


def _load():
    path = os.path.join(config.SPECS_DIR, "orepena3_styles.json")
    out = {}
    if os.path.exists(path):
        for name, v in json.load(open(path)).items():
            out[name] = _O2.plate2(v) if v.get("kind") == "plate2" else _O2.gsolid(v["fills"], v["rings"], v.get("shadow", 0), v.get("cut", 2))
    return out


STYLES.update(_load())


# ---- ore_myk.arc: records screens (bank y3_my) -----------------------------------------------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def crisp(fill, rings, shadow=0, cut=2):
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
        out[letters] = fill
        ys = np.nonzero(out.any(1))[0]
        xs = np.nonzero(out.any(0))[0]
        r0, r1, c0, c1 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
        return out[r0:r1, c0:c1], base + pad - r0
    return style


STYLES.update({
    "myk_stat": crisp(14, [4, 6]),               # palette 33: white in a blue ring and a navy ring
    "myk_head": crisp(15, [10, 3], cut=2),           # palette 19: yellow, brown ring, white band, pale blue glow
    "myk_team": crisp(13, [10, 2]),              # palette 21: peach in a dark red ring and an orange ring
    "myk_small": crisp(5, [2], cut=3),                  # palette 38: blue letters in a pale blue ring
    "myk_tab": crisp(15, [2], cut=3),                # palettes 8-11: white in the tab's dark ring
    "myk_sel_b": crisp(14, [7], cut=3),              # palette 27: SELECT hint, blue
    "myk_sel_r": crisp(14, [7], cut=3),              # palette 26: SELECT hint, red
    "myk_title": crisp(15, [4, 8], cut=3),              # palette 55: green title
})


# ---- ore_ini.arc: prefectures and background of the card (y3_myk), wife and children (y3_kzo) ------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def ringed(fill, rings, shadow=None, off=(2, 2), bottom=None, thresh=3):
    """Letters of palette index `fill` (the lowest row of a stroke at least two high is `bottom` if given) inside
    solid one-pixel rings (first value innermost), plus a solid drop shadow `shadow` of the outer ring `off` pixels
    down and right. No soft edges."""
    def style(ink, base):
        pad = len(rings) + (max(off) if shadow is not None else 0)
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        masks = [grow(m, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(m.shape, np.uint8)
        if shadow is not None:
            sh = np.zeros_like(m)
            for k in range(1, max(off) + 1):          # the shadow is the outline slid down-right, no gaps
                dy, dx = min(k, off[0]), min(k, off[1])
                sh[dy:, dx:] |= masks[-1][:m.shape[0] - dy, :m.shape[1] - dx]
            out[sh] = shadow
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        out[m] = fill
        if bottom is not None:
            dn = np.zeros_like(m); dn[:-1] = m[1:]
            up = np.zeros_like(m); up[1:] = m[:-1]
            out[m & ~dn & up] = bottom
        return out, base + pad
    return style


STYLES.update({
    # y3_myk (palette 23): blue letters, white ring, pale blue ring, blue-grey shadow to the lower right
    "mykblue": ringed(5, [14, 11], shadow=3, off=(2, 2)),
    # y3_kzo list words (palette 20): mint letters, dark teal ring, grey-teal ring, blue-grey shadow
    "kzomint": ringed(15, [11, 6], shadow=4, off=(2, 2), bottom=12),
    # headings (pink palette 7 / green palette 6): light fill, dark ring (two pixels), white ring, grey shadow
    "kzohead_p": ringed(8, [14, 14, 6], shadow=2, off=(1, 1)),
    "kzohead_g": ringed(8, [14, 14, 6], shadow=2, off=(1, 1)),
    # plate words (palette 10): white letters in a blue ring
    "kzoplate": ringed(15, [1, 5], bottom=11),
    # small units of the birth line (palette 3): blue letters, white ring, cyan ring, teal shadow
    "kzounit": ringed(15, [8, 6], shadow=1, off=(1, 1)),
})
