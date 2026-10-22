"""Styles for the My Life practice menu, schedule screen, free agency screen and button hints.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): ore_sub, ore_ren, ore_i_co, ore_fa.
"""
import json
import os
import re
import numpy as np
from pp15 import config
from pp15.art.typeset import grow, shift, banded, logo, dropped, outlined, called
from pp15.art import typeset as ui_type
from pp15.art import textures as _U
from pp15.script import scan as _S
from . import my_life_screens as _O            # registers the DIN fonts "dc<cap>g<gap>b<bold>" and "nb<size>"

STYLES = {}


# ---- ore_ren.arc: practice menu (banks g3_0ren .. g3_3ren) -----------------------------------------------------------

# (the bank split that was here is now pp15.art.textures.split_merged)


def solid(fill, rings, shadow=0, cut=2):
    """Crisp letters (ink >= cut of 6) in one colour, one-pixel rings (colours from the innermost out), optional shadow."""
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


def _load():
    path = os.path.join(config.SPECS_DIR, "ore_ren_styles.json")
    out = {}
    if os.path.exists(path):
        for name, v in json.load(open(path)).items():
            out[name] = solid(v["fill"], v["rings"], v.get("shadow", 0), v.get("cut", 2))
    return out


STYLES.update(_load())


# ---- ore_sub.arc: schedule screen (bank y3_yotei) --------------------------------------------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))

def onband(style, band, size, pad=(3, 2), rim=None):
    """`style`'s art set on a filled rectangle of colour `band`, at least `size` (w, h) (the part's band)."""
    def made(ink, base):
        art, b = style(ink, base)
        h, w = art.shape
        bw, bh = max(size[0], w + 2 * pad[0]), max(size[1], h + 2 * pad[1])
        out = np.full((bh, bw), band, np.uint8)
        x, y = (bw - w) // 2, (bh - h) // 2
        sub = out[y:y + h, x:x + w]
        sub[art > 0] = art[art > 0]
        if rim is not None:
            out[0, :] = out[-1, :] = rim
            out[:, 0] = out[:, -1] = rim
        return out, b + y
    return made


STYLES.update({
    # big yellow headings with blue ring and white band (palette 21)
    "yhead": logo([10, 11, 12, 13], [8, 7], 9, 3, 2, [5, 4], 2, 2),
    # white letters, dark blue ring, paler ring (stadium names, palette 16)
    "stad": banded([0, 12, 13, 14, 15, 15, 15], [5, 9]),
    # navy place names with a pale ring (palette 36)
    "city": banded([0, 9, 11, 13, 14, 15, 15], [3]),

    # day tags on the plates (palette 48, grey ramp): dark letters in a solid white ring
    "chip": banded([0, 8, 4, 2, 2, 2, 2], [15]),
    "homeblue": banded([0, 10, 11, 12, 13, 13, 13], [3, 5], 2),                 # palette 27
    "pinkband": onband(banded([0, 3, 4, 5, 5, 5, 5], []), 1, (96, 20)),                    # palette 66, 24: pink letters on the pale band
    "greenband": onband(banded([0, 3, 4, 5, 5, 5, 5], []), 1, (48, 20)),                  # palette 67, 25: dark green on light green
    "starter": ui_type.boxed([3, 5, 6, 7, 7, 7, 7], (2, 2), (46, 15), 4),       # palette 63 (55): yellow on brown
    "pitchtag": banded([0, 8, 5, 3, 1, 1, 1], [14]),                                      # palette 62 (8b): red with a white ring
    "rain": banded([0, 9, 10, 12, 13, 14, 15], [3, 4]),                          # palette 45, purple
    "gamew": banded([0, 10, 12, 13, 14, 15, 15], [1]),                           # palette 52, navy
    "bigdrop": dropped([0, 3, 2, 1, 1, 1, 1], [8, 9, 10]),                       # palette 44
    "select": banded([0, 10, 12, 13, 14, 15, 15], [6], 4),                       # palette 75
    "transfer": banded([0, 9, 6, 3, 1, 1, 1], [13]),                             # palette 49, red
    "others": banded([0, 8, 10, 12, 14, 15, 15], [2]),                           # palette 47
    "weekly": banded([0, 6, 4, 3, 2, 1, 1], [15]),                               # palette 126
    "wksun": banded([0, 4, 5, 6, 7, 7, 7], [8, 8]),                              # palette 131
    "wkday": banded([0, 4, 5, 6, 7, 7, 7], [8, 8]),                              # palette 132
    "wksat": banded([0, 3, 4, 5, 6, 7, 7], [8, 8]),                              # palette 133
    "dsun": banded([0, 8, 10, 12, 14, 15, 15], [1]),                             # palettes 54 / 55 / 56
    "dday": banded([0, 8, 10, 12, 14, 15, 15], [1]),
    "dsat": banded([0, 8, 10, 12, 14, 15, 15], [1]),
    "pinkmsg": banded([0, 9, 11, 12, 13, 14, 15], [2], 7),                       # palette 112
    "stopmsg": banded([0, 9, 10, 12, 13, 14, 15], [2], 6),                       # palette 125
    "listnavy": banded([0, 8, 10, 12, 13, 14, 15], [1]),                         # palette 119
    "askhead": banded([0, 9, 11, 13, 14, 14, 14], [1, 3]),                       # palette 116
    "bubble": banded([0, 8, 10, 12, 13, 14, 15], [2]),                           # palette 123
    "fastbtn": banded([0, 11, 10, 9, 9, 9, 9], [4, 6]),                          # palette 105
    "slash": banded([0, 9, 8, 7, 6, 6, 6], [3, 2], 4),                           # palette 26
    "daygame": banded([0, 9, 11, 13, 14, 14, 14], [1]),                           # palette 53 (8d)
})


# ---- ore_sub.arc: r5_ut (vessel), r5_tsu (bonds), y3_prof (profile) --------------------------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))

def with_icon(style, icon, gap=1):
    """`style`'s art with a small picture (rows of palette digits, '.' = clear) kept at its left, centred in height."""
    ic = np.array([[0 if c == "." else int(c, 16) for c in row] for row in icon], np.uint8)
    def made(ink, base):
        art, b = style(ink, base)
        h, w = art.shape
        ih, iw = ic.shape
        H = max(h, ih)
        out = np.zeros((H, iw + gap + w), np.uint8)
        ty, iy = (H - h) // 2, (H - ih) // 2
        out[ty:ty + h, iw + gap:] = art
        sub = out[iy:iy + ih, :iw]
        sub[ic > 0] = ic[ic > 0]
        return out, b + ty
    return made

ICON_SW = ["..ffff..", ".ffffff.", ".ffeefff", "fff22dff", "ffd11bff", "fff87fff", ".fffffff", ".fffffff",
           "fff75fff", "ffd11bff", "fff43eff", ".fffffff"]
ICON_MENU = ["..4553..", ".577773.", "178dd75.", "279ff77.", "178ff77.", ".577775.", ".157751.", ".577773.",
             "178dd75.", "279ff77.", "178ff77.", ".577775.", ".157751."]

STYLES.update({
    # lime headings, green outline and rings (palette 16 of r5_ut / r5_tsu): Vessel, Training, Bonds
    "o2head": called([15, 14, 13, 12], [9, 7], 6, 3, 1, [], 2, 1, 1),
    # purple letters, white band, blue rings (palette 34): Cancel
    "o2cancel": banded([0, 11, 12, 13, 14, 15, 15], [9, 2, 3]),
    # small dark teal letters in a pale mint ring (palette 8 of r5_ut): the display switches
    "o2mini": banded([0, 8, 10, 12, 13, 14, 15], [1]),
    # white letters, dark teal ring, paler ring, mint ring (palette 25): the list tabs
    "o2tab": banded([0, 12, 13, 14, 15, 15, 15], [7, 4, 2]),
    # navy letters, pale ring (palette 11): handedness
    "o2hand": banded([0, 7, 9, 11, 13, 14, 15], [4, 2]),
    # navy letters, white ring, pale blue outer ring (palette 10 of r5_ut): Age
    "o2age": banded([0, 9, 7, 5, 3, 2, 1], [15, 12]),
    # navy letters on white, the corner button kept (palette 10 of r5_tsu)
    "o2switch": with_icon(banded([0, 10, 7, 4, 2, 1, 1], [15, 15]), ICON_SW),
    # white letters in blue rings with the button picture (palette 8 of r5_tsu)
    "o2menu": with_icon(banded([0, 12, 13, 14, 15, 15, 15], [7, 1]), ICON_MENU),
    # gold / purple / green letters in a white band and blue rings (palettes 36, 43, 38)
    "o2btn": banded([0, 12, 13, 14, 15, 15, 15], [9, 3], 2),
    # navy letters, white ring, lime glow (palette 74)
    "o2small": banded([0, 10, 12, 13, 14, 15, 15], [7, 2]),
    # profile: cyan heading (palette 9), pink heading (10), green heading (1), positions (15)
    "o2cyan": banded([0, 12, 13, 14, 15, 15, 15], [6, 9]),
    "o2pink": banded([0, 12, 13, 14, 15, 15, 15], [5, 3]),
    "o2green": called([12, 13, 14, 15], [8, 6], 4, 3, 1, [], 2, 1, 1),
    "o2pos": banded([0, 12, 13, 14, 15, 15, 15], [1, 6]),
})


# ---- ore_sub.arc: y3_kine (trophy room), y3_pmoji (profile words) ----------------------------------------------------

def uniform(style, rows):
    """`style`'s art padded evenly above and below to at least `rows` high (equal shelves for the page packer)"""
    def made(ink, base):
        art, b = style(ink, base)
        h, w = art.shape
        if h >= rows: return art, b
        top = (rows - h) // 2
        out = np.zeros((rows, w), np.uint8)
        out[top:top + h] = art
        return out, b + top
    return made

STYLES.update({
    # y3_pmoji palette 0: navy letters with a pale-blue shadow three pixels deep, down and to the right
    "o3pmraw": dropped([0, 11, 12, 13, 14, 14, 14], [6, 4, 2]),
    "o3pm": uniform(dropped([0, 11, 12, 13, 14, 14, 14], [6, 4, 2]), 20),
    # y3_kine palette 18: white letters, a dark ring and a thin brown one, a one-pixel shadow
    "o3stadraw": banded([0, 10, 12, 14, 15, 15, 15], [3, 1], 2),
    "o3stad": banded([0, 10, 12, 14, 15, 15, 15], [3, 1], 2),
    # y3_kine palette 16: the green sign of the trophy room: yellow letters in pale green, dark green and bright green rings
    "o3memo": banded([0, 12, 13, 14, 15, 15, 15], [9, 5, 4, 2], 0),
    # no art at all (a plate copied by a "paint" entry with "copy")
    "o3none": lambda ink, base: (np.zeros((1, 1), np.uint8), base),
})


# ---- ore_fa.arc: free agency (bank y3_fa) ----------------------------------------------------------------------------

ui_type.TTF["din"] = ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0)


def crisp(fill, rings, shadow=(), cut=3):
    fill = list(fill) if isinstance(fill, (list, tuple)) else [fill]

    def style(ink, base):
        pad = len(rings) + len(shadow) + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big >= cut
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(big.shape, np.uint8)
        edge = masks[-1]
        for k in range(len(shadow), 0, -1):
            out[shift(edge, k, k) | shift(edge, k, k - 1) | shift(edge, k - 1, k)] = shadow[k - 1]
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        out[letters] = np.broadcast_to(row, big.shape)[letters]
        ys = np.nonzero(out.any(1))[0]
        xs = np.nonzero(out.any(0))[0]
        r0, r1, c0, c1 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
        return out[r0:r1, c0:c1], base + pad - r0
    return style


STYLES.update({
    # FA / destination heading (palette 7): blue ramp, white ring
    "fa_head": crisp([5, 5, 4, 4, 3, 3, 2, 2], [15]),
    # the purple labels of the status box (palettes 4 and 5): fill f, white ring 6, blue shadow 9 / 1 / 3
    "fa_label": crisp(15, [6], [9, 1, 3]),
    # the team-choice prompt on the green bar (palette 11): dark green, white ring
    "fa_prompt": crisp(11, [4, 4]),
    # Yes / No and the question (palette 21): deep blue, white ring, pale blue shadow
    "fa_ask": crisp([3, 2, 1, 1, 1], [15, 15], [10, 5, 5]),
})


# ---- the plate of "条件提示" (sprite 11, page 3 rect 0,72,72,104 of y3_fa, palette 2): lettering painted on the plate.

_PLATE = {}


def _old_plate():
    if "p" not in _PLATE:
        path = os.path.join(_U.ORIG_ARC_DIR, "ore_fa.arc")
        if not os.path.exists(path):
            path = os.path.join(_S.DATA_FILES, "ore_fa.arc")
        d = open(path, "rb").read()
        b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == "y3_fa")
        _PLATE["p"] = _U.decode_indices(d, *b["pages"][3])[72:104, 0:72].copy()
    return _PLATE["p"].copy()


def _bg(r, c):
    """Plate colour at row r, column c of the 条件提示 band: pale 'e' (14) to row 15, a dither of e / d (13) from 16 to
    22, 'd' below."""
    if r <= 15 or r == 17:
        return 14
    return {16: 14 if c % 2 == 0 else 13, 18: 13 if c % 2 == 0 else 14, 19: 14 if c % 2 == 0 else 13,
            20: 13 if c % 2 == 0 else 14, 22: 14 if c % 2 == 0 else 13}.get(r, 13)


def offerplate(fill, rings, cx=27, cy=18):
    """The old 72x32 plate with its lettering (columns 0-58, rows 6-28) painted over with the plate colours and the
    English centred at (cx, cy). Use with "left": 0, "baseline": 0."""
    inner = crisp(fill, rings)

    def style(ink, base):
        pic = _old_plate()
        for r in range(6, 29):
            for c in range(0, 59):
                pic[r, c] = _bg(r, c)
        art, b = inner(ink, base)
        h, w = art.shape
        x, y = cx - w // 2, cy - h // 2
        sub = pic[y:y + h, x:x + w]
        sub[art > 0] = art[art > 0]
        return pic, 0
    return style


def offerleft(ink, base):
    """Page 1 rect (0,0,72,80) of y3_fa: the plate end, with the right edge of the 条 painted out (columns 62-71, rows 8-28)."""
    path = os.path.join(_U.ORIG_ARC_DIR, "ore_fa.arc")
    if not os.path.exists(path):
        path = os.path.join(_S.DATA_FILES, "ore_fa.arc")
    d = open(path, "rb").read()
    b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == "y3_fa")
    pic = _U.decode_indices(d, *b["pages"][1])[0:80, 0:72].copy()
    for r in range(8, 29):
        for c in range(62, 72):
            pic[r, c] = _bg(r, c)
    return pic, 0


STYLES["fa_offer"] = offerplate(15, [3, 3])
STYLES["fa_offerleft"] = offerleft


# ---- ore_i_co.arc: the button hints (bank y4_btn) --------------------------------------------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def shaded(ramp, rings, shadow, depth):
    """Letters drawn with `ramp`, solid rings (innermost first), and a solid cast `shadow` `depth` pixels down-right."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings) + depth
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        body = masks[-1]
        cast = np.zeros_like(body)
        for k in range(1, depth + 1):
            cast |= shift(body, k, k) | shift(body, k, k - 1) | shift(body, k - 1, k)
        out = np.zeros(big.shape, np.uint8)
        out[cast & ~body] = shadow
        for m, v in zip(masks[::-1], rings[::-1]):
            out[m] = v
        out[letters] = ramp[big[letters]]
        return out, base + pad
    return style


STYLES.update({
    # palette 0: sky-blue letters, white band, pale outer edge (視点変更)
    "btn_view": banded([0, 4, 14, 14, 14, 14, 14], [4, 4, 1]),
    # palette 6: Type: pale letters in a dark blue body, white outer edge
    "btn_type": banded([0, 6, 15, 15, 15, 15, 15], [6, 6, 6, 1]),
    # palette 1: dark grey letters, white ring, pale blue shadow
    "btn_grey": shaded([0, 6, 15, 15, 15, 15, 15], [6, 6], 3, 3),
    "btn_grey1": shaded([0, 6, 15, 15, 15, 15, 15], [6], 3, 2),
    # palette 4: the same with the darker blue shadow
    "btn_grey2": shaded([0, 6, 15, 15, 15, 15, 15], [6, 6], 2, 3),
    # palette 3: white letters, strong blue band, pale outer edge
    "btn_blue": banded([0, 7, 14, 14, 14, 14, 14], [7, 7, 1]),
    # palette 2: white letters, red band, pale outer edge
    "btn_red": banded([0, 7, 14, 14, 14, 14, 14], [7, 7, 1]),
    # palette 5: red letters, white ring, blue shadow
    "btn_redlet": shaded([0, 4, 15, 15, 15, 15, 15], [4, 4], 10, 3),
})
