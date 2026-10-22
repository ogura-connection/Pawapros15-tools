"""Styles for My Life mode (living a pro player's career): the title buttons, team choice, profile screens and card lists, and the in-game HUD, settings, file select and tabs.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): orepena, ore_ini.
"""
import os
import numpy as np
from pp15.art.typeset import banded, ringed, outlined, shadowed, haloed, logo, captioned, dropped, boxed, plated, grow, shift
from pp15 import config
from pp15.art import typeset as ui_type
from pp15.script import scan as _S
from pp15.art import textures as _U
from .common import ringfill, _orig_page

STYLES = {}


# ---- ore_ini.arc: title buttons, team choice, profile screens --------------------------------------------------------

STYLES.update({
    # y3_myt: "Choose your ..." headings, palette 2 of the mye table: gold letters, blue outline, white band, pale shadow
    "mylhead": logo([11, 10, 9, 8, 7], [3], 1, 15, 15, [12], 2, 1),
})


def onbar(inner, nrings, bar, rows, canvas, window, cap=None):
    """A style for lettering on a flat bar (y3_c16, the team-choice headings). The word is drawn by `inner`, centred
    on a canvas `canvas` wide and `rows` (top row, last row) of bar high, over a bar of palette index `bar`; only the
    columns `window` (c0, c1) are returned, so one heading can be shared out over several parts. `cap` = (arc, bank,
    page, rect, row0) puts the original rounded end of the bar in the first columns."""
    def style(ink, base):
        art, b = inner(ink, base)
        h = rows + 1
        top = 1                                                  # bar rows 1 .. h - 1
        capline = b - 1 + nrings                                 # last row of the capitals with their rings
        first = np.nonzero(art.any(1))[0][0]
        t = top + ((h - top) - (capline - first + 1)) // 2 - first
        full = np.zeros((h, canvas), np.uint8)
        left = canvas // 2 - art.shape[1] // 2
        full[top:, :] = bar
        if cap:
            arc, bank, page, (x0, y0, x1, y1), r0 = cap
            full[:, : x1 - x0] = _orig_page(arc, bank, page)[y0 + r0:y0 + r0 + h, x0:x1]
        ys, xs = np.nonzero(art)
        for y, x in zip(ys, xs):
            if 0 <= t + y < h:
                full[t + y, left + x] = art[y, x]
        return full[:, window[0]:window[1]], t + b
    return style


_ring = banded([0, 6, 5, 4, 3, 2, 1], [15])
# sprite 00 of y3_c16: the whole heading on one piece 92 wide; sprite 03: three pieces of a bar 408 wide
STYLES["c16_00"] = onbar(_ring, 1, 11, 16, 116, (0, 116))
STYLES["c16_03a"] = onbar(_ring, 1, 11, 16, 408, (0, 128), ("ore_ini.arc", "y3_c16", 3, (0, 56, 32, 80), 6))
STYLES["c16_03b"] = onbar(_ring, 1, 11, 16, 408, (128, 256))
STYLES["c16_03c"] = onbar(_ring, 1, 11, 16, 408, (256, 376))


def copyof(arc, bank, page, rect, r0, r1):
    """A style that ignores its word and returns the rows r0..r1 of a rectangle of the original page (a plate end that has to stay as it is)."""
    def style(ink, base):
        x0, y0, x1, y1 = rect
        return _orig_page(arc, bank, page)[y0 + r0:y0 + r1 + 1, x0:x1].copy(), 0
    return style


STYLES["c16_cap"] = copyof("ore_ini.arc", "y3_c16", 3, (0, 56, 32, 80), 6, 22)


def gloss(fill, soft, outline, white, rim, shadow, band=2, thick=1, inner=None):
    """Like pp15.art.typeset.logo (letters filled top to foot from `fill`, an `outline`, a `white` band with a `rim`, a cast `shadow`),
    but the soft edge of a letter runs outline -> soft -> fill and never leaves a hole."""
    from pp15.art.typeset import grow, shift
    fill = list(fill)

    def style(ink, base):
        pad = band + 1 + thick + len(shadow)
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        dark = grow(letters, 1)
        for _ in range(thick - 1):
            dark = grow(dark, 1, diagonal=False)
        plate = grow(grow(dark, band - 1), 1, diagonal=False) if band > 1 else grow(dark, 1, diagonal=False)
        edge = grow(plate, 1, diagonal=False)
        out = np.zeros(big.shape, np.uint8)
        for k in range(len(shadow), 0, -1):
            out[shift(edge, k, k) | shift(edge, k, k - 1) | shift(edge, k - 1, k)] = shadow[k - 1]
        out[edge] = rim
        out[plate] = white
        out[dark] = outline
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        ring = np.array([outline] + list(soft))
        lvl = np.rint((big - 1).clip(0, 4) * len(ring) / 4.0).astype(int)        # 1 .. 5 -> outline .. fill
        low = np.where(lvl >= len(ring), row, ring[np.minimum(lvl, len(ring) - 1)])
        out[letters] = np.where(big >= 5, row, low)[letters]
        return out, base + pad
    return style


_YEL = [182, 180, 178, 177, 175, 173, 171, 170, 168, 162, 164]
_SAL = [140, 143, 144, 147, 148, 151, 153, 155, 157, 158, 160]
_PNK = [222, 223, 224, 225, 227, 231, 232, 233, 235, 237, 238, 240]
# y4_t256 (8-bit page, 256 colours): gradient letters, navy outline, white band, cyan rim
STYLES["mlbtn_y"] = gloss(_YEL, [29], 82, 15, 9, [], 3, 2)
STYLES["mlbtn_s"] = gloss(_SAL, [29], 82, 15, 9, [], 3, 2)
STYLES["mlbtn_p"] = gloss(_PNK, [26], 82, 15, 9, [], 3, 2)


# y3_c256 (8-bit): the team-choice banner, orange to pink letters, white / blue / light blue / navy rings, purple shadow
_BAN = [205, 206, 209, 207, 211, 210, 214, 213, 217, 221, 216, 220, 226, 225, 230, 234, 233, 243]
STYLES["mlban"] = ringfill(_BAN, [255, 255, 128, 160, 160, 131], [180, 180])


# ---- ore_ini.arc: the profile card lists (banks y3_mym, y3_mys) ------------------------------------------------------

ui_type.TTF.setdefault("din", ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0))


def bevel(top, core, bottom, thresh=3):
    """Letters with a one-pixel bevel like the Japanese list lettering of y3_mys (palette 8): the left and top
    edge of every stroke is `top`, the right and lower edge `bottom`, the rest `core`; no outline, no soft edge."""
    def style(ink, base):
        pad = 1
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        up = np.zeros_like(m); up[1:] = m[:-1]
        left = np.zeros_like(m); left[:, 1:] = m[:, :-1]
        dn = np.zeros_like(m); dn[:-1] = m[1:]
        rt = np.zeros_like(m); rt[:, :-1] = m[:, 1:]
        out = np.zeros(m.shape, np.uint8)
        out[m] = core
        out[m & (~dn | ~rt)] = bottom
        out[m & (~up | ~left)] = top
        return out, base + pad
    return style


def outlined_pair(top, core, bottom, thresh=3):
    """Letters of palette index `core` in a solid one-pixel ring: `top` on the upper-left side of a stroke, `bottom` on
    the lower-right side (the Japanese list lettering of y3_mys is dark outline / pale fill / dark outline)."""
    def style(ink, base):
        pad = 1
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        ring = grow(m, 1) & ~m
        dn = np.zeros_like(m); dn[:-1] = m[1:]          # letter below
        rt = np.zeros_like(m); rt[:, :-1] = m[:, 1:]    # letter to the right
        out = np.zeros(m.shape, np.uint8)
        out[ring] = bottom
        out[ring & (dn | rt)] = top
        out[m] = core
        return out, base + pad
    return style


def layered(fill, rings, thresh=3, bottom=None, shadow_fill=None):
    """Letters of palette index `fill` (the lowest row of a stroke at least two high is `bottom` if given) inside
    solid one-pixel rings, first value innermost; corners rounded from the second ring on."""
    def style(ink, base):
        pad = len(rings)
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        masks = [grow(m, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = np.zeros(m.shape, np.uint8)
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        out[m] = fill
        if bottom is not None:
            dn = np.zeros_like(m); dn[:-1] = m[1:]
            up = np.zeros_like(m); up[1:] = m[:-1]
            out[m & ~dn & up] = bottom
        return out, base + pad
    return style


def blob(index, radius=3, thresh=2):
    """A black cut-out of the letters grown by `radius` pixels (the shadow sprites): rounded corners."""
    def style(ink, base):
        pad = radius
        h, w = ink.shape
        m = np.zeros((h + 2 * pad, w + 2 * pad), bool)
        m[pad:pad + h, pad:pad + w] = ink >= thresh
        b = grow(m, 1)
        for _ in range(radius - 1):
            b = grow(b, 1, diagonal=False)
        return np.where(b, index, 0).astype(np.uint8), base + pad
    return style


def cardplate(width, plate=1, core=15, light=5, height=16, thresh=3):
    """A label of the profile card: a plate (index `plate`) at least `width` wide and `height` high with the letters
    (index `core`) centred on it and a one-pixel `light` shadow below and to the right of them."""
    def style(ink, base):
        h, w = ink.shape
        bw, bh = max(width, w + 4), max(height, h + 2)
        x, y = (bw - w) // 2, max((bh - base) // 2, 0)
        bh = max(bh, y + h)
        m = np.zeros((bh, bw), bool)
        m[y:y + h, x:x + w] = ink >= thresh
        out = np.full((bh, bw), plate, np.uint8)
        sh = np.zeros_like(m); sh[1:, 1:] = m[:-1, :-1]
        out[sh & ~m] = light
        out[m] = core
        return out, y + base
    return style


STYLES.update({
    "mysr": outlined_pair(5, 14, 7),
    # y3_mys (palette 8, pink ramp): core 14 (e), left/top edge 5, right/bottom edge 7
    "mysl": bevel(5, 14, 7),
    # y3_mym pitching forms (palette 12): fill f (lowest row b), ring 7 (white), halo 4 (mint)
    "mypit": layered(15, [7, 4], bottom=11),
    # batting forms (palette 13): pink fill f (lowest row b) in a black ring (indices 1-7 are all black)
    "mybat": layered(15, [7, 4], bottom=11),
    # the black shadow sprites 2f-3a (palette 38, one colour)
    "myshad": blob(1, 3),
    # the turn-view hints (palette 20): mint fill f, dark blue ring a, mid blue 4, light halo 1
    "myhint": layered(15, [10, 4, 1]),
    # the card labels (palette 7): plate 1, dark letters f, white shadow 5
    "mycard40": cardplate(40), "mycard48": cardplate(48), "mycard64": cardplate(64),
})


# ---- orepena.arc: HUD, settings, file select, tabs -------------------------------------------------------------------

ui_type.TTF["din"] = ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0)
_ARC = {}


def _din_font(cap, gap, bold, space=None):
    """Font "dc<cap>g<gap>b<bold*100>": DIN Condensed Bold one letter at a time with `gap` clear columns between
    letters (the rings of neighbours must not run together)."""
    def make(project=None):
        glyphs = {}
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,!?&'/-+:"
        for ch in chars:
            ink, base = ui_type.ttf_ink(ch, "din", cap, 0.0, 1.0, bold)
            glyphs[ch] = (ink, ink.shape[0] - base)
        return {"words": {}, "glyphs": glyphs, "space": space or max(3, round(cap * 0.3)), "gap": gap}
    return make


def _nb_font(size, gap=1, bold=0):
    """Font "nb<size>": Arial Narrow Bold hinted at `size` pixels, no anti-aliasing: crisp pixels for small lettering."""
    def make(project=None):
        from PIL import Image, ImageDraw, ImageFont
        f = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Narrow Bold.ttf", size)
        glyphs = {}
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,!?&'/-+:~"
        for ch in chars:
            im = Image.new("L", (size * 2, size * 3), 0)
            dr = ImageDraw.Draw(im)
            dr.fontmode = "1"
            dr.text((2, size * 2), ch, font=f, fill=255, anchor="ls")
            a = np.asarray(im) > 0
            if bold:
                a = a | np.pad(a, ((0, 0), (1, 0)))[:, :-1]
            ys, xs = np.nonzero(a)
            ink = np.where(a[ys.min():ys.max() + 1, xs.min():xs.max() + 1], 6, 0)
            glyphs[ch] = (ink, ys.max() + 1 - size * 2)
        return {"words": {}, "glyphs": glyphs, "space": max(3, size // 4), "gap": gap}
    return make


for _s in range(9, 19):
    ui_type.FONTS["nb%d" % _s] = _nb_font(_s)
    ui_type.FONTS["nb%db" % _s] = _nb_font(_s, 1, 1)


for _cap in range(8, 29):
    for _gap in (1, 2):
        for _b in (0, 10, 20, 30):
            ui_type.FONTS["dc%dg%db%d" % (_cap, _gap, _b)] = _din_font(_cap, _gap, _b / 100.0)


def _arc():
    from pp15.art import textures as U
    if "d" not in _ARC:
        _ARC["d"] = open(os.path.join(U.ORIG_ARC_DIR, "orepena.arc"), "rb").read()
        _ARC["b"] = {x["name"]: x for x in U.banks(_ARC["d"], U.elf_symbols(_ARC["d"]))}
    return _ARC["d"], _ARC["b"]


def old_page(bank, pg):
    from pp15.art import textures as U
    if "d" not in _ARC:
        _ARC["d"] = open(os.path.join(U.ORIG_ARC_DIR, "orepena.arc"), "rb").read()
        _ARC["b"] = {x["name"]: x for x in U.banks(_ARC["d"], U.elf_symbols(_ARC["d"]))}
    d, b = _ARC["d"], _ARC["b"][bank]
    return U.decode_indices(d, *b["pages"][pg])


def layers(bank, rect):
    """(runs from the outside in as [(index, thickness)], fill index, shadow index or None, counts) of the old art."""
    pg, x0, y0, x1, y1 = rect
    idx = old_page(bank, pg)[y0:y1, x0:x1]
    m = idx > 0
    pad = np.pad(m, 1)
    dist = np.zeros(m.shape, int)
    cur = pad.copy()
    k = 0
    inner = m.copy()
    while inner.any():
        k += 1
        dist[inner] = k
        er = np.pad(inner, 1)
        inner = inner & er[:-2, 1:-1] & er[2:, 1:-1] & er[1:-1, :-2] & er[1:-1, 2:] & er[:-2, :-2] & er[:-2, 2:] & er[2:, :-2] & er[2:, 2:]
    core = idx[(dist >= 3)]
    fill = int(np.bincount(core).argmax()) if core.size else int(np.bincount(idx[m]).argmax())
    runs = []
    for dd in range(1, 6):
        v = idx[dist == dd]
        if not v.size:
            break
        mode = int(np.bincount(v).argmax())
        if mode == fill and dd > 1:
            break
        if runs and runs[-1][0] == mode:
            runs[-1][1] += 1
        else:
            runs.append([mode, 1])
    return runs, fill


def solid(fill, rings, shadow=0, cut=3, ramp=None):
    """rings: colours from the innermost (against the letters) outwards, one pixel each; the corners of the
    rings after the first are rounded."""
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
    """Styles written by _work/ui_pages/gen_orepena_spec.py to specs/orepena_styles.json:
    {name: {"kind": "solid", "fill", "rings", "shadow"}}."""
    import json
    path = os.path.join(config.SPECS_DIR, "orepena_styles.json")
    out = {}
    if os.path.exists(path):
        for name, v in json.load(open(path)).items():
            out[name] = make(v)
    return out


def make(v):
    if v["kind"] == "solid":
        return solid(v["fill"], v["rings"], v.get("shadow", 0), v.get("cut", 3))
    if v["kind"] == "plate":
        return plate(v)
    raise ValueError(v)


def plate(v):
    """A plate with lettering painted on it (the old art of the rectangles v["rects"] [[page, x0, y0, x1, y1], ...] side by
    side, as one picture), the lettering box v["erase"] [x0, y0, x1, y1] painted over with the plate colour (the colour
    just below the box), and the English drawn by solid(v["fill"], v["rings"], v["shadow"]) centred at (v["cx"], v["cy"])
    of the picture. The style returns the columns v["part"] = (a, b) of the picture, with baseline 0: the label of
    each rectangle has "left": 0 and "baseline": 0 and keeps its place."""
    inner = solid(v["fill"], v["rings"], v.get("shadow", 0), v.get("cut", 3))

    def style(ink, base):
        pic = np.concatenate([old_page(v["bank"], pg)[y0:y1, x0:x1].copy() for pg, x0, y0, x1, y1 in v["rects"]], axis=1)
        ex0, ey0, ex1, ey1 = v["erase"]
        pic[ey0:ey1, ex0:ex1] = pic[ey1 + 1, (ex0 + ex1) // 2]
        art, b = inner(ink, base)
        h, w = art.shape
        x = v["cx"] - w // 2
        y = v["cy"] - h // 2
        sub = pic[y:y + h, x:x + w]
        sub[art > 0] = art[art > 0]
        a, c = v["part"]
        return pic[:, a:c], 0
    return style


STYLES.update(_load())


# ---- My Life tabs ----------------------------------------------------------------------------------------------------

# DIN Condensed Bold: tall narrow letters with strokes two pixels wide, like the Japanese lettering (font spec
# "ttf:din:<cap height>:0:1:0")
ui_type.TTF["din"] = ("/System/Library/Fonts/Supplemental/DIN Condensed Bold.ttf", 0)

STYLES.update({
    # the My Life menu tabs (orepena.arc, y3_menu, palette 4, a blue-to-white ramp): white letters whose soft edge runs
    # down to the blue of the outline, a solid dark blue ring (6) and a solid paler blue ring outside it (5), as round
    # the Japanese letters (whose outline is 6 / 7 with a lighter outer edge of 5)
    "mltab": banded([0, 8, 10, 12, 14, 15, 15], [6, 5]),
})


# ---- orepena.arc fixes (fxA_...) -------------------------------------------------------------------------------------

STYLES['fxA_10_10_6_r4_s44e4'] = ringfill([10, 10, 10, 10, 10, 10], [4], [4, 4, 14, 4])
STYLES['fxA_12_12_6_r111_s'] = ringfill([12, 12, 12, 12, 12, 12], [1, 1, 1], [])
STYLES['fxA_15_15_6_r22_s'] = ringfill([15, 15, 15, 15, 15, 15], [2, 2], [])
STYLES['fxA_15_15_6_r333_s'] = ringfill([15, 15, 15, 15, 15, 15], [3, 3, 3], [])
STYLES['fxA_15_15_6_r33_s'] = ringfill([15, 15, 15, 15, 15, 15], [3, 3], [])
STYLES['fxA_15_15_6_r442_s'] = ringfill([15, 15, 15, 15, 15, 15], [4, 4, 2], [])
STYLES['fxA_15_15_6_r44_s'] = ringfill([15, 15, 15, 15, 15, 15], [4, 4], [])
STYLES['fxA_15_15_6_r55_s'] = ringfill([15, 15, 15, 15, 15, 15], [5, 5], [])
STYLES['fxA_1_1_6_rff_s'] = ringfill([1, 1, 1, 1, 1, 1], [15, 15], [])
STYLES['fxA_6_6_6_r11_s'] = ringfill([6, 6, 6, 6, 6, 6], [1, 1], [])
STYLES['fxA_6_6_6_rff_s'] = ringfill([6, 6, 6, 6, 6, 6], [15, 15], [])
STYLES['fxA_6_6_6_rfff_s'] = ringfill([6, 6, 6, 6, 6, 6], [15, 15, 15], [])
