"""Label styles of orepena.arc (My Life HUD, settings, file select, tabs). Loaded by pp15/art/typeset.py.
solid(fill, rings, shadow): crisp letters (ink >= 3 of 6), one solid fill, solid one-pixel rings, optional shadow.
auto(...): the colours are read from the Japanese lettering of a given rectangle (outermost runs of the same
colour are the band, then the outline, the most common inner colour is the fill)."""
import os
import numpy as np
from pp15 import config
from pp15.art import typeset as ui_type
from pp15.art.typeset import grow, shift

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


STYLES = _load()
