"""Label styles of orepena.arc, banks w5_kek, w5_kek00, y3_k, y3_pnews, y3_mjun (results report, game tags, pro news,
standings). Loaded by ui_type.py. gsolid(fills, rings, shadow, cut): crisp letters, fill colours from the top row of
the letters to the foot (one colour = a flat fill), solid one-pixel rings. The definitions come from
ui_specs/orepena2_styles.json, written by _work/ui_pages/gen_orepena_rest1.py."""
import json, os
import numpy as np
import ui_type
from ui_type import grow, shift
import ui_styles_orepena as _O            # DIN font and the "dc<cap>g<gap>b<bold>" / "nb<size>" fonts


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


def _load():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui_specs", "orepena2_styles.json")
    out = {}
    if os.path.exists(path):
        for name, v in json.load(open(path)).items():
            out[name] = _O.make(v) if v.get("kind") == "plate" else gsolid(v["fills"], v["rings"], v.get("shadow", 0), v.get("cut", 2))
    return out


STYLES = _load()
