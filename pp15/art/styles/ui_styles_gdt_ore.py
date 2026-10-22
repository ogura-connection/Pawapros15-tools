"""Label styles for gdt_ore.arc (My Life match overlays: h3_apm_0, y3_ss, y4_ind_0). Loaded by pp15/art/typeset.py.

gdt_ore.arc merges sprite sets into one bank: h3_apm_0 holds the pages of h3_apm (0-3) and y3_sb (4, 5); y3_ss holds y3_ss
(0, 1), y3_cd (2-4) and g3_mib (5-10). The sprites of the later sets count their pages from 0 again; pp15.art.textures.split_merged
makes every set a bank of its own with its own pages."""
import re
import numpy as np
from pp15 import config
from pp15.art import typeset as ui_type
from pp15.art import textures as _U
from pp15.art.typeset import grow, shift

# (the bank split that was here is now pp15.art.textures.split_merged)

STYLES = {}

from .ui_styles_orepena import solid          # also registers the font "din" and the DIN fonts
# white letters (palette index 15 of the grey ramp of palettes 0 and 151), a solid near-black ring and a black ring outside it
STYLES["gdo_white"] = solid(15, [2, 1], cut=3)
STYLES["gdo_white1"] = solid(15, [1], cut=3)
STYLES["gdo_big"] = solid(15, [2, 1], cut=3)                 # the big lettering (First Duel): a thicker ring
# y3_ss event captions (palette 0, teal ramp): white letters, a mint ring and a dark teal ring
STYLES["gdo_cyan"] = solid(15, [1], cut=3)
# y4_ind_0 thanks banner (palette 0, blue ramp): white letters, two sky-blue rings, two dark blue, one slate
STYLES["gdo_dream"] = solid(15, [10, 10, 4, 4, 2], cut=3)


def solid_grad(fills, rings, cut=3):
    """Like solid(), but the letters take their colour row by row from `fills` (top to bottom): a metallic gradient."""
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
        for mk, v in zip(masks[::-1], rings[::-1]):
            out[mk] = v
        ys = np.nonzero(letters.any(1))[0]
        top, bot = ys.min(), ys.max() + 1
        for y in range(top, bot):
            v = fills[min(len(fills) - 1, (y - top) * len(fills) // (bot - top))]
            out[y][letters[y]] = v
        ys = np.nonzero(out.any(1))[0]
        xs = np.nonzero(out.any(0))[0]
        r0, r1, c0, c1 = ys.min(), ys.max() + 1, xs.min(), xs.max() + 1
        return out[r0:r1, c0:c1], base + pad - r0
    return style


# y4_ind_0 ribbon (palette 1, grey ramp): white to light grey top to bottom, black ring
STYLES["gdo_ribbon"] = solid_grad([13, 12, 11, 10, 10, 9], [1, 1, 1], cut=3)

# ---- letters on plates: styles written by _work/ui_pages/gen_gdt_ore_spec.py to specs/gdt_ore_styles.json
# {name: {"kind": "pill", "bank", "rect": [page, x0, y0, x1, y1], "ref": column, "erase": [c0, c1], "fill", "rings", "cx", "baseline"}}
# pill: the old picture of the rectangle with the columns erase[0]..erase[1] set to what column `ref` shows (a clean piece of the
# plate; the lettering and its shadow above and below are gone) and the English drawn over it; the picture is the label's art.
# {"kind": "badge", ... "box": [x0, y0, x1, y1], "colour"}: the box of the picture painted with one colour, the English over it.
import json as _json
import os as _os

_OLD = {}


def _old_page(bank, pg):
    if "d" not in _OLD:
        p = _os.path.join(_U.ORIG_ARC_DIR, "gdt_ore.arc")
        if not _os.path.exists(p):
            p = _os.path.join(_U.S.DATA_FILES, "gdt_ore.arc")
        _OLD["d"] = open(p, "rb").read()
        _OLD["b"] = {x["name"]: x for x in _U.banks(_OLD["d"], _U.elf_symbols(_OLD["d"]))}
    return _U.decode_indices(_OLD["d"], *_OLD["b"][bank]["pages"][pg])


def _make(v):
    inner = solid(v["fill"], v["rings"], v.get("shadow", 0), v.get("cut", 3))

    def style(ink, base):
        pg, x0, y0, x1, y1 = v["rect"]
        pic = _old_page(v["bank"], pg)[y0:y1, x0:x1].copy()
        if v["kind"] == "pill":
            c0, c1 = v["erase"]
            pic[:, c0:c1] = pic[:, v["ref"]][:, None]
        else:
            bx0, by0, bx1, by1 = v["box"]
            pic[by0:by1, bx0:bx1] = v["colour"]
        art, b = inner(ink, base)
        h, w = art.shape
        x = v["cx"] - w // 2
        y = v["baseline"] - b
        ys0, xs0 = max(y, 0), max(x, 0)
        sub = art[ys0 - y:, xs0 - x:][:pic.shape[0] - ys0, :pic.shape[1] - xs0]
        area = pic[ys0:ys0 + sub.shape[0], xs0:xs0 + sub.shape[1]]
        area[sub > 0] = sub[sub > 0]
        return pic, 0
    return style


def _load():
    path = _os.path.join(config.SPECS_DIR, "gdt_ore_styles.json")
    out = {}
    if _os.path.exists(path):
        for name, v in _json.load(open(path)).items():
            out[name] = _make(v)
    return out


STYLES.update(_load())

# g3_mib 監督 / コーチ (palette 10): dark blue letters, a white ring two pixels wide and a pale blue shadow ring
STYLES["gdo_mgr"] = solid(1, [8, 8, 11], cut=3)
# y3_sb 監督 badge (palette 5): white letters, dark blue rings
STYLES["gdo_navy"] = solid(14, [3, 1], cut=3)
