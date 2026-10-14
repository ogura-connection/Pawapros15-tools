"""Label styles and a bank fix for gdt_ore.arc (My Life match overlays: h3_apm_0, y3_ss, y4_ind_0). Loaded by ui_type.py.

gdt_ore.arc merges sprite sets into one bank: h3_apm_0 holds the pages of h3_apm (0-3) and y3_sb (4, 5); y3_ss holds y3_ss
(0, 1), y3_cd (2-4) and g3_mib (5-10). The sprites of the later sets count their pages from 0 again. banks() is wrapped
here for this one file (recognised by its symbols) so that every set is a bank of its own with its own pages."""
import re
import numpy as np
import ui_type
import ui_textures as _U
from ui_type import grow, shift

_orig_banks = _U.banks


def _split(d, syms):
    out = []
    for b in _orig_banks(d, syms):
        if b["pal"] is not None and "tex_y3_sb00" in syms and "tex_h3_apm00" in syms and b["name"] == "h3_apm_0":
            sets = {"h3_apm_0": "opd_h3_apm_0_", "y3_sb": "opd_y3_sb_"}
        elif b["pal"] is not None and "tex_y3_cd00" in syms and b["name"] == "y3_ss":
            sets = {"y3_ss": "opd_y3_ss_", "y3_cd": "opd_y3_cd_", "g3_mib": "opd_g3_mib_"}
        else:
            out.append(b)
            continue
        pages = list(zip(b["page_names"], b["pages"]))
        for nm, pre in sets.items():
            tex = {"h3_apm_0": "tex_h3_apm", "y3_sb": "tex_y3_sb", "y3_ss": "tex_y3_ss", "y3_cd": "tex_y3_cd", "g3_mib": "tex_g3_mib"}[nm]
            mine = [(pn, pg) for pn, pg in pages if pn.startswith(tex)]
            nb = dict(b)
            nb.update({"name": nm, "pages": [pg for _, pg in mine], "page_names": [pn for pn, _ in mine],
                       "sprites": {n: ps for n, ps in b["sprites"].items() if n.startswith(pre)}})
            out.append(nb)
    return out


_U.banks = _split

STYLES = {}

from ui_styles_orepena import solid          # also registers the font "din" and the DIN fonts
# white letters (palette index 15 of the grey ramp of palettes 0 and 151), a solid near-black ring and a black ring outside it
STYLES["gdo_white"] = solid(15, [2, 1], cut=3)
STYLES["gdo_white1"] = solid(15, [1], cut=3)
STYLES["gdo_big"] = solid(15, [2, 1], cut=3)                 # the big lettering (First Duel): a thicker ring
# y3_ss event captions (palette 0, teal ramp): white letters, a mint ring and a dark teal ring
STYLES["gdo_cyan"] = solid(15, [3, 1], cut=3)
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
