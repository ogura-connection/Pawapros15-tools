"""Label styles for ore_ren.arc (My Life practice menu: banks g3_0ren, g3_1ren .. g3_3ren). Loaded by ui_type.py.

1. ore_ren.arc has no palette symbol for g3_1ren, g3_2ren and g3_3ren, so ui_textures.banks() returns the three as one
   bank "g3_1ren" (27 pages, 212 sprites) in which the sprites of g3_2ren / g3_3ren count their pages from 0 again.
   ui_textures.split_merged gives the three back as separate banks with the pages of each.
2. Styles ren_<n> from ui_specs/ore_ren_styles.json (written by _work/ui_pages/gen_ore_ren_spec.py): crisp letters in one
   fill colour inside solid one-pixel rings, the colours read from the Japanese lettering (palette indices).
"""
import json, os, re
import numpy as np
import ui_type
import ui_textures as _U
from ui_type import grow, shift
import ui_styles_orepena as _O            # registers the DIN fonts "dc<cap>g<gap>b<bold>" and "nb<size>"

# (the bank split that was here is now ui_textures.split_merged)


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
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui_specs", "ore_ren_styles.json")
    out = {}
    if os.path.exists(path):
        for name, v in json.load(open(path)).items():
            out[name] = solid(v["fill"], v["rings"], v.get("shadow", 0), v.get("cut", 2))
    return out


STYLES = _load()
