"""Label styles of ore_myk.arc (My Life records screens, bank y3_my). Loaded by ui_type.py.
Crisp letters in one fill colour inside solid one-pixel rings (colours from the innermost out), palette indices of each
Japanese lettering's own palette (33 stat plates, 19 yellow headings, 21 team tags, 38 small blue text, 8-11 tabs,
26 / 27 SELECT hints, 55 title)."""
import numpy as np
import ui_type
from ui_type import grow, shift

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


STYLES = {
    "myk_stat": crisp(14, [4, 6]),               # palette 33: white in a blue ring and a navy ring
    "myk_head": crisp(15, [10, 3], cut=2),           # palette 19: yellow, brown ring, white band, pale blue glow
    "myk_team": crisp(13, [10, 2]),              # palette 21: peach in a dark red ring and an orange ring
    "myk_small": crisp(5, [2], cut=3),                  # palette 38: blue letters in a pale blue ring
    "myk_tab": crisp(15, [2], cut=3),                # palettes 8-11: white in the tab's dark ring
    "myk_sel_b": crisp(14, [7], cut=3),              # palette 27: SELECT hint, blue
    "myk_sel_r": crisp(14, [7], cut=3),              # palette 26: SELECT hint, red
    "myk_title": crisp(15, [4, 8], cut=3),              # palette 55: green title
}
