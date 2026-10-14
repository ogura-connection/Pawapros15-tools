"""Label styles of ore_i_co.arc (bank y4_btn: the button hints). Loaded by ui_type.py."""
import numpy as np
import ui_type
from ui_type import banded, grow, shift

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


STYLES = {
    # palette 0: sky-blue letters, white band, pale outer edge (視点変更)
    "btn_view": banded([0, 12, 13, 14, 14, 14, 14], [4, 4, 1]),
    # palette 6: Type: pale letters in a dark blue body, white outer edge
    "btn_type": banded([0, 14, 15, 15, 15, 15, 15], [6, 6, 6, 1]),
    # palette 1: dark grey letters, white ring, pale blue shadow
    "btn_grey": shaded([0, 9, 12, 14, 15, 15, 15], [6, 6], 3, 3),
    # palette 4: the same with the darker blue shadow
    "btn_grey2": shaded([0, 9, 12, 14, 15, 15, 15], [6, 6], 2, 3),
    # palette 3: white letters, strong blue band, pale outer edge
    "btn_blue": banded([0, 12, 13, 14, 14, 14, 14], [7, 7, 1]),
    # palette 2: white letters, red band, pale outer edge
    "btn_red": banded([0, 12, 13, 14, 14, 14, 14], [7, 7, 1]),
    # palette 5: red letters, white ring, blue shadow
    "btn_redlet": shaded([0, 11, 13, 15, 15, 15, 15], [4, 4], 10, 3),
}
