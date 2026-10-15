"""Label styles of art run 6, agent D (pn_fa.arc, pn_tgrow.arc). Loaded by ui_type.py. Crisp solid rings, fill ramps only."""
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat

STYLES = {}

# ---- pn_fa.arc g3_fa_0 ---------------------------------------------------------------------------------------------
STYLES["d6_title"] = ringfill([1, 1, 2, 2, 3, 3], [9, 11], [14, 15])        # pal 192: yellow letters, blue ring, white ring, ice shadow
STYLES["d6_b09"] = ringfill([14, 15, 15, 15, 15, 15], [2], [6])               # pal 40: dark red letters, white ring
STYLES["d6_b0a"] = ringfill([14, 15, 15, 15, 15, 15], [9], [8])               # pal 38: brown letters
STYLES["d6_b0b"] = ringfill([14, 14, 13, 13, 14, 14], [9], [3])               # pal 54: purple letters, white ring
STYLES["d6_b0c"] = ringfill([14, 15, 15, 15, 15, 15], [1], [8])               # pal 56: green letters
import numpy as np
from ui_styles_ore_ini import _orig_page


def _neg(inner, rows=(6, 30), cols=(4, 26)):
    """The green box of g3_fa_0 sprite 22 (page 6, rect 96,96,128,128), its face cleaned of the kanji, with `inner`'s lettering on it."""
    def style(ink, base):
        art, b = inner(ink, base)
        plate = _orig_page("pn_fa.arc", "g3_fa_0", 6)[96:128, 96:128].astype(np.uint8).copy()
        plate[3:29, 4:26] = 12                                   # the green ring, filled
        h, w = art.shape
        ox, oy = cols[0] + (cols[1] - cols[0] - w) // 2, rows[0] + (rows[1] - rows[0] - h) // 2
        ys, xs = np.nonzero(art)
        for y, x in zip(ys, xs):
            if 0 <= oy + y < 32 and 0 <= ox + x < 32:
                plate[oy + y, ox + x] = art[y, x]
        return plate, oy + b
    return style


STYLES["d6_neg"] = _neg(ringfill([8, 8, 7, 7, 6, 6], [11], []))             # pal 197: teal letters on the green box
STYLES["d6_teal"] = ringfill([5, 5, 4, 4, 3, 3], [8], [1])                    # pal 70: teal letters, white ring
STYLES["d6_wn212"] = ringfill([15, 15, 14, 14, 13, 13], [7], [8])             # pal 212: white letters, navy ring
STYLES["d6_wn216"] = ringfill([15, 15, 15, 15, 14, 14], [9], [8, 8])          # pal 216: white letters, navy ring
STYLES["d6_wn213"] = ringfill([15, 15, 14, 14, 13, 13], [8], [9])             # pal 213: stat headers
STYLES["d6_pale"] = ringfill([9, 9, 9, 5, 5, 5], [1])                         # pal 220: pale blue letters on grey
STYLES["d6_olive"] = ringfill([14, 13, 12, 11, 10, 9], [6, 4], [3])           # pal 209: olive-gold
STYLES["d6_navy"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)                        # pal 215: navy letters on a white plate
STYLES["d6_cyan"] = ringfill([5, 6, 12, 12, 13, 13], [1, 3], [2])             # pal 193: cyan notice

# ---- pn_fa.arc w5_fa / w5_faz ----------------------------------------------------------------------------------------
STYLES["d6_w_b4"] = ringfill([14, 15, 15, 15, 15, 15], [9], [3, 3])           # pal 4: crimson letters, white ring, blue shadow
STYLES["d6_w_b7"] = ringfill([14, 15, 15, 15, 15, 15], [9], [3, 3])           # pal 7: purple (same ramp numbers, other palette)
STYLES["d6_w_b8"] = ringfill([14, 15, 15, 15, 15, 15], [9], [3, 3])           # pal 8: violet-blue
STYLES["d6_w_title"] = ringfill([12, 12, 13, 13, 14, 14], [3], [1])           # pal 22: lavender-white letters, violet ring
STYLES["d6_w_sal"] = ringfill([15, 15, 14, 14, 13, 13], [3], [1])             # pal 19: white letters, navy ring
STYLES["d6_w_sent"] = ringfill([15, 14, 14, 13, 13, 13], [3], [1])            # pal 26: the sentence, blue ring
