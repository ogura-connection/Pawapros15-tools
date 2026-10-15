"""Label styles of art run 2, agent B (scs_sce3.arc: scenario 3 job list, company names, training screen; scs_sce2.arc: company
ranks). Loaded by ui_type.py. Colours are read from the Japanese lettering of each palette (_work/ui_pages/tools/roles.py).
Every style is crisp: solid one-pixel rings (ui_styles_ore_ini.ringfill), no half tones except the fill gradients."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}
ui_type.TTF.setdefault("avm", ("/System/Library/Fonts/Avenir Next Condensed.ttc", 5))      # Avenir Next Condensed Medium: small lettering


def trim(out, base):
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


def flat(ramp, cut=1):
    """Letters only, no ring: ink level k (1..6) -> palette index ramp[k]; pixels below `cut` are clear."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        return trim(np.where(ink >= cut, ramp[ink], 0).astype(np.uint8), base)
    return style


def rimmed(fill, rings, shadow, rim, edge=3):
    """ringfill letters (`rings` round them, `shadow` cast down and to the right), then a one-pixel `rim` all round the
    whole thing (the thin blue edge of the company names)."""
    inner = ringfill(fill, rings, shadow, edge)

    def style(ink, base):
        art, b = inner(ink, base)
        big = np.zeros((art.shape[0] + 4, art.shape[1] + 4), np.uint8)
        big[2:-2, 2:-2] = art
        solid = big > 0
        out = big.copy()
        out[grow(solid, 1) & ~solid] = rim
        return trim(out, b + 2)
    return style


# ---- y5_hak_0: the job list (scenario 3) -------------------------------------------------------------------------------
# list lines (palette 18): white letters in a one-pixel mid blue ring (one ring keeps the counters of small letters open)
STYLES["b_hak_line"] = ringfill([0xf], [0x3])
# trust ratings (palette 17): dark blue letters, a one-pixel light blue ring
STYLES["b_hak_rate"] = ringfill([0xf], [0x7])
# headings on the cream and white plates (palette 19, black on a grey ramp: 0xf black .. 1 light grey)
STYLES["b_hak_tag"] = flat([0, 0, 0xa, 0x5, 0xd, 0xf, 0xf], cut=2)

# ---- y5_siba_3: company names (palette 22): white letters, a black ring and shadow, a thin blue rim ---------------------------
STYLES["b_sib_name"] = rimmed([0xf], [5, 5], [5, 5], 4)


def plated(ink_ramp, plate, size):
    """Letters painted with `ink_ramp` (ink 0..6 -> index) on a w x h plate: `plate(w, h)` returns the plate indices."""
    ink_ramp = np.array(ink_ramp, np.uint8)
    w, h = size

    def style(ink, base):
        pl = plate(w, h)
        ih, iw = ink.shape
        if iw > w - 4 or ih > h - 4:
            raise ValueError("lettering %dx%d does not fit a plate %dx%d" % (iw, ih, w, h))
        x, y = (w - iw) // 2, (h - ih) // 2
        sub = pl[y:y + ih, x:x + iw]
        sub[:] = np.where(ink > 0, ink_ramp[ink], sub)
        return pl, base + y
    return style


def pay_plate(w, h):
    """The 報酬 heading plate (palette 18): white inside a lavender edge, a dark shadow line right and below."""
    p = np.zeros((h, w), np.uint8)
    p[0:h - 1, 0:w - 1] = 7
    p[1:h - 2, 1:w - 2] = 0xf
    p[1, 2:w - 3] = 0xc                       # a lit top edge
    p[h - 3, 2:w - 3] = 0xa                   # and a soft bottom edge
    for (y, x) in ((0, 0), (0, w - 2), (h - 2, 0), (h - 2, w - 2)):
        p[y, x] = 0                           # rounded corners
    p[1:h - 1, w - 1] = 1
    p[h - 1, 1:w] = 1
    return p


_PAY = {}
for _h in (20, 22, 24):
    for _w in range(24, 41):
        STYLES["b_sib_pay_%d_%d" % (_w, _h)] = plated([0, 0xe, 0x8, 0x5, 0x3, 0x2, 0x2], pay_plate, (_w, _h))
STYLES["b_sib_pay_measure"] = ringfill([2], [])

# ---- y5_sjk_0: the training screen ---------------------------------------------------------------------------------------
# stat labels (palette 16): white letters, a dark blue ring, a white outer ring
STYLES["b_sjk_stat"] = ringfill([0xf], [5, 5, 0xf, 0xe])
# banners: a gradient from near white to a saturated colour, a thick dark ring, a white outer ring
STYLES["b_sjk_pink"] = ringfill([0xe, 0xd, 0xc, 0xb, 0xa, 0x9], [3, 3, 3, 0xf, 0xf])      # palette 20: Shift Over
STYLES["b_sjk_green"] = ringfill([0xe, 0xd, 0xc, 0xb, 0xa, 0x9], [3, 3, 3, 0xf, 0xf])     # palette 21: On the Job
STYLES["b_sjk_blue"] = ringfill([0xe, 0xd, 0xc, 0xb, 0xa, 0x9], [1, 1, 1, 0xf, 0xf])      # palette 22: Job Complete

# ---- y5_siba_2: company ranks (scenario 2) -------------------------------------------------------------------------------
# the small "Rank" heading above each plate: dark letters, a white ring, a grey soft shadow (palettes 22 / 23 / 24)
STYLES["b_ran_head1"] = ringfill([2, 2, 3], [0xf, 0xf], [6])
STYLES["b_ran_head2"] = ringfill([3, 2, 2], [0xf, 0xf], [6])
STYLES["b_ran_head3"] = ringfill([3, 2, 2], [0xf, 0xf], [5])
# the rank on the plate: Grade 3 thin dark grey on pale blue (palette 19), Grade 2 bold blue (20), Grade 1 bold brown (21)
STYLES["b_ran_3"] = ringfill([1, 1, 2], [0xf])
STYLES["b_ran_2"] = ringfill([1, 1, 2], [0xb])
STYLES["b_ran_1"] = ringfill([1, 1, 7], [0xf])
