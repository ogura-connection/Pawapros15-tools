"""Styles for the scenario screens of Success Mode and for its Linked World screens.

The player sees the job list, company names and training screen of scenarios 2 and 3, and the Linked World screens
(player cards from other save files).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): scc_tops, scs_sce3, scs_sce2.
"""
import numpy as np
from pp15.art.typeset import grow, shift
from pp15.art import typeset as ui_type
from .common import ringfill

STYLES = {}


# ---- scs_sce2.arc, scs_sce3.arc: scenario 3 job list, company names, training screen ---------------------------------

ui_type.TTF.setdefault("b_times", ("/System/Library/Fonts/Supplemental/Times New Roman.ttf", 0))             # Grade 3: thin serif letters
ui_type.TTF.setdefault("b_timesb", ("/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf", 0))         # Grades 2 and 1: heavy serif letters (lining figures)
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

# ---- y5_siba_3: company names (palette 22): white letters, a black ring and a one-pixel shadow, a thin blue rim ---------------------------
STYLES["b_sib_name"] = rimmed([0xf], [5, 5], [5], 4)


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
    """The 報酬 heading plate (palette 18): white inside a lavender edge, rounded corners, a dark shadow line right and below."""
    p = np.zeros((h, w), np.uint8)
    bw, bh = w - 1, h - 1                      # the plate proper; column w-1 and row h-1 carry the shadow
    p[0:bh, 0:bw] = 7
    p[1:bh - 1, 1:bw - 1] = 0xf
    p[1, 1:bw - 1] = 0xc                       # a lit top edge
    p[bh - 2, 1:bw - 1] = 0xa                  # and a soft bottom edge
    p[bh - 3, 1:bw - 1] = 0xd
    for r, n in ((0, 3), (1, 2), (2, 1)):      # rounded corners: n pixels cut from the corner rows
        for x in range(n):
            for (yy, xx) in ((r, x), (r, bw - 1 - x), (bh - 1 - r, x), (bh - 1 - r, bw - 1 - x)):
                p[yy, xx] = 0
    p[1:bh, bw] = np.where(p[1:bh, bw - 1] > 0, 1, 0)
    p[bh, 1:bw + 1] = np.where(p[bh - 1, 0:bw] > 0, 1, 0)
    return p


for _h in (20, 22, 24):
    for _w in range(24, 41):
        STYLES["b_sib_pay_%d_%d" % (_w, _h)] = plated([0, 0xe, 0x9, 0x4, 0x3, 0x2, 0x2], pay_plate, (_w, _h))
STYLES["b_sib_pay_measure"] = ringfill([2], [])

# ---- y5_sjk_0: the training screen ---------------------------------------------------------------------------------------
# stat labels (palette 16): white letters, a dark blue ring, a white outer ring
STYLES["b_sjk_stat"] = ringfill([0xf], [5, 5, 0xf, 0xe])
# banners: a gradient from near white to a saturated colour, a thick dark ring, a white outer ring
STYLES["b_sjk_pink"] = ringfill([0xe, 0xd, 0xc, 0xb, 0xa, 0x9], [3, 3, 0xf, 0xf])      # palette 20: Shift Over
STYLES["b_sjk_green"] = ringfill([0xe, 0xd, 0xc, 0xb, 0xa, 0x9], [3, 3, 0xf, 0xf])     # palette 21: On the Job
STYLES["b_sjk_blue"] = ringfill([0xe, 0xd, 0xc, 0xb, 0xa, 0x9], [1, 1, 0xf, 0xf])      # palette 22: Job Complete

# ---- y5_siba_2: company ranks (scenario 2) -------------------------------------------------------------------------------
# the small "Rank" heading above each plate: dark letters, a white ring, a grey soft shadow (palettes 22 / 23 / 24)
STYLES["b_ran_head1"] = ringfill([2, 2, 3], [0xf, 0xf], [6])
STYLES["b_ran_head2"] = ringfill([3, 2, 2], [0xf, 0xf], [6])
STYLES["b_ran_head3"] = ringfill([3, 2, 2], [0xf, 0xf], [5])
# the rank on the plate: Grade 3 thin dark grey on pale blue (palette 19), Grade 2 bold blue (20), Grade 1 bold brown (21)
STYLES["b_ran_3"] = ringfill([1, 1, 2], [0xf])
STYLES["b_ran_2"] = ringfill([1, 1, 2], [0xb])
STYLES["b_ran_1"] = ringfill([1, 1, 7], [0xf])


# ---- scc_tops.arc: the Linked World screens (bank z4_li_0) -----------------------------------------------------------

def trim(out, base):
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


def close_h(mask, n):
    """Gaps of up to n columns between ink on a row filled (dilate, then erode, sideways)."""
    m = mask.copy()
    for _ in range(n):
        m = m | shift(m, 0, 1) | shift(m, 0, -1)
    for _ in range(n):
        m = m & shift(m, 0, 1) & shift(m, 0, -1)
    return m | mask


def stack(fill, layers, inner=None, edge=3):
    """Letters filled top to foot from `fill`, then `layers` outwards, each ("ring", [index per pixel of width]) all round
    the whole so far, or ("se", [index per step]) a copy of the whole so far cast down and to the right (an extruded
    edge, a shadow). A pixel of the soft edge (ink level below `edge`) takes the colour of the first layer. `inner` = an
    index for the outermost pixel row of the letters themselves (a thin darker edge of the fill)."""
    fill = list(fill)
    layers = [(k, list(v)) for k, v in layers]
    reach = sum(len(v) for _, v in layers)

    def style(ink, base):
        pad = reach + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        out = np.zeros(big.shape, np.uint8)
        cur = letters.copy()
        first = True
        for kind, idxs in layers:
            if kind == "close":                                # gaps of up to 4 columns between letters filled with one colour
                gap = close_h(cur, 4) & ~cur
                out[gap] = idxs[0]
                cur = cur | gap
            elif kind == "ring":
                for v in idxs:
                    new = grow(cur, 1, diagonal=first)
                    first = False
                    out[new & ~cur] = v
                    cur = new
            else:                                              # "se" (or "sec": gaps of up to 3 columns between letters closed first)
                n = len(idxs)
                union = cur.copy()
                src = close_h(cur, 3) if kind == "sec" else cur
                for k in range(n, 0, -1):
                    reg = (shift(src, k, k) | shift(src, k, k - 1) | shift(src, k - 1, k)) & ~cur
                    out[reg] = idxs[k - 1]
                    union |= reg
                cur = union
        ys = np.nonzero(letters.any(1))[0]
        f = (np.arange(big.shape[0]) - ys.min()) / max(ys.max() - ys.min(), 1)
        row = np.array(fill)[np.rint(f.clip(0, 1) * (len(fill) - 1)).astype(int)][:, None]
        row = np.broadcast_to(row, big.shape)
        first_idx = layers[0][1][0]
        body = np.where(big >= edge, row, first_idx)
        if inner is not None:
            p = np.pad(letters, 1, constant_values=False)
            border = letters & ~(p[:-2, 1:-1] & p[2:, 1:-1] & p[1:-1, :-2] & p[1:-1, 2:])
            body = np.where(border & (big >= edge), inner, body)
        out[letters] = body[letters]
        return trim(out, base + pad)
    return style


def win(style, c0, c1, r0=0, r1=4096):
    """Only the columns c0..c1 and rows r0..r1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[r0:r1, c0:c1]
        if out.shape[1] == 0 or out.shape[0] == 0:
            out = np.zeros((max(out.shape[0], 1), max(out.shape[1], 1)), np.uint8)
        return out, b - r0
    return cut


# ---- the title: Linked World (palette 16): yellow letters, brown rim and extruded edge, white band, light blue shadow, blue ring
STYLES["b3_title"] = stack([0xc, 0xc, 0xd, 0xd, 0xe, 0xe], [("ring", [8, 8]), ("se", [8, 8, 8, 7, 7]), ("ring", [1, 1, 1]),
                                                           ("se", [5, 5, 5, 5]), ("close", [5]), ("ring", [4, 2, 2])], inner=0xa)

# ---- the village headings and the three buttons: green (palette 17), mint (18), lavender (19) letters with a dark outline cast
# down and to the right, a white band, a light blue shadow and a thin blue ring
STYLES["b3_head1"] = stack([0xe, 0xe, 0xc, 0xc, 0xb, 0xb, 0x8, 0x8], [("ring", [2]), ("se", [2, 1]), ("ring", [5]), ("se", [9, 9]), ("ring", [3])])
STYLES["b3_head2"] = stack([0xd, 0xd, 0xc, 0xc, 0xa, 0xa], [("ring", [5]), ("se", [3, 2]), ("ring", [1]), ("se", [9, 9]), ("ring", [4])])
STYLES["b3_head3"] = stack([0xd, 0xc, 0xc, 0xb, 0xa, 0xa], [("ring", [4]), ("se", [3, 2]), ("ring", [1]), ("se", [9, 9]), ("ring", [5])])

# ---- the A-button legend (palette 43): white letters, a black ring, a thin dark rim
STYLES["b3_legend"] = stack([0xf, 0xf, 0xf, 0xe, 0xd, 0xc], [("ring", [4, 4]), ("ring", [2]), ("se", [1])])

# ---- the small plates (pages 8 / 9): white letters, a dark ring in the plate's own colour, a thin rim; palette 35 (Pro Yr, dark
# green), 39 (Grad, dark green), 51 / 52 / 53 (the team plates: red, blue, orange)
_WHITE = [0xe, 0xf, 0xf, 0xf, 0xf, 0xd]
STYLES["b3_plate35"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_plate39"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_team51"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_team52"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])
STYLES["b3_team53"] = stack(_WHITE, [("ring", [4]), ("ring", [3]), ("se", [2])])

# ---- words shown by two parts that stand side by side: the left 128 columns, the rest (pp15/art/typeset.py: "<style>~<c0>_<c1>")
for _name in ("b3_title", "b3_head1", "b3_head2"):
    STYLES[_name + "~0_128"] = win(STYLES[_name], 0, 128)
    STYLES[_name + "~128_4096"] = win(STYLES[_name], 128, 4096)
