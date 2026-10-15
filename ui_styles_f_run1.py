"""Label styles of art run 1, agent F (order.arc, vs_st.arc). Loaded by ui_type.py (every ui_styles_*.py is).
Colours read from the Japanese lettering of each palette with _work/ui_pages/run1/F/work/roles2.py / probe.py."""
import numpy as np
import ui_type
from ui_type import grow, shift

STYLES = {}


def cast(mask, shadow):
    """The shadow of `mask`: colour shadow[k-1] at k steps down and to the right (near to far), only outside the mask."""
    out = np.zeros(mask.shape, np.uint8)
    for k in range(len(shadow), 0, -1):
        out[shift(mask, k, k) | shift(mask, k, k - 1) | shift(mask, k - 1, k)] = shadow[k - 1]
    return out


def trimmed(out, base):
    ys, xs = np.nonzero(out)
    return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()


def bandtext(ramp, rings, shadow=()):
    """Coloured letters (ramp[ink], ink 0..6) directly inside solid one-pixel rings (innermost first; the first ring
    keeps square corners, the others are rounded) and a cast shadow (near to far)."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = len(rings) + len(shadow) + 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        letters = big > 0
        masks = [grow(letters, 1)]
        for _ in rings[1:]:
            masks.append(grow(masks[-1], 1, diagonal=False))
        out = cast(masks[-1], shadow)
        for m, v in zip(masks[::-1], rings[::-1]):
            out[m] = v
        out[letters] = ramp[big[letters]]
        return trimmed(out, base + pad)
    return style


def onoval(oval, rim, ring, shadow, ramp, height=13, margin=6, ends=(4, 2, 1)):
    """White letters on a dark oval (a stadium shape `height` rows high, the ends cut in by `ends` pixels on the first
    rows, `margin` pixels longer than the word each side) with a lighter `rim` row round it, a one-pixel `ring` round
    the letters (the colour of the oval: letters that stand out of it keep an edge) and the shadow of what hangs out
    of it. The word headings of the bars in g3_od: the oval replaces the dark middle of the bar, which the heading's
    part used to carry."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pd = margin + 2
        h, w = ink.shape
        big = np.zeros((h + 2 * 4 + 4, w + 2 * pd), int)
        big[4:4 + h, pd:pd + w] = ink
        L = big > 0
        B = grow(L, 1)
        cy = 4 + base // 2
        top = cy - height // 2
        ov = np.zeros(L.shape, bool)
        for y in range(top, top + height):
            d = min(y - top, top + height - 1 - y)
            inset = ends[d] if d < len(ends) else 0
            ov[y, pd - margin + inset:pd + w + margin - inset] = True
        rimm = grow(ov, 1, diagonal=False) & ~ov
        out = cast(B, shadow)
        out[(out > 0) & ov] = 0
        out[rimm] = rim
        out[ov] = oval
        out[B & ~ov] = ring
        out[L] = ramp[big[L]]
        return trimmed(out, base + 4)
    return style


# g3_od buttons (palettes 16-23): letters in the colour of the palette (8 .. e, e the light edge), a white ring, a
# blue ring, a light blue shadow
STYLES["f_btn"] = bandtext([0, 12, 10, 9, 8, 8, 8], [15, 7], [4, 3])
# g3_od bars (palettes 32-36): white letters on the dark oval (1) with a lighter rim (4); a light blue shadow (13, 12)
STYLES["f_bar"] = onoval(1, 4, 1, [13, 12], [0, 9, 9, 8, 8, 8, 8])

# g3_od tabs (palette 9, the 控え / 2軍 tabs of the bench panel): navy letters, white ring, blue shadow
STYLES["f_tab"] = bandtext([0, 5, 3, 2, 1, 1, 1], [8, 9], [14, 13])


# thin lettering (the Japanese is one or two pixels thick): regular weight faces
ui_type.TTF["f_arial"] = ("/System/Library/Fonts/Supplemental/Arial.ttf", 0)
ui_type.TTF["f_arialn"] = ("/System/Library/Fonts/Supplemental/Arial Narrow.ttf", 0)


def thin(ramp):
    """Letters only, ramp[ink] (ink 0..6), no ring and no shadow."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        out = np.zeros(ink.shape, np.uint8)
        out[ink > 0] = ramp[ink[ink > 0]]
        return trimmed(out, base)
    return style


# g3_od, light to dark ramps of one colour in the palette (index 1 lightest .. 15 darkest)
STYLES["f_thin"] = thin([0, 4, 7, 9, 12, 14, 15])
STYLES["f_thin_blue"] = thin([0, 4, 6, 9, 11, 13, 14])         # palette 100 (no index 15): ramp 1 .. 14

# the tags Type A / Type B / Rookie / Normal (palettes 43-46): coloured letters (1 darkest .. 12 light edge), a white ring
STYLES["f_tag"] = bandtext([0, 12, 9, 5, 3, 1, 1], [15, 15], [])
# Ready / Resting (palettes 49, 50: 13 = light .. 15 = dark of the blue / red of the 可 / 不可), white ring (12), blue glow
STYLES["f_rdy"] = bandtext([0, 13, 14, 15, 15, 15, 15], [12, 12], [7, 6])
# days (palette 48): dark green letters, white ring (15), blue shadow
STYLES["f_days"] = bandtext([0, 13, 9, 5, 3, 1, 1], [15, 15], [8])


def titlebar(letter, ring, fill, outline, thick=2, margin=7, rows=8, over=1):
    """White letters in a thick dark ring standing on a cyan pill (outline `outline` `thick` pixels, `rows` rows of `fill`).
    The letters' baseline lies `over` rows below the top of the pill's fill. The title bar of the lineup screen."""
    letter = np.array(letter, np.uint8)

    def style(ink, base):
        pd = margin + 4
        h, w = ink.shape
        H = h + 2 * 4 + rows + thick * 2
        big = np.zeros((H, w + 2 * pd), int)
        big[4:4 + h, pd:pd + w] = ink
        L = big > 0
        ringm = grow(grow(L, 1), 1, diagonal=False)
        fill_top = 4 + base - over                     # first row of the pill's fill
        top = fill_top - thick
        bot = fill_top + rows + thick
        bar = np.zeros(L.shape, bool)
        for y in range(top, bot):
            d = min(y - top, bot - 1 - y)
            inset = (4, 2, 1, 0)[d] if d < 4 else 0
            bar[y, pd - margin + inset:pd + w + margin - inset] = True
        inner = np.zeros(L.shape, bool)
        for y in range(fill_top, fill_top + rows):
            d = min(y - fill_top, fill_top + rows - 1 - y)
            inset = (3, 1, 0)[d] if d < 3 else 0
            inner[y, pd - margin + thick + inset:pd + w + margin - thick - inset] = True
        out = np.zeros(L.shape, np.uint8)
        out[bar] = outline
        out[inner] = fill
        out[ringm] = ring
        out[L] = letter[big[L]]
        return trimmed(out, base + 4)
    return style


# the title bar Starting Lineup (palette 12): white letters, blue ring (1), cyan bar (15)
STYLES["f_title"] = titlebar([0, 11, 12, 12, 12, 12, 12], 1, 15, 1)


# ---- vs_st.arc (stadium select) -----------------------------------------------------------------------------------------
from ui_styles_ore_ini import ringfill

# s5_tk, the short names on the stadium tiles (palette 7): navy letters, a white ring, a pale teal glow
STYLES["f_name"] = ringfill([6], [15, 15, 3, 4])
# s5_tk, ランダムで球場が決まります (palette 9): gold letters shading to orange, a navy ring, a muted violet edge
STYLES["f_help"] = ringfill([15, 15, 14, 14, 13, 13, 12, 12, 11, 11], [4, 4, 6], [7, 3])
# s5_tk, the ground types (palettes 21, 22, 24): green / yellow / orange letters, a blue-violet ring, a lilac glow
STYLES["f_turf"] = ringfill([15, 15, 14, 14, 13, 13, 12], [8, 7, 5], [5])
STYLES["f_grass"] = ringfill([15, 15, 14, 14, 13, 13, 12], [5, 8, 4], [4])
STYLES["f_dirt"] = ringfill([15, 15, 14, 14, 13, 13, 12], [8, 7, 5], [5])
# s5_tkz, the full names (8-bit pages, palette 16 = entries 256-511): letters shading from yellow (231) to orange (162), a dark
# teal ring (1), a light blue ring (193), a white band, a pink ring (135, 98) and a dark cast shadow
GOLD = [231, 229, 227, 223, 222, 219, 217, 212, 210, 208, 205, 202, 198, 194, 192, 190, 187, 181, 179, 175, 173, 171, 165, 164, 162]
STYLES["f_stad"] = ringfill(GOLD, [1, 193, 255, 255, 255, 135, 98], [35, 3, 3])
STYLES["f_stad2"] = ringfill(GOLD, [1, 193, 255, 255, 135, 98], [35, 3])
