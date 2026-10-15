"""Label styles of art run 3, agent C (are_abi.arc: the player-data screen of Arrange and Success's Linked World).
Loaded by ui_type.py. Numbers are palette indices read from the Japanese lettering of each palette (roles.py)."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}


def cut(style, thr=3):
    """`style` with the soft edge of the letters taken away: ink below level `thr` (of 6) is dropped, so the strokes keep
    the width the typeface gave them (ringfill counts any ink as a full pixel and would thicken them by up to one pixel)."""
    def thin(ink, base):
        return style(np.where(ink >= thr, ink, 0), base)
    return thin

# two regular-weight faces for the thin lettering (tags, hints): Arial Rounded Bold is too heavy there
ui_type.TTF["c3reg"] = ("/System/Library/Fonts/Supplemental/Arial.ttf", 0)
ui_type.TTF["c3regn"] = ("/System/Library/Fonts/Supplemental/Arial Narrow.ttf", 0)


def plain(ramp):
    """Letters drawn straight from `ramp` (palette index per ink level 0..6), no outline: thin lettering that is
    anti-aliased into the plate behind it."""
    ramp = np.array(ramp, np.uint8)

    def style(ink, base):
        pad = 1
        h, w = ink.shape
        big = np.zeros((h + 2 * pad, w + 2 * pad), int)
        big[pad:pad + h, pad:pad + w] = ink
        return ramp[big], base + pad
    return style


# ---- m3_an, palette 5 (the lilac / white player-data screen) -------------------------------------------------------------
# tabs (page 3): white letters, dark purple outline (e), medium purple shadow (d)
STYLES["c3_tab"] = cut(ringfill([1, 1, 1, 3, 4, 5], [14], [13]))
# the stat words, teams, forms, B/T: dark purple letters (e), white outline, lilac shadow (b)
STYLES["c3_name"] = cut(ringfill([14], [1], [11]))
# birthday / voice / pro-years words: medium purple letters (d), white outline, two rows of lilac shadow (a)
STYLES["c3_mid"] = cut(ringfill([13], [1], [10, 10]))
# the column headings on the lilac plates (page 12): white letters, two rows of dark purple outline, medium purple shadow
STYLES["c3_head"] = cut(ringfill([1, 1, 1, 4, 5], [14, 14], [13, 13]))
