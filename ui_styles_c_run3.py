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

# ---- m3_an, the pill tags (palette 71, lettering on a mint plate): thin navy letters, anti-aliased into the plate ---------------------
ui_type.TTF["c3uni"] = ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0)       # has the star the tags use
STYLES["c3_tag"] = plain([0, 2, 5, 8, 11, 14, 15])
# the hints (palette 85, pages 13): thin blue-violet strokes
STYLES["c3_hint"] = plain([0, 9, 7, 6, 5, 4, 3])
# "this player cannot be uploaded" (palette 86): red letters, soft edge into the page behind
STYLES["c3_red"] = plain([0, 7, 9, 11, 13, 14, 15])
# the message of an unset voice (palette 13): white to yellow letters, dark blue outline, two lighter blue rings
STYLES["c3_msg"] = cut(ringfill([10, 11, 12, 12, 13, 13], [1, 1, 3, 5], []))
# the Role cell (palette 66): blue letters, light outline, painted into the plate
STYLES["c3_role"] = cut(ringfill([1], [15], []))
# the three blue buttons (palettes 83, 80, 84: teal, olive, violet from index 10 on): coloured letters, two white rings, blue glow
STYLES["c3_btn"] = cut(ringfill([15], [9, 9, 7, 5], []))
# z3_nph_0 (palette 32): the pitch-name plates, dark blue letters in a two-pixel white outline, light blue shadow
STYLES["c3_nph"] = cut(ringfill([1, 1, 2, 2], [8, 8], [13, 14]))
# z3_it_0 (palette 1): the colour words, black letters with a white outline
STYLES["c3_it"] = cut(ringfill([15], [1], []))
