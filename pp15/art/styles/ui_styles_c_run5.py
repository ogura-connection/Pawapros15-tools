"""Label styles of art run 5, agent C (pena_sub.arc: s3_phg00, b5_pe00, s3_pen00, s3_pnd00). Loaded by pp15/art/typeset.py.
Colours are read from the Japanese lettering of each palette (indices of the 16-colour palette the sprite part uses); every style is crisp
(solid rings, fill ramps only). Windows "<style>~c0_c1" (columns c0..c1 of the word, for a word shared out over parts that stand side
by side) exist for the styles that need them, cut at multiples of 8."""
from .ui_styles_ore_ini import ringfill
from .ui_styles_c_run1 import win

STYLES = {}


def add(name, style, windows=False, middle=False):
    STYLES[name] = style
    if windows:
        for c in range(8, 296, 8):
            STYLES["%s~0_%d" % (name, c)] = win(style, 0, c)
            STYLES["%s~%d_4096" % (name, c)] = win(style, c, 4096)
    if middle:                                         # a word cut over three or more parts: also the windows in between (multiples of 16)
        for c in range(16, 368, 16):
            STYLES["%s~0_%d" % (name, c)] = win(style, 0, c)
            STYLES["%s~%d_4096" % (name, c)] = win(style, c, 4096)
            for c2 in range(c + 16, 368, 16):
                STYLES["%s~%d_%d" % (name, c, c2)] = win(style, c, c2)


# ---- s3_phg00 stadium names (palette 48): white letters, three grey-blue rings, a shadow; the short plates (56x24) get two rings ----------
add("c5_stad", ringfill([15, 15, 15, 15, 15, 14], [8, 6, 3]))
add("c5_stad_s", ringfill([15, 15, 15, 15, 14, 14], [6, 3]))
add("c5_stad_xs", ringfill([15, 15, 15, 15, 15, 15], [6, 2]))

# ---- b5_pe00 (fan report) -------------------------------------------------------------------------------------------------------------------
add("c5_fan_t7", ringfill([1, 1, 1, 1, 1, 1], [11, 10], [14, 12]))              # pal 7: Fan Change, white letters, purple rings, cyan shadow
add("c5_fan_t27", ringfill([1, 1, 1, 1, 1, 1], [10, 8], [12, 14]))              # pal 27: Fan Count Report
add("c5_fan_h", ringfill([9, 9, 9, 10, 10, 10], [7, 2], [14, 15]))              # pal 20: brown heading with a cream ring and orange shadow
add("c5_pink", ringfill([11, 10, 12, 13, 14, 14], [6, 2], [1]))            # pal 24: pink letters, blue rings, white ring
add("c5_gold", ringfill([15, 15, 15, 14, 13, 12], [9, 2], [1]))            # pal 25: gold letters, blue rings, white ring
add("c5_grey", ringfill([15, 15, 14, 14, 13, 13], [6, 2], [1]))            # pal 26: pale blue letters, navy ring, white ring
add("c5_fans", ringfill([15, 14, 13, 12, 11, 10], [6]))                        # pal 10 / 11 (4d / 4e, same art): pink / cyan 'people' counter
add("c5_fans_big", ringfill([12, 11, 10, 9, 8, 7], [1, 2], [4, 3]))              # pal 19 (91): orange counter

# ---- s3_pen00 -----------------------------------------------------------------------------------------------------------------------------------
add("c5_pen_gold", ringfill([15, 15, 14, 14, 13, 13, 12], [7, 5, 2], [1]))       # pal 0: titles, yellow to orange, blue rings, white ring
add("c5_pen_green", ringfill([11, 11, 12, 13, 14, 15], [2, 5, 8], [1]))          # pal 7: question and buttons, lime to green, blue rings, white ring
add("c5_pen_lime", ringfill([11, 11, 12, 13, 14, 14], [7, 4, 2]))                # pal 12: small plate heading
add("c5_pen_mint", ringfill([10, 11, 12, 13, 13, 13], [6, 4, 2]))                # pal 11
add("c5_pen_blue", ringfill([2, 2, 2, 2, 2, 2], [12]))                           # pal 13: tiny blue suffix
add("c5_pen_help", ringfill([14, 15, 15, 15, 14, 14], [6, 3]), middle=True)                   # pal 16: navy help text, white ring
add("c5_pen_warn", ringfill([14, 15, 15, 14, 14, 13], [6, 3]), middle=True)                   # pal 17: red warning text, white ring

# ---- s3_pnd00 ---------------------------------------------------------------------------------------------------------------------------------
add("c5_pnd", ringfill([14, 14, 13, 12, 11, 10], [2, 3, 14], [6, 5]), windows=True)         # pal 125 / 126: pale silver letters, lilac rings
add("c5_pnd_s", ringfill([14, 13, 12, 11, 10, 10], [3, 14], [6]), windows=True, middle=True)
add("c5_pnd_xs", ringfill([14, 14, 13, 12, 11, 10], [3], [6]), windows=True, middle=True)
add("c5_pnd2", ringfill([10, 9, 8, 6, 6, 6], [3, 12, 13], [1]), windows=True)               # pal 57: Konami Cup lines
add("c5_pnd2_s", ringfill([10, 9, 8, 6, 6, 6], [3, 13], [1]), windows=True)
