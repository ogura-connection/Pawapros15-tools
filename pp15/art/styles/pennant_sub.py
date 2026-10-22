"""Styles for the many sub-screens of Pennant mode (the biggest Pennant file): rosters, reports, results and settings.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): pena_sub, rec_room, pena_ini.
"""
import numpy as _np
import numpy as np
from pp15.art import typeset as ui_type
from .common import ringfill, flat, win
from .controller import flat as _flat

STYLES = {}


# ---- pena_sub.arc: s3_opc_0, s3_pir00, s3_pih00 ----------------------------------------------------------------------

# s3_pih00: pitch names on the orange / cream plates (palette 125: white letters, dark brown ring, pale pink shadow)
STYLES["b5_pitch"] = ringfill([15, 15, 15, 15, 15, 15], [2, 1], [7, 8])

# s3_pir00 / s3_opc_0 buttons: same construction in every hue ramp (index 1 darkest .. 15 white): white letters, dark ring, pale shadow
STYLES["b5_btn"] = ringfill([15, 15, 15, 15, 15, 15], [2, 1], [7, 8])
# small plates (cap < 11): one dark ring only, so the counters of the capitals stay open
STYLES["b5_pitch_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [7])
STYLES["b5_btn_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [7])

# s3_opc_0
# values on the coloured plates (palettes 26-28, 38-41, 43: index 1-8 dark ramp, 9 white, 10+ cream): dark letters, white ring, cream shadow
STYLES["b5_val"] = ringfill([2, 1, 1, 1, 1, 2], [9], [10, 11])
STYLES["b5_val_s"] = ringfill([2, 1, 1, 1, 1, 2], [9], [10])
# headings (palette 24 blue / 23 green: white letters, dark ring, pale halo)
STYLES["b5_head"] = ringfill([15, 15, 15, 15, 15, 14], [4, 4, 12])
STYLES["b5_head_s"] = ringfill([15, 15, 15, 15, 15, 14], [4, 12])
# "Other Teams" (palette 9, black letters on the white plate, no ring)
STYLES["b5_black"] = flat([0, 2, 2, 2, 2, 2, 2], cut=3)


# ---- pena_sub.arc: s3_phg00, b5_pe00, s3_pen00, s3_pnd00 -------------------------------------------------------------

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


# ---- pena_sub.arc: r5_ren, r5_renz, s3_pic00 .. g3_ps_0 --------------------------------------------------------------

STYLES["d5_cancel"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 6], [4, 4])
STYLES["d5_cancel_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [4])
STYLES["d5_abil"] = ringfill([12, 15, 15, 15, 15, 15], [9, 9, 5], [4, 2])
STYLES["d5_abil_s"] = ringfill([12, 15, 15, 15, 15, 15], [9], [4])
STYLES["d5_chem"] = ringfill([15, 15, 15, 15, 15, 15], [12, 8, 8], [8, 3, 3])
STYLES["d5_chem_s"] = ringfill([15, 15, 15, 15, 15, 15], [12], [8])
STYLES["d5_lvl"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["d5_lvl_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_sw1"] = ringfill([13, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["d5_sw1_s"] = ringfill([13, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_sw2"] = ringfill([13, 15, 15, 15, 15, 15], [7, 7], [2])
STYLES["d5_sw2_s"] = ringfill([13, 15, 15, 15, 15, 15], [7], [2])
STYLES["d5_chp"] = ringfill([15, 15, 15, 14, 12, 12], [11, 6, 4], [1])
STYLES["d5_chp_s"] = ringfill([15, 15, 15, 14, 12, 12], [11], [1])
STYLES["d5_rep27"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7, 2], [])
STYLES["d5_rep27_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_rep28"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7, 2], [])
STYLES["d5_rep28_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_rep2c"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["d5_rep2c_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_rep2d"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["d5_rep2d_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_tag"] = ringfill([15, 15, 15, 15, 15, 15], [9, 7], [])
STYLES["d5_tag_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [])
STYLES["d5_tag2"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["d5_tag2_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_love"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_love_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["d5_msg"] = ringfill([11, 11, 12, 13, 13, 14], [9, 4, 4], [4])
STYLES["d5_msg_s"] = ringfill([11, 11, 12, 13, 13, 14], [9], [4])
STYLES["d5_conf"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15], [8])
STYLES["d5_conf_s"] = ringfill([1, 1, 1, 1, 1, 1], [15], [8])
STYLES["d5_f0"] = ringfill([12, 12, 12, 13, 13, 13], [9, 6, 6, 10, 10, 10], [4, 3])
STYLES["d5_f0_s"] = ringfill([12, 12, 12, 13, 13, 13], [9], [4])
STYLES["d5_btnb"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 9], [15])
STYLES["d5_btnb_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [15])
STYLES["d5_cc"] = ringfill([14, 14, 14, 13, 12, 12], [9, 6, 15, 15], [15, 15, 1, 1])
STYLES["d5_cc_s"] = ringfill([14, 14, 14, 13, 12, 12], [9], [15])
STYLES["d5_hp"] = ringfill([3, 1, 1, 1, 1, 1], [8, 8], [15, 15])
STYLES["d5_hp_s"] = ringfill([3, 1, 1, 1, 1, 1], [8], [15])
STYLES["d5_hb"] = ringfill([3, 1, 1, 1, 1, 1], [8, 8], [15, 15])
STYLES["d5_hb_s"] = ringfill([3, 1, 1, 1, 1, 1], [8], [15])
STYLES["d5_hg"] = ringfill([3, 1, 1, 1, 1, 1], [5, 8], [15, 15])
STYLES["d5_hg_s"] = ringfill([3, 1, 1, 1, 1, 1], [5], [15])
STYLES["d5_rowp"] = ringfill([8, 8, 8, 8, 8, 8], [10], [])
STYLES["d5_rowp_s"] = ringfill([8, 8, 8, 8, 8, 8], [10], [])
STYLES["d5_rowb"] = ringfill([8, 8, 8, 8, 8, 8], [10], [])
STYLES["d5_rowb_s"] = ringfill([8, 8, 8, 8, 8, 8], [10], [])
STYLES["d5_rowg"] = ringfill([8, 8, 8, 8, 8, 8], [10], [])
STYLES["d5_rowg_s"] = ringfill([8, 8, 8, 8, 8, 8], [10], [])
STYLES["d5_tab76"] = ringfill([1, 1, 1, 1, 1, 1], [5, 8, 10], [15])
STYLES["d5_tab76_s"] = ringfill([1, 1, 1, 1, 1, 1], [5], [15])
STYLES["d5_tab77"] = ringfill([1, 1, 1, 1, 1, 1], [5, 8, 10], [15])
STYLES["d5_tab77_s"] = ringfill([1, 1, 1, 1, 1, 1], [5], [15])
STYLES["d5_tab78"] = ringfill([1, 1, 1, 1, 1, 1], [5, 8, 10], [15])
STYLES["d5_tab78_s"] = ringfill([1, 1, 1, 1, 1, 1], [5], [15])
STYLES["d5_tab79"] = ringfill([1, 1, 1, 1, 1, 1], [5, 8, 10], [15])
STYLES["d5_tab79_s"] = ringfill([1, 1, 1, 1, 1, 1], [5], [15])
STYLES["d5_type"] = ringfill([2, 1, 1, 1, 1, 1], [15], [])
STYLES["d5_type_s"] = ringfill([2, 1, 1, 1, 1, 1], [15], [])
STYLES["d5_pij"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [])
STYLES["d5_pij_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["d5_pijm"] = ringfill([13, 15, 15, 15, 15, 15], [1, 1], [])
STYLES["d5_pijm_s"] = ringfill([13, 15, 15, 15, 15, 15], [1], [])
STYLES["d5_sai"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["d5_sai_s"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["d5_saib"] = ringfill([1, 1, 1, 1, 1, 1], [13], [])
STYLES["d5_saib_s"] = ringfill([1, 1, 1, 1, 1, 1], [13], [])
STYLES["d5_sair"] = ringfill([1, 1, 1, 1, 1, 1], [14], [])
STYLES["d5_sair_s"] = ringfill([1, 1, 1, 1, 1, 1], [14], [])
STYLES["d5_pt"] = ringfill([13, 15, 14, 15, 15, 15], [8, 8, 8, 8], [])
STYLES["d5_pt_s"] = ringfill([13, 15, 14, 15, 15, 15], [8], [])
STYLES["d5_ps"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["d5_ps_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["d5_pi"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["d5_pi_s"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["d5_pi2"] = ringfill([1, 1, 1, 1, 1, 1], [13], [])
STYLES["d5_pi2_s"] = ringfill([1, 1, 1, 1, 1, 1], [13], [])
STYLES["d5_chk"] = ringfill([15, 14, 13, 11, 11, 10], [1, 1, 2], [4, 4])
STYLES["d5_chk_s"] = ringfill([15, 14, 13, 11, 11, 10], [1], [4])
STYLES["d5_room"] = ringfill([8, 8, 8, 10, 8, 8], [15, 15], [4, 4])
STYLES["d5_room_s"] = ringfill([8, 8, 8, 10, 8, 8], [15], [4])
STYLES["d5_gr"] = ringfill([14, 15, 13, 14, 13, 13], [8, 7, 7, 5, 2], [2, 3, 2])
STYLES["d5_gr_s"] = ringfill([14, 15, 13, 14, 13, 13], [8], [2])
STYLES["d5_t_renz"] = ui_type.logo(**{'fill': [111, 140, 143, 152, 157, 158], 'outline': 103, 'white': 227, 'rim': 254, 'shadow': [254, 254], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d5_t_renz_s"] = STYLES["d5_t_renz"]
STYLES["d5_t_saz00"] = ui_type.logo(**{'fill': [239, 224, 200, 180, 178, 72], 'outline': 32, 'white': 255, 'rim': 98, 'shadow': [98], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d5_t_saz00_s"] = STYLES["d5_t_saz00"]
STYLES["d5_t_saz02"] = ui_type.logo(**{'fill': [183, 190, 194, 196, 214, 214], 'outline': 2, 'white': 1, 'rim': 94, 'shadow': [35, 35, 35, 35, 78], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d5_t_saz02_s"] = STYLES["d5_t_saz02"]
STYLES["d5_t_saz03"] = ui_type.logo(**{'fill': [188, 195, 158, 154, 163, 161], 'outline': 167, 'white': 1, 'rim': 71, 'shadow': [33, 33, 33, 33, 68], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d5_t_saz03_s"] = STYLES["d5_t_saz03"]
STYLES["d5_t_saz04"] = ui_type.logo(**{'fill': [81, 81, 81, 92, 82, 91], 'outline': 44, 'white': 1, 'rim': 94, 'shadow': [90, 35, 35, 35, 71], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d5_t_saz04_s"] = STYLES["d5_t_saz04"]
STYLES["d5_t_saz05"] = ui_type.logo(**{'fill': [227, 99, 101, 126, 124, 124], 'outline': 105, 'white': 1, 'rim': 12, 'shadow': [53, 33, 33, 33, 68], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d5_t_saz05_s"] = STYLES["d5_t_saz05"]
STYLES["d5_t_saz06"] = ui_type.logo(**{'fill': [249, 235, 235, 254, 253, 253], 'outline': 239, 'white': 1, 'rim': 12, 'shadow': [53, 35, 35, 35, 78], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d5_t_saz06_s"] = STYLES["d5_t_saz06"]

# vertical lettering: the same styles on art turned a quarter turn anticlockwise (reads bottom to top)
def _win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = _np.zeros((art.shape[0], 1), _np.uint8)
        return out, b
    return cut
def _turned(style):
    def f(ink, base):
        t = _np.rot90(ink)
        out, b = style(t, t.shape[0])
        return out, out.shape[0]
    return f
STYLES["d5_msg~0_120"] = _win(STYLES["d5_msg"], 0, 120)
STYLES["d5_msg~0_128"] = _win(STYLES["d5_msg"], 0, 128)
STYLES["d5_msg~120_248"] = _win(STYLES["d5_msg"], 120, 248)
STYLES["d5_msg~128_256"] = _win(STYLES["d5_msg"], 128, 256)
STYLES["d5_msg~248_4096"] = _win(STYLES["d5_msg"], 248, 4096)
STYLES["d5_msg~256_4096"] = _win(STYLES["d5_msg"], 256, 4096)
STYLES["d5_tab76_v"] = _turned(STYLES["d5_tab76"])
STYLES["d5_tab76_vs"] = _turned(STYLES["d5_tab76_s"])
STYLES["d5_tab77_v"] = _turned(STYLES["d5_tab77"])
STYLES["d5_tab77_vs"] = _turned(STYLES["d5_tab77_s"])
STYLES["d5_tab78_v"] = _turned(STYLES["d5_tab78"])
STYLES["d5_tab78_vs"] = _turned(STYLES["d5_tab78_s"])
STYLES["d5_tab79_v"] = _turned(STYLES["d5_tab79"])
STYLES["d5_tab79_vs"] = _turned(STYLES["d5_tab79_s"])


# ---- pena_sub.arc: Pennant sub-screens -------------------------------------------------------------------------------

STYLES["e5_s3_itn00_08_5"] = ringfill([15], [7, 6])
STYLES["e5_s3_itn00_09_6"] = ringfill([15], [7, 6])
STYLES["e5_s3_itn00_0b_1"] = ringfill([15], [1, 4])
STYLES["e5_s3_itn00_0c_2"] = ringfill([15], [1, 3])
STYLES["e5_s3_itn00_14"] = ringfill([15, 15, 14, 13, 13, 12], [8, 6, 6, 1], [3, 3])
STYLES["e5_s3_itn00_15_18"] = ringfill([6], [15], [5, 4])
STYLES["e5_s3_itn00_16_19"] = ringfill([6], [15], [5, 4])
STYLES["e5_s3_itn00_29_26"] = ringfill([6], [15], [5, 4])
STYLES["e5_s3_itn00_18"] = ringfill([5], [15], [4, 10])
STYLES["e5_s3_itn00_19_21"] = ringfill([2], [15], [5, 4])
STYLES["e5_s3_itz00_00_0"] = ringfill([31, 31, 29, 29, 28, 28], [25, 19, 19, 22])
STYLES["e5_s3_itz00_01_0"] = ringfill([31, 31, 29, 29, 28, 28], [25, 19, 19, 22])
STYLES["e5_s3_ops_0_09_26"] = ringfill([1], [10, 10], [15])
STYLES["e5_s3_ops_0_0a_27"] = ringfill([1], [10, 10], [15])
STYLES["e5_s3_ops_0_0b_28"] = ringfill([1], [10, 10], [15])
STYLES["e5_s3_ops_0_1c_24"] = ringfill([15], [4, 4, 11])
STYLES["e5_s3_ops_0_1d_24"] = ringfill([15], [4, 4, 11])
STYLES["e5_s3_ops_0_1e_24"] = ringfill([15], [4, 4, 11])
STYLES["e5_s3_ops_0_1f_24"] = ringfill([15], [4, 4, 11])
STYLES["e5_s3_ops_0_20_25"] = ringfill([15, 11, 11, 9, 9, 9], [4, 4], [3, 2, 1])
STYLES["e5_s3_ops_0_21_25"] = ringfill([15, 11, 11, 9, 9, 9], [4, 4], [3, 2, 1])
STYLES["e5_s3_ops_0_23_24"] = ringfill([15], [4, 4, 11])
STYLES["e5_s3_ops_0_24_25"] = ringfill([15, 11, 11, 9, 9, 9], [4, 4], [3, 2, 1])
STYLES["e5_s3_ops_0_25_25"] = ringfill([15, 11, 11, 9, 9, 9], [4, 4], [3, 2, 1])
STYLES["e5_s3_ops_0_26_25"] = ringfill([15, 11, 11, 9, 9, 9], [4, 4], [3, 2, 1])
STYLES["e5_s3_ops_0_27_25"] = ringfill([15, 11, 11, 9, 9, 9], [4, 4], [3, 2, 1])
STYLES["e5_s3_psr00_00_7"] = ringfill([10, 11, 12, 13, 14, 15], [4, 2, 2, 9], [1, 7])
STYLES["e5_s3_psr00_00_8"] = ringfill([1], [0])
STYLES["e5_s3_psr00_02"] = ringfill([1], [8], [15, 14])
STYLES["e5_s3_psr00_03_1"] = ringfill([8, 8, 13, 13, 14, 14], [15, 11])
STYLES["e5_s3_psr00_04_2"] = ringfill([7, 8, 8, 13, 14, 14], [15, 11], [10])
STYLES["e5_s3_psr00_05"] = ringfill([8], [1], [14, 10])
STYLES["e5_s3_ho00_05"] = ringfill([15], [10], [1, 3])
STYLES["e5_s3_ho00_10"] = ringfill([15], [10], [1, 3])
STYLES["e5_s3_ho00_11"] = ringfill([15], [10], [1, 3])
STYLES["e5_s3_ho00_12"] = ringfill([15], [10], [1, 3])
STYLES["e5_s3_ho00_13"] = ringfill([15], [10], [1, 3])
STYLES["e5_s3_ho00_14"] = ringfill([15], [10], [1, 3])
STYLES["e5_s3_ho00_15"] = ringfill([15], [10], [4, 3])
STYLES["e5_s3_ho00_16"] = ringfill([15], [10], [4, 3])
STYLES["e5_s3_ho00_17_7"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_ho00_18"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_ho00_19"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_ho00_1a"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_ho00_1b"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_ho00_1c"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_ho00_1d"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_ho00_1e"] = ringfill([14], [7, 9], [1, 3])
STYLES["e5_s3_hoz00_00"] = ringfill([234, 222, 204, 183, 167, 167], [45, 59, 255], [99, 99])
STYLES["e5_g3_pk_0_06_72"] = ringfill([6, 6, 5, 3, 2, 2], [8], [1, 15])
STYLES["e5_g3_pk_0_07_73"] = ringfill([15, 5, 4, 3, 3, 2], [8], [1])
STYLES["e5_g3_pk_0_08_74"] = ringfill([6, 5, 4, 3, 2, 2], [8], [1])
STYLES["e5_g3_pk_0_09_86"] = ringfill([6, 5, 4, 3, 2, 2], [8], [1])
STYLES["e5_g3_pk_0_0a_87"] = ringfill([6, 5, 4, 3, 2, 2], [8], [1])
STYLES["e5_g3_pk_0_0b_88"] = ringfill([6, 5, 4, 3, 2, 2], [8], [1])
STYLES["e5_g3_pk_0_2b"] = ringfill([5, 5, 3, 3, 1, 1], [8], [15])
STYLES["e5_g3_pk_0_2c"] = ringfill([5, 5, 3, 3, 1, 1], [8], [15])
STYLES["e5_g3_pk_0_37"] = ringfill([4, 5, 5, 6, 6, 6], [15, 3])
STYLES["e5_s3_pco00_05_0"] = ringfill([14], [8, 11], [1])
STYLES["e5_s3_pco00_06_1"] = ringfill([14], [8, 11], [1])
STYLES["e5_s3_pco00_07_2"] = ringfill([14], [8, 11], [1])
STYLES["e5_s3_pco00_08_3"] = ringfill([14], [8, 11], [1])
STYLES["e5_s3_pco00_09_4"] = ringfill([14], [8, 11], [1])
STYLES["e5_s3_pco00_0a_5"] = ringfill([14], [8, 11], [1])
STYLES["e5_s3_pco00_0b_6"] = ringfill([14], [8, 11], [1])
STYLES["e5_s3_pco00_0f"] = ringfill([1], [0])
STYLES["e5_s3_pcz00_00"] = ringfill([11, 16, 28, 36, 40, 40], [237, 225, 1], [198, 198])
STYLES["e5_s3_psz00_01"] = ringfill([155, 189, 193, 190, 191, 20], [159, 1, 41], [50])
STYLES["e5_s3_psz00_02"] = ringfill([177, 178, 243, 252, 250, 57], [80, 1, 70], [50])
STYLES["e5_s3_psz00_03"] = ringfill([129, 134, 148, 153, 156, 20], [93, 1, 34], [50])
STYLES["e5_s3_psz00_04"] = ringfill([128, 127, 138, 147, 152, 21], [94, 1, 41], [45])
STYLES["e5_s3_psz00_05"] = ringfill([27, 39, 36, 51, 51, 15], [2, 1, 41], [50])
STYLES["e5_s3_psz00_06"] = ringfill([24, 232, 226, 244, 254, 20], [81, 1, 79], [50])
STYLES["e5_s3_psz00_07"] = ringfill([229, 227, 245, 253, 248, 20], [200, 1, 41], [50])
STYLES["e5_s3_psz00_08"] = ringfill([242, 234, 225, 211, 200, 190], [118, 107, 255, 255], [127, 127, 127])
STYLES["e5_b5_pen00_00"] = ringfill([180, 93, 180, 241, 239, 177], [52, 250, 45])
STYLES["e5_b5_pen00_01"] = ringfill([177, 182, 180, 184, 239, 176], [52, 251, 43])
STYLES["e5_b5_pen00_02"] = ringfill([59, 61, 185, 186, 209, 60], [98, 71, 247])
STYLES["e5_b5_pen00_03"] = ringfill([59, 61, 184, 184, 210, 60], [97, 71, 245])
STYLES["e5_b5_pen00_04"] = ringfill([173, 119, 179, 208, 246, 109], [41, 127, 60])
STYLES["e5_b5_pen00_05"] = ringfill([171, 115, 179, 248, 245, 107], [41, 184, 34])
STYLES["e5_b5_pen00_06"] = ringfill([107, 64, 64, 167, 164, 138], [73, 195, 110])
STYLES["e5_b5_pen00_07"] = ringfill([131, 132, 176, 176, 208, 131], [242, 186, 192])
STYLES["e5_b5_pen00_08"] = ringfill([131, 129, 176, 177, 205, 131], [243, 186, 191])
STYLES["e5_s3_psa00_08_1"] = ringfill([15], [1, 1], [2])
STYLES["e5_s3_psa00_09_2"] = ringfill([15], [1, 1], [2])
STYLES["e5_s3_psa00_0b"] = ringfill([15], [1, 1])
STYLES["e5_s3_psa00_0f"] = ringfill([15], [1, 1])
STYLES["e5_s3_pnn00_02_122"] = ringfill([15], [8], [5, 3, 2])
STYLES["e5_s3_ton00_06"] = ringfill([15, 14, 13, 13, 12, 11], [2, 4, 4, 8], [1, 1])
STYLES["e5_s3_ton00_07_4"] = ringfill([15], [1], [4, 2])
STYLES["e5_i3_pssx_0_00_0"] = ringfill([131, 134, 141, 148, 155, 164], [51, 94, 228], [94, 84])
STYLES["e5_s4r_yu00_01_2"] = ringfill([7, 8, 10, 11, 12, 13], [14], [14])
STYLES["e5_s4r_yu00_02_3"] = ringfill([7, 8, 10, 11, 12, 13], [14], [14])
STYLES["e5_s3_phd00_00"] = ringfill([10, 9, 8, 7, 6, 6], [2, 3, 3, 12], [1, 14])
STYLES["e5_s3_phd00_01"] = ringfill([10, 9, 8, 7, 6, 6], [2, 3, 3, 12], [1, 14])
STYLES["e5_s3_phd00_02"] = ringfill([10, 9, 8, 7, 6, 6], [2, 3, 3, 12], [1, 14])
STYLES["e5_s3_phd00_03"] = ringfill([10, 9, 8, 7, 6, 6], [2, 3, 3, 12], [1, 14])
STYLES["e5_s3_phd00_0b"] = ringfill([10, 9, 8, 7, 6, 6], [2, 3, 3, 12], [1, 14])
STYLES["e5_s3_phd00_0c"] = ringfill([10, 9, 8, 7, 6, 6], [2, 3, 3, 12], [1, 14])
STYLES["e5_s3_phd00_0d"] = ringfill([10, 9, 8, 7, 6, 6], [2, 3, 3, 12], [1, 14])

PILL = np.array([[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], [0, 0, 0, 0, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4], [0, 0, 0, 1, 4, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 0, 1, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 1, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 1, 4, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [1, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [1, 4, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [1, 4, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [1, 4, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [1, 4, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [1, 4, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [1, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 1, 4, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 1, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 0, 1, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 0, 0, 1, 4, 4, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14], [0, 0, 0, 0, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4], [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]], np.uint8)
STYLES['e5_pager'] = ringfill([2], [12])
_sai = ringfill([15], [13, 2, 1])


def yrs(ink, base):
    art, b = _sai(ink, base)
    h, w = art.shape
    out = np.zeros((32, 22 + w + 1), np.uint8)
    out[:, :16] = PILL
    top = 24 - b
    sub = out[max(top, 0):top + h, 22:22 + w]
    src = art[max(-top, 0):max(-top, 0) + sub.shape[0]]
    sub[src > 0] = src[src > 0]
    return out, 24


STYLES['e5_yrs'] = yrs

_EDGES = list(range(0, 336, 16))
for _k in [k for k in list(STYLES) if k.startswith("e5_s3_phd00_")]:
    for _a in _EDGES:
        for _b in _EDGES + [4096]:
            if _b > _a:
                STYLES["%s~%d_%d" % (_k, _a, _b)] = win(STYLES[_k], _a, _b)


# ---- Pennant fixes (fxB_...) -----------------------------------------------------------------------------------------

# b5_pen00 00-08 (Pennant record captions): the Japanese has dark outer outline, white inline, a mid ring and a shadow.
# fill = the fill of the e5_b5_pen00_NN style; rings innermost first, read from the bottom edge of the Japanese lettering.
_PEN = {
    "00": ([180, 93, 180, 241, 239, 177], [25, 246, 127, 211, 211], [34]),
    "01": ([177, 182, 180, 184, 239, 176], [25, 246, 127, 211, 211], [34]),
    "02": ([59, 61, 185, 186, 209, 60], [108, 70, 34, 20], [243]),
    "03": ([59, 61, 184, 184, 210, 60], [108, 70, 34, 20], [243]),
    "04": ([173, 119, 179, 208, 246, 109], [21, 177, 145, 140, 140], [28]),
    "05": ([171, 115, 179, 248, 245, 107], [21, 177, 145, 140, 140], [28]),
    "06": ([107, 64, 64, 167, 164, 138], [20, 197, 84, 222, 222], [24]),
    "07": ([131, 132, 176, 176, 208, 131], [18, 255, 49, 51, 51], [94]),
    "08": ([131, 129, 176, 177, 205, 131], [18, 255, 49, 51, 51], [94]),
}
for _k, (_f, _r, _s) in _PEN.items():
    STYLES["fxB_pen00_" + _k] = ringfill(_f, _r, _s)

# pena_ini s3_ptz00 04 / 06 / 0b (buttons): fill, inner dark ring, white rings, outer ring, read from the Japanese lettering.
STYLES["fxB_ptz_04"] = ringfill([234, 230, 212, 182, 174, 180], [6, 255, 24], [153])
STYLES["fxB_ptz_06"] = ringfill([249, 249, 242, 233, 222, 201], [2, 255, 180], [185])
STYLES["fxB_ptz_0b"] = ringfill([232, 232, 232, 200, 200, 232], [30, 255], [56])

# rec_room g2_km#2 (bats/throws R/R..., prefectures): black letters with the soft brown edge the Japanese has, on the orange plate
STYLES["fxB_km_text"] = _flat([0, 13, 13, 1, 1, 1, 1], cut=2)

# rec_room g3_sm#3 Best / Worst / Info (select-menu captions): thin letters, one white ring, light-blue outer ring, as the Japanese
STYLES["fxB_sm_best"] = ui_type.ringed([0, 6, 4, 3, 2, 1, 1], [8, 14])
STYLES["fxB_sm_worst"] = ui_type.ringed([0, 6, 4, 3, 2, 1, 1], [8, 14])
STYLES["fxB_sm_info"] = ui_type.ringed([0, 6, 4, 3, 2, 1, 1], [8, 14])
