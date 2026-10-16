"""Label styles of art run 7, agent B (arr_org.arc: original-team creation). Loaded by ui_type.py."""
import numpy as np
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat
from ui_styles_c_run1 import win

STYLES = {}
# banners (yellow letters, blue ring, white ring, light shadow)
STYLES["b7_ein_t"] = ringfill([15, 15, 15, 14, 13, 13], [3, 3, 3, 10, 10], [10, 4, 4])     # s3_ein pal 1
STYLES["b7_ane_t"] = ringfill([15, 15, 15, 14, 14, 14], [1, 1, 10, 10, 10], [10, 5])        # s3_ane pal 16
STYLES["b7_tmr_t"] = ringfill([15, 15, 15, 14, 13, 13], [3, 3, 3, 9, 9], [9, 7, 5])         # s3_tmr pal 10
STYLES["b7_yun_t"] = ringfill([15, 15, 14, 14, 13, 13], [3, 3, 9, 9], [5])                  # s3_yun pal 12
STYLES["b7_ebox_t"] = ringfill([10, 10, 10, 9, 8, 8], [2, 1, 15, 15], [11])                  # s3_ebox pal 14
# headings
STYLES["b7_olive"] = ringfill([13, 15, 15, 15, 15, 15], [9, 9, 4, 1], [3])                  # s3_ein pal 74
STYLES["b7_teal"] = ringfill([13, 15, 15, 15, 15, 15], [9, 9, 4, 1], [3])                   # s3_ein pal 76
STYLES["b7_teal_yun"] = ringfill([13, 15, 15, 15, 15, 15], [9, 6], [3])              # s3_yun pal 21
STYLES["b7_lav"] = ringfill([12, 15, 15, 15, 15, 15], [9, 9, 6], [3, 3])                    # s3_ein pal 73
STYLES["b7_pur"] = ringfill([12, 15, 15, 15, 15, 15], [9, 8, 4], [3, 3])                    # pal 81 / 19
STYLES["b7_ane_h"] = ringfill([13, 13, 13, 13, 13, 13], [1])                                # s3_ane pal 9 (white on green)
STYLES["b7_okp_tab"] = ringfill([6, 6, 6, 6, 6, 6], [14])                      # s3_okp pal 14
STYLES["b7_okp_st"] = ringfill([14, 14, 14, 14, 14, 14], [5])                               # s3_okp pal 0
# flat blue / green lettering on plates
STYLES["b7_okp_it"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)                              # s3_okp pal 3
STYLES["b7_ebox_pl"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)                             # s3_ebox pal 28
STYLES["b7_ebox_tf"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)                                   # s3_ebox pal 3
STYLES["b7_ebox_h"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)                                    # s3_ebox pal 2
STYLES["b7_yun_bl"] = flat([0, 14, 14, 14, 14, 14, 14], cut=3)                              # list text, pal 45 / 6 share the page
# dialog of s3_ein 0a (pal 51): blue letters, light shadow
STYLES["b7_dlg"] = ringfill([1, 1, 1, 2, 2, 2], [8], [9, 11])


def centred(style, total):
    """The art padded left and right to `total` columns (so cuts at piece edges keep a word centred over several pieces)."""
    def cut(ink, base):
        art, b = style(ink, base)
        w = art.shape[1]
        if w >= total:
            return art, b
        l = (total - w) // 2
        out = np.zeros((art.shape[0], total), np.uint8)
        out[:, l:l + w] = art
        return out, b
    return cut


STYLES["b7_dl272"] = centred(STYLES["b7_dlg"], 272)
for _c0, _c1 in ((0, 128), (128, 256), (256, 4096)):
    STYLES["b7_dl272~%d_%d" % (_c0, _c1)] = win(STYLES["b7_dl272"], _c0, _c1)
STYLES["b7_dl168"] = centred(STYLES["b7_dlg"], 168)
for _c0, _c1 in ((0, 112), (112, 4096)):
    STYLES["b7_dl168~%d_%d" % (_c0, _c1)] = win(STYLES["b7_dl168"], _c0, _c1)


def padright(style, total):
    """The art padded on the right to `total` columns (a left-aligned word shown over several pieces)."""
    def cut(ink, base):
        art, b = style(ink, base)
        if art.shape[1] >= total:
            return art, b
        out = np.zeros((art.shape[0], total), np.uint8)
        out[:, :art.shape[1]] = art
        return out, b
    return cut


STYLES["b7_yun_p72"] = padright(STYLES["b7_yun_bl"], 72)          # Cap Logo / Helmet Logo: pieces 16 + 56
STYLES["b7_yun_p72~0_16"] = win(STYLES["b7_yun_p72"], 0, 16)
STYLES["b7_yun_p72~16_4096"] = win(STYLES["b7_yun_p72"], 16, 4096)
STYLES["b7_yun_p80"] = padright(STYLES["b7_yun_bl"], 80)          # Number Trim / Sleeves...: pieces 56 + 24
STYLES["b7_yun_p80~0_56"] = win(STYLES["b7_yun_p80"], 0, 56)
STYLES["b7_yun_p80~56_4096"] = win(STYLES["b7_yun_p80"], 56, 4096)

STYLES["b7_okp_mas"] = ringfill([1, 1, 1, 1, 1, 1], [15])                                 # s3_okp pal 3: white letters, blue ring
