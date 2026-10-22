"""Styles added late to fix individual labels that looked wrong on several different screens.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): champion, order, arr_sub, arrange, rec_room, chmp_t, koukai, sct_a_od, homerun, gameplay, chmp_e, scs_main, orepena, ore_ren.
"""
import numpy as np
from pp15.art import typeset as ui_type
from .common import ringfill, flat
from .my_life_practice import solid as _solid
from . import my_life_report as orepena2

STYLES = {}


# ---- fixes of several screens (fxE_...): champion.arc, order.arc, chmp_t.arc, arr_sub.arc, arrange.arc ---------------

def win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

STYLES['fxE_ch12'] = ringfill([15, 15, 14, 13, 12, 12], [7, 1, 1], [1, 1])
STYLES['fxE_ch15'] = ringfill([10, 10, 10, 10, 10, 10], [1, 1], [2])
STYLES['fxE_ch18'] = ringfill([4, 6, 8, 9, 11, 12], [14, 15, 1], [13, 13])
STYLES['fxE_ch19'] = ringfill([10, 11, 12, 13, 14, 15], [2, 1, 9], [3, 3])
STYLES['fxE_ch1a'] = ringfill([14, 14, 12, 11, 10, 10], [7, 2, 15, 3], [4, 4])
STYLES['fxE_ch1b'] = ringfill([10, 11, 12, 13, 14, 14], [10, 1, 9], [9, 9])
STYLES['fxE_tsk00'] = ringfill([15, 15, 15, 14, 13, 13], [7, 7])
STYLES['fxE_tsk1f'] = ringfill([14, 14, 13, 12, 11, 11], [1, 1, 15, 15], [8, 4])
STYLES['fxE_tna'] = ringfill([13, 14, 15, 15, 15, 15], [9, 8, 5], [4])
STYLES['fxE_herbig'] = ringfill([0xc, 0xc, 0xd, 0xe, 0xf], [1, 8, 3, 3])
STYLES['fxE_ted_02'] = ringfill([11, 5, 4, 2, 1, 11], [1], [15])
STYLES['fxE_ted_1a'] = ringfill([11, 5, 4, 2, 1, 11], [8])
STYLES['fxE_ted'] = ringfill([6, 5, 4, 4, 2, 1], [11, 11], [14])
STYLES['fxE_tig30'] = ringfill([2, 4, 3, 1, 1, 2], [10])
STYLES['fxE_hr22'] = ringfill([14, 15, 15, 15, 14, 13], [9], [5])
STYLES['fxE_od72'] = ringfill([15]*6, [4])
STYLES['fxE_od73'] = ringfill([15]*6, [4])
STYLES['fxE_od74'] = ringfill([15]*6, [4])
STYLES['fxE_od76'] = ringfill([15]*6, [4])
STYLES['fxE_od77'] = ringfill([15]*6, [3])
STYLES['fxE_od75'] = ringfill([14]*6, [4])
STYLES['fxE_kh64'] = ringfill([13, 13, 12, 13, 15, 15], [9, 5, 4])
STYLES['fxE_sh13'] = ringfill([1]*6, [15, 15])
STYLES['fxE_am1f'] = ringfill([15]*6, [9, 9])
STYLES['fxE_am29'] = ringfill([10]*6, [1, 1], [13])
STYLES['fxE_ch12~0_118'] = win(STYLES['fxE_ch12'], 0, 118)
STYLES['fxE_ch12~118_246'] = win(STYLES['fxE_ch12'], 118, 246)
STYLES['fxE_ch12~246_4096'] = win(STYLES['fxE_ch12'], 246, 4096)
STYLES['fxE_ch15~0_127'] = win(STYLES['fxE_ch15'], 0, 127)
STYLES['fxE_ch15~127_4096'] = win(STYLES['fxE_ch15'], 127, 4096)
STYLES['fxE_ch18~0_107'] = win(STYLES['fxE_ch18'], 0, 107)
STYLES['fxE_ch18~107_4096'] = win(STYLES['fxE_ch18'], 107, 4096)
STYLES['fxE_ch1a~0_124'] = win(STYLES['fxE_ch1a'], 0, 124)
STYLES['fxE_ch1a~124_4096'] = win(STYLES['fxE_ch1a'], 124, 4096)
STYLES['fxE_ch1b~0_44'] = win(STYLES['fxE_ch1b'], 0, 44)
STYLES['fxE_ch1b~44_4096'] = win(STYLES['fxE_ch1b'], 44, 4096)
STYLES['fxE_tsk00~0_120'] = win(STYLES['fxE_tsk00'], 0, 120)
STYLES['fxE_tsk00~120_248'] = win(STYLES['fxE_tsk00'], 120, 248)
STYLES['fxE_tsk00~248_4096'] = win(STYLES['fxE_tsk00'], 248, 4096)
STYLES['fxE_tig30~0_29'] = win(STYLES['fxE_tig30'], 0, 29)
STYLES['fxE_tig30~31_4096'] = win(STYLES['fxE_tig30'], 31, 4096)


# ---- leftover fixes (fxL_): orepena.arc, scs_main.arc, rec_room.arc, sct_a_od.arc ------------------------------------

def win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

STYLES['fxL_km'] = flat([0, 0, 13, 1, 1, 1, 1], cut=2)
STYLES['fxL_km1'] = flat([0, 0, 0, 1, 1, 1, 1], cut=3)
STYLES['fxL_od_cancel'] = ringfill([12, 12, 11, 11, 8, 3], [1, 15, 5], [7, 9])
STYLES['fxL_month'] = ringfill([8], [15, 15, 8], [1, 1])
STYLES['fxL_pnews'] = orepena2.gsolid([5, 6, 7, 8], [11, 11, 15, 15], 1)
# option.arc help text: Avenir Next Medium (not condensed): letters stand apart at 9 px
ui_type.TTF.setdefault('avn', ('/System/Library/Fonts/Avenir Next.ttc', 5))


# ---- My Life fixes (fxA_...) -----------------------------------------------------------------------------------------

# koukai y3_koukai 96 (Press to OK): white letters, two navy rings as the Japanese
STYLES["fxA_koukai_96"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [])

# ore_ren g3_0ren practice names: blue letters, thick white ring, thin dark-blue edge (as the Japanese)
STYLES["fxA_ren"] = _solid(3, [15, 15, 7])

# ore_sub: y3_pmoji B/T and money units, r5_ut B/T (as the Japanese reads: pale letters with one dark ring + shadow; dark letters, pale ring)
STYLES["fxA_pm"] = ringfill([14, 14, 14, 14, 14, 14], [5], [5])
STYLES["fxA_ut"] = ringfill([5, 5, 5, 5, 5, 5], [9])


# ---- overrides -------------------------------------------------------------------------------------------------------

STYLES["c8_018"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. rec_room g3_gol#8+g3_syo#9 06
