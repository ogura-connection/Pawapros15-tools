"""Styles for the Records Room: pages of season and career records (games played, home runs, average and so on).

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): rec_room.
"""
from pp15.art import typeset as ui_type
from .common import ringfill, flat

STYLES = {}


# ---- rec_room.arc: pages of g3_gkn, g3_mvp, g3_nen -------------------------------------------------------------------

STYLES["a8_gkn"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1])    # 68/99 votes, e.g. rec_room g3_gkn#12+g3_ji#13 00
STYLES["a8_gkn_s"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 9], [15, 15])
STYLES["a8_gkn_6f"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15])
STYLES["a8_gkn_71"] = ringfill([8, 8, 8, 8, 8, 8], [1, 1], [15])    # 1/1 votes, e.g. rec_room g3_gkn#12+g3_ji#13 71
STYLES["a8_mvp"] = ringfill([15, 15, 15, 15, 15, 15], [9, 1, 1, 5])
STYLES["a8_mvp_ab"] = ringfill([15, 15, 15, 15, 15, 15], [9, 1, 1, 5])
STYLES["a8_nen01"] = ringfill([5, 5, 6, 7, 7, 7], [4, 15], [15, 2])
STYLES["a8_nen02"] = ringfill([5, 5, 6, 6, 7, 7], [4, 15], [15, 2])
STYLES["a8_nen03"] = ringfill([8, 8, 8, 8, 8, 8], [4, 15], [15, 2])
STYLES["a8_nen04"] = ringfill([12, 12, 11, 10, 7, 9], [4, 15, 15], [15])
STYLES["a8_nen05"] = ringfill([1, 1, 1, 1, 1, 1], [6])
STYLES["a8_nen17"] = ringfill([8, 8, 8, 8, 8, 8], [3, 1, 5], [15, 13])
STYLES["a8_nen18"] = ringfill([8, 8, 8, 8, 8, 8], [3, 1, 5], [15, 13])
STYLES["a8_nen19"] = ringfill([8, 8, 8, 8, 8, 8], [1, 12, 13, 13], [1])
STYLES["a8_logo"] = ringfill([13, 14, 14, 14, 13, 10], [9, 1, 4, 7, 5, 2])


# ---- rec_room.arc: pages of g2_ck, g3_ft, g3_syo, g3_npk -------------------------------------------------------------

STYLES["b8_ck55"] = ringfill([15] * 6, [8], [2, 2])
STYLES["b8_ck41"] = ringfill([15] * 6, [8], [10, 2])
STYLES["b8_ck39"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [2, 2])
STYLES["b8_ck58"] = ringfill([15] * 6, [8], [11, 2])
STYLES["b8_ckt30"] = ringfill([4, 4, 4, 4, 4, 4], [8, 8, 8], [15, 15])
STYLES["b8_ckt31"] = ringfill([4, 4, 4, 4, 4, 4], [8, 8, 8], [15, 15])
STYLES["b8_ck4"] = ringfill([1, 1, 1, 1, 1, 1], [3, 8, 8], [15, 15])
STYLES["b8_ck5"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 8], [15, 15])
STYLES["b8_ck6"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 8], [15])
STYLES["b8_ck7"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 8], [15, 15])
STYLES["b8_ck0"] = ringfill([3, 3, 3, 3, 3, 3], [8, 8], [15, 15, 15])
STYLES["b8_ck1"] = ringfill([4, 4, 4, 4, 4, 4], [8, 8, 8], [15, 15])
STYLES["b8_ck2"] = ringfill([3, 3, 3, 3, 3, 3], [8, 8], [15, 15, 15])
STYLES["b8_ck3"] = ringfill([3, 3, 3, 3, 3, 3], [8, 8, 8], [15, 15])
STYLES["b8_ck27"] = ringfill([9, 9, 9, 9, 9, 9], [15, 1])
STYLES["b8_ft27"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8], [8, 8])
STYLES["b8_ft20"] = ringfill([7, 7, 7, 7, 7, 7], [1, 1, 1, 15, 15, 15], [15, 15, 10, 10])
STYLES["b8_ft22"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15], [10, 10, 10])
STYLES["b8_ft21"] = ringfill([10, 10, 10, 10, 10, 10], [1, 1, 1])
STYLES["b8_ft23"] = ringfill([6, 6, 6, 6, 6, 6], [1, 1, 15, 15, 15], [15, 15])
STYLES["b8_ft16"] = ringfill([3, 3, 3, 3, 3, 3], [8, 8, 8], [15, 15])
STYLES["b8_ft13"] = ringfill([8, 8, 8, 8, 8, 8], [1, 1], [15, 15])
STYLES["b8_syo8"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15, 15, 5, 5, 5])
STYLES["b8_syo2"] = ringfill([8, 8, 8, 8, 8, 8], [1, 1], [1, 1])
STYLES["b8_syo1"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15, 15, 15])
STYLES["b8_syo0"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15, 15])
STYLES["b8_npk28"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7, 3])
STYLES["b8_npk36"] = ringfill([15, 15, 15, 15, 15, 15], [7, 5], [1])
STYLES["b8_npk39"] = ringfill([6, 15, 15, 15, 15, 15], [11])
STYLES["b8_npk20"] = ringfill([15] * 6, [7, 7], [7])
STYLES["b8_npk21"] = ringfill([15] * 6, [7, 7], [7])
STYLES["b8_npk22"] = ringfill([15] * 6, [7, 7], [7])
STYLES["b8_npk24"] = ringfill([15, 15, 15, 15, 15, 15], [2])
STYLES["b8_npk65"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7, 3])
STYLES["b8_npk66"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [3])
STYLES["b8_npk18"] = ringfill([15, 15, 15, 15, 15, 15], [2])
STYLES["b8_npk17"] = ringfill([15, 15, 15, 15, 15, 15], [3])
