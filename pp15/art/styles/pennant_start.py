"""Styles for starting a Pennant season and for the draft: team set-up, the draft meeting, the draft board and the season-start backgrounds.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): pena_ini, dft_meet, draft, pn_deban, mbg_2gun, pnbg_rai, pnbg_spr, pnbg_win.
"""
import numpy as np
import os
from pp15 import config
from pp15.art import typeset as ui_type
from pp15.art import textures as _U
from pp15.script import scan as _S
from .common import ringfill, win, flat

STYLES = {}


# ---- pena_ini.arc, dft_meet.arc, mbg_2gun.arc, pnbg_rai.arc ----------------------------------------------------------

def _sil(front, c):
    def style(ink, base):
        out, b = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), b
    return style

STYLES["c6_dtv_1a"] = ringfill([3, 3, 5, 6, 7, 7], [14, 14, 8, 8], [])
STYLES["c6_dtv_1a_s"] = ringfill([3, 3, 5, 6, 7, 7], [14], [])
STYLES["c6_dtv_1d"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5], [])
STYLES["c6_dtv_1d_s"] = ringfill([15, 15, 15, 15, 15, 15], [8], [])
STYLES["c6_dtv_29"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7, 7], [])
STYLES["c6_dtv_29_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["c6_dtv_2b"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["c6_dtv_2b_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["c6_dtv_43"] = ringfill([15, 15, 15, 15, 15, 15], [6, 6], [6])
STYLES["c6_dtv_43_s"] = ringfill([15, 15, 15, 15, 15, 15], [6], [])
STYLES["c6_dtv_45"] = ringfill([15, 15, 15, 15, 15, 15], [6, 7], [6])
STYLES["c6_dtv_45_s"] = ringfill([15, 15, 15, 15, 15, 15], [6], [])
STYLES["c6_g3_dtk_0_21"] = ringfill([13, 9, 9, 8, 7, 13], [3], [])
STYLES["c6_g3_dtk_0_21_h"] = ringfill([7, 8, 8, 9, 9, 10], [13, 13, 1, 1], [])
STYLES["c6_g3_dtk_0_21_h_s"] = ringfill([7, 8, 8, 9, 9, 10], [13], [])
STYLES["c6_g3_dtk_0_21_s"] = ringfill([13, 9, 9, 8, 7, 13], [3], [])
STYLES["c6_g3_dtk_0_22"] = ringfill([13, 7, 13, 13, 7, 13], [2], [5, 5])
STYLES["c6_g3_dtk_0_22_h"] = ringfill([9, 8, 7, 7, 7, 6], [13, 13, 1, 1], [])
STYLES["c6_g3_dtk_0_22_h_s"] = ringfill([9, 8, 7, 7, 7, 6], [13], [])
STYLES["c6_g3_dtk_0_22_s"] = ringfill([13, 7, 13, 13, 7, 13], [2], [])
STYLES["c6_g3_dtv_0_06"] = ringfill([1, 1, 1, 4, 4, 10], [13], [])
STYLES["c6_g3_dtv_0_06_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_06_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_06_s"] = ringfill([1, 1, 1, 4, 4, 10], [13], [])
STYLES["c6_g3_dtv_0_07"] = ringfill([1, 1, 1, 1, 1, 1], [1, 1, 1, 5], [])
STYLES["c6_g3_dtv_0_07_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_07_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_07_s"] = ringfill([1, 1, 1, 1, 1, 1], [1], [])
STYLES["c6_g3_dtv_0_08"] = ringfill([1, 1, 1, 1, 5, 1], [1], [])
STYLES["c6_g3_dtv_0_08_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_08_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_08_s"] = ringfill([1, 1, 1, 1, 5, 1], [1], [])
STYLES["c6_g3_dtv_0_09"] = ringfill([1, 3, 1, 1, 2, 1], [8], [8])
STYLES["c6_g3_dtv_0_09_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_09_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_09_s"] = ringfill([1, 3, 1, 1, 2, 1], [8], [])
STYLES["c6_g3_dtv_0_0a"] = ringfill([1, 1, 5, 5, 1, 1], [9], [])
STYLES["c6_g3_dtv_0_0a_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_0a_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_0a_s"] = ringfill([1, 1, 5, 5, 1, 1], [9], [])
STYLES["c6_g3_dtv_0_0b"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_0b_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_0b_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_0b_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_0c"] = ringfill([1, 1, 1, 1, 1, 1], [2], [])
STYLES["c6_g3_dtv_0_0c_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_0c_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_0c_s"] = ringfill([1, 1, 1, 1, 1, 1], [2], [])
STYLES["c6_g3_dtv_0_0d"] = ringfill([3, 3, 7, 1, 10, 1], [9], [9])
STYLES["c6_g3_dtv_0_0d_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_0d_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_0d_s"] = ringfill([3, 3, 7, 1, 10, 1], [9], [])
STYLES["c6_g3_dtv_0_0e"] = ringfill([1, 1, 1, 1, 1, 1], [7], [7])
STYLES["c6_g3_dtv_0_0e_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_0e_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_0e_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_0f"] = ringfill([1, 1, 1, 5, 5, 1], [1, 1, 1, 8], [])
STYLES["c6_g3_dtv_0_0f_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_0f_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_0f_s"] = ringfill([1, 1, 1, 5, 5, 1], [1], [])
STYLES["c6_g3_dtv_0_10"] = ringfill([8, 1, 1, 1, 1, 1], [9], [])
STYLES["c6_g3_dtv_0_10_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_10_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_10_s"] = ringfill([8, 1, 1, 1, 1, 1], [9], [])
STYLES["c6_g3_dtv_0_11"] = ringfill([1, 1, 5, 5, 2, 2], [13], [])
STYLES["c6_g3_dtv_0_11_h"] = ringfill([1, 1, 1, 1, 1, 1], [4], [9])
STYLES["c6_g3_dtv_0_11_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [4], [])
STYLES["c6_g3_dtv_0_11_s"] = ringfill([1, 1, 5, 5, 2, 2], [13], [])
STYLES["c6_g3_dtv_0_12"] = ringfill([1, 1, 1, 1, 1, 1], [11], [11])
STYLES["c6_g3_dtv_0_12_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_12_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_12_s"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["c6_g3_dtv_0_13"] = ringfill([1, 1, 1, 1, 1, 1], [11], [11])
STYLES["c6_g3_dtv_0_13_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_13_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_13_s"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["c6_g3_dtv_0_14"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_14_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_14_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_14_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_15"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["c6_g3_dtv_0_15_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_15_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_15_s"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["c6_g3_dtv_0_16"] = ringfill([6, 6, 1, 1, 6, 6], [4], [])
STYLES["c6_g3_dtv_0_16_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_16_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_16_s"] = ringfill([6, 6, 1, 1, 6, 6], [4], [])
STYLES["c6_g3_dtv_0_17"] = ringfill([1, 1, 1, 1, 1, 1], [1, 1, 1, 1], [])
STYLES["c6_g3_dtv_0_17_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_17_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_17_s"] = ringfill([1, 1, 1, 1, 1, 1], [1], [])
STYLES["c6_g3_dtv_0_18"] = ringfill([11, 11, 1, 1, 5, 5], [13], [])
STYLES["c6_g3_dtv_0_18_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_18_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_18_s"] = ringfill([11, 11, 1, 1, 5, 5], [13], [])
STYLES["c6_g3_dtv_0_19"] = ringfill([9, 1, 9, 1, 7, 1], [13], [13])
STYLES["c6_g3_dtv_0_19_h"] = ringfill([1, 1, 1, 1, 1, 1], [7], [11])
STYLES["c6_g3_dtv_0_19_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [7], [])
STYLES["c6_g3_dtv_0_19_s"] = ringfill([9, 1, 9, 1, 7, 1], [13], [])
STYLES["c6_s3_ppjo_00_2_h"] = ringfill([15, 15, 15, 15, 15, 15], [11], [9, 9])
STYLES["c6_s3_ppjo_00_2_h_s"] = ringfill([15, 15, 15, 15, 15, 15], [11], [])
STYLES["c6_s3_ppjo_11_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_11_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_12_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_12_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_13_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_13_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_14_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_14_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_15_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_15_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_16_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_16_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_17_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_17_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_18_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_18_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_19_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_19_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1a_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1a_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1b_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1b_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1c_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1c_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1d_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1d_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1e_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1e_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1f_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_1f_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_20_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_20_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_21_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_21_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_23_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_23_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_24_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_24_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_25_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_25_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_26_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_26_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_27_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_27_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_28_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_28_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_29_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_29_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2a_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2a_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2b_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2b_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2c_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2c_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2d_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2d_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2e_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2e_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2f_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_2f_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_30_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_30_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_31_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_31_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_32_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_32_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_33_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_33_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_34_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_34_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_35_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_35_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_36_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_36_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_37_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_37_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_38_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_38_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_39_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_39_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3a_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3a_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3b_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3b_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3c_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3c_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3d_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3d_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3e_4_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_3e_4_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4a_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4a_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4b_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4b_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4c_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4c_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4d_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4d_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4e_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4e_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4f_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_ppjo_4f_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s3_pt00_05"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["c6_s3_pt00_05_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["c6_s3_pt00_06"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["c6_s3_pt00_06_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["c6_s3_pt00_07"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["c6_s3_pt00_07_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["c6_s3_pt00_2b"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["c6_s3_pt00_2b_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["c6_s3_pt00_3f"] = ringfill([1, 1, 1, 1, 1, 1], [15], [15, 15])
STYLES["c6_s3_pt00_3f_s"] = ringfill([1, 1, 1, 1, 1, 1], [15], [])
STYLES["c6_s3_pt00_40"] = ringfill([1, 8, 1, 1, 1, 1], [15], [15, 12])
STYLES["c6_s3_pt00_40_s"] = ringfill([1, 8, 1, 1, 1, 1], [15], [])
STYLES["c6_s3_ptz00_00"] = ringfill([141, 125, 98, 73, 54, 139], [255, 1, 12], [61, 105])
STYLES["c6_s3_ptz00_00_s"] = ringfill([141, 125, 98, 73, 54, 139], [255], [])
STYLES["c6_s3_ptz00_01"] = ringfill([149, 125, 102, 73, 54, 45], [12, 1, 59], [61, 105])
STYLES["c6_s3_ptz00_01_s"] = ringfill([149, 125, 102, 73, 54, 45], [12], [])
STYLES["c6_s3_ptz00_02"] = ringfill([141, 137, 113, 65, 57, 84], [255, 12, 1], [61, 79])
STYLES["c6_s3_ptz00_02_s"] = ringfill([141, 137, 113, 65, 57, 84], [255], [])
STYLES["c6_s3_ptz00_03"] = ringfill([243, 237, 229, 211, 207, 180], [255, 136, 99], [111, 168])
STYLES["c6_s3_ptz00_03_s"] = ringfill([243, 237, 229, 211, 207, 180], [255], [])
STYLES["c6_s3_ptz00_04"] = ringfill([234, 230, 212, 182, 174, 180], [255, 255, 24], [99, 153])
STYLES["c6_s3_ptz00_04_s"] = ringfill([234, 230, 212, 182, 174, 180], [255], [])
STYLES["c6_s3_ptz00_06"] = ringfill([124, 81, 233, 222, 201, 180], [255, 136, 99], [79, 185])
STYLES["c6_s3_ptz00_06_s"] = ringfill([124, 81, 233, 222, 201, 180], [255], [])
STYLES["c6_s3_ptz00_08"] = ringfill([48, 48, 48, 48, 48, 48], [255, 15, 106], [58, 156])
STYLES["c6_s3_ptz00_08_s"] = ringfill([48, 48, 48, 48, 48, 48], [255], [])
STYLES["c6_s3_ptz00_09"] = ringfill([63, 63, 63, 63, 63, 63], [255, 127, 69], [58, 156])
STYLES["c6_s3_ptz00_09_s"] = ringfill([63, 63, 63, 63, 63, 63], [255], [])
STYLES["c6_s3_ptz00_0b"] = ringfill([30, 30, 30, 232, 232, 30], [255, 255, 212], [56, 126])
STYLES["c6_s3_ptz00_0b_s"] = ringfill([30, 30, 30, 232, 232, 30], [255], [])
STYLES["c6_s4_tai00_00"] = ringfill([15, 15, 15, 15, 15, 15], [3], [3, 2])
STYLES["c6_s4_tai00_00_s"] = ringfill([15, 15, 15, 15, 15, 15], [3], [])
STYLES["c6_s4_tai00_01"] = ringfill([15, 15, 15, 15, 6, 15], [2], [])
STYLES["c6_s4_tai00_01_s"] = ringfill([15, 15, 15, 15, 6, 15], [2], [])
STYLES["c6_s4_tai00_02"] = ringfill([15, 15, 15, 15, 15, 15], [3], [3])
STYLES["c6_s4_tai00_02_s"] = ringfill([15, 15, 15, 15, 15, 15], [3], [])
STYLES["c6_s4_tai00_03"] = ringfill([15, 15, 15, 15, 15, 15], [4], [1])
STYLES["c6_s4_tai00_03_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["c6_s4_tai00_04"] = ringfill([15, 15, 15, 15, 6, 15], [2], [2])
STYLES["c6_s4_tai00_04_s"] = ringfill([15, 15, 15, 15, 6, 15], [2], [])
STYLES["c6_s4_tai00_05"] = ringfill([15, 15, 15, 15, 15, 15], [4], [4, 3, 2])
STYLES["c6_s4_tai00_05_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["c6_s4_tai00_08_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_08_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_09_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_09_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0a_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0a_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0b_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0b_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0c_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0c_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0d_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0d_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0e_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0e_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0f_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_0f_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_10_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_10_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_11_p"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_s4_tai00_11_p_s"] = ringfill([15, 15, 15, 15, 15, 15], [0], [])
STYLES["c6_v2_bgm01_02"] = ringfill([4, 15, 4, 15, 15, 9], [1], [])
STYLES["c6_v2_bgm01_02_s"] = ringfill([4, 15, 4, 15, 15, 9], [1], [])
STYLES["c6_v2_pbg1_02"] = ringfill([15, 15, 8, 8, 15, 15], [1], [])
STYLES["c6_v2_pbg1_02_h"] = ringfill([15, 15, 15, 15, 15, 15], [8, 5, 4], [])
STYLES["c6_v2_pbg1_02_h_s"] = ringfill([15, 15, 15, 15, 15, 15], [8], [])
STYLES["c6_v2_pbg1_02_s"] = ringfill([15, 15, 8, 8, 15, 15], [1], [])
STYLES["c6_dtv_1b"] = _sil("c6_dtv_1a", 8)
STYLES["c6_dtv_1b_s"] = _sil("c6_dtv_1a_s", 8)
STYLES["c6_dtv_2a"] = _sil("c6_dtv_29", 7)
STYLES["c6_dtv_2a_s"] = _sil("c6_dtv_29_s", 7)
STYLES["c6_dtv_2c"] = _sil("c6_dtv_2b", 7)
STYLES["c6_dtv_2c_s"] = _sil("c6_dtv_2b_s", 7)
STYLES["c6_dtv_44"] = _sil("c6_dtv_43", 1)
STYLES["c6_dtv_44_s"] = _sil("c6_dtv_43_s", 1)
STYLES["c6_dtv_46"] = _sil("c6_dtv_45", 1)
STYLES["c6_dtv_46_s"] = _sil("c6_dtv_45_s", 1)

# v2_bgm01 sprites 00 / 01: whole-picture styles (the picture with the 2gun box cleared and the English set in it)
_PICS = np.load(os.path.join(config.UI_PAGES_DIR, 'run6', 'C', 'bgm_pics.npz'))
_RING = ringfill([2] * 6, [15, 15], [])
REGION = {'00': (69, 35, 128, 69), '01': (0, 13, 51, 45)}
def _pic(sid):
    pic = _PICS[sid]; x0, y0, x1, y1 = REGION[sid]
    def style(ink, base):
        art, _ = _RING(ink, base)
        out = pic.copy(); out[y0:y1, x0:x1] = 0
        h, w = art.shape
        ox = x0 + max(((x1 - x0) - w) // 2, 0); oy = y0 + max(((y1 - y0) - h) // 2, 0)
        m = art > 0
        out[oy:oy + h, ox:ox + w][m] = art[m]
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], 0
    return style
STYLES['c6_bgm_00'] = _pic('00')
STYLES['c6_bgm_01'] = _pic('01')


# ---- draft.arc, pn_deban.arc, pnbg_spr.arc, pnbg_win.arc -------------------------------------------------------------

_OLD = {}


def _old(arcname, bank, pg):
    if arcname not in _OLD:
        p = os.path.join(_U.ORIG_ARC_DIR, arcname)
        if not os.path.exists(p):
            p = os.path.join(_S.DATA_FILES, arcname)
        d = open(p, "rb").read()
        _OLD[arcname] = (d, {x["name"]: x for x in _U.banks(d, _U.elf_symbols(d))})
    d, bs = _OLD[arcname]
    return _U.decode_indices(d, *bs[bank]["pages"][pg])


def _components(fg):
    """8-connected components of a boolean array: list of lists of (y, x)."""
    seen = np.zeros(fg.shape, bool)
    out = []
    for y, x in zip(*np.nonzero(fg)):
        if seen[y, x]:
            continue
        st = [(y, x)]; seen[y, x] = True; comp = []
        while st:
            cy, cx = st.pop(); comp.append((cy, cx))
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    ny, nx = cy + dy, cx + dx
                    if 0 <= ny < fg.shape[0] and 0 <= nx < fg.shape[1] and fg[ny, nx] and not seen[ny, nx]:
                        seen[ny, nx] = True; st.append((ny, nx))
        out.append(comp)
    return out


def pill(arcname, bank, rect, kind, inner, cx, cy, white=15, top_pale=None, shear=0.0):
    """The old picture of `rect` (page, x0, y0, x1, y1) with its kanji painted out and the English (`inner` style) centred
    at (cx, cy), tilted by `shear` (rows per column, rising to the right). The picture is the label's art: use it with
    "left": 0, "baseline": 0.
    kind "badge": columns 5-21: rows below `top_pale` white (index `white`), rows above the pale plate colour (1);
    kind "disc": the inside of the round stamp (radius 10.5) white; kind "stamp": every piece of ink but the biggest white."""
    def style(ink, base):
        pg, x0, y0, x1, y1 = rect
        pic = _old(arcname, bank, pg)[y0:y1, x0:x1].copy()
        if kind == "badge":
            pic[4:top_pale, 4:22] = 1
            pic[top_pale:25, 4:22] = white
        elif kind == "disc":
            yy, xx = np.mgrid[0:pic.shape[0], 0:pic.shape[1]]
            pic[((yy - 15.5) ** 2 + (xx - 15.5) ** 2) < 10.5 ** 2] = white
        else:
            strong = (pic >= 1) & (pic <= 6)
            comps = _components(strong)
            comps.sort(key=len)
            rim = np.zeros(pic.shape, bool)
            for y, x in comps[-1]:
                rim[y, x] = True
            gone = np.zeros(pic.shape, bool)
            for comp in comps[:-1]:
                for y, x in comp:
                    gone[y, x] = True
            for _ in range(3):
                g2 = gone.copy()
                g2[1:] |= gone[:-1]; g2[:-1] |= gone[1:]; g2[:, 1:] |= gone[:, :-1]; g2[:, :-1] |= gone[:, 1:]
                g2[1:, 1:] |= gone[:-1, :-1]; g2[:-1, :-1] |= gone[1:, 1:]; g2[1:, :-1] |= gone[:-1, 1:]; g2[:-1, 1:] |= gone[1:, :-1]
                gone = g2
            pic[gone & ~rim & (pic != 0)] = white
        art, b = inner(ink, base)
        h, w = art.shape
        x = cx - w // 2
        y = int(round(cy - h / 2))
        ys, xs = np.nonzero(art)
        for yy, xx in zip(ys, xs):
            dy = -int(round((xx - w / 2.0) * shear))
            py, px = y + yy + dy, x + xx
            if 0 <= py < pic.shape[0] and 0 <= px < pic.shape[1]:
                pic[py, px] = art[yy, xx]
        return pic, 0
    return style


def onwhite(inner, W, H, bg=15, nudge=0):
    """The letters on a W x H canvas of colour `bg`, centred (the logo sprites carry their own white board)."""
    def style(ink, base):
        art, b = inner(ink, base)
        h, w = art.shape
        out = np.full((H, W), bg, np.uint8)
        x, y = (W - w) // 2, (H - h) // 2 + nudge
        sub = out[max(y, 0):y + h, max(x, 0):x + w]
        a = art[max(-y, 0):max(-y, 0) + sub.shape[0], max(-x, 0):max(-x, 0) + sub.shape[1]]
        sub[a > 0] = a[a > 0]
        return out, y + b
    return style


# ---- g3_pd_0 (draft.arc): buttons on the draft screen: navy / green / blue / brown / purple letters, white ring, blue shadow
S = STYLES
S["e6_pd_00"] = ringfill([2], [1], [9, 12])
S["e6_pd_05"] = ringfill([3], [1], [9, 12])
S["e6_pd_06"] = ringfill([4], [1], [9, 12])
S["e6_pd_07"] = ringfill([15], [1], [8, 14])
S["e6_pd_08"] = ringfill([5], [1], [10, 13])
S["e6_pd_09"] = ringfill([15], [1], [8, 14])
S["e6_pd_0d"] = ringfill([5], [1], [9, 11])
S["e6_pd_0e"] = ringfill([6], [1], [9, 11])
S["e6_pd_47"] = ringfill([6], [1], [9, 11])
STYLES["e6_pd_title"] = ringfill([14, 14, 14, 14, 14, 14], [1, 6, 6, 6])    # 2/2 votes, e.g. draft g3_pd_0 12
S["e6_pd_14"] = ringfill([8], [3], [10])
S["e6_pd_lime"] = ringfill([15, 13, 13, 11, 11, 11], [5, 5], [7])
S["e6_pd_pos"] = ringfill([10], [15], [12, 11])
S["e6_pd_3c"] = ringfill([12, 11, 10, 9, 8, 7], [1, 1, 2])
S["e6_pd_3e"] = ringfill([3, 3, 2, 2, 1, 1], [8, 13])
S["e6_pd_help"] = ringfill([1], [8])
STYLES["e6_pd_red"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. draft g3_pd_0 48
S["e6_pd_stampfill"] = ringfill([1], [15])
S["e6_in_badge"] = ringfill([7], [12])
# letters on the round / tilted stamps and the school badges: the old picture with the English drawn over it
_D = ("draft.arc", "g3_pd_0")
S["e6_pd_25"] = pill(*_D, [3, 32, 96, 64, 128], "badge", S["e6_in_badge"], 13, 14, white=12, top_pale=9)
S["e6_pd_26"] = pill(*_D, [3, 64, 96, 96, 128], "badge", S["e6_in_badge"], 13, 14, white=12, top_pale=9)
S["e6_pd_27"] = pill(*_D, [3, 96, 96, 128, 128], "badge", S["e6_in_badge"], 13, 14, white=12, top_pale=9)
S["e6_pd_36"] = pill(*_D, [8, 0, 0, 32, 32], "disc", S["e6_pd_stampfill"], 16, 16)
S["e6_pd_37"] = pill(*_D, [8, 32, 0, 64, 32], "disc", S["e6_pd_stampfill"], 16, 16)
S["e6_pd_38"] = pill(*_D, [8, 0, 32, 64, 80], "stamp", S["e6_pd_stampfill"], 32, 23, shear=0.17)
S["e6_pd_39"] = pill(*_D, [8, 0, 80, 64, 128], "stamp", S["e6_pd_stampfill"], 32, 23, shear=0.17)
S["e6_pd_3c~0_128"] = win(S["e6_pd_3c"], 0, 128)
S["e6_pd_3c~128_4096"] = win(S["e6_pd_3c"], 128, 4096)
# ---- m3_ksd_0 (pn_deban.arc)
S["e6_ks_title"] = ringfill([12, 12, 11, 11, 9, 8], [2, 2, 15], [1])
S["e6_ks_title~0_4096"] = S["e6_ks_title"]
S["e6_ks_help"] = ringfill([1], [8])
S["e6_ks_05"] = ringfill([15], [9], [3])
S["e6_ks_focus"] = ringfill([15], [5], [1])
S["e6_ks_plate"] = ringfill([3], [15], [1])
S["e6_ks_on"] = ringfill([1], [15], [2])
S["e6_ks_cond"] = ringfill([1], [15])
STYLES["e6_ks_pick"] = ringfill([15, 15, 15, 15, 15, 15], [4])    # 2/2 votes, e.g. pn_deban m3_ksd_0 20
# ---- s5_ptn / b5_r00 / the pennant logos
S["e6_sk"] = ringfill([15], [4])
STYLES["e6_b5"] = ringfill([2, 2, 2, 2, 2, 2], [14])    # 6/10 votes, e.g. pn_deban b5_r00 00
S["e6_b5_small"] = ringfill([1], [12])
_LOGO = ringfill([8, 8, 8, 9, 9, 9], [15, 15, 6, 6])
S["e6_logo_in"] = _LOGO
S["e6_logo_pbg"] = onwhite(_LOGO, 184, 48)
S["e6_logo_pbg4"] = onwhite(_LOGO, 184, 40)     # pnbg_win: the only room for the 80-wide strip is 80 x 40


def arrow(inner):
    """A right arrow (the English has no glyph for it) drawn through `inner`'s rings and shadow, centred on the capitals."""
    def style(ink, base):
        a = np.zeros((11, 22), int)
        a[4:7, 0:17] = 6
        for k in range(6):
            half = 5 - k
            a[5 - half:6 + half, 16 + k] = 6
        art, b = inner(a, 11)
        return art, b + 2
    return style


S["e6_ks_arrow"] = arrow(S["e6_ks_plate"])
# windows of one word over several parts are added by mkcuts below
