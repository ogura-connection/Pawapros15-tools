"""Styles for Pennant mode (managing a pro team through a season): the main screen, trades, season summary, foreign players, free agency and training growth.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): pennant, pn_trade, pn_fa, gdt_npn, pn_gaijn, pn_tgrow, pnbg_sum, pnbg_fal, gdt_pn.
"""
import numpy as np
from pp15.art import typeset as ui_type
from .common import ringfill, flat, _orig_page

STYLES = {}


# ---- pennant.arc -----------------------------------------------------------------------------------------------------

STYLES["a5_b5_pe01_0"] = ringfill([10, 10, 10, 10, 10, 10], [1, 1, 2], [])
STYLES["a5_b5_pe01_0_s"] = ringfill([10, 10, 10, 10, 10, 10], [1], [])
STYLES["a5_b5_pe01_1"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [8])
STYLES["a5_b5_pe01_1_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_b5_pe01_2"] = ringfill([15, 15, 15, 15, 15, 15], [7, 8], [])
STYLES["a5_b5_pe01_2_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_b5_pe01_3"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [8])
STYLES["a5_b5_pe01_3_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_g3_jun_0"] = ringfill([8, 8, 8, 8, 8, 8], [1, 1, 8], [15])
STYLES["a5_g3_jun_0_s"] = ringfill([8, 8, 8, 8, 8, 8], [1], [])
STYLES["a5_g3_jun_10"] = ringfill([10, 10, 9, 9, 8, 8], [2, 12, 12], [14, 14])
STYLES["a5_g3_jun_10_s"] = ringfill([10, 10, 9, 9, 8, 8], [2], [])
STYLES["a5_g3_jun_11"] = ringfill([10, 10, 10, 10, 10, 15], [11, 6, 6], [])
STYLES["a5_g3_jun_11_s"] = ringfill([10, 10, 10, 10, 10, 15], [11], [])
STYLES["a5_g3_jun_12"] = ringfill([5, 5, 5, 5, 5, 1], [12, 12], [15])
STYLES["a5_g3_jun_12_s"] = ringfill([5, 5, 5, 5, 5, 1], [12], [])
STYLES["a5_g3_jun_15"] = ringfill([10, 10, 10, 8, 10, 2], [12, 12], [14])
STYLES["a5_g3_jun_15_s"] = ringfill([10, 10, 10, 8, 10, 2], [12], [])
STYLES["a5_g3_jun_25"] = ringfill([4, 1, 1, 1, 1, 1], [15, 1, 1], [9])
STYLES["a5_g3_jun_25_s"] = ringfill([4, 1, 1, 1, 1, 1], [15], [])
STYLES["a5_g3_jun_27"] = ringfill([7, 7, 6, 6, 5, 5], [1, 12], [])
STYLES["a5_g3_jun_27_s"] = ringfill([7, 7, 6, 6, 5, 5], [1], [])
STYLES["a5_g3_jun_28"] = ringfill([10, 9, 8, 8, 7, 7], [1, 12], [])
STYLES["a5_g3_jun_28_s"] = ringfill([10, 9, 8, 8, 7, 7], [1], [])
STYLES["a5_g3_jun_3"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["a5_g3_jun_3_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["a5_g3_jun_37"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [])
STYLES["a5_g3_jun_37_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["a5_i3_f00_0"] = ringfill([13, 13, 13, 13, 13, 13], [1, 1, 10], [])
STYLES["a5_i3_f00_0_s"] = ringfill([13, 13, 13, 13, 13, 13], [1], [])
STYLES["a5_i3_f00_1"] = ringfill([11, 14, 14, 12, 5, 15], [3, 7, 1], [6])
STYLES["a5_i3_f00_1_s"] = ringfill([11, 14, 14, 12, 5, 15], [3], [])
STYLES["a5_i3_f00_2"] = ringfill([1, 1, 13, 1, 1, 1], [12, 5], [11, 3])
STYLES["a5_i3_f00_2_s"] = ringfill([1, 1, 13, 1, 1, 1], [12], [])
STYLES["a5_i3_f00_3"] = ringfill([8, 8, 14, 8, 8, 8], [6, 7, 2], [15, 1])
STYLES["a5_i3_f00_3_s"] = ringfill([8, 8, 14, 8, 8, 8], [6], [])
STYLES["a5_r5_cp_1"] = ringfill([3, 3, 3, 3, 3, 3], [11, 11, 12], [15, 1])
STYLES["a5_r5_cp_1_s"] = ringfill([3, 3, 3, 3, 3, 3], [11], [])
STYLES["a5_r5_den_20"] = ringfill([14, 14, 15, 15, 15, 15], [7, 7], [])
STYLES["a5_r5_den_20_s"] = ringfill([14, 14, 15, 15, 15, 15], [7], [])
STYLES["a5_r5_den_21"] = ringfill([14, 14, 15, 15, 15, 15], [7, 7], [])
STYLES["a5_r5_den_21_s"] = ringfill([14, 14, 15, 15, 15, 15], [7], [])
STYLES["a5_r5_rad_19"] = ringfill([14, 14, 14, 14, 14, 14], [15, 15], [1])
STYLES["a5_r5_rad_19_s"] = ringfill([14, 14, 14, 14, 14, 14], [15], [])
STYLES["a5_r5_rad_20"] = ringfill([15, 15, 15, 15, 15, 15], [4], [1])
STYLES["a5_r5_rad_20_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["a5_r5_rad_21"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_r5_rad_21_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_r5_rad_22"] = ringfill([15, 15, 15, 15, 15, 15], [5], [7])
STYLES["a5_r5_rad_22_s"] = ringfill([15, 15, 15, 15, 15, 15], [5], [])
STYLES["a5_r5_rad_3"] = ringfill([15, 15, 15, 15, 15, 15], [9, 15, 15], [7, 1])
STYLES["a5_r5_rad_3_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [])
STYLES["a5_r5_rad_4"] = ringfill([7, 7, 7, 7, 7, 7], [10, 15, 13], [1])
STYLES["a5_r5_rad_4_s"] = ringfill([7, 7, 7, 7, 7, 7], [10], [])
STYLES["a5_r5_rad_5"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["a5_r5_rad_5_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_r5_rad_6"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [1])
STYLES["a5_r5_rad_6_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_r5_rad_7"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [])
STYLES["a5_r5_rad_7_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_r5_rad_8"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [3, 1])
STYLES["a5_r5_rad_8_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_s3_hel00_2"] = ringfill([7, 7, 7, 7, 7, 7], [2], [])
STYLES["a5_s3_hel00_2_s"] = ringfill([7, 7, 7, 7, 7, 7], [2], [])
STYLES["a5_s3_pf00_20"] = ringfill([3, 2, 2, 1, 1, 1], [8, 8], [12, 15])
STYLES["a5_s3_pf00_20_s"] = ringfill([3, 2, 2, 1, 1, 1], [8], [12])
STYLES["a5_s3_pf00_21"] = ringfill([3, 2, 2, 1, 1, 1], [8, 8], [12, 15])
STYLES["a5_s3_pf00_21_s"] = ringfill([3, 2, 2, 1, 1, 1], [8], [12])
STYLES["a5_s3_pf00_22"] = ringfill([3, 2, 2, 1, 1, 1], [8, 8], [12, 15])
STYLES["a5_s3_pf00_22_s"] = ringfill([3, 2, 2, 1, 1, 1], [8], [12])
STYLES["a5_s3_pf00_8"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [])
STYLES["a5_s3_pf00_8_s"] = ringfill([15, 15, 15, 15, 15, 15], [1], [])
STYLES["a5_s3_pi00_135"] = ringfill([1, 1, 1, 1, 1, 14], [8, 8, 10], [15, 12])
STYLES["a5_s3_pi00_135_s"] = ringfill([1, 1, 1, 1, 1, 14], [8], [])
STYLES["a5_s3_pi00_136"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 10], [12, 15, 12])
STYLES["a5_s3_pi00_136_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_pi00_137"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 10], [15, 12])
STYLES["a5_s3_pi00_137_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_pi00_138"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 10], [13, 15, 12])
STYLES["a5_s3_pi00_138_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_pi00_139"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 9], [13, 15, 12])
STYLES["a5_s3_pi00_139_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_pi00_140"] = ringfill([1, 1, 1, 1, 1, 13], [8, 8, 10], [15, 12])
STYLES["a5_s3_pi00_140_s"] = ringfill([1, 1, 1, 1, 1, 13], [8], [])
STYLES["a5_s3_pi00_20"] = ringfill([2, 1, 1, 1, 1, 1], [15, 1, 1], [4])
STYLES["a5_s3_pi00_20_s"] = ringfill([2, 1, 1, 1, 1, 1], [15], [])
STYLES["a5_s3_pi00_33"] = ringfill([5, 5, 5, 5, 5, 5], [1, 1, 7], [])
STYLES["a5_s3_pi00_33_s"] = ringfill([5, 5, 5, 5, 5, 5], [1], [])
STYLES["a5_s3_pi00_34"] = ringfill([4, 4, 4, 4, 4, 4], [1, 1, 7], [])
STYLES["a5_s3_pi00_34_s"] = ringfill([4, 4, 4, 4, 4, 4], [1], [])
STYLES["a5_s3_pi00_39"] = ringfill([4, 4, 4, 4, 4, 4], [1, 1, 7], [])
STYLES["a5_s3_pi00_39_s"] = ringfill([4, 4, 4, 4, 4, 4], [1], [])
STYLES["a5_s3_pi00_41"] = ringfill([5, 5, 5, 5, 5, 5], [1, 1, 7], [])
STYLES["a5_s3_pi00_41_s"] = ringfill([5, 5, 5, 5, 5, 5], [1], [])
STYLES["a5_s3_pi00_54"] = ringfill([5, 5, 5, 5, 5, 5], [1, 1, 7], [])
STYLES["a5_s3_pi00_54_s"] = ringfill([5, 5, 5, 5, 5, 5], [1], [])
STYLES["a5_s3_pi00_55"] = ringfill([4, 4, 4, 4, 4, 4], [1, 1, 7], [])
STYLES["a5_s3_pi00_55_s"] = ringfill([4, 4, 4, 4, 4, 4], [1], [])
STYLES["a5_s3_pi00_56"] = ringfill([4, 4, 4, 4, 4, 4], [1, 1, 7], [])
STYLES["a5_s3_pi00_56_s"] = ringfill([4, 4, 4, 4, 4, 4], [1], [])
STYLES["a5_s3_pi00_58"] = ringfill([6, 6, 6, 6, 6, 6], [1, 1, 7], [])
STYLES["a5_s3_pi00_58_s"] = ringfill([6, 6, 6, 6, 6, 6], [1], [])
STYLES["a5_s3_pi00_71"] = ringfill([5, 5, 5, 5, 5, 5], [15, 15, 14], [10, 9])
STYLES["a5_s3_pi00_71_s"] = ringfill([5, 5, 5, 5, 5, 5], [15], [])
STYLES["a5_s3_pi00_76"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 9], [15, 12])
STYLES["a5_s3_pi00_76_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_pi00_77"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 9], [13, 14, 13])
STYLES["a5_s3_pi00_77_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_pi00_78"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8, 9], [14, 13])
STYLES["a5_s3_pi00_78_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_pi00_8"] = ringfill([11, 15, 15, 15, 15, 15], [4, 1, 4], [])
STYLES["a5_s3_pi00_8_s"] = ringfill([11, 15, 15, 15, 15, 15], [4], [])
STYLES["a5_s3_pi00_88"] = ringfill([14, 14, 13, 12, 12, 12], [7, 7, 15], [4])
STYLES["a5_s3_pi00_88_s"] = ringfill([14, 14, 13, 12, 12, 12], [7], [])
STYLES["a5_s3_pi00_89"] = ringfill([1, 1, 1, 1, 1, 1], [10], [12])
STYLES["a5_s3_pi00_89_s"] = ringfill([1, 1, 1, 1, 1, 1], [10], [])
STYLES["a5_s3_pi00_91"] = ringfill([2, 2, 2, 2, 2, 2], [15, 15], [1])
STYLES["a5_s3_pi00_91_s"] = ringfill([2, 2, 2, 2, 2, 2], [15], [])
STYLES["a5_s3_sav00_0"] = ringfill([15, 13, 12, 10, 10, 10], [1, 1], [1, 1, 1])
STYLES["a5_s3_sav00_0_s"] = ringfill([15, 13, 12, 10, 10, 10], [1], [])
STYLES["a5_s3_sav00_3"] = ringfill([14, 14, 13, 13, 10, 10], [1, 1, 15], [4, 4, 7])
STYLES["a5_s3_sav00_3_s"] = ringfill([14, 14, 13, 13, 10, 10], [1], [])
STYLES["a5_s3_sav00_4"] = ringfill([15, 14, 12, 12, 11, 11], [1, 1, 15], [6, 6, 10])
STYLES["a5_s3_sav00_4_s"] = ringfill([15, 14, 12, 12, 11, 11], [1], [])
STYLES["a5_s3_syp00_25"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [5, 2])
STYLES["a5_s3_syp00_25_s"] = ringfill([15, 15, 15, 15, 15, 15], [7], [])
STYLES["a5_s3_syp00_39"] = ringfill([15, 15, 15, 15, 15, 15], [9, 6], [3, 1])
STYLES["a5_s3_syp00_39_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [])
STYLES["a5_s3_syp00_41"] = ringfill([15, 15, 15, 15, 15, 15], [9, 6], [3, 1])
STYLES["a5_s3_syp00_41_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [])
STYLES["a5_s3_syp00_54"] = ringfill([15, 15, 15, 15, 15, 15], [9, 6], [3, 1])
STYLES["a5_s3_syp00_54_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [])
STYLES["a5_s3_syp00_55"] = ringfill([15, 15, 15, 15, 15, 15], [9, 6], [3, 1])
STYLES["a5_s3_syp00_55_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [])
STYLES["a5_s3_syp00_57"] = ringfill([15, 15, 15, 15, 15, 15], [9, 6], [3, 1])
STYLES["a5_s3_syp00_57_s"] = ringfill([15, 15, 15, 15, 15, 15], [9], [])
STYLES["a5_s3_sys00_29"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["a5_s3_sys00_29_s"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["a5_s3_sys00_64"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15, 14])
STYLES["a5_s3_sys00_64_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_sys00_65"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15, 12])
STYLES["a5_s3_sys00_65_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_sys00_66"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [10, 15, 13])
STYLES["a5_s3_sys00_66_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_sys00_67"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [13, 12])
STYLES["a5_s3_sys00_67_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_sys00_68"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15, 9])
STYLES["a5_s3_sys00_68_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_sys00_69"] = ringfill([7, 1, 1, 1, 1, 15], [8, 8], [])
STYLES["a5_s3_sys00_69_s"] = ringfill([7, 1, 1, 1, 1, 15], [8], [])
STYLES["a5_s3_sys00_70"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8], [15, 9])
STYLES["a5_s3_sys00_70_s"] = ringfill([1, 1, 1, 1, 1, 1], [8], [])
STYLES["a5_s3_sys00_71"] = ringfill([7, 1, 1, 1, 1, 15], [8, 8], [])
STYLES["a5_s3_sys00_71_s"] = ringfill([7, 1, 1, 1, 1, 15], [8], [])
STYLES["a5_x2_asa16_1"] = ringfill([3, 4, 6, 7, 3, 3], [15, 15, 2], [])
STYLES["a5_x2_asa16_1_s"] = ringfill([3, 4, 6, 7, 3, 3], [15], [])
STYLES["a5_y9_hiz_0"] = ringfill([10, 10, 10, 15, 15, 15], [9, 4, 3], [1])
STYLES["a5_y9_hiz_0_s"] = ringfill([10, 10, 10, 15, 15, 15], [9], [])

def twotone(left, right):
    """Two words in two colours: the ink is cut at its widest empty column run (the space) and each half gets its own style."""
    import numpy as np

    def style(ink, base):
        occ = ink.any(0)
        best, run, start = (0, None), 0, None
        xs = np.nonzero(occ)[0]
        for x in range(int(xs.min()), int(xs.max()) + 1):
            if not occ[x]:
                if run == 0: start = x
                run += 1
                if run > best[0]: best = (run, start)
            else:
                run = 0
        if best[1] is None:
            return left(ink, base)
        g0, g1 = best[1], best[1] + best[0]
        la, lb = left(ink[:, :g0], base)
        ra, rb = right(ink[:, g1:], base)
        gap = max(1, best[0] - 3)
        top = max(lb, rb)
        H = max(top - lb + la.shape[0], top - rb + ra.shape[0])
        out = np.zeros((H, la.shape[1] + gap + ra.shape[1]), np.uint8)
        out[top - lb:top - lb + la.shape[0], :la.shape[1]] = la
        sub = out[top - rb:top - rb + ra.shape[0], la.shape[1] + gap:]
        sub[ra > 0] = ra[ra > 0]
        return out, top
    return style


# g3_jun 05 / 07: the Japanese is two words in two colours (blue / gold, pink / gold), white rings, navy ring, teal shadow
_TT05 = (ringfill([7, 8, 9, 9, 10, 10], [6, 6, 14], [11, 11, 11]), ringfill([1, 1, 2, 2, 3, 3], [6, 6, 14], [11, 11, 11]))
_TT05S = (ringfill([7, 8, 9, 9, 10, 10], [6], [11]), ringfill([1, 1, 2, 2, 3, 3], [6], [11]))
_TT07 = (ringfill([7, 6, 6, 5, 5, 5], [12, 12, 1], [15, 15, 15]), ringfill([10, 9, 9, 9, 8, 8], [12, 12, 1], [15, 15, 15]))
_TT07S = (ringfill([7, 6, 6, 5, 5, 5], [12], [15]), ringfill([10, 9, 9, 9, 8, 8], [12], [15]))
STYLES["a5_g3_jun_tt05"] = twotone(*_TT05)
STYLES["a5_g3_jun_tt05_s"] = twotone(*_TT05S)
STYLES["a5_g3_jun_tt07"] = twotone(*_TT07)
STYLES["a5_g3_jun_tt07_s"] = twotone(*_TT07S)


# ---- pn_trade.arc, gdt_pn.arc, pnbg_sum.arc, pnbg_fal.arc (trades, season summary) -----------------------------------

# ---- g3_ptf_0 (plain black / red lettering on a light plate, no ring) -------------------------------------------------
STYLES["a6_ptf_black"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)       # pal 121: index 1 = black
STYLES["a6_ptf_red"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)         # pal 122: index 1 = red

# ---- g3_ptk_0 (cyan-white letters, azure and blue rings, dark blue shadow) --------------------------------------------
STYLES["a6_ptk_item"] = ringfill([15, 14, 13, 12, 11, 10], [7, 3], [1, 1])      # pal 101
STYLES["a6_ptk_any"] = ringfill([15, 14, 13, 12, 11, 10], [5, 3], [1, 1])       # pal 100: pink-white, purple rings
STYLES["a6_ptk_help"] = ringfill([12, 12, 11, 11, 10, 10], [1, 4], [6])        # pal 131: purple letters, white ring
STYLES["a6_ptk_big"] = ringfill([1, 1, 1, 1, 1, 1], [10, 10, 10, 10])    # 1/1 votes, e.g. pn_trade g3_ptk_0 20

# ---- g3_pt_0 ------------------------------------------------------------------------------------------------------------
STYLES["a6_head_green"] = ringfill([8, 9, 10, 11, 13, 15], [5, 2], [])                 # pal 97: lime letters, blue ring (headings 08, 09)
STYLES["a6_pt_title"] = ringfill([1, 1, 1, 1, 1, 1], [5, 5, 5])    # 4/4 votes, e.g. pn_trade g3_pt_0 3f
STYLES["a6_tab"] = ringfill([1, 1, 2, 2, 3, 3], [8, 9], [11, 13])                       # tabs and column headings: dark letters, white ring
STYLES["a6_btn_white"] = ringfill([1, 1, 1, 1, 1, 1], [4, 14], [7])                    # pal 57: white letters
STYLES["a6_btn_navy"] = ringfill([2, 2, 2, 2, 2, 2], [1, 11], [7])                     # pal 55 / 39 family: navy letters, white ring
STYLES["a6_btn_purple"] = ringfill([6, 6, 6, 6, 6, 6], [1, 14], [7])                   # pal 42
STYLES["a6_btn_olive"] = ringfill([15, 14, 14, 13, 13, 12], [1, 2], [8, 4])            # pal 38
STYLES["a6_btn_green"] = ringfill([3, 3, 3, 8, 8, 8], [1, 14], [7])                    # pal 58: green letters
STYLES["a6_btn_crimson"] = ringfill([6, 6, 6, 6, 6, 6], [1, 14], [7])                  # pal 58: crimson letters
STYLES["a6_btn_brown"] = ringfill([5, 5, 5, 5, 5, 5], [1, 14], [7])                    # pal 39
STYLES["a6_pt_out"] = ringfill([1, 1, 1, 2, 2, 2], [11, 13], [15])                      # pal 99: "'s Outgoing Players"
STYLES["a6_banner"] = ringfill([12, 12, 13, 13, 14, 14], [3, 10, 8], [2, 1])              # pal 103: "No trade requests pending!"
STYLES["a6_empty"] = ringfill([8, 8, 8, 8, 8, 8], [11, 11, 11, 11])    # 1/1 votes, e.g. pn_trade g3_pt_0 66
STYLES["a6_noplayers"] = ringfill([4, 4, 5, 5, 6, 6], [3], [])                          # pal 110: "No Players"

# ---- g3_pts_0 -----------------------------------------------------------------------------------------------------------
STYLES["a6_pts_head"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 3/6 votes, e.g. pn_trade g3_pts_0 09

# ---- h3_ydm_0 (gdt_pn.arc) ----------------------------------------------------------------------------------------------
STYLES["a6_ydm_item"] = ringfill([15, 15, 15, 15, 15, 14], [2])                    # pal 4: white letters, one blue ring


K = 60                                          # the baseline row every whole-rectangle style below returns (the label sets it too)


def _win(full, c0, c1):
    return full[:, c0:c1], K


def _flat_bg(inner, bg, H, W, window, vcentre=None):
    """Lettering on a flat opaque rectangle (the logo banners): the art is centred on an H x W canvas of palette index `bg`."""
    def style(ink, base):
        art, b = inner(ink, base)
        full = np.full((H, W), bg, np.uint8)
        h, w = art.shape
        top = (H - h) // 2 if vcentre is None else vcentre - h // 2
        left = (W - w) // 2
        sub = full[top:top + h, left:left + w]
        sub[art > 0] = art[art > 0]
        return _win(full, *window)
    return style


# ---- pnbg_sum.arc / pnbg_fal.arc: the "Pennant Race" logos (white banner, pale ring round white letters) -------------------
_LOGO = ringfill([15, 15, 15, 15, 15, 15], [8, 6, 4, 3])
for _name, _W in (("a6_pbg2", 176), ("a6_pbg3", 184)):
    STYLES[_name] = _flat_bg(_LOGO, 15, 48, _W, (0, _W))
for _c0, _c1 in ((0, 32), (32, 120), (120, 176)):
    STYLES["a6_pbg2~%d_%d" % (_c0, _c1)] = _flat_bg(_LOGO, 15, 48, 176, (_c0, _c1))
for _c0, _c1 in ((0, 128), (128, 184)):
    STYLES["a6_pbg3~%d_%d" % (_c0, _c1)] = _flat_bg(_LOGO, 15, 48, 184, (_c0, _c1))

# ---- g3_pts_0 sprite 01: the "Trade Request" strip (white letters on the brown paper strip) ---------------------------------
_TITLE_INK = ringfill([15, 15, 15, 15, 15, 15], [2])
_strip_cache = []


def _strip():
    """The original 48 x 176 strip (three page rectangles side by side) with the Japanese letters painted out."""
    if _strip_cache:
        return _strip_cache[0].copy()
    pg = _orig_page("pn_trade.arc", "g3_pts_0", 1)
    S = np.hstack([pg[32:80, 16:56], pg[80:128, 16:112], pg[32:80, 72:112]]).astype(np.uint8)
    mask = np.zeros(S.shape, bool)
    mask[6:36, 6:170] = S[6:36, 6:170] >= 11
    grow_ = mask.copy()
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            grow_ |= np.roll(np.roll(mask, dy, 0), dx, 1)
    mask = grow_ & (np.arange(48)[:, None] >= 5) & (np.arange(48)[:, None] < 38)
    out = S.copy()
    H, W = S.shape
    for x in range(W):
        for y in np.nonzero(mask[:, x])[0]:
            up = next((y - d for d in range(1, 30) if y - d >= 3 and not mask[y - d, x]), None)
            dn = next((y + d for d in range(1, 30) if y + d < 42 and not mask[y + d, x]), None)
            src = up if (dn is None or (up is not None and (y - up) <= (dn - y))) else dn
            out[y, x] = S[src, min(max(x + ((y - src) // 3), 4), 168)] if src is not None else S[y, x]
    _strip_cache.append(out)
    return out.copy()


def _title_strip(window):
    def style(ink, base):
        art, b = _TITLE_INK(ink, base)
        full = _strip()
        h, w = art.shape
        top = 21 - h // 2
        left = 88 - w // 2
        sub = full[top:top + h, left:left + w]
        sub[art > 0] = art[art > 0]
        return _win(full, *window)
    return style


for _c0, _c1 in ((0, 40), (40, 136), (136, 176)):
    STYLES["a6_pts_title~%d_%d" % (_c0, _c1)] = _title_strip((_c0, _c1))

# ---- g3_pts_0 sprite 0e: the red approval stamp, re-drawn as a ring round red "OK" ------------------------------------------
_STAMP_INK = ringfill([1, 1, 1, 2, 2, 3], [15])


def _stamp(ink, base):
    art, b = _STAMP_INK(ink, base)
    full = np.zeros((80, 80), np.uint8)
    ring = {35: 15, 34: 15, 33: 1, 32: 1, 31: 1, 30: 1, 29: 14, 28: 15}      # radial profile read from the top of the original
    for y in range(80):
        for x in range(80):
            r = ((y - 39.5) ** 2 + (x - 39.5) ** 2) ** 0.5
            full[y, x] = ring.get(int(r), 0)
    h, w = art.shape
    top = 40 - h // 2
    left = 40 - w // 2
    sub = full[top:top + h, left:left + w]
    sub[art > 0] = art[art > 0]
    return full, K


STYLES["a6_pts_stamp"] = _stamp

STYLES["a6_ydm_gold"] = ringfill([11, 10, 9, 5, 4, 3], [2, 13], [15, 15])                # pal 7: gold calligraphy, brown ring, white, lilac shadow

STYLES["a6_pbg_ink"] = _LOGO


# ---- pn_gaijn.arc, gdt_npn.arc (foreign players) ---------------------------------------------------------------------

STYLES["b6_g3_pg_0_128"] = ringfill([15, 15, 14, 14, 13, 13], [10, 3, 1], [8, 8])
STYLES["b6_g3_pg_0_128_s"] = ringfill([15, 15, 14, 14, 13, 13], [10], [])
STYLES["b6_g3_pg_0_129"] = ringfill([11, 11, 11, 11, 11, 11], [5, 2], [5, 13])    # 1/2 votes, e.g. pn_gaijn g3_pg_0 0d
STYLES["b6_g3_pg_0_129_s"] = ringfill([15, 14, 14, 13, 12, 12], [5], [])
STYLES["b6_g3_pg_0_130"] = ringfill([14, 14, 13, 13, 12, 12], [2], [])
STYLES["b6_g3_pg_0_130_s"] = ringfill([14, 14, 13, 13, 12, 12], [2], [])
STYLES["b6_g3_pg_0_133"] = flat([0, 4, 4, 4, 4, 4, 4], cut=3)
STYLES["b6_g3_pg_0_133_s"] = flat([0, 4, 4, 4, 4, 4, 4], cut=3)
STYLES["b6_g3_pg_0_134"] = ringfill([1, 1, 1, 1, 1, 1], [9, 10, 10])    # 1/1 votes, e.g. pn_gaijn g3_pg_0 28
STYLES["b6_g3_pg_0_134_s"] = ringfill([13, 13, 12, 12, 11, 11], [10], [])
STYLES["b6_g3_pg_0_153"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. pn_gaijn g3_pg_0 29
STYLES["b6_g3_pg_0_153_s"] = ringfill([1, 1, 1, 1, 1, 1], [11], [])
STYLES["b6_g3_pg_0_40"] = ringfill([15, 15, 15, 15, 15, 15], [2, 8], [])
STYLES["b6_g3_pg_0_40_s"] = ringfill([15, 15, 15, 15, 15, 15], [2], [])
STYLES["b6_g3_pg_0_42"] = ringfill([6, 6, 6, 6, 6, 6], [1, 7], [])
STYLES["b6_g3_pg_0_42_s"] = ringfill([6, 6, 6, 6, 6, 6], [1], [])
STYLES["b6_g3_pg_0_55"] = ringfill([4, 4, 4, 4, 4, 4], [1, 7], [])
STYLES["b6_g3_pg_0_55_s"] = ringfill([4, 4, 4, 4, 4, 4], [1], [])
STYLES["b6_g3_pg_0_58"] = ringfill([3, 3, 3, 3, 3, 3], [1, 7], [])
STYLES["b6_g3_pg_0_58_s"] = ringfill([3, 3, 3, 3, 3, 3], [1], [])
STYLES["b6_g3_pgy_0_148"] = ringfill([15, 1, 1, 1, 1, 1, 1, 1], [1], [7])
STYLES["b6_g3_pgy_0_148_s"] = ringfill([15, 1, 1, 1, 1, 1, 1, 1], [1], [])
STYLES["b6_g3_pgy_0_149"] = ringfill([4, 4, 4, 4, 4, 4, 4, 4], [11], [])
STYLES["b6_g3_pgy_0_149_s"] = ringfill([4, 4, 4, 4, 4, 4, 4, 4], [11], [])
STYLES["b6_g3_pgy_0_150"] = ringfill([13, 13, 13, 13, 13, 13], [4], [7])
STYLES["b6_g3_pgy_0_150_s"] = ringfill([13, 13, 13, 13, 13, 13], [4], [])
STYLES["b6_m3_ks_0_14"] = ringfill([15, 15, 15, 15, 15, 15], [4, 6], [])
STYLES["b6_m3_ks_0_14_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["b6_m3_ks_0_24"] = ringfill([15, 15, 15, 15, 15, 15], [4, 6], [])
STYLES["b6_m3_ks_0_24_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["b6_m3_ks_0_25"] = ringfill([15, 15, 15, 15, 15, 15], [4, 6], [])
STYLES["b6_m3_ks_0_25_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["b6_m3_ks_0_26"] = ringfill([15, 15, 15, 15, 15, 15], [4, 6], [])
STYLES["b6_m3_ks_0_26_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["b6_m3_ks_0_27"] = ringfill([15, 15, 15, 15, 15, 15], [4, 6], [])
STYLES["b6_m3_ks_0_27_s"] = ringfill([15, 15, 15, 15, 15, 15], [4], [])
STYLES["b6_m3c_kss_0_14"] = ringfill([15, 15, 15, 15, 15, 15], [5, 4], [2, 1])
STYLES["b6_m3c_kss_0_14_s"] = ringfill([15, 15, 15, 15, 15, 15], [5], [])
STYLES["b6_m3c_kss_0_30"] = ringfill([15, 15, 15, 15, 15, 15], [12], [])
STYLES["b6_m3c_kss_0_30_s"] = ringfill([15, 15, 15, 15, 15, 15], [12], [])
STYLES["b6_m3c_kss_0_31"] = ringfill([15, 15, 15, 15, 15, 15], [12], [])
STYLES["b6_m3c_kss_0_31_s"] = ringfill([15, 15, 15, 15, 15, 15], [12], [])
STYLES["b6_m3c_kss_0_42"] = ringfill([14, 15, 15, 15, 15, 15], [6, 4], [])
STYLES["b6_m3c_kss_0_42_s"] = ringfill([14, 15, 15, 15, 15, 15], [6], [])
STYLES["b6_m3c_kss_0_45"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)
STYLES["b6_m3c_kss_0_45_s"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)
STYLES["b6_m3c_kss_0_46"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)
STYLES["b6_m3c_kss_0_46_s"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)
STYLES["b6_m3c_kss_0_47"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)
STYLES["b6_m3c_kss_0_47_s"] = flat([0, 15, 15, 15, 15, 15, 15], cut=3)

# paper title band (g3_pgy_0 sprite 01): textured band 164x40, letters drawn on it
STYLES["b6_pt"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1], [])
def _paper(letter_style, lo, hi, W=164, H=40, keep=[8, 9], prob=[np.float64(0.376), np.float64(0.624)]):
    def style(ink, base):
        art, b = letter_style(ink, base)
        h, w = art.shape
        rs = np.random.RandomState(5)
        out = np.array(keep, np.uint8)[rs.choice(len(keep), size=(H, W), p=prob)]
        ty, tx = (H - h) // 2, (W - w) // 2
        sub = out[ty:ty + h, tx:tx + w]
        sub[art > 0] = art[art > 0]
        return out[:, lo:hi], ty + b
    return style
STYLES["b6_paper_L"] = _paper(STYLES["b6_pt"], 0, 110)
STYLES["b6_paper_R"] = _paper(STYLES["b6_pt"], 110, 164)


# round position badges (gdt_npn.arc m3_ks_0 35-3f, 93): the plate of sprite 37 without its bar, the English letters drawn on it
_BADGE = np.array([[int(ch, 16) for ch in row] for row in ['00000eeeeeeeeeeee000000', '000eeeccccccccccddd0000', '00eeccaaaaaaaaaaccdd000', '0eecaaaaaaaaaaaaaacdd00', '0ecaabbbbbbbbbbbbaacc00', 'eecabbccccccccccbbacbb0', 'eeabccccccccccccccbabb0', 'eebbccccccccccccccbabb2', 'eebccccccccccccccccbbb2', 'ddbccccccccccccccccbbb2', 'ddbcccccccccccccccccaa2', 'ddacccccccccccccccccaa2', 'ddbccccccccccccccccaaa2', 'ccbccccccccccccccccaaa2', 'ccbccccccccccccccccaaa2', 'ccbccccccccccccccccaaa2', 'cccccccccccccccccccaaa2', 'cccccccccccccccccccc992', 'bbcccccccccccccccccc992', 'bbcccccccccccccccccc992', 'bbcccccccccccccccccc992', 'bbcccccccccccccccccd992', 'aacccccccccccccccccd992', '0accccccccccccccccdb922', '0aaccccccccccdddeeb9922', '00aacddddeeeeeecb999220', '002aaa99999999999992220', '00022999999999999222200', '00002222222222222222000', '00000022222222222200000']], np.uint8)
# letters: white with a light top edge, one dark ring, a shadow
STYLES["b6_bl"] = ringfill([13, 15, 15, 15, 15, 15], [4], [])
def _plate(letter_style, cx=10, cy=14):
    def style(ink, base):
        art, b = letter_style(ink, base)
        h, w = art.shape
        out = _BADGE.copy()
        ty, tx = cy - h // 2, cx - w // 2
        sub = out[ty:ty + h, tx:tx + w]
        sub[art > 0] = art[art > 0]
        return out, ty + b
    return style
STYLES["b6_badge"] = _plate(STYLES["b6_bl"])


# ---- pn_fa.arc, pn_tgrow.arc -----------------------------------------------------------------------------------------

# ---- pn_fa.arc g3_fa_0 ---------------------------------------------------------------------------------------------
STYLES["d6_title"] = ringfill([2, 2, 2, 2, 2, 2], [9, 11, 11])    # 2/3 votes, e.g. pn_fa g3_fa_0 01
STYLES["d6_b09"] = ringfill([14, 15, 15, 15, 15, 15], [2], [6])               # pal 40: dark red letters, white ring
STYLES["d6_b0a"] = ringfill([14, 15, 15, 15, 15, 15], [9], [8])               # pal 38: brown letters
STYLES["d6_b0b"] = ringfill([14, 14, 13, 13, 14, 14], [9], [3])               # pal 54: purple letters, white ring
STYLES["d6_b0c"] = ringfill([14, 15, 15, 15, 15, 15], [1], [8])               # pal 56: green letters


def _neg(inner, rows=(6, 30), cols=(4, 26)):
    """The green box of g3_fa_0 sprite 22 (page 6, rect 96,96,128,128), its face cleaned of the kanji, with `inner`'s lettering on it."""
    def style(ink, base):
        art, b = inner(ink, base)
        plate = _orig_page("pn_fa.arc", "g3_fa_0", 6)[96:128, 96:128].astype(np.uint8).copy()
        plate[3:29, 4:26] = 12                                   # the green ring, filled
        h, w = art.shape
        ox, oy = cols[0] + (cols[1] - cols[0] - w) // 2, rows[0] + (rows[1] - rows[0] - h) // 2
        ys, xs = np.nonzero(art)
        for y, x in zip(ys, xs):
            if 0 <= oy + y < 32 and 0 <= ox + x < 32:
                plate[oy + y, ox + x] = art[y, x]
        return plate, oy + b
    return style


STYLES["d6_neg"] = _neg(ringfill([8, 8, 7, 7, 6, 6], [11], []))             # pal 197: teal letters on the green box
STYLES["d6_teal"] = ringfill([5, 5, 4, 4, 3, 3], [8], [1])                    # pal 70: teal letters, white ring
STYLES["d6_wn212"] = ringfill([15, 15, 14, 14, 13, 13], [7], [8])             # pal 212: white letters, navy ring
STYLES["d6_wn216"] = ringfill([15, 15, 15, 15, 14, 14], [9], [8, 8])          # pal 216: white letters, navy ring
STYLES["d6_wn213"] = ringfill([15, 15, 14, 14, 13, 13], [8], [9])             # pal 213: stat headers
STYLES["d6_pale"] = ringfill([9, 9, 9, 5, 5, 5], [1])                         # pal 220: pale blue letters on grey
STYLES["d6_olive"] = ringfill([14, 13, 12, 11, 10, 9], [6, 4], [3])           # pal 209: olive-gold
STYLES["d6_navy"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)                        # pal 215: navy letters on a white plate
STYLES["d6_cyan"] = ringfill([8, 8, 8, 8, 8, 8], [10, 1])    # 1/1 votes, e.g. pn_fa g3_fa_0 9d

# ---- pn_fa.arc w5_fa / w5_faz ----------------------------------------------------------------------------------------
STYLES["d6_w_b4"] = ringfill([14, 15, 15, 15, 15, 15], [9], [3, 3])           # pal 4: crimson letters, white ring, blue shadow
STYLES["d6_w_b7"] = ringfill([14, 15, 15, 15, 15, 15], [9], [3, 3])           # pal 7: purple (same ramp numbers, other palette)
STYLES["d6_w_b8"] = ringfill([14, 15, 15, 15, 15, 15], [9], [3, 3])           # pal 8: violet-blue
STYLES["d6_w_title"] = ringfill([12, 12, 13, 13, 14, 14], [3], [1])           # pal 22: lavender-white letters, violet ring
STYLES["d6_w_sal"] = ringfill([15, 15, 14, 14, 13, 13], [3], [1])             # pal 19: white letters, navy ring
STYLES["d6_w_sent"] = ringfill([15, 14, 14, 13, 13, 13], [3], [1])            # pal 26: the sentence, blue ring

# ---- pn_tgrow.arc -------------------------------------------------------------------------------------------------------
# the title banks (s3_phd01, s3_pnd01) draw their 4-bit pages with colour tables the game fills in itself, so the styles are
# read from the art's palette indices: ramp top to foot, rings inside out, shadow
STYLES["d6_ph"] = None         # palette 58 (phd01 all, pnd01 07 08)
STYLES["d6_pn"] = None                  # palette 126 (pnd01)


def padded(inner, n=3):
    """`inner` with n clear rows / columns round it (a plate colour margin where index 0 is drawn)."""
    def style(ink, base):
        art, b = inner(ink, base)
        return np.pad(art, n), b + n
    return style


STYLES["d6_zi"] = ui_type.logo(**{'fill': [51, 207, 186, 173, 139, 51], 'outline': 1, 'white': 255, 'rim': 42, 'shadow': [42, 42], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d6_faz"] = ui_type.logo(**{'fill': [160, 163, 171, 172, 175, 183], 'outline': 52, 'white': 207, 'rim': 62, 'shadow': [62, 62, 62], 'soft': [], 'thick': 2, 'band': 2})
STYLES["d6_zi_item"] = ringfill([15, 15, 14, 14, 13, 12], [7, 6], [])         # pal 13: white letters, black ring
STYLES["d6_zi_head"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)                 # pal 4: navy letters, light shadow (heading in the panel)
STYLES["d6_zi_dt"] = ringfill([15, 15, 15, 14, 14, 14], [3], [1])             # pal 7: dialog title, white letters
STYLES["d6_zi_blue"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)                     # pal 5: blue letters on the white dialog

STYLES["d6_ph"] = padded(ringfill([3, 10, 9, 7, 6, 6], [13, 12, 12], [1, 1]))
STYLES["d6_pn"] = padded(ringfill([14, 14, 13, 11, 10, 5], [1], []))
STYLES["d6_zi"] = padded(STYLES["d6_zi"])
STYLES["d6_faz"] = padded(STYLES["d6_faz"])
