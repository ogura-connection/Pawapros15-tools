"""Label styles of art run 10, agent E. Read from the Japanese lettering by
run10/E/c6_lib.py; every style is crisp (solid rings, fill ramps only). _s = small plates (one ring)."""
import numpy as np
from .ui_styles_ore_ini import ringfill

STYLES = {}

def _win(style, c0, c1):
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut

def _sil(front, c):
    def style(ink, base):
        out, b = STYLES[front](ink, base)
        return np.where(out > 0, c, 0).astype(np.uint8), b
    return style

from pp15.art import typeset as ui_type


def _row(items):
    def style(ink, base):
        arts = []
        for t, f, x, c0, c1, sn in items:
            a, b = STYLES[sn](*ui_type.typeset(t, f))
            arts.append((a[:, c0:c1], b, x))
        mb = max(b for _, b, _ in arts)
        H = max(mb - b + a.shape[0] for a, b, _ in arts)
        W = max(x + a.shape[1] for a, _, x in arts)
        out = np.zeros((H, W), np.uint8)
        for a, b, x in arts:
            y = mb - b
            sub = out[y:y + a.shape[0], x:x + a.shape[1]]
            sub[a > 0] = a[a > 0]
        return out, mb
    return style

STYLES["e10_h3_stp_0_00_h"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1, 11, 4, 4], [])
STYLES["e10_h3_stp_0_00_h_m"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1], [])
STYLES["e10_h3_stp_0_00_h_s"] = ringfill([15, 15, 14, 14, 13, 13], [1], [])
STYLES["e10_h3_stp_0_01_h"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1, 11, 4, 4], [])
STYLES["e10_h3_stp_0_01_h_m"] = ringfill([15, 15, 14, 14, 13, 13], [1, 1], [])
STYLES["e10_h3_stp_0_01_h_s"] = ringfill([15, 15, 14, 14, 13, 13], [1], [])
STYLES["e10_r3_tvs_13_h"] = ringfill([9, 9, 10, 11, 12, 13, 14, 14], [1, 1, 9, 5], [])
STYLES["e10_r3_tvs_13_h_m"] = ringfill([9, 9, 10, 11, 12, 13, 14, 14], [1, 1], [])
STYLES["e10_r3_tvs_13_h_s"] = ringfill([9, 9, 10, 11, 12, 13, 14, 14], [1], [])
STYLES["e10_r3_tvsx_09_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_09_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_09_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0a_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_0a_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0a_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0b_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_0b_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0b_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0c_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_0c_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0c_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0d_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_0d_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0d_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0e_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_0e_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0e_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_0f_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_0f_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_0f_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_r3_tvsx_10_h"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80, 157, 157], [])
STYLES["e10_r3_tvsx_10_h_m"] = ringfill([230, 230, 224, 216, 207, 207], [80, 80], [])
STYLES["e10_r3_tvsx_10_h_s"] = ringfill([230, 230, 224, 216, 207, 207], [80], [])
STYLES["e10_stp_00"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_00_m"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_00_s"] = ringfill([15, 15, 14, 13, 12, 1], [1], [])
STYLES["e10_stp_01"] = ringfill([1, 10, 11, 1, 13, 4], [7], [7, 7, 7])
STYLES["e10_stp_01_m"] = ringfill([1, 10, 11, 1, 13, 4], [7], [])
STYLES["e10_stp_01_s"] = ringfill([1, 10, 11, 1, 13, 4], [7], [])
STYLES["e10_tse_blue"] = ringfill([8, 9, 10, 11, 12, 13], [5, 5], [])
STYLES["e10_tse_blue_m"] = ringfill([8, 9, 10, 11, 12, 13], [5, 5], [])
STYLES["e10_tse_blue_s"] = ringfill([8, 9, 10, 11, 12, 13], [5], [])
STYLES["e10_tse_white"] = ringfill([1, 1, 1, 1, 1, 1], [15], [])
STYLES["e10_tse_white_m"] = ringfill([1, 1, 1, 1, 1, 1], [15], [])
STYLES["e10_tse_white_s"] = ringfill([1, 1, 1, 1, 1, 1], [15], [])
STYLES["e10_tvs_14s"] = _sil("e10_r3_tvs_13_h", 1)
STYLES["e10_tvs_14s_m"] = _sil("e10_r3_tvs_13_h_m", 1)
STYLES["e10_tvs_14s_s"] = _sil("e10_r3_tvs_13_h_s", 1)
STYLES["e10_row_p3r0"] = _row([('Auto', 'ttf:narrow:16:0.0:1.0:0.25', 6, 0, 47, 'e10_tse_blue'), ('Normal', 'ttf:narrow:15:0.0:0.85:0.25', 69, 0, 54, 'e10_tse_blue')])
STYLES["e10_row_p3r1"] = _row([('Sweet Spot', 'ttf:narrow:9:0.0:0.85:0.25', 2, 0, 52, 'e10_tse_blue'), ('Show', 'ttf:narrow:16:0.0:0.92:0.25', 62, 0, 49, 'e10_tse_blue')])
STYLES["e10_row_p3r2"] = _row([('Manual', 'ttf:rounded:16:0.0:1.0:0.25', 8, 0, 77, 'e10_tse_blue')])
STYLES["e10_row_p3r3"] = _row([('Hide', 'ttf:rounded:16:0.0:1.0:0.25', 15, 0, 50, 'e10_tse_blue'), ('Show', 'ttf:narrow:15:0.0:0.85:0.25', 83, 0, 44, 'e10_tse_blue')])
STYLES["e10_row_p3r4"] = _row([('Running', 'ttf:narrow:10:0.0:0.85:0.42', 1, 0, 31, 'e10_tse_white'), ('Running', 'ttf:narrow:10:0.0:0.85:0.42', 40, 31, 42, 'e10_tse_white'), ('Fielding', 'ttf:narrow:11:0.0:0.85:0.42', 54, 0, 44, 'e10_tse_white'), ('Bat', 'ttf:narrow:12:0.0:0.85:0.42', 104, 0, 22, 'e10_tse_white')])
STYLES["e10_row_p4r0"] = _row([('Contact Cursor', 'ttf:narrow:10:0.0:0.85:0.42', 5, 0, 74, 'e10_tse_white'), ('ting', 'ttf:narrow:8:0.0:0.85:0.42', 94, 0, 17, 'e10_tse_white')])
STYLES["e10_row_p4r1"] = _row([('Landing Spot', 'ttf:narrow:11:0.0:0.85:0.42', 2, 0, 72, 'e10_tse_white'), ('Pitch', 'ttf:narrow:10:0.0:0.85:0.42', 95, 0, 26, 'e10_tse_white')])
STYLES["e10_row_p4r2"] = _row([('Strike Zone', 'ttf:narrow:13:0.0:0.85:0.42', 8, 0, 72, 'e10_tse_white'), ('ing', 'ttf:narrow:14:0.0:0.85:0.42', 97, 0, 22, 'e10_tse_white')])
STYLES["e10_row_p4r3"] = _row([('Pitch Guide', 'ttf:narrow:11:0.0:0.85:0.42', 1, 0, 62, 'e10_tse_white'), ('Mana', 'ttf:narrow:9:0.0:0.85:0.42', 95, 0, 26, 'e10_tse_white')])
STYLES["e10_row_p4r4"] = _row([('Pitch Cursor', 'ttf:narrow:15:0.0:0.85:0.42', 1, 0, 90, 'e10_tse_white')])
STYLES["e10_row_p3r0~69_80"] = _win(STYLES["e10_row_p3r0"], 69, 80)
STYLES["e10_row_p3r0~6_53"] = _win(STYLES["e10_row_p3r0"], 6, 53)
STYLES["e10_row_p3r0~70_80"] = _win(STYLES["e10_row_p3r0"], 70, 80)
STYLES["e10_row_p3r0~80_121"] = _win(STYLES["e10_row_p3r0"], 80, 121)
STYLES["e10_row_p3r0~80_123"] = _win(STYLES["e10_row_p3r0"], 80, 123)
STYLES["e10_row_p3r0~8_49"] = _win(STYLES["e10_row_p3r0"], 8, 49)
STYLES["e10_row_p3r1~2_54"] = _win(STYLES["e10_row_p3r1"], 2, 54)
STYLES["e10_row_p3r1~62_111"] = _win(STYLES["e10_row_p3r1"], 62, 111)
STYLES["e10_row_p3r1~66_107"] = _win(STYLES["e10_row_p3r1"], 66, 107)
STYLES["e10_row_p3r2~18_56"] = _win(STYLES["e10_row_p3r2"], 18, 56)
STYLES["e10_row_p3r2~56_76"] = _win(STYLES["e10_row_p3r2"], 56, 76)
STYLES["e10_row_p3r2~56_85"] = _win(STYLES["e10_row_p3r2"], 56, 85)
STYLES["e10_row_p3r2~8_56"] = _win(STYLES["e10_row_p3r2"], 8, 56)
STYLES["e10_row_p3r3~15_56"] = _win(STYLES["e10_row_p3r3"], 15, 56)
STYLES["e10_row_p3r3~20_56"] = _win(STYLES["e10_row_p3r3"], 20, 56)
STYLES["e10_row_p3r3~56_125"] = _win(STYLES["e10_row_p3r3"], 56, 125)
STYLES["e10_row_p3r3~56_127"] = _win(STYLES["e10_row_p3r3"], 56, 127)
STYLES["e10_row_p3r4~1_32"] = _win(STYLES["e10_row_p3r4"], 1, 32)
STYLES["e10_row_p3r4~40_126"] = _win(STYLES["e10_row_p3r4"], 40, 126)
STYLES["e10_row_p4r0~5_79"] = _win(STYLES["e10_row_p4r0"], 5, 79)
STYLES["e10_row_p4r0~94_111"] = _win(STYLES["e10_row_p4r0"], 94, 111)
STYLES["e10_row_p4r1~2_74"] = _win(STYLES["e10_row_p4r1"], 2, 74)
STYLES["e10_row_p4r1~95_121"] = _win(STYLES["e10_row_p4r1"], 95, 121)
STYLES["e10_row_p4r2~6_80"] = _win(STYLES["e10_row_p4r2"], 6, 80)
STYLES["e10_row_p4r2~80_119"] = _win(STYLES["e10_row_p4r2"], 80, 119)
STYLES["e10_row_p4r2~8_80"] = _win(STYLES["e10_row_p4r2"], 8, 80)
STYLES["e10_row_p4r2~97_119"] = _win(STYLES["e10_row_p4r2"], 97, 119)
STYLES["e10_row_p4r3~1_63"] = _win(STYLES["e10_row_p4r3"], 1, 63)
STYLES["e10_row_p4r3~95_121"] = _win(STYLES["e10_row_p4r3"], 95, 121)
STYLES["e10_row_p4r4~1_91"] = _win(STYLES["e10_row_p4r4"], 1, 91)
STYLES["e10_row_p4r4~4_89"] = _win(STYLES["e10_row_p4r4"], 4, 89)
