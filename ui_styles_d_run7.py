"""Label styles of art run 7, agent D (are_sub.arc: m3_are, s4w_are, m3_oen, m3_ido, m3_inst, m3_pss, m3_seiseki, s4_mem00).
Loaded by ui_type.py; written by gen_are_sub_spec.py styles (read from the Japanese lettering). Keep importable at every moment."""
import numpy as np
import ui_type
from ui_styles_ore_ini import ringfill

STYLES = {}


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


def windows(name):
    base = STYLES[name]
    for c0 in range(0, 416, 8):
        for c1 in list(range(c0 + 8, 424, 8)) + [4096]:
            STYLES["%s~%d_%d" % (name, c0, c1)] = win(base, c0, c1)

STYLES["d7_m3_are_00"] = ringfill([1, 12, 11, 10, 10, 6], [9], [2])      # fill [1, 6, 7, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_are_01"] = ringfill([8, 15, 15, 15, 15, 15], [7, 2], [4, 3])      # fill [8, 10, 11, 13, 15]
STYLES["d7_m3_are_02"] = ringfill([8, 8, 8, 8, 8, 8], [3], [1])      # fill [5, 7, 8, 10, 11, 13, 15]
STYLES["d7_m3_are_03"] = ringfill([8, 15, 15, 15, 15, 15], [9], [5, 4])      # fill [8, 10, 11, 13, 14, 15]
STYLES["d7_m3_are_04"] = ringfill([8, 15, 15, 15, 15, 15], [7, 2], [4])      # fill [8, 9, 10, 11, 13, 14, 15]
STYLES["d7_m3_are_05"] = ringfill([8, 15, 15, 15, 15, 15], [7, 3], [4])      # fill [8, 10, 11, 13, 15]
STYLES["d7_m3_are_06"] = ringfill([8, 8, 15, 15, 15, 15], [7, 2], [4])      # fill [8, 10, 11, 12, 13, 15]
STYLES["d7_m3_are_07"] = ringfill([8, 15, 15, 8, 8, 8], [6, 3], [4])      # fill [7, 8, 10, 11, 13, 14, 15]
STYLES["d7_m3_are_08"] = ringfill([8, 15, 15, 8, 15, 8], [9], [4, 4])      # fill [7, 8, 10, 11, 13, 14, 15]
STYLES["d7_m3_are_09"] = ringfill([8, 8, 15, 15, 8, 15], [7, 2], [4])      # fill [8, 10, 11, 14, 15]
STYLES["d7_m3_are_0a"] = ringfill([10, 8, 15, 8, 8, 8], [6, 3], [4])      # fill [8, 10, 11, 15]
STYLES["d7_m3_are_0b"] = ringfill([8, 8, 8, 8, 15, 15], [9], [4, 4])      # fill [7, 8, 10, 11, 12, 13, 15]
STYLES["d7_m3_are_0c"] = ringfill([8, 8, 15, 8, 15, 15], [7, 2], [4])      # fill [8, 10, 11, 13, 15]
STYLES["d7_s4w_are_01"] = ringfill([8, 15, 15, 15, 15, 15], [7, 2], [4, 3])      # fill [8, 10, 11, 13, 15]
STYLES["d7_s4w_are_02"] = ringfill([8, 15, 15, 8, 8, 8], [3])      # fill [5, 7, 8, 10, 11, 13, 14, 15]
STYLES["d7_s4w_are_03"] = ringfill([8, 15, 15, 8, 8, 8], [7])      # fill [5, 8, 9, 10, 11, 13, 14, 15]
STYLES["d7_s4w_are_04"] = ringfill([8, 15, 8, 15, 15, 15], [7, 2], [4])      # fill [8, 10, 11, 13, 15]
STYLES["d7_s4w_are_05"] = ringfill([8, 8, 8, 15, 15, 15], [7], [5, 4])      # fill [8, 10, 11, 13, 14, 15]
STYLES["d7_s4w_are_06"] = ringfill([8, 15, 15, 15, 15, 15], [9, 2], [4])      # fill [8, 10, 11, 13, 14, 15]
STYLES["d7_s4w_are_07"] = ringfill([8, 8, 15, 8, 8, 15], [3], [5, 4])      # fill [8, 10, 11, 14, 15]
STYLES["d7_m3_oen_00"] = ringfill([8, 13, 13, 14, 15, 15], [9, 2], [6, 1, 1, 3])      # fill [8, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_oen_06"] = ringfill([9, 15, 15, 15, 15, 15], [8, 5], [3])      # fill [9, 11, 12, 13, 15]
STYLES["d7_m3_oen_07"] = ringfill([9, 15, 15, 9, 15, 15], [6, 1], [3])      # fill [9, 10, 11, 12, 13, 15]
STYLES["d7_m3_oen_08"] = ringfill([9, 9, 15, 15, 9, 15], [6, 1], [3])      # fill [9, 11, 12, 13, 15]
STYLES["d7_m3_oen_09"] = ringfill([9, 9, 15, 15, 15, 15], [8, 1], [3])      # fill [9, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_oen_0a"] = ringfill([9, 15, 15, 15, 15, 15], [12, 1], [3])      # fill [9, 11, 13, 15]
STYLES["d7_m3_oen_0b"] = ringfill([9, 15, 15, 15, 15, 15], [6, 1], [3])      # fill [9, 11, 12, 13, 15]
STYLES["d7_m3_oen_0c"] = ringfill([9, 15, 15, 15, 15, 15], [8, 1], [3])      # fill [9, 11, 12, 14, 15]
STYLES["d7_m3_oen_15"] = ringfill([15, 15, 15, 15, 15, 15], [4])      # fill [1, 7, 10, 15]
STYLES["d7_m3_oen_16"] = ringfill([15, 15, 15, 15, 1, 15], [10])      # fill [1, 15]
STYLES["d7_m3_oen_1a"] = ringfill([15, 15, 15, 15, 15, 15], [10])      # fill [1, 7, 15]
STYLES["d7_m3_oen_31"] = ringfill([8, 12, 13, 8, 14, 15], [7, 4], [6, 3, 3])      # fill [8, 9, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_oen_33"] = ringfill([3, 12, 3, 3, 3, 3], [5], [13, 13])      # fill [3, 7, 9, 10, 11, 12]
STYLES["d7_m3_oen_36"] = ringfill([15, 15, 1, 1, 1, 15], [4])      # fill [1, 12, 15]
STYLES["d7_m3_oen_37"] = ringfill([15, 15, 15, 15, 15, 15], [10])      # fill [1, 12, 15]
STYLES["d7_m3_ido_00"] = ringfill([8, 13, 13, 14, 15, 15], [9, 2], [6, 1, 1, 3])      # fill [8, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_ido_01"] = ringfill([8, 13, 13, 14, 15, 15], [9, 3], [6, 1, 1, 3])      # fill [8, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_ido_03"] = ringfill([9, 15, 15, 15, 15, 15], [10, 1], [3])      # fill [9, 11, 12, 13, 14, 15]
STYLES["d7_m3_ido_04"] = ringfill([9, 9, 15, 15, 9, 15], [4, 1], [3])      # fill [9, 11, 12, 15]
STYLES["d7_m3_ido_05"] = ringfill([9, 9, 15, 9, 15, 15], [8, 1], [3])      # fill [9, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_ido_06"] = ringfill([9, 15, 15, 15, 15, 15], [10, 6], [3])      # fill [9, 11, 12, 13, 15]
STYLES["d7_m3_ido_07"] = ringfill([9, 15, 15, 15, 15, 9], [7, 6], [3])      # fill [9, 11, 12, 13, 15]
STYLES["d7_m3_ido_16"] = ringfill([15, 15, 2, 2, 2, 15], [13])      # fill [2, 4, 10, 14, 15]
STYLES["d7_m3_ido_17"] = ringfill([15, 15, 15, 15, 2, 15], [1])      # fill [2, 4, 10, 13, 14, 15]
STYLES["d7_m3_ido_27"] = ringfill([3, 12, 12, 3, 12, 3], [7], [13, 13])      # fill [3, 9, 10, 12]
STYLES["d7_m3_inst_02"] = ringfill([5, 15, 1, 13, 11, 1], [2])      # fill [1, 3, 4, 5, 8, 11, 13, 14, 15]
STYLES["d7_m3_inst_04"] = ringfill([1, 1, 1, 13, 11, 1], [15])      # fill [1, 2, 4, 6, 8, 9, 11, 13, 14]
STYLES["d7_m3_inst_25"] = ringfill([6, 15, 14, 13, 12, 1], [4])      # fill [1, 6, 12, 13, 14, 15]
STYLES["d7_m3_inst_26"] = ringfill([1, 1, 14, 13, 12, 1], [4])      # fill [1, 6, 12, 13, 14]
STYLES["d7_m3_pss_05"] = ringfill([9, 15, 15, 15, 15, 9], [11, 1], [3])      # fill [9, 12, 13, 15]
STYLES["d7_m3_pss_06"] = ringfill([9, 9, 15, 15, 9, 9], [8, 1], [3])      # fill [9, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_seiseki_00"] = ringfill([8, 13, 13, 14, 15, 15], [9, 2], [6, 1, 1, 4])      # fill [8, 10, 11, 12, 13, 14, 15]
STYLES["d7_m3_seiseki_05"] = ringfill([9, 9, 15, 15, 15, 15], [8, 1], [3])      # fill [9, 10, 11, 12, 13, 15]
STYLES["d7_m3_seiseki_06"] = ringfill([9, 15, 15, 9, 9, 15], [8, 5], [3])      # fill [9, 10, 11, 12, 13, 15]
STYLES["d7_m3_seiseki_07"] = ringfill([9, 9, 15, 15, 9, 15], [8, 1], [3])      # fill [9, 10, 11, 12, 13, 15]
STYLES["d7_m3_seiseki_08"] = ringfill([9, 15, 15, 15, 15, 15], [10, 6], [3])      # fill [9, 11, 12, 13, 15]
STYLES["d7_m3_seiseki_10"] = ringfill([9, 9, 15, 15, 9, 15], [11, 1], [3])      # fill [9, 12, 13, 15]
STYLES["d7_m3_seiseki_03h"] = ringfill([1, 1, 15, 13, 1, 12], [2])      # fill [1, 4, 7, 9, 10, 12, 13, 14, 15]
STYLES["d7_s4_mem00_00"] = ringfill([1, 15, 1, 1, 1, 1], [13])      # fill [1, 7, 10, 12, 15]
STYLES["d7_s4_mem00_01"] = ringfill([1, 15, 1, 1, 1, 1], [13])      # fill [1, 7, 10, 12, 15]
STYLES["d7_s4_mem00_02"] = ringfill([1, 1, 1, 15, 1, 1], [2])      # fill [1, 7, 10, 12, 14, 15]
STYLES["d7_s4_mem00_03"] = ringfill([1, 1, 1, 1, 1, 1], [2])      # fill [1, 7, 10, 13, 15]
STYLES["d7_m3_ido_0b"] = ringfill([15, 15, 15, 15, 15, 15], [12])      # fill [2, 4, 10, 13, 14, 15]
STYLES["d7_m3_ido_0d"] = ringfill([15, 15, 15, 15, 2, 15], [12])      # fill [2, 4, 10, 13, 14, 15]
STYLES["d7_m3_ido_0e"] = ringfill([15, 15, 15, 15, 15, 15], [12])      # fill [2, 4, 10, 13, 14, 15]
STYLES["d7_m3_seiseki_01h"] = ringfill([1, 15, 15, 14, 14, 1], [1])      # fill [1, 2, 5, 7, 10, 13, 14, 15]
STYLES["d7_m3_seiseki_02"] = ringfill([15, 2, 2, 2, 2, 15], [14])      # fill [2, 3, 4, 8, 13, 15]
STYLES["d7_m3_seiseki_avg"] = ringfill([3, 1, 15, 1, 1, 1], [2])      # fill [1, 3, 4, 5, 9, 12, 13, 14, 15]
STYLES["d7_m3_seiseki_hr"] = ringfill([1, 1, 15, 1, 1, 1], [8])      # fill [1, 2, 3, 5, 9, 12, 13, 14, 15]
STYLES["d7_m3_seiseki_rbi"] = ringfill([1, 1, 1, 1, 1, 1], [3])      # fill [1, 5, 13, 14, 15]
STYLES["d7_m3_seiseki_era"] = ringfill([1, 15, 15, 1, 12, 1], [2])      # fill [1, 3, 5, 9, 12, 13, 14, 15]
STYLES["d7_m3_pss_cur"] = ringfill([15, 15, 1, 1, 1, 15], [14])      # fill [1, 2, 3, 6, 9, 15]
STYLES["d7_m3_pss_lr"] = ringfill([14, 15, 1, 15, 15, 15], [6])      # fill [1, 2, 3, 10, 14, 15]
STYLES["d7_m3_pss_pad"] = ringfill([15, 15, 15, 15, 15, 15], [9])      # fill [1, 2, 3, 6, 10, 14, 15]
STYLES["d7_s4_mem00_04"] = ringfill([14, 14, 14, 14, 14, 14], [11])      # fill [1, 3, 5, 7, 8, 9, 10, 13, 14]
STYLES["d7_s4_mem00_05"] = ringfill([14, 14, 1, 14, 14, 14], [12])      # fill [1, 3, 5, 7, 11, 14]
STYLES["d7_s4_mem00_06"] = ringfill([13, 14, 1, 14, 14, 14], [8])      # fill [1, 3, 11, 13, 14]
STYLES["d7_s4_mem00_07"] = ringfill([8, 14, 1, 14, 14, 14], [12])      # fill [1, 3, 7, 8, 9, 11, 14]
STYLES["d7_s4_mem00_08"] = ringfill([14, 1, 1, 1, 14, 14], [11])      # fill [1, 5, 8, 10, 12, 14]
STYLES["d7_s4_mem00_09"] = ringfill([14, 14, 14, 14, 14, 14], [11])      # fill [1, 5, 8, 10, 14]
windows("d7_m3_ido_0b")
windows("d7_m3_ido_0d")
windows("d7_m3_ido_0e")
windows("d7_m3_seiseki_01h")
windows("d7_m3_seiseki_02")
