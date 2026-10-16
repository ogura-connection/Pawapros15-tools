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

STYLES["d7_m3_are_00"] = ringfill([11, 11, 11, 10, 10, 10], [13, 15, 1, 1, 12, 12, 2], [2, 2, 8, 8])      # fill [10, 11]
STYLES["d7_m3_are_01"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5], [4, 4])      # fill [10, 13, 15]
STYLES["d7_m3_are_02"] = ringfill([5, 15, 15, 5, 15, 15], [10, 8])      # fill [5, 15]
STYLES["d7_m3_are_03"] = ringfill([10, 15, 15, 15, 15, 15], [8, 8, 5], [5])      # fill [10, 11, 15]
STYLES["d7_m3_are_04"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5], [4, 4])      # fill [11, 15]
STYLES["d7_m3_are_05"] = ringfill([13, 15, 15, 15, 15, 15], [8, 8, 3, 3], [4])      # fill [13, 15]
STYLES["d7_m3_are_06"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 3, 2], [4])      # fill [13, 15]
STYLES["d7_m3_are_07"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5, 2], [4])      # fill [11, 13, 15]
STYLES["d7_m3_are_08"] = ringfill([15, 15, 15, 15, 15, 15], [11, 8, 3, 5], [4, 4])      # fill [15]
STYLES["d7_m3_are_09"] = ringfill([5, 15, 15, 15, 15, 5], [8, 8])      # fill [5, 11, 15]
STYLES["d7_m3_are_0a"] = ringfill([15, 15, 15, 15, 15, 15], [11, 8, 6, 3], [4])      # fill [15]
STYLES["d7_m3_are_0b"] = ringfill([10, 15, 15, 11, 15, 15], [8, 8, 5], [4])      # fill [10, 11, 15]
STYLES["d7_m3_are_0c"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 3, 3], [4])      # fill [13, 15]
STYLES["d7_s4w_are_01"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5, 5], [4, 3])      # fill [11, 15]
STYLES["d7_s4w_are_02"] = ringfill([15, 15, 15, 15, 15, 15], [13, 8, 7, 5], [4])      # fill [15]
STYLES["d7_s4w_are_03"] = ringfill([15, 15, 15, 15, 15, 15], [13, 8, 7, 5], [4])      # fill [15]
STYLES["d7_s4w_are_04"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 2], [4, 4])      # fill [10, 11, 15]
STYLES["d7_s4w_are_05"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5], [4, 4])      # fill [11, 13, 15]
STYLES["d7_s4w_are_06"] = ringfill([15, 15, 15, 15, 15, 15], [8, 8, 5], [5, 4])      # fill [11, 15]
STYLES["d7_s4w_are_07"] = ringfill([15, 15, 15, 15, 15, 15], [10, 8, 3, 5], [4, 3])      # fill [15]
STYLES["d7_m3_oen_00"] = ringfill([13, 13, 13, 14, 15, 15], [12, 8, 2, 2], [6, 1, 1, 3])      # fill [13, 14, 15]
STYLES["d7_m3_oen_06"] = ringfill([15, 15, 15, 15, 15, 15], [9, 8, 5], [3, 3])      # fill [11, 13, 15]
STYLES["d7_m3_oen_07"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 1], [3, 3])      # fill [11, 13, 15]
STYLES["d7_m3_oen_08"] = ringfill([11, 15, 15, 15, 15, 15], [9, 9, 4], [3, 3])      # fill [11, 13, 15]
STYLES["d7_m3_oen_09"] = ringfill([8, 15, 15, 15, 15, 15], [9, 9], [3])      # fill [8, 15]
STYLES["d7_m3_oen_0a"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 5], [3])      # fill [11, 13, 15]
STYLES["d7_m3_oen_0b"] = ringfill([15, 15, 15, 15, 15, 15], [9, 6, 1], [3, 3])      # fill [11, 13, 15]
STYLES["d7_m3_oen_0c"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 4, 4], [3])      # fill [12, 15]
STYLES["d7_m3_oen_15"] = ringfill([1, 1, 1, 1, 1, 1], [7, 15, 15, 15, 15, 15, 15])      # fill [1]
STYLES["d7_m3_oen_16"] = ringfill([1, 1, 1, 1, 1, 1], [7, 15, 15, 15, 15, 15, 15])      # fill [1]
STYLES["d7_m3_oen_1a"] = ringfill([1, 1, 1, 1, 1, 1], [7, 15, 15, 15, 15, 15, 15], [15])      # fill [1]
STYLES["d7_m3_oen_31"] = ringfill([12, 12, 13, 14, 14, 14], [8, 8, 4, 4], [1, 3, 3])      # fill [10, 12, 13, 14]
STYLES["d7_m3_oen_33"] = ringfill([12, 12, 12, 9, 12, 12], [3, 3, 3, 1], [13, 13])      # fill [9, 12]
STYLES["d7_m3_oen_36"] = ringfill([1, 1, 1, 1, 1, 1], [7, 15, 15, 15, 15, 15, 15], [15])      # fill [1]
STYLES["d7_m3_oen_37"] = ringfill([1, 1, 1, 1, 1, 1], [10, 15, 15, 15, 15, 15, 15], [15, 15])      # fill [1]
STYLES["d7_m3_ido_00"] = ringfill([13, 13, 13, 14, 15, 15], [12, 8, 2, 2], [6, 1, 1])      # fill [13, 14, 15]
STYLES["d7_m3_ido_01"] = ringfill([13, 13, 13, 14, 15, 15], [12, 8, 2, 2], [6, 1, 1, 3])      # fill [13, 14, 15]
STYLES["d7_m3_ido_03"] = ringfill([12, 15, 15, 15, 15, 15], [9, 9, 6], [3, 3])      # fill [12, 15]
STYLES["d7_m3_ido_04"] = ringfill([4, 4, 15, 15, 15, 15], [9, 9])      # fill [4, 15]
STYLES["d7_m3_ido_05"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 6], [3, 3])      # fill [11, 13, 15]
STYLES["d7_m3_ido_06"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 5], [3, 3])      # fill [12, 15]
STYLES["d7_m3_ido_07"] = ringfill([12, 15, 15, 15, 15, 15], [9, 9, 4], [3, 3])      # fill [12, 15]
STYLES["d7_m3_ido_16"] = ringfill([2, 2, 2, 2, 2, 2], [4, 15, 15, 15, 15, 15], [15, 15])      # fill [2]
STYLES["d7_m3_ido_17"] = ringfill([2, 2, 2, 2, 2, 2], [4, 15, 15, 15, 15, 15, 15], [15, 15])      # fill [2]
STYLES["d7_m3_ido_27"] = ringfill([12, 12, 12, 9, 12, 12], [3, 3, 3, 1], [13, 13])      # fill [9, 12]
STYLES["d7_m3_inst_02"] = ringfill([15, 15, 14, 13, 11, 10], [1, 1])      # fill []
STYLES["d7_m3_inst_04"] = ringfill([15, 15, 14, 13, 11, 10], [1, 1])      # fill []
STYLES["d7_m3_inst_25"] = ringfill([1, 1, 1, 13, 13, 1], [6, 15], [7])      # fill [1, 13, 14]
STYLES["d7_m3_inst_26"] = ringfill([1, 1, 1, 13, 1, 1], [6, 15], [7])      # fill [1, 13, 14]
STYLES["d7_m3_pss_05"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 4], [3, 3])      # fill [12, 13, 15]
STYLES["d7_m3_pss_06"] = ringfill([15, 15, 15, 15, 15, 15], [11, 9, 5, 4], [3])      # fill [15]
STYLES["d7_m3_seiseki_00"] = ringfill([13, 13, 13, 14, 15, 15], [8, 8, 2, 3], [6, 1, 1])      # fill [11, 13, 14, 15]
STYLES["d7_m3_seiseki_05"] = ringfill([13, 15, 15, 15, 15, 15], [9, 8, 4], [3, 3])      # fill [12, 13, 15]
STYLES["d7_m3_seiseki_06"] = ringfill([12, 15, 15, 15, 15, 15], [9, 8, 5], [3])      # fill [11, 12, 13, 15]
STYLES["d7_m3_seiseki_07"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 5, 1], [3])      # fill [13, 15]
STYLES["d7_m3_seiseki_08"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 6], [3, 3])      # fill [11, 13, 15]
STYLES["d7_m3_seiseki_10"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 6])      # fill [3, 10, 12, 15]
STYLES["d7_m3_seiseki_03h"] = ringfill([15, 14, 14, 13, 13, 12], [1, 1])      # fill []
STYLES["d7_s4_mem00_00"] = ringfill([15, 15, 14, 13, 12, 11], [1, 1], [8, 7])      # fill []
STYLES["d7_s4_mem00_01"] = ringfill([15, 15, 14, 13, 12, 11], [1, 1], [8, 7])      # fill []
STYLES["d7_s4_mem00_02"] = ringfill([15, 15, 14, 13, 12, 11], [1, 1], [8, 7])      # fill []
STYLES["d7_s4_mem00_03"] = ringfill([15, 15, 14, 13, 12, 11], [1, 1], [8, 7])      # fill []
STYLES["d7_m3_ido_0b"] = ringfill([2, 2, 2, 2, 2, 2], [15, 15, 15, 15, 15, 15])      # fill [2, 10]
STYLES["d7_m3_ido_0d"] = ringfill([2, 2, 2, 2, 2, 2], [4, 15, 15, 15, 15, 15, 15], [15])      # fill [2]
STYLES["d7_m3_ido_0e"] = ringfill([2, 2, 2, 2, 2, 2], [4, 15, 15, 15, 15, 15, 15], [15])      # fill [2]
STYLES["d7_m3_seiseki_01h"] = ringfill([15, 15, 14, 14, 13, 12], [1, 1])      # fill []
STYLES["d7_m3_seiseki_02"] = ringfill([2, 2, 2, 2, 2, 2], [15, 15])      # fill [2, 4, 8]
STYLES["d7_m3_seiseki_avg"] = ringfill([15, 15, 14, 13, 12, 12], [1, 1])      # fill []
STYLES["d7_m3_seiseki_hr"] = ringfill([15, 15, 14, 13, 12, 12], [1, 1])      # fill []
STYLES["d7_m3_seiseki_rbi"] = ringfill([15, 15, 14, 13, 12, 12], [1, 1])      # fill []
STYLES["d7_m3_seiseki_era"] = ringfill([15, 15, 14, 13, 12, 12], [1, 1])      # fill []
STYLES["d7_m3_pss_cur"] = ringfill([15, 15, 15, 14, 13, 13], [1, 1])      # fill []
STYLES["d7_m3_pss_lr"] = ringfill([15, 15, 15, 14, 13, 13], [1, 1])      # fill []
STYLES["d7_m3_pss_pad"] = ringfill([15, 15, 15, 14, 13, 13], [1, 1])      # fill []
STYLES["d7_s4_mem00_04"] = ringfill([14, 14, 14, 13, 13, 12], [1, 1])      # fill []
STYLES["d7_s4_mem00_05"] = ringfill([14, 14, 14, 13, 13, 12], [1, 1])      # fill []
STYLES["d7_s4_mem00_06"] = ringfill([14, 14, 14, 13, 13, 12], [1, 1])      # fill []
STYLES["d7_s4_mem00_07"] = ringfill([14, 14, 14, 13, 13, 12], [1, 1])      # fill []
STYLES["d7_s4_mem00_08"] = ringfill([14, 14, 14, 13, 13, 12], [1, 1])      # fill []
STYLES["d7_s4_mem00_09"] = ringfill([14, 14, 14, 13, 13, 12], [1, 1])      # fill []
windows("d7_m3_ido_0b")
windows("d7_m3_ido_0d")
windows("d7_m3_ido_0e")
windows("d7_m3_seiseki_01h")
windows("d7_m3_seiseki_02")
