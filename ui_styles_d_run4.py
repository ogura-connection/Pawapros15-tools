"""Label styles of art run 4, agent D (sct_main.arc, gdt_sct.arc, sct_a_sc.arc, sct_a_it.arc, sct_sugo.arc). Loaded by ui_type.py."""
from ui_styles_ore_ini import ringfill
import ui_type

STYLES = {}

# ---- sct_main z5_emj_0 (scout window labels) -----------------------------------------------------------------------------
STYLES["d4_emj_head"] = ringfill([1, 1, 2, 3, 4, 5], [15, 15], [11, 10])          # pal 23: violet ramp, white ring, pale blue glow
STYLES["d4_emj_word"] = ringfill([15, 15, 15, 15, 14, 13], [4, 4, 3], [2, 1])      # pal 18: white letters, navy ring, blue glow


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    import numpy as np

    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


def windows(name):
    """STYLES[name~c0_c1] for every c0, c1 on the 16-column grid (and 4096 = to the end): what Bank.window_n asks for."""
    base = STYLES[name]
    for c0 in range(0, 192, 16):
        for c1 in list(range(c0 + 16, 208, 16)) + [4096]:
            STYLES["%s~%d_%d" % (name, c0, c1)] = win(base, c0, c1)

# ---- sct_main z5_esr_0 (growth report) ------------------------------------------------------------------------------------
STYLES["d4_esr_name"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4], [3, 2, 1])       # pal 32 / 34 / 35 / 36 share the index roles
STYLES["d4_esr_title"] = ringfill([15, 15, 15, 15, 15, 15], [11, 8, 5])              # pal 22 (and the black copy, pal 18)
STYLES["d4_esr_trust"] = ringfill([2, 2, 1, 1, 3, 5], [8], [10, 12])                 # pal 23: dark green, white ring, teal glow
for _n in ("d4_esr_name", "d4_esr_title"):
    windows(_n)
