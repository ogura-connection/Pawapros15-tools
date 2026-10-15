"""Label styles of art run 4, agent D (sct_main.arc, gdt_sct.arc, sct_a_sc.arc, sct_a_it.arc, sct_sugo.arc). Loaded by ui_type.py."""
from ui_styles_ore_ini import ringfill
import ui_type

STYLES = {}
ui_type.TTF["d4narrow"] = ("/System/Library/Fonts/Supplemental/Arial Narrow.ttf", 0)       # regular weight, for the thin black lettering
ui_type.TTF["d4tahoma"] = ("/System/Library/Fonts/Supplemental/Tahoma.ttf", 0)

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
    for step, top in ((16, 192), (8, 96)):
        for c0 in range(0, top, step):
            for c1 in list(range(c0 + step, top + 16, step)) + [4096]:
                STYLES["%s~%d_%d" % (name, c0, c1)] = win(base, c0, c1)

# ---- sct_main z5_esr_0 (growth report) ------------------------------------------------------------------------------------
STYLES["d4_esr_name"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4], [3, 2, 1])       # pal 32 / 34 / 35 / 36 share the index roles
STYLES["d4_esr_title"] = ringfill([15, 15, 15, 15, 15, 15], [11, 8, 5])              # pal 22 (and the black copy, pal 18)
STYLES["d4_esr_trust"] = ringfill([2, 2, 1, 1, 3, 5], [8], [10, 12])                 # pal 23: dark green, white ring, teal glow
for _n in ("d4_esr_name", "d4_esr_title"):
    windows(_n)


def plain(dark, mid=None, edge=3):
    """Flat dark lettering (the player info window, black on a white panel): solid `dark` where the ink is at least `edge`,
    `mid` for the thinner edge (None: nothing)."""
    import numpy as np

    def style(ink, base):
        out = np.zeros(ink.shape, np.uint8)
        out[ink >= edge] = dark
        if mid is not None:
            out[(ink > 0) & (ink < edge)] = mid
        ys, xs = np.nonzero(out)
        return out[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base - ys.min()
    return style


# ---- sct_main z4_edsm_0 (player info window): pal 24, black ramp f (black) .. 1 (near white) ----------------------------------
STYLES["d4_edsm"] = plain(15, 8)
windows("d4_edsm")

# ---- sct_main logos (4-bit pages, big letters: fill ramp, dark inner rings, white ring, shadow) ------------------------------
STYLES["d4_efd"] = ringfill([15, 14, 14, 13, 12, 11], [8, 7, 5, 3, 1], [1, 1])               # pal 0: silver-white, teal, near-black
STYLES["d4_efk"] = ringfill([7, 8, 9, 10, 11, 11], [13, 12, 1, 1], [3, 3, 3, 4])             # pal 2: yellow to orange, dark red, white, violet shadow
STYLES["d4_efc"] = ringfill([13, 9, 9, 10, 11, 12], [3, 3, 15, 15], [1, 2, 2, 1])            # pal 4: pale to deep cyan, blue, white, navy shadow

# ---- gdt_sct.arc (Eikan Nine match screen) -------------------------------------------------------------------------------------
STYLES["d4_gm20"] = ringfill([15, 15, 14, 13, 12, 11], [4, 3, 2], [])                  # z4_gm_0 pal 20: white letters, black ring
STYLES["d4_gm22"] = ringfill([15, 15, 14, 13, 12, 11], [1, 1])                         # z4_gm_0 pal 22: white letters, black ring (stats headings)
STYLES["d4_gmt"] = ringfill([15, 15, 14, 13, 12, 11], [4, 3], [2, 1])                  # z5_gmt_0 pal 20: yellow letters, olive and dark green rings
STYLES["d4_gmu"] = ringfill([15, 15, 14, 13, 12, 11], [7, 4, 4, 2])                    # z5_gmu_0 pal 20 / 21: white letters, blue (red) rings; the black layer behind is a copy
STYLES["d4_gmh"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4, 2])                       # z5_gmu_0 sprite 00 (pal 23): white letters, dark ring
STYLES["d4_gms"] = ringfill([2, 2, 1, 1, 3, 5], [8], [10, 12])                         # z5_gmu_0 06 / 07 (pal 18): dark green letters, white ring
windows("d4_gmu")
windows("d4_gm20")
windows("d4_gm22")
