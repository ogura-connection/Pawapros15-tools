"""Label styles of art run 4, agent E (school_g.arc, sct_card.arc, sct_comd.arc, sct_a_ed.arc, sct_a_od.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering of each palette; every style is crisp (solid rings, no half tones except fill ramps)."""
from ui_styles_ore_ini import ringfill

STYLES = {}


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

# ---- sct_a_od.arc (Eikan Nine order screen) -----------------------------------------------------------------------------
STYLES["e4_od_title"] = ringfill([15, 15, 15, 15, 13, 12], [4, 4, 3, 2])             # pal 40: white, navy rings, blue glow
STYLES["e4_od_cancel"] = ringfill([12, 12, 11, 11, 8, 3], [15, 15, 5], [7, 9])         # pal 35: lavender, white ring, blue glow
STYLES["e4_od_blue"] = ringfill([15, 15, 15, 14, 13, 12], [1])                      # pal 20: white, blue ring

# ---- sct_a_ed.arc (graduates screen) ------------------------------------------------------------------------------------
STYLES["e4_ed_title"] = ringfill([15, 14, 13, 12, 11, 10], [5, 5, 1, 1], [2])          # pal 0: gold, near-black ring, blue ring
STYLES["e4_ed_gold"] = ringfill([15, 14, 13, 11, 9, 7], [1, 1], [2])                   # pal 1: olive-gold brush, black ring
STYLES["e4_ed_gold~0_8"] = win(STYLES["e4_ed_gold"], 0, 8)
STYLES["e4_ed_gold~8_4096"] = win(STYLES["e4_ed_gold"], 8, 4096)

# ---- sct_comd.arc (team strength screen) ---------------------------------------------------------------------------------
STYLES["e4_cd_abil"] = ringfill([15, 15, 15, 14, 13, 12], [4], [3, 2])                 # pal 24: white letters, black ring, grey shadow
STYLES["e4_cd_year"] = ringfill([4, 3, 3, 2, 2, 2], [8, 11])                           # pal 17-19 / 4: coloured digits, white ring, pale glow

# ---- school_g.arc (Baseball School) --------------------------------------------------------------------------------------
# the lesson plates: white letters, navy ring, blue shadow; the same indices serve the blue / red / teal / purple palettes (10-13)
STYLES["e4_sg_btn"] = ringfill([15, 15, 15, 15, 14, 14], [8, 7], [5, 3, 2])
STYLES["e4_sg_head"] = ringfill([15, 15, 15, 15, 15, 15], [6, 3])                       # pal 15: white letters, green ring
STYLES["e4_sg_small"] = ringfill([15, 15, 15, 15, 15, 15], [6])                         # pal 15: score panel words


def plate(style, w, h, bg):
    """The styled word centred on a plain plate of index `bg` (at least w x h): lettering that is part of a solid plate."""
    import numpy as np

    def make(ink, base):
        art, b = style(ink, base)
        H, W = max(h, art.shape[0]), max(w, art.shape[1])
        out = np.full((H, W), bg, np.uint8)
        oy, ox = (H - art.shape[0]) // 2, (W - art.shape[1]) // 2
        sub = out[oy:oy + art.shape[0], ox:ox + art.shape[1]]
        sub[art > 0] = art[art > 0]
        return out, b + oy
    return make


# pal 14: Start Practice on a black plate (index 1), white letters
STYLES["e4_sg_start"] = plate(ringfill([15, 15, 15, 14, 14, 13], [6]), 80, 24, 1)
STYLES["e4_sg_start_t"] = ringfill([15, 15, 15, 14, 14, 13], [6])                      # the same letters without the plate (for measuring)


def vcut(style, lo, hi, H, W):
    """The styled word centred on an H x W canvas, then only its rows lo..hi (a word cut across two page rectangles stacked
    on top of each other: the pieces of クリア). The canvas rows below the word stay empty (0)."""
    import numpy as np

    def make(ink, base):
        art, b = style(ink, base)
        out = np.zeros((H, W), np.uint8)
        oy, ox = (H - art.shape[0]) // 2, (W - art.shape[1]) // 2
        out[oy:oy + art.shape[0], ox:ox + art.shape[1]] = art[:H, :W]
        return out[lo:hi], b + oy - lo
    return make


# クリア (p16 y98-128 + p17 y96-108, one 42-row word): "Clear" 96 x 42
STYLES["e4_sg_clear_0"] = vcut(STYLES["e4_sg_head"], 0, 30, 42, 96)
STYLES["e4_sg_clear_1"] = vcut(STYLES["e4_sg_head"], 30, 42, 42, 96)

# ---- sct_card.arc (Eikan Nine command cards) -----------------------------------------------------------------------------
STYLES["e4_em_item"] = ringfill([15, 15, 15, 15, 12, 11], [6, 1])                      # pal 84: white letters, blue ring
STYLES["e4_em_item1"] = ringfill([15, 15, 15, 15, 12, 11], [1])                        # the same with a one-pixel ring (two lines in 24 rows)
