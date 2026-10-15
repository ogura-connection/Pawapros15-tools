"""Label styles of art run 1, agent D (gameplay.arc: defensive shift panel, record banners, team names, position names,
turning / attack / defense point, substitution headings, score challenge, standings, rankings, hero banners,
defence practice). Loaded by ui_type.py. Colours are read from the Japanese lettering of each palette
(_work/ui_pages/run1/D/hist.py, roles.py)."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}

# h3_aps_0: Def. Shift title (palette 14): orange letters in two black rings
STYLES["d_aps_title"] = ringfill([0xf], [1, 1])
# Outfield / Infield (palettes 50, 51): lavender letters, a blue-lavender ring, black shadow
STYLES["d_aps_side"] = ringfill([0xf], [6], [3])
# the rows of shift choices and the Bunt Shift line (palette 52): navy letters in light rings
STYLES["d_aps_row"] = ringfill([4], [0xe, 0xa])
STYLES["d_aps_row1"] = ringfill([4], [0xe])
# h3_lo_0: the record banner (palette 23): white letters shading to cream, blue ring, dark brown outer ring
STYLES["d_lo_banner"] = ringfill([0xf, 0xe, 0xd, 0xc], [8, 8, 1])
# hit-direction tags (palettes 39, 40): orange letters, green ring, dark green outer ring
STYLES["d_lo_tag"] = ringfill([0xf], [4, 1])
# h3_mrg_0 team names (palette 0): white letters, navy ring (one ring: the page has room for 19 names of 20 pixels only)
STYLES["d_mrg_name"] = ringfill([0xf], [1])
# y5_tnp_1 titles: Turning Point (palette 4, cyan on navy), Defense Point (palette 6, mint on deep green),
# Attack Point (palette 5, pink on maroon); each has a three-pixel dark outline and a white outer ring
STYLES["d_tnp_turn"] = ringfill([4, 4, 3, 3, 2, 2], [0xf, 0xf, 0xf, 5, 5, 6])
STYLES["d_tnp_def"] = ringfill([4, 5, 5, 8, 8, 8], [0xf, 0xf, 0xf, 3, 3, 2])
STYLES["d_tnp_atk"] = ringfill([4, 5, 6, 7, 8, 8], [0xf, 0xf, 0xf, 2, 2, 1])
# y4_kkg_0 position names (palette 2): black italic letters with a thin white edge
STYLES["d_kkg"] = ringfill([0xf], [1])
# y4_dem_1 title 守備交代 (palette 4): orange letters, dark ring, brown shadow
STYLES["d_dem_title"] = ringfill([0xf, 0xf, 0xe, 0xd], [4, 1], [8])
# h3_dem_2 headings (palettes 2, 3: one red ramp each): red-orange letters, dark brown ring, black-green outer ring, brown shadow
STYLES["d_dem_head"] = ringfill([0xf, 0xf, 0xe, 0xd], [4, 2], [7])


def platefill(fill, rings, shadow, w, h):
    """ringfill lettering centred on a w x h plate (the plate is palette index 0, opaque in these palettes)."""
    inner = ringfill(fill, rings, shadow)

    def style(ink, base):
        a, b = inner(ink, base)
        ah, aw = a.shape
        if aw > w or ah > h:
            raise ValueError("lettering %dx%d does not fit a plate %dx%d" % (aw, ah, w, h))
        out = np.zeros((h, w), np.uint8)
        x, y = (w - aw) // 2, (h - ah) // 2
        out[y:y + ah, x:x + aw] = a
        return out, b + y
    return style


# h3_rt_0 (g3_hk) score-challenge labels (palette 13): light tan letters, brown ring, on the orange plate (index 0);
# Bonus (palette 15): white letters, grey ring, on the cream plate
for _w in range(16, 97):
    STYLES["d_rt_%d" % _w] = platefill([0xf, 0xe, 0xd], [6], [], _w, 24)
    STYLES["d_oma_%d" % _w] = platefill([0xf, 0xf, 0xf, 0xe], [2], [1], _w, 24)
STYLES["d_rt_measure"] = ringfill([0xf, 0xe, 0xd], [6])      # width probe for the plate styles
STYLES["d_oma_measure"] = ringfill([0xf, 0xf, 0xf, 0xe], [2], [1])

# h3_nxt_ps2: ticker headings (palette 69): cream letters, navy ring; silver titles and rankings (72); league names (73-75); tags (95, 76)
STYLES["d_nxt_head"] = ringfill([8, 8, 0xd, 0xd], [0xf, 0xf], [4])
STYLES["d_nxt_top"] = ringfill([0xb, 0xc, 0xd, 0xd], [1, 1, 0xa, 9], [2])
STYLES["d_nxt_rank"] = ringfill([0xb, 0xc, 0xd, 0xd], [1, 1, 0xa, 9], [2])
STYLES["d_nxt_ce"] = ringfill([0xe, 0xd, 0xc, 0xb], [4, 1], [1])
STYLES["d_nxt_pa"] = ringfill([0xf, 0xe, 0xd, 0xc], [6, 4, 1], [2])
STYLES["d_nxt_le"] = ringfill([0xf, 0xe, 0xc, 0xa], [4, 1], [2])
STYLES["d_nxt_cl"] = ringfill([0xf, 0xf, 0xe, 0xc], [4])
STYLES["d_nxt_ch"] = ringfill([0xf, 0xf, 0xe, 0xd], [8])

# h3_her_0: banners (palette 23): mint letters, bright green ring, dark green outer ring; highlights (14): green letters, blue ring;
# Today's Highlights in red (65): red letters, dark ring, white edge
STYLES["d_her_big"] = ringfill([0xc, 0xc, 0xd, 0xe, 0xf], [1, 1, 8, 5])
STYLES["d_her_hl"] = ringfill([0xf, 0xf, 0xe, 0xd], [4, 1])
STYLES["d_her_red"] = ringfill([9, 8, 8, 7], [4, 1, 0xf])
# h3_rs_0: defence practice (palettes 11, 26, 27): white letters in blue rings
STYLES["d_rs_btn"] = ringfill([0xf], [5])
STYLES["d_rs_head"] = ringfill([0xf, 0xf, 0xe, 0xd], [7, 7], [6])
STYLES["d_rs_sub"] = ringfill([5, 5, 6, 7], [2, 1])
