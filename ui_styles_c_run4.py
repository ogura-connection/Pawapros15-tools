"""Label styles of art run 4, agent C (school.arc, sct_a_ar.arc, sct_a_nh.arc, sct_a_td.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering of each palette; every style is crisp (solid rings, no half tones except fill ramps)."""
from ui_styles_ore_ini import ringfill
import ui_type

STYLES = {}

# ---- school.arc g3_ms (Baseball School menu) -------------------------------------------------------------------------------
STYLES["c4_ms_00"] = ringfill([14, 12, 12, 13, 13, 13], [2, 2, 15], [9, 7, 5])      # pal 0: gold, dark ring, white ring, blue glow
STYLES["c4_ms_02"] = ringfill([12, 12, 11, 10, 9, 9], [5, 5, 13, 14], [2, 3])        # pal 38: peach to orange, maroon ring, white
STYLES["c4_ms_05"] = ringfill([12, 12, 11, 10, 9, 9], [5, 5, 13, 14], [2, 3])        # pal 39: mint to green
STYLES["c4_ms_06"] = ringfill([11, 11, 10, 9, 9, 8], [5, 5, 12, 14], [3, 4])         # pal 40: yellow to green
STYLES["c4_ms_07"] = ringfill([12, 11, 10, 10, 9, 8], [6, 6, 13, 14], [3, 4])        # pal 41: pink to lilac
STYLES["c4_ms_08"] = ringfill([15, 13, 12, 11, 10, 9], [5, 5, 1, 3], [4, 8])         # pal 42: sky blue, navy ring, white
STYLES["c4_ms_10"] = ringfill([10, 11, 12, 13, 14, 15], [1, 1, 9, 8], [7, 6])        # pal 32: peach to orange
STYLES["c4_ms_13"] = ringfill([10, 11, 12, 13, 14, 15], [1, 1, 8, 7], [6, 5])        # pal 33: mint to green
STYLES["c4_ms_15"] = ringfill([13, 13, 12, 11, 10, 5], [1, 1, 14, 9], [8, 7])        # pal 34: yellow to lime
STYLES["c4_ms_16"] = ringfill([13, 12, 11, 10, 9, 9], [1, 1, 15, 8], [7, 6])         # pal 35: pink to lilac
STYLES["c4_ms_17"] = ringfill([15, 9, 8, 7, 6, 5], [1, 1, 12, 13], [11, 10])         # pal 36: sky blue

# ---- school.arc g3_rsz (Baseball School tabs: gold letters in a blue oval, 8-bit page) ---------------------------------------
STYLES["c4_rsz"] = ringfill([142, 144, 148, 152, 157, 162, 166], [75, 70, 70, 197], [32, 32])

RSZ_CAP, RSZ_SQ, RSZ_BOLD = 20, 0.92, 0.35
# per oval sprite: the letters' centre (x, y, in the oval's own pixel coordinates) and the pieces of the oval (page, rectangle of the page,
# the same rectangle in the oval's coordinates) that the lettering band crosses
RSZ = {
    "00": ((78, 38), [(10, [18, 15, 128, 64], [18, 15, 128, 64]), (8, [96, 7, 110, 56], [128, 15, 142, 64])]),
    "01": ((78, 39), [(10, [18, 95, 128, 128], [18, 15, 128, 48]), (11, [18, 0, 128, 16], [18, 48, 128, 64]), (8, [96, 71, 110, 120], [128, 15, 142, 64])]),
    "02": ((78, 39), [(11, [18, 47, 128, 96], [18, 15, 128, 64]), (3, [96, 71, 110, 120], [128, 15, 142, 64])]),
    "03": ((78, 40), [(12, [18, 15, 128, 64], [18, 15, 128, 64]), (12, [0, 95, 14, 128], [128, 15, 142, 48]), (12, [32, 96, 46, 112], [128, 48, 142, 64])]),
    "0f": ((78, 40), [(28, [18, 15, 128, 64], [18, 15, 128, 64]), (28, [0, 96, 14, 128], [128, 16, 142, 48]), (28, [0, 95, 8, 96], [128, 15, 136, 16]),
                      (28, [32, 96, 46, 112], [128, 48, 142, 64])]),
}
_RSZ_CLEAN = {}


def _rsz_clean(spr):
    """The oval of sprite `spr` of g3_rsz (palette indices, the oval's own coordinates) with the Japanese lettering and its shadow
    replaced by the white of the oval's inside; read from the saved original file, once."""
    if spr not in _RSZ_CLEAN:
        import sys, os
        import numpy as np
        here = os.path.dirname(os.path.abspath(__file__))
        for q in (os.path.join(here, "_work", "ui_pages"),):
            if q not in sys.path:
                sys.path.append(q)
        import gen_c_lib as G
        b = G.Arc("school.arc").bank("g3_rsz")
        img, _, _ = b.index_image(spr, pad=0)
        zone = set(np.unique(img[24:54, 30:126]).tolist()) - {0}
        struct = set(np.unique(np.concatenate([img[0:13].ravel(), img[67:].ravel(), img[:, 0:9].ravel(), img[:, 148:].ravel()])).tolist()) - {0}
        m = np.isin(img, list(zone - struct))
        for _ in range(4):
            m = ui_type.grow(m, 1)
        keep = np.zeros_like(m)
        keep[15:64, 18:142] = True
        out = img.copy()
        out[m & keep] = 197
        _RSZ_CLEAN[spr] = out.astype(np.uint8)
    return _RSZ_CLEAN[spr]


def _rsz_style(spr, screen, cx, cy):
    inner = STYLES["c4_rsz"]

    def style(ink, base):
        import numpy as np
        art, b = inner(ink, base)
        sx0, sy0, sx1, sy1 = screen
        out = _rsz_clean(spr)[sy0:sy1, sx0:sx1].copy()
        h, w = art.shape
        ax, ay = cx - w // 2, int(round(cy + RSZ_CAP / 2.0)) - b
        ys, xs = np.nonzero(art)
        for y, x in zip(ys, xs):
            yy, xx = ay + y - sy0, ax + x - sx0
            if 0 <= yy < out.shape[0] and 0 <= xx < out.shape[1]:
                out[yy, xx] = art[y, x]
        return out, b
    return style


for _s, ((_cx, _cy), _parts) in RSZ.items():
    for _k, (_pg, _rect, _scr) in enumerate(_parts):
        STYLES["c4_rsz_%s_%d" % (_s, _k)] = _rsz_style(_s, _scr, _cx, _cy)
