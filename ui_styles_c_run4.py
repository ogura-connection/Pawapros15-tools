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
_RSZ_RIM = set(range(6, 27))
_RSZ_SHADOW = {27, 28, 33, 34, 35, 36, 39, 40, 42, 48, 49}


_RSZ_XL = [(15, 35), (16, 28), (17, 26), (19, 26), (20, 24), (22, 20), (24, 18), (26, 17), (28, 16.5), (30, 16), (32, 14), (34, 13), (36, 12), (38, 11)]


def _rsz_clean(spr):
    """The oval of sprite `spr` of g3_rsz (palette indices, the oval's own coordinates) with the Japanese lettering taken out: the white
    inside of the oval (rows 16-62, measured edge of the inner ring, mirrored about row 38.5) is made flat white and any colour only the
    lettering uses is white too. Read from the saved original file, once."""
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
        out = img.copy()
        m0 = np.isin(img, list(zone - struct))
        out[m0] = 197
        near = m0.copy()
        for _ in range(2):
            near = ui_type.grow(near, 1)
        out[near & np.isin(img, list(_RSZ_RIM)) & ~m0] = 235            # dark-blue edge pixels of the lettering left on the pale ring
        ys = [y for y, _ in _RSZ_XL]
        xs = [x for _, x in _RSZ_XL]
        for y in range(15, 63):
            yy = y if y <= 38 else 77 - y
            xl = np.interp(yy, ys, xs)
            x0, x1 = int(np.ceil(xl)) + 1, int(157 - xl) - 1
            out[y, x0:x1 + 1] = 197
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

# ---- school.arc g3_ykm (Baseball School lessons) ---------------------------------------------------------------------------
STYLES["c4_ykm_title"] = ringfill([15, 15, 15, 15, 14, 14], [11, 11, 6], [5, 4, 3])        # pal 16 / 24: white letters, navy ring, blue (or purple) shadow
STYLES["c4_ykm_go"] = ringfill([12, 13, 14, 15, 15, 15], [9, 9, 6], [4, 3])               # pal 57 / 58: olive-gold (or green) letters, white ring, blue glow
STYLES["c4_ykm_row"] = ringfill([14, 15, 15, 15, 15, 15], [10], [])                      # pal 34-37: dark letters on the coloured rows, white ring
STYLES["c4_ykm_go1"] = ringfill([12, 13, 14, 15, 15, 15], [9, 6], [4])                    # pal 57 / 58 at small sizes: thin rings
STYLES["c4_ykm_pan"] = ringfill([1, 1, 1, 1, 1, 1], [14], [])                           # pal 32: navy letters with a white ring (result panel)


def _panel(inner, left, cy, rect_sprite, align="left", cap=14):
    """A word of the result panel (sprite 4a, pal 32) placed by sprite coordinates: `left` = the art's left edge (align "left") or
    right edge ("right"), `cy` = the row its capitals are centred on; returns the window `rect_sprite` (x0, y0, x1, y1) of the whole."""
    def style(ink, base):
        import numpy as np
        art, b = inner(ink, base)
        x0, y0, x1, y1 = rect_sprite
        out = np.zeros((y1 - y0, x1 - x0), np.uint8)
        h, w = art.shape
        ax = left if align == "left" else left - w
        ay = int(round(cy + cap / 2.0)) - b
        ys, xs = np.nonzero(art)
        for y, x in zip(ys, xs):
            yy, xx = ay + y - y0, ax + x - x0
            if 0 <= yy < out.shape[0] and 0 <= xx < out.shape[1]:
                out[yy, xx] = art[y, x]
        return out, b
    return style


YKM_PAN_CAP = 13
# (page, rectangle of the page, the same in the sprite's coordinates) pieces; the word's anchor
YKM_PAN = {
    "avg": ([(15, [14, 11, 92, 37], [14, 139, 92, 165])], ("left", 18, 151)),
    "clr": ([(15, [14, 79, 94, 105], [14, 207, 94, 233])], ("left", 18, 220)),
    "pts": ([(15, [114, 46, 128, 74], [114, 174, 128, 202]), (17, [32, 46, 50, 74], [128, 174, 146, 202])], ("right", 141, 188)),
}
for _n, (_parts, (_al, _l, _cy)) in YKM_PAN.items():
    for _k, (_pg, _r, _sr) in enumerate(_parts):
        STYLES["c4_ykm_%s_%d" % (_n, _k)] = _panel(STYLES["c4_ykm_pan"], _l, _cy, _sr, _al, YKM_PAN_CAP)


# ---- g3_ykm reaction tags (74-78: a cap-face sticker with hand lettering): the Japanese lettering is taken out of the sticker, the English
# goes where it stood with the same white sticker edge. per sprite: (white, lettering indices, face indices, ink fill, centre x, centre y, parts)
TAG_CAP = 11
TAGS = {
    "74": (15, {1, 2, 3}, {4, 5, 6}, 3, 31, 10, [(21, [0, 80, 64, 120], [0, 0, 64, 40])], [(10, 20, 24, 40)]),
    "75": (15, {7, 8}, {3, 4, 5, 6}, 7, 22, 12, [(21, [64, 80, 128, 120], [0, 0, 64, 40])], [(12, 20, 24, 40)]),
    "76": (15, {1, 2, 3}, {4, 5, 6}, 3, 19, 11, [(23, [8, 64, 48, 104], [0, 0, 40, 40]), (23, [48, 64, 72, 104], [40, 0, 64, 40])], [(14, 18, 25, 40)]),
    "77": (9, {5, 6, 7}, {1, 2, 3, 4}, 7, 25, 9, [(23, [72, 64, 128, 104], [0, 0, 56, 40]), (26, [120, 88, 128, 128], [56, 0, 64, 40]), (26, [96, 64, 120, 72], [8, 40, 32, 48])], [(8, 24, 32, 48)]),
    "78": (15, {5, 6, 7}, {3, 4}, 6, 27, 8, [(23, [0, 104, 72, 128], [0, 0, 72, 24]), (23, [72, 104, 128, 120], [8, 24, 64, 40])], [(14, 14, 26, 40)]),
}
for _s, _t in TAGS.items():
    STYLES["c4_tag_" + _s] = ringfill([_t[3]] * 6, [_t[0], _t[0]], [])
_TAG_CLEAN = {}


def _tag_clean(spr):
    """The tag sprite's picture (palette indices, sprite coordinates) with the Japanese lettering and its sticker edge taken out."""
    if spr not in _TAG_CLEAN:
        import sys, os
        import numpy as np
        here = os.path.dirname(os.path.abspath(__file__))
        q = os.path.join(here, "_work", "ui_pages")
        if q not in sys.path:
            sys.path.append(q)
        import gen_c_lib as G
        b = G.Arc("school.arc").bank("g3_ykm")
        white, text, face, _, _, _, _, decor = TAGS[spr]
        img, _, _ = b.index_image(spr, pad=0)
        T = np.isin(img, list(text))
        F = np.isin(img, list(face))
        near = T.copy()
        for _ in range(3):
            near = ui_type.grow(near, 1)
        keep = F.copy()
        for _ in range(2):
            keep = ui_type.grow(keep, 1)
        for x0, y0, x1, y1 in decor:
            keep[y0:y1, x0:x1] = True
        out = img.copy()
        out[(T | (near & ~keep)) & (img > 0)] = 0
        out[T] = 0
        _TAG_CLEAN[spr] = out.astype(np.uint8)
    return _TAG_CLEAN[spr]


def _tag_style(spr, screen):
    inner = STYLES["c4_tag_" + spr]
    cx, cy = TAGS[spr][4], TAGS[spr][5]

    def style(ink, base):
        import numpy as np
        art, b = inner(ink, base)
        sx0, sy0, sx1, sy1 = screen
        out = _tag_clean(spr)[sy0:sy1, sx0:sx1].copy()
        h, w = art.shape
        ax, ay = cx - w // 2, int(round(cy + TAG_CAP / 2.0)) - b
        ys, xs = np.nonzero(art)
        for y, x in zip(ys, xs):
            yy, xx = ay + y - sy0, ax + x - sx0
            if 0 <= yy < out.shape[0] and 0 <= xx < out.shape[1]:
                out[yy, xx] = art[y, x]
        return out, b
    return style


for _s, _t in TAGS.items():
    for _k, (_pg, _rect, _scr) in enumerate(_t[6]):
        STYLES["c4_tag_%s_%d" % (_s, _k)] = _tag_style(_s, _scr)
