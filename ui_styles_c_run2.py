"""Label styles of art run 2, agent C (gdt_scs.arc Success match labels, scs_vs.arc versus screen, scs_win.arc result screen).
Loaded by ui_type.py. Plain numbers read from the Japanese lettering of each palette (see the comment on every style)."""
import numpy as np
import ui_type
from ui_type import grow, shift
from ui_styles_ore_ini import ringfill

STYLES = {}


def padded(style, h):
    """The art of `style` padded with clear rows at the foot to exactly h rows (labels of one band group are as high as the band)."""
    def cut(ink, base):
        art, b = style(ink, base)
        H, W = art.shape
        if H > h:
            return art, b
        out = np.zeros((h, W), np.uint8)
        out[:H] = art
        return out, b
    return cut


# gdt_scs z3_sgr_0 (palette 11): white letters in a dark blue outline, one pixel, so that 71 phrases fit the ten pages
STYLES["c2_sgr"] = padded(ringfill([15], [4], []), 17)
# gdt_scs z3_sgi_0 (palette 2): white letters, navy outline, blue ring
STYLES["c2_sgi"] = padded(ringfill([15], [4, 2], []), 20)
# gdt_scs h3_mrs_0 (palette 0): orange letters, dark brown outline, brown ring
STYLES["c2_mrs"] = ringfill([15], [1, 3], [])
# gdt_scs / scs_vs svt_0 (palette 0): white letters, navy outline, blue band, white rim
STYLES["c2_svt"] = ringfill([15], [1, 1, 9, 9, 9, 15, 15], [7, 13])


def window(inner, W, c0, c1):
    """`inner` art centred on a canvas W columns wide, only the columns c0..c1 returned: one word shared out over the pieces
    (parts) that the sprite is drawn from, each piece painted in place by a "paint" entry."""
    def cut(ink, base):
        art, b = inner(ink, base)
        H, aw = art.shape
        full = np.zeros((H, W), np.uint8)
        x = (W - aw) // 2
        if x >= 0:
            full[:, x:x + aw] = art
        else:
            full[:] = art[:, -x:-x + W]
        out = full[:, c0:c1]
        return (out if out.shape[1] else np.zeros((H, 1), np.uint8)), b
    return cut


for _w, _c0, _c1 in ((80, 0, 80), (80, 0, 48), (80, 48, 80), (32, 0, 32)):
    STYLES["c2_mrsw_%d_%d_%d" % (_w, _c0, _c1)] = window(STYLES["c2_mrs"], _w, _c0, _c1)


# ---- gdt_scs y4_mmk_1: the 32 x 32 team emblems with one kanji (two Latin capitals instead) ---------------------------
import os
import scan_story as _S
import ui_textures as _U
_ORIG = {}


def _orig_rect(arc, bank, page, rect):
    """The 32 x 32 indices of an emblem in the untouched file."""
    key = (arc, bank, page)
    if key not in _ORIG:
        path = os.path.join(_U.ORIG_ARC_DIR, arc)
        if not os.path.exists(path):
            path = os.path.join(_S.DATA_FILES, arc)
        d = open(path, "rb").read()
        b = next(x for x in _U.banks(d, _U.elf_symbols(d)) if x["name"] == bank)
        _ORIG[key] = _U.decode_indices(d, *b["pages"][page])
    x0, y0, x1, y1 = rect
    return _ORIG[key][y0:y1, x0:x1]


def _erode(mask, n):
    m = mask.copy()
    for _ in range(n):
        p = np.pad(m, 1)
        m = m & p[:-2, 1:-1] & p[2:, 1:-1] & p[1:-1, :-2] & p[1:-1, 2:]
    return m


def emblem(fill, rings, shadow=(), plate=None, dy=0):
    """The word (two capitals) in `ringfill` colours on a 32 x 32 canvas; `plate` = (page, rect, depth, inner, drop) keeps the
    tile or ring of the original emblem: its edge `depth` pixels deep is copied (index in `drop` = old letter, replaced by `inner`),
    the inside is flat `inner`."""
    inner_style = ringfill(fill, rings, shadow)
    cut = _emblem_cut(inner_style, plate, dy)
    cut.raw = inner_style                           # the bare word (to measure it)
    return cut


def _emblem_cut(inner_style, plate, dy):
    def cut(ink, base):
        art, _ = inner_style(ink, base)
        out = np.zeros((32, 32), np.uint8)
        mid = (16, 16)
        if plate:
            out, mid = _plate(*plate)
        H, W = art.shape
        y, x = mid[0] - H // 2 + dy, mid[1] - W // 2
        area = out[y:y + H, x:x + W]
        area[art > 0] = art[art > 0]
        return out, 0
    return cut


def _plate(kind, page, rect):
    """The tile (kind "tile") or the ring and disc (kind "disc") of an emblem, cleaned of its kanji, from the untouched file."""
    old = _orig_rect("gdt_scs.arc", "y4_mmk_1", page, rect)
    solid = old > 0
    ys, xs = np.nonzero(solid)
    out = np.zeros((32, 32), np.uint8)
    if kind == "tile":                       # 選: a red tile; the sweep of the kanji left of it is dropped
        x0, x1, y0, y1 = xs.min() + 3, xs.max() + 1, ys.min(), ys.max() + 1
        out[y0:y1, x0:x1] = 2                # pale blue edge
        out[y0 + 1:y1 - 1, x0 + 1:x1 - 1] = 5     # dark red border
        out[y0 + 2:y1 - 2, x0 + 2:x1 - 2] = 7     # red tile
        out[y0 + 2, x0 + 2:x1 - 2] = 9            # light top edge
        for cy, cx in ((y0, x0), (y0, x1 - 1), (y1 - 1, x0), (y1 - 1, x1 - 1)):
            out[cy, cx] = 0
        return out, ((y0 + y1) // 2, (x0 + x1) // 2)
    cy, cx = (ys.min() + ys.max()) / 2.0, (xs.min() + xs.max()) / 2.0      # disc
    r = (ys.max() - ys.min() + 1) / 2.0
    yy, xx = np.mgrid[0:32, 0:32]
    dist = np.hypot(yy - cy, xx - cx)
    out = np.where(solid & (dist > r - 4.5), old, 0).astype(np.uint8)
    out[np.isin(out, (2, 3, 4, 5, 6)) & (dist > r - 4.5)] = 10
    out[dist <= r - 4.5] = 12
    return out, (int(round(cy)), int(round(cx)))


# 選 (palette 23): red tile, white capitals in dark red
STYLES["c2_emb_03"] = emblem([15, 15, 15, 14, 14, 14, 14, 14], [4], [], ("tile", 1, (64, 0, 96, 32)), dy=-1)
# 極 (palette 43): pale lilac capitals, purple outline, blue shadow
STYLES["c2_emb_05"] = emblem([7, 6, 6, 5, 5, 4, 4, 3], [1, 1], [13, 15])
# て (palette 45): blue capitals, pale cyan outline, blue shadow
STYLES["c2_emb_06"] = emblem([14, 14, 14, 14, 14, 14, 14, 14], [10], [5])
# 浪 (palette 36): white capitals, dark purple outline, lilac shadow
STYLES["c2_emb_08"] = emblem([1, 1, 2, 2, 3, 3, 3, 3], [7, 7], [10])
# ぴ (palette 37): white capitals, royal blue outline, sky blue ring
STYLES["c2_emb_09"] = emblem([15, 15, 14, 14, 13, 13, 12, 12], [2, 2], [9])
# 覇 (palette 47): dark capitals on the pale grey disc of a red ring
STYLES["c2_emb_0b"] = emblem([2, 2, 2, 2, 3, 3, 3, 3], [12], [], ("disc", 1, (32, 0, 64, 32)), dy=0)
# ど (palette 44): black capitals, pale blue outline
STYLES["c2_emb_0d"] = emblem([2, 2, 3, 3, 2, 2, 1, 1], [10, 9], [7])


for _k in list(STYLES):
    if _k.startswith("c2_emb_"):
        STYLES["c2_embm" + _k[6:]] = STYLES[_k].raw
