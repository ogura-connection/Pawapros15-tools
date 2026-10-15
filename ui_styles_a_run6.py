"""Label styles of art run 6, agent A (pn_trade.arc, gdt_pn.arc, pnbg_sum.arc, pnbg_fal.arc). Loaded by ui_type.py.
Colours are read from the Japanese lettering; every style is crisp (solid rings, fill ramps only)."""
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat

STYLES = {}

# ---- g3_ptf_0 (plain black / red lettering on a light plate, no ring) -------------------------------------------------
STYLES["a6_ptf_black"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)       # pal 121: index 1 = black
STYLES["a6_ptf_red"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)         # pal 122: index 1 = red

# ---- g3_ptk_0 (cyan-white letters, azure and blue rings, dark blue shadow) --------------------------------------------
STYLES["a6_ptk_item"] = ringfill([15, 14, 13, 12, 11, 10], [7, 3], [1, 1])      # pal 101
STYLES["a6_ptk_any"] = ringfill([15, 14, 13, 12, 11, 10], [5, 3], [1, 1])       # pal 100: pink-white, purple rings
STYLES["a6_ptk_help"] = ringfill([12, 12, 11, 11, 10, 10], [1, 4], [6])        # pal 131: purple letters, white ring
STYLES["a6_ptk_big"] = ringfill([9, 9, 8, 8, 7, 7], [10, 12, 14], [2, 2])      # pal 102: the 3-line notice

# ---- g3_pt_0 ------------------------------------------------------------------------------------------------------------
STYLES["a6_head_green"] = ringfill([8, 9, 10, 11, 13, 15], [5, 2], [])                 # pal 97: lime letters, blue ring (headings 08, 09)
STYLES["a6_pt_title"] = ringfill([15, 14, 11, 12, 12, 13], [5, 1], [8, 8])                  # pal 98: orange titles, white ring, blue ring
STYLES["a6_tab"] = ringfill([1, 1, 2, 2, 3, 3], [8, 9], [11, 13])                       # tabs and column headings: dark letters, white ring
STYLES["a6_btn_white"] = ringfill([1, 1, 1, 1, 1, 1], [4, 14], [7])                    # pal 57: white letters
STYLES["a6_btn_navy"] = ringfill([2, 2, 2, 2, 2, 2], [1, 11], [7])                     # pal 55 / 39 family: navy letters, white ring
STYLES["a6_btn_purple"] = ringfill([6, 6, 6, 6, 6, 6], [1, 14], [7])                   # pal 42
STYLES["a6_btn_olive"] = ringfill([15, 14, 14, 13, 13, 12], [1, 2], [8, 4])            # pal 38
STYLES["a6_btn_green"] = ringfill([3, 3, 3, 8, 8, 8], [1, 14], [7])                    # pal 58: green letters
STYLES["a6_btn_crimson"] = ringfill([6, 6, 6, 6, 6, 6], [1, 14], [7])                  # pal 58: crimson letters
STYLES["a6_btn_brown"] = ringfill([5, 5, 5, 5, 5, 5], [1, 14], [7])                    # pal 39
STYLES["a6_pt_out"] = ringfill([1, 1, 1, 2, 2, 2], [11, 13], [15])                      # pal 99: "'s Outgoing Players"
STYLES["a6_banner"] = ringfill([12, 12, 13, 13, 14, 14], [3, 10, 8], [2, 1])              # pal 103: "No trade requests pending!"
STYLES["a6_empty"] = ringfill([8, 8, 7, 7, 6, 6], [3, 11, 13], [2, 1])                    # pal 104: "List / Empty"
STYLES["a6_noplayers"] = ringfill([4, 4, 5, 5, 6, 6], [3], [])                          # pal 110: "No Players"

# ---- g3_pts_0 -----------------------------------------------------------------------------------------------------------
STYLES["a6_pts_head"] = ringfill([1, 1, 1, 2, 2, 3], [9, 12], [])                       # pal 120: dark brown letters, tan edge

# ---- h3_ydm_0 (gdt_pn.arc) ----------------------------------------------------------------------------------------------
STYLES["a6_ydm_item"] = ringfill([15, 15, 15, 15, 15, 14], [2])                    # pal 4: white letters, one blue ring

import numpy as np
from ui_styles_ore_ini import _orig_page

K = 60                                          # the baseline row every whole-rectangle style below returns (the label sets it too)


def _win(full, c0, c1):
    return full[:, c0:c1], K


def _flat_bg(inner, bg, H, W, window, vcentre=None):
    """Lettering on a flat opaque rectangle (the logo banners): the art is centred on an H x W canvas of palette index `bg`."""
    def style(ink, base):
        art, b = inner(ink, base)
        full = np.full((H, W), bg, np.uint8)
        h, w = art.shape
        top = (H - h) // 2 if vcentre is None else vcentre - h // 2
        left = (W - w) // 2
        sub = full[top:top + h, left:left + w]
        sub[art > 0] = art[art > 0]
        return _win(full, *window)
    return style


# ---- pnbg_sum.arc / pnbg_fal.arc: the "Pennant Race" logos (white banner, pale ring round white letters) -------------------
_LOGO = ringfill([15, 15, 15, 15, 15, 15], [8, 6, 4, 3])
for _name, _W in (("a6_pbg2", 176), ("a6_pbg3", 184)):
    STYLES[_name] = _flat_bg(_LOGO, 15, 48, _W, (0, _W))
for _c0, _c1 in ((0, 32), (32, 120), (120, 176)):
    STYLES["a6_pbg2~%d_%d" % (_c0, _c1)] = _flat_bg(_LOGO, 15, 48, 176, (_c0, _c1))
for _c0, _c1 in ((0, 128), (128, 184)):
    STYLES["a6_pbg3~%d_%d" % (_c0, _c1)] = _flat_bg(_LOGO, 15, 48, 184, (_c0, _c1))

# ---- g3_pts_0 sprite 01: the "Trade Request" strip (white letters on the brown paper strip) ---------------------------------
_TITLE_INK = ringfill([15, 15, 15, 15, 15, 15], [2])
_strip_cache = []


def _strip():
    """The original 48 x 176 strip (three page rectangles side by side) with the Japanese letters painted out."""
    if _strip_cache:
        return _strip_cache[0].copy()
    pg = _orig_page("pn_trade.arc", "g3_pts_0", 1)
    S = np.hstack([pg[32:80, 16:56], pg[80:128, 16:112], pg[32:80, 72:112]]).astype(np.uint8)
    mask = np.zeros(S.shape, bool)
    mask[6:36, 6:170] = S[6:36, 6:170] >= 11
    grow_ = mask.copy()
    for dy in (-1, 0, 1):
        for dx in (-1, 0, 1):
            grow_ |= np.roll(np.roll(mask, dy, 0), dx, 1)
    mask = grow_ & (np.arange(48)[:, None] >= 5) & (np.arange(48)[:, None] < 38)
    out = S.copy()
    H, W = S.shape
    for x in range(W):
        for y in np.nonzero(mask[:, x])[0]:
            up = next((y - d for d in range(1, 30) if y - d >= 3 and not mask[y - d, x]), None)
            dn = next((y + d for d in range(1, 30) if y + d < 42 and not mask[y + d, x]), None)
            src = up if (dn is None or (up is not None and (y - up) <= (dn - y))) else dn
            out[y, x] = S[src, min(max(x + ((y - src) // 3), 4), 168)] if src is not None else S[y, x]
    _strip_cache.append(out)
    return out.copy()


def _title_strip(window):
    def style(ink, base):
        art, b = _TITLE_INK(ink, base)
        full = _strip()
        h, w = art.shape
        top = 21 - h // 2
        left = 88 - w // 2
        sub = full[top:top + h, left:left + w]
        sub[art > 0] = art[art > 0]
        return _win(full, *window)
    return style


for _c0, _c1 in ((0, 40), (40, 136), (136, 176)):
    STYLES["a6_pts_title~%d_%d" % (_c0, _c1)] = _title_strip((_c0, _c1))

# ---- g3_pts_0 sprite 0e: the red approval stamp, re-drawn as a ring round red "OK" ------------------------------------------
_STAMP_INK = ringfill([1, 1, 1, 2, 2, 3], [15])


def _stamp(ink, base):
    art, b = _STAMP_INK(ink, base)
    full = np.zeros((80, 80), np.uint8)
    ring = {35: 15, 34: 15, 33: 1, 32: 1, 31: 1, 30: 1, 29: 14, 28: 15}      # radial profile read from the top of the original
    for y in range(80):
        for x in range(80):
            r = ((y - 39.5) ** 2 + (x - 39.5) ** 2) ** 0.5
            full[y, x] = ring.get(int(r), 0)
    h, w = art.shape
    top = 40 - h // 2
    left = 40 - w // 2
    sub = full[top:top + h, left:left + w]
    sub[art > 0] = art[art > 0]
    return full, K


STYLES["a6_pts_stamp"] = _stamp

STYLES["a6_ydm_gold"] = ringfill([11, 10, 9, 5, 4, 3], [2, 13], [15, 15])                # pal 7: gold calligraphy, brown ring, white, lilac shadow

STYLES["a6_pbg_ink"] = _LOGO
