"""Label styles of art run 6, agent E (draft.arc g3_pd_0, pn_deban.arc m3_ksd_0 / s5_ptn / b5_r00, pnbg_spr.arc, pnbg_win.arc).
Loaded by pp15/art/typeset.py. Read by hand from the colour histograms of the Japanese lettering (indices of each page's palette).
Keep importable at every moment."""
import os
import numpy as np
from pp15.art import typeset as ui_type
from pp15.art import textures as _U
from pp15.script import scan as _S
from .ui_styles_ore_ini import ringfill

STYLES = {}
_OLD = {}


def win(style, c0, c1):
    """Only the columns c0..c1 of the whole word (a word shared out over parts that stand side by side)."""
    def cut(ink, base):
        art, b = style(ink, base)
        out = art[:, c0:c1]
        if out.shape[1] == 0:
            out = np.zeros((art.shape[0], 1), np.uint8)
        return out, b
    return cut


def _old(arcname, bank, pg):
    if arcname not in _OLD:
        p = os.path.join(_U.ORIG_ARC_DIR, arcname)
        if not os.path.exists(p):
            p = os.path.join(_S.DATA_FILES, arcname)
        d = open(p, "rb").read()
        _OLD[arcname] = (d, {x["name"]: x for x in _U.banks(d, _U.elf_symbols(d))})
    d, bs = _OLD[arcname]
    return _U.decode_indices(d, *bs[bank]["pages"][pg])


def _components(fg):
    """8-connected components of a boolean array: list of lists of (y, x)."""
    seen = np.zeros(fg.shape, bool)
    out = []
    for y, x in zip(*np.nonzero(fg)):
        if seen[y, x]:
            continue
        st = [(y, x)]; seen[y, x] = True; comp = []
        while st:
            cy, cx = st.pop(); comp.append((cy, cx))
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    ny, nx = cy + dy, cx + dx
                    if 0 <= ny < fg.shape[0] and 0 <= nx < fg.shape[1] and fg[ny, nx] and not seen[ny, nx]:
                        seen[ny, nx] = True; st.append((ny, nx))
        out.append(comp)
    return out


def pill(arcname, bank, rect, kind, inner, cx, cy, white=15, top_pale=None, shear=0.0):
    """The old picture of `rect` (page, x0, y0, x1, y1) with its kanji painted out and the English (`inner` style) centred
    at (cx, cy), tilted by `shear` (rows per column, rising to the right). The picture is the label's art: use it with
    "left": 0, "baseline": 0.
    kind "badge": columns 5-21: rows below `top_pale` white (index `white`), rows above the pale plate colour (1);
    kind "disc": the inside of the round stamp (radius 10.5) white; kind "stamp": every piece of ink but the biggest white."""
    def style(ink, base):
        pg, x0, y0, x1, y1 = rect
        pic = _old(arcname, bank, pg)[y0:y1, x0:x1].copy()
        if kind == "badge":
            pic[4:top_pale, 4:22] = 1
            pic[top_pale:25, 4:22] = white
        elif kind == "disc":
            yy, xx = np.mgrid[0:pic.shape[0], 0:pic.shape[1]]
            pic[((yy - 15.5) ** 2 + (xx - 15.5) ** 2) < 10.5 ** 2] = white
        else:
            strong = (pic >= 1) & (pic <= 6)
            comps = _components(strong)
            comps.sort(key=len)
            rim = np.zeros(pic.shape, bool)
            for y, x in comps[-1]:
                rim[y, x] = True
            gone = np.zeros(pic.shape, bool)
            for comp in comps[:-1]:
                for y, x in comp:
                    gone[y, x] = True
            for _ in range(3):
                g2 = gone.copy()
                g2[1:] |= gone[:-1]; g2[:-1] |= gone[1:]; g2[:, 1:] |= gone[:, :-1]; g2[:, :-1] |= gone[:, 1:]
                g2[1:, 1:] |= gone[:-1, :-1]; g2[:-1, :-1] |= gone[1:, 1:]; g2[1:, :-1] |= gone[:-1, 1:]; g2[:-1, 1:] |= gone[1:, :-1]
                gone = g2
            pic[gone & ~rim & (pic != 0)] = white
        art, b = inner(ink, base)
        h, w = art.shape
        x = cx - w // 2
        y = int(round(cy - h / 2))
        ys, xs = np.nonzero(art)
        for yy, xx in zip(ys, xs):
            dy = -int(round((xx - w / 2.0) * shear))
            py, px = y + yy + dy, x + xx
            if 0 <= py < pic.shape[0] and 0 <= px < pic.shape[1]:
                pic[py, px] = art[yy, xx]
        return pic, 0
    return style


def onwhite(inner, W, H, bg=15, nudge=0):
    """The letters on a W x H canvas of colour `bg`, centred (the logo sprites carry their own white board)."""
    def style(ink, base):
        art, b = inner(ink, base)
        h, w = art.shape
        out = np.full((H, W), bg, np.uint8)
        x, y = (W - w) // 2, (H - h) // 2 + nudge
        sub = out[max(y, 0):y + h, max(x, 0):x + w]
        a = art[max(-y, 0):max(-y, 0) + sub.shape[0], max(-x, 0):max(-x, 0) + sub.shape[1]]
        sub[a > 0] = a[a > 0]
        return out, y + b
    return style


# ---- g3_pd_0 (draft.arc): buttons on the draft screen: navy / green / blue / brown / purple letters, white ring, blue shadow
S = STYLES
S["e6_pd_00"] = ringfill([2], [1], [9, 12])
S["e6_pd_05"] = ringfill([3], [1], [9, 12])
S["e6_pd_06"] = ringfill([4], [1], [9, 12])
S["e6_pd_07"] = ringfill([15], [1], [8, 14])
S["e6_pd_08"] = ringfill([5], [1], [10, 13])
S["e6_pd_09"] = ringfill([15], [1], [8, 14])
S["e6_pd_0d"] = ringfill([5], [1], [9, 11])
S["e6_pd_0e"] = ringfill([6], [1], [9, 11])
S["e6_pd_47"] = ringfill([6], [1], [9, 11])
S["e6_pd_title"] = ringfill([15, 15, 14, 14, 14, 12], [1, 1, 6], [10, 10])
S["e6_pd_14"] = ringfill([8], [3], [10])
S["e6_pd_lime"] = ringfill([15, 13, 13, 11, 11, 11], [5, 5], [7])
S["e6_pd_pos"] = ringfill([10], [15], [12, 11])
S["e6_pd_3c"] = ringfill([12, 11, 10, 9, 8, 7], [1, 1, 2])
S["e6_pd_3e"] = ringfill([3, 3, 2, 2, 1, 1], [8, 13])
S["e6_pd_help"] = ringfill([1], [8])
S["e6_pd_red"] = ringfill([1], [8])
S["e6_pd_stampfill"] = ringfill([1], [15])
S["e6_in_badge"] = ringfill([7], [12])
# letters on the round / tilted stamps and the school badges: the old picture with the English drawn over it
_D = ("draft.arc", "g3_pd_0")
S["e6_pd_25"] = pill(*_D, [3, 32, 96, 64, 128], "badge", S["e6_in_badge"], 13, 14, white=12, top_pale=9)
S["e6_pd_26"] = pill(*_D, [3, 64, 96, 96, 128], "badge", S["e6_in_badge"], 13, 14, white=12, top_pale=9)
S["e6_pd_27"] = pill(*_D, [3, 96, 96, 128, 128], "badge", S["e6_in_badge"], 13, 14, white=12, top_pale=9)
S["e6_pd_36"] = pill(*_D, [8, 0, 0, 32, 32], "disc", S["e6_pd_stampfill"], 16, 16)
S["e6_pd_37"] = pill(*_D, [8, 32, 0, 64, 32], "disc", S["e6_pd_stampfill"], 16, 16)
S["e6_pd_38"] = pill(*_D, [8, 0, 32, 64, 80], "stamp", S["e6_pd_stampfill"], 32, 23, shear=0.17)
S["e6_pd_39"] = pill(*_D, [8, 0, 80, 64, 128], "stamp", S["e6_pd_stampfill"], 32, 23, shear=0.17)
S["e6_pd_3c~0_128"] = win(S["e6_pd_3c"], 0, 128)
S["e6_pd_3c~128_4096"] = win(S["e6_pd_3c"], 128, 4096)
# ---- m3_ksd_0 (pn_deban.arc)
S["e6_ks_title"] = ringfill([12, 12, 11, 11, 9, 8], [2, 2, 15], [1])
S["e6_ks_title~0_4096"] = S["e6_ks_title"]
S["e6_ks_help"] = ringfill([1], [8])
S["e6_ks_05"] = ringfill([15], [9], [3])
S["e6_ks_focus"] = ringfill([15], [5], [1])
S["e6_ks_plate"] = ringfill([3], [15], [1])
S["e6_ks_on"] = ringfill([1], [15], [2])
S["e6_ks_cond"] = ringfill([1], [15])
S["e6_ks_pick"] = ringfill([4], [15], [2])
# ---- s5_ptn / b5_r00 / the pennant logos
S["e6_sk"] = ringfill([15], [4])
S["e6_b5"] = ringfill([14], [2])
S["e6_b5_small"] = ringfill([1], [12])
_LOGO = ringfill([8, 8, 8, 9, 9, 9], [15, 15, 6, 6])
S["e6_logo_in"] = _LOGO
S["e6_logo_pbg"] = onwhite(_LOGO, 184, 48)
S["e6_logo_pbg4"] = onwhite(_LOGO, 184, 40)     # pnbg_win: the only room for the 80-wide strip is 80 x 40


def arrow(inner):
    """A right arrow (the English has no glyph for it) drawn through `inner`'s rings and shadow, centred on the capitals."""
    def style(ink, base):
        a = np.zeros((11, 22), int)
        a[4:7, 0:17] = 6
        for k in range(6):
            half = 5 - k
            a[5 - half:6 + half, 16 + k] = 6
        art, b = inner(a, 11)
        return art, b + 2
    return style


S["e6_ks_arrow"] = arrow(S["e6_ks_plate"])
# windows of one word over several parts are added by mkcuts below
