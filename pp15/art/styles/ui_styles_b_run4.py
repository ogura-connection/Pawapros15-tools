"""Label styles of art run 4, agent B (sct_titl.arc, sct_g_cd.arc, sct_a_pr.arc, sct_a_sy.arc). Loaded by pp15/art/typeset.py.
Colours are read from the Japanese lettering of each palette; every style is crisp (solid rings, fill ramps only)."""
from .ui_styles_ore_ini import ringfill
from pp15.art import typeset as ui_type

ui_type.TTF["b4uni"] = ("/System/Library/Fonts/Supplemental/Arial Unicode.ttf", 0)       # has the star of the messenger lines

STYLES = {}

# ---- sct_g_cd.arc z4_gmc_0: white letters, near-black ring, teal / olive / blue glow (palettes 93, 84, 90, 28, 44, 24, 21) ---------
STYLES["b4_gm"] = ringfill([15, 15, 15, 14, 13, 12], [4, 4], [3, 2])
# orange / yellow tab words (palettes 98 / 99; the dark twin copy in 100 / 101 is the same art)
STYLES["b4_or"] = ringfill([15, 15, 15, 14, 14, 13], [8, 6])
# ---- sct_g_cd.arc z4_gmd_0 -------------------------------------------------------------------------------------------------
STYLES["b4_gd_blue"] = ringfill([5, 4, 3, 3, 2, 2], [8, 8], [10])                        # pal 18: blue letters, white ring
STYLES["b4_gd_black"] = ringfill([1], [1, 1, 1], [1, 1])                                   # pal 13: the black twin of the blue line
STYLES["b4_gd_green"] = ringfill([15, 14, 14, 13, 12, 12], [4, 4], [3, 2])                 # pal 20: lime letters, black ring
STYLES["b4_gm_s"] = ringfill([15, 15, 15, 14, 13, 12], [4], [3])                           # the same on small plates: one ring, one shadow row

# ---- sct_a_pr.arc z4_edr_0 (Eikan Nine practice-order screen) -----------------------------------------------------------------------
STYLES["b4_pr_tab"] = ringfill([15, 15, 15, 14, 13, 12], [4, 4, 3, 2])                     # pal 40-43: white letters, dark ring, coloured glow
STYLES["b4_pr_head"] = ringfill([15, 15, 14, 13, 12, 11], [4, 4], [3])                     # pal 49 / 56: column heads and "Active" on a teal plate
STYLES["b4_pr_pos"] = ringfill([15, 15, 14, 14, 13, 13], [3])                              # pal 52 / 53: position glyphs, black on a light cell
STYLES["b4_pr_col"] = ringfill([6, 4, 3, 2, 2, 4], [8, 8], [14])                           # pal 61-63: brown / blue / green letters, white ring (hands, years)
STYLES["b4_pr_msg"] = ringfill([3, 2, 1, 1, 1, 2], [8, 8, 8], [12, 13])                    # pal 64-68: dark letters, white band, pale glow (practice orders)
STYLES["b4_pr_head_s"] = ringfill([15, 15, 14, 13, 12, 11], [4])                           # the same with one ring: heads of 32 px cells (two arts fit one 24 row cell)

# ---- sct_a_sy.arc z4_esy_0 (system settings: chalk on the blackboard, palette 24) ----------------------------------------------------------
STYLES["b4_sy"] = ringfill([15, 15, 14, 14, 13, 13], [3])                                  # chalk white, a dark green ring so the strokes stay solid

# ---- sct_titl.arc: the Eikan Nine title logo (bank r4_eik, 8-bit pages 0-2: a 304 x 128 picture, colour table palette 144) ----------------------
# The art is redrawn whole (as run 3's logo2 does for scc_tops.arc) and every page rectangle takes its window of it.
import os, functools
import numpy as np

from pp15 import config
from . import ui_styles_a_run3 as _A3

_B = os.path.join(config.UI_PAGES_DIR, "run4", "B")
LOGO_X = (0, 128, 256)                                           # canvas column of page 0, 1, 2


def _logo_in():
    return np.load(os.path.join(_B, "logo_orig_canvas.npy")), np.load(os.path.join(_B, "logo_pal.npy"))


def _dilate(m, up=3, left=3, down=5, right=5):
    out = m.copy()
    H, W = m.shape
    for dy in range(-up, down + 1):
        for dx in range(-left, right + 1):
            sy0, sy1 = max(0, -dy), min(H, H - dy)
            sx0, sx1 = max(0, -dx), min(W, W - dx)
            out[sy0 + dy:sy1 + dy, sx0 + dx:sx1 + dx] |= m[sy0:sy1, sx0:sx1]
    return out


def _propagate(rgb, mask, valid):
    """Fill `mask` pixels from the valid pixels round them, layer by layer (each takes the mean of its valid 8-neighbours)."""
    out = rgb.copy(); ok = valid & ~mask; todo = mask.copy()
    H, W = mask.shape
    while todo.any():
        pk = np.pad(ok, 1); pc = np.pad(out, ((1, 1), (1, 1), (0, 0)))
        cnt = np.zeros(mask.shape); acc = np.zeros(out.shape)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dy or dx:
                    sel = pk[1 + dy:1 + dy + H, 1 + dx:1 + dx + W]
                    cnt += sel
                    acc += pc[1 + dy:1 + dy + H, 1 + dx:1 + dx + W] * sel[..., None]
        now = todo & (cnt > 0)
        if not now.any():
            break
        out[now] = acc[now] / cnt[now][:, None]
        ok = ok | now; todo = todo & ~now
    return out


def sct_logo(title="Eikan Nine", sub="Build a Powerhouse Club!", tcap=34, tsq=0.9, tstroke=0.35, scap=12, ssq=0.9, sstroke=0.0, tcx=146, tcy=59, scx=148, scy=100):
    A = _A3
    c, pal = _logo_in()
    q = A.Quant(pal, c)
    rgb = pal[c][..., :3].astype(float)
    ri = pal[c][..., :3].astype(int)
    lum = 0.299 * ri[..., 0] + 0.587 * ri[..., 1] + 0.114 * ri[..., 2]
    plate = (lum < 125) & (ri[..., 2] >= ri[..., 0] - 4) & (ri[..., 2] >= ri[..., 1] - 10) & (pal[c][..., 3] > 0)
    new = c.copy()
    H, W = c.shape
    # --- erase the Japanese title: letters + their outline / shadow are cut out of the plate rows and filled from the plate beside them
    zone = np.zeros(c.shape, bool)
    for y in range(33, 87):
        L = next((x for x in range(26, 100) if plate[y, x:x + 5].all()), 40)
        R = next((x for x in range(290, 150, -1) if plate[y, x - 4:x + 1].all()), 250)
        zone[y, L + 4:R - 3] = True
    letters = zone & ~plate
    mask = _dilate(letters, 3, 3, 5, 5) & zone
    rgb2 = A.row_inpaint(rgb, mask, valid=plate & ~mask)
    new[mask] = q(rgb2[mask])
    # --- the new title
    m, base = A.crisp_mask(title, tcap, font="condbi", stroke=tstroke, squeeze=tsq)
    m = A.despeckle(m)
    h, w = m.shape
    pad = 4
    big = np.zeros((h + 2 * pad, w + 2 * pad), bool); big[pad:pad + h, pad:pad + w] = m
    out = np.zeros(big.shape + (3,)); alpha = np.zeros(big.shape, bool)
    bevel = A.grow(big, 1)
    shadow = A.shift(bevel, 2, 2) | A.shift(bevel, 1, 2) | A.shift(bevel, 2, 1)
    out[shadow] = (16, 16, 32); alpha |= shadow
    out[bevel] = (214, 216, 232); alpha |= bevel                         # silver bevel ring, as the Japanese lettering has
    ring = A.grow(bevel, 1, diag=False) & ~bevel
    out[ring] = (40, 40, 72); alpha |= ring
    ys = np.nonzero(big.any(1))[0]
    g = A.grad_rows(A.TITLE_GRAD, ys.max() - ys.min() + 1)
    rowc = np.zeros((big.shape[0], 3)); rowc[ys.min():ys.max() + 1] = g
    out[big] = np.broadcast_to(rowc[:, None, :], big.shape + (3,))[big]; alpha |= big
    hi = big & ~A.shift(big, 1, 0)
    out[hi] = (255, 250, 225)
    y0, x0 = tcy - big.shape[0] // 2, tcx - big.shape[1] // 2
    reg = (slice(y0, y0 + big.shape[0]), slice(x0, x0 + big.shape[1]))
    new[reg][alpha] = q(out[alpha])
    # --- subtitle: the old lettering and its cream halo are cut out of the green (rows filled from the green on both sides), the new
    # words are set in the same brown with a cream halo of their own, as the Japanese had
    green = (ri[..., 1] > ri[..., 0] + 40) & (ri[..., 1] > ri[..., 2] + 40) & (lum < 190)
    reg = np.zeros(c.shape, bool); reg[85:118, 38:266] = True
    rim = _dilate(pal[c][..., 3] == 0, 3, 3, 3, 3)                          # the white edge of the whole logo stays
    old = reg & ~green & ~plate & ~rim & (pal[c][..., 3] > 0)
    old = _dilate(old, 1, 1, 1, 1) & reg & ~green & ~plate & ~rim
    # the green behind the band: rows read from the green that still shows inside it (between the old letters at the top, in the point
    # below), the rows between them interpolated top to foot; the picture beside the band is darker at the top and lighter below it
    inner = np.zeros(c.shape, bool); inner[:, 66:234] = True
    known = {}
    for y in range(86, 117):
        px = rgb[y][green[y] & inner[y] & ~old[y]]
        if len(px) >= 3:
            known[y] = np.median(px, axis=0)
    ys_k = sorted(known)
    rgb3 = rgb.copy()
    for y in range(86, 117):
        row = np.array([np.interp(y, ys_k, [known[k][ch] for k in ys_k]) for ch in range(3)])
        rgb3[y][old[y]] = row
    new[old] = q(rgb3[old])
    sm, sbase = A.crisp_mask(sub, scap, font="condb", stroke=sstroke, squeeze=ssq)
    sm = A.despeckle(sm)
    sh_, sw_ = sm.shape
    pad2 = 5
    sbig = np.zeros((sh_ + 2 * pad2, sw_ + 2 * pad2), bool); sbig[pad2:pad2 + sh_, pad2:pad2 + sw_] = sm
    halo = A.grow(sbig, 3); edge = A.grow(halo, 1, diag=False) & ~halo
    sy0 = scy - sbig.shape[0] // 2; sx0 = scx - sbig.shape[1] // 2
    sreg = (slice(sy0, sy0 + sbig.shape[0]), slice(sx0, sx0 + sbig.shape[1]))
    new[sreg][edge] = q(np.array([(255, 255, 255)]))[0]
    new[sreg][halo] = q(np.array([(255, 252, 232)]))[0]
    new[sreg][sbig] = q(np.array([(98, 41, 16)]))[0]
    return new, (w, h), (sw_, sh_)


@functools.lru_cache(None)
def _logo():
    return sct_logo()[0]


def _logo_window(c0, c1):
    def style(ink, base):
        return _logo()[:, c0:c1].copy(), 0
    return style


STYLES["b4_eik0"] = _logo_window(0, 128)           # page 0 rect 0,0,128,128
STYLES["b4_eik1"] = _logo_window(128, 256)         # page 1 rect 0,0,128,128
STYLES["b4_eik2"] = _logo_window(256, 304)         # page 2 rect 0,0,48,128

# ---- sct_titl.arc r4_eikz page 4 / 5: the info card of the Continue screen (green letters, white ring, blue glow; palettes 1 / 7) ----------------
STYLES["b4_info"] = ringfill([9, 8, 5, 3, 2, 1], [10, 10, 12], [15, 15])
STYLES["b4_info2"] = ringfill([13, 15, 15, 15, 13, 11], [7, 7], [5, 4])                    # palette 7: dark green letters, white ring, pale glow (card labels)
