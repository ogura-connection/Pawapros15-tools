"""Styles for large English title logos that are pictures cut over several pages of a sprite sheet.

The player sees them on the Hakkyu Dream title screen, the home-run mode title, the Pennant start screen and the My Life title. The pictures are rebuilt from the untouched .arc file and cached.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): homerun, pena_ini, pn_acivt, ore_ini.
"""
import os
import sys
import functools
import numpy as np
import importlib.util as _iu
from PIL import Image
from pp15.art import typeset as ui_type
from . import logo_front_panel as A

STYLES = {}


# ---- scc_tops.arc / scs_titl.arc: the Hakkyu Dream logo (y5_tic_0 pages 0-1) -----------------------------------------

OV = 4
def disc_dilate(m, r):
    """round dilation of boolean hi-res mask by radius r (hi-res px)."""
    if r <= 0: return m.copy()
    ri = int(np.ceil(r)); H, W = m.shape
    p = np.pad(m, ri); out = np.zeros_like(m)
    for dy in range(-ri, ri + 1):
        for dx in range(-ri, ri + 1):
            if dy * dy + dx * dx <= r * r + 0.25:
                out |= p[ri + dy:ri + dy + H, ri + dx:ri + dx + W]
    return out

def shift_hi(m, dy, dx):
    return A.shift(m, dy, dx)

def hires_cov(text, cap, font, stroke, sq, track, s0=1.0, s1=1.0, rise=0, slant=0.0):
    """hi-res coverage (float) of text at OV x, letters growing s0 -> s1 left to right, baseline climbing `rise` px."""
    cov, base, ov = A.rendertext(text, cap, font=font, stroke=stroke, squeeze=sq, over=OV, track=track, slant=slant)
    H, W = cov.shape
    xs = np.nonzero(cov.max(0) > 0.02)[0]
    cov = cov[:, xs.min():xs.max() + 1]; W = cov.shape[1]
    if s0 == 1.0 and s1 == 1.0 and not rise:
        ys = np.nonzero(cov.max(1) > 0.02)[0]
        return cov[ys.min():ys.max() + 1]
    outH = int((H / ov) * max(s0, s1, 1.0) + rise + 8) * ov
    ob = int(outH - (H - base) / ov * max(s0, s1, 1.0) * ov - 4 * ov)
    out = np.zeros((outH, W), np.float32); yy = np.arange(outH)
    for X in range(W):
        t = X / max(W - 1, 1); s = s0 + (s1 - s0) * t; yb = ob - rise * ov * t
        src = base + (yy - yb) / s
        lo = np.floor(src).astype(int); fr = src - lo
        ok = (lo >= 0) & (lo + 1 < H)
        col = np.zeros(outH, np.float32)
        col[ok] = cov[lo[ok], X] * (1 - fr[ok]) + cov[lo[ok] + 1, X] * fr[ok]
        out[:, X] = col
    ys = np.nonzero(out.max(1) > 0.02)[0]
    return out[ys.min():ys.max() + 1]

def smooth_mask(cov, thr=0.5):
    """cov (float hi-res) -> bool hi-res, with a light blur so the edge has no stair steps."""
    im = Image.fromarray((cov * 255).astype(np.uint8)).filter(__import__("PIL.ImageFilter", fromlist=["x"]).GaussianBlur(OV * 0.45))
    return np.asarray(im, np.float32) / 255.0 >= thr

def compose_layers(face_mask, layers, face_rows, pad=6):
    """face_mask hi-res bool. layers: list of (radius_hi, (r,g,b), None) outermost first (each a dilation of the face).
    Each 1x pixel takes the layer that covers most of it (solid outline, no blended colours); the face takes its row
    gradient. Returns (rgb 1x float, alpha 1x bool)."""
    P = pad * OV
    h, w = face_mask.shape
    H = (h + 2 * P + OV - 1) // OV * OV; W = (w + 2 * P + OV - 1) // OV * OV
    big = np.zeros((H, W), bool); big[P:P + h, P:P + w] = face_mask
    lay = np.zeros((H, W), np.int8)            # 0 none, 1.. layers outer->inner, len+1 face
    for i, (r, col, off) in enumerate(layers):
        d = disc_dilate(big, r)
        if off: d = shift_hi(d, off[0] * OV, off[1] * OV)
        lay[d] = i + 1
    lay[big] = len(layers) + 1
    n = len(layers) + 2
    cnt = np.stack([(lay == k).reshape(H // OV, OV, W // OV, OV).sum((1, 3)) for k in range(n)])
    # coverage thresholds: a pixel belongs to a layer when it is the one with most hi-res samples among non-empty ones,
    # and is drawn at all when >= half covered
    filled = cnt[1:].sum(0)
    pick = cnt[1:].argmax(0) + 1
    al = filled >= (OV * OV) // 2
    ys = np.nonzero(big.any(1))[0]
    nn = (ys.max() - ys.min() + 1)
    g = face_rows(max(nn, 2))
    rowc = np.zeros((H, 3)); rowc[ys.min():ys.max() + 1] = g
    face1 = rowc.reshape(H // OV, OV, 3).mean(1)
    out = np.zeros((H // OV, W // OV, 3))
    for i, (r, col, off) in enumerate(layers):
        out[pick == i + 1] = col
    fm = pick == len(layers) + 1
    out[fm] = np.broadcast_to(face1[:, None, :], out.shape)[fm]
    return out, al

BLUE_FACE = [(0.0, (170, 205, 255)), (0.16, (90, 130, 255)), (0.45, (0, 0, 255)), (0.8, (0, 0, 180)), (1.0, (0, 0, 120))]
SUB_FACE = [(0.0, (255, 250, 150)), (0.5, (255, 205, 40)), (1.0, (255, 130, 0))]

def title_piece(text, cap, sq, trk, s0, s1, rise, font="condbi", stroke=0.25):
    cov = hires_cov(text, cap, font, stroke, sq, trk, s0, s1, rise)
    m = smooth_mask(cov)
    return compose_layers(m, [
        (3.2 * OV / 4 * 1.0 + 2.6, (255, 255, 255), None),        # white border ~ 2.6 px
        (3.0 * 1.0, (0, 0, 90), None),                           # navy edge ~ .75 px
    ], lambda n: A.grad_rows(BLUE_FACE, n))

def sub_piece(text, cap, sq, font="condb", stroke=0.2):
    cov = hires_cov(text, cap, font, stroke, sq, 0.0)
    m = smooth_mask(cov, 0.5)
    return compose_layers(m, [
        (OV * 1.6, (255, 255, 255), None),
        (OV * 0.8, (110, 10, 0), None),
    ], lambda n: A.grad_rows(SUB_FACE, n), pad=3)

def logo(title="Hakkyu Dream", sub="~ Industrial-League Ball! ~", tcap=21, tsq=0.76, trk=1.5, s0=0.82, s1=1.12, rise=6,
         tx=28, tbottom=64, scap=11, ssq=0.9, scx=118, sbottom=80, sfont="condb", sstroke=0.2, twhite=2.6, tnavy=0.8, tstroke=0.1, strk=0.6, shadow=(1, 1)):
    new, c, erase, red = A.erase3()
    pal = A.logo_pal(16); q = A.Quant(pal, c)
    H, W = new.shape
    rgb = np.zeros((H, W, 3)); Am = np.zeros((H, W), bool)
    # pennant continuation
    keepred = red & (new == c) & (new > 0) & ~erase
    top = {}
    for x in range(128, 167):
        col = np.nonzero(keepred[:, x])[0]
        if len(col): top[x] = col.min()
    px = np.array(list(top)); py = np.array([top[x] for x in top])
    k, b0 = np.polyfit(px, py, 1)
    rowcnt = keepred[:40].sum(1); ybot = int(np.nonzero(rowcnt >= 8)[0].max())
    yy, xx = np.mgrid[0:H, 0:W]
    band = (xx >= 98) & (xx <= 172) & (yy >= k * xx + b0 - 0.5) & (yy <= ybot) & (new == 0) & ~keepred
    cyc = np.array(A.WEDGE_ROWS, float)
    for y in range(H):
        m = band[y]
        if not m.any(): continue
        r = pal[c][y][keepred[y]][:, :3] if keepred[y].any() else None
        col = np.median(r, 0) if r is not None else cyc[(y * 7 // 2) % len(cyc)]
        rgb[y][m] = col; Am[y] |= m
    allw = keepred | band
    bord = A.grow(allw, 2) & ~allw & (new == 0)
    rgb[bord] = (255, 255, 255); Am |= bord
    new[Am] = q(rgb[Am]); Am[:] = False
    # title
    cov = hires_cov(title, tcap, "condbi", tstroke, tsq, trk, s0, s1, rise)
    m = smooth_mask(cov)
    tr, ta = compose_layers(m, [(OV * twhite, (255, 255, 255), None), (OV * tnavy, (0, 0, 90), shadow), (OV * tnavy, (0, 0, 90), None)], lambda n: A.grad_rows(BLUE_FACE, n))
    y = tbottom - tr.shape[0]
    sl = (slice(y, y + tr.shape[0]), slice(tx, tx + tr.shape[1]))
    rgb[sl][ta] = tr[ta]; Am[sl] |= ta
    # seam on the ball
    seam = np.zeros((H, W), bool)
    cxs, cys, R = 80.0, 44.0, 35.0
    for ang in np.arange(150, 216, 1.0):
        px_ = cxs + R * np.cos(np.radians(ang)); py_ = cys + R * np.sin(np.radians(ang))
        if np.hypot(px_ - A.BALL[0], py_ - A.BALL[1]) < A.BALL[2] - 2.5: seam[int(py_), int(px_)] = True
    for ang in np.arange(152, 214, 6.0):
        for t in (-2, -1, 1, 2):
            px_ = cxs + (R + t) * np.cos(np.radians(ang)); py_ = cys + (R + t) * np.sin(np.radians(ang))
            if np.hypot(px_ - A.BALL[0], py_ - A.BALL[1]) < A.BALL[2] - 2.5: seam[int(py_), int(px_)] = True
    new[seam & ~Am] = q(np.array([(255, 150, 150)]))[0]
    # subtitle
    cov = hires_cov(sub, scap, sfont, sstroke, ssq, strk)
    m = smooth_mask(cov)
    sr, sa = compose_layers(m, [(OV * 1.6, (255, 255, 255), None), (OV * 0.8, (110, 10, 0), None)], lambda n: A.grad_rows(SUB_FACE, n), pad=3)
    x_ = scx - sr.shape[1] // 2; y_ = sbottom - sr.shape[0]
    sl2 = (slice(y_, y_ + sr.shape[0]), slice(x_, x_ + sr.shape[1]))
    rgb[sl2][sa] = sr[sa]; Am[sl2] |= sa
    new[Am] = q(rgb[Am])
    info = dict(title=(tr.shape[1], tr.shape[0], tx, y), sub=(sr.shape[1], sr.shape[0], x_, y_))
    return new, info

@functools.lru_cache(None)
def _hakkyu():
    return logo()[0]

def _window(fn, y0, y1, x0, x1):
    def style(ink, base):
        return fn()[y0:y1, x0:x1].copy(), 0
    return style

STYLES.update({
    "p11_hak0": _window(_hakkyu, 0, 80, 0, 128),
    "p11_hak1": _window(_hakkyu, 0, 80, 128, 224),
})


# ---- scs_titl.arc y5_tic_h1: the big Hakkyu Dream title logo (sprite 00, canvas 312 x 128, palette 128) -----------------------
_PARTS = [(0, -5, 128), (1, 123, 128), (2, 251, 56)]     # page, canvas x of page column 0, used width
def _h1_orig():
    from pp15.art import textures as U
    d = open(os.path.join(U.ORIG_ARC_DIR, "scs_titl.arc"), "rb").read()
    b = next(x for x in U.banks(d, U.elf_symbols(d)) if x["name"] == "y5_tic_h1")
    c = np.zeros((128, 312), np.uint8)
    for pg, x0, w in _PARTS:
        idx = U.decode_indices(d, *b["pages"][pg])
        for X in range(w):
            if 0 <= x0 + X < 312: c[:, x0 + X] = idx[:, X]
    return c, U.palette_colours(d, b["pal"])[128 * 16:128 * 16 + 256]

def _blob_filter(m, minsize):
    from collections import deque
    H, W = m.shape; seen = np.zeros_like(m); out = np.zeros_like(m)
    for y in range(H):
        for x in range(W):
            if m[y, x] and not seen[y, x]:
                q = deque([(y, x)]); seen[y, x] = True; comp = []
                while q:
                    a, b = q.popleft(); comp.append((a, b))
                    for da in (-1, 0, 1):
                        for db in (-1, 0, 1):
                            a2, b2 = a + da, b + db
                            if 0 <= a2 < H and 0 <= b2 < W and m[a2, b2] and not seen[a2, b2]:
                                seen[a2, b2] = True; q.append((a2, b2))
                if len(comp) >= minsize:
                    for a, b in comp: out[a, b] = True
    return out

def logo_h1(title="Hakkyu Dream", sub="~ Industrial-League Ball! ~", tcap=34, tsq=0.78, trk=2.0, s0=0.85, s1=1.12, rise=12,
            tx=26, tbottom=94, scap=14, ssq=0.9, scx=190, sbottom=116, sstroke=0.2, strk=0.8, tstroke=0.12, twhite=3.0, tnavy=1.0,
            shadow=(1, 1), debug=None):
    c, pal = _h1_orig()
    q = A.Quant(pal, c)
    rgb0 = pal[c][..., :3].astype(int); R, G, B = rgb0[..., 0], rgb0[..., 1], rgb0[..., 2]
    H, W = c.shape; yy, xx = np.mgrid[0:H, 0:W]
    nz = c > 0
    red = (R > 200) & (R - G > 60) & (R - B > 20); orange = (R > 200) & (G > 90) & (B < 110)
    sblue = (B > 200) & (G > 80) & (R < 110) & (G > R + 40)
    flag = nz & (red | orange | sblue)
    cx, cy, rr = 52.5, 65.0, 44.5
    d = np.hypot(xx - cx, yy - cy)
    ball = d <= rr + 2.5
    keep = flag & ~ball & ~((xx >= 100) & (xx <= 273) & (yy >= 86))
    keep |= flag & (xx <= 48) & (yy >= 98)
    keep |= nz & ((R > 200) & (R - G > 40)) & ball & (xx >= 85) & (yy >= 98) & (xx <= 102)   # orange tip under the title
    keep = _blob_filter(keep, 25)
    new = np.zeros_like(c); rgbf = np.zeros((H, W, 3)); A_ = np.zeros((H, W), bool)
    # ball: white disc, kept stitches, rim
    disc = d <= rr
    stitch = disc & (c > 0) & (R > 200) & (R - G > 45) & (np.abs(B - G) < 80) & (d <= rr - 2)
    rgbf[disc] = (255, 255, 255); A_ |= disc
    rim = (np.abs(d - rr) <= 0.75)
    rgbf[rim] = (106, 106, 148)
    rgbf[stitch] = rgb0[stitch]
    # blue spikes rebuilt (fragments only survive under the old lettering)
    def tri(pts):
        return A.poly_mask(pts, H, W)
    for pts in (((236, 22), (262, 16), (241, 32)), ((250, 41), (284, 43), (253, 50)), ((262, 62), (286, 68), (265, 71))):
        m = tri(pts) & ~keep; keep |= m
        rgbf[m] = (40, 110, 255)
    # pennant: extend the red band to the left behind the title
    redk = keep & (rgb0[..., 0] > 200) & (rgb0[..., 0] - rgb0[..., 1] > 60)
    rgbf[keep & ~redk] = rgb0[keep & ~redk]
    rgbf[redk] = rgb0[redk]
    pen = tri(((150, 44), (178, 37), (232, 10), (238, 11), (232, 40), (200, 60), (150, 62))) & ~keep
    for y in range(H):
        row = pen[y]
        if row.any():
            ref = rgb0[y][redk[y]] if redk[y].any() else None
            col = np.median(ref, 0) if ref is not None else np.array([255, 49, 82])
            rgbf[y][row] = col
    keep |= pen
    A_ |= keep
    shape = A_.copy()
    # title
    cov = hires_cov(title, tcap, "condbi", tstroke, tsq, trk, s0, s1, rise)
    m = smooth_mask(cov)
    tr, ta = compose_layers(m, [(OV * twhite, (255, 255, 255), None), (OV * tnavy, (0, 0, 90), shadow), (OV * tnavy, (0, 0, 90), None)],
                            lambda n: A.grad_rows(BLUE_FACE, n), pad=6)
    y = tbottom - tr.shape[0]
    sl = (slice(y, y + tr.shape[0]), slice(tx, tx + tr.shape[1]))
    # the title sits over ball/flags; stitches only where the title is not
    rgbf[sl][ta] = tr[ta]; A_[sl] |= ta
    # subtitle
    cov = hires_cov(sub, scap, "condb", sstroke, ssq, strk)
    m2 = smooth_mask(cov)
    sr, sa = compose_layers(m2, [(OV * 1.6, (255, 255, 255), None), (OV * 0.8, (110, 10, 0), None)], lambda n: A.grad_rows(SUB_FACE, n), pad=3)
    x_ = scx - sr.shape[1] // 2; y_ = sbottom - sr.shape[0]
    sl2 = (slice(y_, y_ + sr.shape[0]), slice(x_, x_ + sr.shape[1]))
    rgbf[sl2][sa] = sr[sa]; A_[sl2] |= sa
    # outer white border around everything that is not already bordered (ball+flags)
    allm = A_ & ~(disc & ~rim & False)
    bord = A.grow(A_, 2) & ~A_
    rgbf[bord] = (255, 255, 255); A_ |= bord
    new[A_] = q(rgbf[A_])
    return new, dict(title=(tr.shape[1], tr.shape[0], tx, y), sub=(sr.shape[1], sr.shape[0], x_, y_))

@functools.lru_cache(None)
def _h1():
    return logo_h1()[0]

def _h1page(page):
    def style(ink, base):
        C = _h1()
        if page == 0: a = np.concatenate([np.zeros((128, 5), np.uint8), C[:, 0:123]], 1)
        elif page == 1: a = C[:, 123:251]
        else: a = C[:, 251:307]
        return a.copy(), 0
    return style
STYLES["p11_h1_0"] = _h1page(0); STYLES["p11_h1_1"] = _h1page(1); STYLES["p11_h1_2"] = _h1page(2)


# ---- big title logos painted into pictures that the game cuts over several pages (homerun, pena_ini, pn_acivt, ore_ini) ----

_cache = {}


def hexrgb(h):
    h = h.lstrip("#")
    return np.array([int(h[i:i + 2], 16) for i in (0, 2, 4)], float)


def load(arcname, bankref, sprite):
    """(index canvas, rgb canvas (float), parts, origin, tables): a sprite drawn from the saved original; each part is
    coloured with its own palette; tables[k] = (colour table (256, 3), used indices of the part's whole page)."""
    from pp15.art import original_arc as kit
    from pp15.art import textures as U
    arc = kit.Arc(arcname)
    d = arc.D
    b = arc.resolve(d, bankref)
    ps = next(p for n, p in b["sprites"].items() if n.endswith("_" + sprite) or n == sprite)
    ps = [p for p in ps if p.x > -2000 and p.y > -2000]
    x0 = min(p.x for p in ps); y0 = min(p.y for p in ps)
    x1 = max(p.x + p.x1 - p.x0 for p in ps); y1 = max(p.y + p.y1 - p.y0 for p in ps)
    cv = np.zeros((y1 - y0, x1 - x0), np.uint8)
    rgb = np.zeros((y1 - y0, x1 - x0, 3))
    full = U.palette_colours(d, b["pal"])
    grey = np.stack([np.arange(256)] * 3, 1).astype(float)
    tables = []
    for p in ps:
        page = U.decode_indices(d, *b["pages"][p.page])
        idx = page[p.y0:p.y1, p.x0:p.x1]
        tbl = U.page_colours(full, p.palette, U.raw_size(d, *b["pages"][p.page]))[:256, :3].astype(float) if len(full) else grey
        if len(tbl) < 256: tbl = np.concatenate([tbl, np.zeros((256 - len(tbl), 3))])
        tables.append((tbl, sorted(set(np.unique(page).tolist()) - {0})))
        cv[p.y - y0:p.y - y0 + idx.shape[0], p.x - x0:p.x - x0 + idx.shape[1]] = idx
        rgb[p.y - y0:p.y - y0 + idx.shape[0], p.x - x0:p.x - x0 + idx.shape[1]] = tbl[idx]
    return cv, rgb, ps, (x0, y0), tables


def rows_fill(rgb, box, cv=None, clear=None):
    """Rebuild box (x0, y0, x1, y1) row by row between the pixel left of it and the one right of it. With cv and a
    bool array `clear`: rows whose two end pixels are transparent are flagged in `clear` (they end up transparent
    unless lettering is drawn on them)."""
    x0, y0, x1, y1 = box
    if cv is not None:
        for y in range(y0, y1):
            if cv[y, x0 - 1] == 0 and cv[y, x1] == 0:
                clear[y, x0:x1] = True
    a, b = rgb[y0:y1, x0 - 1], rgb[y0:y1, x1]
    t = (np.arange(x1 - x0) + 1)[None, :, None] / (x1 - x0 + 1)
    rgb[y0:y1, x0:x1] = a[:, None, :] * (1 - t) + b[:, None, :] * t


def mask_fill(rgb, box, strong, grow_n=4, vfrom=None, smooth=0, wy=0.4):
    """Erase the Japanese lettering of `box` without touching the rest of the picture: the pixels `strong(rgb)` marks
    (saturated body / outline colours), grown by `grow_n`, are rebuilt row by row run by run from the pixels left and
    right of each run. Returns the erased mask."""
    x0, y0, x1, y1 = box
    m = np.zeros(rgb.shape[:2], bool)
    m[y0:y1, x0:x1] = strong(rgb[y0:y1, x0:x1])
    m = ui_type.grow(m, grow_n, diagonal=True)
    m[:y0] = False; m[y1:] = False; m[:, :x0] = False; m[:, x1:] = False
    src = rgb.copy()
    full = m.copy()
    if vfrom is not None:                           # column runs reaching row `vfrom` or lower: rebuilt column by column
        done = np.zeros_like(m)
        for x in range(x0, x1):
            ys = np.nonzero(m[:, x])[0]
            if not len(ys):
                continue
            for r in np.split(ys, np.nonzero(np.diff(ys) > 1)[0] + 1):
                r = r[r >= vfrom]
                if not len(r):
                    continue
                rgb[r, x] = src[min(r[-1] + 1, rgb.shape[0] - 1), x]
                done[r, x] = True
        m &= ~done
    for y in range(y0, y1):
        xs = np.nonzero(m[y])[0]
        if not len(xs):
            continue
        runs = np.split(xs, np.nonzero(np.diff(xs) > 1)[0] + 1)
        for r in runs:
            a, b = r[0] - 1, r[-1] + 1
            t = (np.arange(len(r)) + 1)[:, None] / (len(r) + 1)
            rgb[y, r] = src[y, a] * (1 - t) + src[y, min(b, rgb.shape[1] - 1)] * t
    if smooth:                                      # relax the rebuilt pixels towards their neighbours (rows weigh 1, columns wy)
        for _ in range(smooth):
            up = np.roll(rgb, 1, 0); dn = np.roll(rgb, -1, 0); lf = np.roll(rgb, 1, 1); rt = np.roll(rgb, -1, 1)
            new = (lf + rt + wy * (up + dn)) / (2 + 2 * wy)
            rgb[full] = new[full]
    return full


def pen_strong(px):
    r, g, b = px[..., 0], px[..., 1], px[..., 2]
    lum = px.mean(2)
    navy = (b > r + 50) & (lum < 120)
    gold = (r > 200) & (g > 120) & (b < 110)
    rim = (r > 200) & (g < 130) & (b < 90)
    return navy | gold | rim


def text_mask(text, cap, squeeze=1.0, bold=0.5, slant=0.0, face="rounded", level=3):
    ink, base = ui_type.ttf_ink(text, face, cap, slant, squeeze, bold)
    return ink >= level


def ramp(stops, h):
    """(h, 3) colours from `stops` [(t, hex)] top to foot."""
    ts = np.array([s[0] for s in stops], float)
    cs = np.array([hexrgb(s[1]) for s in stops])
    f = np.linspace(0, 1, h)
    return np.stack([np.interp(f, ts, cs[:, k]) for k in range(3)], 1)


def draw_logo(rgb, mask, cx, cy, fill, rings, plate_down=None, shadow=None, light=None):
    """Paint `mask` (letters) centred on (cx, cy): rings = [(hex, n, diagonal)] outward from the letters, then optional
    plate_down = (hex, n): the letters + rings shifted down 1..n px in that colour (an extrusion) behind them,
    shadow = (hex, dx, dy, n) behind everything; fill = gradient stops; light = (hex, rows) a highlight line at the
    top inside the fill."""
    pad = sum(r[1] for r in rings) + (plate_down[1] if plate_down else 0) + (shadow[3] + max(abs(shadow[1]), abs(shadow[2])) if shadow else 0) + 4
    h, w = mask.shape
    big = np.zeros((h + 2 * pad, w + 2 * pad), bool)
    big[pad:pad + h, pad:pad + w] = mask
    layers = [(big, fill)]
    cur = big
    masks = []
    for ring in rings:
        hexc, n, diag = ring[:3]
        cur = ui_type.grow(cur, n, diagonal=diag)
        masks.append((cur, hexc, ring[3] if len(ring) > 3 else 1.0))
    top, left = cy - big.shape[0] // 2, cx - big.shape[1] // 2
    H, W = rgb.shape[:2]
    area = rgb[top:top + big.shape[0], left:left + big.shape[1]]
    if area.shape[:2] != big.shape:
        raise ValueError("logo runs off the picture: %s at %s" % (big.shape, (left, top)))
    outer = masks[-1][0] if masks else big
    if shadow:
        hexc, dx, dy, n = shadow
        base = plate_down_mask(outer, plate_down[1]) if plate_down else outer
        s = np.zeros_like(base)
        for k in range(1, n + 1):
            s |= ui_type.shift(base, dy + k - 1, dx + k - 1)
        s |= ui_type.shift(base, dy, dx)
        area[s] = hexrgb(hexc)
        shadow_m = s
    if plate_down:
        plate_m = plate_down_mask(outer, plate_down[1])
        area[plate_m] = hexrgb(plate_down[0])
    for m, hexc, alpha in masks[::-1]:
        area[m] = area[m] * (1 - alpha) + hexrgb(hexc) * alpha
    ys = np.nonzero(big.any(1))[0]
    colours = ramp(fill, ys.max() - ys.min() + 1)
    col = np.zeros((big.shape[0], 3))
    col[ys.min():ys.max() + 1] = colours
    col[:ys.min()] = colours[0]; col[ys.max() + 1:] = colours[-1]
    area[big] = np.broadcast_to(col[:, None, :], big.shape + (3,))[big]
    if light:
        hexc, rows = light
        top_edge = big & ~ui_type.shift(big, 1, 0)
        area[top_edge] = hexrgb(hexc)
    painted = np.zeros(rgb.shape[:2], bool)
    painted[top:top + big.shape[0], left:left + big.shape[1]] = (shadow_m if shadow else outer) | (plate_m if plate_down else outer) | outer
    return painted


def plate_down_mask(m, n):
    out = m.copy()
    for k in range(1, n + 1):
        out |= ui_type.shift(m, k, 0)
    return out


def fit_text(text, maxw, maxh, extra, caps=range(90, 7, -1), squeeze=1.0, bold=0.5, slant=0.0, face="rounded"):
    """Largest cap whose mask + `extra` px each side fits (maxw, maxh): (mask, cap)."""
    for cap in caps:
        m = text_mask(text, cap, squeeze, bold, slant, face)
        if m.shape[1] + 2 * extra <= maxw and m.shape[0] + 2 * extra <= maxh:
            return m, cap
    raise ValueError("%r does not fit %dx%d" % (text, maxw, maxh))


def snap(rgb, cv, changed, ps, org, tables, clear=None):
    """Nearest colour of the part's own page for every changed pixel (index 0 = clear is never chosen)."""
    out = cv.copy()
    for p, (tbl, used) in zip(ps, tables):
        y, x = p.y - org[1], p.x - org[0]
        h, w = p.y1 - p.y0, p.x1 - p.x0
        ys, xs = np.nonzero(changed[y:y + h, x:x + w])
        if not len(ys):
            continue
        pal = tbl[used]
        px = rgb[y + ys, x + xs]
        dist = ((px[:, None, :] - pal[None, :, :]) ** 2).sum(-1)
        out[y + ys, x + xs] = np.asarray(used)[dist.argmin(1)]
    if clear is not None:
        out[clear] = 0
    return out


# ---- the logos --------------------------------------------------------------------------------------------------

LOGOS = {}


def final(key):
    if key not in _cache:
        spec = LOGOS[key]
        cv, rgb, ps, org, tables = load(spec["arc"], spec["bank"], spec["sprite"])
        changed = np.zeros(cv.shape, bool)
        clear = np.zeros(cv.shape, bool)
        out = spec["recipe"](rgb, cv, None, changed, clear)
        new = out if isinstance(out, np.ndarray) else snap(rgb, cv, changed, ps, org, tables, clear)
        _cache[key] = (new, ps, org)
    return _cache[key]


def window_style(key, k):
    def style(ink, base):
        new, ps, org = final(key)
        p = ps[k]
        x, y = p.x - org[0], p.y - org[1]
        return new[y:y + p.y1 - p.y0, x:x + p.x1 - p.x0].copy(), 0
    return style


def register(key, arc, bank, sprite, nparts, recipe):
    LOGOS[key] = {"arc": arc, "bank": bank, "sprite": sprite, "recipe": recipe, "n": nparts}
    for k in range(nparts):
        STYLES["b9_%s_%d" % (key, k)] = window_style(key, k)


def parts_of(key):
    """[(page, [x0, y0, x1, y1])] of the logo's parts, for the generator."""
    cv, rgb, ps, org, tables = load(LOGOS[key]["arc"], LOGOS[key]["bank"], LOGOS[key]["sprite"])
    return [(p.page, [p.x0, p.y0, p.x1, p.y1]) for p in ps]


# homerun.arc r3_hrx sprite 00: ホームラン競争 -> Home Run Derby (banner 512 x 80)
def _hr(rgb, cv, colours, changed, clear):
    box = (114, 8, 404, 80)
    rows_fill(rgb, box, cv, clear)
    m, cap = fit_text("Home Run Derby", 280, 58, 7, squeeze=0.82, bold=0.7)
    painted = draw_logo(rgb, m, 259, 42, [(0, "f6aa28"), (0.5, "ff7a50"), (1, "ff3694")],
              [("#ffffff", 2, True), ("#0f48d0", 1, True), ("#62b4f6", 2, True), ("#3c82d0", 1, True)],
              plate_down=("#62b4f6", 3), shadow=("#4a6aa4", 1, 2, 2))
    changed[box[1]:box[3], box[0]:box[2]] = True
    clear &= ~painted


register("hr", "homerun.arc", "r3_hrx", "00", 5, _hr)


# pena_ini.arc s4_taz00 sprite 00: ペナント (+ small PENNANT above) -> Pennant (512 x 448 picture, pages 1, 2, 5, 6)
def _pn(rgb, cv, colours, changed, clear):
    box = (140, 70, 378, 176)
    m = mask_fill(rgb, box, pen_strong, 5, vfrom=150)
    changed |= m
    m2, cap = fit_text("Pennant", 236, 90, 9, squeeze=0.8, bold=0.9)
    painted = draw_logo(rgb, m2, 259, 120, [(0, "fcd800"), (0.5, "f8b820"), (1, "f08020")],
                        [("#1018a8", 3, True), ("#ffffff", 2, True), ("#e86830", 1, True)])
    changed |= painted


register("pn", "pena_ini.arc", "s4_taz00", "00", 16, _pn)


# ore_ini.arc y4_bsta_opd sprite 00: マイライフ -> My Life (512 x 448 picture, pages 1 and 2)
def ml_strong(px):
    r, g, b = px[..., 0], px[..., 1], px[..., 2]
    gold = (r > 215) & (g > 170) & (b < 110)
    navy = (b > 130) & (r < 60) & (g < 90)
    cyan = (r < 70) & (g > 140) & (g < 220) & (b > 215)
    return gold | navy | cyan


def _ml(rgb, cv, colours, changed, clear):
    box = (140, 4, 378, 84)
    m = mask_fill(rgb, box, ml_strong, 10, smooth=120, wy=0.5)
    changed |= m
    m2, cap = fit_text("My Life", 232, 80, 11, squeeze=0.85, bold=0.9)
    painted = draw_logo(rgb, m2, 259, 44, [(0, "ffee20"), (0.6, "ffd810"), (1, "ffc000")],
                        [("#1038a8", 2, True), ("#18b4f4", 3, True), ("#ffffff", 3, True, 0.7), ("#ffffff", 3, True, 0.35)])
    changed |= painted


register("ml", "ore_ini.arc", "y4_bsta_opd", "00", 16, _ml)


def rot_mask(m, deg):
    """A bool mask rotated by `deg` degrees (counter-clockwise), grown to fit."""
    from PIL import Image
    im = Image.fromarray((m * 255).astype(np.uint8)).rotate(deg, resample=Image.BICUBIC, expand=True)
    a = np.asarray(im) >= 128
    ys, xs = np.nonzero(a)
    return a[ys.min():ys.max() + 1, xs.min():xs.max() + 1]


# pn_acivt.arc i3_f02 sprite 00: 秋季キャンプ -> Fall Camp (368 x 179, 4-bit pages 0-2; the colours are loaded at run time,
# so everything is done in palette indices: body 6..11 banded along y + 0.24 x, wire 13, wide ring 3, shadow 15)
BODY_RAMP = [11] * 12 + [9] * 5 + [10] * 4 + [7] * 3 + [8] * 4 + [6] * 14 + [8] * 6 + [7] * 5 + [10] * 5 + [9] * 8 + [11] * 8


def _fc(rgb, cv, colours, changed, clear):
    H, W = cv.shape
    pad = 12
    best = None
    for cap in range(80, 10, -1):
        m = rot_mask(text_mask("Fall Camp", cap, 0.92, 0.9, 0.12), 13.5)
        if m.shape[1] + 2 * pad <= W - 4 and m.shape[0] + 2 * pad <= H - 2:
            best = m; break
    m = best
    h, w = m.shape
    big = np.zeros((H, W), bool)
    top, left = (H - h) // 2 + 1, (W - w) // 2
    big[top:top + h, left:left + w] = m
    r1 = ui_type.grow(big, 2, diagonal=True)
    r2 = ui_type.grow(r1, 6, diagonal=True)
    sh = np.zeros_like(r2)
    for k in range(1, 4):
        sh |= ui_type.shift(r2, k, k - 1)
    new = np.zeros((H, W), np.uint8)
    new[sh] = 15; new[r2] = 3; new[r1] = 13
    yy, xx = np.mgrid[0:H, 0:W]
    t = yy + 0.24 * xx
    t0, t1 = t[big].min(), t[big].max()
    u = ((t - t0) / (t1 - t0)).clip(0, 1)
    ramp = np.array(BODY_RAMP)
    new[big] = ramp[np.minimum((u * (len(ramp) - 1)).round().astype(int), len(ramp) - 1)][big]
    return new


register("fc", "pn_acivt.arc", "i3_f02", "00", 3, _fc)
