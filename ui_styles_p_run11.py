"""Run 11 agent P: Hakkyu Dream logo (y5_tic_0 pages 0-1 of scc_tops.arc / scs_titl.arc) with a smooth, solid outline and
a legible subtitle. Layers are built at OV x resolution (round dilations of the lettering), box-downsampled with
blending between the inside layers, and quantised to the palette colours already in the page. Names p11_*."""
import os, sys, functools
import numpy as np
from PIL import Image
T = os.path.expanduser("~/Projects/Pawapuro/Pawapros15-tools")
sys.path.insert(0, T)
import ui_styles_a_run3 as A

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
    """face_mask hi-res bool. layers: list of (radius_hi, (r,g,b)) outermost first (each dilation of the face).
    face_rows: function(n)->(n,3) colours for the face rows (1x rows).  Returns (rgb 1x float, alpha 1x bool)."""
    P = pad * OV
    h, w = face_mask.shape
    H = (h + 2 * P + OV - 1) // OV * OV; W = (w + 2 * P + OV - 1) // OV * OV
    big = np.zeros((H, W), bool); big[P:P + h, P:P + w] = face_mask
    rgb = np.zeros((H, W, 3), float); al = np.zeros((H, W), bool)
    for r, col, off in layers:
        m = disc_dilate(big, r)
        if off: m = shift_hi(m, off[0] * OV, off[1] * OV)
        rgb[m] = col; al |= m
    ys = np.nonzero(big.any(1))[0]
    n = (ys.max() - ys.min() + 1)
    g = face_rows(max(n, 2))
    rowc = np.zeros((H, 3)); rowc[ys.min():ys.max() + 1] = g
    rgb[big] = np.broadcast_to(rowc[:, None, :], big.shape + (3,))[big]; al |= big
    # downsample: alpha by coverage >= .5, colour = mean of covered subpixels
    a4 = al.reshape(H // OV, OV, W // OV, OV)
    cnt = a4.sum((1, 3))
    c4 = (rgb * al[..., None]).reshape(H // OV, OV, W // OV, OV, 3).sum((1, 3))
    out = c4 / np.maximum(cnt, 1)[..., None]
    return out, cnt >= (OV * OV) // 2

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

def logo(title="Hakkyu Dream", sub="~ Industrial-League Ball! ~", tcap=20, tsq=0.76, trk=1.5, s0=0.82, s1=1.12, rise=6,
         tx=28, tbottom=64, scap=10, ssq=0.9, scx=118, sbottom=80, sfont="condb", sstroke=0.2, twhite=2.6, tnavy=0.8):
    new, c, erase, red = A.erase3()
    pal = A.logo_pal(16); q = A.Quant(pal, c)
    H, W = new.shape
    rgb = np.zeros((H, W, 3)); Am = np.zeros((H, W), bool)
    # pennant continuation (as run 3)
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
    cov = hires_cov(title, tcap, "condbi", 0.25, tsq, trk, s0, s1, rise)
    m = smooth_mask(cov)
    tr, ta = compose_layers(m, [(OV * twhite, (255, 255, 255), None), (OV * tnavy, (0, 0, 90), None)], lambda n: A.grad_rows(BLUE_FACE, n))
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
    cov = hires_cov(sub, scap, sfont, sstroke, ssq, 0.0)
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

STYLES = {
    "p11_hak0": _window(_hakkyu, 0, 80, 0, 128),
    "p11_hak1": _window(_hakkyu, 0, 80, 128, 224),
}
