"""Label styles of art run 3, agent A (scc_tops.arc: the Success banner and the logos of Hakkyu Dream and Eikan Nine).
Each style returns one rectangle (a window) of a whole redrawn logo: the banner (232 x 72, pages 30 and 28 of the
bank the reader calls m4_ona00), Hakkyu Dream (224 x 80, pages 0 and 1 of y5_tic_0) and Eikan Nine (224 x 104, pages 0, 1
and 2 of y5_tic_0). The art is built from the saved original of scc_tops.arc (_work/orig_arc, else DATA/files) and the
system font Avenir Next Condensed; it is cached. Written by _work/ui_pages/gen_scc_tops_logo_spec.py."""
import os, sys
import numpy as np
from PIL import Image, ImageDraw, ImageFont
T = os.path.expanduser("~/Projects/Pawapuro/Pawapros15-tools")
sys.path.insert(0, T)
import ui_textures as U, scan_story as S

SYS = "/System/Library/Fonts/"
FONTS = {"condd": (SYS + "Avenir Next Condensed.ttc", 2), "condhi": (SYS + "Avenir Next Condensed.ttc", 9), "condbi": (SYS + "Avenir Next Condensed.ttc", 1), "condb": (SYS + "Avenir Next Condensed.ttc", 0), "cond": (SYS + "Avenir Next Condensed.ttc", 9), "heavy": (SYS + "Avenir Next.ttc", 9),
         "cond_up": (SYS + "Avenir Next Condensed.ttc", 8)}

def orig_data():
    p = os.path.join(U.ORIG_ARC_DIR, "scc_tops.arc")
    if not os.path.exists(p): p = os.path.join(S.DATA_FILES, "scc_tops.arc")
    return open(p, "rb").read()

_cache = {}
def page_of(bank, n):
    key = (bank, n)
    if key not in _cache:
        d = orig_data()
        b = next(x for x in U.banks(d, U.elf_symbols(d)) if x["name"] == bank)
        _cache[key] = (d, U.decode_indices(d, *b["pages"][n]).copy(), U.palette_colours(d, b["pal"]))
    return _cache[key]

def rendertext(text, cap, font="cond", stroke=0.0, over=4, slant=0.0, track=0, squeeze=1.0):
    """crisp-ready coverage (float 0..1) of text, capitals `cap` px high; returns (cov, baseline_row)."""
    path, idx = FONTS[font]
    probe = ImageFont.truetype(path, 400, index=idx)
    bb = probe.getbbox("H"); sz = round(400 * cap * over / (bb[3] - bb[1]))
    f = ImageFont.truetype(path, sz, index=idx)
    l, t, r, b = f.getbbox(text, anchor="ls")
    pad = 6 * over
    img = Image.new("L", (r - l + 2 * pad + int(abs(slant) * (b - t)) + 8 * over, b - t + 2 * pad), 0)
    base = -t + pad
    dr = ImageDraw.Draw(img)
    st = round(stroke * over)
    if track:
        x = pad - l
        for ch in text:
            dr.text((x, base), ch, font=f, fill=255, anchor="ls", stroke_width=st, stroke_fill=255)
            x += f.getlength(ch) + track * over
    else:
        dr.text((pad - l, base), text, font=f, fill=255, anchor="ls", stroke_width=st, stroke_fill=255)
    if slant:
        img = img.transform(img.size, Image.AFFINE, (1, slant, -slant * base, 0, 1, 0), Image.BICUBIC)
    if squeeze != 1.0:
        img = img.resize((max(over, round(img.width * squeeze)), img.height), Image.BICUBIC)
    return np.asarray(img, np.float32) / 255.0, base, over

def box_down(a, over):
    h, w = a.shape; h2, w2 = h // over, w // over
    return a[:h2 * over, :w2 * over].reshape(h2, over, w2, over).mean((1, 3))

def crisp_mask(text, cap, **kw):
    cov, base, over = rendertext(text, cap, **kw)
    m = box_down(cov, over) >= 0.5
    ys, xs = np.nonzero(m)
    return m[ys.min():ys.max() + 1, xs.min():xs.max() + 1], base // over - ys.min()

def grow(mask, n=1, diag=True):
    m = mask.copy()
    for _ in range(n):
        p = np.pad(m, 1); o = m.copy()
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if (dy or dx) and (diag or not (dy and dx)):
                    o |= p[1 + dy:1 + dy + m.shape[0], 1 + dx:1 + dx + m.shape[1]]
        m = o
    return m

def shift(mask, dy, dx):
    out = np.zeros_like(mask); h, w = mask.shape
    out[max(dy, 0):h + min(dy, 0), max(dx, 0):w + min(dx, 0)] = mask[max(-dy, 0):h + min(-dy, 0), max(-dx, 0):w + min(-dx, 0)]
    return out

# ---- banner -------------------------------------------------------------------------------------
RAMP = [179,180,180,178,181,182,183,184,185,186,191,190,193,193,194,198,198,200,255,255,254,253,251,251,249,249,248,243,243,242,
        240,240,238,236,236,234,234,233,231,231,230,229,228,227,227,225,224,223,222,219]
WHITE, BLUE, DARK, SHADOW = 141, 71, 51, 23

def ramp_rows(h):
    return np.array(RAMP)[np.rint(np.linspace(0, len(RAMP) - 1, h)).astype(int)]

def banner(cap=46, stroke=0.6, slant=0.0, W=232, H=72, text="Success"):
    m, base = crisp_mask(text, cap, font="cond", stroke=stroke, slant=slant)
    m = despeckle(m)
    h, w = m.shape
    pad = 8
    big = np.zeros((h + 2 * pad, w + 2 * pad), bool); big[pad:pad + h, pad:pad + w] = m
    white = grow(big, 2); blue = grow(white, 1); dark = grow(blue, 1)
    sh = np.zeros_like(big)
    for k in range(1, 5):
        sh |= shift(dark, k, min(k, 3))
    out = np.zeros(big.shape, np.uint8)
    out[sh] = SHADOW; out[dark] = DARK; out[blue] = BLUE; out[white] = WHITE
    fill = np.broadcast_to(ramp_rows(big.shape[0])[:, None], big.shape)   # placeholder, set below
    ys = np.nonzero(big.any(1))[0]
    rows = np.zeros(big.shape[0], int); rows[ys.min():ys.max() + 1] = ramp_rows(ys.max() - ys.min() + 1)
    out[big] = np.broadcast_to(rows[:, None], big.shape)[big]
    ys, xs = np.nonzero(out)
    art = out[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    return art

def banner_canvas(**kw):
    art = banner(**kw)
    H, W = 72, 232
    if art.shape[0] > H - 2 or art.shape[1] > W - 2:
        raise ValueError("banner art %s too big" % (art.shape,))
    c = np.zeros((H, W), np.uint8)
    y = (H - art.shape[0]) // 2; x = (W - art.shape[1]) // 2
    c[y:y + art.shape[0], x:x + art.shape[1]] = art
    return c

# ---- logo canvases --------------------------------------------------------------------------------
# (bank, page, src rect x0,y0,x1,y1, canvas x, canvas y)
L1_PARTS = [(0, (0, 0, 128, 80), 0, 0), (1, (0, 0, 96, 80), 128, 0)]
L2_PARTS = [(0, (0, 80, 128, 128), 0, 0), (1, (0, 80, 96, 128), 128, 0), (2, (0, 0, 128, 56), 0, 48), (2, (16, 56, 96, 112), 128, 48)]
def logo_canvas(parts, W=224, H=104):
    c = np.zeros((H, W), np.uint8)
    for pg, (x0, y0, x1, y1), cx, cy in parts:
        c[cy:cy + y1 - y0, cx:cx + x1 - x0] = page_of("y5_tic_0", pg)[1][y0:y1, x0:x1]
    return c
def logo_pal(pn):
    return page_of("y5_tic_0", 0)[2][pn * 16:pn * 16 + 256]

# ---- colour helpers ---------------------------------------------------------------------------------
class Quant:
    def __init__(self, pal, canvas, extra=()):
        used = sorted(set(np.unique(canvas).tolist()) - {0})
        self.idx = np.array(used)
        self.rgb = pal[self.idx][:, :3].astype(float)
        self.pal = pal
    def __call__(self, rgb):
        a = np.asarray(rgb, float).reshape(-1, 3)
        d = ((a[:, None, :] - self.rgb[None]) ** 2 * np.array([2, 4, 3])).sum(-1)
        return self.idx[d.argmin(1)].reshape(np.asarray(rgb).shape[:-1]).astype(np.uint8)

def grad_rows(stops, n):
    """stops [(frac, (r,g,b))] -> (n,3) colours."""
    f = np.linspace(0, 1, n)
    xs = [s[0] for s in stops]
    return np.stack([np.interp(f, xs, [s[1][k] for s in stops]) for k in range(3)], 1)

def row_inpaint(rgb, mask, valid=None):
    """fill masked pixels per row by linear interpolation between the nearest unmasked pixel on each side."""
    out = rgb.copy()
    H, W = mask.shape
    ok = ~mask if valid is None else valid
    for y in range(H):
        xs = np.nonzero(mask[y])[0]
        if not len(xs): continue
        good = np.nonzero(ok[y])[0]
        if not len(good): continue
        for x in xs:
            l = good[good < x]; r = good[good > x]
            if len(l) and len(r):
                a, b = l[-1], r[0]; t = (x - a) / (b - a)
                out[y, x] = rgb[y, a] * (1 - t) + rgb[y, b] * t
            elif len(l): out[y, x] = rgb[y, l[-1]]
            else: out[y, x] = rgb[y, r[0]]
    return out

def despeckle(m):
    """drop single-pixel islands and fill single-pixel holes of a boolean mask."""
    p = np.pad(m, 1)
    n = sum(p[1 + dy:1 + dy + m.shape[0], 1 + dx:1 + dx + m.shape[1]] for dy in (-1, 0, 1) for dx in (-1, 0, 1) if dy or dx)
    return (m & (n > 0)) | (~m & (n == 8))

# ---- Eikan Nine logo (canvas 224 x 104, palette 32) -------------------------------------------------------------
TITLE_GRAD = [(0.0, (255, 246, 197)), (0.12, (255, 232, 140)), (0.30, (255, 205, 8)), (0.48, (238, 160, 0)),
              (0.68, (213, 98, 0)), (0.85, (197, 57, 0)), (1.0, (214, 92, 70))]
def logo2(title="Eikan Nine", sub="Build a Powerhouse Club!", tcap=26, tsq=0.82, tstroke=0.3, scap=10, ssq=0.92, sstroke=0.0):
    c = logo_canvas(L2_PARTS); pal = logo_pal(32)
    q = Quant(pal, c)
    rgb = pal[c][..., :3].astype(float)
    # --- erase the Japanese title: plate rows interpolated between its clean left and right edges
    mask = np.zeros(c.shape, bool); mask[32:62, 48:183] = True
    rgb = row_inpaint(rgb, mask)
    new = c.copy()
    new[mask] = q(rgb[mask])
    # --- new title
    m, base = crisp_mask(title, tcap, font="condbi", stroke=tstroke, squeeze=tsq)
    m = despeckle(m)
    h, w = m.shape
    pad = 3
    big = np.zeros((h + 2 * pad, w + 2 * pad), bool); big[pad:pad + h, pad:pad + w] = m
    out = np.zeros(big.shape + (3,)); alpha = np.zeros(big.shape, bool)
    dark = grow(big, 1)
    sh = shift(dark, 1, 1)
    out[sh] = (28, 24, 48); alpha |= sh
    out[dark] = (16, 16, 32); alpha |= dark
    ys = np.nonzero(big.any(1))[0]
    g = grad_rows(TITLE_GRAD, ys.max() - ys.min() + 1)
    rowc = np.zeros((big.shape[0], 3)); rowc[ys.min():ys.max() + 1] = g
    out[big] = np.broadcast_to(rowc[:, None, :], big.shape + (3,))[big]; alpha |= big
    hi = big & ~shift(big, 1, 0)
    out[hi] = (255, 250, 225)
    hl = big & ~shift(big, 0, 1) & ~hi
    out[hl] = (255, 240, 180)
    alpha_full = alpha
    cy, cx = 47, 116
    y0, x0 = cy - big.shape[0] // 2, cx - big.shape[1] // 2
    reg = (slice(y0, y0 + big.shape[0]), slice(x0, x0 + big.shape[1]))
    new[reg][alpha] = q(out[alpha])
    # --- subtitle band
    bx0, bx1, by0, by1 = 46, 191, 65, 84
    band = np.zeros(c.shape, bool); band[by0:by1, bx0:bx1] = True
    for (yy, xx) in ((by0, bx0), (by0, bx1 - 1), (by1 - 1, bx0), (by1 - 1, bx1 - 1)): band[yy, xx] = False
    new[band] = q(np.array([(255, 255, 246)]))[0]
    new[by1 - 2, bx0 + 1:bx1 - 1] = q(np.array([(246, 238, 230)]))[0]
    new[by1 - 1, bx0 + 1:bx1 - 1] = q(np.array([(205, 189, 172)]))[0]
    sm, sbase = crisp_mask(sub, scap, font="condb", stroke=sstroke, squeeze=ssq)
    sm = despeckle(sm)
    sh_, sw_ = sm.shape
    sy = by0 + (by1 - 2 - by0 - sh_) // 2 + 1; sx = (bx0 + bx1 - sw_) // 2
    new[sy:sy + sh_, sx:sx + sw_][sm] = q(np.array([(98, 41, 16)]))[0]
    return new, (title_dims := (w, h)), (sw_, sh_)

# ---- Hakkyu Dream logo (canvas 224 x 80, palette 16) --------------------------------------------------------------
def poly_mask(pts, H, W):
    im = Image.new('L', (W, H), 0)
    ImageDraw.Draw(im).polygon([(x, y) for x, y in pts], fill=1)
    return np.asarray(im, bool)

P1 = [(28, 62), (33, 40), (48, 30), (84, 24), (100, 17), (126, 17), (142, 21), (162, 19), (170, 22), (180, 32), (193, 50), (193, 73), (80, 73), (60, 69), (36, 66)]
WEDGE = [(100, 30), (116, 23), (166, 8), (172, 13), (172, 31), (150, 37), (100, 37)]
BALL = (56.5, 41.5, 29.5)

def erase1():
    c = logo_canvas(L1_PARTS, H=80); pal = logo_pal(16)
    q = Quant(pal, c)
    rgb = pal[c][..., :3].astype(float)
    H, W = c.shape
    P = poly_mask(P1, H, W)
    P[3:41, 100:172] = True
    P[62:74, 24:60] = True
    P[48:62, 190:212] = True
    yy, xx = np.mgrid[0:H, 0:W]
    d = np.hypot(xx + 0.5 - BALL[0] - 0.5, yy + 0.5 - BALL[1] - 0.5)
    new = c.copy()
    # ball inside the erased area
    inball = P & (d <= BALL[2] - 0.5)
    ring = P & (d > BALL[2] - 0.5) & (d <= BALL[2] + 0.8)
    border = P & (d > BALL[2] + 0.8) & (d <= BALL[2] + 1.9)
    stitch = (rgb[..., 0] > 200) & (rgb[..., 1] < 190) & (rgb[..., 0] - rgb[..., 1] > 45) & (np.abs(rgb[..., 2] - rgb[..., 1]) < 70)
    keep = P & stitch & (d <= BALL[2] + 1)
    new[P] = 0
    new[inball] = q(np.array([(255, 255, 255)]))[0]
    new[ring] = q(np.array([(106, 106, 148)]))[0]
    new[border] = q(np.array([(255, 255, 255)]))[0]
    new[keep] = c[keep]
    return new, c, P

def warp_mask(text, cap, font, stroke, squeeze, s0, s1, rise, over=4, thresh=0.5, slant=0.0, track=0):
    """crisp mask of text whose letters grow from scale s0 (left) to s1 (right) and whose baseline climbs by `rise` px."""
    cov, base, ov = rendertext(text, cap, font=font, stroke=stroke, squeeze=squeeze, over=over, slant=slant, track=track)
    H, W = cov.shape
    xs = np.nonzero(cov.max(0) > 0.02)[0]
    cov = cov[:, xs.min():xs.max() + 1]; W = cov.shape[1]
    Wout = W // over
    outH = int((H / over) * max(s0, s1, 1.0) + rise + 8) * over
    ob = int(outH - (H - base) / over * max(s0, s1, 1.0) * over - 4 * over)       # output baseline row (at 4x) for x = 0
    out = np.zeros((outH, W), np.float32)
    yy = np.arange(outH)
    for X in range(W):
        t = X / max(W - 1, 1)
        s = s0 + (s1 - s0) * t
        yb = ob - rise * over * t
        src = base + (yy - yb) / s
        lo = np.floor(src).astype(int); fr = src - lo
        ok = (lo >= 0) & (lo + 1 < H)
        col = np.zeros(outH, np.float32)
        col[ok] = cov[lo[ok], X] * (1 - fr[ok]) + cov[lo[ok] + 1, X] * fr[ok]
        out[:, X] = col
    m = box_down(out, over) >= thresh
    ys_, xs_ = np.nonzero(m)
    return m[ys_.min():ys_.max() + 1, xs_.min():xs_.max() + 1]

BLUE_GRAD = [(0.0, (150, 195, 255)), (0.18, (70, 110, 255)), (0.45, (0, 0, 255)), (0.8, (0, 0, 180)), (1.0, (0, 0, 120))]
SUB_GRAD = [(0.0, (255, 250, 150)), (0.5, (255, 205, 40)), (1.0, (255, 120, 0))]
WEDGE_ROWS = [(255, 49, 82), (255, 82, 123), (255, 41, 74), (255, 65, 98), (255, 106, 148), (246, 32, 65)]

def title_art(text, cap, sq, stroke=0.3, trk=3.0, s0=1.0, s1=1.0, rise=0, font="condbi"):
    m = warp_mask(text, cap, font, stroke, sq, s0, s1, rise, track=trk) if (s0 != 1.0 or s1 != 1.0 or rise) else None
    if m is None:
        m, _ = crisp_mask(text, cap, font=font, stroke=stroke, squeeze=sq, track=trk)
    m = despeckle(m)
    h, w = m.shape
    big = np.zeros((h + 10, w + 10), bool); big[4:4 + h, 4:4 + w] = m
    ring = grow(big, 1)
    exb = shift(ring, 1, 0) | shift(ring, 2, 1) | shift(ring, 2, 0)
    white = grow(ring | exb, 1)
    gy = np.nonzero(big.any(1))[0]
    g = grad_rows(BLUE_GRAD, gy.max() - gy.min() + 1)
    rowc = np.zeros((big.shape[0], 3)); rowc[gy.min():gy.max() + 1] = g
    tr = np.zeros(big.shape + (3,))
    tr[white] = (255, 255, 255); tr[exb] = (0, 0, 90); tr[ring] = (255, 255, 255)
    tr[big] = np.broadcast_to(rowc[:, None, :], big.shape + (3,))[big]
    return tr, white

def logo1b(l1="Hakkyu", l2="Dream", sub="~ Hot-Blooded Industrial-League Ball! ~", tcap=25, tsq=0.9, trk=3.0,
           p1=(30, 0), p2=(104, 34), scap=8, sy=65, sstroke=0.0, sq=1.0, sfont="condd", subplate=False):
    new, c, P = erase1()
    pal = logo_pal(16); q = Quant(pal, c)
    H, W = new.shape
    rgb = np.zeros((H, W, 3)); A = np.zeros((H, W), bool)
    wm = poly_mask(WEDGE2, H, W)
    rows = np.array(WEDGE_ROWS, float)[(np.arange(H) * 7 // 2) % len(WEDGE_ROWS)]
    wb = grow(wm, 2) & ~wm
    rgb[wm] = np.broadcast_to(rows[:, None, :], (H, W, 3))[wm]; A |= wm
    rgb[wb] = (255, 255, 255); A |= wb
    for text, (x, y) in ((l2, p2), (l1, p1)):
        tr, ta = title_art(text, tcap, tsq, trk=trk)
        sl = (slice(y, y + tr.shape[0]), slice(x, x + tr.shape[1]))
        rgb[sl][ta] = tr[ta]; A[sl] |= ta
    # ball stitches (lower left seam), under everything but on the ball
    seam = np.zeros((H, W), bool)
    cxs, cys, R = 80.0, 44.0, 35.0
    for ang in np.arange(150, 216, 1.0):
        px = cxs + R * np.cos(np.radians(ang)); py = cys + R * np.sin(np.radians(ang))
        if np.hypot(px - BALL[0], py - BALL[1]) < BALL[2] - 2.5:
            seam[int(py), int(px)] = True
    ticks = np.zeros((H, W), bool)
    for ang in np.arange(152, 214, 6.0):
        for t in (-2, -1, 1, 2):
            px = cxs + (R + t) * np.cos(np.radians(ang)); py = cys + (R + t) * np.sin(np.radians(ang))
            if np.hypot(px - BALL[0], py - BALL[1]) < BALL[2] - 2.5:
                ticks[int(py), int(px)] = True
    st = ticks | seam
    sm_, _ = crisp_mask(sub, scap, font=sfont, stroke=sstroke, squeeze=sq)
    sm = despeckle(sm_)
    sh_, sw_ = sm.shape
    if subplate:
        pad = 4
        plate = np.zeros((sh_ + 2 * pad, sw_ + 2 * pad), bool); plate[:] = True
        plate[0, 0] = plate[0, -1] = plate[-1, 0] = plate[-1, -1] = False
        border = grow(plate, 1) & ~plate
        r = np.zeros(plate.shape + (3,)); r[border] = (255, 255, 255)
        pg = grad_rows([(0, (30, 40, 150)), (1, (0, 0, 80))], plate.shape[0])
        r[plate] = np.broadcast_to(pg[:, None, :], plate.shape + (3,))[plate]
        full = plate | border
        txt = np.zeros_like(plate); txt[pad:pad + sh_, pad:pad + sw_] = sm
        sg = np.nonzero(txt.any(1))[0]
        gg = grad_rows(SUB_GRAD, sg.max() - sg.min() + 1)
        rc = np.zeros((plate.shape[0], 3)); rc[sg.min():sg.max() + 1] = gg
        r[txt] = np.broadcast_to(rc[:, None, :], plate.shape + (3,))[txt]
        d2 = full
    else:
        bg = np.zeros((sh_ + 4, sw_ + 4), bool); bg[2:2 + sh_, 2:2 + sw_] = sm
        d1 = grow(bg, 1); d2 = grow(d1, 1)
        r = np.zeros(bg.shape + (3,)); r[d2] = (255, 255, 255); r[d1] = (110, 10, 0)
        sg = np.nonzero(bg.any(1))[0]
        gg = grad_rows(SUB_GRAD, sg.max() - sg.min() + 1)
        rc = np.zeros((bg.shape[0], 3)); rc[sg.min():sg.max() + 1] = gg
        r[bg] = np.broadcast_to(rc[:, None, :], bg.shape + (3,))[bg]
    x_ = 116 - r.shape[1] // 2
    sy = min(sy, H - r.shape[0])
    sl = (slice(sy, sy + r.shape[0]), slice(x_, x_ + r.shape[1]))
    # stitches first (behind title) - they were drawn after wedge and before title; apply now into base canvas
    rgb[st & ~A] = (255, 150, 150); A |= (st & ~A)
    rgb[sl][d2] = r[d2]; A[sl] |= d2
    new[A] = q(rgb[A])
    return new
WEDGE2 = [(122, 37), (164, 7), (172, 12), (176, 38)]


import functools

@functools.lru_cache(None)
def _banner():
    return banner_canvas(cap=47, stroke=0.25)

@functools.lru_cache(None)
def _hakkyu():
    return logo1b(sfont="condb")

@functools.lru_cache(None)
def _eikan():
    return logo2()[0]


def _window(fn, y0, y1, x0, x1):
    def style(ink, base):
        return fn()[y0:y1, x0:x1].copy(), 0
    return style


STYLES = {
    "a3_ban0": _window(_banner, 0, 72, 0, 128),          # page 30 rect 0,0,128,72
    "a3_ban1": _window(_banner, 0, 72, 128, 232),        # page 28 rect 0,56,104,128
    "a3_hak0": _window(_hakkyu, 0, 80, 0, 128),          # y5_tic_0 page 0 rect 0,0,128,80
    "a3_hak1": _window(_hakkyu, 0, 80, 128, 224),        # page 1 rect 0,0,96,80
    "a3_eik0": _window(_eikan, 0, 48, 0, 128),           # page 0 rect 0,80,128,128
    "a3_eik1": _window(_eikan, 0, 48, 128, 224),         # page 1 rect 0,80,96,128
    "a3_eik2": _window(_eikan, 48, 104, 0, 128),         # page 2 rect 0,0,128,56
    "a3_eik3": _window(_eikan, 48, 104, 128, 208),       # page 2 rect 16,56,96,112
}
