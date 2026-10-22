"""Styles for the English logos of Hakkyu Dream and Eikan Nine on the Success Mode front panel and title screens.

The logos are drawn large, reduced to normal size, then outlined and coloured with the colours the sheet already uses.

A style is a recipe that tells the lettering tool (pp15/art/typeset.py) how to draw an English label on a sprite sheet:
font, size, colours, outline, shadow.

Used by these spec files (specs/<name>.json, one per sprite file, each label names a style): scc_tops, sct_titl, scs_titl.
"""
import os
import sys
import functools
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from pp15 import config
from pp15.art import textures as U

STYLES = {}


OV = 8
S = "/System/Library/Fonts/Supplemental/"
FACES = {"impact": (S + "Impact.ttf", 0), "futura": (S + "Futura.ttc", 4), "black": (S + "Arial Black.ttf", 0),
         "avh": ("/System/Library/Fonts/Avenir Next Condensed.ttc", 8), "avb": ("/System/Library/Fonts/Avenir Next Condensed.ttc", 0),
         "rounded": (S + "Arial Rounded Bold.ttf", 0), "din": (S + "DIN Condensed Bold.ttf", 0)}


# ---- source art -----------------------------------------------------------------------------------------------------------------
CANV = {  # key: (arc, bank, [(page, x0, y0, x1, y1, cx, cy)], W, H, palette number)
    "hak_tit": ("scs_titl.arc", "y5_tic_h1", [(0, 0, 0, 128, 128, 0, 0), (1, 0, 0, 128, 128, 128, 0), (2, 0, 0, 56, 128, 256, 0)], 312, 128, 128),
    "eik_tit": ("sct_titl.arc", "r4_eik#3", [(0, 0, 0, 128, 128, 0, 0), (1, 0, 0, 128, 128, 128, 0), (2, 0, 0, 48, 128, 256, 0)], 304, 128, 144),
    "hak_sel": ("scc_tops.arc", "y5_tic_0", [(0, 0, 0, 128, 80, 0, 0), (1, 0, 0, 96, 80, 128, 0)], 224, 80, 16),
    "eik_sel": ("scc_tops.arc", "y5_tic_0", [(0, 0, 80, 128, 128, 0, 0), (1, 0, 80, 96, 128, 128, 0), (2, 0, 0, 128, 56, 0, 48),
                                             (2, 16, 56, 96, 112, 128, 48)], 224, 104, 32),
}


@functools.lru_cache(None)
def _file(arc):
    p = os.path.join(U.ORIG_ARC_DIR, arc)
    d = open(p, "rb").read()
    return d, U.banks(d, U.elf_symbols(d))


def source(key):
    """(index canvas, 256 palette colours as int RGBA) of the Japanese logo."""
    arc, bank, parts, W, H, pn = CANV[key]
    d, banks = _file(arc)
    b = U.bank_named(banks, bank)
    pal = U.palette_colours(d, b["pal"])[pn * 16:pn * 16 + 256].astype(int)
    c = np.zeros((H, W), np.uint8)
    for pg, x0, y0, x1, y1, cx, cy in parts:
        c[cy:cy + y1 - y0, cx:cx + x1 - x0] = U.decode_indices(d, *b["pages"][pg])[y0:y1, x0:x1]
    return c, pal


class Quant:
    """RGB -> nearest index among the colours the canvas already uses (weighted distance)."""
    def __init__(self, pal, canvas):
        self.idx = np.array(sorted(set(np.unique(canvas).tolist()) - {0}))
        self.rgb = pal[self.idx][:, :3].astype(float)
    def __call__(self, rgb):
        a = np.asarray(rgb, float)
        flat = a.reshape(-1, 3)
        d = ((flat[:, None, :] - self.rgb[None]) ** 2 * np.array([3, 4, 2])).sum(-1)
        return self.idx[d.argmin(1)].reshape(a.shape[:-1]).astype(np.uint8)


# ---- masks at 1x ------------------------------------------------------------------------------------------------------------------
def grow(m, n=1, diag=True):
    for _ in range(n):
        p = np.pad(m, 1); o = m.copy()
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if (dy or dx) and (diag or not (dy and dx)):
                    o |= p[1 + dy:1 + dy + m.shape[0], 1 + dx:1 + dx + m.shape[1]]
        m = o
    return m


def ring(m, spec):
    """grow by a list of steps: 8 = 8-neighbour step, 4 = 4-neighbour step (rounder outline)."""
    for s in spec:
        m = grow(m, 1, diag=(s == 8))
    return m


def shift(m, dy, dx):
    out = np.zeros_like(m); h, w = m.shape
    out[max(dy, 0):h + min(dy, 0), max(dx, 0):w + min(dx, 0)] = m[max(-dy, 0):h + min(-dy, 0), max(-dx, 0):w + min(-dx, 0)]
    return out


def poly(pts, H, W):
    im = Image.new("L", (W, H), 0); ImageDraw.Draw(im).polygon([tuple(p) for p in pts], fill=255)
    return np.asarray(im) > 0


def despeckle(m):
    p = np.pad(m, 1)
    n = sum(p[1 + dy:1 + dy + m.shape[0], 1 + dx:1 + dx + m.shape[1]] for dy in (-1, 0, 1) for dx in (-1, 0, 1) if dy or dx)
    return (m & (n > 1)) | (~m & (n >= 7))


# ---- lettering ---------------------------------------------------------------------------------------------------------------------
def hires(text, face, cap, squeeze=1.0, track=0.0, shear=0.0, rise=0.0, bold=0.0):
    """coverage (float, OV x) of `text`: capitals `cap` px, letters squeezed, extra tracking (1x px), italic `shear`
    (dx per dy), baseline rising `rise` 1x px from the left end to the right end; `bold` = stroke in 1x px."""
    path, idx = FACES[face]
    probe = ImageFont.truetype(path, 400, index=idx)
    bb = probe.getbbox("H")
    f = ImageFont.truetype(path, max(4, round(400 * cap * OV / (bb[3] - bb[1]))), index=idx)
    st = int(round(bold * OV))
    pad = int(cap * OV * 0.8) + st + 8 * OV
    if track:
        widths = [f.getlength(ch) + track * OV for ch in text]
        tw = int(sum(widths)) + 2 * pad
    else:
        tw = int(f.getlength(text)) + 2 * pad
    H0 = int(cap * OV * 1.9) + 2 * pad
    img = Image.new("L", (tw, H0), 0)
    dr = ImageDraw.Draw(img)
    base = pad + int(cap * OV * 1.2)
    if track:
        x = pad
        for ch, w in zip(text, widths):
            dr.text((x, base), ch, font=f, fill=255, anchor="ls", stroke_width=st, stroke_fill=255)
            x += w
    else:
        dr.text((pad, base), text, font=f, fill=255, anchor="ls", stroke_width=st, stroke_fill=255)
    if squeeze != 1.0:
        img = img.resize((max(1, round(img.width * squeeze)), img.height), Image.LANCZOS)
    W = img.width
    k = -rise * OV / max(1.0, (W - 2 * pad))          # y_in = y_out + ... : right end higher
    # output (x, y) samples input (x + shear * (y - base), y - k * (x - pad))
    img = img.transform(img.size, Image.AFFINE, (1, shear, -shear * base, -k, 1, k * pad), Image.BICUBIC)
    a = np.asarray(img, np.float32) / 255.0
    ys = np.nonzero(a.max(1) > 0.01)[0]; xs = np.nonzero(a.max(0) > 0.01)[0]
    y0 = ys.min() // OV * OV; x0 = xs.min() // OV * OV
    a = a[y0:, x0:]
    h = (ys.max() - y0) // OV * OV + OV; w = (xs.max() - x0) // OV * OV + OV
    return a[:h, :w], (base - y0) / OV


def to1x(cov):
    h, w = cov.shape
    return cov.reshape(h // OV, OV, w // OV, OV).mean((1, 3))


def letters(text, face, cap, thr=0.5, **kw):
    """1x mask + 1x coverage + baseline row of the left end."""
    cov, base = hires(text, face, cap, **kw)
    c1 = to1x(cov)
    return c1 >= thr, c1, base


def grad(stops, n):
    f = np.linspace(0, 1, max(n, 1))
    xs = [s[0] for s in stops]
    return np.stack([np.interp(f, xs, [s[1][k] for s in stops]) for k in range(3)], 1)


def styled(mask, cov, st, pad=8):
    """Build the coloured lettering. mask/cov 1x. st: dict with
       face: gradient stops; stripes: (period, amount) lighter rows; soft: (lo, colour) face-edge tone for cov in [lo, .5)
       layers: list of (kind, args, colour) applied inside-out: ("ring", [8,4..]), ("extrude", (dy, dx, depth)), ("shadow", (dy, dx))
       Returns rgb (H, W, 3) float, alpha bool, offset pad."""
    H, W = mask.shape
    m = np.zeros((H + 2 * pad, W + 2 * pad), bool); m[pad:pad + H, pad:pad + W] = mask
    cv = np.zeros(m.shape, float); cv[pad:pad + H, pad:pad + W] = cov
    soft = st.get("soft")
    face = m.copy()
    edge = np.zeros_like(m)
    if soft:
        edge = (cv >= soft[0]) & ~m & grow(m, 1, False)
        face = m | edge
    face = despeckle(face) if st.get("despeckle", True) else face
    rgb = np.zeros(m.shape + (3,)); al = np.zeros(m.shape, bool)
    cur = face.copy()
    order = []                                       # (mask, colour or callable) from inside out
    for kind, args, col in st["layers"]:
        if kind == "ring":
            nxt = ring(cur, args)
            order.append((nxt & ~cur, col)); cur = nxt
        elif kind == "extrude":
            dy, dx, depth = args
            ex = cur.copy()
            for k in range(1, depth + 1):
                ex |= shift(cur, int(round(dy * k)), int(round(dx * k)))
            order.append((ex & ~cur, col)); cur = ex
        elif kind == "shadow":
            dy, dx = args
            sh = shift(cur, dy, dx)
            order.append((sh & ~cur, col)); cur = cur | sh
    # paint outermost first
    for msk, col in reversed(order):
        if callable(col):
            rgb[msk] = col(msk)[msk]
        else:
            rgb[msk] = col
        al |= msk
    ys = np.nonzero(face.any(1))[0]
    rows = np.zeros((m.shape[0], 3))
    g = grad(st["face"], ys.max() - ys.min() + 1)
    if st.get("stripes"):
        per, amt, ph = st["stripes"]
        r = np.arange(len(g))
        g = g + ((r + ph) % per == 0)[:, None] * amt
    rows[ys.min():ys.max() + 1] = np.clip(g, 0, 255)
    fc = np.broadcast_to(rows[:, None, :], rgb.shape)
    rgb[face] = fc[face]
    if soft:
        e2 = edge & face
        rgb[e2] = soft[1]
    al |= face
    return rgb, al, face, pad


def place(dst_rgb, dst_al, rgb, al, x, y):
    """paste with clipping; returns the mask of pasted pixels in dst coordinates."""
    H, W = dst_al.shape; h, w = al.shape
    out = np.zeros((H, W), bool)
    sx0, sy0 = max(0, -x), max(0, -y); dx0, dy0 = max(0, x), max(0, y)
    ww = min(w - sx0, W - dx0); hh = min(h - sy0, H - dy0)
    if ww <= 0 or hh <= 0: return out
    a = al[sy0:sy0 + hh, sx0:sx0 + ww]
    dst_rgb[dy0:dy0 + hh, dx0:dx0 + ww][a] = rgb[sy0:sy0 + hh, sx0:sx0 + ww][a]
    dst_al[dy0:dy0 + hh, dx0:dx0 + ww] |= a
    out[dy0:dy0 + hh, dx0:dx0 + ww] = a
    return out


# ---- fills -------------------------------------------------------------------------------------------------------------------------
def nearest_fill(rgb, al, hole, valid):
    """each hole pixel takes colour + opacity of the nearest valid pixel (valid may include transparent ones)."""
    ys, xs = np.nonzero(valid)
    hy, hx = np.nonzero(hole)
    out_rgb = rgb.copy(); out_al = al.copy()
    if not len(hy): return out_rgb, out_al
    for i in range(0, len(hy), 2000):
        d = (hy[i:i + 2000, None] - ys[None]) ** 2 + (hx[i:i + 2000, None] - xs[None]) ** 2
        j = d.argmin(1)
        out_rgb[hy[i:i + 2000], hx[i:i + 2000]] = rgb[ys[j], xs[j]]
        out_al[hy[i:i + 2000], hx[i:i + 2000]] = al[ys[j], xs[j]]
    return out_rgb, out_al


def row_fill(rgb, al, hole, valid):
    """per row: linear blend between the nearest valid pixels left and right."""
    out = rgb.copy(); oal = al.copy()
    H, W = hole.shape
    for y in range(H):
        xs = np.nonzero(hole[y])[0]
        if not len(xs): continue
        good = np.nonzero(valid[y])[0]
        if not len(good): continue
        for x in xs:
            l = good[good < x]; r = good[good > x]
            if len(l) and len(r):
                a, b = l[-1], r[0]; t = (x - a) / (b - a)
                out[y, x] = rgb[y, a] * (1 - t) + rgb[y, b] * t; oal[y, x] = al[y, a] or al[y, b]
            else:
                s = l[-1] if len(l) else r[0]
                out[y, x] = rgb[y, s]; oal[y, x] = al[y, s]
    return out, oal


def concat(pieces, gap=2):
    """pieces: list of (mask, cov, base) -> one (mask, cov, base) aligned on the baseline, `gap` px apart."""
    up = max(int(np.ceil(b)) for m, c, b in pieces); down = max(m.shape[0] - int(np.ceil(b)) for m, c, b in pieces)
    W = sum(m.shape[1] for m, c, b in pieces) + gap * (len(pieces) - 1)
    M = np.zeros((up + down, W), bool); C = np.zeros((up + down, W))
    x = 0
    for m, c, b in pieces:
        y = up - int(np.ceil(b)); h, w = m.shape
        M[y:y + h, x:x + w] |= m; C[y:y + h, x:x + w] = np.maximum(C[y:y + h, x:x + w], c); x += w + gap
    return M, C, up


def with_tildes(text, face, cap, tface="black", tcap=None, tgap=3, **kw):
    t = letters("~", tface, tcap or cap * 0.8)
    body = letters(text, face, cap, **kw)
    return concat([t, body, t], tgap)


# ---- Hakkyu Dream ------------------------------------------------------------------------------------------------------------------
WHITE, NAVY = (255, 255, 255), (0, 0, 74)


def _ext_col(m):
    H, W = m.shape; r = np.arange(H)[:, None]; out = np.zeros((H, W, 3))
    out[:] = (0, 0, 140); out[(r % 3 == 0).repeat(W, 1)] = (16, 57, 246)
    return out


HAK_TITLE = dict(face=[(0, (140, 190, 255)), (0.3, (40, 100, 255)), (0.6, (0, 0, 255)), (1, (0, 0, 205))], stripes=(4, (24, 50, 0), 1),
                 soft=(0.3, (90, 123, 180)),
                 layers=[("ring", [4], WHITE), ("extrude", (1, -0.5, 7), _ext_col), ("ring", [8], NAVY), ("ring", [8, 4], WHITE), ("ring", [4], NAVY)])
HAK_SUB = dict(face=[(0, (255, 255, 115)), (0.45, (255, 222, 74)), (0.75, (255, 148, 8)), (1, (255, 90, 16))], soft=None,
               layers=[("ring", [4], (65, 0, 0)), ("ring", [8, 4], WHITE), ("ring", [8], (0, 0, 123))])


def _with_depth(st, depth):
    return dict(st, layers=[(k, (a[0], a[1], depth) if k == "extrude" else a, c) for k, a, c in st["layers"]])


# right-hand decoration (pennant + fan of two-tone spikes), title-screen coordinates
PENNANT = [(128, 64), (128, 42), (250, 15.5), (253, 19), (238, 64)]   # tip ends inside the top spike of the fan (drawn over it)
HUB = (236, 42)
SPIKES = [((261, 3), "b", 10), ((288, 15), "y", 10), ((298, 35), "b", 9), ((290, 48), "r", 6), ((308, 59), "y", 10),
          ((298, 71), "b", 8.5), ((302, 92), "y", 9)]
SPIKE_COL = {"b": ((60, 130, 255), (0, 16, 222)), "y": ((255, 230, 74), (255, 148, 8)), "r": ((246, 98, 131), (230, 32, 65))}
PENNANT_COL = ((238, 74, 106), (230, 32, 65))


def deco(H, W, f, k=1.0):
    S4 = 4
    big = Image.new("RGB", (W * S4, H * S4), (0, 0, 0)); msk = Image.new("L", (W * S4, H * S4), 0)
    d = ImageDraw.Draw(big); dm = ImageDraw.Draw(msk)
    P = lambda pts: [(f(x, y)[0] * S4, f(x, y)[1] * S4) for x, y in pts]
    pm = Image.new("L", big.size, 0); ImageDraw.Draw(pm).polygon(P(PENNANT), fill=255)
    st = Image.new("RGB", big.size, PENNANT_COL[1]); ds = ImageDraw.Draw(st)
    per = 5 * k * S4
    for i in range(-80, 200):
        x0 = i * per
        ds.polygon([(x0, 0), (x0 + per * 0.45, 0), (x0 + per * 0.45 - big.size[1] * 0.5, big.size[1]), (x0 - big.size[1] * 0.5, big.size[1])],
                   fill=PENNANT_COL[0])
    big.paste(st, (0, 0), pm); msk.paste(255, (0, 0), pm)
    hx, hy = HUB
    for (tx, ty), ck, w in SPIKES:
        ax, ay = tx - hx, ty - hy; L = np.hypot(ax, ay); ux, uy = ax / L, ay / L; nx, ny = -uy, ux
        bx, by = hx + ux * L * 0.3, hy + uy * L * 0.3
        w = w * max(1.0, 0.8 / k)
        light = [(tx, ty), (bx + nx * w, by + ny * w), (bx, by)]
        dark = [(tx, ty), (bx, by), (bx - nx * w, by - ny * w)]
        up, dn = (light, dark) if ny < 0 else (dark, light)
        d.polygon(P(up), fill=SPIKE_COL[ck][0]); d.polygon(P(dn), fill=SPIKE_COL[ck][1])
        dm.polygon(P(up), fill=255); dm.polygon(P(dn), fill=255)
    a = np.asarray(big, float).reshape(H, S4, W, S4, 3)
    mm = np.asarray(msk).reshape(H, S4, W, S4) > 0
    m = mm.mean((1, 3)) >= 0.5
    cnt = mm.sum((1, 3))[..., None]
    rgb = (a * mm[..., None]).sum((1, 3)) / np.maximum(cnt, 1)
    return rgb, m


def _classes(c, pal):
    rgb = pal[c][..., :3].astype(int); R, G, B = rgb[..., 0], rgb[..., 1], rgb[..., 2]
    nz = c > 0
    blue = nz & (B > R + 50) & (B >= 60) & (R < 130)
    white = nz & (R > 190) & (G > 190) & (B > 190)
    warm = nz & (R > 150) & (B < 140) & (R >= G)
    dred = nz & (R > B) & (R < 140) & (G < 40)
    navy = nz & (B > R + 25) & (R < 70) & (G < 70)
    return blue, white, warm, dred, navy


HAK_TZ = [(20, 96), (28, 42), (100, 40), (175, 22), (245, 14), (262, 58), (292, 104), (105, 100), (40, 102)]
HAK_SZ = [(100, 86), (276, 84), (278, 120), (98, 122)]
HAK_DZ = [(140, 0), (312, 0), (312, 96), (268, 96), (262, 84), (140, 84)]
_K = 0.663
def _f(x, y): return (56.5 + (x - 52.5) * _K, 41.5 + (y - 65) * _K)
HAK = {
    "hak_tit": dict(
        T=dict(text=dict(text="HAKKYU DREAM", face="futura", cap=34, squeeze=0.72, shear=0.22, rise=14, track=2.2, bold=0.3), x=14, y=34,
               style=HAK_TITLE),
        Sb=dict(text=dict(text="Industrial-League Ball!", face="avh", cap=16, squeeze=0.78, track=0.7), cx=184, y=92, style=HAK_SUB),
        tz=HAK_TZ, sz=HAK_SZ, dz=HAK_DZ, ball=(52.5, 65.0, 44.5), fmap=lambda x, y: (x, y), k=1.0),
    "hak_sel": dict(
        T=dict(text=dict(text="HAKKYU DREAM", face="futura", cap=22, squeeze=0.68, shear=0.22, rise=9, track=1.4, bold=0.2), x=22, y=22,
               style=_with_depth(HAK_TITLE, 5)),
        Sb=dict(text=dict(text="Industrial-League Ball!", face="din", cap=12, squeeze=1.0, track=0.6), cx=139, y=58, style=HAK_SUB),
        tz=[(26, 66), (32, 30), (80, 26), (130, 14), (178, 6), (186, 12), (191, 40), (197, 62), (80, 68), (40, 70)],
        sz=[_f(x, y) for x, y in HAK_SZ], dz=[_f(x, y) for x, y in HAK_DZ], ball=(56.5, 41.5, 29.5), fmap=_f, k=_K),
}


def hakkyu(key):
    P = HAK[key]
    c, pal = source(key); H, W = c.shape
    q = Quant(pal, c)
    blue, white, warm, dred, navy = _classes(c, pal)
    TZ = poly(P["tz"], H, W); SZ = poly(P["sz"], H, W)
    M = (TZ & (blue | white | navy)) | (SZ & (blue | white | warm | dred | navy))
    M = (grow(M, 1) & (TZ | SZ) & (c > 0)) | M
    rgb = pal[c][..., :3].astype(float); al = c > 0
    cx, cy, rr = P["ball"]
    yy, xx = np.mgrid[0:H, 0:W]; dist = np.hypot(xx - cx, yy - cy)
    # right-hand decoration redrawn clean (behind everything new)
    DZ = poly(P["dz"], H, W) & ~(dist <= rr + 1.5)
    al[DZ] = False; M &= ~DZ
    drgb, dm = deco(H, W, P["fmap"], P["k"])
    wb = ring(dm, [8, 4]) & ~dm & ~al
    rgb[wb] = WHITE; al[wb] = True
    rgb[dm] = drgb[dm]; al[dm] = True
    # new lettering
    nrgb = np.zeros_like(rgb); nal = np.zeros_like(al)
    T, Sb = P["T"], P["Sb"]
    m, cv, b = letters(**T["text"]); r, a, f, pad = styled(m, cv, T["style"])
    place(nrgb, nal, r, a, T["x"] - pad, T["y"] - pad)
    m2, cv2, b2 = with_tildes(**Sb["text"]); r2, a2, f2, pad2 = styled(m2, cv2, Sb["style"])
    sx = Sb["cx"] - m2.shape[1] // 2
    place(nrgb, nal, r2, a2, sx - pad2, Sb["y"] - pad2)
    # Japanese lettering not covered by the English: ball disc rebuilt, the rest cut out with a white edge
    hole = M & ~nal
    inball = hole & (dist <= rr - 0.5)
    rgb[inball] = WHITE; al[inball] = True
    rim = hole & (np.abs(dist - rr) <= 0.8)
    rgb[rim] = (106, 106, 148); al[rim] = True
    cut = hole & ~inball & ~rim
    al[cut] = False
    edge = cut & grow(al & ~cut, 1) & ~nal
    rgb[edge] = WHITE; al[edge] = True
    rgb[nal] = nrgb[nal]; al |= nal
    out = np.zeros((H, W), np.uint8); out[al] = q(rgb[al])
    return out


# ---- Eikan Nine --------------------------------------------------------------------------------------------------------------------
def _bevel_col(m):
    H, W = m.shape; out = np.zeros((H, W, 3))
    out[:] = grad([(0, (238, 238, 255)), (0.5, (205, 205, 230)), (1, (150, 150, 185))], H)[:, None, :]
    return out


EIK_TITLE = dict(face=[(0, (255, 246, 197)), (0.14, (255, 230, 140)), (0.32, (255, 200, 8)), (0.5, (238, 160, 0)), (0.7, (213, 98, 0)),
                       (0.88, (197, 57, 0)), (1, (214, 100, 72))], soft=None,
                 layers=[("extrude", (-1, -1, 3), _bevel_col), ("shadow", (1, 1), (16, 16, 24)), ("shadow", (1, 1), (16, 16, 24))])
EIK_SUB = dict(face=[(0, (115, 50, 20)), (1, (80, 24, 8))], soft=None, layers=[("ring", [8, 4], (255, 255, 238))])
EIK = {
    "eik_tit": dict(
        T=dict(text=dict(text="EIKAN NINE", face="futura", cap=38, squeeze=0.72, track=2.0, bold=0.4), cx=145, y=38, style=EIK_TITLE),
        Sb=dict(text=dict(text="Build a Powerhouse Club!", face="avh", cap=15, squeeze=0.86, track=0.6), cx=150, y=91, style=EIK_SUB),
        tz=[(36, 28), (254, 28), (254, 87), (36, 87)], sz=[(56, 87), (246, 87), (246, 114), (56, 114)]),
    "eik_sel": dict(
        T=dict(text=dict(text="EIKAN NINE", face="futura", cap=25, squeeze=0.72, track=1.5, bold=0.1), cx=114, y=32,
               style=dict(EIK_TITLE, layers=[("extrude", (-1, -1, 2), _bevel_col), ("shadow", (1, 1), (16, 16, 24))])),
        Sb=dict(text=dict(text="Build a Powerhouse Club!", face="din", cap=13, squeeze=0.95, track=0.6), cx=115, y=67,
                style=dict(EIK_SUB, layers=[("ring", [8], (255, 255, 238))])),
        tz=[(40, 28), (190, 28), (190, 64), (40, 64)], sz=[(52, 64), (180, 64), (180, 84), (52, 84)]),
}


def eikan(key):
    P = EIK[key]
    c, pal = source(key); H, W = c.shape
    q = Quant(pal, c)
    rgb0 = pal[c][..., :3].astype(int); R, G, B = rgb0[..., 0], rgb0[..., 1], rgb0[..., 2]; nz = c > 0
    warm = nz & (R > 140) & (B < 140) & (R > G)
    light = nz & (R > 120) & (G > 120) & (B > 140) & ~(B > R + 25)
    brown = nz & (R > G + 25) & (R < 190) & (B < 110) & (G < 130)
    cream = nz & (R > 180) & (G > 170) & (B > 140)
    TZ = poly(P["tz"], H, W); SZ = poly(P["sz"], H, W)
    M = (TZ & (warm | light)) | (SZ & (brown | cream))
    M = (grow(M, 2) & TZ) | (grow(M, 1) & SZ) | M
    rgb, al = row_fill(rgb0.astype(float), nz.copy(), M, ~M & nz)
    nrgb = np.zeros_like(rgb); nal = np.zeros_like(al)
    T, Sb = P["T"], P["Sb"]
    m, cv, b = letters(**T["text"]); r, a, f, pad = styled(m, cv, T["style"])
    place(nrgb, nal, r, a, T["cx"] - m.shape[1] // 2 - pad, T["y"] - pad)
    m2, cv2, b2 = letters(**Sb["text"]); r2, a2, f2, pad2 = styled(m2, cv2, Sb["style"])
    place(nrgb, nal, r2, a2, Sb["cx"] - m2.shape[1] // 2 - pad2, Sb["y"] - pad2)
    rgb[nal] = nrgb[nal]; al |= nal
    out = np.zeros((H, W), np.uint8); out[al] = q(rgb[al])
    return out


# ---- styles: one window of a redrawn logo per paint rectangle ----------------------------------------------------------------------
# Hakkyu Dream redone 2026-10-20 (_work/ui_pages/hakkyu/compose.py: original ball, pennant and spikes kept and rebuilt
# behind the words, perspective italic HAKKYU DREAM with the Japanese 3D extrusion): the finished index canvases.
_HAK_FINAL = os.path.join(config.UI_PAGES_DIR, "hakkyu", "final_%s.npy")


@functools.lru_cache(None)
def logo(key):
    if key.startswith("hak") and os.path.exists(_HAK_FINAL % key):
        return np.load(_HAK_FINAL % key)
    return hakkyu(key) if key.startswith("hak") else eikan(key)


def _window(key, y0, y1, x0, x1):
    def style(ink, base):
        return logo(key)[y0:y1, x0:x1].copy(), 0
    return style


STYLES.update({
    # scc_tops.arc y5_tic_0 (mode-select panel): Hakkyu Dream page 0 [0,0,128,80], page 1 [0,0,96,80]
    "l11_hak0": _window("hak_sel", 0, 80, 0, 128), "l11_hak1": _window("hak_sel", 0, 80, 128, 224),
    # Eikan Nine: page 0 [0,80,128,128], page 1 [0,80,96,128], page 2 [0,0,128,56] and [16,56,96,112]
    "l11_eik0": _window("eik_sel", 0, 48, 0, 128), "l11_eik1": _window("eik_sel", 0, 48, 128, 224),
    "l11_eik2": _window("eik_sel", 48, 104, 0, 128), "l11_eik3": _window("eik_sel", 48, 104, 128, 208),
    # scs_titl.arc y5_tic_h1 (Hakkyu Dream title screen): pages 0, 1 [0,0,128,128], page 2 [0,0,56,128]
    "l11_h1_0": _window("hak_tit", 0, 128, 0, 128), "l11_h1_1": _window("hak_tit", 0, 128, 128, 256), "l11_h1_2": _window("hak_tit", 0, 128, 256, 312),
    # sct_titl.arc r4_eik#3 (Eikan Nine title screen): pages 0, 1 [0,0,128,128], page 2 [0,0,48,128]
    "l11_e1_0": _window("eik_tit", 0, 128, 0, 128), "l11_e1_1": _window("eik_tit", 0, 128, 128, 256), "l11_e1_2": _window("eik_tit", 0, 128, 256, 304),
})
