"""The big animated 対 ("versus") of the Success match intro (scs_vs.arc z5_svs_0) redrawn as an italic "VS".
Styles vsf_p<page> (one per page, paint entries in ui_specs/scs_vs.json with "copy": "clear" over the whole page).

The effect is built from one letter mask L ("VS", Impact, italic) placed on the screen frame of the sprites
(origin = sprite origin), plus a 2-pixel drop shadow S to the lower right (M = L | S), exactly like the Japanese art:
  page 0       outline ring (index 2) drawn piece by piece by sprites 01-18 (rectangles fixed by the sprite table)
  page 1       white fill (index 1 = letters, 2 = ring) for sprite 00; its top-left 32x32 is also the red corner
               bits 19-22 (palette 0)
  pages 2-7    white flash silhouettes growing / blurring (sprites 24-26)
  pages 8-9    white silhouette (23, palette 12) and the base of the final art (27-2b, palette 16): dark letters,
               white band, green gradient rim, cyan outer rim
  pages 10-13  the flame-textured letters, four animation frames (28-2b, palette 20)
Every band colour is taken from the Japanese pages: a new pixel at octagonal distance k from M takes the index of the
nearest Japanese pixel at the same distance (vertical distance weighted, so the green gradient keeps running top to
bottom; same 2x2 position for the dithered flash edges). The flame texture of each frame is kept where the old
letters were and mirrored in vertically (along the flame streaks) where the new letters reach outside them."""
import os, sys, functools
import numpy as np
from PIL import Image, ImageDraw, ImageFont

T = os.path.expanduser("~/Projects/Pawapuro/Pawapros15-tools")
if T not in sys.path:
    sys.path.insert(0, T)
import ui_textures as U

ARC, BANK = "scs_vs.arc", "z5_svs_0"
FACE = "/System/Library/Fonts/Supplemental/Impact.ttf"
OV = 8
N, O = 192, 96                     # screen canvas, origin at (O, O)
# glyph: cap height, horizontal squeeze, shear (negative = leaning right), V and S top-left on screen
GLYPH = dict(h=110, squeeze=0.6, shear=-0.08, v=(-49, -58), s=(-10, -57))
RING = 5                           # outline / fill ring width round the letters

BIG = lambda p, q: [(p, 0, 0, 128, 128, -80, -88), (q, 0, 0, 32, 128, 48, -88), (q, 32, 0, 112, 48, -80, 40),
                    (q, 32, 48, 112, 96, 0, 40)]
LAY = {  # layer: [(page, x0, y0, x1, y1, screen x, screen y)] from the sprite parts
    "outline": [(0, 0, 0, 128, 128, -64, -64)], "fill": [(1, 0, 0, 128, 128, -64, -64)],
    "b1": BIG(2, 3), "b2": BIG(4, 5), "b3": BIG(6, 7),
    "rim": [(8, 0, 0, 128, 128, -72, -80), (9, 0, 0, 16, 128, 56, -80), (9, 16, 0, 88, 32, -72, 48),
            (9, 16, 32, 88, 64, 0, 48)],
    "f0": [(10, 0, 0, 128, 128, -64, -64)], "f1": [(11, 0, 0, 128, 128, -64, -64)],
    "f2": [(12, 0, 0, 128, 128, -64, -64)], "f3": [(13, 0, 0, 128, 128, -64, -64)],
}


@functools.lru_cache(None)
def _file():
    d = open(os.path.join(U.ORIG_ARC_DIR, ARC), "rb").read()
    b = U.bank_named(U.banks(d, U.elf_symbols(d)), BANK)
    return d, b


def page(k):
    d, b = _file()
    return U.decode_indices(d, *b["pages"][k]).copy()


def extent(name):
    m = np.zeros((N, N), bool)
    for pg, x0, y0, x1, y1, sx, sy in LAY[name]:
        m[O + sy:O + sy + y1 - y0, O + sx:O + sx + x1 - x0] = True
    return m


def canvas(name):
    c = np.zeros((N, N), np.uint8)
    for pg, x0, y0, x1, y1, sx, sy in LAY[name]:
        c[O + sy:O + sy + y1 - y0, O + sx:O + sx + x1 - x0] = page(pg)[y0:y1, x0:x1]
    return c


def uncanvas(name, c, pages):
    for pg, x0, y0, x1, y1, sx, sy in LAY[name]:
        if pg not in pages:
            pages[pg] = page(pg)
        pages[pg][y0:y1, x0:x1] = c[O + sy:O + sy + y1 - y0, O + sx:O + sx + x1 - x0]


# ---- masks ----------------------------------------------------------------------------------------------------------------
def grow(m, n=1, diag=True):
    m = m.copy()
    for _ in range(n):
        g = m.copy()
        g[1:] |= m[:-1]; g[:-1] |= m[1:]; g[:, 1:] |= m[:, :-1]; g[:, :-1] |= m[:, 1:]
        if diag:
            g[1:, 1:] |= m[:-1, :-1]; g[1:, :-1] |= m[:-1, 1:]; g[:-1, 1:] |= m[1:, :-1]; g[:-1, :-1] |= m[1:, 1:]
        m = g
    return m


def odist(m, maxn=40):
    """octagonal distance from m (0 inside): 4- and 8-neighbour steps in turn"""
    out = np.full(m.shape, 999, int)
    cur = m.copy(); out[cur] = 0
    for k in range(1, maxn):
        nx = grow(cur, 1, diag=(k % 2 == 0)); out[nx & ~cur] = k; cur = nx
    return out


def shift(m, dy, dx):
    o = np.zeros_like(m); H, W = m.shape
    o[max(dy, 0):H + min(dy, 0), max(dx, 0):W + min(dx, 0)] = m[max(-dy, 0):H + min(-dy, 0), max(-dx, 0):W + min(-dx, 0)]
    return o


def shadow_of(L):
    s = np.zeros_like(L)
    for dy in (0, 1, 2):
        for dx in (0, 1, 2):
            s |= shift(L, dy, dx)
    return s & ~L


def letter(ch, h, shear, squeeze):
    f = ImageFont.truetype(FACE, 400)
    bb = f.getbbox(ch)
    im = Image.new("L", (bb[2] + 200, bb[3] + 200), 0)
    ImageDraw.Draw(im).text((100, 100), ch, font=f, fill=255)
    a = np.array(im); ys, xs = np.nonzero(a > 127)
    a = a[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    H = h * OV; W = int(a.shape[1] * H / a.shape[0] * squeeze)
    im = Image.fromarray(a).resize((W, H), Image.LANCZOS)
    if shear:
        pad = int(abs(shear) * H) + 2
        im = im.transform((W + pad, H), Image.AFFINE, (1, shear, -shear * H if shear > 0 else 0, 0, 1, 0),
                          resample=Image.BICUBIC)
    a = np.array(im).astype(float)
    hh, ww = a.shape[0] // OV, a.shape[1] // OV
    a = a[:hh * OV, :ww * OV].reshape(hh, OV, ww, OV).mean((1, 3)) / 255
    m = a >= 0.5
    ys, xs = np.nonzero(m)
    return m[ys.min():ys.max() + 1, xs.min():xs.max() + 1]


@functools.lru_cache(None)
def new_letters():
    g = GLYPH
    L = np.zeros((N, N), bool)
    for ch, (x, y) in (("V", g["v"]), ("S", g["s"])):
        m = letter(ch, g["h"], g["shear"], g["squeeze"])
        L[O + y:O + y + m.shape[0], O + x:O + x + m.shape[1]] |= m
    return L


@functools.lru_cache(None)
def old_letters():
    fs = [canvas(k) for k in ("f0", "f1", "f2", "f3")]
    M = fs[0] > 0
    D = np.all([f == 2 for f in fs], 0)          # the drop shadow: index 2 in every frame
    return M, M & ~D


# ---- band transfer --------------------------------------------------------------------------------------------------------
def transfer(old, dold, dnew, region, ks, wy=2.0, cell=False):
    """new index image: each pixel of `region` with distance k in `ks` takes the index of the nearest old pixel
    (dy weighted by wy) with the same distance k (and the same 2x2 cell position if `cell`)."""
    out = np.zeros_like(old)
    yy, xx = np.mgrid[0:N, 0:N]
    for k in ks:
        tgt = region & (dnew == k)
        if not tgt.any():
            continue
        classes = [(a, b) for a in (0, 1) for b in (0, 1)] if cell else [None]
        for cl in classes:
            t = tgt if cl is None else tgt & (yy % 2 == cl[0]) & (xx % 2 == cl[1])
            src = (dold == k) if cl is None else (dold == k) & (yy % 2 == cl[0]) & (xx % 2 == cl[1])
            if not t.any() or not src.any():
                continue
            ty, tx = np.nonzero(t); sy, sx = np.nonzero(src)
            for i in range(0, len(ty), 512):
                d2 = ((ty[i:i + 512, None] - sy[None]) * wy) ** 2 + (tx[i:i + 512, None] - sx[None]) ** 2
                j = d2.argmin(1)
                out[ty[i:i + 512], tx[i:i + 512]] = old[sy[j], sx[j]]
    return out


def flame_fill(frame, Lold_core, Lnew):
    """texture for the new letters: kept inside the old letters' core, mirrored in vertically elsewhere."""
    out = np.zeros_like(frame)
    core_cols = np.nonzero(Lold_core.any(0))[0]
    ys, xs = np.nonzero(Lnew)
    for y, x in zip(ys, xs):
        cx = x if Lold_core[:, x].any() else core_cols[np.abs(core_cols - x).argmin()]
        col = Lold_core[:, cx]
        if col[y] and cx == x:
            out[y, x] = frame[y, x]
            continue
        inside = np.nonzero(col)[0]
        j = inside[np.abs(inside - y).argmin()]                 # nearest core pixel in the column
        k = abs(y - j); step = 1 if y > j else -1                # mirror back into the core
        yy = j - step * (k - 1) if k > 0 else j
        if not (0 <= yy < N and col[yy]):
            yy = j
        out[y, x] = frame[yy, cx]
    return out


@functools.lru_cache(None)
def build():
    """{page: new 128x128 index array} for pages 0-13."""
    Mo, Lo = old_letters()
    L = new_letters(); S = shadow_of(L); M = L | S
    do, dn = odist(Mo), odist(M)
    pages = {}
    # outline (page 0) and white fill (page 1): ring of RING pixels round the letters
    dl = odist(L)
    ring = (dl >= 1) & (dl <= RING)
    c = np.zeros((N, N), np.uint8); c[ring] = 2
    uncanvas("outline", c, pages)
    c = np.zeros((N, N), np.uint8); c[L] = 1; c[ring] = 2
    uncanvas("fill", c, pages)
    # flash silhouettes (pages 2-7): the old bands, dither kept by 2x2 position
    for name in ("b1", "b2", "b3"):
        old = canvas(name); ext = extent(name)
        c = transfer(old, do, dn, ext & (dn > 0), range(1, 40), wy=1.0, cell=True)
        c[M] = old[Mo][0]
        uncanvas(name, c, pages)
    # rim (pages 8-9): dark letters, grey shadow, white band, green gradient, cyan rim
    old = canvas("rim"); ext = extent("rim")
    c = transfer(old, do, dn, ext & (dn > 0), range(1, 40), wy=3.0)
    c[(dn > 0) & np.isin(c, (1, 2, 3))] = 4                 # no stray greys in the white band
    c[L] = 1; c[S] = 2
    uncanvas("rim", c, pages)
    # flames (pages 10-13)
    core = Lo & ~grow(~Lo, 2)
    for name in ("f0", "f1", "f2", "f3"):
        fr = canvas(name)
        c = flame_fill(fr, core, L)
        c[S] = 2
        uncanvas(name, c, pages)
    return pages


def check_fit():
    """layers that would run off their pages: {layer: pixels lost}"""
    L = new_letters(); M = L | shadow_of(L); dn = odist(M); dl = odist(L)
    need = {"outline": dl <= RING, "fill": dl <= RING, "rim": dn <= 16, "b1": dn <= 19, "b2": dn <= 21,
            "b3": dn <= 28, "f0": M}
    return {k: int((m & ~extent(k)).sum()) for k, m in need.items()}


def _style(pg):
    def style(ink, base):
        return build()[pg].copy(), 0
    return style


STYLES = {"vsf_p%02d" % k: _style(k) for k in range(14)}
