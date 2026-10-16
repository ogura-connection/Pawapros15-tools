"""Label styles of art run 9, agent B: big title logos painted into pictures that the game cuts over several pages.
Each style b9_<key>_<k> returns the window of part k (page rectangle, in the order of the sprite's parts) of a whole
redrawn picture: the original picture is built from the saved original .arc in RGB, the Japanese lettering area is
rebuilt row by row from the pixels left and right of it, the English is drawn with layers (gradient fill, rings, plate,
drop shadow) in the colours of the Japanese logo, and the result is snapped to the nearest colour the picture already
uses. Cached. Written for _work/ui_pages/gen_*_r9b_spec.py (spec "paint" entries with "copy": "clear")."""
import os, sys
import numpy as np

T = os.path.expanduser("~/Projects/Pawapuro/Pawapros15-tools")
sys.path.insert(0, T)
sys.path.insert(0, os.path.join(T, "_work/ui_pages/kit"))
import ui_type

STYLES = {}
_cache = {}


def hexrgb(h):
    h = h.lstrip("#")
    return np.array([int(h[i:i + 2], 16) for i in (0, 2, 4)], float)


def load(arcname, bankref, sprite):
    """(index canvas, colours, parts, origin, bank) of a sprite, drawn from the saved original."""
    import kit, ui_textures as U
    arc = kit.Arc(arcname)
    d = arc.D
    b = arc.resolve(d, bankref)
    ps = next(p for n, p in b["sprites"].items() if n.endswith("_" + sprite) or n == sprite)
    ps = [p for p in ps if p.x > -2000 and p.y > -2000]
    x0 = min(p.x for p in ps); y0 = min(p.y for p in ps)
    x1 = max(p.x + p.x1 - p.x0 for p in ps); y1 = max(p.y + p.y1 - p.y0 for p in ps)
    cv = np.zeros((y1 - y0, x1 - x0), np.uint8)
    for p in ps:
        idx = U.decode_indices(d, *b["pages"][p.page])[p.y0:p.y1, p.x0:p.x1]
        cv[p.y - y0:p.y - y0 + idx.shape[0], p.x - x0:p.x - x0 + idx.shape[1]] = idx
    return cv, U.palette_colours(d, b["pal"])[:256, :3].astype(float), ps, (x0, y0)


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
    for hexc, n, diag in rings:
        cur = ui_type.grow(cur, n, diagonal=diag)
        masks.append((cur, hexc))
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
    for m, hexc in masks[::-1]:
        area[m] = hexrgb(hexc)
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


def fit_text(text, maxw, maxh, extra, caps=range(40, 7, -1), squeeze=1.0, bold=0.5, slant=0.0, face="rounded"):
    """Largest cap whose mask + `extra` px each side fits (maxw, maxh): (mask, cap)."""
    for cap in caps:
        m = text_mask(text, cap, squeeze, bold, slant, face)
        if m.shape[1] + 2 * extra <= maxw and m.shape[0] + 2 * extra <= maxh:
            return m, cap
    raise ValueError("%r does not fit %dx%d" % (text, maxw, maxh))


def snap(rgb, cv, changed, colours, clear=None):
    """Nearest colour of the picture's own for every changed pixel (index 0 = clear is never chosen)."""
    used = sorted(set(np.unique(cv).tolist()) - {0})
    pal = colours[used]
    ys, xs = np.nonzero(changed)
    out = cv.copy()
    if len(ys):
        px = rgb[ys, xs]
        dist = ((px[:, None, :] - pal[None, :, :]) ** 2).sum(-1)
        out[ys, xs] = np.asarray(used)[dist.argmin(1)]
    if clear is not None:
        out[clear] = 0
    return out


# ---- the logos --------------------------------------------------------------------------------------------------

LOGOS = {}


def final(key):
    if key not in _cache:
        spec = LOGOS[key]
        cv, colours, ps, org = load(spec["arc"], spec["bank"], spec["sprite"])
        rgb = colours[cv].copy()
        changed = np.zeros(cv.shape, bool)
        clear = np.zeros(cv.shape, bool)
        spec["recipe"](rgb, cv, colours, changed, clear)
        new = snap(rgb, cv, changed, colours, clear)
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
    cv, colours, ps, org = load(LOGOS[key]["arc"], LOGOS[key]["bank"], LOGOS[key]["sprite"])
    return [(p.page, [p.x0, p.y0, p.x1, p.y1]) for p in ps]


# homerun.arc r3_hrx sprite 00: ホームラン競争 -> Home Run Derby (banner 512 x 80)
def _hr(rgb, cv, colours, changed, clear):
    box = (114, 8, 404, 80)
    rows_fill(rgb, box, cv, clear)
    m, cap = fit_text("Home Run Derby", 280, 58, 7, squeeze=0.82, bold=0.7)
    painted = draw_logo(rgb, m, 259, 42, [(0, "f6aa28"), (0.5, "ff7a50"), (1, "ff3694")],
              [("#ffffff", 2, True), ("#0f48d0", 1, True), ("#62b4f6", 2, True), ("#1862a4", 1, True)],
              plate_down=("#62b4f6", 3), shadow=("#4a6aa4", 1, 2, 2))
    changed[box[1]:box[3], box[0]:box[2]] = True
    clear &= ~painted


register("hr", "homerun.arc", "r3_hrx", "00", 5, _hr)
