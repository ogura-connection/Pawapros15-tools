"""Read lettering out of the MLB Power Pros 2008 label sheets and fit it into a smaller space.

Pawapuro 15 and MLB Power Pros 2008 (the American localisation of the same game series) draw their menu lettering the
same way, so an English label can often be cut from an MLB picture instead of being invented. An MLB "sheet" is one
texture of a .pack file in its project.bin; a "box" is the rectangle of one label on it. This module finds the boxes,
sorts the pixels of a label into roles (outline, fill, plate, ...) and shrinks a label to a given width and height
without blurring it. The functions that draw a whole spec onto an .arc are in pp15/art/spec_render.py; the command line is
pp15/art/spec_cli.py (`pp15 art ...`); the old names render, bank_of, load_spec and main are still reachable from here.

  mlb_texture(pack, tex, project)    (indices, palette, format) of one texture of an MLB .pack file
  find_boxes(idx, min_index)         label boxes (left, top, right, bottom) of a sheet, in reading order
  source_classes(spec, project)      (mask, roles) of one cropped label: which pixels are ink, and which role each has
  fit(mask, roles, ...)              the label as palette indices that fit w x h (columns and rows are carved out, not blurred)
  split_words(mask, cls, parts)      cut a label at its widest gaps into words
  draw(page, rect, area, label)      centre a fitted label in an area of a page
  add_halo(page, rect, halo)         surround everything in a rectangle with solid one-pixel rings
  despeckle(grid), carve_axis(...)   the cleaning steps the above use

Roles: a source style (SOURCE_STYLES) names every pixel "fill", "ring" or "outer" (stat labels), or "letter", "plate",
"edge_dark" or "edge_light" (command words). A spec then gives each role one palette index of the target page.
"""
import importlib
import os
import struct

import numpy as np
from PIL import Image

from pp15 import config
from pp15.art.gx_pixels import rgb5a3_colours, untile
from pp15.reference import mlb_assets

PROJECT = config.MLB_PROJECT_BIN        # the MLB project.bin the sheets are read from (a spec can name another)
_projects = {}                          # path -> opened mlb_assets.Project, so a file is opened once


def mlb_texture(pack: str, tex: int, project: str = None) -> tuple:
    """(indices (h, w), palette (n, 4), format) of the tex-th C4/C8 texture of an MLB .pack."""
    path = os.path.expanduser(project or PROJECT)
    if path not in _projects:
        _projects[path] = mlb_assets.Project(path)
    d = _projects[path].read("/%s.pack" % pack)
    o = mlb_assets.decode_all(d)[tex][0]
    h, w, fmt, ptr = struct.unpack_from(">HHII", d, o)
    q = ptr & 0xFFFFFFF
    n = 16 if fmt == 8 else 256
    pal = rgb5a3_colours(np.frombuffer(d, dtype=">u2", count=n, offset=q - n * 2))
    if fmt == 8:
        raw = np.frombuffer(d, dtype=np.uint8, count=w * h // 2, offset=q)
        idx = untile(np.stack([raw >> 4, raw & 15], -1).reshape(-1), h, w, 8, 8)
    else:
        idx = untile(np.frombuffer(d, dtype=np.uint8, count=w * h, offset=q), h, w, 4, 8)
    return idx, pal, fmt


def runs(flags: np.ndarray, gap: int) -> list:
    """[(start, end)] of the True stretches of a 1-D array, stretches closer than `gap` joined."""
    out, start, last = [], None, 0
    for k, f in enumerate(flags):
        if f:
            if start is None:
                start = k
            last = k
        elif start is not None and k - last > gap:
            out.append((start, last + 1))
            start = None
    if start is not None:
        out.append((start, last + 1))
    return out


def find_boxes(idx: np.ndarray, min_index: int = 1, gap: int = 4, halo: int = 3) -> list:
    """Label boxes (l, t, r, b) of an MLB sheet, in reading order. Rows and columns are found from
    the pixels with index >= min_index (the glow that joins neighbours has lower indices); each
    box is then grown by `halo` pixels, never past the middle of the gap to its neighbour."""
    core = idx >= min_index
    boxes = []
    for t, b in runs(core.any(1), 2):
        cols = runs(core[t:b].any(0), gap)
        for k, (l, r) in enumerate(cols):
            lo = l - halo if k == 0 else max(l - halo, (cols[k - 1][1] + l) // 2)
            hi = r + halo if k == len(cols) - 1 else min(r + halo, (r + cols[k + 1][0]) // 2)
            boxes.append((max(lo, 0), max(t - halo, 0), min(hi, idx.shape[1]), min(b + halo, idx.shape[0])))
    return boxes


# ── Source styles: (indices, palette) -> role class of every pixel ─────────────────────────────

def luma(c: np.ndarray) -> np.ndarray:
    """Brightness 0..1 of RGB(A) colours (last axis = channels)."""
    return (0.299 * c[..., 0] + 0.587 * c[..., 1] + 0.114 * c[..., 2]) / 255.0


def style_param(idx: np.ndarray, pal: np.ndarray) -> np.ndarray:
    """Stat labels of ScsParamPlate: white-to-light-blue letters, blue ring, navy outer edge."""
    c = pal[idx].astype(np.float32)
    navy = (c[..., 2] < 150) & (c[..., 1] < 20)
    ring = (c[..., 0] < 40) & (c[..., 2] > 200) & (c[..., 1] < 110) & ~navy
    return np.where(navy, "outer", np.where(ring, "ring", "fill"))


def style_comcmd(idx: np.ndarray, pal: np.ndarray) -> np.ndarray:
    """Command words of ScsComMain: grey rim and shadow (indices 1-8), teal plate with mint letters (9-15)."""
    c = pal[idx].astype(np.float32)
    teal = idx >= 9
    return np.where(teal, np.where(idx >= 12, "letter", "plate"),
                    np.where(luma(c) < 0.55, "edge_dark", "edge_light"))


def style_light(idx: np.ndarray, pal: np.ndarray) -> np.ndarray:
    """Small labels drawn as thin white letters on their own plate: letters = light pixels, plate = the rest."""
    c = pal[idx].astype(np.float32)
    return np.where(luma(c) > 0.75, "fill", "ring")


# source style name (a spec's "style") -> function (indices, palette) -> role of every pixel
SOURCE_STYLES = {"param": style_param, "comcmd": style_comcmd, "light": style_light}
# letters count a little more than the rest when a stroke is cut down to a pixel or two
WEIGHTS = {"fill": 4.0, "letter": 4.0, "outer": 0.6, "edge_dark": 0.6}


def _pieces(mask: np.ndarray):
    """Yield the connected pieces (8-way) of a boolean mask, each as a list of (y, x) pixels."""
    h, w = mask.shape
    seen = np.zeros_like(mask)
    for y0, x0 in zip(*np.nonzero(mask)):
        if seen[y0, x0]:
            continue
        stack, pts = [(y0, x0)], []
        seen[y0, x0] = True
        while stack:
            y, x = stack.pop()
            pts.append((y, x))
            for yy in range(max(y - 1, 0), min(y + 2, h)):
                for xx in range(max(x - 1, 0), min(x + 2, w)):
                    if mask[yy, xx] and not seen[yy, xx]:
                        seen[yy, xx] = True
                        stack.append((yy, xx))
        yield pts


def drop_slivers(mask: np.ndarray) -> np.ndarray:
    """Remove pieces of neighbouring labels that reach into a crop: connected pieces (8-way) that touch
    the border and are at most 2 pixels wide or tall."""
    h, w = mask.shape
    keep = mask.copy()
    for pts in _pieces(mask):
        ys, xs = zip(*pts)
        touches = min(ys) == 0 or min(xs) == 0 or max(ys) == h - 1 or max(xs) == w - 1
        if touches and (max(xs) - min(xs) < 2 or max(ys) - min(ys) < 2):
            for y, x in pts:
                keep[y, x] = False
    return keep


def drop_specks(mask: np.ndarray, max_size: int = 3) -> np.ndarray:
    """Remove connected pieces (8-way) of at most `max_size` pixels: bits of neighbouring labels and
    shadow dots that the crop box catches."""
    keep = mask.copy()
    for pts in _pieces(mask):
        if len(pts) <= max_size:
            for y, x in pts:
                keep[y, x] = False
    return keep


def source_classes(spec: dict, project: str = None) -> tuple:
    """(mask, cls) of the cropped source label: mask = pixels of the label, cls = role of each.
    spec: {"pack", "tex", "box": [l, t, r, b], "style": a SOURCE_STYLES name, "drop": roles to leave out,
    "speck": largest speck to drop (default 3)}."""
    idx, pal, _ = mlb_texture(spec["pack"], spec["tex"], project)
    l, t, r, b = spec["box"]
    idx = idx[t:b, l:r]
    cls = SOURCE_STYLES[spec["style"]](idx, pal)
    mask = drop_slivers(idx != 0)
    for role in spec.get("drop", ()):           # roles the target draws with the plate colour anyway
        mask &= cls != role
    mask = drop_specks(mask, spec.get("speck", 3))
    ys, xs = np.nonzero(mask)
    sl = (slice(ys.min(), ys.max() + 1), slice(xs.min(), xs.max() + 1))
    return mask[sl], cls[sl]


def carve_axis(grid: np.ndarray, target: int, axis: int) -> np.ndarray:
    """Remove whole columns (axis 1) or rows (axis 0) of an integer label map until `target` are left.
    The line that loses the least goes first: lines identical to a neighbour (the middle of a thick
    stroke, a wide gap) cost nothing, a one-pixel stroke or a one-pixel gap costs a lot. Nothing is
    averaged, so every remaining pixel is a pixel of the original art."""
    g = grid if axis == 1 else grid.T
    cols = list(range(g.shape[1]))
    g = g.copy()
    taken = []
    while g.shape[1] > target:
        n = g.shape[1]
        best, best_cost = None, None
        for c in range(n):
            left = g[:, c - 1] if c > 0 else np.zeros_like(g[:, 0])
            right = g[:, c + 1] if c < n - 1 else np.zeros_like(g[:, 0])
            cur = g[:, c]
            loss = int((left != cur).sum()) + int((cur != right).sum()) - int((left != right).sum())
            if c in (0, n - 1):
                loss += 1                                   # keep the outermost pixels
            loss = loss * 100 + sum(1 for t in taken if abs(t - cols[c]) <= 2) * 3 + (n - 1 - c) % 2
            if best_cost is None or loss < best_cost:
                best, best_cost = c, loss
        taken.append(cols[best])
        g = np.delete(g, best, axis=1)
        del cols[best]
    return g if axis == 1 else g.T


def despeckle(grid: np.ndarray, passes: int = 2) -> np.ndarray:
    """Remove single-pixel noise from an integer label map: a pixel none of whose 4 neighbours share its
    value, and of which at least 3 agree with each other, takes their value (dither dots, one-pixel
    holes). Strokes of one pixel are not touched: they have neighbours of their own value."""
    g = grid.copy()
    for _ in range(passes):
        p = np.pad(g, 1, mode="edge")
        nb = np.stack([p[:-2, 1:-1], p[2:, 1:-1], p[1:-1, :-2], p[1:-1, 2:]])
        same = (nb == g).sum(0)
        out = g.copy()
        for v in np.unique(nb):
            votes = (nb == v).sum(0)
            fix = (same == 0) & (votes >= 3)
            out[fix] = v
        if (out == g).all():
            break
        g = out
    return g


def _fit_carve(mask, cls, roles, w, h, band):
    """fit() by cutting out the least important columns and rows; see fit."""
    sh, sw = mask.shape
    names = list(roles)
    grid = np.zeros(mask.shape, np.int32)
    for k, name in enumerate(names):
        grid[mask & (cls == name)] = k + 1
    grid = despeckle(grid)
    if band:                                    # letter pixels on the edge of the label become band
        inner, outer = names.index(band[0]) + 1, names.index(band[1]) + 1
        p = np.pad(grid, 1)
        touches = np.zeros(grid.shape, bool)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                touches |= p[1 + dy:1 + dy + grid.shape[0], 1 + dx:1 + dx + grid.shape[1]] == 0
        grid[(grid == inner) & touches] = outer
    if sw > w:
        grid = carve_axis(grid, max(w, 1), 1)
    if sh > h:
        grid = carve_axis(grid, max(h, 1), 0)
    grid = despeckle(grid)
    first = np.array([0] + [np.atleast_1d(roles[n])[0] for n in names], np.uint8)
    out = first[grid]
    for k, n in enumerate(names):               # a role given as [top, bottom] is a vertical gradient
        r = np.atleast_1d(roles[n])
        if len(r) == 2:
            rows = np.nonzero((grid == k + 1).any(1))[0]
            if len(rows):
                frac = (np.arange(grid.shape[0]) - rows.min()) / max(rows.max() - rows.min(), 1)
                shade = np.rint(r[0] + (r[1] - r[0]) * frac).astype(np.uint8)
                out = np.where(grid == k + 1, shade[:, None], out)
    return out


def _fit_area(mask, cls, roles, w, h, max_stretch, max_scale):
    """fit() by resampling with an area filter and letting the strongest role win each pixel; see fit."""
    sh, sw = mask.shape
    names = list(roles)
    sx = min(w / sw, max_scale)
    sy = min(sx * max_stretch, h / sh, max_scale * max_stretch)
    sy = max(sy, min(sx, h / sh))
    nw, nh = max(1, round(sw * sx)), max(1, round(sh * sy))
    cover = []
    for name in names:
        m = ((cls == name) & mask).astype(np.float32)
        cover.append(m if (nw, nh) == (sw, sh) else
                     np.asarray(Image.fromarray(m, "F").resize((nw, nh), Image.BOX), dtype=np.float32))
    cover = np.stack(cover)
    total = cover.sum(0)
    weights = np.array([WEIGHTS.get(n, 1.0) for n in names], np.float32)[:, None, None]
    pick = (cover * weights).argmax(0)
    index = np.array([roles[n] for n in names], np.uint8)[pick]
    return np.where(total >= 0.4, index, 0).astype(np.uint8)


def fit(mask: np.ndarray, cls: np.ndarray, roles: dict, w: int, h: int, max_stretch: float = 1.0,
        max_scale: float = 1.0, method: str = "carve", band=None) -> np.ndarray:
    """The label as an array of palette indices (0 = clear) that fits w x h. method "carve" (default)
    removes the least important columns and rows (see carve_axis); "area" resamples with an area filter
    (smoother, softer). Labels are never enlarged.
    roles: {role name: palette index, or [top, bottom] for a vertical gradient}. band = [inner role, outer role]:
    pixels of the inner role on the edge of the label become the outer role (a solid band round the letters)."""
    if method == "carve":
        return _fit_carve(mask, cls, roles, w, h, band)
    return _fit_area(mask, cls, roles, w, h, max_stretch, max_scale)


def draw(page: np.ndarray, rect: tuple, area: tuple, label: np.ndarray) -> None:
    """Draw the label (an index array, 0 = clear) centred in `area` (a box inside rect) on the page.
    `rect` is not used for the drawing; it is kept so the call matches add_halo."""
    h, w = label.shape
    ax0, ay0, ax1, ay1 = area
    ox, oy = ax0 + (ax1 - ax0 - w) // 2, ay0 + (ay1 - ay0 - h) // 2
    ys, xs = np.nonzero(label)
    page[oy + ys, ox + xs] = label[ys, xs]


def add_halo(page: np.ndarray, rect: tuple, halo: tuple) -> None:
    """Surround everything in the rectangle with solid one-pixel rings, first value innermost. The
    rings grow in all 8 directions, so corners are filled and the band has no gaps."""
    x0, y0, x1, y1 = rect
    region = page[y0:y1, x0:x1]
    for value in halo:
        g = np.pad(region != 0, 1)
        ring = np.zeros_like(g)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                ring |= np.roll(np.roll(g, dy, 0), dx, 1)
        ring = ring[1:-1, 1:-1]
        region[ring & (region == 0)] = value


def split_words(mask: np.ndarray, cls: np.ndarray, parts: int = 2, min_gap: int = 2) -> list:
    """Cut a label at its widest empty column gaps into `parts` words: [(mask, cls)] left to right,
    each cropped to its pixels. (`min_gap` is accepted for old callers and not used.)"""
    cols = (mask & np.isin(cls, ("fill", "letter"))).any(0)      # gaps between the letters themselves
    gaps = []
    start = None
    for x in range(1, len(cols) - 1):
        if not cols[x]:
            start = x if start is None else start
        elif start is not None:
            gaps.append((x - start, start, x))
            start = None
    gaps = sorted(sorted(gaps, reverse=True)[:parts - 1], key=lambda g: g[1])
    cuts = [0] + [(g[1] + g[2]) // 2 for g in gaps] + [mask.shape[1]]
    out = []
    for l, r in zip(cuts, cuts[1:]):
        m, c = mask[:, l:r].copy(), cls[:, l:r]
        pad = np.pad(m, 1)
        neighbours = sum(pad[1 + dy:1 + dy + m.shape[0], 1 + dx:1 + dx + m.shape[1]]
                         for dy in (-1, 0, 1) for dx in (-1, 0, 1) if dy or dx)
        m &= neighbours > 0                                   # isolated pixels are noise
        ys, xs = np.nonzero(m)
        sl = (slice(ys.min(), ys.max() + 1), slice(xs.min(), xs.max() + 1))
        out.append((m[sl], c[sl]))
    return out


# ── Names that moved ─────────────────────────────────────────────────────────────────────

# Spec rendering and the command line need the lettering tool (pp15/art/typeset.py), and the lettering tool reads its
# letters through this module, so they live in their own modules to keep the imports one-way. These names stay reachable
# as `labels.render` etc. for the tools that were written against them (pp15/kit/export_labels.py, pp15/cli.py).
_MOVED = {"render": "pp15.art.spec_render", "bank_of": "pp15.art.spec_io", "load_spec": "pp15.art.spec_io",
          "main": "pp15.art.spec_cli"}


def __getattr__(name: str):
    """Module-level lookup of the names in _MOVED: import the module that now holds them and return the object."""
    if name in _MOVED:
        return getattr(importlib.import_module(_MOVED[name]), name)
    raise AttributeError("module %r has no attribute %r" % (__name__, name))
