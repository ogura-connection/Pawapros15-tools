#!/usr/bin/env python3
"""Put English lettering from the MLB Power Pros games into the Pawapuro 15 UI pages.

  ui_labels.py boxes PACK TEX [MIN_INDEX]   label boxes (left, top, right, bottom) of one MLB texture
  ui_labels.py preview SPEC.json OUT.png          before/after sheet of every label in a spec, nothing written
  ui_labels.py apply SPEC.json                    write the labels into DATA/files/<arc> (original kept first)
  ui_labels.py restore ARC                        put the saved original .arc back

"repack" groups set whole words with ui_type.py and lay a page out again (see that file):
  "repack": [{"bank": "y5_smi_0", "palette": 28, "style": "command", "areas": [[page, x0, y0, x1, y1], ...],
              "labels": [{"from": [page, x0, y0, x1, y1], "text": "Practice"}, {"from": [...]}]}]
"paint" entries redraw lettering that is part of a plate, in place: {"bank", "page", "rect", "text",
"font", "ramp": palette index for ink 0 (the plate) to 6}.
A label of a group without "text" keeps its Japanese art. A label without "pack" only clears its rectangle (a piece of a Japanese label that has no use any more).
A spec is a JSON file:
  {"arc": "scs_main.arc",
   "project": "~/Projects/Pawapuro/MLB2008/DATA/files/project.bin",       (optional)
   "labels": [{"bank": "y5_smi_0", "page": 1, "palette": 28, "rect": [x0, y0, x1, y1],
               "pack": "ScsComMain", "tex": 0, "box": [l, t, r, b], "style": "comcmd",
               "roles": {...}, "max_stretch": 1.6, "halo": [4, 5], "lines": 2, "name": "Practice"}, ...]}
"drop" lists roles that are left out of the label (the outer edge of a label already sits on a plate
of that colour; leaving it out gives the letters the room), "halo" draws that colour back as a one-pixel
edge afterwards, "full" = overrides for the unscaled art, used when the label fits as drawn in MLB, "band": ["letter", "plate"] turns letter pixels on the outer edge of the label into plate, giving a
solid band round the letters, "lines": 2 stacks the two words of a label (cut at its widest gap) when it is too long
for one line. `rect` is a sprite rectangle of the page (see ui_textures.py parts); it is cleared, and the label is
centred in the part of it the Japanese label covered (its bounding box; "area": "rect" uses the whole
rectangle), minus `margin` pixels. The source colours are sorted into roles (outer / ring / fill for the
stat labels; edge_dark / edge_light / plate / letter for the command labels) and each role is given one
palette index of the target page ("roles"). Roles are resampled with an area filter and every pixel
takes the strongest role, so the result has hard edges and no in-between colours.
Nothing is drawn that is not in the MLB sheets: a label with no MLB counterpart is not in a spec.
"""
import json
import os
import struct
import sys

import numpy as np
from PIL import Image

import mlb_assets as G
import ui_textures as U

PROJECT = os.path.expanduser("~/Projects/Pawapuro/MLB2008/DATA/files/project.bin")
_projects = {}


def mlb_texture(pack, tex, project=None):
    """(indices (h, w), palette (n, 4), format) of the tex-th C4/C8 texture of an MLB .pack."""
    path = os.path.expanduser(project or PROJECT)
    if path not in _projects:
        _projects[path] = G.Project(path)
    d = _projects[path].read("/%s.pack" % pack)
    o = G.decode_all(d)[tex][0]
    h, w, fmt, ptr = struct.unpack_from(">HHII", d, o)
    q = ptr & 0xFFFFFFF
    n = 16 if fmt == 8 else 256
    pal = G._rgb5a3(np.frombuffer(d, dtype=">u2", count=n, offset=q - n * 2))
    if fmt == 8:
        raw = np.frombuffer(d, dtype=np.uint8, count=w * h // 2, offset=q)
        idx = G._blocks(np.stack([raw >> 4, raw & 15], -1).reshape(-1), h, w, 8, 8)
    else:
        idx = G._blocks(np.frombuffer(d, dtype=np.uint8, count=w * h, offset=q), h, w, 4, 8)
    return idx, pal, fmt


def runs(flags, gap):
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


def find_boxes(idx, min_index=1, gap=4, halo=3):
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

def luma(c):
    return (0.299 * c[..., 0] + 0.587 * c[..., 1] + 0.114 * c[..., 2]) / 255.0


def style_param(idx, pal):
    """Stat labels of ScsParamPlate: white-to-light-blue letters, blue ring, navy outer edge."""
    c = pal[idx].astype(np.float32)
    navy = (c[..., 2] < 150) & (c[..., 1] < 20)
    ring = (c[..., 0] < 40) & (c[..., 2] > 200) & (c[..., 1] < 110) & ~navy
    return np.where(navy, "outer", np.where(ring, "ring", "fill"))


def style_comcmd(idx, pal):
    """Command words of ScsComMain: grey rim and shadow (indices 1-8), teal plate with mint letters (9-15)."""
    c = pal[idx].astype(np.float32)
    teal = idx >= 9
    return np.where(teal, np.where(idx >= 12, "letter", "plate"),
                    np.where(luma(c) < 0.55, "edge_dark", "edge_light"))


def style_light(idx, pal):
    """Small labels drawn as thin white letters on their own plate: letters = light pixels, plate = the rest."""
    c = pal[idx].astype(np.float32)
    return np.where(luma(c) > 0.75, "fill", "ring")


STYLES = {"param": style_param, "comcmd": style_comcmd, "light": style_light}
# letters count a little more than the rest when a stroke is cut down to a pixel or two
WEIGHTS = {"fill": 4.0, "letter": 4.0, "outer": 0.6, "edge_dark": 0.6}


def drop_slivers(mask):
    """Remove pieces of neighbouring labels that reach into a crop: connected pieces (8-way) that touch
    the border and are at most 2 pixels wide or tall."""
    h, w = mask.shape
    seen = np.zeros_like(mask)
    keep = mask.copy()
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
        ys, xs = zip(*pts)
        touches = min(ys) == 0 or min(xs) == 0 or max(ys) == h - 1 or max(xs) == w - 1
        if touches and (max(xs) - min(xs) < 2 or max(ys) - min(ys) < 2):
            for y, x in pts:
                keep[y, x] = False
    return keep


def drop_specks(mask, max_size=3):
    """Remove connected pieces (8-way) of at most `max_size` pixels: bits of neighbouring labels and
    shadow dots that the crop box catches."""
    h, w = mask.shape
    seen = np.zeros_like(mask)
    keep = mask.copy()
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
        if len(pts) <= max_size:
            for y, x in pts:
                keep[y, x] = False
    return keep


def source_classes(spec, project=None):
    """(mask, cls) of the cropped source label: mask = pixels of the label, cls = role of each."""
    idx, pal, _ = mlb_texture(spec["pack"], spec["tex"], project)
    l, t, r, b = spec["box"]
    idx = idx[t:b, l:r]
    cls = STYLES[spec["style"]](idx, pal)
    mask = drop_slivers(idx != 0)
    for role in spec.get("drop", ()):           # roles the target draws with the plate colour anyway
        mask &= cls != role
    mask = drop_specks(mask, spec.get("speck", 3))
    ys, xs = np.nonzero(mask)
    sl = (slice(ys.min(), ys.max() + 1), slice(xs.min(), xs.max() + 1))
    return mask[sl], cls[sl]


def carve_axis(grid, target, axis):
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


def despeckle(grid, passes=2):
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


def fit(mask, cls, roles, w, h, max_stretch=1.0, max_scale=1.0, method="carve", band=None):
    """The label as an array of palette indices (0 = clear) that fits w x h. method "carve" (default)
    removes the least important columns and rows (see carve_axis); "area" resamples with an area filter
    (smoother, softer). Labels are never enlarged."""
    sh, sw = mask.shape
    names = list(roles)
    if method == "carve":
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


def draw(page, rect, area, label, halo=()):
    """Draw the label (an index array, 0 = clear) centred in `area` (a box inside rect), then the `halo`
    indices as successive one-pixel rings around everything in the rectangle."""
    x0, y0, x1, y1 = rect
    h, w = label.shape
    ax0, ay0, ax1, ay1 = area
    ox, oy = ax0 + (ax1 - ax0 - w) // 2, ay0 + (ay1 - ay0 - h) // 2
    ys, xs = np.nonzero(label)
    page[oy + ys, ox + xs] = label[ys, xs]


def add_halo(page, rect, halo):
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


def split_words(mask, cls, parts=2, min_gap=2):
    """Cut a label at its widest empty column gaps into `parts` words: [(mask, cls)] left to right,
    each cropped to its pixels."""
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


def render(spec, d, banks, project=None):
    """The index page with every label of the spec drawn, per (bank, page): {(bank, page): array}.
    render.patches = [(file offset, bytes)] for the sprite parts moved by "repack" groups."""
    pages = {}
    lab_used, scales = [], []
    render.patches, render.repacked = [], []
    for group in spec.get("repack", ()):
        import ui_type
        b = next(x for x in banks if x["name"] == group["bank"])
        local = {p: a for (name, p), a in pages.items() if name == group["bank"]}
        rows = ui_type.repack(group, d, b, local, render.patches, project)
        for p, a in local.items():
            pages[(group["bank"], p)] = a
        render.repacked += [(group["bank"],) + r for r in rows]
    for lab in spec.get("paint", ()):               # lettering that is part of a plate: redrawn in place
        import ui_type
        b = next(x for x in banks if x["name"] == lab["bank"])
        key = (lab["bank"], lab["page"])
        if key not in pages:
            pages[key] = U.decode_indices(d, *b["pages"][lab["page"]]).copy()
        x0, y0, x1, y1 = lab["rect"]
        ink, base = ui_type.typeset(lab["text"], lab["font"], project)
        h, w = ink.shape
        ox, oy = x0 + (x1 - x0 - w) // 2, y0 + (y1 - y0 - base) // 2
        pages[key][y0:y1, x0:x1] = lab["ramp"][0]
        area = pages[key][oy:oy + h, ox:ox + w]
        area[ink > 0] = np.array(lab["ramp"], np.uint8)[ink[ink > 0]]
        render.repacked.append((lab["bank"], lab["text"], "painted", "%dx%d" % (w, h),
                                "page %d x %d y %d" % (lab["page"], ox, oy), 0))
    for lab in spec.get("labels", ()):
        b = next(x for x in banks if x["name"] == lab["bank"])
        key = (lab["bank"], lab["page"])
        if key not in pages:
            off, size = b["pages"][lab["page"]]
            pages[key] = U.decode_indices(d, off, size).copy()
        x0, y0, x1, y1 = lab["rect"]
        if "pack" not in lab:                       # a rectangle that is only cleared
            pages[key][y0:y1, x0:x1] = 0
            continue
        # the label may only use the area the Japanese one covered (its neighbours overlap the rest)
        ys, xs = np.nonzero(pages[key][y0:y1, x0:x1])
        area = (x0 + xs.min(), y0 + ys.min(), x0 + xs.max() + 1, y0 + ys.max() + 1) \
            if len(xs) and lab.get("area", "label") == "label" else lab["rect"]
        pages[key][y0:y1, x0:x1] = 0
        # "full" = the art as drawn in MLB, tried first: used only if it fits without any scaling
        variant = dict(lab)
        if "full" in lab:
            full = dict(lab, **lab["full"])
            fm, _ = source_classes(full, project)
            m = full.get("margin", 0)
            if fm.shape[1] <= area[2] - area[0] - 2 * m and fm.shape[0] <= area[3] - area[1] - 2 * m \
                    and full.get("lines", 1) == 1:
                variant = full
        m = variant.get("margin", 0)
        ax0, ay0, ax1, ay1 = area[0] + m, area[1] + m, area[2] - m, area[3] - m
        mask, cls = source_classes(variant, project)
        halo = variant.get("halo", ())
        pad = len(halo)                              # room for the rings
        lab_used.append((lab["name"], variant is not lab))
        words = split_words(mask, cls, variant["lines"]) if variant.get("lines", 1) > 1 else [(mask, cls)]
        rows = len(words)
        band = (ay1 - ay0) // rows
        for k, (wm, wc) in enumerate(words):
            box = (ax0, ay0 + k * band, ax1, ay0 + (k + 1) * band)
            label = fit(wm, wc, variant["roles"], box[2] - box[0] - 2 * pad, box[3] - box[1] - 2 * pad,
                        variant.get("max_stretch", 1.0), variant.get("max_scale", 1.0),
                        variant.get("method", "carve"), variant.get("band"))
            scales.append((lab["name"], label.shape, wm.shape))
            draw(pages[key], lab["rect"], box, label)
        add_halo(pages[key], lab["rect"], halo)
    render.report = {"scales": scales, "full": lab_used}
    return pages


def load_spec(path):
    """The spec, with "arc" as a path, and "source" = the untouched original if one was saved: labels
    are always drawn onto the original pages, so applying a spec twice gives the same file."""
    with open(path) as f:
        spec = json.load(f)
    spec["arc"] = spec["arc"] if os.path.exists(spec["arc"]) else os.path.join(U.S.DATA_FILES, spec["arc"])
    saved = os.path.join(U.ORIG_ARC_DIR, os.path.basename(spec["arc"]))
    spec["source"] = saved if os.path.exists(saved) else spec["arc"]
    return spec


def cmd_preview(spec_path, out):
    spec = load_spec(spec_path)
    with open(spec["source"], "rb") as f:
        d = f.read()
    banks = U.banks(d, U.elf_symbols(d))
    pages = render(spec, d, banks, spec.get("project"))
    ims = []
    for (bank, page), new in pages.items():
        b = next(x for x in banks if x["name"] == bank)
        pal = U.palette_colours(d, b["pal"])
        lab = next((x for x in spec.get("labels", ()) if x["bank"] == bank and x["page"] == page), None) \
            or next(x for x in spec["repack"] if x["bank"] == bank)
        col = U.page_colours(pal, lab["palette"], 8192)
        off, size = b["pages"][page]
        old = U.decode_indices(d, off, size)
        for arr in (old, new):
            im = Image.new("RGBA", (U.PAGE, U.PAGE), (96, 96, 96, 255))
            im.alpha_composite(Image.fromarray(np.ascontiguousarray(col[arr]), "RGBA"))
            ims.append(im.resize((U.PAGE * 3, U.PAGE * 3), Image.NEAREST))
    sheet = Image.new("RGB", (U.PAGE * 6 + 8, U.PAGE * 3 * (len(ims) // 2)), (30, 30, 30))
    for k, im in enumerate(ims):
        sheet.paste(im.convert("RGB"), ((k % 2) * (U.PAGE * 3 + 8), (k // 2) * U.PAGE * 3))
    sheet.save(out)
    print("%d labels on %d pages -> %s" % (len(spec.get("labels", ())) + len(render.repacked), len(pages), out))


def cmd_apply(spec_path):
    spec = load_spec(spec_path)
    U.backup_orig(spec["arc"])
    spec = load_spec(spec_path)
    with open(spec["source"], "rb") as f:
        d = f.read()
    banks = U.banks(d, U.elf_symbols(d))
    pages = render(spec, d, banks, spec.get("project"))
    out = bytearray(d)
    for (bank, page), idx in pages.items():
        b = next(x for x in banks if x["name"] == bank)
        off, size = b["pages"][page]
        out[off:off + size] = U.encode_indices(idx, size, U.page_bits(d, off, size))
    for off, data in render.patches:
        out[off:off + len(data)] = data
    assert len(out) == len(d)
    with open(spec["arc"], "wb") as f:
        f.write(out)
    for row in render.repacked:
        print("  %-12s %-10s was %-6s now %-6s %s, %d sprite part(s)" % row)
    print("%s: %d labels and %d repacked labels written to %d pages, %d sprite parts moved "
          "(%d bytes changed)" % (os.path.basename(spec["arc"]), len(spec.get("labels", ())),
                                  len(render.repacked), len(pages), len(render.patches),
                                  sum(a != b for a, b in zip(d, out))))


def cmd_restore(arc):
    src = os.path.join(U.ORIG_ARC_DIR, os.path.basename(arc))
    if not os.path.exists(src):
        sys.exit("no saved original for %s" % arc)
    U.shutil.copy2(src, os.path.join(U.S.DATA_FILES, os.path.basename(arc)))
    print("restored", arc)


def main():
    a = sys.argv[1:]
    if a[:1] == ["boxes"] and len(a) >= 3:
        idx, _, _ = mlb_texture(a[1], int(a[2]))
        for k, b in enumerate(find_boxes(idx, int(a[3]) if len(a) > 3 else 1)):
            print(k, b, "%dx%d" % (b[2] - b[0], b[3] - b[1]))
    elif a[:1] == ["preview"] and len(a) == 3:
        cmd_preview(a[1], a[2])
    elif a[:1] == ["apply"] and len(a) == 2:
        cmd_apply(a[1])
    elif a[:1] == ["restore"] and len(a) == 2:
        cmd_restore(a[1])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
